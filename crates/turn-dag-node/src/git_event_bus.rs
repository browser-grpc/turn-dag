//! Git-branch-backed `grpcdc.events.v1.EventBus` broker.
//!
//! The branch is the durable log, following grpc-dc's existing
//! git serde: one commit per event, with the protobuf-encoded
//! event stored as `event.pb`. Unlike the upstream serde layer,
//! this broker's live Publish path appends to git *before*
//! fanning an event out, and Subscribe first replays the
//! matching branch history and then continues with live events.
//! Delivery remains at-most-once per subscriber: each queue is
//! bounded and drops its oldest events when it falls behind.

use grpc_dc::eventbus::pb::{Event, PublishReply, PublishRequest, SubscribeRequest, TagValue};
use grpc_dc::eventbus::tags_match;
use grpc_dc::eventbus_git::{export_events, import_events, init_event_log_repo, EVENT_LOG_BRANCH};
use grpc_dc::{server_stream_method, unary_method, CallCtx, ResponseStream, ServiceDef, Status};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use turn_dag_wallet::{HotWallet, PqAddress, PqWallet};

/// Per-subscriber queue bound, matching the upstream broker.
pub const SUBSCRIBER_QUEUE_CAPACITY: usize = 128;

// ---------------- signed event envelopes ----------------
//
// Every published event carries a CBOR envelope as its payload:
// the browser's persistent wallet key (derived from a WebAuthn
// PRF secret in the wallet app) certifies a short-lived ephemeral
// ML-DSA keypair, and the ephemeral key signs each event. Git
// commits therefore attribute events cryptographically to the
// browser wallet, not merely to the server that appended them.
// The broker verifies the full chain before appending: certified
// ephemeral key, address derived from the wallet pubkey matching
// publisher_id, cert not expired, per-ephemeral client sequence
// strictly increasing (an exact signed envelope cannot replay).

#[derive(serde::Serialize, serde::Deserialize)]
struct CertCore {
    v: u8,
    wallet_addr: serde_bytes::ByteArray<20>,
    wallet_pubkey: serde_bytes::ByteBuf,
    ephemeral_pubkey: serde_bytes::ByteBuf,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EventCore {
    v: u8,
    cert_sha256: serde_bytes::ByteArray<32>,
    client_seq: u64,
    tags_pb: serde_bytes::ByteBuf,
    payload: serde_bytes::ByteBuf,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SignedEnvelope {
    cert_core: serde_bytes::ByteBuf,
    cert_sig: serde_bytes::ByteBuf,
    event_core: serde_bytes::ByteBuf,
    event_sig: serde_bytes::ByteBuf,
}

/// A publish payload after successful signed-envelope verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSignedEvent {
    pub wallet: PqAddress,
    pub ephemeral_pubkey: Vec<u8>,
    pub client_seq: u64,
    pub payload: Vec<u8>,
}

fn cbor<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("CBOR encode signed event");
    out
}

fn tags_to_pb(tags: &[TagValue]) -> Vec<u8> {
    let mut out = Vec::new();
    for tag in tags {
        let bytes = tag.encode();
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&bytes);
    }
    out
}

fn tags_from_pb(mut bytes: &[u8]) -> Result<Vec<TagValue>, String> {
    let mut tags = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err("truncated signed tag list".to_string());
        }
        let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        let Some(rest) = bytes.get(4..4 + len) else {
            return Err("truncated signed tag value".to_string());
        };
        tags.push(TagValue::decode(rest)?);
        bytes = &bytes[4 + len..];
    }
    Ok(tags)
}

/// Build a signed publish payload. The wallet key certifies the
/// ephemeral key until `expires_at_ms`; the ephemeral key signs
/// this event. Mirrored byte-for-byte by web/signed-pubsub.js.
pub fn sign_event_envelope(
    wallet: &HotWallet,
    ephemeral: &HotWallet,
    issued_at_ms: u64,
    expires_at_ms: u64,
    client_seq: u64,
    tags: &[TagValue],
    payload: &[u8],
) -> Vec<u8> {
    let cert_core = cbor(&CertCore {
        v: 1,
        wallet_addr: serde_bytes::ByteArray::from(wallet.address().0),
        wallet_pubkey: serde_bytes::ByteBuf::from(wallet.public_key().to_vec()),
        ephemeral_pubkey: serde_bytes::ByteBuf::from(ephemeral.public_key().to_vec()),
        issued_at_ms,
        expires_at_ms,
    });
    let cert_sig = wallet.sign(&cert_core);
    let event_core = cbor(&EventCore {
        v: 1,
        cert_sha256: serde_bytes::ByteArray::from(<[u8; 32]>::from(Sha256::digest(&cert_core))),
        client_seq,
        tags_pb: serde_bytes::ByteBuf::from(tags_to_pb(tags)),
        payload: serde_bytes::ByteBuf::from(payload.to_vec()),
    });
    let event_sig = ephemeral.sign(&event_core);
    cbor(&SignedEnvelope {
        cert_core: serde_bytes::ByteBuf::from(cert_core),
        cert_sig: serde_bytes::ByteBuf::from(cert_sig),
        event_core: serde_bytes::ByteBuf::from(event_core),
        event_sig: serde_bytes::ByteBuf::from(event_sig),
    })
}

/// Verify a signed publish payload against the request's tags and
/// claimed publisher. `Ok` carries the verified inner payload.
pub fn verify_signed_event(
    tags: &[TagValue],
    envelope: &[u8],
    publisher_id: &str,
    now_ms: i64,
) -> Result<VerifiedSignedEvent, String> {
    let env: SignedEnvelope =
        ciborium::from_reader(envelope).map_err(|e| format!("signed envelope CBOR: {e}"))?;
    let cert: CertCore = ciborium::from_reader(env.cert_core.as_slice())
        .map_err(|e| format!("certificate CBOR: {e}"))?;
    let core: EventCore = ciborium::from_reader(env.event_core.as_slice())
        .map_err(|e| format!("signed event CBOR: {e}"))?;
    if cert.v != 1 || core.v != 1 {
        return Err("unsupported signed event version".to_string());
    }
    let wallet_addr = PqAddress(cert.wallet_addr.into_array());
    if PqAddress::from_pubkey(cert.wallet_pubkey.as_slice()) != wallet_addr {
        return Err("wallet address does not match wallet pubkey".to_string());
    }
    let expected_publisher: String = wallet_addr
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if publisher_id != expected_publisher {
        return Err("publisher_id is not the signing wallet address".to_string());
    }
    if now_ms < 0
        || cert.issued_at_ms > now_ms as u64 + 300_000
        || cert.expires_at_ms <= now_ms as u64
        || cert.expires_at_ms > cert.issued_at_ms.saturating_add(24 * 60 * 60 * 1000)
    {
        return Err("ephemeral certificate expired or validity window invalid".to_string());
    }
    if !HotWallet::verify(
        cert.wallet_pubkey.as_slice(),
        env.cert_core.as_slice(),
        env.cert_sig.as_slice(),
    ) {
        return Err("ephemeral certificate signature invalid".to_string());
    }
    let cert_hash: [u8; 32] = Sha256::digest(env.cert_core.as_slice()).into();
    if cert_hash != *core.cert_sha256 {
        return Err("event is not bound to this ephemeral certificate".to_string());
    }
    if !HotWallet::verify(
        cert.ephemeral_pubkey.as_slice(),
        env.event_core.as_slice(),
        env.event_sig.as_slice(),
    ) {
        return Err("event signature invalid".to_string());
    }
    if tags_from_pb(core.tags_pb.as_slice())? != tags {
        return Err("signed tags do not match publish tags".to_string());
    }
    Ok(VerifiedSignedEvent {
        wallet: wallet_addr,
        ephemeral_pubkey: cert.ephemeral_pubkey.into_vec(),
        client_seq: core.client_seq,
        payload: core.payload.into_vec(),
    })
}

fn signed_counter_of(envelope: &[u8]) -> Option<(Vec<u8>, u64)> {
    let env: SignedEnvelope = ciborium::from_reader(envelope).ok()?;
    let cert: CertCore = ciborium::from_reader(env.cert_core.as_slice()).ok()?;
    let core: EventCore = ciborium::from_reader(env.event_core.as_slice()).ok()?;
    Some((cert.ephemeral_pubkey.into_vec(), core.client_seq))
}

/// Calendar current time in Unix milliseconds for verification.
fn signed_now_ms() -> i64 {
    now_unix_ms()
}

struct SubscriberState {
    filter: Vec<TagValue>,
    queue: VecDeque<Event>,
    waker: Option<Waker>,
    dropped: u64,
}

struct BrokerState {
    subscribers: HashMap<u64, Arc<Mutex<SubscriberState>>>,
    next_subscriber: u64,
    seq: u64,
    published: u64,
    dropped: u64,
    /// Highest accepted client_seq per ephemeral pubkey.
    signed_client_seqs: std::collections::HashMap<Vec<u8>, u64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GitEventBusStats {
    pub published: u64,
    pub subscribers: u64,
    pub dropped: u64,
    pub last_seq: u64,
}

/// A `grpcdc.events.v1.EventBus` broker whose durable history is
/// a git branch. New subscribers replay matching history from
/// that branch, in sequence order, before receiving live events.
pub struct GitEventBusBroker {
    repo: PathBuf,
    branch: String,
    state: Mutex<BrokerState>,
    pub queue_capacity: usize,
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl GitEventBusBroker {
    /// Open (or initialize) `repo` and adopt the branch's current
    /// maximum sequence number, so publishing resumes after restart.
    pub fn open(repo: impl Into<PathBuf>) -> Result<Arc<Self>, String> {
        Self::open_branch(repo, EVENT_LOG_BRANCH)
    }

    pub fn open_branch(repo: impl Into<PathBuf>, branch: &str) -> Result<Arc<Self>, String> {
        let repo = repo.into();
        init_event_log_repo(&repo)?;
        let history = import_events(&repo, branch, &[], 0, 0)?;
        let seq = history.iter().map(|event| event.seq).max().unwrap_or(0);
        let mut signed_client_seqs = std::collections::HashMap::new();
        for event in &history {
            if let Some((ephemeral, client_seq)) = signed_counter_of(&event.payload) {
                let last: &mut u64 = signed_client_seqs.entry(ephemeral).or_default();
                *last = (*last).max(client_seq);
            }
        }
        Ok(Arc::new(Self {
            repo,
            branch: branch.to_string(),
            state: Mutex::new(BrokerState {
                subscribers: HashMap::new(),
                next_subscriber: 0,
                seq,
                published: history.len() as u64,
                dropped: 0,
                signed_client_seqs,
            }),
            queue_capacity: SUBSCRIBER_QUEUE_CAPACITY,
        }))
    }

    pub fn repo(&self) -> &std::path::Path {
        &self.repo
    }

    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Matching history currently stored in git, oldest first.
    /// An empty filter matches every event.
    pub fn history(&self, filter: &[TagValue]) -> Result<Vec<Event>, String> {
        import_events(&self.repo, &self.branch, filter, 0, 0)
    }

    /// Append one event to git, then fan it out to subscribers.
    ///
    /// The broker lock serializes sequence assignment and git's
    /// compare-and-swap ref update within this process. If an
    /// external exporter has advanced the branch, the sequence is
    /// re-synchronized from git and the append is retried.
    pub fn publish_event(
        &self,
        tags: Vec<TagValue>,
        payload: Vec<u8>,
        publisher_id: &str,
    ) -> Result<Event, String> {
        // Every RPC/direct publish must be a valid signed envelope:
        // wallet-certified ephemeral key + per-key monotonic counter.
        let verified = verify_signed_event(&tags, &payload, publisher_id, signed_now_ms())?;
        let mut last_error = String::new();
        for _ in 0..3 {
            let event = {
                let mut state = self.state.lock().unwrap();
                if state
                    .signed_client_seqs
                    .get(&verified.ephemeral_pubkey)
                    .is_some_and(|last| verified.client_seq <= *last)
                {
                    return Err(format!(
                        "replayed signed event client_seq {}",
                        verified.client_seq
                    ));
                }
                let existing = import_events(&self.repo, &self.branch, &[], state.seq, 0)?;
                if let Some(max_seq) = existing.iter().map(|event| event.seq).max() {
                    state.seq = state.seq.max(max_seq);
                }

                let event = Event {
                    tags: tags.clone(),
                    payload: payload.clone(),
                    seq: state.seq + 1,
                    publisher_id: publisher_id.to_string(),
                    timestamp_unix_ms: now_unix_ms(),
                    ..Default::default()
                };

                match export_events(&self.repo, std::slice::from_ref(&event), &self.branch) {
                    Ok(_) => {
                        // export_events skips a sequence already present. Verify
                        // that the persisted bytes are this event, not a
                        // colliding sequence written by another exporter.
                        let persisted =
                            import_events(&self.repo, &self.branch, &[], event.seq - 1, event.seq)?;
                        if !persisted.iter().any(|candidate| candidate == &event) {
                            last_error =
                                format!("sequence {} was taken by another exporter", event.seq);
                            state.seq = state.seq.max(event.seq);
                            continue;
                        }
                    }
                    Err(error) => {
                        last_error = error;
                        continue;
                    }
                }

                state.seq = event.seq;
                state.published += 1;
                state
                    .signed_client_seqs
                    .insert(verified.ephemeral_pubkey.clone(), verified.client_seq);
                self.fan_out_locked(&mut state, &event);
                event
            };
            return Ok(event);
        }
        Err(format!("append event to git branch: {last_error}"))
    }

    fn fan_out_locked(&self, state: &mut BrokerState, event: &Event) {
        let capacity = if self.queue_capacity > 0 {
            self.queue_capacity
        } else {
            SUBSCRIBER_QUEUE_CAPACITY
        };
        let subscribers: Vec<Arc<Mutex<SubscriberState>>> =
            state.subscribers.values().cloned().collect();
        let mut dropped = 0;
        for subscriber in subscribers {
            let mut subscriber = subscriber.lock().unwrap();
            if !tags_match(&event.tags, &subscriber.filter) {
                continue;
            }
            if subscriber.queue.len() >= capacity {
                subscriber.queue.pop_front();
                subscriber.dropped += 1;
                dropped += 1;
            }
            subscriber.queue.push_back(event.clone());
            if let Some(waker) = subscriber.waker.take() {
                waker.wake();
            }
        }
        state.dropped += dropped;
    }

    fn add_subscriber(
        &self,
        filter: Vec<TagValue>,
    ) -> Result<(u64, Arc<Mutex<SubscriberState>>), Status> {
        let capacity = if self.queue_capacity > 0 {
            self.queue_capacity
        } else {
            SUBSCRIBER_QUEUE_CAPACITY
        };
        let mut state = self.state.lock().unwrap();

        // Synchronize sequence state with git before registration.
        // Holding the broker lock across registration + replay means
        // a concurrent publish cannot slip between the two steps.
        let all = import_events(&self.repo, &self.branch, &[], 0, 0).map_err(Status::internal)?;
        if let Some(max_seq) = all.iter().map(|event| event.seq).max() {
            state.seq = state.seq.max(max_seq);
        }
        state.next_subscriber += 1;
        let id = state.next_subscriber;

        let mut queue: VecDeque<Event> = all
            .into_iter()
            .filter(|event| tags_match(&event.tags, &filter))
            .collect();
        let mut dropped = 0;
        while queue.len() > capacity {
            queue.pop_front();
            dropped += 1;
        }
        state.dropped += dropped;

        let subscriber = Arc::new(Mutex::new(SubscriberState {
            filter,
            queue,
            waker: None,
            dropped,
        }));
        state.subscribers.insert(id, subscriber.clone());
        Ok((id, subscriber))
    }

    fn remove_subscriber(&self, id: u64) {
        self.state.lock().unwrap().subscribers.remove(&id);
    }

    /// Response stream used by the RPC Subscribe method.
    pub fn subscribe_stream(
        self: &Arc<Self>,
        filter: Vec<TagValue>,
    ) -> Result<ResponseStream<Event>, Status> {
        let (id, subscriber) = self.add_subscriber(filter)?;
        Ok(Box::pin(GitSubscribeStream {
            broker: self.clone(),
            id,
            subscriber,
        }))
    }

    pub fn stats(&self) -> GitEventBusStats {
        let state = self.state.lock().unwrap();
        GitEventBusStats {
            published: state.published,
            subscribers: state.subscribers.len() as u64,
            dropped: state.dropped,
            last_seq: state.seq,
        }
    }

    /// The `grpcdc.events.v1.EventBus` service definition.
    pub fn service(self: &Arc<Self>) -> ServiceDef {
        let publish_broker = self.clone();
        let subscribe_broker = self.clone();
        ServiceDef::new(
            "grpcdc.events.v1.EventBus",
            vec![
                unary_method("Publish", move |req: PublishRequest, _ctx: CallCtx| {
                    let broker = publish_broker.clone();
                    async move {
                        let event = broker
                            .publish_event(req.tags, req.payload, &req.publisher_id)
                            .map_err(Status::internal)?;
                        Ok(PublishReply {
                            seq: event.seq,
                            ..Default::default()
                        })
                    }
                }),
                server_stream_method("Subscribe", move |req: SubscribeRequest, _ctx: CallCtx| {
                    let broker = subscribe_broker.clone();
                    async move { broker.subscribe_stream(req.filter) }
                }),
            ],
        )
    }
}

struct GitSubscribeStream {
    broker: Arc<GitEventBusBroker>,
    id: u64,
    subscriber: Arc<Mutex<SubscriberState>>,
}

impl grpc_dc::futures_core::Stream for GitSubscribeStream {
    type Item = Result<Event, Status>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut subscriber = self.subscriber.lock().unwrap();
        if let Some(event) = subscriber.queue.pop_front() {
            return Poll::Ready(Some(Ok(event)));
        }
        subscriber.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl Drop for GitSubscribeStream {
    fn drop(&mut self) {
        self.broker.remove_subscriber(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grpc_dc::eventbus::pb::Tag;
    use grpc_dc::eventbus::tag_string;
    use grpc_dc::futures_core::Stream;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_REPO: AtomicU64 = AtomicU64::new(0);

    fn temp_repo(name: &str) -> PathBuf {
        let n = NEXT_REPO.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "turn-dag-git-event-bus-{name}-{}-{n}",
            std::process::id()
        ))
    }

    fn poll(stream: &mut ResponseStream<Event>) -> Poll<Option<Result<Event, Status>>> {
        let waker = std::task::Waker::noop().clone();
        let mut context = Context::from_waker(&waker);
        Pin::new(stream).poll_next(&mut context)
    }

    fn next(stream: &mut ResponseStream<Event>) -> Event {
        match poll(stream) {
            Poll::Ready(Some(Ok(event))) => event,
            other => panic!("expected queued event, got {other:?}"),
        }
    }

    fn signed_payload(
        wallet: &HotWallet,
        ephemeral: &HotWallet,
        client_seq: u64,
        tags: &[TagValue],
        payload: &[u8],
    ) -> Vec<u8> {
        let now = signed_now_ms() as u64;
        sign_event_envelope(
            wallet,
            ephemeral,
            now.saturating_sub(1_000),
            now + 3_600_000,
            client_seq,
            tags,
            payload,
        )
    }

    fn publisher(wallet: &HotWallet) -> String {
        wallet
            .address()
            .0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn inner(event: &Event) -> Vec<u8> {
        verify_signed_event(
            &event.tags,
            &event.payload,
            &event.publisher_id,
            signed_now_ms(),
        )
        .unwrap()
        .payload
    }

    #[test]
    fn branch_is_durable_log_replay_and_live_tail() {
        let repo = temp_repo("durable");
        let broker = GitEventBusBroker::open(&repo).unwrap();
        let wallet = HotWallet::generate(&[90u8; 32]).unwrap();
        let ephemeral = HotWallet::generate(&[91u8; 32]).unwrap();
        let publisher_id = publisher(&wallet);
        let orders = vec![tag_string(Tag::Topic, "orders")];
        let other = vec![tag_string(Tag::Topic, "other")];

        let first = broker
            .publish_event(
                orders.clone(),
                signed_payload(&wallet, &ephemeral, 1, &orders, b"o1"),
                &publisher_id,
            )
            .unwrap();
        broker
            .publish_event(
                other.clone(),
                signed_payload(&wallet, &ephemeral, 2, &other, b"x1"),
                &publisher_id,
            )
            .unwrap();
        let third = broker
            .publish_event(
                orders.clone(),
                signed_payload(&wallet, &ephemeral, 3, &orders, b"o2"),
                &publisher_id,
            )
            .unwrap();
        assert_eq!((first.seq, third.seq), (1, 3));

        // Reopening the repo reconstructs sequence/history from git.
        let reopened = GitEventBusBroker::open(&repo).unwrap();
        assert_eq!(reopened.stats().last_seq, 3);
        assert_eq!(
            reopened
                .history(&orders)
                .unwrap()
                .iter()
                .map(inner)
                .collect::<Vec<_>>(),
            vec![b"o1".to_vec(), b"o2".to_vec()]
        );

        let mut stream = reopened.subscribe_stream(orders.clone()).unwrap();
        assert_eq!(inner(&next(&mut stream)), b"o1");
        assert_eq!(inner(&next(&mut stream)), b"o2");
        assert!(matches!(poll(&mut stream), Poll::Pending));

        reopened
            .publish_event(
                orders.clone(),
                signed_payload(&wallet, &ephemeral, 4, &orders, b"o3"),
                &publisher_id,
            )
            .unwrap();
        assert_eq!(inner(&next(&mut stream)), b"o3");

        let count = std::process::Command::new("git")
            .args([
                "-C",
                repo.to_str().unwrap(),
                "rev-list",
                "--count",
                EVENT_LOG_BRANCH,
            ])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&count.stdout).trim(), "4");

        drop(stream);
        assert_eq!(reopened.stats().subscribers, 0);
        std::fs::remove_dir_all(&repo).unwrap();
    }

    #[test]
    fn unsigned_tampered_and_replayed_events_are_rejected() {
        let repo = temp_repo("signed-negatives");
        let broker = GitEventBusBroker::open(&repo).unwrap();
        let wallet = HotWallet::generate(&[94u8; 32]).unwrap();
        let ephemeral = HotWallet::generate(&[95u8; 32]).unwrap();
        let tags = vec![tag_string(Tag::Topic, "orders")];
        let publisher_id = publisher(&wallet);

        // Plain unsigned protobuf payloads are no longer accepted.
        assert!(broker
            .publish_event(tags.clone(), b"raw".to_vec(), &publisher_id)
            .is_err());

        let signed = signed_payload(&wallet, &ephemeral, 1, &tags, b"o1");
        broker
            .publish_event(tags.clone(), signed.clone(), &publisher_id)
            .unwrap();
        // Exact envelope replay: signature is valid, counter is not.
        let replay = broker.publish_event(tags.clone(), signed, &publisher_id);
        assert!(
            format!("{replay:?}").contains("replayed signed event"),
            "{replay:?}"
        );

        // Tamper with the next envelope's signature bytes.
        let mut tampered = signed_payload(&wallet, &ephemeral, 2, &tags, b"o2");
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(broker.publish_event(tags, tampered, &publisher_id).is_err());

        assert_eq!(broker.history(&[]).unwrap().len(), 1);
        std::fs::remove_dir_all(&repo).unwrap();
    }

    #[test]
    fn branch_commits_use_upstream_event_format() {
        let repo = temp_repo("format");
        let broker = GitEventBusBroker::open_branch(&repo, "events/custom").unwrap();
        let wallet = HotWallet::generate(&[92u8; 32]).unwrap();
        let ephemeral = HotWallet::generate(&[93u8; 32]).unwrap();
        let tags = vec![tag_string(Tag::Topic, "orders")];
        broker
            .publish_event(
                tags.clone(),
                signed_payload(&wallet, &ephemeral, 1, &tags, b"o1"),
                &publisher(&wallet),
            )
            .unwrap();

        // The vendored upstream importer understands our branch, and
        // git log carries the same human-readable trailer index.
        let imported = import_events(&repo, "events/custom", &[], 0, 0).unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(inner(&imported[0]), b"o1");
        let log = std::process::Command::new("git")
            .args([
                "-C",
                repo.to_str().unwrap(),
                "log",
                "-1",
                "--format=%B",
                "events/custom",
            ])
            .output()
            .unwrap();
        let message = String::from_utf8_lossy(&log.stdout);
        assert!(message.contains("grpc-dc event 1"));
        assert!(message.contains("Seq: 1"));
        assert!(message.contains("Tag: 1|s:orders"));

        std::fs::remove_dir_all(&repo).unwrap();
    }
}
