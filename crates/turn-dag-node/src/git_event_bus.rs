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
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

/// Per-subscriber queue bound, matching the upstream broker.
pub const SUBSCRIBER_QUEUE_CAPACITY: usize = 128;

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
        Ok(Arc::new(Self {
            repo,
            branch: branch.to_string(),
            state: Mutex::new(BrokerState {
                subscribers: HashMap::new(),
                next_subscriber: 0,
                seq,
                published: history.len() as u64,
                dropped: 0,
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
        let mut last_error = String::new();
        for _ in 0..3 {
            let event = {
                let mut state = self.state.lock().unwrap();
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

    #[test]
    fn branch_is_durable_log_replay_and_live_tail() {
        let repo = temp_repo("durable");
        let broker = GitEventBusBroker::open(&repo).unwrap();
        let orders = vec![tag_string(Tag::Topic, "orders")];
        let other = vec![tag_string(Tag::Topic, "other")];

        let first = broker
            .publish_event(orders.clone(), b"o1".to_vec(), "test")
            .unwrap();
        broker.publish_event(other, b"x1".to_vec(), "test").unwrap();
        let third = broker
            .publish_event(orders.clone(), b"o2".to_vec(), "test")
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
                .map(|event| event.payload.clone())
                .collect::<Vec<_>>(),
            vec![b"o1".to_vec(), b"o2".to_vec()]
        );

        let mut stream = reopened.subscribe_stream(orders.clone()).unwrap();
        assert_eq!(next(&mut stream).payload, b"o1");
        assert_eq!(next(&mut stream).payload, b"o2");
        assert!(matches!(poll(&mut stream), Poll::Pending));

        reopened
            .publish_event(orders, b"o3".to_vec(), "test")
            .unwrap();
        assert_eq!(next(&mut stream).payload, b"o3");

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
    fn branch_commits_use_upstream_event_format() {
        let repo = temp_repo("format");
        let broker = GitEventBusBroker::open_branch(&repo, "events/custom").unwrap();
        broker
            .publish_event(
                vec![tag_string(Tag::Topic, "orders")],
                b"o1".to_vec(),
                "test",
            )
            .unwrap();

        // The vendored upstream importer understands our branch, and
        // git log carries the same human-readable trailer index.
        let imported = import_events(&repo, "events/custom", &[], 0, 0).unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].payload, b"o1");
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
