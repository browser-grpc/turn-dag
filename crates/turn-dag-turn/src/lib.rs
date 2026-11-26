//! TURN issuer + allocation policy (TODO section 6), as pure Rust
//! logic over plain data. The API handlers (`handle_get_challenge`,
//! `handle_post_redeem`) model `GET /challenge` and `POST /redeem`
//! without a kernel TCP server; the user-space TCP/UDP stack lives
//! in [`stack`] on smoltcp. No kernel TCP listener or stream types
//! are used anywhere in this crate (enforced by an integration test
//! that scans this crate's sources).
//!
//! TURN PoW (SHA-256, 20 bits, IP-bound) is a *separate* construction
//! from mint PoW (Argon2id, epoch-bound, in `turn-dag-minter`):
//! distinct challenge derivation, distinct hash, distinct solution
//! type, no conversions between them. A solution for one can never
//! be presented as a solution for the other.
//!
//! All times are deterministic parameters (unix seconds); no sleeps.

pub mod live;
pub mod stack;
pub mod tls;
pub mod tun;
pub mod vnet;
pub mod wire;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;

type HmacSha1 = Hmac<Sha1>;

/// Default TURN PoW difficulty: 20 leading zero bits (~1M hashes).
pub const TURN_POW_BITS: u32 = 20;
/// TURN UDP/TCP port (RFC 8656) - bound on the smoltcp stack only.
pub const TURN_PORT: u16 = 3478;

/// Allocation policy. Every limit is a field here (spec coturn
/// tuning), never a magic number at a call site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationPolicy {
    /// `max-bps` in *bytes*/sec (spec: 16384, not bits).
    pub max_bps: u64,
    /// `max-allocate-lifetime` seconds (spec: 120).
    pub max_allocate_lifetime_secs: u64,
    /// `user-quota`: concurrent rendezvous per user (spec: 1).
    pub user_quota: usize,
    /// `total-quota`: concurrent allocations (spec: 200).
    pub total_quota: usize,
    /// `bps-capacity`: aggregate bytes/sec (spec: 3_276_800).
    pub bps_capacity: u64,
    /// `no-tcp-relay`: TCP relay allocations are not admitted.
    pub no_tcp_relay: bool,
    /// Credential lifetime seconds (spec: 120 for rendezvous).
    pub credential_lifetime_secs: u64,
    /// TURN PoW difficulty in leading zero bits (spec: 20).
    pub pow_bits: u32,
    /// TURN PoW challenge lifetime seconds.
    pub pow_ttl_secs: u64,
}

impl Default for AllocationPolicy {
    fn default() -> Self {
        Self {
            max_bps: 16_384,
            max_allocate_lifetime_secs: 120,
            user_quota: 1,
            total_quota: 200,
            bps_capacity: 3_276_800,
            no_tcp_relay: true,
            credential_lifetime_secs: 120,
            pow_bits: TURN_POW_BITS,
            pow_ttl_secs: 120,
        }
    }
}

impl AllocationPolicy {
    /// Per-allocation byte cap: 16_384 * 120 = 1_966_080 (~1.9 MB).
    pub fn byte_cap(&self) -> u64 {
        self.max_bps * self.max_allocate_lifetime_secs
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

// ---------------- denied peer IPs (SSRF hardening) ----------------

/// CIDRs denied as relay peers, exactly the spec list. Checked with
/// `ipnet` prefix containment for both families.
pub const DENIED_PEER_CIDRS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "192.0.0.0/24",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];

/// True iff `ip` is in any denied-peer range (private, loopback,
/// link-local incl. cloud metadata 169.254.169.254, CGNAT,
/// benchmarking, multicast, reserved, IPv6 loopback/ULA/link-local).
pub fn is_denied_peer_ip(ip: IpAddr) -> bool {
    DENIED_PEER_CIDRS.iter().any(|cidr| {
        cidr.parse::<ipnet::IpNet>()
            .map(|net| net.contains(&ip))
            .unwrap_or(false)
    })
}

// ---------------- TURN PoW (separate from mint PoW) ----------------

/// TURN PoW challenge: SHA-256, IP-bound (contrast mint: epoch-bound).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TurnPowChallenge {
    pub challenge_id: [u8; 16],
    pub challenge: [u8; 32],
    pub client_ip: IpAddr,
    pub issued_at: u64,
    pub expires_at: u64,
    pub bits: u32,
}

/// TURN PoW solution. Intentionally unrelated to `MintSolution`:
/// no `From`/`Into` exists between them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TurnPowSolution {
    pub challenge_id: [u8; 16],
    pub nonce: u64,
}

fn turn_challenge_bytes(
    secret: &[u8],
    client_ip: &IpAddr,
    issued_at: u64,
    counter: u64,
) -> ([u8; 16], [u8; 32]) {
    let mut h = Sha256::new();
    h.update(b"turn-pow-challenge-v1");
    h.update(secret);
    h.update(client_ip.to_string().as_bytes());
    h.update(issued_at.to_be_bytes());
    h.update(counter.to_be_bytes());
    let digest: [u8; 32] = h.finalize().into();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    (id, digest)
}

pub fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut n = 0;
    for b in hash {
        n += b.leading_zeros();
        if *b != 0 {
            break;
        }
    }
    n
}

fn turn_pow_hash(challenge: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"turn-pow-solution-v1");
    h.update(challenge);
    h.update(nonce.to_be_bytes());
    h.finalize().into()
}

/// Verify a TURN PoW solution with one SHA-256 evaluation.
pub fn verify_turn_pow(challenge: &TurnPowChallenge, solution: &TurnPowSolution) -> bool {
    solution.challenge_id == challenge.challenge_id
        && leading_zero_bits(&turn_pow_hash(&challenge.challenge, solution.nonce)) >= challenge.bits
}

/// Solve TURN PoW by scanning nonces (SHA-256; ~2^bits expected tries).
pub fn solve_turn_pow(challenge: &TurnPowChallenge) -> TurnPowSolution {
    let mut nonce: u64 = 0;
    loop {
        if leading_zero_bits(&turn_pow_hash(&challenge.challenge, nonce)) >= challenge.bits {
            return TurnPowSolution {
                challenge_id: challenge.challenge_id,
                nonce,
            };
        }
        nonce = nonce.wrapping_add(1);
    }
}

// ---------------- burn confirmation gate ----------------

/// Injected confirmation check: a burn may only be redeemed after
/// it reaches confirmation weight in the DAG (implemented by the
/// caller over `turn-dag-dag`; tests inject a stub). Allocation on
/// a local/unconfirmed view is rejected.
pub trait BurnConfirmation {
    fn is_burn_confirmed(&self, burn_id: &[u8; 32]) -> bool;
}

/// Always-unconfirmed checker (safe default).
pub struct NeverConfirmed;
impl BurnConfirmation for NeverConfirmed {
    fn is_burn_confirmed(&self, _burn_id: &[u8; 32]) -> bool {
        false
    }
}

// ---------------- credentials ----------------

/// One issued TURN credential + its allocation accounting.
/// username = `expiry:pow:<ticket_id>`,
/// password = base64(HMAC-SHA1(secret, username)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TurnCredential {
    pub ticket_id: String,
    pub username: String,
    pub password: String,
    pub expires_at: u64,
    pub max_bps: u64,
    pub byte_cap: u64,
    pub bytes_used: u64,
}

pub fn credential_password(secret: &[u8], username: &str) -> String {
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(username.as_bytes());
    B64.encode(mac.finalize().into_bytes())
}

/// Parse `expiry:pow:<ticket_id>`; returns (expiry, ticket_id).
pub fn parse_username(username: &str) -> Option<(u64, String)> {
    let mut parts = username.splitn(3, ':');
    let expiry: u64 = parts.next()?.parse().ok()?;
    if parts.next()? != "pow" {
        return None;
    }
    let ticket = parts.next()?;
    if ticket.is_empty() {
        return None;
    }
    Some((expiry, ticket.to_string()))
}

// ---------------- issuer (GET /challenge, POST /redeem logic) ----------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RedeemError {
    UnknownChallenge,
    ChallengeExpired,
    ChallengeAlreadyUsed,
    IpMismatch,
    BadPow,
    UnconfirmedBurn,
    DeniedPeerIp,
    TcpRelayDenied,
    UserQuotaExceeded,
    TotalQuotaExceeded,
    BpsCapacityExceeded,
}

/// Plain-data model of an API response (no HTTP server needed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiResponse<T> {
    pub status: u16,
    pub body: Result<T, RedeemError>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeResponse {
    pub challenge_id: [u8; 16],
    pub challenge: [u8; 32],
    pub bits: u32,
    pub expires_at: u64,
}

#[derive(Clone, Debug)]
pub struct RedeemRequest {
    pub user_id: String,
    /// IP the PoW challenge was issued to (must match).
    pub client_ip: IpAddr,
    /// Requested relay peer IP (denied-peer checked).
    pub peer_ip: IpAddr,
    pub transport: Transport,
    /// Both peers behind symmetric NAT -> 2 tickets for the rendezvous.
    pub both_symmetric_nat: bool,
    pub burn_id: [u8; 32],
    pub pow: TurnPowSolution,
}

pub struct TurnIssuer<'a> {
    secret: Vec<u8>,
    policy: AllocationPolicy,
    checker: &'a dyn BurnConfirmation,
    challenges: HashMap<[u8; 16], TurnPowChallenge>,
    used_challenges: std::collections::HashSet<[u8; 16]>,
    allocations: HashMap<String, TurnCredential>,
    /// user -> active ticket ids
    user_tickets: HashMap<String, Vec<String>>,
    counter: u64,
}

impl<'a> TurnIssuer<'a> {
    pub fn new(
        secret: Vec<u8>,
        policy: AllocationPolicy,
        checker: &'a dyn BurnConfirmation,
    ) -> Self {
        Self {
            secret,
            policy,
            checker,
            challenges: HashMap::new(),
            used_challenges: Default::default(),
            allocations: HashMap::new(),
            user_tickets: HashMap::new(),
            counter: 0,
        }
    }

    pub fn policy(&self) -> &AllocationPolicy {
        &self.policy
    }

    /// `GET /challenge` logic: issue an IP-bound TURN PoW challenge.
    pub fn handle_get_challenge(
        &mut self,
        client_ip: IpAddr,
        now: u64,
    ) -> ApiResponse<ChallengeResponse> {
        self.counter += 1;
        let (challenge_id, challenge) =
            turn_challenge_bytes(&self.secret, &client_ip, now, self.counter);
        let ch = TurnPowChallenge {
            challenge_id,
            challenge,
            client_ip,
            issued_at: now,
            expires_at: now + self.policy.pow_ttl_secs,
            bits: self.policy.pow_bits,
        };
        self.challenges.insert(challenge_id, ch.clone());
        ApiResponse {
            status: 200,
            body: Ok(ChallengeResponse {
                challenge_id: ch.challenge_id,
                challenge: ch.challenge,
                bits: ch.bits,
                expires_at: ch.expires_at,
            }),
        }
    }

    fn prune_expired(&mut self, now: u64) {
        let expired: Vec<String> = self
            .allocations
            .iter()
            .filter(|(_, c)| now > c.expires_at)
            .map(|(k, _)| k.clone())
            .collect();
        for ticket in expired {
            self.allocations.remove(&ticket);
        }
        for tickets in self.user_tickets.values_mut() {
            tickets.retain(|t| self.allocations.contains_key(t));
        }
        self.user_tickets.retain(|_, v| !v.is_empty());
    }

    pub fn active_allocations(&self) -> usize {
        self.allocations.len()
    }

    pub fn active_bps(&self) -> u64 {
        self.allocations.values().map(|c| c.max_bps).sum()
    }

    /// `POST /redeem` logic: burn + PoW -> 120 s TURN credential(s).
    /// 1 ticket per allocation; 2 tickets iff both peers are behind
    /// symmetric NAT. Unconfirmed burns get no credential.
    pub fn handle_post_redeem(
        &mut self,
        req: &RedeemRequest,
        now: u64,
    ) -> ApiResponse<Vec<TurnCredential>> {
        let err = |status: u16, e: RedeemError| ApiResponse {
            status,
            body: Err(e),
        };
        self.prune_expired(now);

        // PoW: exists, IP-bound, unexpired, single-use, valid.
        let ch = match self.challenges.get(&req.pow.challenge_id) {
            Some(c) => c.clone(),
            None => return err(404, RedeemError::UnknownChallenge),
        };
        if self.used_challenges.contains(&req.pow.challenge_id) {
            return err(409, RedeemError::ChallengeAlreadyUsed);
        }
        if now > ch.expires_at {
            return err(410, RedeemError::ChallengeExpired);
        }
        if req.client_ip != ch.client_ip {
            return err(403, RedeemError::IpMismatch);
        }
        if !verify_turn_pow(&ch, &req.pow) {
            return err(403, RedeemError::BadPow);
        }
        // Admission policy.
        if req.transport == Transport::Tcp && self.policy.no_tcp_relay {
            return err(403, RedeemError::TcpRelayDenied);
        }
        if is_denied_peer_ip(req.peer_ip) {
            return err(403, RedeemError::DeniedPeerIp);
        }
        // Burn must have reached confirmation weight.
        if !self.checker.is_burn_confirmed(&req.burn_id) {
            return err(403, RedeemError::UnconfirmedBurn);
        }
        // Quotas: 1 ticket normally, 2 if both peers symmetric NAT.
        let tickets: usize = if req.both_symmetric_nat { 2 } else { 1 };
        let user_active = self
            .user_tickets
            .get(&req.user_id)
            .map(|v| v.len())
            .unwrap_or(0);
        // user-quota counts rendezvous: an active rendezvous blocks a new one.
        if user_active > 0 && user_active >= self.policy.user_quota {
            return err(429, RedeemError::UserQuotaExceeded);
        }
        if self.allocations.len() + tickets > self.policy.total_quota {
            return err(429, RedeemError::TotalQuotaExceeded);
        }
        if self.active_bps() + (tickets as u64) * self.policy.max_bps > self.policy.bps_capacity {
            return err(429, RedeemError::BpsCapacityExceeded);
        }

        // Consume the PoW challenge only on success (single-use).
        self.used_challenges.insert(req.pow.challenge_id);

        let expires_at = now + self.policy.credential_lifetime_secs;
        let mut out = Vec::with_capacity(tickets);
        for i in 0..tickets {
            self.counter += 1;
            let mut h = Sha256::new();
            h.update(b"turn-ticket-v1");
            h.update(&self.secret);
            h.update(req.burn_id);
            h.update(self.counter.to_be_bytes());
            h.update((i as u64).to_be_bytes());
            let digest: [u8; 32] = h.finalize().into();
            let ticket_id = digest[..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let username = format!("{}:pow:{}", expires_at, ticket_id);
            let password = credential_password(&self.secret, &username);
            let cred = TurnCredential {
                ticket_id: ticket_id.clone(),
                username,
                password,
                expires_at,
                max_bps: self.policy.max_bps,
                byte_cap: self.policy.byte_cap(),
                bytes_used: 0,
            };
            self.allocations.insert(ticket_id.clone(), cred.clone());
            self.user_tickets
                .entry(req.user_id.clone())
                .or_default()
                .push(ticket_id);
            out.push(cred);
        }
        ApiResponse {
            status: 200,
            body: Ok(out),
        }
    }

    /// Verify a presented credential at time `now`: HMAC-SHA1 must
    /// match and the credential must be unexpired (120 s lifetime)
    /// and be a live allocation.
    pub fn verify_credential(&self, username: &str, password: &str, now: u64) -> bool {
        let (expiry, ticket_id) = match parse_username(username) {
            Some(v) => v,
            None => return false,
        };
        if now > expiry {
            return false;
        }
        if !self.allocations.contains_key(&ticket_id) {
            return false;
        }
        credential_password(&self.secret, username) == password
    }

    /// Account relayed bytes against the ~1.9 MB cap. Returns false
    /// (allocation must be dropped) when the cap would be exceeded
    /// or the ticket is unknown/expired.
    pub fn record_usage(&mut self, ticket_id: &str, bytes: u64, now: u64) -> bool {
        self.prune_expired(now);
        match self.allocations.get_mut(ticket_id) {
            Some(cred) => {
                if cred.bytes_used + bytes > cred.byte_cap {
                    return false;
                }
                cred.bytes_used += bytes;
                true
            }
            None => false,
        }
    }

    pub fn allocation(&self, ticket_id: &str) -> Option<&TurnCredential> {
        self.allocations.get(ticket_id)
    }
}

// ---------------- relay lifecycle ----------------

/// Relay lifecycle state machine (deterministic time).
/// If direct host/srflx succeeds the relay is dropped; if still
/// relayed at 90 s the next PoW is solved in the background and the
/// client restarts ICE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayState {
    /// Relay allocated, direct path not yet proven.
    Relayed { since: u64 },
    /// Direct path succeeded; relay dropped.
    DirectDropped,
    /// Still relayed at 90 s: background re-PoW + restartIce required.
    RenewalRequired {
        restart_ice: bool,
        background_repow: bool,
    },
}

#[derive(Clone, Debug)]
pub struct RelaySession {
    pub state: RelayState,
    /// Seconds after which a still-relayed session must renew.
    pub renew_after_secs: u64,
}

impl Default for RelaySession {
    fn default() -> Self {
        Self::new(0)
    }
}

impl RelaySession {
    pub fn new(now: u64) -> Self {
        Self {
            state: RelayState::Relayed { since: now },
            renew_after_secs: 90,
        }
    }

    /// Direct (host/srflx) success drops the relay allocation.
    pub fn on_direct_success(&mut self) {
        self.state = RelayState::DirectDropped;
    }

    pub fn is_relay_active(&self) -> bool {
        matches!(
            self.state,
            RelayState::Relayed { .. } | RelayState::RenewalRequired { .. }
        )
    }

    /// Advance with deterministic time. At >=90 s still-relayed,
    /// transitions to `RenewalRequired{restart_ice:true}`.
    pub fn tick(&mut self, now: u64) -> RelayState {
        if let RelayState::Relayed { since } = self.state {
            if now.saturating_sub(since) >= self.renew_after_secs {
                self.state = RelayState::RenewalRequired {
                    restart_ice: true,
                    background_repow: true,
                };
            }
        }
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    pub(crate) fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    struct Confirmed;
    impl BurnConfirmation for Confirmed {
        fn is_burn_confirmed(&self, _burn_id: &[u8; 32]) -> bool {
            true
        }
    }

    fn fast_policy() -> AllocationPolicy {
        // Cheap PoW bits for tests; production default is 20.
        AllocationPolicy {
            pow_bits: 8,
            ..AllocationPolicy::default()
        }
    }

    fn redeem_req(issuer: &mut TurnIssuer, user: &str, now: u64) -> RedeemRequest {
        let client_ip = ip("203.0.113.10");
        let resp = issuer.handle_get_challenge(client_ip, now);
        let ch_resp = resp.body.unwrap();
        let ch = TurnPowChallenge {
            challenge_id: ch_resp.challenge_id,
            challenge: ch_resp.challenge,
            client_ip,
            issued_at: now,
            expires_at: ch_resp.expires_at,
            bits: ch_resp.bits,
        };
        let pow = solve_turn_pow(&ch);
        RedeemRequest {
            user_id: user.to_string(),
            client_ip,
            peer_ip: ip("203.0.113.20"),
            transport: Transport::Udp,
            both_symmetric_nat: false,
            burn_id: [42u8; 32],
            pow,
        }
    }

    #[test]
    fn default_policy_matches_spec() {
        let p = AllocationPolicy::default();
        assert_eq!(p.max_bps, 16_384);
        assert_eq!(p.max_allocate_lifetime_secs, 120);
        assert_eq!(p.user_quota, 1);
        assert_eq!(p.total_quota, 200);
        assert_eq!(p.bps_capacity, 3_276_800);
        assert_eq!(p.byte_cap(), 1_966_080);
        assert!(p.no_tcp_relay);
        assert_eq!(p.credential_lifetime_secs, 120);
        assert_eq!(p.pow_bits, 20);
    }

    #[test]
    fn denied_peer_ips_cover_spec_ranges() {
        let denied = [
            "0.1.2.3",
            "10.0.0.5",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "192.0.0.1",
            "198.18.0.1",
            "198.19.255.255",
            "224.0.0.1",
            "240.0.0.1",
            "::1",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "febf::1",
        ];
        for s in denied {
            assert!(is_denied_peer_ip(ip(s)), "{s} must be denied");
        }
        let allowed = [
            "8.8.8.8",
            "203.0.113.20",
            "198.17.0.1",
            "172.32.0.1",
            "2606:4700:4700::1111",
        ];
        for s in allowed {
            assert!(!is_denied_peer_ip(ip(s)), "{s} must be allowed");
        }
        // Metadata endpoint explicitly.
        assert!(is_denied_peer_ip(IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))));
    }

    #[test]
    fn redeem_happy_path_credential_hmac_and_expiry() {
        let checker = Confirmed;
        let mut issuer = TurnIssuer::new(b"issuer-secret".to_vec(), fast_policy(), &checker);
        let req = redeem_req(&mut issuer, "alice", 1_000);
        let resp = issuer.handle_post_redeem(&req, 1_000);
        assert_eq!(resp.status, 200);
        let creds = resp.body.unwrap();
        assert_eq!(creds.len(), 1, "1 ticket per allocation");
        let cred = &creds[0];
        assert_eq!(cred.expires_at, 1_120, "120s lifetime");
        let (expiry, ticket) = parse_username(&cred.username).unwrap();
        assert_eq!(expiry, 1_120);
        assert_eq!(ticket, cred.ticket_id);
        // password = base64(HMAC-SHA1(secret, username))
        assert_eq!(
            cred.password,
            credential_password(b"issuer-secret", &cred.username)
        );
        assert!(issuer.verify_credential(&cred.username, &cred.password, 1_100));
        assert!(
            !issuer.verify_credential(&cred.username, &cred.password, 1_121),
            "expired at 120s"
        );
        assert!(!issuer.verify_credential(&cred.username, "wrong", 1_100));
    }

    #[test]
    fn unconfirmed_burn_gets_no_credential() {
        let checker = NeverConfirmed;
        let mut issuer = TurnIssuer::new(b"s".to_vec(), fast_policy(), &checker);
        let req = redeem_req(&mut issuer, "alice", 0);
        let resp = issuer.handle_post_redeem(&req, 0);
        assert_eq!(resp.body, Err(RedeemError::UnconfirmedBurn));
        assert_eq!(issuer.active_allocations(), 0);
    }

    #[test]
    fn ssrf_peer_ips_rejected_at_redeem() {
        let checker = Confirmed;
        for peer in [
            "169.254.169.254",
            "10.1.2.3",
            "192.168.0.9",
            "127.0.0.1",
            "::1",
            "fe80::5",
            "fc00::7",
        ] {
            let mut issuer = TurnIssuer::new(b"s".to_vec(), fast_policy(), &checker);
            let mut req = redeem_req(&mut issuer, "alice", 0);
            req.peer_ip = ip(peer);
            let resp = issuer.handle_post_redeem(&req, 0);
            assert_eq!(resp.body, Err(RedeemError::DeniedPeerIp), "peer {peer}");
            assert_eq!(issuer.active_allocations(), 0);
        }
    }

    #[test]
    fn tcp_relay_denied_and_pow_ip_bound_and_single_use() {
        let checker = Confirmed;
        let mut issuer = TurnIssuer::new(b"s".to_vec(), fast_policy(), &checker);
        // TCP relay denied (no-tcp-relay).
        let mut req = redeem_req(&mut issuer, "alice", 0);
        req.transport = Transport::Tcp;
        assert_eq!(
            issuer.handle_post_redeem(&req, 0).body,
            Err(RedeemError::TcpRelayDenied)
        );

        // IP-bound: same PoW from a different IP fails.
        let mut issuer = TurnIssuer::new(b"s".to_vec(), fast_policy(), &checker);
        let mut req = redeem_req(&mut issuer, "alice", 0);
        req.client_ip = ip("203.0.113.99");
        assert_eq!(
            issuer.handle_post_redeem(&req, 0).body,
            Err(RedeemError::IpMismatch)
        );

        // Single-use + user quota.
        let mut issuer = TurnIssuer::new(b"s".to_vec(), fast_policy(), &checker);
        let req = redeem_req(&mut issuer, "alice", 0);
        assert!(issuer.handle_post_redeem(&req, 0).body.is_ok());
        assert_eq!(
            issuer.handle_post_redeem(&req, 0).body,
            Err(RedeemError::ChallengeAlreadyUsed)
        );
        // New challenge, same user: user-quota=1 blocks second rendezvous.
        let req2 = redeem_req(&mut issuer, "alice", 0);
        assert_eq!(
            issuer.handle_post_redeem(&req2, 0).body,
            Err(RedeemError::UserQuotaExceeded)
        );
        // After 120s expiry the quota frees.
        let req3 = redeem_req(&mut issuer, "alice", 121);
        assert!(issuer.handle_post_redeem(&req3, 121).body.is_ok());
    }

    #[test]
    fn symmetric_nat_gets_two_tickets() {
        let checker = Confirmed;
        let mut issuer = TurnIssuer::new(b"s".to_vec(), fast_policy(), &checker);
        let mut req = redeem_req(&mut issuer, "alice", 0);
        req.both_symmetric_nat = true;
        let creds = issuer.handle_post_redeem(&req, 0).body.unwrap();
        assert_eq!(creds.len(), 2);
        assert_ne!(creds[0].ticket_id, creds[1].ticket_id);
        assert_eq!(issuer.active_allocations(), 2);
    }

    #[test]
    fn byte_cap_enforced() {
        let checker = Confirmed;
        let mut issuer = TurnIssuer::new(b"s".to_vec(), fast_policy(), &checker);
        let req = redeem_req(&mut issuer, "alice", 0);
        let creds = issuer.handle_post_redeem(&req, 0).body.unwrap();
        let ticket = creds[0].ticket_id.clone();
        assert_eq!(creds[0].byte_cap, 1_966_080);
        assert!(issuer.record_usage(&ticket, 1_966_080, 10));
        assert!(!issuer.record_usage(&ticket, 1, 10), "over 1.9MB cap");
        // Expired allocation rejects usage.
        assert!(!issuer.record_usage(&ticket, 1, 1_000));
    }

    #[test]
    fn total_quota_and_bps_capacity_enforced() {
        let checker = Confirmed;
        let policy = AllocationPolicy {
            pow_bits: 4,
            total_quota: 3,
            bps_capacity: 16_384 * 3,
            ..AllocationPolicy::default()
        };
        let mut issuer = TurnIssuer::new(b"s".to_vec(), policy, &checker);
        for i in 0..3 {
            let req = redeem_req(&mut issuer, &format!("user{i}"), 0);
            assert!(issuer.handle_post_redeem(&req, 0).body.is_ok(), "user{i}");
        }
        assert_eq!(issuer.active_bps(), 3 * 16_384);
        let req = redeem_req(&mut issuer, "user3", 0);
        let e = issuer.handle_post_redeem(&req, 0).body.unwrap_err();
        assert!(
            matches!(
                e,
                RedeemError::TotalQuotaExceeded | RedeemError::BpsCapacityExceeded
            ),
            "{e:?}"
        );
    }

    #[test]
    fn relay_lifecycle_direct_drop_and_90s_renewal() {
        let mut s = RelaySession::new(0);
        assert!(s.is_relay_active());
        assert_eq!(s.tick(89), RelayState::Relayed { since: 0 });
        match s.tick(90) {
            RelayState::RenewalRequired {
                restart_ice,
                background_repow,
            } => {
                assert!(restart_ice);
                assert!(background_repow);
            }
            other => panic!("expected renewal at 90s, got {other:?}"),
        }
        let mut s2 = RelaySession::new(0);
        s2.on_direct_success();
        assert_eq!(s2.state, RelayState::DirectDropped);
        assert!(!s2.is_relay_active());
        // Direct success before 90s never triggers renewal.
        assert_eq!(s2.tick(500), RelayState::DirectDropped);
    }

    #[test]
    fn turn_pow_verify_and_wrong_nonce() {
        let mut issuer_secret = b"s".to_vec();
        let (id, challenge) = turn_challenge_bytes(&issuer_secret, &ip("203.0.113.1"), 0, 1);
        issuer_secret.clear();
        let ch = TurnPowChallenge {
            challenge_id: id,
            challenge,
            client_ip: ip("203.0.113.1"),
            issued_at: 0,
            expires_at: 120,
            bits: 10,
        };
        let sol = solve_turn_pow(&ch);
        assert!(verify_turn_pow(&ch, &sol));
        assert!(leading_zero_bits(&turn_pow_hash(&ch.challenge, sol.nonce)) >= 10);
        let bad = TurnPowSolution {
            nonce: sol.nonce.wrapping_add(1),
            ..sol.clone()
        };
        // A neighbouring nonce passes with prob 2^-10; just assert the
        // API distinguishes a tampered challenge id deterministically.
        let bad_id = TurnPowSolution {
            challenge_id: [0u8; 16],
            ..bad
        };
        assert!(!verify_turn_pow(&ch, &bad_id));
    }
}
