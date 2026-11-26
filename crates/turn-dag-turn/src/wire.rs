//! TURN wire protocol (RFC 8656 subset) over STUN framing (RFC 8489):
//! Allocate / Refresh / CreatePermission / ChannelBind / Send+Data.
//! Transport-agnostic: [`TurnServer::handle`] takes one datagram and
//! returns a response, a forward to a peer, or a drop. It runs over
//! the smoltcp UDP socket in [`crate::stack`]; there is no kernel
//! socket anywhere. Lifetime is capped at 120s and relay peers are
//! checked against the denied-peer list before any permission/channel.
use crate::is_denied_peer_ip;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub const STUN_MAGIC: u32 = 0x2112_A442;
/// First bytes as hex, for TURN_DEBUG packet logs.
pub fn hex_preview(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub mod method {
    pub const BINDING: u16 = 0x001;
    pub const ALLOCATE: u16 = 0x003;
    pub const REFRESH: u16 = 0x004;
    pub const SEND: u16 = 0x006;
    pub const DATA: u16 = 0x007;
    pub const CREATE_PERMISSION: u16 = 0x008;
    pub const CHANNEL_BIND: u16 = 0x009;
}
pub mod attr_type {
    pub const MAPPED_ADDRESS: u16 = 0x0001;
    pub const ERROR_CODE: u16 = 0x0009;
    pub const CHANNEL_NUMBER: u16 = 0x000C;
    pub const LIFETIME: u16 = 0x000D;
    pub const XOR_PEER_ADDRESS: u16 = 0x0012;
    pub const DATA: u16 = 0x0013;
    pub const XOR_RELAYED_ADDRESS: u16 = 0x0016;
    pub const REQUESTED_TRANSPORT: u16 = 0x0019;
    pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
    pub const USERNAME: u16 = 0x0006;
    pub const MESSAGE_INTEGRITY: u16 = 0x0008;
    pub const REALM: u16 = 0x0014;
    pub const NONCE: u16 = 0x0015;
    pub const FINGERPRINT: u16 = 0x8028;
    pub const SOFTWARE: u16 = 0x8022;
}
/// STUN message classes, encoded in bits 4 and 8 of the type field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Request,
    Indication,
    Success,
    Error,
}
pub fn encode_type(method: u16, class: Class) -> u16 {
    // RFC 8489 §6: class LSB at bit 4, MSB at bit 8. Request=00,
    // Indication=01, Success=10, Error=11 - so Allocate success is
    // 0x0103, not 0x0013 (an indication). Swapping these makes real
    // browsers ignore every success response and retransmit.
    let (b4, b8) = match class {
        Class::Request => (0, 0),
        Class::Indication => (1, 0),
        Class::Success => (0, 1),
        Class::Error => (1, 1),
    };
    (method & 0x000F) | ((method & 0x0070) << 1) | ((method & 0x0F80) << 2) | (b4 << 4) | (b8 << 8)
}
pub fn decode_type(t: u16) -> (u16, Class) {
    let method = (t & 0x000F) | ((t >> 1) & 0x0070) | ((t >> 2) & 0x0F80);
    let class = match ((t >> 4) & 1, (t >> 8) & 1) {
        (0, 0) => Class::Request,
        (1, 0) => Class::Indication,
        (0, 1) => Class::Success,
        _ => Class::Error,
    };
    (method, class)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StunMessage {
    pub method: u16,
    pub class: Class,
    pub transaction: [u8; 12],
    pub attrs: Vec<(u16, Vec<u8>)>,
}
impl StunMessage {
    pub fn new(method: u16, class: Class, transaction: [u8; 12]) -> Self {
        Self {
            method,
            class,
            transaction,
            attrs: Vec::new(),
        }
    }
    pub fn attr(&self, t: u16) -> Option<&[u8]> {
        self.attrs
            .iter()
            .find(|(k, _)| *k == t)
            .map(|(_, v)| v.as_slice())
    }
    pub fn push_attr(&mut self, t: u16, v: Vec<u8>) {
        self.attrs.push((t, v));
    }
    /// Raw encode without fingerprint computation (sign_wire handles it).
    /// Each attribute is padded to a 4-byte boundary independently
    /// (RFC 5389 §15); padding is never cumulative.
    pub fn encode_raw(&self) -> Vec<u8> {
        let mut body = Vec::new();
        for (t, v) in &self.attrs {
            let mut attr = Vec::with_capacity(4 + v.len() + 3);
            attr.extend_from_slice(&t.to_be_bytes());
            attr.extend_from_slice(&(v.len() as u16).to_be_bytes());
            attr.extend_from_slice(v);
            while attr.len() % 4 != 0 {
                attr.push(0);
            }
            body.extend_from_slice(&attr);
        }
        let mut out = Vec::with_capacity(20 + body.len());
        out.extend_from_slice(&encode_type(self.method, self.class).to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&STUN_MAGIC.to_be_bytes());
        out.extend_from_slice(&self.transaction);
        out.extend_from_slice(&body);
        out
    }
    /// Encode without FINGERPRINT (Chromium ignores absent fingerprints
    /// on requests; authenticated successes get a correct one).
    pub fn encode(&self) -> Vec<u8> {
        sign_wire(self.clone(), None)
    }
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 20 || data[0] >> 6 != 0 {
            return None;
        }
        let raw_type = u16::from_be_bytes(data[0..2].try_into().ok()?);
        let len = u16::from_be_bytes(data[2..4].try_into().ok()?) as usize;
        if u32::from_be_bytes(data[4..8].try_into().ok()?) != STUN_MAGIC
            || len % 4 != 0
            || data.len() < 20 + len
        {
            return None;
        }
        let (method, class) = decode_type(raw_type);
        let mut transaction = [0u8; 12];
        transaction.copy_from_slice(&data[8..20]);
        let mut attrs = Vec::new();
        let mut i = 20;
        let end = 20 + len;
        while i + 4 <= end {
            let t = u16::from_be_bytes(data[i..i + 2].try_into().ok()?);
            let l = u16::from_be_bytes(data[i + 2..i + 4].try_into().ok()?) as usize;
            i += 4;
            if i + l > end {
                return None;
            }
            attrs.push((t, data[i..i + l].to_vec()));
            i += l + (4 - l % 4) % 4;
        }
        if i != end {
            return None;
        }
        Some(Self {
            method,
            class,
            transaction,
            attrs,
        })
    }
}

fn xor_addr(addr: SocketAddr, txn: &[u8; 12]) -> Vec<u8> {
    let mut o = vec![0u8, if addr.is_ipv4() { 1 } else { 2 }];
    o.extend_from_slice(&(addr.port() ^ (STUN_MAGIC >> 16) as u16).to_be_bytes());
    match addr.ip() {
        IpAddr::V4(v4) => {
            o.extend_from_slice(&(u32::from(v4) ^ STUN_MAGIC).to_be_bytes());
        }
        IpAddr::V6(v6) => {
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&STUN_MAGIC.to_be_bytes());
            mask[4..].copy_from_slice(txn);
            for (i, b) in v6.octets().iter().enumerate() {
                o.push(b ^ mask[i]);
            }
        }
    }
    o
}
fn unxor_addr(v: &[u8], txn: &[u8; 12]) -> Option<SocketAddr> {
    if v.len() < 4 {
        return None;
    }
    let port = u16::from_be_bytes(v[2..4].try_into().ok()?) ^ (STUN_MAGIC >> 16) as u16;
    match v[1] {
        1 if v.len() >= 8 => {
            let ip = u32::from_be_bytes(v[4..8].try_into().ok()?) ^ STUN_MAGIC;
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
        }
        2 if v.len() >= 20 => {
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&STUN_MAGIC.to_be_bytes());
            mask[4..].copy_from_slice(txn);
            let mut oct = [0u8; 16];
            for i in 0..16 {
                oct[i] = v[4 + i] ^ mask[i];
            }
            Some(SocketAddr::new(IpAddr::V6(oct.into()), port))
        }
        _ => None,
    }
}
/// Long-term credential key: MD5(username:realm:password) (RFC 8656 §9.2).
pub fn integrity_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(username.as_bytes());
    h.update(b":");
    h.update(realm.as_bytes());
    h.update(b":");
    h.update(password.as_bytes());
    h.finalize().into()
}
fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}
/// Encode+sign a message for the wire: MESSAGE-INTEGRITY (if a key is
/// given) then FINGERPRINT last, in RFC 8656 order. Unsigned/error
/// messages carry no FINGERPRINT: Chromium's libnice ignores absent
/// fingerprints, while a malformed one is worse than none.
pub fn sign_wire(mut msg: StunMessage, integrity: Option<&[u8; 16]>) -> Vec<u8> {
    let Some(k) = integrity else {
        return msg.encode_raw();
    };
    msg.push_attr(attr_type::MESSAGE_INTEGRITY, vec![0u8; 20]);
    msg.push_attr(attr_type::FINGERPRINT, vec![0u8; 4]);
    let mut bytes = msg.encode_raw();
    // Reserving the fingerprint's tail keeps offsets stable regardless
    // of what the CRC computes over. The tail is exactly the
    // 8-byte fingerprint attribute (type + length + 4 value bytes).
    let n = bytes.len();
    assert_eq!(&bytes[n - 8..n - 4], &[0x80, 0x28, 0x00, 0x04]);
    // MESSAGE-INTEGRITY over up to the attribute with adjusted length.
    let mi_at = n - 8 - 24;
    let mut head = bytes[..mi_at].to_vec();
    head[2..4].copy_from_slice(&((mi_at - 20 + 24) as u16).to_be_bytes());
    let mac = hmac_sha1(k, &head);
    bytes[mi_at + 4..mi_at + 24].copy_from_slice(&mac);
    // FINGERPRINT last (RFC 8489 §14.7): CRC32 over the message up
    // to (but excluding) the FINGERPRINT attribute itself. Browsers
    // reject Allocate successes whose fingerprint covers the zeroed
    // attribute and silently retransmit the request.
    let fp = (crc32(&bytes[..n - 8]) ^ 0x5354_554E).to_be_bytes();
    bytes[n - 4..n].copy_from_slice(&fp);
    bytes
}
pub fn sign_integrity(msg: StunMessage, key: &[u8; 16]) -> Vec<u8> {
    sign_wire(msg, Some(key))
}

/// Verify MESSAGE-INTEGRITY over a raw request datagram.
/// The HMAC covers the header (with length adjusted to include the
/// 24-byte integrity attribute) up to the attribute itself.
pub fn verify_integrity(raw: &[u8], key: &[u8; 16]) -> bool {
    if raw.len() < 20 {
        return false;
    }
    let len = u16::from_be_bytes(raw[2..4].try_into().unwrap()) as usize;
    let end = (20 + len).min(raw.len());
    let mut i = 20;
    while i + 4 <= end {
        let t = u16::from_be_bytes(raw[i..i + 2].try_into().unwrap());
        let l = u16::from_be_bytes(raw[i + 2..i + 4].try_into().unwrap()) as usize;
        if t == attr_type::MESSAGE_INTEGRITY {
            if l != 20 || i + 24 > end {
                return false;
            }
            let mut head = raw[..i].to_vec();
            let adj = (i - 20 + 24) as u16;
            head[2..4].copy_from_slice(&adj.to_be_bytes());
            let expect = hmac_sha1(key, &head);
            return expect == raw[i + 4..i + 24];
        }
        i += 4 + l + (4 - l % 4) % 4;
    }
    false
}
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    crc ^ 0xFFFF_FFFF
}
fn err_response(req: &StunMessage, code: u16, reason: &str) -> StunMessage {
    let mut m = StunMessage::new(req.method, Class::Error, req.transaction);
    let mut v = vec![0, 0, (code / 100) as u8, (code % 100) as u8];
    v.extend_from_slice(reason.as_bytes());
    m.push_attr(attr_type::ERROR_CODE, v);
    m
}
/// Error code from an ERROR-CODE attribute, e.g. 403/437/442 (tests + callers).
pub fn error_code(m: &StunMessage) -> Option<u16> {
    let v = m.attr(attr_type::ERROR_CODE)?;
    if v.len() < 4 {
        return None;
    }
    Some(v[2] as u16 * 100 + v[3] as u16)
}

#[derive(Clone, Debug)]
struct Allocation {
    relayed: SocketAddr,
    expires_at: u64,
    permissions: HashSet<IpAddr>,
    channels: HashMap<u16, SocketAddr>,
    bytes: u64,
    /// Issuer ticket (`expiry:pow:<ticket>`) that created this
    /// allocation, when REST/burn auth is in use. One live allocation
    /// per ticket (issuer user-quota=1 at the wire).
    ticket: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandleOutcome {
    Response(Vec<u8>),
    Forward { peer: SocketAddr, data: Vec<u8> },
    Drop,
}

/// ChannelData frame: channel number + length + payload, padded to 4.
pub fn encode_channel_data(channel: u16, payload: &[u8]) -> Vec<u8> {
    let mut o = Vec::with_capacity(4 + payload.len() + 3);
    o.extend_from_slice(&channel.to_be_bytes());
    o.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    o.extend_from_slice(payload);
    while o.len() % 4 != 0 {
        o.push(0);
    }
    o
}
/// Decode a ChannelData frame, returning (channel, payload).
pub fn decode_channel_data(data: &[u8]) -> Option<(u16, &[u8])> {
    if data.len() < 4 || (data[0] >> 6) != 0b01 {
        return None;
    }
    let chan = u16::from_be_bytes(data[0..2].try_into().ok()?);
    let len = u16::from_be_bytes(data[2..4].try_into().ok()?) as usize;
    if data.len() < 4 + len {
        return None;
    }
    Some((chan, &data[4..4 + len]))
}

/// Minimal TURN server state machine (no relay sockets of its own:
/// `Forward` tells the stack owner which peer a payload goes to).
pub struct TurnServer {
    server_ip: IpAddr,
    next_port: u16,
    max_lifetime_secs: u64,
    byte_cap: u64,
    allocations: HashMap<SocketAddr, Allocation>,
    realm: String,
    credentials: HashMap<String, String>,
    /// REST (issuer) secret: when set, usernames are
    /// `expiry:pow:<ticket>` and the long-term key derives from the
    /// issuer HMAC, exactly as TurnIssuer issues them.
    rest_secret: Option<Vec<u8>>,
    /// Burn gate: when configured, REST tickets must be present here
    /// (tickets are minted only after a confirmed burn).
    burn_tickets: Option<std::collections::HashSet<String>>,
    nonce: String,
    /// `total-quota`: max concurrent allocations (spec: 200).
    max_allocations: usize,
}
impl TurnServer {
    pub fn new(server_ip: IpAddr) -> Self {
        Self {
            server_ip,
            next_port: 49152,
            max_lifetime_secs: 120,
            byte_cap: 16_384 * 120,
            allocations: HashMap::new(),
            realm: "turn-dag".into(),
            credentials: HashMap::new(),
            rest_secret: None,
            burn_tickets: None,
            nonce: String::new(),
            max_allocations: 200,
        }
    }
    /// Override `total-quota` (default 200, spec coturn tuning).
    pub fn with_max_allocations(mut self, max: usize) -> Self {
        self.max_allocations = max;
        self
    }
    /// Verify issuer-issued REST credentials (username=expiry:pow:<ticket>,
    /// HMAC-SHA1 password) instead of static long-term credentials.
    pub fn with_rest_auth(mut self, secret: Vec<u8>) -> Self {
        self.rest_secret = Some(secret);
        if self.burn_tickets.is_none() {
            // Gate off by default; enable with burn tickets.
        }
        self.nonce = format!("{:016x}", {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(self.server_ip.to_string().as_bytes());
            h.update(self.realm.as_bytes());
            u64::from_be_bytes(h.finalize()[..8].try_into().unwrap())
        });
        self
    }
    /// Enable the burn gate: REST tickets must have been minted after
    /// a confirmed burn (issuer-side gate). The operator supplies the
    /// ticket IDs issued by TurnIssuer::handle_post_redeem.
    pub fn with_burn_tickets(mut self, tickets: Vec<String>) -> Self {
        self.burn_tickets = Some(tickets.into_iter().collect());
        self
    }
    /// Enable long-term credential auth (401 challenge + integrity).
    pub fn with_auth(mut self, realm: &str, credentials: HashMap<String, String>) -> Self {
        self.realm = realm.into();
        self.nonce = format!("{:016x}", {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(self.server_ip.to_string().as_bytes());
            h.update(realm.as_bytes());
            u64::from_be_bytes(h.finalize()[..8].try_into().unwrap())
        });
        self.credentials = credentials;
        self
    }
    fn auth_key(&self, msg: &StunMessage) -> Option<[u8; 16]> {
        let user = std::str::from_utf8(msg.attr(attr_type::USERNAME)?).ok()?;
        let password = if let Some(secret) = &self.rest_secret {
            crate::credential_password(secret, user)
        } else {
            self.credentials.get(user)?.clone()
        };
        Some(integrity_key(user, &self.realm, &password))
    }
    /// Ok(key) if the request may proceed (auth off, or valid integrity).
    fn check_auth(
        &self,
        raw: &[u8],
        msg: &StunMessage,
        now: u64,
    ) -> Result<Option<[u8; 16]>, StunMessage> {
        if self.credentials.is_empty() && self.rest_secret.is_none() {
            return Ok(None);
        }
        if self.rest_secret.is_some() {
            let Some(user) = msg
                .attr(attr_type::USERNAME)
                .and_then(|v| std::str::from_utf8(v).ok())
            else {
                return Err(self.challenge(msg));
            };
            let Some((expiry, ticket)) = crate::parse_username(user) else {
                return Err(self.challenge(msg));
            };
            if now > expiry {
                return Err(self.challenge(msg));
            }
            // Burn gate: only tickets minted after a confirmed burn.
            if let Some(allowed) = &self.burn_tickets {
                if !allowed.contains(&ticket) {
                    return Err(self.challenge(msg));
                }
            }
            if let Some(key) = self.auth_key(msg) {
                if verify_integrity(raw, &key) {
                    return Ok(Some(key));
                }
            }
            return Err(self.challenge(msg));
        }
        let user = msg
            .attr(attr_type::USERNAME)
            .and_then(|v| std::str::from_utf8(v).ok());
        let nonce_ok = msg
            .attr(attr_type::NONCE)
            .map(|v| v == self.nonce.as_bytes())
            .unwrap_or(false);
        let realm_ok = msg
            .attr(attr_type::REALM)
            .map(|v| v == self.realm.as_bytes())
            .unwrap_or(true);
        if let (Some(user), true, true) = (user, nonce_ok, realm_ok) {
            if let Some(password) = self.credentials.get(user) {
                let key = integrity_key(user, &self.realm, password);
                if verify_integrity(raw, &key) {
                    return Ok(Some(key));
                }
            }
        }
        Err(self.challenge(msg))
    }
    fn challenge(&self, msg: &StunMessage) -> StunMessage {
        let mut m = StunMessage::new(msg.method, Class::Error, msg.transaction);
        let mut v = vec![0, 0, 4, 1];
        v.extend_from_slice(b"Unauthorized");
        m.push_attr(attr_type::ERROR_CODE, v);
        m.push_attr(attr_type::REALM, self.realm.as_bytes().to_vec());
        m.push_attr(attr_type::NONCE, self.nonce.as_bytes().to_vec());
        m
    }
    pub fn relayed_address(&self, client: &SocketAddr) -> Option<SocketAddr> {
        self.allocations.get(client).map(|a| a.relayed)
    }
    pub fn allocation_count(&self) -> usize {
        // dbg counter
        self.allocations.len()
    }
    pub fn handle(&mut self, data: &[u8], src: SocketAddr, now: u64) -> HandleOutcome {
        // ChannelData (top bits 01) is not STUN-framed.
        if data.len() >= 4 && (data[0] >> 6) == 0b01 {
            return self.on_channel_data(data, src, now);
        }
        let Some(msg) = StunMessage::decode(data) else {
            return HandleOutcome::Drop;
        };
        self.allocations.retain(|_, a| a.expires_at > now);
        // Long-term auth on every TURN method (Binding is exempt).
        let auth_key = if msg.method != method::BINDING && msg.class == Class::Request {
            match self.check_auth(data, &msg, now) {
                Ok(k) => k,
                Err(m) => return HandleOutcome::Response(m.encode()),
            }
        } else {
            None
        };
        let out = self.dispatch(&msg, src, now);
        // Sign successful/error responses when auth is in use.
        if let (Some(key), HandleOutcome::Response(bytes)) = (auth_key, &out) {
            if StunMessage::decode(bytes).map(|m| m.method) == Some(msg.method)
                && msg.method != method::BINDING
            {
                let _ = key; // responses are signed inside dispatch via respond()
            }
            let _ = bytes;
        }
        out
    }
    fn respond(&self, msg: StunMessage, req: &StunMessage) -> HandleOutcome {
        // Attach integrity if the request was authenticated, under
        // either auth mode. REST (issuer-credential) responses were
        // previously unsigned - browsers ignore unauthenticated
        // Allocate successes and retransmit the request forever.
        if let Some(key) = self.auth_key(req) {
            return HandleOutcome::Response(sign_integrity(msg, &key));
        }
        HandleOutcome::Response(msg.encode())
    }
    fn dispatch(&mut self, msg: &StunMessage, src: SocketAddr, now: u64) -> HandleOutcome {
        match (msg.method, msg.class) {
            (method::ALLOCATE, Class::Request) => self.on_allocate(msg, src, now),
            (method::REFRESH, Class::Request) => self.on_refresh(msg, src, now),
            (method::CREATE_PERMISSION, Class::Request) => self.on_permission(msg, src),
            (method::CHANNEL_BIND, Class::Request) => self.on_channel_bind(msg, src),
            (method::SEND, Class::Indication) => self.on_send(msg, src),
            (method::BINDING, Class::Request) => {
                let mut r = StunMessage::new(method::BINDING, Class::Success, msg.transaction);
                r.push_attr(
                    attr_type::XOR_MAPPED_ADDRESS,
                    xor_addr(src, &msg.transaction),
                );
                HandleOutcome::Response(r.encode())
            }
            _ => HandleOutcome::Drop,
        }
    }
    fn on_allocate(&mut self, msg: &StunMessage, src: SocketAddr, now: u64) -> HandleOutcome {
        if std::env::var_os("TURN_DEBUG").is_some() {
            eprintln!(
                "turn-alloc from {src} has_alloc={} relayed={:?}",
                self.allocations.contains_key(&src),
                self.allocations.get(&src).map(|a| a.relayed)
            );
        }
        // REQUESTED-TRANSPORT must be UDP (17); TCP relay is refused.
        match msg.attr(attr_type::REQUESTED_TRANSPORT) {
            Some(v) if v.first() == Some(&17) => {}
            _ => {
                return self.respond(
                    err_response(msg, 442, "Unsupported transport protocol"),
                    msg,
                )
            }
        }
        // Idempotent: a retransmitted Allocate from the same client must
        // return the same relayed address (RFC 8656; strict ICE stacks
        // discard allocations whose address changes across retries).
        if let Some(a) = self.allocations.get(&src) {
            let relayed = a.relayed;
            let mut r = StunMessage::new(method::ALLOCATE, Class::Success, msg.transaction);
            r.push_attr(
                attr_type::XOR_RELAYED_ADDRESS,
                xor_addr(relayed, &msg.transaction),
            );
            r.push_attr(
                attr_type::XOR_MAPPED_ADDRESS,
                xor_addr(src, &msg.transaction),
            );
            r.push_attr(attr_type::SOFTWARE, b"turn-dag".to_vec());
            r.push_attr(
                attr_type::LIFETIME,
                (self.max_lifetime_secs as u32).to_be_bytes().to_vec(),
            );
            return self.respond(r, msg);
        }
        // total-quota (486 when full) + one live allocation per
        // issuer ticket. Static-credential allocations are exempt
        // from the per-ticket rule (one user may hold many PCs).
        let ticket = msg
            .attr(attr_type::USERNAME)
            .and_then(|v| std::str::from_utf8(v).ok())
            .and_then(crate::parse_username)
            .map(|(_, t)| t);
        if ticket.is_some() && self.allocations.values().any(|a| a.ticket == ticket) {
            return self.respond(err_response(msg, 486, "Allocation Quota Reached"), msg);
        }
        if self.allocations.len() >= self.max_allocations {
            return self.respond(err_response(msg, 486, "Allocation Quota Reached"), msg);
        }
        let relayed = SocketAddr::new(self.server_ip, self.next_port);
        self.next_port = self.next_port.wrapping_add(1).max(49152);
        self.allocations.insert(
            src,
            Allocation {
                relayed,
                expires_at: now + self.max_lifetime_secs,
                permissions: HashSet::new(),
                channels: HashMap::new(),
                bytes: 0,
                ticket,
            },
        );
        let mut r = StunMessage::new(method::ALLOCATE, Class::Success, msg.transaction);
        r.push_attr(
            attr_type::XOR_RELAYED_ADDRESS,
            xor_addr(relayed, &msg.transaction),
        );
        r.push_attr(
            attr_type::XOR_MAPPED_ADDRESS,
            xor_addr(src, &msg.transaction),
        );
        r.push_attr(attr_type::SOFTWARE, b"turn-dag".to_vec());
        r.push_attr(
            attr_type::LIFETIME,
            (self.max_lifetime_secs as u32).to_be_bytes().to_vec(),
        );
        self.respond(r, msg)
    }
    fn on_refresh(&mut self, msg: &StunMessage, src: SocketAddr, now: u64) -> HandleOutcome {
        let lifetime = msg
            .attr(attr_type::LIFETIME)
            .filter(|v| v.len() >= 4)
            .map(|v| u32::from_be_bytes(v[..4].try_into().unwrap()) as u64)
            .unwrap_or(self.max_lifetime_secs);
        if lifetime == 0 {
            self.allocations.remove(&src);
        } else if let Some(a) = self.allocations.get_mut(&src) {
            a.expires_at = now + lifetime.min(self.max_lifetime_secs);
        } else {
            return self.respond(err_response(msg, 437, "Allocation Mismatch"), msg);
        }
        let mut r = StunMessage::new(method::REFRESH, Class::Success, msg.transaction);
        r.push_attr(
            attr_type::LIFETIME,
            (lifetime.min(self.max_lifetime_secs) as u32)
                .to_be_bytes()
                .to_vec(),
        );
        self.respond(r, msg)
    }
    fn is_internal_relayed(&self, addr: SocketAddr) -> bool {
        // Our own allocation endpoint (server_ip + allocated port) or an
        // existing allocation's relayed address.
        self.allocations.values().any(|a| a.relayed == addr)
            || (addr.ip() == self.server_ip && addr.port() >= 49152)
    }
    fn peer_of(&self, msg: &StunMessage) -> Option<SocketAddr> {
        unxor_addr(msg.attr(attr_type::XOR_PEER_ADDRESS)?, &msg.transaction)
    }
    fn on_permission(&mut self, msg: &StunMessage, src: SocketAddr) -> HandleOutcome {
        let Some(peer) = self.peer_of(msg) else {
            return self.respond(err_response(msg, 400, "Bad Request"), msg);
        };
        if is_denied_peer_ip(peer.ip()) && !self.is_internal_relayed(peer) {
            return self.respond(err_response(msg, 403, "Forbidden"), msg);
        }
        match self.allocations.get_mut(&src) {
            Some(a) => {
                a.permissions.insert(peer.ip());
                self.respond(
                    StunMessage::new(method::CREATE_PERMISSION, Class::Success, msg.transaction),
                    msg,
                )
            }
            None => self.respond(err_response(msg, 437, "Allocation Mismatch"), msg),
        }
    }
    fn on_channel_bind(&mut self, msg: &StunMessage, src: SocketAddr) -> HandleOutcome {
        let chan = msg
            .attr(attr_type::CHANNEL_NUMBER)
            .filter(|v| v.len() >= 2)
            .map(|v| u16::from_be_bytes(v[..2].try_into().unwrap()));
        let (Some(chan), Some(peer)) = (chan, self.peer_of(msg)) else {
            return self.respond(err_response(msg, 400, "Bad Request"), msg);
        };
        if !(0x4000..=0xFFFE).contains(&chan) {
            return self.respond(err_response(msg, 400, "Bad channel"), msg);
        }
        if is_denied_peer_ip(peer.ip()) && !self.is_internal_relayed(peer) {
            return self.respond(err_response(msg, 403, "Forbidden"), msg);
        }
        match self.allocations.get_mut(&src) {
            Some(a) => {
                a.channels.insert(chan, peer);
                self.respond(
                    StunMessage::new(method::CHANNEL_BIND, Class::Success, msg.transaction),
                    msg,
                )
            }
            None => self.respond(err_response(msg, 437, "Allocation Mismatch"), msg),
        }
    }
    fn on_send(&mut self, msg: &StunMessage, src: SocketAddr) -> HandleOutcome {
        let (Some(peer), Some(payload)) = (self.peer_of(msg), msg.attr(attr_type::DATA)) else {
            return HandleOutcome::Drop;
        };
        let payload = payload.to_vec();
        self.deliver(src, peer, &payload, msg.transaction)
    }
    /// Relay one payload from `src` toward `peer`. If `peer` is another
    /// allocation's relayed address, deliver to that client (ChannelData
    /// when it bound a channel to the sender, else a Data indication);
    /// otherwise forward externally toward the peer itself.
    fn deliver(
        &mut self,
        src: SocketAddr,
        peer: SocketAddr,
        payload: &[u8],
        txn: [u8; 12],
    ) -> HandleOutcome {
        let Some(sender) = self.allocations.get(&src).cloned() else {
            return HandleOutcome::Drop;
        };
        if !sender.permissions.contains(&peer.ip()) && !self.is_internal_relayed(peer) {
            return HandleOutcome::Drop;
        }
        if self.is_internal_relayed(peer) {
            // Internal relay: permission is checked on the recipient for
            // the sender's relayed address below; the sender needs either
            // a permission or a channel toward the target.
            let has_chan = sender.channels.values().any(|p| *p == peer);
            if !has_chan && !sender.permissions.contains(&peer.ip()) {
                return HandleOutcome::Drop;
            }
        } else if is_denied_peer_ip(peer.ip()) {
            return HandleOutcome::Drop;
        }
        // Recipient allocation (internal relay)?
        let recipient = self
            .allocations
            .iter()
            .find(|(_, a)| a.relayed == peer)
            .map(|(c, a)| (*c, a.clone()));
        if let Some((rclient, ralloc)) = recipient {
            if !ralloc.permissions.contains(&sender.relayed.ip()) {
                return HandleOutcome::Drop;
            }
            let total = sender.bytes + ralloc.bytes + payload.len() as u64;
            if total > self.byte_cap * 2 {
                return HandleOutcome::Drop;
            }
            if let Some(a) = self.allocations.get_mut(&src) {
                a.bytes += payload.len() as u64;
            }
            if let Some(a) = self.allocations.get_mut(&rclient) {
                a.bytes += payload.len() as u64;
            }
            // Prefer the recipient's channel bound to the sender.
            let back = ralloc
                .channels
                .iter()
                .find(|(_, p)| **p == sender.relayed)
                .map(|(c, _)| *c);
            return match back {
                Some(chan) => HandleOutcome::Forward {
                    peer: rclient,
                    data: encode_channel_data(chan, payload),
                },
                None => {
                    let mut d = StunMessage::new(method::DATA, Class::Indication, txn);
                    d.push_attr(attr_type::XOR_PEER_ADDRESS, xor_addr(sender.relayed, &txn));
                    d.push_attr(attr_type::DATA, payload.to_vec());
                    HandleOutcome::Forward {
                        peer: rclient,
                        data: d.encode(),
                    }
                }
            };
        }
        // External peer.
        if sender.bytes + payload.len() as u64 > self.byte_cap {
            return HandleOutcome::Drop;
        }
        if let Some(a) = self.allocations.get_mut(&src) {
            a.bytes += payload.len() as u64;
        }
        let mut d = StunMessage::new(method::DATA, Class::Indication, txn);
        d.push_attr(attr_type::XOR_PEER_ADDRESS, xor_addr(src, &txn));
        d.push_attr(attr_type::DATA, payload.to_vec());
        HandleOutcome::Forward {
            peer,
            data: d.encode(),
        }
    }
    fn on_channel_data(&mut self, data: &[u8], src: SocketAddr, now: u64) -> HandleOutcome {
        self.allocations.retain(|_, a| a.expires_at > now);
        let chan = u16::from_be_bytes(data[0..2].try_into().unwrap());
        let len = u16::from_be_bytes(data[2..4].try_into().unwrap()) as usize;
        if data.len() < 4 + len {
            return HandleOutcome::Drop;
        }
        let payload = data[4..4 + len].to_vec();
        let Some(peer) = self
            .allocations
            .get(&src)
            .and_then(|a| a.channels.get(&chan).copied())
        else {
            return HandleOutcome::Drop;
        };
        self.deliver(src, peer, &payload, [0u8; 12])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn txn() -> [u8; 12] {
        [9u8; 12]
    }
    fn client() -> SocketAddr {
        "203.0.113.7:5000".parse().unwrap()
    }
    fn allocate_req() -> Vec<u8> {
        let mut m = StunMessage::new(method::ALLOCATE, Class::Request, txn());
        m.push_attr(attr_type::REQUESTED_TRANSPORT, vec![17, 0, 0, 0]);
        m.encode()
    }
    fn peer_attr(ip: &str) -> Vec<u8> {
        let a: SocketAddr = ip.parse().unwrap();
        xor_addr(a, &txn())
    }
    fn server() -> TurnServer {
        TurnServer::new("198.51.100.1".parse().unwrap())
    }
    fn decode_ok(out: HandleOutcome) -> StunMessage {
        match out {
            HandleOutcome::Response(b) => StunMessage::decode(&b).expect("decode response"),
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[test]
    fn stun_type_wire_values_match_rfc8489() {
        // Exact on-the-wire type values (RFC 8489 §6 / RFC 8656):
        // browsers reject success responses encoded as indications.
        assert_eq!(encode_type(method::ALLOCATE, Class::Success), 0x0103);
        assert_eq!(encode_type(method::ALLOCATE, Class::Error), 0x0113);
        assert_eq!(encode_type(method::ALLOCATE, Class::Request), 0x0003);
        assert_eq!(encode_type(method::BINDING, Class::Success), 0x0101);
        assert_eq!(encode_type(method::SEND, Class::Indication), 0x0016);
        assert_eq!(encode_type(method::DATA, Class::Indication), 0x0017);
        for (m, c) in [
            (method::ALLOCATE, Class::Success),
            (method::SEND, Class::Indication),
            (method::REFRESH, Class::Error),
        ] {
            assert_eq!(decode_type(encode_type(m, c)), (m, c));
        }
        assert_eq!(decode_type(0x0103), (method::ALLOCATE, Class::Success));
        assert_eq!(decode_type(0x0016), (method::SEND, Class::Indication));
    }

    #[test]
    fn stun_codec_roundtrip_and_padding() {
        let bytes = allocate_req();
        let m = StunMessage::decode(&bytes).unwrap();
        assert_eq!(m.method, method::ALLOCATE);
        assert_eq!(m.class, Class::Request);
        let re = m.encode();
        let re2 = StunMessage::decode(&re).unwrap();
        let non_fp = |m: &StunMessage| {
            m.attrs
                .iter()
                .filter(|(t, _)| *t != attr_type::FINGERPRINT)
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(non_fp(&re2), non_fp(&m));
        assert!(re2.attr(attr_type::FINGERPRINT).is_none());
        assert_eq!(StunMessage::decode(&bytes[..10]), None);
        assert_eq!(StunMessage::decode(b"not stun at all......"), None);
        let mut bad = bytes.clone();
        bad[3] = 3; // length not multiple of 4
        assert_eq!(StunMessage::decode(&bad), None);
    }

    #[test]
    fn allocate_success_caps_lifetime_at_120() {
        let mut s = server();
        let r = decode_ok(s.handle(&allocate_req(), client(), 1000));
        assert_eq!(r.class, Class::Success);
        let relayed = unxor_addr(r.attr(attr_type::XOR_RELAYED_ADDRESS).unwrap(), &txn()).unwrap();
        assert_eq!(relayed.port(), 49152);
        let life = u32::from_be_bytes(
            r.attr(attr_type::LIFETIME).unwrap()[..4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(life, 120);
        assert_eq!(s.allocation_count(), 1);
        assert_eq!(s.relayed_address(&client()), Some(relayed));
    }

    #[test]
    fn allocate_tcp_transport_refused_442() {
        let mut s = server();
        let mut m = StunMessage::new(method::ALLOCATE, Class::Request, txn());
        m.push_attr(attr_type::REQUESTED_TRANSPORT, vec![6, 0, 0, 0]);
        let r = decode_ok(s.handle(&m.encode(), client(), 0));
        assert_eq!(r.class, Class::Error);
        assert_eq!(error_code(&r), Some(442));
        assert_eq!(s.allocation_count(), 0);
    }

    #[test]
    fn total_quota_486_and_ticket_single_allocation() {
        let mut s = server().with_max_allocations(2);
        let c2: SocketAddr = "203.0.113.8:5000".parse().unwrap();
        let c3: SocketAddr = "203.0.113.9:5000".parse().unwrap();
        assert_eq!(
            decode_ok(s.handle(&allocate_req(), client(), 0)).class,
            Class::Success
        );
        assert_eq!(
            decode_ok(s.handle(&allocate_req(), c2, 0)).class,
            Class::Success
        );
        let third = decode_ok(s.handle(&allocate_req(), c3, 0));
        assert_eq!(error_code(&third), Some(486));
        assert_eq!(s.allocation_count(), 2);
        // Same ticket from a second client: 486 even under total quota.
        let mut s2 = TurnServer::new("198.51.100.1".parse().unwrap())
            .with_rest_auth(b"quota-secret".to_vec())
            .with_burn_tickets(vec!["tick1".to_string()]);
        let alloc_with = |user: &str| {
            let mut m = StunMessage::new(method::ALLOCATE, Class::Request, txn());
            m.push_attr(attr_type::REQUESTED_TRANSPORT, vec![17, 0, 0, 0]);
            m.push_attr(attr_type::USERNAME, user.as_bytes().to_vec());
            m.push_attr(attr_type::REALM, b"turn-dag".to_vec());
            m.push_attr(attr_type::NONCE, b"n".to_vec());
            let pass = crate::credential_password(b"quota-secret", user);
            sign_wire(m, Some(&integrity_key(user, "turn-dag", &pass)))
        };
        let user = "9999999999:pow:tick1";
        assert_eq!(
            decode_ok(s2.handle(&alloc_with(user), client(), 100)).class,
            Class::Success
        );
        let dup = decode_ok(s2.handle(&alloc_with(user), c2, 100));
        assert_eq!(error_code(&dup), Some(486));
    }

    #[test]
    fn refresh_zero_deletes_and_unknown_refresh_437() {
        let mut s = server();
        let unknown = decode_ok(s.handle(
            &{
                let mut m = StunMessage::new(method::REFRESH, Class::Request, txn());
                m.push_attr(attr_type::LIFETIME, 60u32.to_be_bytes().to_vec());
                m.encode()
            },
            client(),
            0,
        ));
        assert_eq!(error_code(&unknown), Some(437));
        decode_ok(s.handle(&allocate_req(), client(), 0));
        let mut m = StunMessage::new(method::REFRESH, Class::Request, txn());
        m.push_attr(attr_type::LIFETIME, 0u32.to_be_bytes().to_vec());
        decode_ok(s.handle(&m.encode(), client(), 10));
        assert_eq!(s.allocation_count(), 0);
    }

    #[test]
    fn permission_and_channel_bind_block_metadata_ip() {
        let mut s = server();
        decode_ok(s.handle(&allocate_req(), client(), 0));
        for ip in ["169.254.169.254:80", "10.0.0.5:80", "[::1]:80"] {
            let mut m = StunMessage::new(method::CREATE_PERMISSION, Class::Request, txn());
            m.push_attr(attr_type::XOR_PEER_ADDRESS, peer_attr(ip));
            let r = decode_ok(s.handle(&m.encode(), client(), 1));
            assert_eq!(error_code(&r), Some(403), "{ip}");
        }
        let mut ok = StunMessage::new(method::CREATE_PERMISSION, Class::Request, txn());
        ok.push_attr(attr_type::XOR_PEER_ADDRESS, peer_attr("8.8.8.8:53"));
        assert_eq!(
            decode_ok(s.handle(&ok.encode(), client(), 1)).class,
            Class::Success
        );
        let mut cb = StunMessage::new(method::CHANNEL_BIND, Class::Request, txn());
        cb.push_attr(attr_type::CHANNEL_NUMBER, 0x4001u16.to_be_bytes().to_vec());
        cb.push_attr(attr_type::XOR_PEER_ADDRESS, peer_attr("8.8.8.8:53"));
        assert_eq!(
            decode_ok(s.handle(&cb.encode(), client(), 1)).class,
            Class::Success
        );
        let mut bad_chan = StunMessage::new(method::CHANNEL_BIND, Class::Request, txn());
        bad_chan.push_attr(attr_type::CHANNEL_NUMBER, 0x0001u16.to_be_bytes().to_vec());
        bad_chan.push_attr(attr_type::XOR_PEER_ADDRESS, peer_attr("8.8.8.8:53"));
        assert_eq!(
            error_code(&decode_ok(s.handle(&bad_chan.encode(), client(), 1))),
            Some(400)
        );
    }

    #[test]
    fn send_requires_permission_and_forwards_data() {
        let mut s = server();
        decode_ok(s.handle(&allocate_req(), client(), 0));
        let mut send = StunMessage::new(method::SEND, Class::Indication, txn());
        send.push_attr(attr_type::XOR_PEER_ADDRESS, peer_attr("8.8.8.8:53"));
        send.push_attr(attr_type::DATA, b"ping".to_vec());
        assert_eq!(s.handle(&send.encode(), client(), 1), HandleOutcome::Drop);
        let mut perm = StunMessage::new(method::CREATE_PERMISSION, Class::Request, txn());
        perm.push_attr(attr_type::XOR_PEER_ADDRESS, peer_attr("8.8.8.8:53"));
        decode_ok(s.handle(&perm.encode(), client(), 1));
        match s.handle(&send.encode(), client(), 2) {
            HandleOutcome::Forward { peer, data } => {
                assert_eq!(peer, "8.8.8.8:53".parse::<SocketAddr>().unwrap());
                let d = StunMessage::decode(&data).unwrap();
                assert_eq!(d.method, method::DATA);
                assert_eq!(d.attr(attr_type::DATA), Some(b"ping".as_slice()));
            }
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[test]
    fn expired_allocation_drops_send() {
        let mut s = server();
        decode_ok(s.handle(&allocate_req(), client(), 0));
        let mut perm = StunMessage::new(method::CREATE_PERMISSION, Class::Request, txn());
        perm.push_attr(attr_type::XOR_PEER_ADDRESS, peer_attr("8.8.8.8:53"));
        decode_ok(s.handle(&perm.encode(), client(), 1));
        let mut send = StunMessage::new(method::SEND, Class::Indication, txn());
        send.push_attr(attr_type::XOR_PEER_ADDRESS, peer_attr("8.8.8.8:53"));
        send.push_attr(attr_type::DATA, b"x".to_vec());
        // t=121: allocation (120s from t=0) is expired and pruned.
        assert_eq!(s.handle(&send.encode(), client(), 121), HandleOutcome::Drop);
        assert_eq!(s.allocation_count(), 0);
    }

    #[test]
    fn binding_request_returns_xor_mapped() {
        let mut s = server();
        let m = StunMessage::new(method::BINDING, Class::Request, txn());
        let r = decode_ok(s.handle(&m.encode(), client(), 0));
        let mapped = unxor_addr(r.attr(attr_type::XOR_MAPPED_ADDRESS).unwrap(), &txn()).unwrap();
        assert_eq!(mapped, client());
    }

    #[test]
    fn signed_allocate_response_carries_valid_fingerprint() {
        let mut s = auth_server();
        let nonce = s.nonce.clone();
        let raw = signed_allocate("alice", "wonderland", &nonce);
        match s.handle(&raw, client(), 0) {
            HandleOutcome::Response(bytes) => {
                let m = StunMessage::decode(&bytes).unwrap();
                assert_eq!(m.class, Class::Success);
                let fp = m.attr(attr_type::FINGERPRINT).unwrap();
                let n = bytes.len();
                // RFC 8489 §14.7: CRC over the message up to (but
                // excluding) the FINGERPRINT attribute itself.
                let expect = (crc32(&bytes[..n - 8]) ^ 0x5354_554E).to_be_bytes();
                assert_eq!(fp, expect.as_slice());
                assert_eq!(bytes[n - 4..n].to_vec(), expect.to_vec());
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }
    #[test]
    fn rest_auth_accepts_issuer_credential_and_rejects_expired() {
        let secret = b"issuer-secret".to_vec();
        let mut s = TurnServer::new("127.0.0.1".parse().unwrap()).with_rest_auth(secret.clone());
        // Issuer-shaped username: expiry:pow:ticket.
        let now = 1_000u64;
        let username = format!("{}:pow:ticket-1", now + 120);
        let password = crate::credential_password(&secret, &username);
        let nonce = s.nonce.clone();
        let mut m = StunMessage::new(method::ALLOCATE, Class::Request, txn());
        m.push_attr(attr_type::REQUESTED_TRANSPORT, vec![17, 0, 0, 0]);
        m.push_attr(attr_type::USERNAME, username.as_bytes().to_vec());
        m.push_attr(attr_type::REALM, b"turn-dag".to_vec());
        m.push_attr(attr_type::NONCE, nonce.as_bytes().to_vec());
        let raw = sign_wire(m, Some(&integrity_key(&username, "turn-dag", &password)));
        match s.handle(&raw, client(), now) {
            HandleOutcome::Response(b) => {
                let r = StunMessage::decode(&b).unwrap();
                assert_eq!(r.class, Class::Success, "{r:?}");
                // REST successes must be signed like static ones, or
                // browsers ignore them and retransmit.
                assert!(
                    r.attr(attr_type::MESSAGE_INTEGRITY).is_some(),
                    "REST allocate success must carry MESSAGE-INTEGRITY"
                );
                assert!(verify_integrity(
                    &b,
                    &integrity_key(&username, "turn-dag", &password)
                ));
            }
            other => panic!("expected allocate success, got {other:?}"),
        }
        // Expired credential (now past expiry) gets 401.
        let raw2 = sign_wire(
            {
                let mut m = StunMessage::new(method::ALLOCATE, Class::Request, txn());
                m.push_attr(attr_type::REQUESTED_TRANSPORT, vec![17, 0, 0, 0]);
                m.push_attr(attr_type::USERNAME, username.as_bytes().to_vec());
                m.push_attr(attr_type::REALM, b"turn-dag".to_vec());
                m.push_attr(attr_type::NONCE, nonce.as_bytes().to_vec());
                m
            },
            Some(&integrity_key(&username, "turn-dag", &password)),
        );
        let out = s.handle(&raw2, client(), now + 200);
        assert_eq!(error_code(&decode_ok(out)), Some(401));
        // Wrong secret fails integrity.
        let other = {
            let mut m = StunMessage::new(method::ALLOCATE, Class::Request, txn());
            m.push_attr(attr_type::REQUESTED_TRANSPORT, vec![17, 0, 0, 0]);
            m.push_attr(attr_type::USERNAME, username.as_bytes().to_vec());
            m.push_attr(attr_type::REALM, b"turn-dag".to_vec());
            m.push_attr(attr_type::NONCE, nonce.as_bytes().to_vec());
            m
        };
        let bad = sign_wire(other, Some(&integrity_key(&username, "turn-dag", "forged")));
        let out = s.handle(&bad, client(), now);
        assert_eq!(error_code(&decode_ok(out)), Some(401));
    }
    #[test]
    fn burn_gate_allows_only_confirmed_tickets() {
        // No gate: REST ticket works.
        let secret = b"issuer-secret".to_vec();
        let username = "1120:pow:ticket-9";
        let password = crate::credential_password(&secret, username);
        let build = |tickets: Option<Vec<String>>| {
            let mut s =
                TurnServer::new("127.0.0.1".parse().unwrap()).with_rest_auth(secret.clone());
            if let Some(t) = tickets {
                s = s.with_burn_tickets(t);
            }
            s
        };
        let signed = |s: &TurnServer, user: &str, pass: &str| {
            let mut m = StunMessage::new(method::ALLOCATE, Class::Request, txn());
            m.push_attr(attr_type::REQUESTED_TRANSPORT, vec![17, 0, 0, 0]);
            m.push_attr(attr_type::USERNAME, user.as_bytes().to_vec());
            m.push_attr(attr_type::REALM, b"turn-dag".to_vec());
            m.push_attr(attr_type::NONCE, s_nonces(s, user).as_bytes().to_vec());
            sign_wire(m, Some(&integrity_key(user, "turn-dag", pass)))
        };
        fn s_nonces(s: &TurnServer, _u: &str) -> String {
            // nonce is derived from server_ip + realm; recompute identically.
            format!("{:016x}", {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(s.server_ip.to_string().as_bytes());
                h.update(s.realm.as_bytes());
                u64::from_be_bytes(h.finalize()[..8].try_into().unwrap())
            })
        }
        // Ungated: succeeds.
        let mut open = build(None);
        let raw = signed(&open, username, &password);
        assert!(matches!(
            open.handle(&raw, client(), 1000),
            HandleOutcome::Response(_)
        ));
        // Gated, ticket NOT in set (unconfirmed burn): 401.
        let mut gated = build(Some(vec!["other-ticket".into()]));
        let raw = signed(&gated, username, &password);
        assert_eq!(
            error_code(&decode_ok(gated.handle(&raw, client(), 1000))),
            Some(401)
        );
        // Gated, ticket IS in set (confirmed burn): proceeds.
        let mut gated2 = build(Some(vec!["ticket-9".into()]));
        let raw = signed(&gated2, username, &password);
        match gated2.handle(&raw, client(), 1000) {
            HandleOutcome::Response(b) => {
                let r = StunMessage::decode(&b).unwrap();
                assert_eq!(r.class, Class::Success);
            }
            other => panic!("expected success, got {other:?}"),
        }
    }
    fn auth_server() -> TurnServer {
        let mut creds = std::collections::HashMap::new();
        creds.insert("alice".to_string(), "wonderland".to_string());
        TurnServer::new("127.0.0.1".parse().unwrap()).with_auth("turn-dag", creds)
    }
    fn signed_allocate(user: &str, pass: &str, nonce: &str) -> Vec<u8> {
        let mut m = StunMessage::new(method::ALLOCATE, Class::Request, txn());
        m.push_attr(attr_type::REQUESTED_TRANSPORT, vec![17, 0, 0, 0]);
        m.push_attr(attr_type::USERNAME, user.as_bytes().to_vec());
        m.push_attr(attr_type::REALM, b"turn-dag".to_vec());
        m.push_attr(attr_type::NONCE, nonce.as_bytes().to_vec());
        sign_wire(m, Some(&integrity_key(user, "turn-dag", pass)))
    }

    #[test]
    fn auth_challenge_then_signed_allocate() {
        let mut s = auth_server();
        // Unsigned allocate gets 401 with realm+nonce.
        let r = decode_ok(s.handle(&allocate_req(), client(), 0));
        assert_eq!(r.class, Class::Error);
        assert_eq!(error_code(&r), Some(401));
        let _nonce = String::from_utf8(r.attr(attr_type::NONCE).unwrap().to_vec()).unwrap();
        assert_eq!(r.attr(attr_type::REALM), Some(b"turn-dag".as_slice()));
        // Wrong password fails integrity -> 401 again.
        let bad = signed_allocate("alice", "wrong", &s.nonce);
        assert_eq!(
            error_code(&decode_ok(s.handle(&bad, client(), 0))),
            Some(401)
        );
        assert_eq!(s.allocation_count(), 0);
        // Correctly signed allocate succeeds and response is signed.
        let good = signed_allocate("alice", "wonderland", &s.nonce);
        match s.handle(&good, client(), 0) {
            HandleOutcome::Response(bytes) => {
                let key = integrity_key("alice", "turn-dag", "wonderland");
                assert!(verify_integrity(&bytes, &key), "response integrity");
                let m = StunMessage::decode(&bytes).unwrap();
                assert_eq!(m.class, Class::Success);
            }
            other => panic!("expected Response, got {other:?}"),
        }
        assert_eq!(s.allocation_count(), 1);
    }

    #[test]
    fn relay_between_two_allocations_via_channel_data() {
        let mut s = TurnServer::new("127.0.0.1".parse().unwrap());
        let a: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:40002".parse().unwrap();
        decode_ok(s.handle(&allocate_req(), a, 0));
        decode_ok(s.handle(&allocate_req(), b, 0));
        let ra = s.relayed_address(&a).unwrap();
        let rb = s.relayed_address(&b).unwrap();
        // Each side creates a permission for the other's relayed address.
        for (src, peer) in [(a, rb), (b, ra)] {
            let mut m = StunMessage::new(method::CREATE_PERMISSION, Class::Request, txn());
            m.push_attr(attr_type::XOR_PEER_ADDRESS, xor_addr(peer, &txn()));
            assert_eq!(
                decode_ok(s.handle(&m.encode(), src, 1)).class,
                Class::Success
            );
        }
        // B binds channel 0x4001 to A's relayed address; A sends via Send.
        let mut cb = StunMessage::new(method::CHANNEL_BIND, Class::Request, txn());
        cb.push_attr(attr_type::CHANNEL_NUMBER, 0x4001u16.to_be_bytes().to_vec());
        cb.push_attr(attr_type::XOR_PEER_ADDRESS, xor_addr(ra, &txn()));
        assert_eq!(
            decode_ok(s.handle(&cb.encode(), b, 1)).class,
            Class::Success
        );
        let mut send = StunMessage::new(method::SEND, Class::Indication, txn());
        send.push_attr(attr_type::XOR_PEER_ADDRESS, xor_addr(rb, &txn()));
        send.push_attr(attr_type::DATA, b"hello-b".to_vec());
        match s.handle(&send.encode(), a, 2) {
            HandleOutcome::Forward { peer, data } => {
                assert_eq!(peer, b);
                let (chan, payload) = decode_channel_data(&data).unwrap();
                assert_eq!(chan, 0x4001);
                assert_eq!(payload, b"hello-b");
            }
            other => panic!("expected Forward to B, got {other:?}"),
        }
        // B replies with ChannelData on its bound channel.
        match s.handle(&encode_channel_data(0x4001, b"hello-a"), b, 3) {
            HandleOutcome::Forward { peer, data } => {
                assert_eq!(peer, a);
                let d = StunMessage::decode(&data).unwrap();
                assert_eq!(d.method, method::DATA);
                assert_eq!(d.attr(attr_type::DATA), Some(b"hello-a".as_slice()));
            }
            other => panic!("expected Forward to A, got {other:?}"),
        }
        // Truncated channel data is dropped, never panics.
        assert_eq!(s.handle(&[0x40, 0x01, 0xFF], a, 4), HandleOutcome::Drop);
    }
}

#[cfg(test)]
mod allocate_idempotency_tests {
    use super::*;
    fn txn() -> [u8; 12] {
        [9u8; 12]
    }
    fn client() -> SocketAddr {
        "203.0.113.7:5000".parse().unwrap()
    }
    #[test]
    fn allocate_reuses_relayed_address() {
        let mut s = TurnServer::new("127.0.0.1".parse().unwrap());
        let mut m = StunMessage::new(method::ALLOCATE, Class::Request, txn());
        m.push_attr(attr_type::REQUESTED_TRANSPORT, vec![17, 0, 0, 0]);
        let raw = m.encode();
        let get_port = |s: &mut TurnServer| match s.handle(&raw, client(), 0) {
            HandleOutcome::Response(b) => {
                let r = StunMessage::decode(&b).unwrap();
                let v = r.attr(attr_type::XOR_RELAYED_ADDRESS).unwrap();
                u16::from_be_bytes(v[2..4].try_into().unwrap()) ^ (STUN_MAGIC >> 16) as u16
            }
            _ => panic!("response"),
        };
        assert_eq!(get_port(&mut s), 49152);
        assert_eq!(get_port(&mut s), 49152);
        assert_eq!(get_port(&mut s), 49152);
        assert_eq!(s.allocation_count(), 1);
    }
}

// Deterministic mutation sweep (no fuzzing framework needed): every
// truncation and every single-bit flip of a valid datagram must be
// handled without panicking and without accepting garbage.
#[cfg(test)]
mod mutation_tests {
    use super::*;
    fn seed_allocate() -> Vec<u8> {
        let mut m = StunMessage::new(method::ALLOCATE, Class::Request, [3u8; 12]);
        m.push_attr(attr_type::REQUESTED_TRANSPORT, vec![17, 0, 0, 0]);
        m.push_attr(attr_type::USERNAME, b"alice".to_vec());
        m.encode()
    }
    #[test]
    fn truncations_never_panic_and_never_accept() {
        let seed = seed_allocate();
        let mut s = TurnServer::new("127.0.0.1".parse().unwrap());
        let src: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        for n in 0..seed.len() {
            let out = s.handle(&seed[..n], src, 0);
            // Truncated datagrams may drop or error, never succeed or panic.
            match out {
                HandleOutcome::Response(b) => {
                    let m = StunMessage::decode(&b).expect("response decodes");
                    assert_eq!(m.class, Class::Error, "n={n} must not succeed");
                }
                HandleOutcome::Forward { .. } => panic!("truncated forward n={n}"),
                HandleOutcome::Drop => {}
            }
        }
    }
    #[test]
    fn single_bit_flips_never_panic() {
        let seed = seed_allocate();
        let mut s = TurnServer::new("127.0.0.1".parse().unwrap());
        let src: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        for i in 0..seed.len() {
            for bit in [0u8, 3, 7] {
                let mut bad = seed.clone();
                bad[i] ^= 1 << bit;
                let _ = s.handle(&bad, src, 0);
                let _ = StunMessage::decode(&bad);
            }
        }
    }
    #[test]
    fn garbage_and_random_inputs_never_panic() {
        let mut s = TurnServer::new("127.0.0.1".parse().unwrap());
        let src: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let mut x: u64 = 0x1234_5678_9ABC_DEF0;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..2000 {
            let len = (next() % 64) as usize;
            let mut buf = vec![0u8; len];
            for b in buf.iter_mut() {
                *b = next() as u8;
            }
            let _ = s.handle(&buf, src, 0);
            let _ = StunMessage::decode(&buf);
            let _ = decode_channel_data(&buf);
        }
        // All-zero and all-ones extremes.
        for buf in [vec![0u8; 64], vec![0xFFu8; 64], vec![0x40u8; 64]] {
            let _ = s.handle(&buf, src, 0);
        }
    }
}
