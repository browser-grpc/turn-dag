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
    let (b4, b8) = match class {
        Class::Request => (0, 0),
        Class::Indication => (0, 1),
        Class::Success => (1, 0),
        Class::Error => (1, 1),
    };
    (method & 0x000F) | ((method & 0x0070) << 1) | ((method & 0x0F80) << 2) | (b4 << 4) | (b8 << 8)
}
pub fn decode_type(t: u16) -> (u16, Class) {
    let method = (t & 0x000F) | ((t >> 1) & 0x0070) | ((t >> 2) & 0x0F80);
    let class = match ((t >> 4) & 1, (t >> 8) & 1) {
        (0, 0) => Class::Request,
        (0, 1) => Class::Indication,
        (1, 0) => Class::Success,
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
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        for (t, v) in &self.attrs {
            body.extend_from_slice(&t.to_be_bytes());
            body.extend_from_slice(&(v.len() as u16).to_be_bytes());
            body.extend_from_slice(v);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        let mut out = Vec::with_capacity(20 + body.len());
        out.extend_from_slice(&encode_type(self.method, self.class).to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&STUN_MAGIC.to_be_bytes());
        out.extend_from_slice(&self.transaction);
        out.extend_from_slice(&body);
        out
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandleOutcome {
    Response(Vec<u8>),
    Forward { peer: SocketAddr, data: Vec<u8> },
    Drop,
}

/// Minimal TURN server state machine (no relay sockets of its own:
/// `Forward` tells the stack owner which peer a payload goes to).
pub struct TurnServer {
    server_ip: IpAddr,
    next_port: u16,
    max_lifetime_secs: u64,
    byte_cap: u64,
    allocations: HashMap<SocketAddr, Allocation>,
}
impl TurnServer {
    pub fn new(server_ip: IpAddr) -> Self {
        Self {
            server_ip,
            next_port: 49152,
            max_lifetime_secs: 120,
            byte_cap: 16_384 * 120,
            allocations: HashMap::new(),
        }
    }
    pub fn relayed_address(&self, client: &SocketAddr) -> Option<SocketAddr> {
        self.allocations.get(client).map(|a| a.relayed)
    }
    pub fn allocation_count(&self) -> usize {
        self.allocations.len()
    }
    pub fn handle(&mut self, data: &[u8], src: SocketAddr, now: u64) -> HandleOutcome {
        let Some(msg) = StunMessage::decode(data) else {
            return HandleOutcome::Drop;
        };
        self.allocations.retain(|_, a| a.expires_at > now);
        match (msg.method, msg.class) {
            (method::ALLOCATE, Class::Request) => self.on_allocate(&msg, src, now),
            (method::REFRESH, Class::Request) => self.on_refresh(&msg, src, now),
            (method::CREATE_PERMISSION, Class::Request) => self.on_permission(&msg, src),
            (method::CHANNEL_BIND, Class::Request) => self.on_channel_bind(&msg, src),
            (method::SEND, Class::Indication) => self.on_send(&msg, src),
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
        // REQUESTED-TRANSPORT must be UDP (17); TCP relay is refused.
        match msg.attr(attr_type::REQUESTED_TRANSPORT) {
            Some(v) if v.first() == Some(&17) => {}
            _ => {
                return HandleOutcome::Response(
                    err_response(msg, 442, "Unsupported transport protocol").encode(),
                )
            }
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
        r.push_attr(
            attr_type::LIFETIME,
            (self.max_lifetime_secs as u32).to_be_bytes().to_vec(),
        );
        HandleOutcome::Response(r.encode())
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
            return HandleOutcome::Response(err_response(msg, 437, "Allocation Mismatch").encode());
        }
        let mut r = StunMessage::new(method::REFRESH, Class::Success, msg.transaction);
        r.push_attr(
            attr_type::LIFETIME,
            (lifetime.min(self.max_lifetime_secs) as u32)
                .to_be_bytes()
                .to_vec(),
        );
        HandleOutcome::Response(r.encode())
    }
    fn peer_of(&self, msg: &StunMessage) -> Option<SocketAddr> {
        unxor_addr(msg.attr(attr_type::XOR_PEER_ADDRESS)?, &msg.transaction)
    }
    fn on_permission(&mut self, msg: &StunMessage, src: SocketAddr) -> HandleOutcome {
        let Some(peer) = self.peer_of(msg) else {
            return HandleOutcome::Response(err_response(msg, 400, "Bad Request").encode());
        };
        if is_denied_peer_ip(peer.ip()) {
            return HandleOutcome::Response(err_response(msg, 403, "Forbidden").encode());
        }
        match self.allocations.get_mut(&src) {
            Some(a) => {
                a.permissions.insert(peer.ip());
                HandleOutcome::Response(
                    StunMessage::new(method::CREATE_PERMISSION, Class::Success, msg.transaction)
                        .encode(),
                )
            }
            None => HandleOutcome::Response(err_response(msg, 437, "Allocation Mismatch").encode()),
        }
    }
    fn on_channel_bind(&mut self, msg: &StunMessage, src: SocketAddr) -> HandleOutcome {
        let chan = msg
            .attr(attr_type::CHANNEL_NUMBER)
            .filter(|v| v.len() >= 2)
            .map(|v| u16::from_be_bytes(v[..2].try_into().unwrap()));
        let (Some(chan), Some(peer)) = (chan, self.peer_of(msg)) else {
            return HandleOutcome::Response(err_response(msg, 400, "Bad Request").encode());
        };
        if !(0x4000..=0xFFFE).contains(&chan) {
            return HandleOutcome::Response(err_response(msg, 400, "Bad channel").encode());
        }
        if is_denied_peer_ip(peer.ip()) {
            return HandleOutcome::Response(err_response(msg, 403, "Forbidden").encode());
        }
        match self.allocations.get_mut(&src) {
            Some(a) => {
                a.channels.insert(chan, peer);
                HandleOutcome::Response(
                    StunMessage::new(method::CHANNEL_BIND, Class::Success, msg.transaction)
                        .encode(),
                )
            }
            None => HandleOutcome::Response(err_response(msg, 437, "Allocation Mismatch").encode()),
        }
    }
    fn on_send(&mut self, msg: &StunMessage, src: SocketAddr) -> HandleOutcome {
        let (Some(peer), Some(payload)) = (self.peer_of(msg), msg.attr(attr_type::DATA)) else {
            return HandleOutcome::Drop;
        };
        let Some(a) = self.allocations.get_mut(&src) else {
            return HandleOutcome::Drop;
        };
        if !a.permissions.contains(&peer.ip()) || is_denied_peer_ip(peer.ip()) {
            return HandleOutcome::Drop;
        }
        if a.bytes + payload.len() as u64 > self.byte_cap {
            return HandleOutcome::Drop;
        }
        a.bytes += payload.len() as u64;
        // Wrap payload in a Data indication addressed back via the stack.
        let mut d = StunMessage::new(method::DATA, Class::Indication, msg.transaction);
        d.push_attr(attr_type::XOR_PEER_ADDRESS, xor_addr(src, &msg.transaction));
        d.push_attr(attr_type::DATA, payload.to_vec());
        HandleOutcome::Forward {
            peer,
            data: d.encode(),
        }
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
    fn stun_codec_roundtrip_and_padding() {
        let bytes = allocate_req();
        let m = StunMessage::decode(&bytes).unwrap();
        assert_eq!(m.method, method::ALLOCATE);
        assert_eq!(m.class, Class::Request);
        assert_eq!(m.encode(), bytes);
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
}
