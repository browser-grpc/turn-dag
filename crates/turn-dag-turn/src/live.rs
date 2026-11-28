//! Live TURN service: the wire server over a real UDP socket, and
//! the `turns:` (5349) server over rustls on the smoltcp user-space
//! TCP stack (TUN-backed). UDP stays on ordinary sockets (spec
//! §14.4); the no-kernel-TCP rule only governs TCP, which remains
//! inside the smoltcp stack.
use crate::stack::UserSpaceStack;
use crate::tls::TlsServer;
use crate::wire::{HandleOutcome, TurnServer};
use smoltcp::phy::Device;
use smoltcp::wire::IpAddress;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub struct LiveUdpTurnServer {
    socket: UdpSocket,
    server: TurnServer,
    /// Per-allocation relay sockets for external (non-client) peers.
    relay_sockets: std::collections::HashMap<SocketAddr, UdpSocket>,
}
impl LiveUdpTurnServer {
    pub fn bind(addr: SocketAddr, server: TurnServer) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_read_timeout(Some(Duration::from_millis(250)))?;
        Ok(Self {
            socket,
            server,
            relay_sockets: Default::default(),
        })
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    pub fn allocation_count(&self) -> usize {
        self.server.allocation_count()
    }
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
    /// Handle one pending datagram; Ok(false) on read timeout.
    fn relay_socket(&mut self, relayed: SocketAddr) -> io::Result<&UdpSocket> {
        use std::collections::hash_map::Entry;
        if let Entry::Vacant(slot) = self.relay_sockets.entry(relayed) {
            let sock = UdpSocket::bind(relayed).or_else(|_| {
                let any: SocketAddr = match relayed {
                    SocketAddr::V4(_) => format!("0.0.0.0:{}", relayed.port()).parse().unwrap(),
                    SocketAddr::V6(_) => format!("[::]:{}", relayed.port()).parse().unwrap(),
                };
                UdpSocket::bind(any)
            })?;
            sock.set_nonblocking(true)?;
            slot.insert(sock);
        }
        Ok(&self.relay_sockets[&relayed])
    }

    fn drain_relay_sockets(&mut self) -> io::Result<bool> {
        let mut worked = false;
        let relayed_addrs: Vec<SocketAddr> = self.relay_sockets.keys().copied().collect();
        for relayed in relayed_addrs {
            loop {
                let mut buf = vec![0u8; 65536];
                let got = {
                    let sock = &self.relay_sockets[&relayed];
                    sock.recv_from(&mut buf)
                };
                match got {
                    Ok((n, peer)) => {
                        worked = true;
                        let outcome = self.server.handle_relayed_datagram(
                            relayed,
                            peer,
                            &buf[..n],
                            Self::now(),
                        );
                        if let HandleOutcome::Forward { peer: client, data } = outcome {
                            self.socket.send_to(&data, client)?;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
        }
        // Prune relay sockets whose allocation expired.
        let dead: Vec<SocketAddr> = self
            .relay_sockets
            .keys()
            .filter(|r| !self.server.has_allocation_for_relayed(**r))
            .copied()
            .collect();
        for r in dead {
            self.relay_sockets.remove(&r);
        }
        Ok(worked)
    }

    pub fn serve_once(&mut self) -> io::Result<bool> {
        if self.drain_relay_sockets()? {
            // Still fall through to the control socket below (its
            // 250ms timeout bounds relay-ingress latency).
        }
        let mut buf = [0u8; 2048];
        let (n, src) = match self.socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                return Ok(false)
            }
            Err(e) => return Err(e),
        };
        if std::env::var_os("TURN_DEBUG").is_some() {
            eprintln!(
                "turn-udp recv {n}B from {src}: {}",
                crate::wire::hex_preview(&buf[..n])
            );
        }
        let outcome = self.server.handle(&buf[..n], src, Self::now());
        if std::env::var_os("TURN_DEBUG").is_some() {
            match &outcome {
                HandleOutcome::Response(b) if std::env::var_os("TURN_DUMP_RESP").is_some() => {
                    eprintln!("RESPONSE-FINGERPRINT-VALID {}", hex_bytes(b));
                }
                _ => {}
            }
            match &outcome {
                HandleOutcome::Response(b) => eprintln!(
                    "turn-udp resp {}B: {}",
                    b.len(),
                    crate::wire::hex_preview(b)
                ),
                HandleOutcome::Forward { peer, data } => {
                    eprintln!("turn-udp fwd {peer} {}B", data.len())
                }
                HandleOutcome::ForwardExternal {
                    relayed,
                    peer,
                    payload,
                } => {
                    eprintln!("turn-udp fwd-ext {relayed} -> {peer} {}B", payload.len())
                }
                HandleOutcome::Drop => eprintln!("turn-udp drop"),
            }
        }
        match outcome {
            HandleOutcome::Response(bytes) => {
                self.socket.send_to(&bytes, src)?;
            }
            HandleOutcome::Forward { peer, data } => {
                self.socket.send_to(&data, peer)?;
            }
            HandleOutcome::ForwardExternal {
                relayed,
                peer,
                payload,
            } => {
                let sock = self.relay_socket(relayed)?;
                sock.send_to(&payload, peer)?;
            }
            HandleOutcome::Drop => {}
        }
        Ok(true)
    }
    /// Serve until `stop` returns true (checked between datagrams).
    pub fn serve_until(&mut self, stop: impl Fn() -> bool) -> io::Result<()> {
        while !stop() {
            self.serve_once()?;
        }
        Ok(())
    }
    pub fn into_socket(self) -> UdpSocket {
        self.socket
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Extract one STUN/ChannelData frame from a stream buffer. Over
/// stream transports (TCP/TLS) ChannelData is padded to a 4-byte
/// boundary (RFC 8656 stream framing): consuming it unpadded leaves
/// 1-3 zero bytes that desync every following frame - DTLS starts,
/// then the stream silently blackholes. STUN messages are always
/// a multiple of 4 bytes already. Returns None if more bytes needed.
pub fn take_frame(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buf.len() < 4 {
        return None;
    }
    let total = if buf[0] >> 6 == 0b01 {
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        4 + len + (4 - len % 4) % 4
    } else if buf[0] >> 6 == 0 {
        if buf.len() < 20 {
            return None;
        }
        20 + u16::from_be_bytes([buf[2], buf[3]]) as usize
    } else {
        // Not STUN/ChannelData framing: drop the buffer to resync.
        buf.clear();
        return None;
    };
    if buf.len() < total {
        return None;
    }
    Some(buf.drain(..total).collect())
}

/// Serve one TLS connection (any byte stream: smoltcp TCP in the
/// live server, in-process pipes in tests) until idle. Responses go
/// back on the same connection; forwards to allocations owned by
/// other connections are dropped here (the multi-connection server
/// below routes them).
pub fn serve_tls_stream<S: Read + Write>(
    config: Arc<rustls::ServerConfig>,
    stream: S,
    turn: &mut TurnServer,
    src: SocketAddr,
) -> io::Result<()> {
    let mut tls = TlsServer::new(config, stream)?;
    for _ in 0..1000 {
        match tls.handshake() {
            Ok(()) => break,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2))
            }
            Err(e) => return Err(e),
        }
    }
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut idle_rounds = 0;
    loop {
        match tls.read_app(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                idle_rounds = 0;
                buf.extend_from_slice(&chunk[..n]);
                while let Some(frame) = take_frame(&mut buf) {
                    match turn.handle(&frame, src, now_secs()) {
                        HandleOutcome::Response(bytes) => {
                            tls.write_app(&bytes)?;
                        }
                        HandleOutcome::Forward { data, .. } => {
                            let _ = data;
                        }
                        HandleOutcome::ForwardExternal { .. } => {
                            // Single-stream helper owns no relay sockets.
                        }
                        HandleOutcome::Drop => {}
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                idle_rounds += 1;
                if idle_rounds > 500 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

struct TlsConn {
    handle: smoltcp::iface::SocketHandle,
    /// None = plain TURN/TCP (turn:?transport=tcp); Some = turns:.
    tls: Option<rustls::ServerConnection>,
    plain_in: Vec<u8>,
    cipher_out: Vec<u8>,
    src: SocketAddr,
    dead: bool,
}

/// Live `turns:` server: rustls over smoltcp TCP sockets on a
/// TUN-backed (or any) smoltcp device. Multiple concurrent TLS
/// connections; ChannelData forwards are routed to the connection
/// that owns the recipient allocation. No kernel TCP anywhere.
pub struct LiveTlsTurnServer<D: Device> {
    stack: UserSpaceStack<D>,
    /// None serves plain TURN over TCP; Some serves turns: (TLS).
    config: Option<Arc<rustls::ServerConfig>>,
    turn: TurnServer,
    listeners: Vec<smoltcp::iface::SocketHandle>,
    port: u16,
    conns: Vec<TlsConn>,
    /// Per-allocation smoltcp UDP relay sockets (external peers).
    relay_sockets: std::collections::HashMap<SocketAddr, smoltcp::iface::SocketHandle>,
    now_ms: i64,
}

impl<D: Device> LiveTlsTurnServer<D> {
    pub fn new(
        stack: UserSpaceStack<D>,
        config: Arc<rustls::ServerConfig>,
        turn: TurnServer,
        port: u16,
    ) -> io::Result<Self> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut srv = Self {
            stack,
            config: Some(config),
            turn,
            listeners: Vec::new(),
            port,
            conns: Vec::new(),
            relay_sockets: Default::default(),
            now_ms: 0,
        };
        // A pool of listening sockets: one smoltcp listener captures
        // a single SYN, so simultaneous connects would otherwise RST.
        for _ in 0..4 {
            let h = srv.stack.add_tcp_socket();
            srv.stack
                .tcp_listen(h, port)
                .map_err(|e| io::Error::other(format!("tls listen: {e:?}")))?;
            srv.listeners.push(h);
        }
        Ok(srv)
    }

    /// Plain TURN over TCP (`turn:...?transport=tcp`) on the same
    /// smoltcp/TUN stack - the TCP flavor Firefox initiates (it
    /// never initiates turns:). No TLS wrapping of any kind.
    pub fn new_plain(stack: UserSpaceStack<D>, turn: TurnServer, port: u16) -> io::Result<Self> {
        let mut srv = Self {
            stack,
            config: None,
            turn,
            listeners: Vec::new(),
            port,
            conns: Vec::new(),
            relay_sockets: Default::default(),
            now_ms: 0,
        };
        for _ in 0..4 {
            let h = srv.stack.add_tcp_socket();
            srv.stack
                .tcp_listen(h, port)
                .map_err(|e| io::Error::other(format!("tcp listen: {e:?}")))?;
            srv.listeners.push(h);
        }
        Ok(srv)
    }

    pub fn connection_count(&self) -> usize {
        self.conns.len()
    }

    fn endpoint_to_std(ep: smoltcp::wire::IpEndpoint) -> SocketAddr {
        match ep.addr {
            IpAddress::Ipv4(v4) => SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(v4.octets())),
                ep.port,
            ),
            IpAddress::Ipv6(v6) => SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(v6.octets())),
                ep.port,
            ),
        }
    }

    fn std_to_endpoint(addr: SocketAddr) -> smoltcp::wire::IpEndpoint {
        match addr {
            SocketAddr::V4(v4) => smoltcp::wire::IpEndpoint::new(
                IpAddress::Ipv4(smoltcp::wire::Ipv4Address::from(v4.ip().octets())),
                v4.port(),
            ),
            SocketAddr::V6(v6) => smoltcp::wire::IpEndpoint::new(
                IpAddress::Ipv6(smoltcp::wire::Ipv6Address::from(v6.ip().octets())),
                v6.port(),
            ),
        }
    }

    fn ensure_relay_socket(&mut self, relayed: SocketAddr) -> smoltcp::iface::SocketHandle {
        if let Some(h) = self.relay_sockets.get(&relayed) {
            return *h;
        }
        let h = self.stack.add_udp_socket(relayed.port());
        self.relay_sockets.insert(relayed, h);
        h
    }

    /// One service round: poll the stack, accept new TLS connections,
    /// pump ciphertext/plaintext both ways. Ok(false) when idle.
    pub fn serve_once(&mut self) -> io::Result<bool> {
        self.now_ms += 5;
        let now = self.now_ms;
        self.stack.poll(now);
        // Accept: a listening socket itself becomes the connection;
        // replace it so the pool always has listeners ready.
        for li in 0..self.listeners.len() {
            let handle = self.listeners[li];
            if self.stack.tcp_state(handle) != smoltcp::socket::tcp::State::Established {
                continue;
            }
            let Some(ep) = self.stack.tcp_remote_endpoint(handle) else {
                continue;
            };
            let src = Self::endpoint_to_std(ep);
            let tls = match &self.config {
                Some(cfg) => match rustls::ServerConnection::new(cfg.clone()) {
                    Ok(t) => Some(t),
                    Err(_) => return Ok(true),
                },
                None => None,
            };
            if std::env::var_os("TURN_DEBUG").is_some() {
                eprintln!("turn-tcp accept from {src} tls={}", tls.is_some());
            }
            self.conns.push(TlsConn {
                handle,
                tls,
                plain_in: Vec::new(),
                cipher_out: Vec::new(),
                src,
                dead: false,
            });
            let h = self.stack.add_tcp_socket();
            match self.stack.tcp_listen(h, self.port) {
                Ok(()) => {
                    self.listeners[li] = h;
                }
                Err(e) => {
                    if std::env::var_os("TURN_DEBUG").is_some() {
                        eprintln!("turn-tcp re-listen failed: {e:?}");
                    }
                }
            }
        }
        let mut worked = false;
        // Pump each connection.
        for idx in 0..self.conns.len() {
            worked |= self.pump_conn(idx);
        }
        // Handle complete frames (may produce cross-conn forwards).
        let mut outputs: Vec<(Option<SocketAddr>, usize, Vec<u8>)> = Vec::new();
        let mut externals: Vec<(SocketAddr, SocketAddr, Vec<u8>)> = Vec::new();
        // Relay-socket ingress: external peers -> owning clients.
        {
            let relayed_addrs: Vec<SocketAddr> = self.relay_sockets.keys().copied().collect();
            for relayed in relayed_addrs {
                let handle = self.relay_sockets[&relayed];
                while let Some((data, ep)) = self.stack.udp_recv_on(handle) {
                    let peer = Self::endpoint_to_std(ep);
                    let outcome =
                        self.turn
                            .handle_relayed_datagram(relayed, peer, &data, now_secs());
                    if let HandleOutcome::Forward { peer: client, data } = outcome {
                        outputs.push((Some(client), 0, data));
                        worked = true;
                    }
                }
            }
        }
        for idx in 0..self.conns.len() {
            let src = self.conns[idx].src;
            while let Some(frame) = take_frame(&mut self.conns[idx].plain_in) {
                if std::env::var_os("TURN_DEBUG").is_some() {
                    let desc = crate::wire::StunMessage::decode(&frame)
                        .map(|m| {
                            format!(
                                "stun method={:#x} class={:?} len={}",
                                m.method,
                                m.class,
                                frame.len()
                            )
                        })
                        .unwrap_or_else(|| format!("channeldata/other len={}", frame.len()));
                    eprintln!("turn-tcp frame from {src}: {desc}");
                }
                match self.turn.handle(&frame, src, now_secs()) {
                    HandleOutcome::Response(bytes) => outputs.push((None, idx, bytes)),
                    HandleOutcome::Forward { peer, data } => outputs.push((Some(peer), idx, data)),
                    HandleOutcome::ForwardExternal {
                        relayed,
                        peer,
                        payload,
                    } => externals.push((relayed, peer, payload)),
                    HandleOutcome::Drop => {}
                }
                worked = true;
            }
        }
        for (target, from_idx, bytes) in outputs {
            let dest = match target {
                None => Some(from_idx),
                Some(peer) => self.conns.iter().position(|c| c.src == peer),
            };
            if let Some(d) = dest {
                match &mut self.conns[d].tls {
                    Some(tls) => {
                        use std::io::Write as _;
                        let _ = tls.writer().write(&bytes);
                    }
                    None => self.conns[d].cipher_out.extend_from_slice(&bytes),
                }
            }
        }
        for (relayed, peer, payload) in externals {
            let handle = self.ensure_relay_socket(relayed);
            let _ = self
                .stack
                .udp_send_on(handle, Self::std_to_endpoint(peer), &payload);
            worked = true;
        }
        // Flush TLS ciphertext toward the sockets.
        for idx in 0..self.conns.len() {
            let conn = &mut self.conns[idx];
            if let Some(tls) = &mut conn.tls {
                let mut sink: Vec<u8> = Vec::new();
                if tls.wants_write() {
                    let _ = tls.write_tls(&mut sink);
                    conn.cipher_out.extend_from_slice(&sink);
                }
            }
            if !conn.cipher_out.is_empty() {
                if let Ok(n) = self.stack.tcp_send(conn.handle, &conn.cipher_out.clone()) {
                    conn.cipher_out.drain(..n);
                    worked = true;
                }
            }
        }
        self.stack.poll(now + 1);
        // Prune dead connections.
        let mut i = 0;
        while i < self.conns.len() {
            let state = self.stack.tcp_state(self.conns[i].handle);
            if self.conns[i].dead
                || (matches!(
                    state,
                    smoltcp::socket::tcp::State::Closed | smoltcp::socket::tcp::State::TimeWait
                ) && self.conns[i].cipher_out.is_empty())
            {
                let c = self.conns.remove(i);
                self.stack.remove_socket(c.handle);
            } else {
                i += 1;
            }
        }
        // Prune relay sockets whose allocation has expired.
        {
            let dead: Vec<SocketAddr> = self
                .relay_sockets
                .keys()
                .filter(|r| !self.turn.has_allocation_for_relayed(**r))
                .copied()
                .collect();
            for r in dead {
                if let Some(h) = self.relay_sockets.remove(&r) {
                    self.stack.remove_socket(h);
                }
            }
        }
        Ok(worked)
    }

    fn pump_conn(&mut self, idx: usize) -> bool {
        let mut worked = false;
        // Ciphertext socket -> rustls.
        loop {
            let mut chunk = [0u8; 4096];
            let n = match self.stack.tcp_recv(self.conns[idx].handle, &mut chunk) {
                Ok(n) => n,
                Err(_) => {
                    self.conns[idx].dead = true;
                    break;
                }
            };
            if n == 0 {
                break;
            }
            worked = true;
            if self.conns[idx].tls.is_none() {
                // Plain TURN/TCP: socket bytes are already frames.
                self.conns[idx].plain_in.extend_from_slice(&chunk[..n]);
                continue;
            }
            let mut cursor = io::Cursor::new(chunk[..n].to_vec());
            match self.conns[idx].tls.as_mut().unwrap().read_tls(&mut cursor) {
                Ok(_) => {}
                Err(_) => {
                    self.conns[idx].dead = true;
                    break;
                }
            }
            match self.conns[idx].tls.as_mut().unwrap().process_new_packets() {
                Ok(_) => {}
                Err(e) => {
                    if std::env::var_os("TURN_DEBUG").is_some() {
                        eprintln!("turn-tls process error from {}: {e}", self.conns[idx].src);
                    }
                    self.conns[idx].dead = true;
                    break;
                }
            }
            // Plaintext out of rustls.
            loop {
                let mut plain = [0u8; 4096];
                match self.conns[idx]
                    .tls
                    .as_mut()
                    .unwrap()
                    .reader()
                    .read(&mut plain)
                {
                    Ok(0) => break,
                    Ok(m) => {
                        self.conns[idx].plain_in.extend_from_slice(&plain[..m]);
                        worked = true;
                    }
                    Err(_) => break,
                }
            }
        }
        worked
    }

    pub fn serve_until(&mut self, stop: impl Fn() -> bool) -> io::Result<()> {
        while !stop() {
            self.serve_once()?;
            std::thread::sleep(Duration::from_millis(2));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl LiveTlsTurnServer<crate::tun::FdDevice<std::fs::File>> {
    /// Bind on a TUN device: the kernel interface must also be given
    /// `ip` by the operator (CAP_NET_ADMIN), e.g.
    /// `ip addr add 10.99.0.1/24 dev turndag0 && ip link set turndag0 up`.
    pub fn bind_tun(
        tun_name: &str,
        ip: IpAddress,
        prefix_len: u8,
        config: Arc<rustls::ServerConfig>,
        turn: TurnServer,
        port: u16,
    ) -> io::Result<Self> {
        let file = crate::tun::open_tun(tun_name)?;
        let device = crate::tun::FdDevice::new(file, 1500);
        let stack = UserSpaceStack::new_with_device(device, ip, prefix_len, crate::TURN_PORT);
        Self::new(stack, config, turn, port)
    }

    /// Plain TURN/TCP on a TUN device (see `bind_tun` operator note).
    pub fn bind_tun_plain(
        tun_name: &str,
        ip: IpAddress,
        prefix_len: u8,
        turn: TurnServer,
        port: u16,
    ) -> io::Result<Self> {
        let file = crate::tun::open_tun(tun_name)?;
        let device = crate::tun::FdDevice::new(file, 1500);
        let stack = UserSpaceStack::new_with_device(device, ip, prefix_len, crate::TURN_PORT);
        Self::new_plain(stack, turn, port)
    }
}

/// Plain TURN/TCP and turns: share one implementation.
pub type LiveTcpTurnServer<D> = LiveTlsTurnServer<D>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::*;
    use std::net::IpAddr;
    use std::sync::mpsc;

    struct Pipe(mpsc::Receiver<Vec<u8>>, mpsc::Sender<Vec<u8>>, Vec<u8>);
    impl Read for Pipe {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.2.is_empty() {
                match self.0.try_recv() {
                    Ok(v) => self.2 = v,
                    Err(_) => return Err(io::Error::new(io::ErrorKind::WouldBlock, "empty")),
                }
            }
            let n = self.2.len().min(buf.len());
            buf[..n].copy_from_slice(&self.2[..n]);
            self.2.drain(..n);
            Ok(n)
        }
    }
    impl Write for Pipe {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.1.send(buf.to_vec()).unwrap();
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn take_frame_handles_stun_and_channeldata_streams() {
        let mut req = StunMessage::new(method::ALLOCATE, Class::Request, [1u8; 12]);
        req.push_attr(attr_type::REQUESTED_TRANSPORT, vec![17, 0, 0, 0]);
        let bytes = req.encode();
        let mut buf = bytes[..10].to_vec();
        assert_eq!(take_frame(&mut buf), None);
        buf.extend_from_slice(&bytes[10..]);
        // Stream transports pad ChannelData to a 4-byte boundary.
        buf.extend_from_slice(&[0x40, 0x01, 0, 2, b'x', b'y', 0, 0]);
        let f1 = take_frame(&mut buf).unwrap();
        assert_eq!(StunMessage::decode(&f1).unwrap().method, method::ALLOCATE);
        let f2 = take_frame(&mut buf).unwrap();
        assert_eq!(crate::wire::decode_channel_data(&f2).unwrap().1, b"xy");
        assert!(buf.is_empty());
    }

    fn craft_tcp(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        seq: i32,
        payload: &[u8],
    ) -> Vec<u8> {
        use smoltcp::wire::{
            IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr,
            TcpSeqNumber,
        };
        let src_a = Ipv4Address::from(src);
        let dst_a = Ipv4Address::from(dst);
        let repr = TcpRepr {
            src_port: sport,
            dst_port: dport,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(seq),
            ack_number: None,
            window_len: 64240,
            window_scale: None,
            max_seg_size: Some(1460),
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload,
        };
        let tcp_len = repr.header_len() + payload.len();
        let mut buf = vec![0u8; 20 + tcp_len];
        let mut tcp_pkt = TcpPacket::new_unchecked(&mut buf[20..]);
        repr.emit(
            &mut tcp_pkt,
            &IpAddress::Ipv4(src_a),
            &IpAddress::Ipv4(dst_a),
            &smoltcp::phy::ChecksumCapabilities::default(),
        );
        let ip_repr = Ipv4Repr {
            src_addr: src_a,
            dst_addr: dst_a,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_len,
            hop_limit: 64,
        };
        let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf[..]);
        ip_repr.emit(&mut ip_pkt, &smoltcp::phy::ChecksumCapabilities::default());
        buf
    }

    #[test]
    fn tls_server_syn_gets_synack_over_virtual_device() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let rc = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let scfg = crate::tls::server_config(
            rc.cert.pem().as_bytes(),
            rc.key_pair.serialize_pem().as_bytes(),
        )
        .unwrap();
        let stack = UserSpaceStack::new(IpAddress::v4(10, 99, 0, 1), 24, crate::TURN_PORT);
        let turn = TurnServer::new("10.99.0.1".parse::<IpAddr>().unwrap());
        let mut srv = LiveTlsTurnServer::new(stack, scfg, turn, 5349).unwrap();
        let syn = craft_tcp([10, 99, 0, 2], [10, 99, 0, 1], 40000, 5349, 100, &[]);
        srv.stack.device.inject(syn);
        srv.serve_once().unwrap();
        assert!(
            !srv.stack.device.tx_queue.is_empty(),
            "SYN must be answered (SYN-ACK) by the user-space stack"
        );
        // Parse the reply: TCP flags should include SYN+ACK (0x12).
        let reply = srv.stack.device.tx_queue.front().unwrap().clone();
        assert_eq!(reply[9], 6, "reply is TCP");
        let tcp = &reply[20..];
        assert_eq!(tcp[13] & 0x12, 0x12, "SYN-ACK flags, got {:#x}", tcp[13]);
    }

    #[test]
    fn tls_server_two_simultaneous_syns_both_answered() {
        // Listener pool: two SYNs from different clients in the same
        // poll window must both get SYN-ACKs (a single listening
        // socket would RST the second).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let rc = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let scfg = crate::tls::server_config(
            rc.cert.pem().as_bytes(),
            rc.key_pair.serialize_pem().as_bytes(),
        )
        .unwrap();
        let stack = UserSpaceStack::new(IpAddress::v4(10, 99, 0, 1), 24, crate::TURN_PORT);
        let turn = TurnServer::new("10.99.0.1".parse::<IpAddr>().unwrap());
        let mut srv = LiveTlsTurnServer::new(stack, scfg, turn, 5349).unwrap();
        srv.stack.device.inject(craft_tcp(
            [10, 99, 0, 2],
            [10, 99, 0, 1],
            40001,
            5349,
            100,
            &[],
        ));
        srv.stack.device.inject(craft_tcp(
            [10, 99, 0, 2],
            [10, 99, 0, 1],
            40002,
            5349,
            200,
            &[],
        ));
        srv.serve_once().unwrap();
        srv.serve_once().unwrap();
        let synacks = srv
            .stack
            .device
            .tx_queue
            .iter()
            .filter(|p| p.len() > 33 && p[9] == 6 && (p[33] & 0x12) == 0x12)
            .count();
        assert_eq!(synacks, 2, "both simultaneous SYNs answered");
    }

    #[test]
    fn plain_tcp_server_syn_gets_synack_over_virtual_device() {
        // Plain TURN/TCP shares the listener-pool stack: a SYN must
        // be answered exactly as in TLS mode, minus the handshake.
        let stack = UserSpaceStack::new(IpAddress::v4(10, 99, 0, 1), 24, crate::TURN_PORT);
        let turn = TurnServer::new("10.99.0.1".parse::<IpAddr>().unwrap());
        let mut srv = LiveTlsTurnServer::new_plain(stack, turn, 3478).unwrap();
        srv.stack.device.inject(craft_tcp(
            [10, 99, 0, 2],
            [10, 99, 0, 1],
            40000,
            3478,
            100,
            &[],
        ));
        srv.serve_once().unwrap();
        assert!(!srv.stack.device.tx_queue.is_empty());
        let reply = srv.stack.device.tx_queue.front().unwrap().clone();
        assert_eq!(reply[9], 6);
        assert_eq!(reply[33] & 0x12, 0x12, "SYN-ACK flags");
        assert_eq!(u16::from_be_bytes([reply[20], reply[21]]), 3478);
    }

    #[test]
    fn tls_server_real_kernel_syn_gets_synack() {
        // Exact SYN bytes captured from a Linux kernel client over TUN
        // (MSS+SACK+timestamps+window-scale options).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let rc = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let scfg = crate::tls::server_config(
            rc.cert.pem().as_bytes(),
            rc.key_pair.serialize_pem().as_bytes(),
        )
        .unwrap();
        let stack = UserSpaceStack::new(IpAddress::v4(10, 99, 0, 1), 24, crate::TURN_PORT);
        let turn = TurnServer::new("10.99.0.1".parse::<IpAddr>().unwrap());
        let mut srv = LiveTlsTurnServer::new(stack, scfg, turn, 5349).unwrap();
        let hex = "4500003ca0dc4000400685170a6300020a630001c8d014e58d5664f300000000a002faf00f400000020405b40402080af95b5fa8000000000103030a";
        let syn: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        srv.stack.device.inject(syn);
        srv.serve_once().unwrap();
        assert!(
            !srv.stack.device.tx_queue.is_empty(),
            "kernel SYN must be answered over the stack"
        );
    }

    #[test]
    fn tls_server_syn_over_fddevice_duplex() {
        // Same kernel SYN, but delivered through FdDevice (the TUN
        // token plumbing) over an in-memory duplex.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let rc = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let scfg = crate::tls::server_config(
            rc.cert.pem().as_bytes(),
            rc.key_pair.serialize_pem().as_bytes(),
        )
        .unwrap();
        let hex = "4500003ca0dc4000400685170a6300020a630001c8d014e58d5664f300000000a002faf00f400000020405b40402080af95b5fa8000000000103030a";
        let syn: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        // Separate directions: Duplex reads from `shared`, writes go to
        // `outq` (a shared single queue would re-consume our own SYN-ACK).
        struct DuplexOut(
            std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
            std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        );
        impl Read for DuplexOut {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let mut g = self.0.lock().unwrap();
                if g.is_empty() {
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, "empty"));
                }
                let n = g.len().min(buf.len());
                buf[..n].copy_from_slice(&g[..n]);
                g.drain(..n);
                Ok(n)
            }
        }
        impl Write for DuplexOut {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.1.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let shared = std::sync::Arc::new(std::sync::Mutex::new(syn));
        let outq = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let device = crate::tun::FdDevice::new(DuplexOut(shared.clone(), outq.clone()), 1500);
        let stack = UserSpaceStack::new_with_device(
            device,
            IpAddress::v4(10, 99, 0, 1),
            24,
            crate::TURN_PORT,
        );
        let turn = TurnServer::new("10.99.0.1".parse::<IpAddr>().unwrap());
        let mut srv = LiveTlsTurnServer::new(stack, scfg, turn, 5349).unwrap();
        srv.serve_once().unwrap();
        let out = outq.lock().unwrap();
        assert!(
            out.len() > 20,
            "SYN-ACK must be written via FdDevice, got {}B",
            out.len()
        );
        assert_eq!(out[9], 6);
        assert_eq!(out[33] & 0x12, 0x12, "SYN-ACK flags");
    }

    #[test]
    fn tls_stream_allocate_end_to_end() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let rc = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = rc.cert.pem();
        let key_pem = rc.key_pair.serialize_pem();
        let scfg = crate::tls::server_config(cert_pem.as_bytes(), key_pem.as_bytes()).unwrap();
        let ccfg = crate::tls::client_config(cert_pem.as_bytes()).unwrap();
        let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>();
        let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>();
        let server = std::thread::spawn(move || {
            let mut turn = TurnServer::new("127.0.0.1".parse::<IpAddr>().unwrap());
            serve_tls_stream(
                scfg,
                Pipe(s2c_rx, c2s_tx, Vec::new()),
                &mut turn,
                "203.0.113.7:5000".parse().unwrap(),
            )
        });
        let mut cli =
            crate::tls::TlsClient::new(ccfg, "localhost", Pipe(c2s_rx, s2c_tx, Vec::new()))
                .unwrap();
        for _ in 0..500 {
            match cli.handshake() {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(e) => panic!("client handshake: {e}"),
            }
        }
        let mut req = StunMessage::new(method::ALLOCATE, Class::Request, [7u8; 12]);
        req.push_attr(attr_type::REQUESTED_TRANSPORT, vec![17, 0, 0, 0]);
        cli.write_app(&req.encode()).unwrap();
        let mut buf = [0u8; 2048];
        let mut resp = None;
        for _ in 0..500 {
            match cli.read_app(&mut buf) {
                Ok(0) => std::thread::sleep(Duration::from_millis(2)),
                Ok(n) => {
                    resp = StunMessage::decode(&buf[..n]);
                    break;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(2)),
            }
        }
        let resp = resp.expect("allocate response over TLS");
        assert_eq!(resp.class, Class::Success);
        assert!(resp.attr(attr_type::XOR_RELAYED_ADDRESS).is_some());
        let life = u32::from_be_bytes(
            resp.attr(attr_type::LIFETIME).unwrap()[..4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(life, 120);
        // Server thread exits on idle timeout; do not join (it may be
        // mid-sleep) - just assert it did not panic early.
        drop(cli);
        let _ = server;
    }

    #[test]
    fn live_udp_allocate_roundtrip_on_loopback() {
        let server = TurnServer::new("127.0.0.1".parse::<IpAddr>().unwrap());
        let mut live = LiveUdpTurnServer::bind("127.0.0.1:0".parse().unwrap(), server).unwrap();
        let addr = live.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut req = StunMessage::new(method::ALLOCATE, Class::Request, [3u8; 12]);
        req.push_attr(attr_type::REQUESTED_TRANSPORT, vec![17, 0, 0, 0]);
        client.send_to(&req.encode(), addr).unwrap();
        // Pump the server until the client's response arrives.
        let mut buf = [0u8; 2048];
        live.serve_once().unwrap();
        let n = client.recv(&mut buf).expect("allocate response");
        let resp = StunMessage::decode(&buf[..n]).unwrap();
        assert_eq!(resp.class, Class::Success);
        assert!(resp.attr(attr_type::XOR_RELAYED_ADDRESS).is_some());
        assert_eq!(live.allocation_count(), 1);
    }
}
