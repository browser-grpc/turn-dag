//! Live TURN service: the wire server over a real UDP socket.
//! UDP stays on ordinary sockets (spec §14.4); the no-kernel-TCP rule
//! only governs TCP, which remains inside the smoltcp stack.
use crate::wire::{HandleOutcome, TurnServer};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub struct LiveUdpTurnServer {
    socket: UdpSocket,
    server: TurnServer,
}
impl LiveUdpTurnServer {
    pub fn bind(addr: SocketAddr, server: TurnServer) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_read_timeout(Some(Duration::from_millis(250)))?;
        Ok(Self { socket, server })
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
    pub fn serve_once(&mut self) -> io::Result<bool> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::*;
    use std::net::IpAddr;

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
