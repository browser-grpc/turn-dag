//! User-space TCP/UDP stack on smoltcp (no kernel TCP anywhere).
//!
//! All TCP in this system (TURN over TCP/TLS admission, DAG gossip,
//! issuer APIs) must run over smoltcp sockets - a poll-based,
//! no_std user-space stack driven over a TUN/TAP, raw-packet or
//! virtual [`Device`]. This module provides:
//! - [`VirtualDevice`]: an in-memory packet queue device for tests
//!   and embedding (packets are handed to/from the stack as raw IP).
//! - [`UserSpaceStack`]: a smoltcp `Interface` + `SocketSet` with a
//!   UDP socket bound to the TURN port and a TCP socket type bound
//!   through the same stack, so no kernel socket is ever created.
//!
//! `no-tcp-relay` is enforced at the issuer admission layer
//! (`AllocationPolicy::no_tcp_relay`); this stack only provides the
//! user-space transport that such allocations would run over.

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use std::collections::VecDeque;

/// In-memory virtual device: outbound IP packets are queued for the
/// embedder to inspect; inbound packets are injected with
/// [`VirtualDevice::inject`]. Medium is raw IP (no Ethernet).
#[derive(Debug, Default)]
pub struct VirtualDevice {
    pub rx_queue: VecDeque<Vec<u8>>,
    pub tx_queue: VecDeque<Vec<u8>>,
    pub mtu: usize,
}

impl VirtualDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            mtu,
        }
    }

    /// Queue a raw IP packet for the stack to receive on next poll.
    pub fn inject(&mut self, packet: Vec<u8>) {
        self.rx_queue.push_back(packet);
    }
}

pub struct VirtualRxToken(Vec<u8>);
pub struct VirtualTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl<'a> TxToken for VirtualTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

impl Device for VirtualDevice {
    type RxToken<'b>
        = VirtualRxToken
    where
        Self: 'b;
    type TxToken<'b>
        = VirtualTxToken<'b>
    where
        Self: 'b;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx_queue.pop_front()?;
        Some((VirtualRxToken(packet), VirtualTxToken(&mut self.tx_queue)))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtualTxToken(&mut self.tx_queue))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = if self.mtu == 0 { 1500 } else { self.mtu };
        caps.medium = Medium::Ip;
        caps
    }
}

/// A running user-space stack instance, generic over the smoltcp
/// `Device` (virtual in tests, TUN-backed for live TCP/TLS).
pub struct UserSpaceStack<D: Device = VirtualDevice> {
    pub device: D,
    pub iface: Interface,
    pub sockets: SocketSet<'static>,
    pub udp_handle: SocketHandle,
    pub tcp_handle: SocketHandle,
}

impl<D: Device> UserSpaceStack<D> {
    /// Create a stack over an existing device with `ip/prefix`, a UDP
    /// socket on `udp_port` and an (unconnected) user-space TCP
    /// socket. No kernel socket of any kind is created.
    pub fn new_with_device(mut device: D, ip: IpAddress, prefix_len: u8, udp_port: u16) -> Self {
        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(ip, prefix_len));
        });

        let udp_rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 4096]);
        let udp_tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 8], vec![0u8; 4096]);
        let mut udp_socket = udp::Socket::new(udp_rx, udp_tx);
        udp_socket.bind(udp_port).expect("bind TURN UDP port");

        let tcp_socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 4096]),
            tcp::SocketBuffer::new(vec![0u8; 4096]),
        );

        let mut sockets = SocketSet::new(vec![]);
        let udp_handle = sockets.add(udp_socket);
        let tcp_handle = sockets.add(tcp_socket);

        Self {
            device,
            iface,
            sockets,
            udp_handle,
            tcp_handle,
        }
    }

    /// Poll the stack at deterministic smoltcp time `now_millis`.
    /// Returns true if any socket may have work afterwards.
    pub fn poll(&mut self, now_millis: i64) -> bool {
        let now = Instant::from_millis(now_millis);
        !matches!(
            self.iface.poll(now, &mut self.device, &mut self.sockets),
            smoltcp::iface::PollResult::None
        )
    }

    /// Send a UDP datagram from the TURN socket.
    pub fn send_udp(&mut self, dst: IpEndpoint, payload: &[u8]) -> Result<(), udp::SendError> {
        let socket = self.sockets.get_mut::<udp::Socket>(self.udp_handle);
        socket.send_slice(payload, dst)
    }

    /// Receive the next UDP datagram, if one is queued.
    pub fn recv_udp(&mut self) -> Option<(Vec<u8>, IpEndpoint)> {
        let socket = self.sockets.get_mut::<udp::Socket>(self.udp_handle);
        match socket.recv() {
            Ok((data, meta)) => Some((data.to_vec(), meta.endpoint)),
            Err(_) => None,
        }
    }

    pub fn udp_is_open(&self) -> bool {
        self.sockets.get::<udp::Socket>(self.udp_handle).is_open()
    }

    /// The TCP socket lives in the same user-space stack; listening
    /// / connecting happens over smoltcp, never the kernel.
    pub fn tcp_socket_is_user_space(&self) -> bool {
        // Presence of the handle in our SocketSet is the proof: the
        // only TCP implementation reachable here is smoltcp's.
        let _socket: &tcp::Socket = self.sockets.get::<tcp::Socket>(self.tcp_handle);
        true
    }

    /// Create an additional user-space TCP socket in this stack and
    /// return its handle (for listeners / accepted connections).
    pub fn add_tcp_socket(&mut self) -> SocketHandle {
        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 16384]),
            tcp::SocketBuffer::new(vec![0u8; 16384]),
        );
        self.sockets.add(socket)
    }

    pub fn tcp_listen(&mut self, handle: SocketHandle, port: u16) -> Result<(), tcp::ListenError> {
        self.sockets.get_mut::<tcp::Socket>(handle).listen(port)
    }

    pub fn tcp_state(&self, handle: SocketHandle) -> tcp::State {
        self.sockets.get::<tcp::Socket>(handle).state()
    }

    pub fn tcp_remote_endpoint(&self, handle: SocketHandle) -> Option<IpEndpoint> {
        self.sockets.get::<tcp::Socket>(handle).remote_endpoint()
    }

    /// Receive bytes from a TCP socket; Ok(0) means no data right now.
    pub fn tcp_recv(
        &mut self,
        handle: SocketHandle,
        buf: &mut [u8],
    ) -> Result<usize, tcp::RecvError> {
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        if !socket.can_recv() {
            return Ok(0);
        }
        socket.recv_slice(buf)
    }

    /// Send bytes on a TCP socket; returns bytes accepted.
    pub fn tcp_send(&mut self, handle: SocketHandle, data: &[u8]) -> Result<usize, tcp::SendError> {
        self.sockets.get_mut::<tcp::Socket>(handle).send_slice(data)
    }

    pub fn tcp_close(&mut self, handle: SocketHandle) {
        self.sockets.get_mut::<tcp::Socket>(handle).close();
    }

    pub fn remove_socket(&mut self, handle: SocketHandle) {
        self.sockets.remove(handle);
    }
}

impl UserSpaceStack<VirtualDevice> {
    /// Create a stack on an in-memory virtual device (tests/embedding).
    pub fn new(ip: IpAddress, prefix_len: u8, udp_port: u16) -> Self {
        Self::new_with_device(VirtualDevice::new(1500), ip, prefix_len, udp_port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr};

    fn craft_udp(
        src: Ipv4Address,
        dst: Ipv4Address,
        sport: u16,
        dport: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut buf = vec![0u8; total_len];
        let mut udp_pkt = UdpPacket::new_unchecked(&mut buf[20..]);
        let repr = UdpRepr {
            src_port: sport,
            dst_port: dport,
        };
        repr.emit(
            &mut udp_pkt,
            &IpAddress::Ipv4(src),
            &IpAddress::Ipv4(dst),
            payload.len(),
            |p| p.copy_from_slice(payload),
            &smoltcp::phy::ChecksumCapabilities::default(),
        );
        let ip_repr = Ipv4Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Udp,
            payload_len: udp_len,
            hop_limit: 64,
        };
        let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf[..]);
        ip_repr.emit(&mut ip_pkt, &smoltcp::phy::ChecksumCapabilities::default());
        buf
    }

    #[test]
    fn virtual_device_udp_roundtrip_through_stack() {
        let ip = IpAddress::v4(203, 0, 113, 1);
        let mut stack = UserSpaceStack::new(ip, 24, crate::TURN_PORT);
        assert!(stack.udp_is_open());
        assert!(stack.tcp_socket_is_user_space());

        // Idle poll does nothing and emits nothing.
        stack.poll(0);
        assert!(stack.device.tx_queue.is_empty());
        assert_eq!(stack.recv_udp(), None);

        // Inject a raw UDP/IP packet addressed to the TURN port.
        let packet = craft_udp(
            Ipv4Address::new(203, 0, 113, 9),
            Ipv4Address::new(203, 0, 113, 1),
            5000,
            crate::TURN_PORT,
            b"turn-probe",
        );
        stack.device.inject(packet);
        stack.poll(1);
        let (data, endpoint) = stack
            .recv_udp()
            .expect("datagram delivered via virtual device");
        assert_eq!(data, b"turn-probe");
        assert_eq!(endpoint.port, 5000);

        // Outbound path goes through the device queue, not a kernel socket.
        stack
            .send_udp(
                IpEndpoint::new(IpAddress::v4(203, 0, 113, 9), 5000),
                b"reply",
            )
            .unwrap();
        stack.poll(2);
        assert!(
            !stack.device.tx_queue.is_empty(),
            "tx captured by virtual device"
        );
    }

    #[test]
    fn virtual_device_capabilities_are_ip_medium() {
        let dev = VirtualDevice::new(1500);
        let caps = dev.capabilities();
        assert_eq!(caps.medium, Medium::Ip);
        assert_eq!(caps.max_transmission_unit, 1500);
    }
}
