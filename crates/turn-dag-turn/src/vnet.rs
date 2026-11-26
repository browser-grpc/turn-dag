//! A virtual network for Rust-side integration tests: several
//! smoltcp stacks (each on a [`SwitchDevice`]) connected through a
//! shared [`VirtualNetwork`] switch that routes raw IPv4 packets by
//! destination address, with deterministic latency and loss knobs.
//!
//! This is the user-space answer to "test multi-node behaviour
//! without TUN/root/Docker": a TURN server stack, a client stack,
//! and an issuer stack can exchange real IP packets in-process, in
//! milliseconds, under `cargo test`.

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

#[derive(Default)]
struct Inner {
    endpoints: HashMap<[u8; 4], VecDeque<Vec<u8>>>,
    pending: Vec<(u64, [u8; 4], Vec<u8>)>,
    tick: u64,
    latency_ticks: u64,
    drop_every: u32,
    tx_counter: u32,
}

impl Inner {
    fn route(&mut self, packet: Vec<u8>) {
        if packet.len() < 20 {
            return;
        }
        let dst: [u8; 4] = packet[16..20].try_into().unwrap();
        self.tx_counter = self.tx_counter.wrapping_add(1);
        if self.drop_every > 0 && self.tx_counter % self.drop_every == 0 {
            return; // deterministic loss
        }
        if self.latency_ticks == 0 {
            if let Some(q) = self.endpoints.get_mut(&dst) {
                q.push_back(packet);
            }
        } else {
            let due = self.tick + self.latency_ticks;
            self.pending.push((due, dst, packet));
        }
    }

    fn release_pending(&mut self) {
        self.tick += 1;
        let (due, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending)
            .into_iter()
            .partition(|(d, _, _)| *d <= self.tick);
        self.pending = rest;
        for (_, dst, pkt) in due {
            if let Some(q) = self.endpoints.get_mut(&dst) {
                q.push_back(pkt);
            }
        }
    }
}

/// Shared switch. Clone it (or borrow device endpoints from it) to
/// attach stacks; packets move when endpoints poll/transmit.
#[derive(Clone, Default)]
pub struct VirtualNetwork {
    inner: Rc<RefCell<Inner>>,
}

impl VirtualNetwork {
    pub fn new() -> Self {
        Self::default()
    }

    /// Packets take `ticks` switch ticks (receive/transmit calls)
    /// to cross the network.
    pub fn with_latency_ticks(self, ticks: u64) -> Self {
        self.inner.borrow_mut().latency_ticks = ticks;
        self
    }

    /// Drop every n-th packet (deterministic loss; 0 = no loss).
    pub fn with_drop_every(self, n: u32) -> Self {
        self.inner.borrow_mut().drop_every = n;
        self
    }

    /// Attach an endpoint for `ip` (dotted IPv4) and return its device.
    pub fn device(&self, ip: &str) -> SwitchDevice {
        let addr: [u8; 4] = ip
            .parse::<std::net::Ipv4Addr>()
            .expect("ipv4 endpoint")
            .octets();
        self.inner.borrow_mut().endpoints.entry(addr).or_default();
        SwitchDevice {
            inner: self.inner.clone(),
            addr,
            mtu: 1500,
        }
    }
}

/// One node's device on a [`VirtualNetwork`].
pub struct SwitchDevice {
    inner: Rc<RefCell<Inner>>,
    addr: [u8; 4],
    mtu: usize,
}

pub struct SwitchRxToken(Vec<u8>);
pub struct SwitchTxToken {
    inner: Rc<RefCell<Inner>>,
}

impl RxToken for SwitchRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl TxToken for SwitchTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.inner.borrow_mut().route(buf);
        r
    }
}

impl Device for SwitchDevice {
    type RxToken<'b>
        = SwitchRxToken
    where
        Self: 'b;
    type TxToken<'b>
        = SwitchTxToken
    where
        Self: 'b;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut inner = self.inner.borrow_mut();
        inner.release_pending();
        let packet = inner.endpoints.get_mut(&self.addr)?.pop_front()?;
        Some((
            SwitchRxToken(packet),
            SwitchTxToken {
                inner: self.inner.clone(),
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(SwitchTxToken {
            inner: self.inner.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu;
        caps.medium = Medium::Ip;
        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stack::UserSpaceStack;
    use smoltcp::wire::{IpAddress, IpEndpoint};

    fn stack_on(net: &VirtualNetwork, ip: &str) -> UserSpaceStack<SwitchDevice> {
        let octets: Vec<&str> = ip.split('.').collect();
        let addr = IpAddress::v4(
            octets[0].parse().unwrap(),
            octets[1].parse().unwrap(),
            octets[2].parse().unwrap(),
            octets[3].parse().unwrap(),
        );
        UserSpaceStack::new_with_device(net.device(ip), addr, 24, crate::TURN_PORT)
    }

    #[test]
    fn two_stacks_exchange_udp_over_virtual_network() {
        let net = VirtualNetwork::new();
        let mut a = stack_on(&net, "10.0.0.1");
        let mut b = stack_on(&net, "10.0.0.2");
        b.send_udp(
            IpEndpoint::new(IpAddress::v4(10, 0, 0, 1), crate::TURN_PORT),
            b"hello-virtual-network",
        )
        .unwrap();
        for t in 0..10 {
            a.poll(t);
            b.poll(t);
        }
        let (data, from) = a.recv_udp().expect("packet routed by the switch");
        assert_eq!(data, b"hello-virtual-network");
        assert_eq!(from.addr, IpAddress::v4(10, 0, 0, 2));
        // And back the other way.
        a.send_udp(
            IpEndpoint::new(IpAddress::v4(10, 0, 0, 2), crate::TURN_PORT),
            b"reply",
        )
        .unwrap();
        for t in 10..20 {
            a.poll(t);
            b.poll(t);
        }
        assert_eq!(b.recv_udp().unwrap().0, b"reply");
    }

    #[test]
    fn virtual_network_loss_drops_everything_at_drop_every_1() {
        let net = VirtualNetwork::new().with_drop_every(1);
        let mut a = stack_on(&net, "10.0.0.1");
        let mut b = stack_on(&net, "10.0.0.2");
        b.send_udp(
            IpEndpoint::new(IpAddress::v4(10, 0, 0, 1), crate::TURN_PORT),
            b"doomed",
        )
        .unwrap();
        for t in 0..10 {
            a.poll(t);
            b.poll(t);
        }
        assert_eq!(a.recv_udp(), None);
    }

    #[test]
    fn virtual_network_latency_delays_delivery() {
        let net = VirtualNetwork::new().with_latency_ticks(50);
        let mut a = stack_on(&net, "10.0.0.1");
        let mut b = stack_on(&net, "10.0.0.2");
        b.send_udp(
            IpEndpoint::new(IpAddress::v4(10, 0, 0, 1), crate::TURN_PORT),
            b"slow",
        )
        .unwrap();
        b.poll(0);
        a.poll(0);
        assert_eq!(a.recv_udp(), None, "not yet: still in flight");
        for t in 1..200 {
            a.poll(t);
            b.poll(t);
        }
        assert_eq!(a.recv_udp().unwrap().0, b"slow");
    }
}
