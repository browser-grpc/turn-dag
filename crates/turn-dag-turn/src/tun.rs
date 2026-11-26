//! TUN device for the smoltcp stack on Linux (spec §13/14): the one
//! place raw frames enter the process. Requires a one-time grant
//! (/dev/net/tun access or a pre-created TUN); the stack itself then
//! runs unprivileged and ports 3478/5349 are just numbers inside it.
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use std::io::{self, Read, Write};

/// smoltcp `Device` over any frame file (a TUN fd in production, a
/// pipe or duplex stream in tests). Medium is raw IP.
pub struct FdDevice<F> {
    inner: F,
    mtu: usize,
    rx_buf: Vec<u8>,
}
impl<F: Read + Write> FdDevice<F> {
    pub fn new(inner: F, mtu: usize) -> Self {
        Self {
            inner,
            mtu: if mtu == 0 { 1500 } else { mtu },
            rx_buf: vec![0u8; 65536],
        }
    }
    pub fn into_inner(self) -> F {
        self.inner
    }
}
pub struct FdRxToken(Vec<u8>);
pub struct FdTxToken<'a, F>(&'a mut F);
impl RxToken for FdRxToken {
    fn consume<R, F2>(self, f: F2) -> R
    where
        F2: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}
impl<F: Write> TxToken for FdTxToken<'_, F> {
    fn consume<R, F2>(self, len: usize, f: F2) -> R
    where
        F2: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        if std::env::var_os("TURN_DEBUG").is_some() {
            eprintln!(
                "tun tx {len}B proto={:#04x}",
                buf.get(9).copied().unwrap_or(0)
            );
        }
        let _ = self.0.write_all(&buf);
        r
    }
}
impl<F: Read + Write> Device for FdDevice<F> {
    type RxToken<'b>
        = FdRxToken
    where
        Self: 'b;
    type TxToken<'b>
        = FdTxToken<'b, F>
    where
        Self: 'b;
    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // TUN reads return one frame per read; WouldBlock means none.
        match self.inner.read(&mut self.rx_buf) {
            Ok(0) | Err(_) => None,
            Ok(n) => {
                if std::env::var_os("TURN_DEBUG").is_some() {
                    let hex: String = self.rx_buf[..n.min(64)]
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    eprintln!("tun rx {n}B {hex}");
                }
                let pkt = self.rx_buf[..n].to_vec();
                Some((FdRxToken(pkt), FdTxToken(&mut self.inner)))
            }
        }
    }
    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(FdTxToken(&mut self.inner))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu;
        caps.medium = Medium::Ip;
        caps
    }
}

/// Open a Linux TUN device (`/dev/net/tun`) without packet info
/// headers (IFF_TUN | IFF_NO_PI). Errors (not panics) when the device
/// or permission is unavailable, so callers can fall back to a
/// virtual device and say so.
#[cfg(target_os = "linux")]
pub fn open_tun(name: &str) -> io::Result<std::fs::File> {
    use std::os::unix::io::AsRawFd;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;
    #[repr(C)]
    struct IfReq {
        name: [u8; 16],
        flags: u16,
        _pad: [u8; 22],
    }
    const IFF_TUN: u16 = 0x0001;
    const IFF_NO_PI: u16 = 0x1000;
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    let mut req = IfReq {
        name: [0u8; 16],
        flags: IFF_TUN | IFF_NO_PI,
        _pad: [0u8; 22],
    };
    let nb = name.as_bytes();
    if nb.len() >= 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tun name too long",
        ));
    }
    req.name[..nb.len()].copy_from_slice(nb);
    let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &req as *const IfReq) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // smoltcp is a poll-based stack: its poll loop runs egress only
    // after device.receive() returns None. A blocking TUN fd would
    // park the loop in ingress forever and no SYN-ACK would ever be
    // sent, so the fd MUST be non-blocking.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn fd_device_roundtrips_a_frame_through_stack_tokens() {
        // Duplex in-memory file: written frames are readable back.
        struct Duplex(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl Read for Duplex {
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
        impl Write for Duplex {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut dev = FdDevice::new(Duplex(shared.clone()), 1500);
        assert_eq!(dev.capabilities().medium, Medium::Ip);
        // Nothing to receive yet.
        assert!(dev.receive(Instant::now()).is_none());
        let tx = dev.transmit(Instant::now()).unwrap();
        tx.consume(4, |b| b.copy_from_slice(&[0x45, 0, 0, 4]));
        let (rx, _tx2) = dev.receive(Instant::now()).expect("frame back");
        rx.consume(|pkt| assert_eq!(pkt, &[0x45, 0, 0, 4]));
        let _ = Cursor::new(Vec::<u8>::new());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn open_tun_errors_gracefully_without_device() {
        // In CI/containers /dev/net/tun may be absent or unprivileged:
        // either a real device opens, or we get a clean io error.
        match open_tun("turndag-test-nonexistent-xyz") {
            Ok(_) => {}
            Err(e) => assert!(!e.to_string().is_empty()),
        }
    }
}
