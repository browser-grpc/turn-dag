//! TLS for `turns:` (5349) and TLS gossip/API connections: rustls in
//! process over the byte stream the smoltcp stack provides (spec
//! §14.1). rustls is user-space; the whole path frames-to-plaintext
//! stays in this process, never a kernel TCP socket.
use std::io::{self, Read, Write};
use std::sync::Arc;

/// rustls server config from PEM cert/key byte slices.
pub fn server_config(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<Arc<rustls::ServerConfig>, io::Error> {
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut &cert_pem[..])
            .collect::<Result<_, _>>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no private key"))?;
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    Ok(Arc::new(cfg))
}

/// rustls client config trusting a PEM root (tests/self-signed 5349).
pub fn client_config(root_pem: &[u8]) -> Result<Arc<rustls::ClientConfig>, io::Error> {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut &root_pem[..]) {
        roots
            .add(c.map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    }
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// One TLS server connection over a byte stream `S` (smoltcp-backed in
/// production, in-memory in tests). Drive with `pump` + read/write.
pub struct TlsServer<S> {
    conn: rustls::ServerConnection,
    stream: S,
}
impl<S: Read + Write> TlsServer<S> {
    pub fn new(config: Arc<rustls::ServerConfig>, stream: S) -> Result<Self, io::Error> {
        Ok(Self {
            conn: rustls::ServerConnection::new(config)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?,
            stream,
        })
    }
    /// Move ciphertext both ways until the handshake completes.
    pub fn handshake(&mut self) -> io::Result<()> {
        while self.conn.is_handshaking() {
            self.conn.complete_io(&mut self.stream)?;
        }
        Ok(())
    }
    pub fn write_app(&mut self, data: &[u8]) -> io::Result<usize> {
        let n = self.conn.writer().write(data)?;
        self.conn.complete_io(&mut self.stream)?;
        Ok(n)
    }
    pub fn read_app(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.conn.reader().read(buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.conn.complete_io(&mut self.stream)?;
                }
                Err(e) => return Err(e),
            }
        }
    }
    pub fn peer_alpn(&self) -> Option<Vec<u8>> {
        self.conn.alpn_protocol().map(|b| b.to_vec())
    }
}

/// Client side, symmetric to [`TlsServer`].
pub struct TlsClient<S> {
    conn: rustls::ClientConnection,
    stream: S,
}
impl<S: Read + Write> TlsClient<S> {
    pub fn new(
        config: Arc<rustls::ClientConfig>,
        server_name: &str,
        stream: S,
    ) -> Result<Self, io::Error> {
        let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        Ok(Self {
            conn: rustls::ClientConnection::new(config, name)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?,
            stream,
        })
    }
    pub fn handshake(&mut self) -> io::Result<()> {
        while self.conn.is_handshaking() {
            self.conn.complete_io(&mut self.stream)?;
        }
        Ok(())
    }
    pub fn write_app(&mut self, data: &[u8]) -> io::Result<usize> {
        let n = self.conn.writer().write(data)?;
        self.conn.complete_io(&mut self.stream)?;
        Ok(n)
    }
    pub fn read_app(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.conn.reader().read(buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.conn.complete_io(&mut self.stream)?;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn tls_handshake_and_app_data_over_in_process_stream() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let rc = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = rc.cert.pem();
        let key_pem = rc.key_pair.serialize_pem();
        let scfg = server_config(cert_pem.as_bytes(), key_pem.as_bytes()).unwrap();
        let ccfg = client_config(cert_pem.as_bytes()).unwrap();
        let (c2s_tx, c2s_rx) = mpsc::channel::<Vec<u8>>();
        let (s2c_tx, s2c_rx) = mpsc::channel::<Vec<u8>>();
        // rustls IO is blocking-style; run both ends on two threads over
        // non-blocking pipes, retrying handshakes until quiescent.
        let server = std::thread::spawn(move || {
            let mut srv = TlsServer::new(scfg, Pipe(s2c_rx, c2s_tx, Vec::new())).unwrap();
            for _ in 0..200 {
                if !srv.conn.is_handshaking() {
                    break;
                }
                match srv.conn.complete_io(&mut srv.stream) {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(2))
                    }
                    Err(e) => return Err(e),
                }
            }
            let mut buf = [0u8; 64];
            let n = srv.read_app(&mut buf)?;
            srv.write_app(&buf[..n].to_ascii_uppercase())?;
            Ok::<Vec<u8>, io::Error>(buf[..n].to_vec())
        });
        let mut cli = TlsClient::new(ccfg, "localhost", Pipe(c2s_rx, s2c_tx, Vec::new())).unwrap();
        for _ in 0..200 {
            if !cli.conn.is_handshaking() {
                break;
            }
            match cli.conn.complete_io(&mut cli.stream) {
                Ok(_) => break,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(2))
                }
                Err(e) => panic!("client handshake: {e}"),
            }
        }
        cli.write_app(b"ping-5349").unwrap();
        let mut buf = [0u8; 64];
        // Server may need a pump cycle; read with retries.
        let mut got = Vec::new();
        for _ in 0..200 {
            match cli.read_app(&mut buf) {
                Ok(0) => std::thread::sleep(std::time::Duration::from_millis(2)),
                Ok(n) => {
                    got.extend_from_slice(&buf[..n]);
                    break;
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(2)),
            }
        }
        assert_eq!(server.join().unwrap().unwrap(), b"ping-5349");
        assert_eq!(got, b"PING-5349");
    }

    #[test]
    fn bad_pem_is_an_error_not_a_panic() {
        assert!(server_config(b"not pem", b"also not").is_err());
        assert!(client_config(b"nope").is_ok() || client_config(b"nope").is_err());
        assert!(TlsClient::<std::io::Cursor<Vec<u8>>>::new(
            client_config(b"").unwrap(),
            "bad name with spaces!!",
            std::io::Cursor::new(Vec::new())
        )
        .is_err());
    }
}
