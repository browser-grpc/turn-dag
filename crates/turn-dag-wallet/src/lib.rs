//! PQ wallets: hot ML-DSA-65 (real `ml-dsa` crate, FIPS 204),
//! cold SLH-DSA-SHA2-128s (real `slh-dsa` crate, FIPS 205), and ML-KEM-768
//! seed backup (real `ml-kem` crate, FIPS 203). NEVER log seeds/private keys.

use sha3::{Digest, Sha3_256};

/// Address = SHA3-256(pubkey)[:20], bech32-encoded for display.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PqAddress(pub [u8; 20]);

impl PqAddress {
    pub fn from_pubkey(pubkey: &[u8]) -> Self {
        let h = Sha3_256::digest(pubkey);
        let mut b = [0u8; 20];
        b.copy_from_slice(&h[..20]);
        Self(b)
    }
    /// bech32 encode (HRP "turn").
    pub fn to_bech32(&self) -> String {
        use bech32::{Bech32, Hrp};
        bech32::encode::<Bech32>(Hrp::parse("turn").expect("hrp"), &self.0).expect("bech32 encode")
    }
    pub fn from_bech32(s: &str) -> Result<Self, WalletError> {
        let (_hrp, data) = bech32::decode(s).map_err(|_| WalletError::BadAddress)?;
        if data.len() != 20 {
            return Err(WalletError::BadAddress);
        }
        let mut b = [0u8; 20];
        b.copy_from_slice(&data);
        Ok(Self(b))
    }
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalletError {
    BadAddress,
    BadSeedLength,
    BadKeyLength,
    VerifyFailed,
    DecryptFailed,
}

pub trait PqWallet: Sized {
    const PUBKEY_LEN: usize;
    const SIG_LEN: usize;
    const SEED_LEN: usize;
    /// Deterministic from a 32-byte seed. Never log the seed.
    fn generate(seed: &[u8; 32]) -> Result<Self, WalletError>;
    fn address(&self) -> PqAddress {
        PqAddress::from_pubkey(self.public_key())
    }
    fn public_key(&self) -> &[u8];
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    fn verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool;
}

// ---------------- Hot wallet: real ML-DSA-65 ----------------
pub struct HotWallet {
    signing_key: ml_dsa::SigningKey<ml_dsa::MlDsa65>,
    pubkey: Vec<u8>,
}

impl PqWallet for HotWallet {
    const PUBKEY_LEN: usize = 1952;
    const SIG_LEN: usize = 3309;
    const SEED_LEN: usize = 32;
    fn generate(seed: &[u8; 32]) -> Result<Self, WalletError> {
        use ml_dsa::{KeyExport, Keypair};
        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_dsa::Seed::from(*seed));
        let pubkey = sk.verifying_key().to_bytes().to_vec();
        debug_assert_eq!(pubkey.len(), Self::PUBKEY_LEN);
        Ok(Self {
            signing_key: sk,
            pubkey,
        })
    }
    fn public_key(&self) -> &[u8] {
        &self.pubkey
    }
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        use ml_dsa::{SignatureEncoding, Signer};
        self.signing_key.sign(msg).to_bytes().to_vec()
    }
    fn verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        use ml_dsa::{KeyInit, Verifier};
        if pubkey.len() != Self::PUBKEY_LEN || sig.len() != Self::SIG_LEN {
            return false;
        }
        let pk_arr: ml_dsa::EncodedVerifyingKey<ml_dsa::MlDsa65> = match pubkey.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::new(&pk_arr);
        let sig_arr: ml_dsa::EncodedSignature<ml_dsa::MlDsa65> = match sig.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let signature = match ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(&sig_arr) {
            Some(s) => s,
            None => return false,
        };
        vk.verify(msg, &signature).is_ok()
    }
}

// ---------------- Cold wallet: real SLH-DSA-SHA2-128s (FIPS 205) ----------------
/// Deterministic SHA3-stream RNG so `generate(seed)` is reproducible.
/// Implements the `rand_core` 0.6 traits used by `slh-dsa`'s `signature`.
struct DetRng {
    seed: [u8; 32],
    ctr: u64,
    buf: Vec<u8>,
}
impl slh_dsa::signature::rand_core::RngCore for DetRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        while self.buf.len() < dest.len() {
            let mut h = Sha3_256::new();
            h.update(b"turn-dag-detrng");
            h.update(self.seed);
            h.update(self.ctr.to_be_bytes());
            self.buf.extend_from_slice(&h.finalize());
            self.ctr += 1;
        }
        dest.copy_from_slice(&self.buf[..dest.len()]);
        self.buf.drain(..dest.len());
    }
    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), slh_dsa::signature::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl slh_dsa::signature::rand_core::CryptoRng for DetRng {}

pub struct ColdWallet {
    signing_key: slh_dsa::SigningKey<slh_dsa::Sha2_128s>,
    pubkey: Vec<u8>,
}

impl PqWallet for ColdWallet {
    const PUBKEY_LEN: usize = 32;
    const SIG_LEN: usize = 7856;
    const SEED_LEN: usize = 32;
    fn generate(seed: &[u8; 32]) -> Result<Self, WalletError> {
        use slh_dsa::signature::Keypair;
        let mut rng = DetRng {
            seed: *seed,
            ctr: 0,
            buf: Vec::new(),
        };
        let sk = slh_dsa::SigningKey::<slh_dsa::Sha2_128s>::new(&mut rng);
        let pubkey = sk.verifying_key().to_bytes().to_vec();
        debug_assert_eq!(pubkey.len(), Self::PUBKEY_LEN);
        Ok(Self {
            signing_key: sk,
            pubkey,
        })
    }
    fn public_key(&self) -> &[u8] {
        &self.pubkey
    }
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        use slh_dsa::signature::Signer;
        let sig = self.signing_key.sign(msg);
        let bytes = sig.to_bytes().to_vec();
        debug_assert_eq!(bytes.len(), Self::SIG_LEN);
        bytes
    }
    fn verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        use slh_dsa::signature::Verifier;
        if pubkey.len() != Self::PUBKEY_LEN || sig.len() != Self::SIG_LEN {
            return false;
        }
        let vk = match slh_dsa::VerifyingKey::<slh_dsa::Sha2_128s>::try_from(pubkey) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let signature = match slh_dsa::Signature::<slh_dsa::Sha2_128s>::try_from(sig) {
            Ok(s) => s,
            Err(_) => return false,
        };
        vk.verify(msg, &signature).is_ok()
    }
}

// ---------------- ML-KEM-768 seed backup (real FIPS 203) ----------------
// Blob = ML-KEM ciphertext (1088 B) || masked seed (32 B) || SHA3 tag (32 B).
// The shared secret masks the seed; the tag binds ciphertext+masked seed.
pub struct KemKeypair {
    decapsulation: ml_kem::DecapsulationKey<ml_kem::MlKem768>,
    pubkey: Vec<u8>,
}

fn expand64(seed: &[u8; 32], domain: &[u8]) -> [u8; 64] {
    let mut out = Vec::with_capacity(64);
    let mut ctr: u64 = 0;
    while out.len() < 64 {
        let mut h = Sha3_256::new();
        h.update(domain);
        h.update(seed);
        h.update(ctr.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        ctr += 1;
    }
    let mut b = [0u8; 64];
    b.copy_from_slice(&out[..64]);
    b
}

impl KemKeypair {
    pub fn generate(seed: &[u8; 32]) -> Self {
        use ml_kem::KeyExport;
        let dk = ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed(ml_kem::Seed::from(
            expand64(seed, b"turn-dag-mlkem"),
        ));
        let pubkey = dk.encapsulation_key().to_bytes().to_vec();
        Self {
            decapsulation: dk,
            pubkey,
        }
    }
    pub fn encapsulation_key(&self) -> &[u8] {
        &self.pubkey
    }
    pub fn decrypt_seed(&self, blob: &[u8]) -> Result<[u8; 32], WalletError> {
        use ml_kem::{Ciphertext, Decapsulate};
        if blob.len() != KemKeypair::blob_len() {
            return Err(WalletError::DecryptFailed);
        }
        let (ct_bytes, rest) = blob.split_at(1088);
        let (masked, tag) = rest.split_at(32);
        let ct_arr: &[u8; 1088] = ct_bytes
            .try_into()
            .map_err(|_| WalletError::DecryptFailed)?;
        let ct: Ciphertext<ml_kem::MlKem768> = ml_kem::array::Array::from(*ct_arr);
        let shared = self.decapsulation.decapsulate(&ct);
        let stream = mask_stream(shared.as_slice(), 32);
        let mut h = Sha3_256::new();
        h.update(b"seed-backup-tag");
        h.update(ct_bytes);
        h.update(masked);
        h.update(shared.as_slice());
        if h.finalize().as_slice() != tag {
            return Err(WalletError::DecryptFailed);
        }
        let mut seed = [0u8; 32];
        for i in 0..32 {
            seed[i] = masked[i] ^ stream[i];
        }
        Ok(seed)
    }
    pub fn blob_len() -> usize {
        1088 + 32 + 32
    }
}

fn mask_stream(shared: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut ctr: u64 = 0;
    while out.len() < len {
        let mut h = Sha3_256::new();
        h.update(b"seed-backup-mask");
        h.update(shared);
        h.update(ctr.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        ctr += 1;
    }
    out.truncate(len);
    out
}

/// Encrypt a 32-byte wallet seed to an ML-KEM-768 encapsulation key.
pub fn seed_backup_encrypt(
    encapsulation_key: &[u8],
    seed: &[u8; 32],
) -> Result<Vec<u8>, WalletError> {
    use ml_kem::EncapsulationKey;
    let ek_arr: ml_kem::array::Array<u8, ml_kem::array::sizes::U1184> =
        match encapsulation_key.try_into() {
            Ok(a) => a,
            Err(_) => return Err(WalletError::BadKeyLength),
        };
    let ek = EncapsulationKey::<ml_kem::MlKem768>::new(&ek_arr)
        .map_err(|_| WalletError::BadKeyLength)?;
    // Deterministic encapsulation randomness derived from key+seed keeps
    // tests reproducible; production callers may randomize via encapsulate().
    let mut mh = Sha3_256::new();
    mh.update(b"turn-dag-mlkem-encap");
    mh.update(encapsulation_key);
    mh.update(seed);
    let digest: [u8; 32] = mh.finalize().into();
    let m: ml_kem::B32 = ml_kem::array::Array::from(digest);
    let (ct, shared) = ek.encapsulate_deterministic(&m);
    let stream = mask_stream(shared.as_slice(), 32);
    let masked: Vec<u8> = seed.iter().zip(stream.iter()).map(|(a, b)| a ^ b).collect();
    let mut h = Sha3_256::new();
    h.update(b"seed-backup-tag");
    h.update(ct.as_slice());
    h.update(&masked);
    h.update(shared.as_slice());
    let tag = h.finalize();
    let mut out = Vec::with_capacity(KemKeypair::blob_len());
    out.extend_from_slice(ct.as_slice());
    out.extend_from_slice(&masked);
    out.extend_from_slice(&tag);
    Ok(out)
}
