use turn_dag_wallet::*;
#[test]
fn hot_sizes_and_roundtrip() {
    assert_eq!(HotWallet::PUBKEY_LEN, 1952);
    assert_eq!(HotWallet::SIG_LEN, 3309);
    assert_eq!(HotWallet::SEED_LEN, 32);
    let w = HotWallet::generate(&[7u8; 32]).unwrap();
    assert_eq!(w.public_key().len(), 1952);
    let sig = w.sign(b"hello");
    assert_eq!(sig.len(), 3309);
    assert!(HotWallet::verify(w.public_key(), b"hello", &sig));
    assert!(!HotWallet::verify(w.public_key(), b"other", &sig));
    let w2 = HotWallet::generate(&[8u8; 32]).unwrap();
    assert!(!HotWallet::verify(w2.public_key(), b"hello", &sig));
    let mut tampered = sig.clone();
    tampered[0] ^= 1;
    assert!(!HotWallet::verify(w.public_key(), b"hello", &tampered));
    // deterministic address + bech32 round-trip
    let w_again = HotWallet::generate(&[7u8; 32]).unwrap();
    assert_eq!(w.address(), w_again.address());
    assert_eq!(w.address(), PqAddress::from_pubkey(w.public_key()));
    let enc = w.address().to_bech32();
    assert!(enc.starts_with("turn1"));
    assert_eq!(PqAddress::from_bech32(&enc).unwrap(), w.address());
}
#[test]
fn cold_sizes_and_roundtrip() {
    assert_eq!(ColdWallet::PUBKEY_LEN, 32);
    assert_eq!(ColdWallet::SIG_LEN, 7856);
    let w = ColdWallet::generate(&[3u8; 32]).unwrap();
    assert_eq!(w.public_key().len(), 32);
    let sig = w.sign(b"cold");
    assert_eq!(sig.len(), 7856);
    assert!(ColdWallet::verify(w.public_key(), b"cold", &sig));
    assert!(!ColdWallet::verify(w.public_key(), b"nope", &sig));
    let mut t = sig.clone();
    t[100] ^= 1;
    assert!(!ColdWallet::verify(w.public_key(), b"cold", &t));
}
#[test]
fn cold_wrong_key_and_errors() {
    let w = ColdWallet::generate(&[3u8; 32]).unwrap();
    let other = ColdWallet::generate(&[4u8; 32]).unwrap();
    let sig = w.sign(b"cold");
    assert!(!ColdWallet::verify(other.public_key(), b"cold", &sig));
    assert!(!ColdWallet::verify(&[0u8; 31], b"cold", &sig));
    assert!(!ColdWallet::verify(w.public_key(), b"cold", &sig[..100]));
    let again = ColdWallet::generate(&[3u8; 32]).unwrap();
    assert_eq!(w.address(), again.address());
    assert_eq!(w.address(), PqAddress::from_pubkey(w.public_key()));
}

#[test]
fn seed_backup_roundtrip() {
    let kem = KemKeypair::generate(&[5u8; 32]);
    assert_eq!(kem.encapsulation_key().len(), 1184);
    let blob = seed_backup_encrypt(kem.encapsulation_key(), &[9u8; 32]).unwrap();
    assert_eq!(blob.len(), KemKeypair::blob_len());
    assert_eq!(kem.decrypt_seed(&blob).unwrap(), [9u8; 32]);
    // Wrong KEM key cannot decrypt; tampered blob fails tag; bad key rejected.
    let wrong = KemKeypair::generate(&[6u8; 32]);
    assert!(wrong.decrypt_seed(&blob).is_err());
    let mut bad = blob.clone();
    bad[1100] ^= 1;
    assert!(kem.decrypt_seed(&bad).is_err());
    assert!(kem.decrypt_seed(&blob[..100]).is_err());
    assert!(seed_backup_encrypt(b"short", &[9u8; 32]).is_err());
}

#[test]
fn address_errors() {
    assert!(PqAddress::from_bech32("not-bech32").is_err());
    assert!(PqAddress::from_bech32("turn1qqqqqqqq").is_err());
}
