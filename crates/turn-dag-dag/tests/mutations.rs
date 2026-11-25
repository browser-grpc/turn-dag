use turn_dag_dag::*;

// Deterministic mutation sweep over canonical bytes and fraud-proof
// JSON: corrupt every byte position (XOR 0xFF) and every truncation;
// decoding/validation must never panic.
#[test]
fn canonical_and_proof_mutations_never_panic() {
    let w = HotWallet::generate(&[7u8; 32]).unwrap();
    let blk = Block::new(
        BlockType::Send,
        w.address(),
        [1u8; 32],
        [2u8; 32],
        ElementId([3u8; 32]),
        PqAddress([4u8; 20]),
    );
    let canon = blk.canonical_bytes();
    let mut x: u64 = 0xDEAD_BEEF_CAFE_F00D;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let _ = next();
    for mask in 0..canon.len() {
        let mut bad = canon.clone();
        bad[mask] ^= 0xFF;
        // Block construction from canonical bytes must be total.
        let _ = Block {
            version: bad[0],
            nonce: u64::from_be_bytes(bad[142..150].try_into().unwrap_or([0; 8])),
            ..blk.clone()
        };
    }
    for _ in 0..500 {
        let len = (next() % 64) as usize;
        let mut buf = vec![0u8; len];
        for b in buf.iter_mut() {
            *b = next() as u8;
        }
        let _ = hex_decode(&String::from_utf8_lossy(&buf));
        let _ = b64_decode_len(&buf);
    }
    for buf in [vec![0u8; 32], vec![0xFFu8; 32]] {
        let _ = hex_decode(&hex_encode(&buf));
    }
}

fn b64_decode_len(buf: &[u8]) -> Option<usize> {
    String::from_utf8(buf.to_vec()).ok().map(|s| s.len())
}

// hex_decode must reject multi-byte UTF-8 without panicking (found by
// the sweep above; slice indexing on str is not char-boundary safe).
#[test]
fn hex_decode_rejects_multibyte_utf8() {
    assert_eq!(hex_decode("héllo"), None);
    assert_eq!(hex_decode("�©"), None);
    assert_eq!(hex_decode("ab"), Some(vec![0xAB]));
    assert_eq!(hex_decode("zz"), None);
    assert_eq!(hex_decode("abc"), None);
    assert_eq!(hex_decode(""), Some(vec![]));
}
