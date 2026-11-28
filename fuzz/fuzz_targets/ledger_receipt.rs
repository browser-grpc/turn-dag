// cargo fuzz run ledger_receipt -- -max_total_time=60
#![no_main]
use libfuzzer_sys::fuzz_target;
use turn_dag_ledger::*;
use turn_dag_wallet::*;

fuzz_target!(|data: &[u8]| {
    // hex_decode path (found a UTF-8 panic here historically).
    let s = String::from_utf8_lossy(data);
    let _ = hex_decode(&s);
    // Receipt signature verification must be total on junk input.
    if data.len() >= 84 {
        let mut id = [0u8; 32];
        id.copy_from_slice(&data[..32]);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[32..64]);
        let receipt = BurnReceipt {
            element_id: turn_dag_element::ElementId(id),
            entry_hash: hash,
            seq: u64::from_be_bytes(data[64..72].try_into().unwrap()),
            origin: PqAddress([0u8; 20]),
            origin_pubkey: data[72..].to_vec(),
            origin_sig: vec![0u8; 3309],
        };
        let _ = receipt.verify_signature();
    }
});
