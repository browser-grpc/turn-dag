// cargo fuzz run fraud_proof_verify -- -max_total_time=60
#![no_main]
use libfuzzer_sys::fuzz_target;
use turn_dag_dag::*;
use turn_dag_element::*;
use turn_dag_wallet::*;

fuzz_target!(|data: &[u8]| {
    // hex_decode path (found a UTF-8 panic here historically).
    let _ = hex_decode(&String::from_utf8_lossy(data));
    // Fraud proof JSON deserialization must be total.
    let s = String::from_utf8_lossy(data);
    if let Ok(proof) = serde_json::from_str::<FraudProof>(&s) {
        let mut dag = Dag::new();
        let _ = dag.verify_fraud_proof(&proof);
    }
    let _ = hex_decode(&s);
});



