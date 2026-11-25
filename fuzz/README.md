# Fuzzing

libFuzzer targets for the parsers that face untrusted bytes:

```sh
cargo +nightly install cargo-fuzz   # once
cargo +nightly fuzz run stun_decode -- -max_total_time=60
cargo +nightly fuzz run fraud_proof_verify -- -max_total_time=60
cargo +nightly fuzz run channel_data -- -max_total_time=60
```

- `stun_decode`: `StunMessage::decode` + `decode_channel_data` must
  never panic (400+ mutation tests in `crates/turn-dag-turn` cover
  the deterministic subset; this is the open-ended version).
- `fraud_proof_verify`: fraud-proof JSON deserialization +
  `verify_fraud_proof` + `hex_decode` (an earlier build panicked on
  multi-byte UTF-8 in `hex_decode`; fixed at the root).
- `channel_data`: ChannelData encode/decode round-trips.

Crashes write to `fuzz/artifacts/<target>/` — none observed so far
(8.3M runs STUN, 7.1M fraud-proof, 4.5M channel-data).

The deterministic in-tree sweeps (`wire::mutation_tests`,
`crates/turn-dag-dag/tests/mutations.rs`) run under `cargo test` and
are the CI gate; this directory is for deeper local runs.
