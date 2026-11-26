# turn-dag

PoW pay-per-use TURN relay passes on a DAG, with post-quantum wallets.

Small DataChannel relay only, not media. 1 indivisible mined element = 1 relay pass (a 120s credential; called "rendezvous" in the spec PDF - not grpc-dc's rendezvous endpoint), 16 kB/s. Elements cannot be subdivided, ownership can be transferred. Double spend across untrusted TURN servers is detected via DAG fork / fraud proof and penalized by bond slash.

## Spec

- `docs/bond-contract-fraud-proof-spec.pdf` — Bond Contract and Fraud-Proof Spec, 16 pages
  - Nano-style block-lattice DAG, many untrusted participants
  - Bond contract: 5 lock blocks, slash by representative vote, 1 element bounty to reporter, 4 burned
  - Fraud proof: two conflicting ML-DSA-65 signatures on the same element_id, plus fork evidence
  - Minting: inflationary PoW supply, Argon2id / RandomX, epoch-anchored difficulty retarget
  - PQ wallets: ML-DSA-65 hot, SLH-DSA-128s cold
  - All TCP via a user-space stack, e.g. smoltcp, no kernel TCP. UDP relay for DataChannel stays UDP.

## Docker — all build/test/tool/run/ci in one file

No host tooling beyond Docker. All concerns live in `Dockerfile`:

```
docker build -t turn-dag .
docker run --rm turn-dag test
docker run --rm turn-dag build
docker run --rm -it turn-dag tool
docker run --rm turn-dag run
docker run --rm turn-dag ci
```

CI should only checkout, `docker build`, and `docker run`. Build, test, tool, run, and CI logic lives in `Dockerfile` + `scripts/`.

## Status

Implemented in Rust (workspace of 6 crates, no longer spec-only):

- `turn-dag-element` / `turn-dag-wallet`: indivisible elements; all PQ is real — hot ML-DSA-65 (`ml-dsa`), cold SLH-DSA-SHA2-128s (`slh-dsa`, 32B/7856B), ML-KEM-768 seed backup (`ml-kem`, blob = KEM ct || masked seed || tag).
- `turn-dag-dag`: block-lattice DAG, representative voting (≥67%, 5s epoch ticks), bonds, fraud proofs, slashing (1 bounty / 4 burned).
- `turn-dag-minter`: Argon2id mint PoW, epoch-bound challenges, difficulty retarget.
- `turn-dag-turn`: TURN issuer logic (120s credentials, quotas, SSRF denied-peer list), a smoltcp user-space stack on a virtual device, and a TURN wire server (`wire`: STUN framing + Allocate/Refresh/CreatePermission/ChannelBind/Send-Data, 120s cap, denied peers 403). No kernel TCP. Live servers: UDP relay (`serve-udp`) and `turns:` TLS 5349 (`serve-tls`, rustls over smoltcp TCP on a non-blocking TUN device).
- `turn-dag-node`: CLI binary (`--help`, `init`, `status`, `mint`, `transfer`, `burn`, `relaypass`, `demo`, `stack`) wiring all crates in-process.

Verify: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all -- --check`, or `docker build -t turn-dag . && docker run --rm turn-dag test`.

## License

Apache License 2.0, see LICENSE.
