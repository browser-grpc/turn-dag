# turn-dag

PoW pay-per-use TURN rendezvous on a DAG, with post-quantum wallets.

Small DataChannel rendezvous only, not media. 1 indivisible mined element = 1 rendezvous, 120s, 16 kB/s. Elements cannot be subdivided, ownership can be transferred. Double spend across untrusted TURN servers is detected via DAG fork / fraud proof and penalized by bond slash.

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

Spec only, no code yet.

## License

Apache License 2.0, see LICENSE.
