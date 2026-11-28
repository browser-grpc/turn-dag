# TODO — turn-dag

Resume file for Muse Code. Read this, `README.md`, and
`docs/bond-contract-fraud-proof-spec.pdf` (16 pages, authoritative spec)
before writing code. Implementation language is **Rust**.

## Project

- Repo: https://github.com/browser-grpc/turn-dag
- Public, Apache-2.0. Org: browser-grpc. Owner: unicomp21.
- Goal: PoW pay-per-use TURN relay passes on a DAG, with post-quantum wallets.
- Terminology: the burn-for-credential unit is a **relay pass** (`turn-dag-node relaypass`, `issue_relay_pass`); the spec PDF calls it "rendezvous", which now collides with grpc-dc's rendezvous (a pre-published fixed server endpoint), so docs/code prefer relay pass. The old CLI name and Rust fn were removed outright (nothing is released yet, so no compatibility aliases are kept).
- TURN is only for small DataChannel communication (a relay pass), not media.
- 1 indivisible mined element = 1 relay pass: 120s, 16 kB/s (`max-bps=16384`),
  ~1.9 MB max per direction, ~$0.00002 at $0.01/GB.
- Elements cannot be subdivided. Ownership can be transferred.
  Wallet balance = count of elements owned. No amount field, no dust.

## SUPERSEDED 2026-11-26 — serial per-node ledger replaces the DAG

Directed by the user ("distributed dag is too complex, just use
ledger per node, coins bound to originating node" / "do it, go"):

- `turn-dag-dag` is **deleted**. In its place, `turn-dag-ledger`:
  each node keeps one append-only, hash-chained serial log of the
  coins it originated; it is the single writer for them, so a
  double spend is rejected atomically (AlreadySpent) at
  transfer/burn time. Foreign coins are absent, never honored.
- **Bonds are removed entirely** (no BondLock/BondRelease, no
  spend gate, no slash votes, no freeze-on-gossip): prevention at
  the origin replaces detection-plus-punishment. Burns produce
  origin-signed `BurnReceipt`s, verifiable offline; two conflicting
  signed receipts are equivocation evidence.
- Representative voting/finality, forks, fraud proofs, and the
  spent-set CRDT are gone with the DAG crate. The fraud-proof fuzz
  target became `ledger_receipt`. Mint PoW, PQ wallets, issuer,
  wire protocol, TURN servers, quotas and rate limits are unchanged.
- The spec PDF and the sections below describe the superseded
  design and are kept as history. This section wins on conflict.

## Decisions already made — do not re-litigate without asking John

- **DAG, not linear ledger.** Many untrusted participants, no central
  sequencer, no trusted coordinator.
  Nano-style block-lattice: one chain per PQ wallet, each transfer is a
  block in that chain. Double spend = fork (two blocks, same predecessor,
  same element). General DAG layer: 2 parents per block (own predecessor
  + cross-chain tip), tip selection, representative voting / cumulative
  weight, finality at ≥67% of online voting weight sustained one 5s vote
  epoch. Losing branch orphaned but retained as evidence.
- **Bond:** 5 elements locked as bond UTXOs, not spendable for TURN.
  Spend gate enforced by voters (no bond, no burn votes). 24h timelocked
  release, cancelled by any in-window fraud proof. Slash by consensus:
  anyone submits a slash claim, representatives vote it to confirmation,
  1 element bounty to reporter, 4 burned. Freeze-on-gossip + gossiped
  blacklist. Slash must be ≥100x the double-spend gain.
- **Fraud proof:** two conflicting ML-DSA-65 signatures, same owner
  pubkey / element_id, different to_address / nonce, plus fork evidence
  (both blocks + shared predecessor). JSON wire format, ~12–14 KB.
  5 offline verification conditions. Gossip, freeze → slash-vote → blacklist.
  Fix per-element spend nonce to 0 so any two sigs on that id conflict.
- **Minting / inflation:** inflationary PoW supply, no cap. Fixed issuance
  per day, e.g. 10,000/day, epoch-anchored difficulty retarget (24h epoch,
  0.25x–4x clamp). Argon2id default, RandomX heavyweight alternative.
  SHA256 is NOT for minting (GPU/ASIC vulnerable). TURN PoW (20 bits,
  ~1M hashes) is separate from mint PoW — same solution must never both
  grant TURN and mint. Mint blocks attach to the miner's own chain.
- **PQ wallets:** hot = ML-DSA-65 (FIPS 204, pub 1,952 B, priv 4,032 B,
  sig 3,309 B, seed 32 B). Cold/treasury = SLH-DSA-128s (pub 32 B,
  sig 7,856 B). Address = hash of pubkey (bech32 of SHA3-256(pub)[:20]).
  Do not use ECDSA/Ed25519 alone. ML-KEM for encrypting seed backup/sync.
- **Spend for TURN:** burn to unspendable sink `SHA3-256("burn")` by default.
  1 element in, 1 rendezvous out. Net supply = minted − burned.
  Pay-to-issuer variant is noted in the spec, not chosen.
- **TURN tuning (rendezvous only):**
  `max-allocate-lifetime=120`, `user-quota=1`, `total-quota=200`,
  `max-bps=16384` (bytes/sec, not bits), `bps-capacity=3276800`,
  `no-tcp-relay` in coturn terms — but see TCP rule below.
  Credential: per-session, 15–60 min normally, 120s for rendezvous,
  username = expiry, password = base64(HMAC-SHA1(secret, username)).
  PoW/Turnstile in front of credential issuance, not in TURN RFC.
  If direct host/srflx succeeds, drop relay. If still relayed at 90s,
  solve next PoW in background and `restartIce()`.
  Hardening: `denied-peer-ip` for 0/8, 10/8, 100.64/10, 127/8,
  169.254/16, 172.16/12, 192.168/16, 192.0.0/24, 198.18/15, 224/4,
  240/4, IPv6 ::1, fc00::/7, fe80::/10. No loopback/multicast peers.
  SSRF to 169.254.169.254 is the main relay attack — see CVE-2026-100251.
- **All TCP via user-space stack.** No kernel TCP anywhere.
  Use smoltcp (Rust, no_std, poll-based SocketSet, TUN/TAP or raw-packet
  Device) for TURN TCP (3478) and TURN over TLS (5349), any TCP relay
  allocation and its outbound peer leg, DAG gossip, mint server, and
  issuer/ledger APIs. Alternatives: lwIP, picoTCP, gVisor netstack, uIP.
  TLS via rustls over smoltcp sockets. No TSO assumption.
  Stock coturn on kernel sockets does NOT comply — build on smoltcp,
  front it, or disable TCP TURN.
  UDP stays UDP: WebRTC DataChannel (SCTP/DTLS/UDP), TURN UDP relay, STUN/ICE.
- **Docker:** all build/test/tool/run/ci concerns live in `Dockerfile`.
  No host tooling beyond Docker. `scripts/build.sh`, `scripts/test.sh`.
  CI should only checkout, `docker build`, `docker run`.

## Current state (2026-11-25)

- Steps 1–8 implemented in Rust (6-crate workspace, uncommitted for review):
  element/wallet, DAG, minter, TURN issuer + smoltcp stack, node binary.
- PQ status: HotWallet uses the REAL `ml-dsa` 0.1.2 crate (ML-DSA-65,
  pub 1952B / sig 3309B). ColdWallet SLH-DSA-128s and ML-KEM seed backup
  were test doubles; as of the coverage pass ALL PQ is real (see §3).
- TURN handlers are pure data models; smoltcp stack is a virtual-device
  transport only — no live TURN wire-protocol server yet.
- `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo fmt --all -- --check`, `docker build` + `docker run --rm turn-dag test`
  all pass (Docker needs Rust 1.87: `ml-dsa` requires rustc ≥1.87).

## Implementation in Rust — work plan

Do in order. Each step: implement, test in Docker, commit, do not skip tests.

### 1. Workspace skeleton — [x] done (6 crates, fmt/clippy in Dockerfile+scripts)
- `Cargo.toml` workspace, edition 2021, Rust 1.85+.
- Crates: `turn-dag-element`, `turn-dag-wallet`, `turn-dag-dag`,
  `turn-dag-minter`, `turn-dag-turn`, `turn-dag-node` (binary).
- `cargo fmt`, `cargo clippy -- -D warnings` in CI via Dockerfile.
- Keep `Dockerfile` as the only build/test entrypoint; update it if a
  new crate needs a system dep, do not add host setup docs.

### 2. Element / UTXO types — [x] done (turn-dag-element; nonce fixed 0, burn sink SHA3-256("burn")[:20])
- `ElementId = SHA256(challenge || nonce || miner_pq_address)`
- `Element { id, owner: PqAddress, status: Unspent|Spent|Burned, mint_epoch }`
- No amount field. Any split / amount != 1 is rejected.
- `Transfer { element_id, from_pubkey, to_address, nonce }`,
  `sig = ML-DSA-65.Sign(from_priv, SHA3-256(tx))`
- Verify: element exists/unspent, from_pubkey hashes to current owner,
  sig verifies, nonce not used, atomically mark spent and create new
  record with same element_id and new owner (provenance preserved).
- Burn: transfer to sink `SHA3-256("burn")`.

### 3. PQ wallet — [x] done, all real crates (hot ML-DSA-65 `ml-dsa`; cold SLH-DSA-SHA2-128s `slh-dsa` 32B/7856B; ML-KEM-768 `ml-kem` seed backup; signature pinned =2.3.0-pre.4 for slh-dsa)
- Crates: `pqcrypto-dilithium` / `liboqs` bindings, or `pqcrypto` + `oqs`.
  Verify ML-DSA-65 sizes against spec before locking a crate.
- `Wallet::generate() -> 32-byte seed`, `address()`, `sign()`, `verify()`.
- Cold wallet: SLH-DSA-128s, same trait, different key/sig sizes.
- ML-KEM for seed backup encryption. Never log a seed or private key.
- Tests: known-answer / round-trip sign-verify, wrong-key fails,
  address derivation is deterministic.

### 4. DAG / block-lattice — [x] done (turn-dag-dag; Storage trait with InMemory + SQLite `SqliteStorage` impls, blocks table per §9.3)
- `Block { id, owner_chain, predecessor, parents: [own_prev, cross_tip], payload: Mint|Transfer|BondLock|BondRelease|SlashClaim, sig }`
- Per-wallet chain, append-only, fork detection: two blocks with same
  predecessor = fork.
- Tip selection, gossip (smoltcp TCP, see §6), spent-set CRDT
  (union / weight-max merge).
- Voting: representatives, cumulative weight, finality ≥67% for one
  5s epoch. Losing branch orphaned, retained as evidence.
- No TURN allocation on local view alone — allocation waits for burn
  confirmation weight. State the 1–5s latency tradeoff in code comments.
- Storage: SQLite/Postgres for node state in v1, with the SQL tables
  from spec § (elements, blocks, votes, bonds, blacklist). Keep the
  storage trait so a later embedded store can swap in.

### 5. PoW minter — [x] done (argon2 Argon2id, epoch-bound challenges, retarget clamp 0.25x-4x, economics >=100x test)
- Argon2id (crate `argon2`) default, RandomX behind a feature flag.
- Challenge: random, difficulty, 30s expiry, IP-bound for TURN PoW;
  mint challenge is epoch-bound, not IP-bound.
- Difficulty retarget per 24h epoch to hit 10,000 mints/day, clamp 0.25x–4x.
- Mint block on the miner's own chain, with PoW solution attached.
- Verify in 1 hash / 1 Argon2 verify, mark challenge single-use (Redis
  in prod, in-memory + SQLite in v1).
- Economics test: mint cost in time, double-spend gain ~$0.00002,
  slash loss 5 elements, assert ≥100x penalty in a test.

### 6. TURN issuer + smoltcp TURN — [x] done: pure-logic issuer + smoltcp VirtualDevice stack + TURN wire server (Allocate/Refresh/Permission/ChannelBind/Send-Data). Not yet: live TUN/TAP device, rustls TLS listener
- Issuer API: `GET /challenge`, `POST /redeem` → 120s TURN creds,
  `username = expiry:pow:<ticket_id>`, 1 ticket per allocation,
  2 tickets per rendezvous if both peers are behind symmetric NAT.
- TURN server in Rust on smoltcp, not coturn. Implement:
  TURN over UDP (allocation, refresh, permissions, channel bind),
  TURN over TCP/TLS via smoltcp + rustls, `no-tcp-relay` semantics
  at the smoltcp admission layer, `denied-peer-ip` enforcement in
  the stack, per-allocation `max-bps=16384`, `max-allocate-lifetime=120`.
- Relay: if direct succeeds, drop relay; if still relayed at 90s,
  background PoW + `restartIce()`.
- Tests: SSRF blocked (169.254.169.254, RFC1918, loopback), quota
  enforced, 120s expiry enforced, 1.9 MB cap enforced.

### 7. Bond + fraud proof + slashing — [x] done (5-element bond, 5-condition fraud proof ~12.6KB JSON, slash 1 bounty/4 burned; Examples A/B/C as tests)
- Bond lock blocks: 5 elements, spend gate in voter logic.
- Fraud proof wire format from spec: `{element_id, tx1, sig1, tx2, sig2,
  fork_block_a, fork_block_b, predecessor}`.
- Verify offline: 5 conditions in spec, no network needed.
- Slash flow: gossip proof → freeze all unspent elements of that
  pubkey → slash vote → on confirmation, 1 element bounty to reporter,
  4 burned, pubkey to shared blacklist, adaptive PoW +4 bits for that
  IP/pubkey.
- Worked examples in spec A (valid transfer), B (double spend),
  C (slash) — turn each into a Rust test. Hashes in the spec are
  shortened illustrative fragments, not test vectors — recompute them.

### 8. Node binary + Docker — [x] done (turn-dag-node CLI, workspace integration tests incl. 3-node A/B/C + two-issuer race + TCP audit; Dockerfile/scripts run real cargo; docker build/run verified; no GitHub Actions YAML added)
- `turn-dag-node`: DAG node + minter + issuer + TURN, all on smoltcp.
- `docker build -t turn-dag .`, `docker run --rm turn-dag test`,
  `docker run --rm turn-dag ci` must pass before any push.
- Add GitHub Actions only as a thin wrapper around Docker (checkout,
  build, run). Do not put build/test logic in YAML.

## Browser e2e (Playwright) — gaps filled 2026-11-25

- `tests/browser/run.mjs` now runs Firefox **and** Chromium, plus raw
  UDP/STUN wire sub-tests against the live `serve-udp` servers:
  allocate lifetime 120s, TCP refused 442, denied-peer 403
  (169.254.169.254/RFC1918/loopback), refresh cap/delete/437,
  byte-cap (exactly 983×2000B = 1,966,000B delivered, then drop),
  total-quota 486 (`--total-quota`), one live allocation per issuer
  ticket 486, REST valid/forged/expired (401), expired + negative
  browser credentials, public STUN controls (Google
  `stun.l.google.com:19302` + Cloudflare `stun.cloudflare.com:3478`,
  srflx candidates in both engines), and a real burn→challenge/PoW→
  redeem→ticket→browser Allocate flow (`turn-dag-node relaypass`
  now mints credentials with wall-clock expiry). `tls-turns` SKIPs:
  no live 5349 listener exists yet (rustls-over-smoltcp only).
- Hard gate: `scripts/browser-test.sh` (Docker `--network host`)
  sets `REQUIRE_RELAY=1 MIN_PASS=10`; gather/relay/issuer failures
  are FAIL there, SKIPs elsewhere (GitHub loopback job).
- Three live-wire bugs found by the new suite and fixed in
  `crates/turn-dag-turn/src/wire.rs`: STUN class bits were swapped
  (Allocate success went out as 0x0013, an indication, so browsers
  retransmitted forever), FINGERPRINT now follows RFC 8489 §14.7
  (CRC excluding the attribute), and REST-authenticated responses
  are MESSAGE-INTEGRITY signed like static ones. Regression tests:
  `stun_type_wire_values_match_rfc8489`,
  `signed_allocate_response_carries_valid_fingerprint`,
  `rest_auth_accepts_issuer_credential_and_rejects_expired`,
  `total_quota_486_and_ticket_single_allocation`.
- Cross-engine rendezvous: Firefox↔Chromium (plus 32 KiB binary
  payload, checksum-verified), Firefox↔WebKit, Chromium↔WebKit, and
  WebKit↔WebKit all pass relay/relay in Docker; an issuer-credential
  pair (fresh DAG-burn ticket + second registered ticket, burn-gated
  relay) also passes. WebKit launches without `--no-sandbox`
  (it rejects the flag) and SKIPs on hosts lacking its OS deps.
- Three-peer mesh (all 3 pairs relay/relay) and the 90s
  `restartIce()` renewal (DataChannel verified alive after restart
  at ~100s; candidates must be drained for a fixed window since
  connectionState never drops) pass in the browser suite.
- Live `turns:` (TLS 5349): `turn-dag-node serve-tls` runs rustls
  over smoltcp TCP on a TUN device (`LiveTlsTurnServer`, multiple
  connections, cross-connection ChannelData routing). Found and
  fixed: the TUN fd must be O_NONBLOCK or smoltcp's poll loop never
  reaches egress. Operator: create the TUN, then
  `ip addr add 10.99.0.2/24 dev turndag0 && ip link set turndag0 up`
  (host-side address differs from the stack's 10.99.0.1).
  Chromium gathers a relay candidate over `turns:` in Docker
  (`--cap-add NET_ADMIN --device /dev/net/tun`) and a full
  Chromium DataChannel pair over `turns:` passes (this required
  two more fixes: a pool of listening smoltcp sockets — one
  listener RSTs simultaneous connects — and RFC 8656 padded
  ChannelData stream framing in `take_frame`). Firefox turns:
  SKIPs with evidence — packet capture shows this Firefox build
  attempts `turn:?transport=tcp` but never initiates `turns:`.
- Verified: `cargo test --workspace` (90 tests after the ledger cutover), clippy, fmt,
  `docker build --target ci`, and
  `docker build --target browser && docker run --rm --network host --cap-add NET_ADMIN --device /dev/net/tun turn-dag:browser`
  (52 passed, 3 skipped — Firefox + WebKit turns and fresh-context
  passkey sync — 0 failed).

## Virtual network, rate limiting, scale, CI gate (2026-11-25)

- **Virtual network (Rust): yes, implemented.** `turn-dag-turn::vnet`
  is a shared switch connecting any number of smoltcp stacks by IPv4
  address, with deterministic latency (`with_latency_ticks`) and loss
  (`with_drop_every`) knobs. It answers "multi-node tests without
  TUN/root/Docker": real IP packets between stacks under `cargo test`
  in milliseconds. The FdDevice/TUN path remains for live traffic only.
- **max-bps is now enforced in the wire server**: per-allocation
  token bucket (16384 B/s, 1s burst; `with_max_bps`, 0 disables).
  The ~1.9MB total byte cap is proven in Rust with a synthetic clock;
  the browser suite asserts the live burst rate (`wire-bps-rate`).
- **Browser longevity + scale**: a Firefox session must stay alive
  past the 120s allocation lifetime via client Refresh
  (`relay:allocation-longevity-120s`), and the suite adds 50
  concurrent raw allocations plus 5 simultaneous Chromium relay pairs.
- **CI gates it**: the GitHub browser workflow now only builds and
  runs the Docker host-network/TUN suite; the loopback job that
  skipped everything is gone. Playwright engine coverage is
  Blink (Chromium), Gecko (Firefox), and WebKit — every shipping
  engine family; Edge is Blink, and Playwright WebKit approximates
  (does not equal) real Safari, which no CI here can run.

## Browser wallet + browser PoW (2026-11-26)

- The browser PQ wallet is **WebAuthn-based**: `web/` registers a
  passkey with the PRF extension, auth evaluates PRF over a fixed
  domain salt, HKDF expands the output into the ML-DSA-65 seed
  (@noble/post-quantum). Same passkey → same wallet address
  (SHA3-256(pubkey)[..20], matching the Rust derivation). No silent
  seed fallback: without PRF the wallet refuses to derive keys.
  Note: WebAuthn needs the `localhost` origin (IP-literal RP IDs
  are rejected), and Chromium's CDP virtual authenticator needs
  `hasPrf: true` to exercise the real flow in tests.
- **All PoW happens in the browser**: TURN PoW (SHA-256) and mint
  PoW (Argon2id at the minter's cheap params) are solved in-page
  via hash-wasm; the Rust node only verifies. Stateless CLI
  oracles: `pow-challenge`/`pow-verify`, `mint-challenge`/
  `mint-verify`, `sig-verify --pubkey`. Playwright sub-tests
  (`browser-wallet:*`, `browser-pow:*`) run the real register →
  auth/PRF → sign → solve flows against those oracles.
- Serialized cross-party artifacts use **CBOR (serde/ciborium)**
  where serialization is needed, starting with `BurnReceipt`
  (`to_cbor`/`from_cbor`, byte-string fields, canonical roundtrip
  test). Key references stay hash-based where appropriate:
  a 20-byte SHA3-256 digest stands in for the 1,952-byte pubkey.

## Coverage gaps filled (2026-11-26)

- **Burn-replay fixed**: `TurnIssuer` now keeps a spent-burn
  registry — one burn = one relay pass (`BurnAlreadyRedeemed`, 409),
  consumed only on success; symmetric-NAT two-ticket passes still
  work, other-user replays do not allocate. Regression:
  `same_burn_cannot_redeem_twice`. (Registry is in-memory like the
  challenge store; persist it with the issuer state in production.)
- **Production PoW in browser**: 20-bit TURN PoW and production
  Argon2id (64MiB, t=3, p=4) solved in-page and verified by the
  Rust CLI (`browser-pow:turn-20bit`, `browser-pow:mint-production`;
  ~0.2-2.4s on CI-class hardware). Cheap-parameter tests remain.
- **Direct path**: `direct:stun-datachannel` proves a full
  DataChannel over public STUN with a non-relay selected pair
  (host/prflx locally) — the direct path is no longer gather-only.
- **Wallet negatives/recovery**: unlock without a passkey fails,
  an empty/wrong authenticator cannot unlock, and after a page
  reload the same passkey re-derives the identical wallet with
  no re-registration (`browser-wallet:*`). Caveat: a second
  *tab's* WebAuthn ceremony hangs in headless Chrome, so recovery
  is asserted across reloads, not tabs.
- **WebKit turns**: attempted in the TUN gate next to Chromium.
- **Fresh-context derivation**: probed via credential export →
  import into a fresh context's authenticator (passkey-sync
  model). Plain cross-context assertion works, but imported CDP
  virtual-authenticator credentials carry no hmac-secret/PRF
  material, so `browser-wallet:fresh-context` records SKIP with
  that exact reason; real synced platform passkeys re-derive
  PRF on-device. Second-tab ceremonies also hang in headless
  Chrome — both are environment limits, documented, not faked.
- **Burn replay also at node/suite levels**:
  `Node::relay_pass` consumes the burn in the origin ledger
  (`node_relay_pass_consumes_burn_exactly_once`), and
  `issuer:burn-replay-stdio` drives one long-lived TurnIssuer
  through the stateful `issuer-stdio` oracle: burn A redeems,
  its replay is `BurnAlreadyRedeemed`, burn B still redeems.

## Decisions (settled 2026-11-25, "go all, pick as needed")

- Mint issuance: **10,000/epoch stands** (configurable via
  `MinterConfig.target_per_epoch`; retarget clamp [0.25x, 4x] over 24h).
  Rationale: already the shipped/tested default; changing supply
  economics needs usage data, not guesswork. Revisit with metrics.
- Representative set: **delegation-based voting stands** (any node
  can register/delegate; weight is stake, equivocation discards both
  votes). A fixed-set mode is explicitly not built. Rationale: fixed
  sets contradict the untrusted-participant design goal.
- TURN server identity: **one binary per node stands**
  (`turn-dag-node serve-udp` + `serve-tls`, issuer creds optional).
  Split issuer/relay roles are explicitly not built. Rationale: role
  split is an ops topology choice the single binary already covers.
- Bounty/slash split: **spec rule 1 reporter / 4 burned stands**,
  enforced by validation. Rationale: it is the spec's ≥100x economics;
  do not tune without a spec change.
All four remain code-configured values, so any decision can be
revisited without a rewrite; they are no longer open questions.

## How to resume in Muse Code

1. `git clone https://github.com/browser-grpc/turn-dag.git`
2. Read `TODO.md`, `README.md`, `docs/bond-contract-fraud-proof-spec.pdf`.
3. `docker build -t turn-dag . && docker run --rm turn-dag test`
4. Pick the next unchecked step in § Implementation, implement it in Rust,
   add tests, update this TODO.md (check off, add notes), commit.
5. Do not re-publish, re-mint, or change the spec PDF without asking John.
6. Do not use kernel TCP, do not use a central sequencer, do not split elements.
