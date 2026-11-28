//! Argon2id PoW minter (TODO sections 5-6).
//!
//! Mint PoW is Argon2id and epoch-bound (not IP-bound). TURN PoW is a
//! separate SHA-256 construction in `turn-dag-turn` with a distinct
//! solution type; a mint solution can never be a TURN solution and
//! vice versa (distinct types, distinct hash functions, distinct
//! challenge derivations, enforced by tests in both crates).
//!
//! No wall-clock sleeps: every time-dependent function takes a
//! deterministic `now` (unix seconds) parameter.

use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use turn_dag_element::ElementId;
use turn_dag_wallet::PqAddress;

/// Config for the minter. Issuance target and epoch length are
/// parameters (spec open question: 10_000/day is an example), never
/// hardcoded magic numbers at call sites.
#[derive(Clone, Debug, PartialEq)]
pub struct MinterConfig {
    /// Target mints per epoch (default 10_000).
    pub target_per_epoch: u64,
    /// Epoch length in seconds (default 24h = 86_400).
    pub epoch_secs: u64,
    /// Challenge lifetime in seconds (spec: 30).
    pub challenge_ttl_secs: u64,
    /// Argon2id memory cost in KiB.
    pub argon_m_cost_kib: u32,
    /// Argon2id time cost (iterations).
    pub argon_t_cost: u32,
    /// Argon2id lanes.
    pub argon_p_cost: u32,
    /// Argon2id output length.
    pub argon_out_len: usize,
}

impl Default for MinterConfig {
    fn default() -> Self {
        Self {
            target_per_epoch: 10_000,
            epoch_secs: 86_400,
            challenge_ttl_secs: 30,
            // ASIC-resistant default (64 MiB, t=3, p=4): the spec rejects
            // SHA256 PoW precisely because GPU/ASICs trivialize it.
            argon_m_cost_kib: 65_536,
            argon_t_cost: 3,
            argon_p_cost: 4,
            argon_out_len: 32,
        }
    }
}

impl MinterConfig {
    /// Cheap Argon2 params for tests (still real Argon2id).
    pub fn cheap_for_tests() -> Self {
        Self {
            argon_m_cost_kib: 256,
            argon_t_cost: 1,
            argon_p_cost: 1,
            ..Self::default()
        }
    }
}

/// Difficulty as expected number of Argon2 evaluations (work factor).
/// A hash meets difficulty `d` iff hash < 2^256 / d (big-endian).
pub type Difficulty = u64;

fn threshold_bytes(difficulty: Difficulty) -> [u8; 32] {
    if difficulty <= 1 {
        return [0xff; 32];
    }
    // floor(2^256 / difficulty): divide the 33-byte big-endian
    // representation of 2^256 (a 1 followed by 32 zero bytes) by
    // `difficulty`, byte by byte.
    let mut quotient = [0u8; 33];
    let mut rem: u128 = 0;
    let d = difficulty as u128;
    for (i, q) in quotient.iter_mut().enumerate() {
        let cur = (rem << 8) | if i == 0 { 1u128 } else { 0u128 };
        *q = (cur / d) as u8;
        rem = cur % d;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&quotient[1..]);
    out
}

/// True iff `hash` (32-byte BE) meets `difficulty`.
pub fn meets_difficulty(hash: &[u8; 32], difficulty: Difficulty) -> bool {
    if difficulty <= 1 {
        return true;
    }
    *hash < threshold_bytes(difficulty)
}

/// Difficulty retarget for the next 24h epoch:
/// `next = now * observed / target`, clamped to `[0.25x, 4x]` of `now`.
/// All quantities come from `cfg`; result is at least 1.
pub fn difficulty_next(current: Difficulty, observed_mints: u64, cfg: &MinterConfig) -> Difficulty {
    if current == 0 {
        return 1;
    }
    let target = cfg.target_per_epoch.max(1) as u128;
    let raw = (current as u128) * (observed_mints as u128) / target;
    let lo = ((current as u128) / 4).max(1);
    let hi = (current as u128) * 4;
    raw.clamp(lo, hi).min(u64::MAX as u128) as u64
}

/// A mint challenge. `challenge = SHA256(epoch_be || miner || frontier)`.
/// Epoch-bound, deliberately NOT IP-bound (contrast TURN PoW).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintChallenge {
    pub epoch: u64,
    pub miner: PqAddress,
    pub dag_frontier_hash: [u8; 32],
    pub challenge: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    pub difficulty: Difficulty,
}

pub fn derive_challenge(epoch: u64, miner: &PqAddress, dag_frontier_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(epoch.to_be_bytes());
    h.update(miner.0);
    h.update(dag_frontier_hash);
    h.finalize().into()
}

/// A mint PoW solution. Distinct type from any TURN PoW solution;
/// there is intentionally no conversion between the two.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintSolution {
    pub challenge: [u8; 32],
    pub nonce: u64,
    /// Argon2id output for (challenge, nonce); verified in 1 Argon2 run.
    pub hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MintError {
    UnknownChallenge,
    ChallengeExpired,
    ChallengeAlreadyUsed,
    EpochMismatch,
    BadWork,
    DifficultyNotMet,
}

fn argon2_hash(
    cfg: &MinterConfig,
    challenge: &[u8; 32],
    nonce: u64,
) -> Result<[u8; 32], MintError> {
    let params = Params::new(
        cfg.argon_m_cost_kib,
        cfg.argon_t_cost,
        cfg.argon_p_cost,
        Some(cfg.argon_out_len),
    )
    .map_err(|_| MintError::BadWork)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut password = Vec::with_capacity(40);
    password.extend_from_slice(challenge);
    password.extend_from_slice(&nonce.to_be_bytes());
    // Salt: first 16 bytes of the challenge (deterministic, >= 8 bytes).
    let mut out = [0u8; 32];
    argon
        .hash_password_into(
            &password,
            &challenge[..16],
            &mut out[..cfg.argon_out_len.min(32)],
        )
        .map_err(|_| MintError::BadWork)?;
    Ok(out)
}

/// Solve a mint challenge by scanning nonces (real Argon2id per try).
pub fn solve_mint(
    cfg: &MinterConfig,
    challenge: &MintChallenge,
) -> Result<MintSolution, MintError> {
    let mut nonce: u64 = 0;
    loop {
        let hash = argon2_hash(cfg, &challenge.challenge, nonce)?;
        if meets_difficulty(&hash, challenge.difficulty) {
            return Ok(MintSolution {
                challenge: challenge.challenge,
                nonce,
                hash,
            });
        }
        nonce = nonce.checked_add(1).ok_or(MintError::BadWork)?;
    }
}

/// Verify a solution with exactly one Argon2id evaluation.
pub fn verify_mint_once(
    cfg: &MinterConfig,
    challenge: &MintChallenge,
    solution: &MintSolution,
) -> Result<(), MintError> {
    if solution.challenge != challenge.challenge {
        return Err(MintError::UnknownChallenge);
    }
    let hash = argon2_hash(cfg, &challenge.challenge, solution.nonce)?;
    if hash != solution.hash {
        return Err(MintError::BadWork);
    }
    if !meets_difficulty(&hash, challenge.difficulty) {
        return Err(MintError::DifficultyNotMet);
    }
    Ok(())
}

/// In-memory single-use challenge store (SQLite/Redis in production).
#[derive(Clone, Debug, Default)]
pub struct ChallengeStore {
    issued: HashMap<[u8; 32], MintChallenge>,
    used: HashSet<[u8; 32]>,
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a challenge for `epoch` at deterministic time `now`.
    pub fn issue(
        &mut self,
        cfg: &MinterConfig,
        epoch: u64,
        miner: PqAddress,
        dag_frontier_hash: [u8; 32],
        difficulty: Difficulty,
        now: u64,
    ) -> MintChallenge {
        let challenge = MintChallenge {
            epoch,
            miner,
            dag_frontier_hash,
            challenge: derive_challenge(epoch, &miner, &dag_frontier_hash),
            issued_at: now,
            expires_at: now + cfg.challenge_ttl_secs,
            difficulty,
        };
        self.issued.insert(challenge.challenge, challenge.clone());
        challenge
    }

    /// Verify + consume a challenge (single-use). On success the
    /// challenge can never be redeemed again.
    pub fn redeem(
        &mut self,
        cfg: &MinterConfig,
        solution: &MintSolution,
        current_epoch: u64,
        now: u64,
    ) -> Result<MintChallenge, MintError> {
        let challenge = self
            .issued
            .get(&solution.challenge)
            .cloned()
            .ok_or(MintError::UnknownChallenge)?;
        if self.used.contains(&solution.challenge) {
            return Err(MintError::ChallengeAlreadyUsed);
        }
        if challenge.epoch != current_epoch {
            return Err(MintError::EpochMismatch);
        }
        if now > challenge.expires_at {
            return Err(MintError::ChallengeExpired);
        }
        verify_mint_once(cfg, &challenge, solution)?;
        self.used.insert(solution.challenge);
        Ok(challenge)
    }

    pub fn is_used(&self, challenge: &[u8; 32]) -> bool {
        self.used.contains(challenge)
    }
}

/// Build the mint block on the miner's own chain with work attached.
/// The block's element is derived exactly as `turn-dag-element`
/// prescribes: `ElementId = SHA256(challenge || nonce_be || miner)`.
/// Derive the element id a solved challenge mints (the ledger
/// records it serially at the origin node; there is no mint block).
pub fn mint_element_id(challenge: &MintChallenge, solution: &MintSolution) -> ElementId {
    ElementId::derive(&challenge.challenge, solution.nonce, &challenge.miner)
}

pub const ZERO_FRONTIER: [u8; 32] = [0u8; 32];

// ---------------- Economics ----------------

/// Economic parameters for the forgery-cost assertion. With a
/// per-node serial ledger a double spend is rejected atomically, so
/// the relevant ratio is re-mint (forgery) cost vs one relay pass's
/// value. All values are parameters so the test asserts a numerical
/// relationship, not a hardcoded conclusion.
#[derive(Clone, Debug, PartialEq)]
pub struct EconomicsConfig {
    /// Bytes per rendezvous per direction: 16_384 B/s * 120 s.
    pub rendezvous_bytes: u64,
    /// Assumed bandwidth price, nano-USD per gigabyte (1e9 bytes).
    /// Default: $0.01/GB = 10_000_000 nano-USD/GB.
    pub price_nano_usd_per_gb: f64,
    /// Replacement (re-mint) cost of one element, nano-USD. Default
    /// $0.001 - a conservative Argon2id compute/energy estimate.
    pub element_value_nano_usd: f64,
    /// Elements an attacker must re-mint to replace one burned
    /// element's value when forging supply (unit: elements).
    pub remint_elements: u64,
}

impl Default for EconomicsConfig {
    fn default() -> Self {
        Self {
            rendezvous_bytes: 16_384 * 120,
            price_nano_usd_per_gb: 10_000_000.0,
            element_value_nano_usd: 1_000_000.0,
            remint_elements: 5,
        }
    }
}

impl EconomicsConfig {
    /// Value of one relay pass (= max gain from a forged element), nano-USD.
    pub fn double_spend_gain_nano_usd(&self) -> f64 {
        (self.rendezvous_bytes as f64) * self.price_nano_usd_per_gb / 1_000_000_000.0
    }
    /// Cost to re-mint the elements a forged burn would consume, nano-USD.
    pub fn slash_loss_nano_usd(&self) -> f64 {
        (self.remint_elements as f64) * self.element_value_nano_usd
    }
    /// Re-mint cost / relay-pass value (kept name for the assertion).
    pub fn slash_to_gain_ratio(&self) -> f64 {
        self.slash_loss_nano_usd() / self.double_spend_gain_nano_usd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> MinterConfig {
        MinterConfig::cheap_for_tests()
    }
    fn miner() -> PqAddress {
        PqAddress([7u8; 20])
    }

    #[test]
    fn challenge_is_epoch_bound_derivation() {
        let c = derive_challenge(3, &miner(), &[9u8; 32]);
        assert_eq!(c, derive_challenge(3, &miner(), &[9u8; 32]));
        assert_ne!(c, derive_challenge(4, &miner(), &[9u8; 32]));
        assert_ne!(c, derive_challenge(3, &PqAddress([8u8; 20]), &[9u8; 32]));
        assert_ne!(c, derive_challenge(3, &miner(), &[8u8; 32]));
    }

    #[test]
    fn mint_solve_verify_and_single_use() {
        let cfg = cfg();
        let mut store = ChallengeStore::new();
        let ch = store.issue(&cfg, 1, miner(), [9u8; 32], 2, 1_000);
        let sol = solve_mint(&cfg, &ch).unwrap();
        // Verify in 1 Argon2 verify.
        verify_mint_once(&cfg, &ch, &sol).unwrap();
        let redeemed = store.redeem(&cfg, &sol, 1, 1_010).unwrap();
        assert_eq!(redeemed.epoch, 1);
        assert!(store.is_used(&ch.challenge));
        // Single-use: second redemption fails.
        assert_eq!(
            store.redeem(&cfg, &sol, 1, 1_010),
            Err(MintError::ChallengeAlreadyUsed)
        );
    }

    #[test]
    fn expired_and_wrong_epoch_rejected_without_sleeps() {
        let cfg = cfg();
        let mut store = ChallengeStore::new();
        let ch = store.issue(&cfg, 1, miner(), [9u8; 32], 1, 1_000);
        let sol = solve_mint(&cfg, &ch).unwrap();
        // 30 s ttl: issued 1000, expires 1030.
        assert_eq!(ch.expires_at, 1_030);
        assert_eq!(
            store.redeem(&cfg, &sol, 1, 1_031),
            Err(MintError::ChallengeExpired)
        );
        // Not consumed by the failed attempt; wrong epoch also fails.
        assert_eq!(
            store.redeem(&cfg, &sol, 2, 1_010),
            Err(MintError::EpochMismatch)
        );
        assert!(store.redeem(&cfg, &sol, 1, 1_010).is_ok());
    }

    #[test]
    fn tampered_solution_fails_single_verify() {
        let cfg = cfg();
        let mut store = ChallengeStore::new();
        let ch = store.issue(&cfg, 1, miner(), [9u8; 32], 1, 0);
        let mut sol = solve_mint(&cfg, &ch).unwrap();
        sol.hash[0] ^= 1;
        assert_eq!(verify_mint_once(&cfg, &ch, &sol), Err(MintError::BadWork));
        sol.hash[0] ^= 1;
        sol.nonce = sol.nonce.wrapping_add(1);
        // nonce changed -> recomputed hash won't match stored hash
        // (or, astronomically rarely, difficulty check). Accept BadWork/Difficulty.
        assert!(verify_mint_once(&cfg, &ch, &sol).is_err());
    }

    #[test]
    fn retarget_formula_and_clamps() {
        let cfg = MinterConfig::default(); // target 10_000/epoch
                                           // On target: unchanged.
        assert_eq!(difficulty_next(1_000, 10_000, &cfg), 1_000);
        // Twice the mints: double (within 4x clamp).
        assert_eq!(difficulty_next(1_000, 20_000, &cfg), 2_000);
        // Half: halve.
        assert_eq!(difficulty_next(1_000, 5_000, &cfg), 500);
        // Huge overshoot clamps to 4x.
        assert_eq!(difficulty_next(1_000, 1_000_000, &cfg), 4_000);
        // Collapse clamps to 0.25x.
        assert_eq!(difficulty_next(1_000, 1, &cfg), 250);
        assert_eq!(difficulty_next(1_000, 0, &cfg), 250);
        // Parameter, not magic: different target changes result.
        let cfg2 = MinterConfig {
            target_per_epoch: 5_000,
            ..cfg.clone()
        };
        assert_eq!(difficulty_next(1_000, 10_000, &cfg2), 2_000);
        // Never zero.
        assert!(difficulty_next(1, 0, &cfg) >= 1);
    }

    #[test]
    fn difficulty_threshold_monotonic() {
        assert!(meets_difficulty(&[0xff; 32], 1));
        assert!(meets_difficulty(&[0x00; 32], 1_000_000));
        assert!(!meets_difficulty(&[0xff; 32], 2));
        // ~half of hashes meet difficulty 2: threshold is 0x80||0...
        assert!(meets_difficulty(&[0x7f; 32], 2));
        let mut at = [0u8; 32];
        at[0] = 0x80;
        assert!(!meets_difficulty(&at, 2), "hash == threshold must not meet");
        // difficulty 4: threshold 0x40||0...
        let mut below4 = [0u8; 32];
        below4[0] = 0x3f;
        assert!(meets_difficulty(&below4, 4));
        let mut at4 = [0u8; 32];
        at4[0] = 0x40;
        assert!(!meets_difficulty(&at4, 4));
    }

    #[test]
    fn mint_element_id_is_challenge_bound() {
        let cfg = cfg();
        let mut store = ChallengeStore::new();
        let ch = store.issue(&cfg, 5, miner(), [9u8; 32], 1, 100);
        let sol = solve_mint(&cfg, &ch).unwrap();
        let eid = mint_element_id(&ch, &sol);
        assert_eq!(eid, ElementId::derive(&ch.challenge, sol.nonce, &miner()));
        // A different miner solving the same challenge mints a different id.
        let ch2 = store.issue(&cfg, 5, PqAddress([8u8; 20]), [9u8; 32], 1, 100);
        let sol2 = solve_mint(&cfg, &ch2).unwrap();
        assert_ne!(mint_element_id(&ch2, &sol2), eid);
    }

    #[test]
    fn economics_forgery_cost_at_least_100x_gain() {
        let econ = EconomicsConfig::default();
        let gain = econ.double_spend_gain_nano_usd();
        let loss = econ.slash_loss_nano_usd();
        // 1 relay pass: 1_966_080 bytes at $0.01/GB ~ $0.0000197.
        assert!((gain - 19_660.8).abs() < 1.0, "gain={gain}");
        assert_eq!(econ.remint_elements, 5);
        assert_eq!(loss, 5.0 * econ.element_value_nano_usd);
        let ratio = econ.slash_to_gain_ratio();
        assert!(ratio >= 100.0, "slash/gain ratio {ratio} must be >= 100");
        assert!(loss >= 100.0 * gain);
    }
}
