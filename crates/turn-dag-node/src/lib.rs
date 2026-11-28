//! In-process node wiring: per-node serial ledger + minter + TURN
//! issuer + PQ wallet.
//!
//! No kernel TCP anywhere: the CLI uses `std::env::args` only (no
//! listener/stream types), and the user-space transport demo uses
//! the smoltcp `VirtualDevice`/`UserSpaceStack` from `turn-dag-turn`.
//!
//! There is no distributed DAG and there are no bonds: each node is
//! the single writer for the coins it originated (turn-dag-ledger),
//! a relay pass is issued only against a burn recorded in that
//! node's own ledger, and a foreign node's coins are simply absent.

pub mod git_event_bus;

use turn_dag_element::ElementId;
use turn_dag_ledger::{BurnReceipt, Ledger};
use turn_dag_turn::{AllocationPolicy, BurnConfirmation, TurnIssuer};
pub use turn_dag_wallet::PqAddress;
use turn_dag_wallet::{HotWallet, PqWallet};

pub fn wallet(seed: u8) -> HotWallet {
    HotWallet::generate(&[seed; 32]).expect("wallet")
}
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    turn_dag_ledger::hex_decode(s)
}

/// One node: its own serial ledger (as origin) and its origin key.
pub struct Node {
    pub name: String,
    pub ledger: Ledger,
    pub wallet: HotWallet,
    /// Active relay-pass expiry times per user (bond-priced quota).
    active_passes: std::collections::HashMap<PqAddress, Vec<u64>>,
}

impl Node {
    pub fn new(name: &str, seed: u8) -> Self {
        let wallet = wallet(seed);
        let ledger = Ledger::new(wallet.address());
        Self {
            name: name.into(),
            ledger,
            wallet,
            active_passes: Default::default(),
        }
    }
    pub fn address(&self) -> PqAddress {
        self.wallet.address()
    }
    /// Mint one element for `miner` at this node (real Argon2id,
    /// cheap params) and record it serially. Returns (id, entry hash).
    pub fn mint_for(
        &mut self,
        miner: &HotWallet,
        epoch: u64,
        now: u64,
    ) -> Result<(ElementId, [u8; 32]), String> {
        self.ledger_mint(miner, epoch, now)
    }
    pub fn transfer(
        &mut self,
        element_id: ElementId,
        from: &HotWallet,
        to: PqAddress,
    ) -> Result<[u8; 32], String> {
        self.ledger
            .transfer(element_id, from, to, &self.wallet)
            .map(|e| e.hash)
            .map_err(|e| format!("transfer: {e:?}"))
    }
    pub fn burn(
        &mut self,
        element_id: ElementId,
        owner: &HotWallet,
    ) -> Result<BurnReceipt, String> {
        self.ledger
            .burn(element_id, owner, &self.wallet)
            .map_err(|e| format!("burn: {e:?}"))
    }
    fn ledger_mint(
        &mut self,
        miner: &HotWallet,
        epoch: u64,
        now: u64,
    ) -> Result<(ElementId, [u8; 32]), String> {
        mint_one(&mut self.ledger, &self.wallet, miner, epoch, now)
    }
    pub fn balance(&self, owner: &PqAddress) -> usize {
        self.ledger.balance(owner)
    }
    /// Issue a relay pass for `receipt`'s burn, consuming it at this
    /// origin: a second issuance for the same burn fails with
    /// `BurnAlreadyRedeemed`, across calls and issuer sessions.
    pub fn relay_pass(
        &mut self,
        receipt: &turn_dag_ledger::BurnReceipt,
        user: &HotWallet,
        client_ip: std::net::IpAddr,
        peer_ip: std::net::IpAddr,
        now: u64,
    ) -> Result<turn_dag_turn::TurnCredential, String> {
        if self.ledger.is_redeemed(&receipt.entry_hash) {
            return Err(format!(
                "{:?}",
                turn_dag_turn::RedeemError::BurnAlreadyRedeemed
            ));
        }
        // Bond-priced concurrent-session quota: 1 free, +1 per
        // element locked as rate bond at this origin. Session
        // count costs locked elements, not hash power.
        let quota = self.ledger.session_quota(&user.address());
        let active = self.active_passes.entry(user.address()).or_default();
        active.retain(|exp| *exp > now);
        if active.len() >= quota {
            return Err(format!(
                "{:?}",
                turn_dag_turn::RedeemError::UserQuotaExceeded
            ));
        }
        let user_label = hex(&user.address().0);
        let cred = issue_relay_pass(
            &self.ledger,
            b"demo-secret".to_vec(),
            receipt.entry_hash,
            &user_label,
            client_ip,
            peer_ip,
            now,
        )
        .map_err(|e| format!("{e:?}"))?;
        self.ledger
            .mark_redeemed(&receipt.entry_hash)
            .map_err(|e| format!("mark redeemed: {e:?}"))?;
        self.active_passes
            .entry(user.address())
            .or_default()
            .push(cred.expires_at);
        Ok(cred)
    }

    /// Lock one of `owner`'s elements as rate bond at this node.
    pub fn bond_lock(
        &mut self,
        element_id: ElementId,
        owner: &HotWallet,
    ) -> Result<[u8; 32], String> {
        self.ledger
            .bond_lock(element_id, owner, &self.wallet)
            .map(|e| e.hash)
            .map_err(|e| format!("bond_lock: {e:?}"))
    }
}

/// Burn checker backed by this node's own ledger (the origin's
/// serial record is the confirmation; there is no voting weight).
pub struct LedgerBurnConfirmation<'a>(pub &'a Ledger);
impl BurnConfirmation for LedgerBurnConfirmation<'_> {
    fn is_burn_confirmed(&self, burn_id: &[u8; 32]) -> bool {
        self.0.is_burned(burn_id)
    }
}

/// Fast-PoW policy for in-process demos/tests (production default is 20 bits).
pub fn demo_policy() -> AllocationPolicy {
    AllocationPolicy {
        pow_bits: 8,
        ..AllocationPolicy::default()
    }
}

/// Full burn-for-relay-pass flow against one node's ledger: a burn
/// recorded at the origin redeemed (issuer challenge/PoW/redeem)
/// for a 120s TURN credential. This is turn-dag's "relay pass" -
/// not grpc-dc's rendezvous (a pre-published fixed server endpoint).
pub fn issue_relay_pass(
    ledger: &Ledger,
    secret: Vec<u8>,
    burn_hash: [u8; 32],
    user: &str,
    client_ip: std::net::IpAddr,
    peer_ip: std::net::IpAddr,
    now: u64,
) -> Result<turn_dag_turn::TurnCredential, turn_dag_turn::RedeemError> {
    let checker = LedgerBurnConfirmation(ledger);
    let mut issuer = TurnIssuer::new(secret, demo_policy(), &checker);
    let ch = issuer.handle_get_challenge(client_ip, now).body?;
    let challenge = turn_dag_turn::TurnPowChallenge {
        challenge_id: ch.challenge_id,
        challenge: ch.challenge,
        client_ip,
        issued_at: now,
        expires_at: ch.expires_at,
        bits: ch.bits,
    };
    let pow = turn_dag_turn::solve_turn_pow(&challenge);
    let req = turn_dag_turn::RedeemRequest {
        user_id: user.into(),
        client_ip,
        peer_ip,
        transport: turn_dag_turn::Transport::Udp,
        both_symmetric_nat: false,
        burn_id: burn_hash,
        pow,
    };
    let resp = issuer.handle_post_redeem(&req, now);
    let creds = resp.body?;
    Ok(creds.into_iter().next().expect("one credential"))
}

/// Mint one element via real Argon2id (cheap params) and record it
/// in the origin node's serial ledger.
pub fn mint_one(
    ledger: &mut Ledger,
    origin_key: &HotWallet,
    miner: &HotWallet,
    epoch: u64,
    now: u64,
) -> Result<(ElementId, [u8; 32]), String> {
    use turn_dag_minter::{mint_element_id, solve_mint, ChallengeStore, MinterConfig};
    let cfg = MinterConfig::cheap_for_tests();
    let mut store = ChallengeStore::new();
    // The ledger tip is the challenge frontier: every mint moves it,
    // so consecutive mints never derive the same element.
    let frontier = ledger
        .entries()
        .last()
        .map(|e| e.hash)
        .unwrap_or(turn_dag_minter::ZERO_FRONTIER);
    let ch = store.issue(&cfg, epoch, miner.address(), frontier, 1, now);
    let sol = solve_mint(&cfg, &ch).map_err(|e| format!("solve: {e:?}"))?;
    store
        .redeem(&cfg, &sol, epoch, now)
        .map_err(|e| format!("redeem challenge: {e:?}"))?;
    let eid = mint_element_id(&ch, &sol);
    let entry = ledger
        .mint(eid, miner, origin_key)
        .map_err(|e| format!("ledger mint: {e:?}"))?;
    Ok((eid, entry.hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use turn_dag_turn::Transport;

    #[test]
    fn helpers_are_deterministic() {
        assert_eq!(hex(&[0xAB, 0x01]), "ab01");
        assert_eq!(wallet(3).address(), wallet(3).address());
        assert_ne!(wallet(3).address(), wallet(4).address());
        assert_eq!(hex_decode("ff00"), Some(vec![0xFF, 0x00]));
        let p = demo_policy();
        assert_eq!(p.pow_bits, 8);
        assert_eq!(p.max_bps, 16_384);
        assert_eq!(p.byte_cap(), 1_966_080);
    }

    #[test]
    fn fresh_node_has_empty_ledger() {
        let n = Node::new("fresh", 42);
        assert!(n.ledger.is_empty());
        assert_eq!(n.balance(&n.address()), 0);
        assert_eq!(n.address(), wallet(42).address());
        assert_eq!(n.ledger.origin(), n.address());
    }

    #[test]
    fn burn_gate_defaults_false_and_foreign_burn_rejected() {
        let mut a = Node::new("a", 43);
        let mut b = Node::new("b", 44);
        let alice = wallet(7);
        let (eid, _) = a.mint_for(&alice, 1, 1_000).unwrap();
        // B never originated Alice's coin: not burned there, not present.
        assert!(b.burn(eid, &alice).is_err());
        let checker = LedgerBurnConfirmation(&b.ledger);
        use turn_dag_turn::BurnConfirmation as _;
        assert!(!checker.is_burn_confirmed(&[1u8; 32]));
        let receipt = a.burn(eid, &alice).unwrap();
        assert!(a.ledger.verify_receipt(&receipt));
        assert!(!checker.is_burn_confirmed(&receipt.entry_hash));
        let checker_a = LedgerBurnConfirmation(&a.ledger);
        assert!(checker_a.is_burn_confirmed(&receipt.entry_hash));
    }

    #[test]
    fn relay_pass_rejects_unburned_and_denied_peer() {
        let n = Node::new("r", 45);
        let client: std::net::IpAddr = "203.0.113.1".parse().unwrap();
        let err = issue_relay_pass(
            &n.ledger,
            b"s3cret".to_vec(),
            [2u8; 32],
            "u",
            client,
            "8.8.8.8".parse().unwrap(),
            1_000,
        )
        .unwrap_err();
        assert_eq!(err, turn_dag_turn::RedeemError::UnconfirmedBurn);
        assert!(turn_dag_turn::is_denied_peer_ip(
            "169.254.169.254".parse().unwrap()
        ));
        let _ = Transport::Udp;
    }

    #[test]
    fn mint_transfer_burn_flow_and_double_spend_rejected() {
        let mut n = Node::new("m", 47);
        let alice = wallet(47);
        let bob = wallet(48);
        let (eid, _) = n.mint_for(&alice, 1, 1_000).unwrap();
        assert_eq!(n.balance(&alice.address()), 1);
        // Wrong owner cannot transfer.
        assert!(n.transfer(eid, &bob, alice.address()).is_err());
        n.transfer(eid, &alice, bob.address()).unwrap();
        let receipt = n.burn(eid, &bob).unwrap();
        assert!(n.ledger.is_burned(&receipt.entry_hash));
        // Second spends fail atomically.
        assert!(n.burn(eid, &bob).is_err());
        assert!(n.transfer(eid, &bob, alice.address()).is_err());
    }
}
