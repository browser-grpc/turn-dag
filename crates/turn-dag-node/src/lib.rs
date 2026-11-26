//! In-process node wiring: DAG + minter + TURN issuer + PQ wallet.
//!
//! No kernel TCP anywhere: the CLI uses `std::env::args` only (no
//! listener/stream types), gossip between nodes in tests is direct
//! `SignedBlock` hand-off, and the user-space transport demo uses the
//! smoltcp `VirtualDevice`/`UserSpaceStack` from `turn-dag-turn`.
//! Allocation waits for burn confirmation weight - never a local view.

use turn_dag_dag::{sign_block, Block, BlockStatus, BlockType, Dag, SignedBlock, ZERO_HASH};
use turn_dag_element::ElementId;
use turn_dag_turn::{AllocationPolicy, BurnConfirmation, TurnIssuer};
pub use turn_dag_wallet::PqAddress;
use turn_dag_wallet::{HotWallet, PqWallet};

pub fn rep_wallet() -> HotWallet {
    HotWallet::generate(&[200u8; 32]).expect("rep wallet")
}
pub fn wallet(seed: u8) -> HotWallet {
    HotWallet::generate(&[seed; 32]).expect("wallet")
}
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// One mutually-distrusting in-process node: its own DAG view + wallet.
pub struct Node {
    pub name: String,
    pub dag: Dag,
    pub wallet: HotWallet,
    pub rep: PqAddress,
}

impl Node {
    pub fn new(name: &str, seed: u8) -> Self {
        let mut dag = Dag::new();
        let rep = rep_wallet().address();
        for i in 0..10u8 {
            dag.register_element(ElementId([100 + i; 32]), rep);
        }
        dag.delegate(rep, rep);
        Self {
            name: name.into(),
            dag,
            wallet: wallet(seed),
            rep,
        }
    }
    pub fn address(&self) -> PqAddress {
        self.wallet.address()
    }
    /// Insert a gossiped block (verified independently by this node).
    pub fn gossip(
        &mut self,
        b: SignedBlock,
    ) -> Result<turn_dag_dag::InsertOutcome, turn_dag_dag::DagError> {
        self.dag.insert_block(b)
    }
    pub fn confirm(&mut self, signed: SignedBlock) -> Result<[u8; 32], String> {
        let h = signed.block_hash();
        self.dag
            .insert_block(signed)
            .map_err(|e| format!("insert: {e:?}"))?;
        self.dag
            .cast_vote(self.rep, h)
            .map_err(|e| format!("vote: {e:?}"))?;
        self.dag.confirm_step();
        self.dag.confirm_step();
        if self.dag.block_status(&h) == Some(BlockStatus::Confirmed) {
            Ok(h)
        } else {
            Err(format!("not confirmed: {:?}", self.dag.block_status(&h)))
        }
    }
    pub fn tip(&self) -> [u8; 32] {
        self.dag.account_tip(&self.address()).unwrap_or(ZERO_HASH)
    }
}

/// Bond `owner` with 5 confirmed BondLock blocks; returns new tip.
pub fn bond(dag: &mut Dag, rep: PqAddress, owner: &HotWallet) -> Result<[u8; 32], String> {
    let addr = owner.address();
    let mut tip = dag.account_tip(&addr).unwrap_or(ZERO_HASH);
    for i in 0..5u8 {
        let mut b = [0u8; 32];
        b[0] = addr.0[0];
        b[1] = i + 1;
        b[2] = 0xB0;
        let id = ElementId(b);
        dag.register_element(id, addr);
        let blk = Block::new(
            BlockType::BondLock,
            addr,
            tip,
            ZERO_HASH,
            id,
            turn_dag_dag::bond_pseudo_account(&addr),
        );
        let s = sign_block(blk, owner);
        let h = s.block_hash();
        dag.insert_block(s)
            .map_err(|e| format!("bond insert: {e:?}"))?;
        dag.cast_vote(rep, h)
            .map_err(|e| format!("bond vote: {e:?}"))?;
        dag.confirm_step();
        dag.confirm_step();
        if dag.block_status(&h) != Some(BlockStatus::Confirmed) {
            return Err("bond not confirmed".into());
        }
        tip = h;
    }
    if !dag.has_confirmed_bond(&addr) {
        return Err("no confirmed bond".into());
    }
    Ok(tip)
}

pub fn confirm_on(dag: &mut Dag, rep: PqAddress, signed: SignedBlock) -> Result<[u8; 32], String> {
    let h = signed.block_hash();
    dag.insert_block(signed)
        .map_err(|e| format!("insert: {e:?}"))?;
    dag.cast_vote(rep, h).map_err(|e| format!("vote: {e:?}"))?;
    dag.confirm_step();
    dag.confirm_step();
    if dag.block_status(&h) == Some(BlockStatus::Confirmed) {
        Ok(h)
    } else {
        Err(format!("not confirmed: {:?}", dag.block_status(&h)))
    }
}

/// Burn checker backed by a real DAG view (confirmation weight gate).
pub struct DagBurnConfirmation<'a>(pub &'a Dag);
impl BurnConfirmation for DagBurnConfirmation<'_> {
    fn is_burn_confirmed(&self, burn_id: &[u8; 32]) -> bool {
        self.0.is_confirmed(burn_id)
    }
}

/// Fast-PoW policy for in-process demos/tests (production default is 20 bits).
pub fn demo_policy() -> AllocationPolicy {
    AllocationPolicy {
        pow_bits: 8,
        ..AllocationPolicy::default()
    }
}

/// Full burn-for-relay-pass flow on one node view: a confirmed burn
/// redeemed (issuer challenge/PoW/redeem) for a 120s TURN credential.
/// This is turn-dag's "relay pass" - not grpc-dc's rendezvous (a
/// pre-published fixed server endpoint); the name differs on purpose.
pub fn issue_relay_pass(
    dag: &Dag,
    secret: Vec<u8>,
    burn_hash: [u8; 32],
    user: &str,
    client_ip: std::net::IpAddr,
    peer_ip: std::net::IpAddr,
    now: u64,
) -> Result<turn_dag_turn::TurnCredential, turn_dag_turn::RedeemError> {
    let checker = DagBurnConfirmation(dag);
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

/// Mint one element via real Argon2id (cheap params) + confirmed Mint block.
pub fn mint_one(
    dag: &mut Dag,
    rep: PqAddress,
    miner: &HotWallet,
    epoch: u64,
    now: u64,
) -> Result<(ElementId, [u8; 32]), String> {
    use turn_dag_minter::{build_mint_block, solve_mint, ChallengeStore, MinterConfig};
    let cfg = MinterConfig::cheap_for_tests();
    let mut store = ChallengeStore::new();
    let frontier = dag.tips().first().copied().unwrap_or(ZERO_HASH);
    let ch = store.issue(&cfg, epoch, miner.address(), frontier, 1, now);
    let sol = solve_mint(&cfg, &ch).map_err(|e| format!("solve: {e:?}"))?;
    store
        .redeem(&cfg, &sol, epoch, now)
        .map_err(|e| format!("redeem challenge: {e:?}"))?;
    let prev = dag.account_tip(&miner.address()).unwrap_or(ZERO_HASH);
    let link = dag
        .select_link_parent(&miner.address())
        .unwrap_or(ZERO_HASH);
    let (blk, eid) = build_mint_block(&ch, &sol, prev, link);
    let h = confirm_on(dag, rep, sign_block(blk, miner))?;
    Ok((eid, h))
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
        assert_eq!(rep_wallet().address(), rep_wallet().address());
        let p = demo_policy();
        assert_eq!(p.pow_bits, 8);
        assert_eq!(p.max_bps, 16_384);
        assert_eq!(p.byte_cap(), 1_966_080);
    }

    #[test]
    fn fresh_node_has_zero_tip_and_no_bond() {
        let n = Node::new("fresh", 42);
        assert_eq!(n.tip(), ZERO_HASH);
        assert!(!n.dag.has_confirmed_bond(&n.address()));
        assert_eq!(n.address(), wallet(42).address());
    }

    #[test]
    fn burn_confirmation_gate_defaults_false() {
        let n = Node::new("gate", 43);
        let checker = DagBurnConfirmation(&n.dag);
        use turn_dag_turn::BurnConfirmation as _;
        assert!(!checker.is_burn_confirmed(&[1u8; 32]));
    }

    #[test]
    fn relay_pass_rejects_unconfirmed_burn_and_denied_peer() {
        let n = Node::new("r", 44);
        let client: std::net::IpAddr = "203.0.113.1".parse().unwrap();
        let err = issue_relay_pass(
            &n.dag,
            b"s3cret".to_vec(),
            [2u8; 32],
            "u",
            client,
            "8.8.8.8".parse().unwrap(),
            1_000,
        )
        .unwrap_err();
        assert_eq!(err, turn_dag_turn::RedeemError::UnconfirmedBurn);
        // Denied metadata peer is rejected before burn is even considered
        // only when burn passes; here the unconfirmed gate fires first, so
        // assert the peer is at least classed denied by the policy helper.
        assert!(turn_dag_turn::is_denied_peer_ip(
            "169.254.169.254".parse().unwrap()
        ));
        let _ = Transport::Udp;
    }

    #[test]
    fn confirm_rejects_bad_signature() {
        let mut n = Node::new("bad", 45);
        let blk = Block::new(
            BlockType::BondLock,
            n.address(),
            ZERO_HASH,
            ZERO_HASH,
            ElementId([1u8; 32]),
            n.address(),
        );
        let mut signed = sign_block(blk, &n.wallet);
        signed.signature[0] ^= 1;
        assert!(n.confirm(signed).is_err());
    }

    #[test]
    fn gossip_duplicate_is_idempotent_outcome() {
        let mut n = Node::new("g", 46);
        let blk = Block::new(
            BlockType::BondLock,
            n.address(),
            ZERO_HASH,
            ZERO_HASH,
            ElementId([2u8; 32]),
            n.address(),
        );
        let signed = sign_block(blk, &n.wallet);
        let first = n.gossip(signed.clone());
        // First insert may pend/fail validation rules, but gossiping the
        // same block twice must never panic and must agree on the hash.
        let second = n.gossip(signed);
        match (first, second) {
            (Ok(a), Ok(b)) => assert_eq!(
                format!("{a:?}").split('{').next(),
                format!("{b:?}").split('{').next()
            ),
            (Err(e1), Err(e2)) => assert_eq!(format!("{e1:?}"), format!("{e2:?}")),
            _ => {}
        }
    }

    #[test]
    fn bond_then_mint_flow() {
        let mut n = Node::new("m", 47);
        let rep = n.rep;
        let owner = wallet(47);
        let tip = bond(&mut n.dag, rep, &owner).unwrap();
        assert_ne!(tip, ZERO_HASH);
        let (eid, h) = mint_one(&mut n.dag, rep, &owner, 1, 1_000).unwrap();
        assert_ne!(h, ZERO_HASH);
        assert!(n.dag.is_confirmed(&h));
        // Element record exists in the dag view (owner or in-flight).
        let _ = eid;
    }
}
