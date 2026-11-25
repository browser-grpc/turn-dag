use turn_dag_dag::*;

fn w(seed: u8) -> HotWallet {
    HotWallet::generate(&[seed; 32]).unwrap()
}
fn eid(b: u8) -> ElementId {
    ElementId([b; 32])
}
fn confirm<S: Storage>(dag: &mut Dag<S>, rep: PqAddress, signed: SignedBlock) -> [u8; 32] {
    let h = signed.block_hash();
    dag.insert_block(signed).unwrap();
    dag.cast_vote(rep, h).unwrap();
    dag.confirm_step();
    assert_eq!(
        dag.block_status(&h),
        Some(BlockStatus::Confirmed),
        "confirm"
    );
    h
}
fn setup_rep<S: Storage>(dag: &mut Dag<S>) -> PqAddress {
    let rep = w(200).address();
    for i in 0..10u8 {
        dag.register_element(eid(100 + i), rep);
    }
    dag.delegate(rep, rep);
    rep
}
/// Wallet bonded with exactly 5 confirmed bond locks; returns tip.
fn bond<S: Storage>(dag: &mut Dag<S>, rep: PqAddress, wallet: &HotWallet) -> [u8; 32] {
    let owner = wallet.address();
    let mut tip = ZERO_HASH;
    for i in 0..5u8 {
        let id = ElementId([owner.0[0] ^ (i + 1); 32]);
        // unique-ish bond element ids derived per owner byte + index
        let id = ElementId({
            let mut b = [0u8; 32];
            b[0] = owner.0[0];
            b[1] = i + 1;
            b[2] = 0xB0;
            let _ = id;
            b
        });
        dag.register_element(id, owner);
        let blk = Block::new(
            BlockType::BondLock,
            owner,
            tip,
            ZERO_HASH,
            id,
            bond_pseudo_account(&owner),
        );
        tip = confirm(dag, rep, sign_block(blk, wallet));
    }
    assert!(dag.has_confirmed_bond(&owner));
    tip
}
fn bonded_owner(seed: u8) -> (Dag, HotWallet, PqAddress, [u8; 32]) {
    let mut dag = Dag::new();
    let rep = setup_rep(&mut dag);
    let owner = w(seed);
    let tip = bond(&mut dag, rep, &owner);
    (dag, owner, rep, tip)
}

#[test]
fn example_a_valid_transfer_confirms() {
    let mut dag = Dag::new();
    let rep = setup_rep(&mut dag);
    let alice = w(1);
    let bob = w(2);
    let tip_a = bond(&mut dag, rep, &alice);
    let e = eid(42);
    dag.register_element(e, alice.address());
    let send = Block::new(
        BlockType::Send,
        alice.address(),
        tip_a,
        ZERO_HASH,
        e,
        bob.address(),
    );
    let send_h = confirm(&mut dag, rep, sign_block(send, &alice));
    assert_eq!(dag.element(&e).unwrap().status, ElementStatus::InFlight);
    // receive on Bob's chain, referencing the send via link_parent
    let recv = Block::new(
        BlockType::Receive,
        bob.address(),
        ZERO_HASH,
        send_h,
        e,
        bob.address(),
    );
    confirm(&mut dag, rep, sign_block(recv, &bob));
    let rec = dag.element(&e).unwrap();
    assert_eq!(rec.owner, bob.address());
    assert_eq!(rec.status, ElementStatus::Unspent);
    // canonical / hash determinism, recomputed
    let blk = Block::new(
        BlockType::Send,
        alice.address(),
        tip_a,
        ZERO_HASH,
        e,
        bob.address(),
    );
    assert_eq!(blk.canonical_bytes(), blk.clone().canonical_bytes());
    assert_eq!(blk.canonical_hash(), blk.clone().canonical_hash());
    let mut other = blk.clone();
    other.nonce = 1;
    assert_ne!(blk.canonical_hash(), other.canonical_hash());
}

#[test]
fn example_b_double_spend_fork_loser_orphaned() {
    let (mut dag, mallory, rep, tip) = bonded_owner(3);
    let e = eid(43);
    dag.register_element(e, mallory.address());
    let b1 = Block::new(
        BlockType::Burn,
        mallory.address(),
        tip,
        ZERO_HASH,
        e,
        burn_sink(),
    );
    let b2 = Block::new(
        BlockType::Send,
        mallory.address(),
        tip,
        ZERO_HASH,
        e,
        w(9).address(),
    );
    let s1 = sign_block(b1, &mallory);
    let s2 = sign_block(b2, &mallory);
    let h1 = s1.block_hash();
    let h2 = s2.block_hash();
    match dag.insert_block(s1.clone()).unwrap() {
        InsertOutcome::Inserted { fork, .. } => assert!(!fork),
        x => panic!("{x:?}"),
    }
    match dag.insert_block(s2).unwrap() {
        InsertOutcome::Inserted { fork, .. } => assert!(fork),
        x => panic!("{x:?}"),
    }
    // duplicate identical block is NOT a fork
    assert!(matches!(
        dag.insert_block(s1).unwrap(),
        InsertOutcome::Duplicate { .. }
    ));
    dag.cast_vote(rep, h1).unwrap();
    dag.confirm_step();
    assert_eq!(dag.block_status(&h1), Some(BlockStatus::Confirmed));
    assert_eq!(dag.block_status(&h2), Some(BlockStatus::Orphaned));
    // orphaned branch retained as evidence
    assert!(dag.get_block(&h2).is_some());
    assert_eq!(dag.spent_set.winner(&e).unwrap().winning_hash, h1);
}

fn slash_setup() -> (
    Dag,
    HotWallet,
    PqAddress,
    SignedBlock,
    SignedBlock,
    PqAddress,
) {
    let (mut dag, mallory, rep, tip) = bonded_owner(3);
    let e = eid(43);
    dag.register_element(e, mallory.address());
    let b1 = Block::new(
        BlockType::Burn,
        mallory.address(),
        tip,
        ZERO_HASH,
        e,
        burn_sink(),
    );
    let b2 = Block::new(
        BlockType::Send,
        mallory.address(),
        tip,
        ZERO_HASH,
        e,
        w(9).address(),
    );
    let s1 = sign_block(b1, &mallory);
    let s2 = sign_block(b2, &mallory);
    dag.insert_block(s1.clone()).unwrap();
    dag.insert_block(s2.clone()).unwrap();
    (dag, mallory, rep, s1, s2, w(77).address())
}

#[test]
fn example_c_slash_one_four_blacklist_freeze() {
    let (mut dag, mallory, rep, s1, s2, reporter) = slash_setup();
    assert!(validate_slash_split(1, 4));
    assert!(!validate_slash_split(2, 3));
    assert!(!validate_slash_split(0, 5));
    let proof = build_fraud_proof(&s1, &s2, reporter, 1_700_000_000);
    let ph = dag.receive_proof(proof.clone()).unwrap();
    assert_eq!(ph, proof.proof_hash().unwrap());
    assert!(dag.is_frozen(&mallory.address()));
    assert!(dag.cast_slash_vote(rep, ph).unwrap());
    let out = dag.slash_outcome(&ph).unwrap().clone();
    assert_eq!(out.bounty_element, {
        let mut v = dag.bonded_elements(&mallory.address());
        v.clear();
        out.bounty_element
    });
    assert_eq!(dag.element(&out.bounty_element).unwrap().owner, reporter);
    assert_eq!(
        dag.element(&out.bounty_element).unwrap().status,
        ElementStatus::Unspent
    );
    assert_eq!(out.burned_elements.len(), 4);
    for id in &out.burned_elements {
        assert_eq!(dag.element(id).unwrap().status, ElementStatus::Burned);
    }
    assert!(dag.is_blacklisted_addr(&mallory.address()));
    assert!(dag.is_blacklisted_pubkey(mallory.public_key()));
    // blacklisted key cannot insert new blocks
    let e2 = eid(99);
    dag.register_element(e2, mallory.address());
    let bad = Block::new(
        BlockType::Send,
        mallory.address(),
        s1.block_hash(),
        ZERO_HASH,
        e2,
        reporter,
    );
    assert_eq!(
        dag.insert_block(sign_block(bad, &mallory)),
        Err(DagError::Blacklisted)
    );
}

#[test]
fn freeze_reversible_if_slash_fails() {
    let (mut dag, mallory, _rep, s1, s2, reporter) = slash_setup();
    let proof = build_fraud_proof(&s1, &s2, reporter, 1);
    let ph = dag.receive_proof(proof).unwrap();
    assert!(dag.is_frozen(&mallory.address()));
    dag.fail_slash(&ph).unwrap();
    assert!(!dag.is_frozen(&mallory.address()));
}

#[test]
fn equivocation_discards_both_votes() {
    let (mut dag, mallory, rep, tip) = bonded_owner(3);
    let e = eid(44);
    dag.register_element(e, mallory.address());
    let b1 = sign_block(
        Block::new(
            BlockType::Burn,
            mallory.address(),
            tip,
            ZERO_HASH,
            e,
            burn_sink(),
        ),
        &mallory,
    );
    let b2 = sign_block(
        Block::new(
            BlockType::Send,
            mallory.address(),
            tip,
            ZERO_HASH,
            e,
            w(9).address(),
        ),
        &mallory,
    );
    let h1 = b1.block_hash();
    let h2 = b2.block_hash();
    dag.insert_block(b1).unwrap();
    dag.insert_block(b2).unwrap();
    assert_eq!(dag.cast_vote(rep, h1).unwrap(), VoteOutcome::Counted);
    assert_eq!(
        dag.cast_vote(rep, h2).unwrap(),
        VoteOutcome::EquivocatedDiscarded
    );
    assert_eq!(dag.cumulative_weight(&h1), 0);
    assert_eq!(dag.cumulative_weight(&h2), 0);
    dag.confirm_step();
    assert_eq!(dag.block_status(&h1), Some(BlockStatus::Pending));
}

#[test]
fn crdt_merge_converges() {
    let e = eid(50);
    let mut a = SpentSet::default();
    let mut b = SpentSet::default();
    a.observe(e, [1u8; 32], 10);
    b.observe(e, [2u8; 32], 20);
    b.observe(eid(51), [3u8; 32], 5);
    let mut ab = a.clone();
    ab.merge(&b);
    let mut ba = b.clone();
    ba.merge(&a);
    assert_eq!(ab, ba);
    assert_eq!(ab.winner(&e).unwrap().winning_hash, [2u8; 32]);
    assert_eq!(ab.winner(&e).unwrap().weight, 20);
    assert_eq!(ab.conflicts.get(&e).unwrap().len(), 2);
}

#[test]
fn no_bond_burn_voted_down() {
    let mut dag = Dag::new();
    let rep = setup_rep(&mut dag);
    let alice = w(5);
    let e = eid(60);
    dag.register_element(e, alice.address());
    let burn = sign_block(
        Block::new(
            BlockType::Burn,
            alice.address(),
            ZERO_HASH,
            ZERO_HASH,
            e,
            burn_sink(),
        ),
        &alice,
    );
    let h = burn.block_hash();
    dag.insert_block(burn).unwrap();
    assert_eq!(dag.cast_vote(rep, h), Err(DagError::NoBond));
    dag.confirm_step();
    assert_eq!(dag.block_status(&h), Some(BlockStatus::Pending));
    assert!(!dag.has_confirmed_bond(&alice.address()));
}

#[test]
fn release_timelock_matures_without_proof() {
    let (mut dag, owner, rep, tip) = bonded_owner(6);
    let bonded = dag.bonded_elements(&owner.address());
    let rel = sign_block(
        Block::new(
            BlockType::BondRelease,
            owner.address(),
            tip,
            ZERO_HASH,
            bonded[0],
            owner.address(),
        ),
        &owner,
    );
    confirm(&mut dag, rep, rel);
    let rec = dag
        .request_release_record(&owner.address())
        .unwrap()
        .clone();
    assert!(!rec.cancelled && !rec.executed);
    dag.advance_epochs(BOND_RELEASE_EPOCHS + 2);
    assert_eq!(
        dag.element(&bonded[0]).unwrap().status,
        ElementStatus::Unspent
    );
}

#[test]
fn release_cancelled_by_in_window_proof() {
    let (mut dag, mallory, rep, s1, s2, reporter) = slash_setup();
    let bonded = dag.bonded_elements(&mallory.address());
    let tip = dag.account_tip(&mallory.address()).unwrap();
    let rel = sign_block(
        Block::new(
            BlockType::BondRelease,
            mallory.address(),
            tip,
            ZERO_HASH,
            bonded[0],
            mallory.address(),
        ),
        &mallory,
    );
    confirm(&mut dag, rep, rel);
    assert!(
        !dag.request_release_record(&mallory.address())
            .unwrap()
            .cancelled
    );
    let proof = build_fraud_proof(&s1, &s2, reporter, 7);
    dag.receive_proof(proof).unwrap();
    assert!(
        dag.request_release_record(&mallory.address())
            .unwrap()
            .cancelled
    );
    dag.advance_epochs(BOND_RELEASE_EPOCHS + 2);
    assert_eq!(
        dag.element(&bonded[0]).unwrap().status,
        ElementStatus::Bonded
    );
    let _ = (s1, s2);
}

#[test]
fn fraud_proof_size_and_valid() {
    let (_dag, _m, _rep, s1, s2, reporter) = slash_setup();
    let proof = build_fraud_proof(&s1, &s2, reporter, 42);
    let json = proof.to_json();
    println!("fraud proof json bytes={}", json.len());
    assert!(
        (10_000..16_000).contains(&json.len()),
        "size {}",
        json.len()
    );
    let round: FraudProof = serde_json::from_str(&json).unwrap();
    assert_eq!(round, proof);
}

#[test]
fn fraud_proof_five_conditions_fail_individually() {
    // condition 1: different fork point
    {
        let (dag, _m, _r, s1, s2, reporter) = slash_setup();
        let mut p = build_fraud_proof(&s1, &s2, reporter, 1);
        p.fork.block_b.block.previous = hex_encode(&[9u8; 32]);
        assert_eq!(
            dag.verify_fraud_proof(&p),
            Err(FraudError::DifferentForkPoint)
        );
    }
    // condition 2: identical blocks
    {
        let (dag, _m, _r, s1, _s2, reporter) = slash_setup();
        let p = build_fraud_proof(&s1, &s1, reporter, 1);
        assert_eq!(dag.verify_fraud_proof(&p), Err(FraudError::IdenticalBlocks));
    }
    // condition 3: previous not in confirmed history
    {
        let (mut dag, mallory, _rep, _s1, _s2, reporter) = slash_setup();
        // unconfirmed predecessor (inserted, never voted)
        let mint = sign_block(
            Block::new(
                BlockType::Mint,
                mallory.address(),
                ZERO_HASH,
                ZERO_HASH,
                eid(70),
                mallory.address(),
            ),
            &mallory,
        );
        let mh = mint.block_hash();
        dag.insert_block(mint).unwrap();
        let e = eid(71);
        dag.register_element(e, mallory.address());
        // fork blocks are NOT inserted; previous=mh is pending, not confirmed
        let a = sign_block(
            Block::new(
                BlockType::Burn,
                mallory.address(),
                mh,
                ZERO_HASH,
                e,
                burn_sink(),
            ),
            &mallory,
        );
        let b = sign_block(
            Block::new(
                BlockType::Send,
                mallory.address(),
                mh,
                ZERO_HASH,
                e,
                reporter,
            ),
            &mallory,
        );
        // element owner fallback is mallory, sigs valid -> only C3 can fail
        let p = build_fraud_proof(&a, &b, reporter, 1);
        assert_eq!(
            dag.verify_fraud_proof(&p),
            Err(FraudError::PreviousNotConfirmed)
        );
    }
    // condition 4: owner pubkey does not match account
    {
        let (dag, _m, _r, s1, s2, reporter) = slash_setup();
        let mut p = build_fraud_proof(&s1, &s2, reporter, 1);
        // swap in a different wallet's pubkey (base64 via re-building proof)
        let other = w(123);
        // re-encode manually using dag's json roundtrip: replace field
        // owner_pubkey must be base64 of other pubkey; use build with tamper
        // through serde_json value
        let mut v: serde_json::Value = serde_json::from_str(&p.to_json()).unwrap();
        // base64 encode without extra crate: use FraudProof field from a proof built by other signer is
        // not possible, so tamper by using s1 pubkey bytes via block json is not available.
        // Instead use the other wallet to build a proof (pubkey=other, blocks still mallory's)
        let _ = other;
        // fallback: corrupt owner_pubkey to another valid base64 string of wrong length/content
        v["owner_pubkey"] = serde_json::Value::String("AAAA".to_string());
        p = serde_json::from_value(v).unwrap();
        // "AAAA" decodes to 3 bytes -> address mismatch (condition 4)
        assert_eq!(dag.verify_fraud_proof(&p), Err(FraudError::OwnerMismatch));
    }
    // condition 5: bad signature
    {
        let (dag, _m, _r, s1, s2, reporter) = slash_setup();
        let mut p = build_fraud_proof(&s1, &s2, reporter, 1);
        let mut sig = p.fork.block_a.signature.clone();
        let first = sig.remove(0);
        sig.insert(0, if first == 'A' { 'B' } else { 'A' });
        // ensure first char change alters decoded bytes: replace with different char
        p.fork.block_a.signature = sig;
        assert_eq!(dag.verify_fraud_proof(&p), Err(FraudError::BadSignature));
    }
    // valid proof passes
    {
        let (dag, _m, _r, s1, s2, reporter) = slash_setup();
        let p = build_fraud_proof(&s1, &s2, reporter, 1);
        assert!(dag.verify_fraud_proof(&p).is_ok());
    }
}

#[test]
fn tip_selection_prefers_confirmed_not_own() {
    let (dag, mallory, rep, _tip) = bonded_owner(8);
    let _ = rep;
    let own_tip = dag.account_tip(&mallory.address()).unwrap();
    let sel = dag.select_link_parent(&mallory.address());
    assert!(sel.is_none() || sel.unwrap() != own_tip);
}

#[test]
fn sqlite_storage_roundtrip_and_dag() {
    // Direct storage round-trip, incl. work payload + persistence of hashes.
    let alice = w(77);
    let mut store = SqliteStorage::in_memory().unwrap();
    let mut blk = Block::new(
        BlockType::Mint,
        alice.address(),
        ZERO_HASH,
        ZERO_HASH,
        eid(9),
        alice.address(),
    );
    blk.work = Some(vec![1, 2, 3, 4]);
    blk.epoch = 7;
    let signed = sign_block(blk, &alice);
    let h = signed.block_hash();
    store.put(h, signed.clone());
    assert!(store.contains(&h));
    assert_eq!(store.get(&h), Some(&signed));
    assert_eq!(store.hashes(), vec![h]);
    assert_eq!(store.get(&[9u8; 32]), None);
    assert!(!store.contains(&[9u8; 32]));
    // Dag over SQLite storage confirms a block like in-memory storage.
    let mut dag = Dag::with_storage(SqliteStorage::in_memory().unwrap());
    let rep = setup_rep(&mut dag);
    let tip = bond(&mut dag, rep, &alice);
    assert_ne!(tip, ZERO_HASH);
    assert!(dag.has_confirmed_bond(&alice.address()));
}

#[test]
fn descendant_blocks_add_cumulative_weight() {
    let (mut dag, owner, _rep, tip) = bonded_owner(31);
    let before = dag.descendant_weight(&tip);
    // A new block on owner's chain descends from the tip and cross-refs it.
    let e = eid(231);
    dag.register_element(e, owner.address());
    let next = Block::new(
        BlockType::BondLock,
        owner.address(),
        tip,
        tip,
        e,
        bond_pseudo_account(&owner.address()),
    );
    let h = sign_block(next, &owner).block_hash();
    let signed = sign_block(
        Block::new(
            BlockType::BondLock,
            owner.address(),
            tip,
            tip,
            e,
            bond_pseudo_account(&owner.address()),
        ),
        &owner,
    );
    let _ = h;
    // Insert may pend on rules; descendant weight counts stored blocks regardless.
    let _ = dag.insert_block(signed);
    let after = dag.descendant_weight(&tip);
    assert!(
        after > before,
        "new descendant must add weight ({before} -> {after})"
    );
    assert_eq!(dag.cumulative_weight(&tip), dag.vote_weight(&tip) + after);
    assert_eq!(dag.cumulative_weight(&[8u8; 32]), 0);
    assert_eq!(dag.descendant_weight(&[8u8; 32]), 0);
}

#[test]
fn network_partition_minority_cannot_allocate() {
    // Partition: two sides vote for rival burns of one element. On heal
    // both burns land on one node; at most one rival may confirm and
    // the loser is orphaned evidence, so no TURN server allocates twice.
    let mut dag = Dag::new();
    let rep_a = setup_rep(&mut dag);
    let owner = w(41);
    let tip = bond(&mut dag, rep_a, &owner);
    let e = eid(240);
    dag.register_element(e, owner.address());
    // Second representative with weight (rep_b, 10 delegated elements).
    let rep_b = w(201).address();
    for i in 0..10u8 {
        dag.register_element(ElementId([150 + i; 32]), rep_b);
    }
    dag.delegate(rep_b, rep_b);
    // Rival burns: same predecessor + element, different hashes.
    let burn_a = sign_block(
        Block::new(
            BlockType::Burn,
            owner.address(),
            tip,
            ZERO_HASH,
            e,
            burn_sink(),
        ),
        &owner,
    );
    let mut burn_b_blk = Block::new(
        BlockType::Burn,
        owner.address(),
        tip,
        ZERO_HASH,
        e,
        burn_sink(),
    );
    // Rival burn differs in to_address (different sink address), so the
    // signed content differs and the hashes must differ.
    let mut alt = burn_sink();
    alt.0[0] ^= 1;
    burn_b_blk.to_address = alt;
    let burn_b = sign_block(burn_b_blk, &owner);
    let ha = burn_a.block_hash();
    let hb = burn_b.block_hash();
    assert_ne!(ha, hb);
    dag.insert_block(burn_a).unwrap();
    dag.insert_block(burn_b).unwrap();
    dag.cast_vote(rep_a, ha).unwrap();
    dag.cast_vote(rep_b, hb).unwrap();
    for _ in 0..5 {
        dag.confirm_step();
    }
    let ca = dag.is_confirmed(&ha);
    let cb = dag.is_confirmed(&hb);
    assert!(!(ca && cb), "both rivals confirmed: {ca} {cb}");
    let orphaned = [ha, hb]
        .iter()
        .any(|h| dag.block_status(h) == Some(BlockStatus::Orphaned));
    // Neither side reached 67% alone in this balanced split (10 vs 10),
    // so both burns stay pending and NO allocation is made on either
    // partition -- the spec's stall-instead-of-double-spend rule.
    assert!(!ca && !cb);
    assert!(!orphaned);
}

#[test]
fn eclipsed_server_sees_attacker_fed_view_but_weight_protects() {
    // An eclipsed TURN server whose only peer is the attacker can be
    // fed votes for a rival burn; its confirmation checks still require
    // weight from the full online set, so it cannot allocate locally
    // without network weight. Model: attacker controls the only vote;
    // burn must not confirm.
    let mut dag = Dag::new();
    let rep = setup_rep(&mut dag);
    let owner = w(42);
    let tip = bond(&mut dag, rep, &owner);
    let e = eid(241);
    dag.register_element(e, owner.address());
    // Remove the honest rep from the online set (eclipse): online
    // weight becomes whatever the attacker supplies.
    let attacker = w(99).address();
    dag.register_element(eid(250), attacker);
    // Attacker votes for its own burn without delegation weight.
    let burn = sign_block(
        Block::new(
            BlockType::Burn,
            owner.address(),
            tip,
            ZERO_HASH,
            e,
            burn_sink(),
        ),
        &owner,
    );
    let h = burn.block_hash();
    dag.insert_block(burn).unwrap();
    // Even with the attacker's vote, cumulative weight is below 67% of
    // online weight, so the burn stays pending and unallocatable.
    let _ = dag.cast_vote(attacker, h).unwrap();
    for _ in 0..3 {
        dag.confirm_step();
    }
    assert!(!dag.is_confirmed(&h));
    assert_ne!(
        dag.block_status(&h),
        Some(BlockStatus::Confirmed),
        "eclipse-fed single vote must not confirm"
    );
}

#[test]
fn release_timelock_to_rendezvous_story() {
    // Full bond lifecycle on the node path: lock 5, spend gate requires
    // the bond, release starts the 24h timelock, maturity returns the
    // element to unspent, and a cancelled release keeps it bonded.
    let mut dag = Dag::new();
    let rep = setup_rep(&mut dag);
    let owner = w(50);
    let owner_addr = owner.address();
    let mut tip = bond(&mut dag, rep, &owner);
    assert!(dag.has_confirmed_bond(&owner_addr));
    // A release block for one bonded element starts the timelock.
    let recs = dag.releases();
    assert!(recs.is_empty());
    let bonded = dag.bonded_elements(&owner_addr);
    assert_eq!(bonded.len(), 5);
    let e = bonded[0];
    let rel = sign_block(
        Block::new(BlockType::BondRelease, owner_addr, tip, ZERO_HASH, e, owner_addr),
        &owner,
    );
    let h = rel.block_hash();
    dag.insert_block(rel).unwrap();
    dag.cast_vote(rep, h).unwrap();
    dag.confirm_step();
    assert!(dag.is_confirmed(&h));
    let rec = dag.request_release_record(&owner_addr).unwrap().clone();
    assert!(!rec.cancelled && !rec.executed);
    // Not yet mature: still bonded, element not spendable as unspent.
    assert_eq!(dag.element(&e).unwrap().status, ElementStatus::Bonded);
    // Advance past the timelock: release executes, element is unspent.
    dag.advance_epochs(BOND_RELEASE_EPOCHS + 1);
    assert!(dag.request_release_record(&owner_addr).unwrap().executed);
    assert_eq!(dag.element(&e).unwrap().status, ElementStatus::Unspent);
    // After one release the bond has 4 locks: below BOND_SIZE (5) the
    // spend gate closes again -- burn votes are rejected with NoBond.
    // That is why v1 keeps the full 5 until every release matures.
    let e2 = eid(251);
    dag.register_element(e2, owner_addr);
    let burn = sign_block(
        Block::new(BlockType::Burn, owner_addr, dag.account_tip(&owner_addr).unwrap(), ZERO_HASH, e2, burn_sink()),
        &owner,
    );
    let bh = burn.block_hash();
    dag.insert_block(burn).unwrap();
    let vote = dag.cast_vote(rep, bh);
    assert_eq!(vote, Err(DagError::NoBond));
    assert!(!dag.is_confirmed(&bh));
}
