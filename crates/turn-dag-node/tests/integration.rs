//! Workspace-level end-to-end tests (TODO section 8):
//! Examples A/B/C across >=3 mutually distrusting in-process nodes,
//! a double-spend race against two issuer instances, a workspace TCP
//! audit, and CLI smoke tests. Each node keeps its own Dag view and
//! verifies every gossiped block independently; no sleeps.

use std::net::IpAddr;
use turn_dag_dag::*;
use turn_dag_element::ElementId;
use turn_dag_node::*;
use turn_dag_turn::*;
use turn_dag_wallet::PqWallet;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// Broadcast a signed block to all nodes and confirm it on each.
fn confirm_all(nodes: &mut [Node], signed: SignedBlock) -> [u8; 32] {
    let h = signed.block_hash();
    for n in nodes.iter_mut() {
        n.dag.insert_block(signed.clone()).unwrap();
        n.dag.cast_vote(n.rep, h).unwrap();
        n.dag.confirm_step();
        n.dag.confirm_step();
        assert_eq!(
            n.dag.block_status(&h),
            Some(BlockStatus::Confirmed),
            "node {}",
            n.name
        );
    }
    h
}
fn broadcast(nodes: &mut [Node], signed: &SignedBlock) {
    for n in nodes.iter_mut() {
        n.dag.insert_block(signed.clone()).unwrap();
    }
}
/// Identically bond `owner` on every node (same signed blocks gossiped).
fn bond_all(nodes: &mut [Node], owner: &turn_dag_wallet::HotWallet) -> [u8; 32] {
    let addr = owner.address();
    let mut tip = ZERO_HASH;
    for i in 0..5u8 {
        let mut b = [0u8; 32];
        b[0] = addr.0[0];
        b[1] = i + 1;
        b[2] = 0xB0;
        let id = ElementId(b);
        for n in nodes.iter_mut() {
            n.dag.register_element(id, addr);
        }
        let blk = Block::new(
            BlockType::BondLock,
            addr,
            tip,
            ZERO_HASH,
            id,
            bond_pseudo_account(&addr),
        );
        tip = confirm_all(nodes, sign_block(blk, owner));
    }
    for n in nodes.iter() {
        assert!(n.dag.has_confirmed_bond(&addr), "{}", n.name);
    }
    tip
}
fn three_nodes() -> Vec<Node> {
    vec![
        Node::new("node-a", 11),
        Node::new("node-b", 12),
        Node::new("node-c", 13),
    ]
}
fn redeem(
    issuer: &mut TurnIssuer,
    user: &str,
    burn_id: [u8; 32],
    now: u64,
) -> ApiResponse<Vec<TurnCredential>> {
    let client = ip("203.0.113.10");
    let ch = issuer.handle_get_challenge(client, now).body.unwrap();
    let challenge = TurnPowChallenge {
        challenge_id: ch.challenge_id,
        challenge: ch.challenge,
        client_ip: client,
        issued_at: now,
        expires_at: ch.expires_at,
        bits: ch.bits,
    };
    let pow = solve_turn_pow(&challenge);
    issuer.handle_post_redeem(
        &RedeemRequest {
            user_id: user.into(),
            client_ip: client,
            peer_ip: ip("203.0.113.20"),
            transport: Transport::Udp,
            both_symmetric_nat: false,
            burn_id,
            pow,
        },
        now,
    )
}

#[test]
fn example_a_valid_transfer_across_three_nodes() {
    let mut nodes = three_nodes();
    let alice = wallet(1);
    let bob = wallet(2);
    let tip = bond_all(&mut nodes, &alice);
    let e = ElementId([42u8; 32]);
    for n in nodes.iter_mut() {
        n.dag.register_element(e, alice.address());
    }
    let send = sign_block(
        Block::new(
            BlockType::Send,
            alice.address(),
            tip,
            ZERO_HASH,
            e,
            bob.address(),
        ),
        &alice,
    );
    let send_h = confirm_all(&mut nodes, send);
    let recv = sign_block(
        Block::new(
            BlockType::Receive,
            bob.address(),
            ZERO_HASH,
            send_h,
            e,
            bob.address(),
        ),
        &bob,
    );
    confirm_all(&mut nodes, recv);
    for n in &nodes {
        let rec = n.dag.element(&e).unwrap();
        assert_eq!(rec.owner, bob.address(), "{}", n.name);
        assert_eq!(rec.status, turn_dag_element::ElementStatus::Unspent);
        assert!(n.dag.is_confirmed(&send_h));
    }
}

#[test]
fn example_b_double_spend_race_two_issuers_neither_allocates_before_confirmation() {
    let mut nodes = three_nodes();
    let mallory = wallet(3);
    let tip = bond_all(&mut nodes, &mallory);
    let e = ElementId([43u8; 32]);
    for n in nodes.iter_mut() {
        n.dag.register_element(e, mallory.address());
    }
    let burn = sign_block(
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
    let send = sign_block(
        Block::new(
            BlockType::Send,
            mallory.address(),
            tip,
            ZERO_HASH,
            e,
            wallet(9).address(),
        ),
        &mallory,
    );
    let burn_h = burn.block_hash();
    let send_h = send.block_hash();
    broadcast(&mut nodes, &burn);
    broadcast(&mut nodes, &send);
    // Race: two mutually distrusting issuer instances, different DAG views.
    // Neither allocates before confirmation.
    for idx in [0usize, 1] {
        let checker = DagBurnConfirmation(&nodes[idx].dag);
        let mut issuer = TurnIssuer::new(b"issuer-secret".to_vec(), demo_policy(), &checker);
        for bid in [burn_h, send_h] {
            let resp = redeem(&mut issuer, "mallory", bid, 1_000);
            assert_eq!(
                resp.body,
                Err(RedeemError::UnconfirmedBurn),
                "issuer on {} pre-confirmation",
                nodes[idx].name
            );
            assert_eq!(issuer.active_allocations(), 0);
        }
    }
    // Burn branch wins the vote on every node; send branch is orphaned.
    for n in nodes.iter_mut() {
        n.dag.cast_vote(n.rep, burn_h).unwrap();
        n.dag.confirm_step();
        n.dag.confirm_step();
        assert_eq!(n.dag.block_status(&burn_h), Some(BlockStatus::Confirmed));
        assert_eq!(n.dag.block_status(&send_h), Some(BlockStatus::Orphaned));
        assert!(
            n.dag.get_block(&send_h).is_some(),
            "loser retained as evidence"
        );
    }
    // Winner issuer allocates exactly one credential; loser is refused.
    {
        let checker = DagBurnConfirmation(&nodes[0].dag);
        let mut winner = TurnIssuer::new(b"issuer-secret".to_vec(), demo_policy(), &checker);
        let ok = redeem(&mut winner, "mallory", burn_h, 1_100);
        assert_eq!(ok.status, 200);
        assert_eq!(ok.body.unwrap().len(), 1);
        assert_eq!(winner.active_allocations(), 1);
    }
    {
        let checker = DagBurnConfirmation(&nodes[1].dag);
        let mut loser = TurnIssuer::new(b"issuer-secret".to_vec(), demo_policy(), &checker);
        let no = redeem(&mut loser, "mallory", send_h, 1_100);
        assert_eq!(
            no.body,
            Err(RedeemError::UnconfirmedBurn),
            "orphaned loser must be refused"
        );
        assert_eq!(loser.active_allocations(), 0);
    }
}

#[test]
fn example_c_slash_across_three_nodes() {
    let mut nodes = three_nodes();
    let mallory = wallet(3);
    let reporter = wallet(77).address();
    let tip = bond_all(&mut nodes, &mallory);
    let e = ElementId([44u8; 32]);
    for n in nodes.iter_mut() {
        n.dag.register_element(e, mallory.address());
    }
    let s1 = sign_block(
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
    let s2 = sign_block(
        Block::new(
            BlockType::Send,
            mallory.address(),
            tip,
            ZERO_HASH,
            e,
            wallet(9).address(),
        ),
        &mallory,
    );
    broadcast(&mut nodes, &s1);
    broadcast(&mut nodes, &s2);
    let proof = build_fraud_proof(&s1, &s2, reporter, 1_700_000_000);
    for n in nodes.iter_mut() {
        let ph = n.dag.receive_proof(proof.clone()).unwrap();
        assert!(n.dag.is_frozen(&mallory.address()), "{}", n.name);
        assert!(n.dag.cast_slash_vote(n.rep, ph).unwrap());
        let out = n.dag.slash_outcome(&ph).unwrap().clone();
        assert_eq!(n.dag.element(&out.bounty_element).unwrap().owner, reporter);
        assert_eq!(out.burned_elements.len(), 4);
        for id in &out.burned_elements {
            assert_eq!(
                n.dag.element(id).unwrap().status,
                turn_dag_element::ElementStatus::Burned
            );
        }
        assert!(n.dag.is_blacklisted_addr(&mallory.address()));
        assert!(n.dag.is_blacklisted_pubkey(mallory.public_key()));
    }
    let _ = tip;
}

#[test]
fn tcp_audit_workspace_sources_have_no_kernel_tcp() {
    // Scan every workspace src/**/*.rs, comments stripped. Test files
    // (including this audit) are excluded: they name the patterns.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = vec![];
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for ent in std::fs::read_dir(&dir).unwrap() {
            let p = ent.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if name == "target" || name == ".git" {
                continue;
            }
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().map(|x| x == "rs").unwrap_or(false)
                && p.components().any(|c| c.as_os_str() == "src")
            {
                files.push(p);
            }
        }
    }
    assert!(
        files.len() >= 6,
        "expected workspace sources, got {}",
        files.len()
    );
    for f in &files {
        let src = std::fs::read_to_string(f).unwrap();
        let code: String = src
            .lines()
            .map(|l| match l.find("//") {
                Some(i) => &l[..i],
                None => l,
            })
            .collect::<Vec<_>>()
            .join("\n");
        for pat in ["TcpListener", "TcpStream"] {
            assert!(
                !code.contains(pat),
                "{} contains forbidden {pat} outside comments",
                f.display()
            );
        }
    }
}

#[test]
fn cli_help_and_demo_flows() {
    let bin = env!("CARGO_BIN_EXE_turn-dag-node");
    for args in [
        &["--help"][..],
        &["demo"][..],
        &["rendezvous"][..],
        &["stack"][..],
        &["init"][..],
        &["status"][..],
    ] {
        let out = std::process::Command::new(bin).args(args).output().unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let help = std::process::Command::new(bin)
        .arg("--help")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&help.stdout).contains("burn-for-rendezvous"));
    let bad = std::process::Command::new(bin)
        .arg("nope")
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
}

#[test]
fn cli_keygen_backup_recover_roundtrip() {
    use std::process::Command;
    let dir = std::env::temp_dir().join("turndag-keygen-test");
    let _ = std::fs::create_dir_all(&dir);
    let seed = dir.join("seed.hex");
    let backup = dir.join("backup.hex");
    let recovered = dir.join("recovered.hex");
    let bin = env!("CARGO_BIN_EXE_turn-dag-node");
    let st = Command::new(bin)
        .args([
            "keygen",
            "--out",
            seed.to_str().unwrap(),
            "--backup",
            backup.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(st.success());
    // Seed file is owner-only (0600 on Unix).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&seed).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    assert!(backup.exists());
    // Recover into a different file: byte-identical seed.
    let st = Command::new(bin)
        .args([
            "recover",
            "--backup",
            backup.to_str().unwrap(),
            "--seed-file",
            recovered.to_str().unwrap(),
            "--kem-seed-file",
            seed.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(st.success());
    assert_eq!(
        std::fs::read(&seed).unwrap(),
        std::fs::read(&recovered).unwrap(),
        "recovered seed must match"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn burn_gate_end_to_end_cli_ticket_to_wire() {
    // Node flow: bond + mint + burn (confirmed on the DAG) -> rendezvous
    // ticket. The wire server accepts only that ticket; a forged ticket
    // with valid HMAC but no confirmed burn gets 401.
    use turn_dag_turn::wire::attr_type;
    use turn_dag_turn::wire::Class;
    use turn_dag_turn::wire::StunMessage;
    use turn_dag_turn::wire::{method, HandleOutcome, TurnServer};
    let mut node = Node::new("gate-node", 51);
    let rep = node.rep;
    let owner = wallet(51);
    bond(&mut node.dag, rep, &owner).unwrap();
    let (eid, _) = mint_one(&mut node.dag, rep, &owner, 1, 1_000).unwrap();
    let tip = node
        .dag
        .account_tip(&owner.address())
        .unwrap_or(turn_dag_dag::ZERO_HASH);
    let burn = turn_dag_dag::sign_block(
        turn_dag_dag::Block::new(
            turn_dag_dag::BlockType::Burn,
            owner.address(),
            tip,
            turn_dag_dag::ZERO_HASH,
            eid,
            turn_dag_dag::burn_sink(),
        ),
        &owner,
    );
    let burn_h = burn.block_hash();
    confirm_on(&mut node.dag, rep, burn).unwrap();
    assert!(node.dag.is_confirmed(&burn_h));
    let secret = b"gate-issuer-secret".to_vec();
    // Ticket minted ONLY after confirmation (rendezvous() gates on it).
    let cred = rendezvous(
        &node.dag,
        secret.clone(),
        burn_h,
        "gate-user",
        "203.0.113.5".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        2_000,
    )
    .unwrap();
    // Wire server with the confirmed-burn ticket registry.
    let mut srv = TurnServer::new("127.0.0.1".parse().unwrap())
        .with_rest_auth(secret.clone())
        .with_burn_tickets(vec![cred.ticket_id.clone()]);
    let nonce = "gate-nonce";
    let _ = nonce;
    // Allocate with the real ticket: succeeds.
    let req = {
        let mut m = StunMessage::new(method::ALLOCATE, Class::Request, [5u8; 12]);
        m.push_attr(attr_type::REQUESTED_TRANSPORT, vec![17, 0, 0, 0]);
        m.push_attr(attr_type::USERNAME, cred.username.as_bytes().to_vec());
        m.push_attr(attr_type::REALM, b"turn-dag".to_vec());
        m.push_attr(attr_type::NONCE, b"gate-nonce".to_vec());
        turn_dag_turn::wire::sign_wire(
            m,
            Some(&turn_dag_turn::wire::integrity_key(
                &cred.username,
                "turn-dag",
                &cred.password,
            )),
        )
    };
    match srv.handle(&req, "203.0.113.5:5000".parse().unwrap(), 2_000) {
        HandleOutcome::Response(b) => {
            let r = StunMessage::decode(&b).unwrap();
            assert_eq!(r.class, Class::Success);
        }
        other => panic!("ticketed allocate must succeed, got {other:?}"),
    }
    // Unconfirmed-burn ticket (forged ticket id, valid HMAC): 401.
    let forged = {
        let mut m = StunMessage::new(method::ALLOCATE, Class::Request, [5u8; 12]);
        m.push_attr(attr_type::REQUESTED_TRANSPORT, vec![17, 0, 0, 0]);
        m.push_attr(attr_type::USERNAME, b"2120:pow:forged-ticket".to_vec());
        m.push_attr(attr_type::REALM, b"turn-dag".to_vec());
        m.push_attr(attr_type::NONCE, b"gate-nonce".to_vec());
        let pass = turn_dag_turn::credential_password(&secret, "2120:pow:forged-ticket");
        turn_dag_turn::wire::sign_wire(
            m,
            Some(&turn_dag_turn::wire::integrity_key(
                "2120:pow:forged-ticket",
                "turn-dag",
                &pass,
            )),
        )
    };
    match srv.handle(&forged, "203.0.113.5:5000".parse().unwrap(), 2_000) {
        HandleOutcome::Response(b) => {
            let r = StunMessage::decode(&b).unwrap();
            assert_eq!(turn_dag_turn::wire::error_code(&r), Some(401));
        }
        other => panic!("forged ticket must 401, got {other:?}"),
    }
}
