//! Workspace-level end-to-end tests for the per-node serial
//! ledger design: coins bound to their originating node, atomic
//! double-spend rejection, foreign-node non-honoring, origin-signed
//! burn receipts feeding the relay-pass gate, a workspace TCP
//! audit, and CLI smoke tests.

use std::net::IpAddr;
use turn_dag_node::*;
use turn_dag_turn::*;
use turn_dag_wallet::PqWallet;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn mint_transfer_burn_on_origin_ledger() {
    let mut node = Node::new("origin-a", 11);
    let alice = wallet(1);
    let bob = wallet(2);
    let (eid, _) = node.mint_for(&alice, 1, 1_000).unwrap();
    assert_eq!(node.balance(&alice.address()), 1);
    assert_eq!(node.ledger.record(&eid).unwrap().origin, node.address());
    node.transfer(eid, &alice, bob.address()).unwrap();
    assert_eq!(node.ledger.record(&eid).unwrap().owner, bob.address());
    let receipt = node.burn(eid, &bob).unwrap();
    assert!(node.ledger.verify_receipt(&receipt));
    assert!(node.ledger.verify_chain());
}

#[test]
fn double_spend_is_rejected_atomically_and_foreign_node_does_not_honor() {
    let mut a = Node::new("origin-a", 11);
    let mut b = Node::new("origin-b", 12);
    let alice = wallet(1);
    let bob = wallet(2);
    let (eid, _) = a.mint_for(&alice, 1, 1_000).unwrap();
    // Foreign node: the coin is absent there and cannot be spent.
    assert!(b.burn(eid, &alice).is_err());
    assert!(b.transfer(eid, &alice, bob.address()).is_err());
    // At the origin, the first spend wins and every second fails.
    a.transfer(eid, &alice, bob.address()).unwrap();
    assert!(
        a.transfer(eid, &bob, alice.address()).is_ok(),
        "owner transfer is the live spend path"
    );
    // (transfer back to Alice succeeded above; now burn and re-spend)
    let _receipt = a.burn(eid, &alice).unwrap();
    assert!(a.burn(eid, &alice).is_err());
    assert!(a.transfer(eid, &alice, bob.address()).is_err());
}

#[test]
fn node_relay_pass_consumes_burn_exactly_once() {
    let mut node = Node::new("origin-a", 31);
    let alice = wallet(3);
    let bob = wallet(4);
    let (e1, _) = node.mint_for(&alice, 1, 1_000).unwrap();
    let (e2, _) = node.mint_for(&bob, 1, 1_010).unwrap();
    let r1 = node.burn(e1, &alice).unwrap();
    let r2 = node.burn(e2, &bob).unwrap();
    let client = ip("203.0.113.10");
    let peer = ip("203.0.113.20");
    let c1 = node.relay_pass(&r1, &alice, client, peer, 2_000).unwrap();
    assert_eq!(c1.expires_at, 2_120);
    // Replay against the same node: rejected, no second credential.
    let mallory = wallet(77);
    let again = node.relay_pass(&r1, &mallory, client, peer, 2_000);
    assert!(
        format!("{again:?}").contains("BurnAlreadyRedeemed"),
        "{again:?}"
    );
    // A different burn still issues (and the first ticket is unharmed).
    let c2 = node.relay_pass(&r2, &bob, client, peer, 2_100).unwrap();
    assert_ne!(c1.ticket_id, c2.ticket_id);
    assert!(node.ledger.is_redeemed(&r1.entry_hash));
    assert!(node.ledger.is_redeemed(&r2.entry_hash));

    // Bond-priced quota: Alice has one active pass and no bond -
    // a second concurrent pass is refused; locking one element
    // as rate bond raises her quota and the same pass succeeds.
    let (e3, _) = node.mint_for(&alice, 1, 1_030).unwrap();
    let (e4, _) = node.mint_for(&alice, 1, 1_040).unwrap();
    let (bond_el, _) = node.mint_for(&alice, 1, 1_050).unwrap();
    let r3 = node.burn(e3, &alice).unwrap();
    let blocked = node.relay_pass(&r3, &alice, client, peer, 2_050);
    assert!(
        format!("{blocked:?}").contains("UserQuotaExceeded"),
        "baseline quota=1 must block a second concurrent pass: {blocked:?}"
    );
    assert!(
        !node.ledger.is_redeemed(&r3.entry_hash),
        "blocked pass must not consume the burn"
    );
    node.bond_lock(bond_el, &alice).unwrap();
    let _c3 = node.relay_pass(&r3, &alice, client, peer, 2_050).unwrap();
    // After the first pass expires, the baseline quota frees again.
    let r4 = node.burn(e4, &alice).unwrap();
    let _c4 = node.relay_pass(&r4, &alice, client, peer, 2_200).unwrap();
}

#[test]
fn relay_pass_requires_origin_burn_receipt() {
    let mut node = Node::new("origin-a", 21);
    let alice = wallet(3);
    let (eid, _) = node.mint_for(&alice, 1, 1_000).unwrap();
    // Before burn: no credential.
    let client = ip("203.0.113.10");
    let err = issue_relay_pass(
        &node.ledger,
        b"issuer-secret".to_vec(),
        [9u8; 32],
        "alice",
        client,
        ip("203.0.113.20"),
        1_000,
    )
    .unwrap_err();
    assert_eq!(err, RedeemError::UnconfirmedBurn);
    let receipt = node.burn(eid, &alice).unwrap();
    let cred = issue_relay_pass(
        &node.ledger,
        b"issuer-secret".to_vec(),
        receipt.entry_hash,
        "alice",
        client,
        ip("203.0.113.20"),
        1_100,
    )
    .unwrap();
    assert_eq!(cred.expires_at, 1_220);
    assert!(cred.username.ends_with(&cred.ticket_id));
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
        files.len() >= 5,
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
        &["relaypass"][..],
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
    assert!(String::from_utf8_lossy(&help.stdout).contains("burn-for-relay-pass"));
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
    // Node flow: bond + mint + burn (confirmed on the DAG) -> relay pass
    // ticket. The wire server accepts only that ticket; a forged ticket
    // with valid HMAC but no confirmed burn gets 401.
    use turn_dag_turn::wire::attr_type;
    use turn_dag_turn::wire::Class;
    use turn_dag_turn::wire::StunMessage;
    use turn_dag_turn::wire::{method, HandleOutcome, TurnServer};
    let mut node = Node::new("gate-node", 51);
    let owner = wallet(51);
    let (eid, _) = node.mint_for(&owner, 1, 1_000).unwrap();
    let receipt = node.burn(eid, &owner).unwrap();
    let burn_h = receipt.entry_hash;
    assert!(node.ledger.is_burned(&burn_h));
    let secret = b"gate-issuer-secret".to_vec();
    // Ticket minted ONLY after confirmation (issue_relay_pass gates on it).
    let cred = issue_relay_pass(
        &node.ledger,
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
