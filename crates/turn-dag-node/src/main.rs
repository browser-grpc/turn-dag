//! turn-dag-node CLI (std args only, no kernel TCP).
use std::net::IpAddr;
use turn_dag_dag::{sign_block, Block, BlockType, ZERO_HASH};
use turn_dag_node::*;
use turn_dag_wallet::PqWallet;

const HELP: &str = "\
turn-dag-node - DAG + minter + TURN issuer node (in-process, smoltcp virtual device, no kernel TCP)
USAGE:
  turn-dag-node [--help|help]
  turn-dag-node init
  turn-dag-node status
  turn-dag-node mint
  turn-dag-node transfer
  turn-dag-node burn
  turn-dag-node rendezvous
  turn-dag-node demo
  turn-dag-node stack
  turn-dag-node serve-udp [--addr 127.0.0.1:3478] [--relay-ip IP] [--user USER --pass PASS]
Commands demonstrate node init/status, mint, transfer and the
burn-for-rendezvous flow in-process on a virtual/smoltcp device or
pure logic. No listener is opened.";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("demo");
    if cmd == "serve-udp" {
        std::process::exit(serve_udp(&args[2..]));
    }
    std::process::exit(run(cmd));
}

fn serve_udp(args: &[String]) -> i32 {
    let mut addr = "127.0.0.1:3478".to_string();
    let mut relay_ip: Option<String> = None;
    let mut user: Option<String> = None;
    let mut pass: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--addr" => addr = it.next().cloned().unwrap_or_default(),
            "--relay-ip" => relay_ip = it.next().cloned(),
            "--user" => user = it.next().cloned(),
            "--pass" => pass = it.next().cloned(),
            _ => {
                eprintln!("unknown serve-udp arg: {a}");
                return 2;
            }
        }
    }
    let Ok(sock_addr) = addr.parse::<std::net::SocketAddr>() else {
        eprintln!("bad --addr: {addr}");
        return 2;
    };
    let relay: std::net::IpAddr = relay_ip
        .and_then(|r| r.parse().ok())
        .unwrap_or(sock_addr.ip());
    let mut server = turn_dag_turn::wire::TurnServer::new(relay);
    if let (Some(u), Some(p)) = (user, pass) {
        let mut creds = std::collections::HashMap::new();
        creds.insert(u, p);
        server = server.with_auth("turn-dag", creds);
    }
    let mut live = match turn_dag_turn::live::LiveUdpTurnServer::bind(sock_addr, server) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {addr} failed: {e}");
            return 1;
        }
    };
    println!(
        "turn-udp listening addr={} auth={}",
        live.local_addr().map(|a| a.to_string()).unwrap_or_default(),
        live.allocation_count()
    );
    // Serve until killed (Ctrl-C / SIGTERM). UDP only; no kernel TCP.
    loop {
        if let Err(e) = live.serve_once() {
            eprintln!("serve error: {e}");
            return 1;
        }
    }
}

fn run(cmd: &str) -> i32 {
    match cmd {
        "--help" | "-h" | "help" => {
            println!("{HELP}");
            0
        }
        "init" => {
            let n = Node::new("node-1", 1);
            println!("node init: ok");
            println!(
                "name={} address={} bech32={}",
                n.name,
                hex(&n.address().0),
                n.address().to_bech32()
            );
            println!("epoch={} tips={}", n.dag.epoch(), n.dag.tips().len());
            0
        }
        "status" => {
            let n = Node::new("node-1", 1);
            println!(
                "node status: ok address={} epoch={} online_weight={}",
                hex(&n.address().0),
                n.dag.epoch(),
                n.dag.online_weight()
            );
            0
        }
        "stack" => {
            use turn_dag_turn::stack::UserSpaceStack;
            use turn_dag_turn::TURN_PORT;
            let s = UserSpaceStack::new(smoltcp::wire::IpAddress::v4(10, 0, 0, 1), 24, TURN_PORT);
            println!(
                "smoltcp virtual stack: ok udp_port={} tcp_via_smoltcp=true kernel_tcp=false",
                TURN_PORT
            );
            println!(
                "udp_handle={:?} tcp_handle={:?} tx_queue={}",
                s.udp_handle,
                s.tcp_handle,
                s.device.tx_queue.len()
            );
            0
        }
        "mint" | "transfer" | "burn" | "rendezvous" | "demo" => flow(cmd),
        _ => {
            eprintln!("unknown command: {cmd}\n{HELP}");
            2
        }
    }
}

fn flow(cmd: &str) -> i32 {
    let mut alice = Node::new("alice-node", 1);
    let rep = alice.rep;
    let alice_wallet = wallet(1);
    if let Err(e) = bond(&mut alice.dag, rep, &alice_wallet) {
        eprintln!("bond failed: {e}");
        return 1;
    }
    println!(
        "bond: confirmed (5 elements) has_bond={}",
        alice.dag.has_confirmed_bond(&alice_wallet.address())
    );
    let bob = wallet(2);
    let (eid, mint_h) = match mint_one(&mut alice.dag, rep, &alice_wallet, 1, 1_000) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("mint failed: {e}");
            return 1;
        }
    };
    println!(
        "mint: element={} block={} owner={}",
        hex(&eid.0),
        hex(&mint_h),
        hex(&alice_wallet.address().0)
    );
    if cmd == "mint" {
        return 0;
    }
    let (eid_t, _) = match mint_one(&mut alice.dag, rep, &alice_wallet, 1, 1_010) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("mint2: {e}");
            return 1;
        }
    };
    let (eid_b, _) = match mint_one(&mut alice.dag, rep, &alice_wallet, 1, 1_020) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("mint3: {e}");
            return 1;
        }
    };
    let tip = alice
        .dag
        .account_tip(&alice_wallet.address())
        .unwrap_or(ZERO_HASH);
    let send = sign_block(
        Block::new(
            BlockType::Send,
            alice_wallet.address(),
            tip,
            ZERO_HASH,
            eid_t,
            bob.address(),
        ),
        &alice_wallet,
    );
    let send_h = match confirm_on(&mut alice.dag, rep, send) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("send: {e}");
            return 1;
        }
    };
    let recv = sign_block(
        Block::new(
            BlockType::Receive,
            bob.address(),
            ZERO_HASH,
            send_h,
            eid_t,
            bob.address(),
        ),
        &bob,
    );
    if let Err(e) = confirm_on(&mut alice.dag, rep, recv) {
        eprintln!("receive: {e}");
        return 1;
    }
    println!(
        "transfer: element={} send={} owner_now={}",
        hex(&eid_t.0),
        hex(&send_h),
        hex(&alice
            .dag
            .element(&eid_t)
            .map(|r| r.owner.0)
            .unwrap_or([0; 20]))
    );
    if cmd == "transfer" {
        return 0;
    }
    let tip2 = alice
        .dag
        .account_tip(&alice_wallet.address())
        .unwrap_or(ZERO_HASH);
    let burn = sign_block(
        Block::new(
            BlockType::Burn,
            alice_wallet.address(),
            tip2,
            ZERO_HASH,
            eid_b,
            turn_dag_dag::burn_sink(),
        ),
        &alice_wallet,
    );
    let burn_h = match confirm_on(&mut alice.dag, rep, burn) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("burn: {e}");
            return 1;
        }
    };
    println!(
        "burn: element={} burn_block={} confirmed={}",
        hex(&eid_b.0),
        hex(&burn_h),
        alice.dag.is_confirmed(&burn_h)
    );
    if cmd == "burn" {
        return 0;
    }
    let client: IpAddr = "203.0.113.10".parse().unwrap();
    let peer: IpAddr = "203.0.113.20".parse().unwrap();
    match rendezvous(
        &alice.dag,
        b"demo-secret".to_vec(),
        burn_h,
        "alice",
        client,
        peer,
        2_000,
    ) {
        Ok(c) => {
            println!(
                "rendezvous: ticket={} username={} expires_at={} max_bps={} byte_cap={}",
                c.ticket_id, c.username, c.expires_at, c.max_bps, c.byte_cap
            );
            0
        }
        Err(e) => {
            eprintln!("rendezvous failed: {e:?}");
            1
        }
    }
}
