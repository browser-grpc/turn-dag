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
  turn-dag-node relaypass   (burn -> 120s TURN credential; formerly 'rendezvous')
  turn-dag-node demo
  turn-dag-node stack
  turn-dag-node serve-udp [--addr 127.0.0.1:3478] [--relay-ip IP] [--user USER --pass PASS] [--rest-secret HEX --ticket ID] [--total-quota N]
  turn-dag-node serve-tls --cert CERT.pem --key KEY.pem [--tun turndag0] [--ip 10.99.0.1] [--port 5349] [--user USER --pass PASS]
  turn-dag-node keygen [--out FILE] [--backup FILE]
  turn-dag-node backup --seed-file FILE [--out FILE]
  turn-dag-node recover --backup FILE [--seed-file FILE]
Commands demonstrate node init/status, mint, transfer and the
burn-for-relay-pass flow in-process on a virtual/smoltcp device or
pure logic. No listener is opened.";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("demo");
    if cmd == "serve-udp" {
        std::process::exit(serve_udp(&args[2..]));
    }
    if cmd == "serve-tls" {
        std::process::exit(serve_tls(&args[2..]));
    }
    if cmd == "keygen" {
        std::process::exit(keygen(&args[2..]));
    }
    if cmd == "backup" {
        std::process::exit(backup(&args[2..]));
    }
    if cmd == "recover" {
        std::process::exit(recover(&args[2..]));
    }
    std::process::exit(run(cmd));
}

fn serve_udp(args: &[String]) -> i32 {
    let mut addr = "127.0.0.1:3478".to_string();
    let mut relay_ip: Option<String> = None;
    let mut user: Option<String> = None;
    let mut pass: Option<String> = None;
    let mut rest_secret: Option<String> = None;
    let mut burn_tickets: Vec<String> = Vec::new();
    let mut total_quota: Option<usize> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--addr" => addr = it.next().cloned().unwrap_or_default(),
            "--relay-ip" => relay_ip = it.next().cloned(),
            "--user" => user = it.next().cloned(),
            "--pass" => pass = it.next().cloned(),
            "--rest-secret" => rest_secret = it.next().cloned(),
            "--ticket" => burn_tickets.push(it.next().cloned().unwrap_or_default()),
            "--total-quota" => total_quota = it.next().and_then(|v| v.parse().ok()),
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
    if let Some(q) = total_quota {
        server = server.with_max_allocations(q);
    }
    if let Some(hex_secret) = rest_secret {
        let secret = turn_dag_dag::hex_decode(&hex_secret).unwrap_or_default();
        // Issuer REST credentials (username=expiry:pow:<ticket>): the
        // long-term key derives from the issuer HMAC, as TurnIssuer
        // issues them. With --ticket, only tickets minted after a
        // confirmed burn (TurnIssuer::handle_post_redeem) are accepted:
        // the burn gate is the ticket registry.
        server = server.with_rest_auth(secret);
        if !burn_tickets.is_empty() {
            server = server.with_burn_tickets(burn_tickets);
        }
    } else if let (Some(u), Some(p)) = (user, pass) {
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

fn serve_tls(args: &[String]) -> i32 {
    let mut tun = "turndag0".to_string();
    let mut ip = "10.99.0.1".to_string();
    let mut port: u16 = 5349;
    let mut cert_path: Option<String> = None;
    let mut key_path: Option<String> = None;
    let mut user: Option<String> = None;
    let mut pass: Option<String> = None;
    let mut rest_secret: Option<String> = None;
    let mut burn_tickets: Vec<String> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--tun" => tun = it.next().cloned().unwrap_or_default(),
            "--ip" => ip = it.next().cloned().unwrap_or_default(),
            "--port" => port = it.next().and_then(|v| v.parse().ok()).unwrap_or(5349),
            "--cert" => cert_path = it.next().cloned(),
            "--key" => key_path = it.next().cloned(),
            "--user" => user = it.next().cloned(),
            "--pass" => pass = it.next().cloned(),
            "--rest-secret" => rest_secret = it.next().cloned(),
            "--ticket" => burn_tickets.push(it.next().cloned().unwrap_or_default()),
            _ => {
                eprintln!("unknown serve-tls arg: {a}");
                return 2;
            }
        }
    }
    let (Some(cert_path), Some(key_path)) = (cert_path, key_path) else {
        eprintln!("serve-tls requires --cert CERT.pem --key KEY.pem");
        return 2;
    };
    let cert_pem = match std::fs::read(&cert_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("read cert: {e}");
            return 1;
        }
    };
    let key_pem = match std::fs::read(&key_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("read key: {e}");
            return 1;
        }
    };
    let config = match turn_dag_turn::tls::server_config(&cert_pem, &key_pem) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tls config: {e}");
            return 1;
        }
    };
    let Ok(relay_ip) = ip.parse::<IpAddr>() else {
        eprintln!("bad --ip: {ip}");
        return 2;
    };
    let smol_ip = match relay_ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            smoltcp::wire::IpAddress::v4(o[0], o[1], o[2], o[3])
        }
        IpAddr::V6(_) => {
            eprintln!("serve-tls currently requires an IPv4 --ip");
            return 2;
        }
    };
    let mut server = turn_dag_turn::wire::TurnServer::new(relay_ip);
    if let Some(hex_secret) = rest_secret {
        let secret = turn_dag_dag::hex_decode(&hex_secret).unwrap_or_default();
        server = server.with_rest_auth(secret);
        if !burn_tickets.is_empty() {
            server = server.with_burn_tickets(burn_tickets);
        }
    } else if let (Some(u), Some(p)) = (user, pass) {
        let mut creds = std::collections::HashMap::new();
        creds.insert(u, p);
        server = server.with_auth("turn-dag", creds);
    }
    let mut live = match turn_dag_turn::live::LiveTlsTurnServer::bind_tun(
        &tun, smol_ip, 24, config, server, port,
    ) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "serve-tls bind tun '{tun}' failed: {e} (needs /dev/net/tun access; \
                 operator must also run: ip addr add {ip}/24 dev {tun} && ip link set {tun} up)"
            );
            return 1;
        }
    };
    println!("turn-tls listening tun={tun} ip={ip} port={port}");
    loop {
        if let Err(e) = live.serve_once() {
            eprintln!("serve-tls error: {e}");
            return 1;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
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
        "mint" | "transfer" | "burn" | "rendezvous" | "relaypass" | "demo" => flow(cmd),
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
    // Real wall-clock expiry: the printed credential must be usable
    // against a live serve-udp relay for its full 120s lifetime.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(2_000);
    match issue_relay_pass(
        &alice.dag,
        b"demo-secret".to_vec(),
        burn_h,
        "alice",
        client,
        peer,
        now,
    ) {
        Ok(c) => {
            println!(
                "relaypass: ticket={} username={} expires_at={} max_bps={} byte_cap={}",
                c.ticket_id, c.username, c.expires_at, c.max_bps, c.byte_cap
            );
            println!(
                "serve-udp: pass --rest-secret <issuer-secret-hex> --ticket {} to relay for this burn (ticket is valid only because the burn was confirmed)",
                c.ticket_id
            );
            0
        }
        Err(e) => {
            eprintln!("relaypass failed: {e:?}");
            1
        }
    }
}

fn read_seed_file(path: &str) -> Result<[u8; 32], String> {
    let data = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let hex = String::from_utf8(data).map_err(|e| format!("seed file not UTF-8: {e}"))?;
    let hex = hex.trim();
    let bytes = turn_dag_dag::hex_decode(hex).ok_or_else(|| "seed file is not hex".to_string())?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| format!("seed must be 32 bytes, got {len}"))
}

fn keygen(args: &[String]) -> i32 {
    let mut out = "seed.hex".to_string();
    let mut backup_path: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => out = it.next().cloned().unwrap_or_default(),
            "--backup" => backup_path = it.next().cloned(),
            _ => {
                eprintln!("unknown keygen arg: {a}");
                return 2;
            }
        }
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("OS entropy");
    // Owner-only file: 0600 on Unix.
    {
        use std::os::unix::fs::PermissionsExt;
        let hex = hex(&seed);
        std::fs::write(&out, format!("{hex}\n")).unwrap_or_else(|e| {
            eprintln!("write seed file: {e}");
            std::process::exit(1)
        });
        #[cfg(unix)]
        let _ = std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600));
    }
    let wallet = turn_dag_node::wallet(0);
    let _ = wallet;
    println!("seed written (0600) to {out}");
    if let Some(bp) = backup_path {
        let kem = turn_dag_wallet::KemKeypair::generate(&seed);
        let blob = turn_dag_wallet::seed_backup_encrypt(kem.encapsulation_key(), &seed)
            .unwrap_or_else(|e| {
                eprintln!("encrypt backup: {e:?}");
                std::process::exit(1)
            });
        std::fs::write(&bp, hex(&blob)).unwrap_or_else(|e| {
            eprintln!("write backup: {e}");
            std::process::exit(1)
        });
        println!("kem backup written to {bp} (store your decapsulation seed separately)");
    }
    0
}

fn backup(args: &[String]) -> i32 {
    let mut seed_file = String::new();
    let mut out = "backup.hex".to_string();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--seed-file" => seed_file = it.next().cloned().unwrap_or_default(),
            "--out" => out = it.next().cloned().unwrap_or_default(),
            _ => {
                eprintln!("unknown backup arg: {a}");
                return 2;
            }
        }
    }
    let Ok(seed) = read_seed_file(&seed_file) else {
        eprintln!("cannot read seed file");
        return 1;
    };
    let kem = turn_dag_wallet::KemKeypair::generate(&seed);
    let blob = match turn_dag_wallet::seed_backup_encrypt(kem.encapsulation_key(), &seed) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("encrypt: {e:?}");
            return 1;
        }
    };
    if let Err(e) = std::fs::write(&out, hex(&blob)) {
        eprintln!("write backup: {e}");
        return 1;
    }
    println!("backup written to {out}");
    0
}

fn recover(args: &[String]) -> i32 {
    let mut backup_path = String::new();
    let mut seed_file = "recovered-seed.hex".to_string();
    let mut kem_seed_file = String::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--backup" => backup_path = it.next().cloned().unwrap_or_default(),
            "--seed-file" => seed_file = it.next().cloned().unwrap_or_default(),
            "--kem-seed-file" => kem_seed_file = it.next().cloned().unwrap_or_default(),
            _ => {
                eprintln!("unknown recover arg: {a}");
                return 2;
            }
        }
    }
    let hexs = match std::fs::read_to_string(&backup_path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("read backup: {e}");
            return 1;
        }
    };
    let blob = turn_dag_dag::hex_decode(hexs.trim()).unwrap_or_default();
    // Recovery needs the same decapsulation key (derived from the seed
    // file or stored separately); use the seed file if present, else
    // attempt with the default demo seed and report failure honestly.
    let kem_seed_file = if kem_seed_file.is_empty() {
        // Default: the keygen seed file next to this command's cwd.
        "seed.hex".to_string()
    } else {
        kem_seed_file
    };
    let kem_seed_file = kem_seed_file.as_str();
    match read_seed_file(kem_seed_file) {
        Ok(s) => {
            let kem = turn_dag_wallet::KemKeypair::generate(&s);
            match kem.decrypt_seed(&blob) {
                Ok(seed) => {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &seed_file,
                        std::fs::Permissions::from_mode(0o600),
                    );
                    if let Err(e) = std::fs::write(&seed_file, format!("{}\n", hex(&seed))) {
                        eprintln!("write recovered seed: {e}");
                        return 1;
                    }
                    println!("recovered seed to {seed_file} (0600)");
                    0
                }
                Err(e) => {
                    eprintln!("decrypt failed: {e:?}");
                    1
                }
            }
        }
        Err(_) => {
            eprintln!("need decapsulation seed file '{kem_seed_file}' to recover");
            1
        }
    }
}
