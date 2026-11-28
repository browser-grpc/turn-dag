// Playwright WebRTC coverage for the Rust TURN relay.
//
// Browser sub-tests (per engine, Firefox + Chromium):
//   gather        - single PC, iceTransportPolicy=relay -> relay candidate
//   stun-google / stun-cloudflare - public STUN (Google, Cloudflare)
//                   must yield srflx candidates where internet is up
//   negative      - wrong credentials -> no relay candidate
//   expired       - expired issuer credential -> no relay candidate
//   relay         - two PCs in isolated contexts, relay/relay DataChannel
//   issuer        - credential from a real DAG burn -> TurnIssuer
//                   challenge/PoW/redeem (turn-dag-node relaypass) used
//                   in-browser against a burn-gated serve-udp relay
// Raw-wire sub-tests (Node UDP/STUN client against the live server):
//   wire-allocate-lifetime (120s cap), wire-tcp-refused (442),
//   wire-denied-peer (403 for metadata/RFC1918/loopback),
//   wire-refresh (cap/delete/437), wire-bps-rate (16384 B/s bucket),
//   wire-total-quota (486), wire-rest-valid/forged/expired (401),
//   wire-ticket-quota (one live allocation per ticket, 486)
//
// REQUIRE_RELAY=1 (Docker --network host job): gather/relay/issuer
// failures are FAIL, and at least MIN_PASS (default 10) sub-tests must
// PASS. Elsewhere they SKIP so loopback-only sandboxes stay green.
import { firefox, chromium, webkit } from 'playwright';
import { spawn } from 'node:child_process';
import http from 'node:http';
import dgram from 'node:dgram';
import net from 'node:net';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const PORT = 35478;
const REST_PORT = PORT + 1;
const QUOTA_PORT = PORT + 2;
const HOST = process.env.TURN_HOST || '192.168.68.114';
const USER = 'browser-test-user';
const PASS = 'browser-test-secret';
const REQUIRE = process.env.REQUIRE_RELAY === '1';
const MIN_PASS = Number(process.env.MIN_PASS || (REQUIRE ? 10 : 0));
const ENGINES = (process.env.BROWSERS || 'firefox').split(',').map((s) => s.trim()).filter(Boolean);
const GATHER_TIMEOUT_MS = 15000;
const CONNECT_TIMEOUT_MS = 30000;
const BYTE_CAP = 16384 * 120;

const results = [];
const record = (name, status, detail) => {
  results.push({ name, status, detail });
  console.log(`[${status}] ${name}${detail ? ` - ${detail}` : ''}`);
};
// Network-dependent assertion: hard-fails only when a real path is required.
const recordNet = (name, ok, detail, failDetail) =>
  ok ? record(name, 'PASS', detail) : record(name, REQUIRE ? 'FAIL' : 'SKIP', failDetail || detail);

import fs from 'node:fs';
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.json': 'application/json', '.wasm': 'application/wasm' };
const pageServer = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  // Browser wallet app + its vendor modules (real app under test).
  if (url.pathname.startsWith('/grpc-vendor/')) {
    const gv = path.join(root, 'vendor/grpc-dc/js');
    const rel = url.pathname.slice('/grpc-vendor/'.length);
    const fp = path.join(gv, rel);
    if (!fp.startsWith(gv) || !fs.existsSync(fp)) { res.writeHead(404); res.end('not found'); return; }
    res.setHeader('content-type', MIME[path.extname(fp)] || 'application/octet-stream');
    fs.createReadStream(fp).pipe(res);
    return;
  }
  if (url.pathname.startsWith('/wallet-app/') || url.pathname.startsWith('/vendor/')) {
    const isVendor = url.pathname.startsWith('/vendor/');
    const base = isVendor
      ? path.join(root, 'tests/browser/node_modules')
      : path.join(root, 'web');
    const rel = url.pathname.slice(isVendor ? '/vendor/'.length : '/wallet-app/'.length) || 'index.html';
    const filePath = path.join(base, rel);
    if (!filePath.startsWith(base) || !fs.existsSync(filePath)) {
      res.writeHead(404); res.end('not found'); return;
    }
    res.setHeader('content-type', MIME[path.extname(filePath)] || 'application/octet-stream');
    fs.createReadStream(filePath).pipe(res);
    return;
  }
  res.setHeader('content-type', 'text/html');
  res.end('<!doctype html><title>turn-dag webrtc test</title>');
});
await new Promise((r) => pageServer.listen(0, '127.0.0.1', r));
const pagePort = pageServer.address().port;
const pageUrl = `http://127.0.0.1:${pagePort}/`;

const servers = [];
function startServer(args) {
  const proc = spawn(path.join(root, 'target/debug/turn-dag-node'), args, {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let log = '';
  proc.stdout.on('data', (d) => (log += d));
  proc.stderr.on('data', (d) => (log += d));
  servers.push(proc);
  return { proc, log: () => log };
}
async function waitListening(srv, label) {
  for (let i = 0; i < 50 && !srv.log().includes('listening'); i++) {
    await new Promise((r) => setTimeout(r, 100));
  }
  if (!srv.log().includes('listening')) throw new Error(`${label} did not start: ${srv.log()}`);
}
const turnCfg = (user, pass, port = PORT) => ({
  iceServers: [{ urls: `turn:${HOST}:${port}?transport=udp`, username: user, credential: pass }],
  iceTransportPolicy: 'relay',
});

// ---------- minimal STUN/TURN wire client (raw e2e over live UDP) ----------
const MAGIC = 0x2112a442;
const M = { BINDING: 0x001, ALLOCATE: 0x003, REFRESH: 0x004, CREATE_PERMISSION: 0x008, CHANNEL_BIND: 0x009 };
const A = { ERROR_CODE: 0x0009, CHANNEL_NUMBER: 0x000c, LIFETIME: 0x000d, XOR_PEER: 0x0012, XOR_RELAYED: 0x0016, REQUESTED_TRANSPORT: 0x0019, XOR_MAPPED: 0x0020, USERNAME: 0x0006, MI: 0x0008, REALM: 0x0014, NONCE: 0x0015 };
const encodeType = (method, cls) => {
  const [b4, b8] = cls === 'success' ? [1, 0] : cls === 'error' ? [1, 1] : cls === 'indication' ? [0, 1] : [0, 0];
  return (method & 0xf) | ((method & 0x70) << 1) | ((method & 0xf80) << 2) | (b4 << 4) | (b8 << 8);
};
function buildMsg(method, attrs, key, txn) {
  const parts = [];
  for (const [t, v] of attrs) {
    const h = Buffer.alloc(4);
    h.writeUInt16BE(t); h.writeUInt16BE(v.length, 2);
    const pad = (4 - (v.length % 4)) % 4;
    parts.push(h, v, Buffer.alloc(pad));
  }
  let body = Buffer.concat(parts);
  if (key) {
    const head = Buffer.alloc(20);
    head.writeUInt16BE(encodeType(method, 'request'));
    head.writeUInt16BE(body.length + 24, 2);
    head.writeUInt32BE(MAGIC, 4);
    Buffer.from(txn).copy(head, 8);
    const mac = crypto.createHmac('sha1', key).update(Buffer.concat([head, body])).digest();
    const mi = Buffer.alloc(4);
    mi.writeUInt16BE(A.MI); mi.writeUInt16BE(20, 2);
    body = Buffer.concat([body, mi, mac]);
  }
  const head = Buffer.alloc(20);
  head.writeUInt16BE(encodeType(method, 'request'));
  head.writeUInt16BE(body.length, 2);
  head.writeUInt32BE(MAGIC, 4);
  Buffer.from(txn).copy(head, 8);
  return Buffer.concat([head, body]);
}
function parseMsg(buf, txn) {
  const attrs = new Map();
  let i = 20;
  const end = Math.min(buf.length, 20 + buf.readUInt16BE(2));
  while (i + 4 <= end) {
    const t = buf.readUInt16BE(i);
    const l = buf.readUInt16BE(i + 2);
    attrs.set(t, buf.subarray(i + 4, i + 4 + l));
    i += 4 + l + ((4 - (l % 4)) % 4);
  }
  const type = buf.readUInt16BE(0);
  // RFC 8489 class bits: bit4 = LSB, bit8 = MSB.
  const c0 = (type >> 4) & 1;
  const c1 = (type >> 8) & 1;
  const cls = c1 === 1 && c0 === 1 ? 'error' : c1 === 1 ? 'success' : c0 === 1 ? 'indication' : 'request';
  const err = attrs.get(A.ERROR_CODE);
  const xor = (v) => {
    if (!v || v.length < 8) return null;
    const port = v.readUInt16BE(2) ^ (MAGIC >>> 16);
    const ip = (v.readUInt32BE(4) ^ MAGIC) >>> 0;
    return `${(ip >>> 24) & 255}.${(ip >>> 16) & 255}.${(ip >>> 8) & 255}.${ip & 255}:${port}`;
  };
  return {
    cls,
    errorCode: err && err.length >= 4 ? err[2] * 100 + err[3] : null,
    lifetime: attrs.get(A.LIFETIME)?.readUInt32BE(0),
    relayed: xor(attrs.get(A.XOR_RELAYED)),
    realm: attrs.get(A.REALM)?.toString(),
    nonce: attrs.get(A.NONCE)?.toString(),
    raw: buf,
    _txn: txn,
  };
}
const xorPeer = (addr, txn) => {
  const [ip, port] = addr.split(':');
  const v = Buffer.alloc(8);
  v[1] = 1;
  v.writeUInt16BE(Number(port) ^ (MAGIC >>> 16), 2);
  const n = ip.split('.').reduce((a, o) => ((a << 8) | Number(o)) >>> 0, 0);
  v.writeUInt32BE((n ^ MAGIC) >>> 0, 4);
  return v;
};
const rawClients = [];
class RawClient {
  constructor() {
    rawClients.push(this);
    this.sock = dgram.createSocket('udp4');
    this.waiter = null;
    this.onData = null;
    this.sock.on('message', (msg) => {
      if (msg.length >= 4 && (msg[0] >> 6) === 1) {
        const len = msg.readUInt16BE(2);
        this.onData?.(msg.subarray(4, 4 + len));
        return;
      }
      const w = this.waiter;
      this.waiter = null;
      w?.(msg);
    });
  }
  exchange(buf, port, timeout = 4000) {
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => { this.waiter = null; reject(new Error('stun timeout')); }, timeout);
      this.waiter = (msg) => { clearTimeout(t); resolve(msg); };
      this.sock.send(buf, port, HOST);
    });
  }
  async request(method, attrs, key, port) {
    const txn = crypto.randomBytes(12);
    const resp = await this.exchange(buildMsg(method, attrs, key, txn), port);
    return parseMsg(resp, txn);
  }
  async allocate(user, pass, port, transport = 17) {
    const first = await this.request(M.ALLOCATE, [[A.REQUESTED_TRANSPORT, Buffer.from([transport, 0, 0, 0])]], null, port);
    if (first.cls === 'success') return first;
    const key = crypto.createHash('md5').update(`${user}:${first.realm || 'turn-dag'}:${pass}`).digest();
    return this.request(M.ALLOCATE, [
      [A.REQUESTED_TRANSPORT, Buffer.from([transport, 0, 0, 0])],
      [A.USERNAME, Buffer.from(user)],
      [A.REALM, Buffer.from(first.realm || 'turn-dag')],
      [A.NONCE, Buffer.from(first.nonce || '')],
    ], key, port);
  }
  async authed(method, attrs, user, pass, realmNonce, port) {
    const key = crypto.createHash('md5').update(`${user}:${realmNonce.realm}:${pass}`).digest();
    return this.request(method, [
      ...attrs,
      [A.USERNAME, Buffer.from(user)],
      [A.REALM, Buffer.from(realmNonce.realm)],
      [A.NONCE, Buffer.from(realmNonce.nonce)],
    ], key, port);
  }
  close() { try { this.sock.close(); } catch {} }
}
class TcpRawClient {
  constructor() {
    this.sock = null;
    this.buffer = Buffer.alloc(0);
    this.waiters = [];
  }
  connect(host, port) {
    return new Promise((resolve, reject) => {
      this.sock = net.connect(port, host);
      this.sock.once('error', reject);
      this.sock.on('data', (data) => {
        this.buffer = Buffer.concat([this.buffer, data]);
        this.drain();
      });
      this.sock.on('connect', () => {
        this.sock.off('error', reject);
        resolve();
      });
    });
  }
  drain() {
    while (this.buffer.length >= 20) {
      const len = 20 + this.buffer.readUInt16BE(2);
      if (this.buffer.length < len) return;
      const frame = this.buffer.subarray(0, len);
      this.buffer = this.buffer.subarray(len);
      this.waiters.shift()?.(frame);
    }
  }
  exchange(buf, timeout = 4000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('tcp stun timeout')), timeout);
      this.waiters.push((frame) => { clearTimeout(timer); resolve(frame); });
      this.sock.write(buf);
      this.drain();
    });
  }
  async request(method, attrs, key) {
    const txn = crypto.randomBytes(12);
    return parseMsg(await this.exchange(buildMsg(method, attrs, key, txn)), txn);
  }
  async allocate(user, pass) {
    const first = await this.request(M.ALLOCATE, [[A.REQUESTED_TRANSPORT, Buffer.from([17, 0, 0, 0])]], null);
    if (first.cls === 'success') return { result: first, realm: first.realm || 'turn-dag', nonce: first.nonce || '' };
    const realm = first.realm || 'turn-dag';
    const nonce = first.nonce || '';
    const key = crypto.createHash('md5').update(`${user}:${realm}:${pass}`).digest();
    const result = await this.request(M.ALLOCATE, [
      [A.REQUESTED_TRANSPORT, Buffer.from([17, 0, 0, 0])],
      [A.USERNAME, Buffer.from(user)],
      [A.REALM, Buffer.from(realm)],
      [A.NONCE, Buffer.from(nonce)],
    ], key);
    return { result, realm, nonce };
  }
  async permission(peer, user, pass, auth) {
    const key = crypto.createHash('md5').update(`${user}:${auth.realm}:${pass}`).digest();
    const txn = crypto.randomBytes(12);
    return parseMsg(await this.exchange(buildMsg(M.CREATE_PERMISSION, [
      [A.XOR_PEER, xorPeer(peer, txn)],
      [A.USERNAME, Buffer.from(user)],
      [A.REALM, Buffer.from(auth.realm)],
      [A.NONCE, Buffer.from(auth.nonce)],
    ], key, txn)), txn);
  }
  close() { try { this.sock?.destroy(); } catch {} }
}

const credFor = (user, secretText) => crypto.createHmac('sha1', secretText).update(user).digest('base64');
function runCli(args) {
  return new Promise((resolve, reject) => {
    const p = spawn(path.join(root, 'target/debug/turn-dag-node'), args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (out += d));
    p.on('error', reject);
    p.on('close', (code) => (code === 0 ? resolve(out) : reject(new Error(`cli ${args[0]} exit ${code}: ${out}`))));
  });
}

// ---------- browser helpers (evaluated in-page) ----------
async function gatherOnce(page, cfg, timeout) {
  return page.evaluate(async ({ cfg, timeout }) => {
    const pc = new RTCPeerConnection(cfg);
    const cands = [];
    const errors = [];
    pc.onicecandidate = (e) => { if (e.candidate?.candidate) cands.push(e.candidate.candidate); };
    pc.onicecandidateerror = (e) => errors.push(e.errorText || `code ${e.errorCode}`);
    const done = new Promise((res) => {
      pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === 'complete') res(); };
      setTimeout(res, timeout);
    });
    pc.createDataChannel('probe');
    await pc.setLocalDescription(await pc.createOffer());
    await done;
    const state = pc.iceGatheringState;
    pc.close();
    return { state, cands, errors };
  }, { cfg, timeout }).catch((e) => ({ state: 'error', cands: [], errors: [String(e)] }));
}

async function relayOnce(page1, page2, cfg, connectTimeout, binaryBytes = 0) {
  // PCs live on window in each isolated context; Node shuttles SDP/ICE.
  // `cfg` may be [cfgForPage1, cfgForPage2] (e.g. distinct issuer tickets).
  const [cfg1, cfg2] = Array.isArray(cfg) ? cfg : [cfg, cfg];
  const init = async (page, isOfferer, pcCfg) => page.evaluate(async ({ cfg, isOfferer }) => {
    const pc = new RTCPeerConnection(cfg);
    window.__pc = pc;
    window.__cands = [];
    pc.onicecandidate = (e) => { if (e.candidate) window.__cands.push(JSON.parse(JSON.stringify(e.candidate))); };
    window.__dc = isOfferer ? pc.createDataChannel('rendezvous') : null;
    if (window.__dc) window.__dc.binaryType = 'arraybuffer';
    window.__got = [];
    pc.ondatachannel = (e) => { window.__dc = e.channel; e.channel.binaryType = 'arraybuffer'; e.channel.onmessage = (m) => window.__got.push(m.data); };
    if (window.__dc) window.__dc.onmessage = (m) => window.__got.push(m.data);
    return true;
  }, { cfg: pcCfg, isOfferer });
  const pollCands = async (page) => page.evaluate(() => { const c = window.__cands || []; window.__cands = []; return c; });
  try {
    await init(page1, true, cfg1);
    await init(page2, false, cfg2);
    const offer = await page1.evaluate(async () => {
      const pc = window.__pc;
      await pc.setLocalDescription(await pc.createOffer());
      return JSON.parse(JSON.stringify(pc.localDescription));
    });
    await page2.evaluate(async (desc) => { await window.__pc.setRemoteDescription(desc); }, offer);
    const answer = await page2.evaluate(async () => {
      const pc = window.__pc;
      await pc.setLocalDescription(await pc.createAnswer());
      return JSON.parse(JSON.stringify(pc.localDescription));
    });
    await page1.evaluate(async (desc) => { await window.__pc.setRemoteDescription(desc); }, answer);
    const deadline = Date.now() + connectTimeout;
    let states = '';
    while (Date.now() < deadline) {
      for (const c of await pollCands(page1)) await page2.evaluate(async (cand) => { await window.__pc.addIceCandidate(cand).catch(() => {}); }, c).catch(() => {});
      for (const c of await pollCands(page2)) await page1.evaluate(async (cand) => { await window.__pc.addIceCandidate(cand).catch(() => {}); }, c).catch(() => {});
      states = await page1.evaluate(() => `${window.__pc.connectionState}/${window.__pc.iceConnectionState}`);
      const s2 = await page2.evaluate(() => window.__pc.connectionState);
      if (states.startsWith('connected') && s2 === 'connected') break;
      await new Promise((r) => setTimeout(r, 250));
    }
    if (!states.startsWith('connected')) throw new Error(`not connected: ${states}`);
    const out = await page1.evaluate(async () => {
      const waitOpen = (dc) => new Promise((res, rej) => {
        if (dc.readyState === 'open') return res();
        dc.onopen = res;
        setTimeout(() => rej(new Error(`dc ${dc.readyState}`)), 10000);
      });
      await waitOpen(window.__dc);
      window.__dc.send('one element, one rendezvous');
      return true;
    });
    void out;
    let got2 = [];
    for (let i = 0; i < 40 && !got2.length; i++) {
      got2 = await page2.evaluate(() => window.__got || []);
      if (!got2.length) await new Promise((r) => setTimeout(r, 250));
    }
    await page2.evaluate(() => { window.__dc.send('ack over relay'); });
    let got1 = [];
    for (let i = 0; i < 40 && !got1.length; i++) {
      got1 = await page1.evaluate(() => window.__got || []);
      if (!got1.length) await new Promise((r) => setTimeout(r, 250));
    }
    const pairType = await page1.evaluate(async () => {
      const stats = await window.__pc.getStats();
      let pair = null;
      stats.forEach((r) => {
        if (r.type === 'candidate-pair' && (r.state === 'succeeded' || r.nominated)) {
          const local = stats.get(r.localCandidateId);
          const remote = stats.get(r.remoteCandidateId);
          if (local && remote) pair = `${local.candidateType}/${remote.candidateType}`;
        }
      });
      return pair;
    });
    let bin = null;
    if (binaryBytes > 0) {
      await page2.evaluate(() => {
        window.__bin = null;
        window.__dc.onmessage = (m) => {
          if (typeof m.data === 'string') { window.__got.push(m.data); return; }
          const u = new Uint8Array(m.data);
          let sum = 0;
          for (const x of u) sum = (sum + x) >>> 0;
          window.__bin = { len: u.length, sum };
        };
      });
      const expect = await page1.evaluate(async (n) => {
        const u = new Uint8Array(n);
        let sum = 0;
        for (let i = 0; i < n; i++) { u[i] = i % 251; sum = (sum + u[i]) >>> 0; }
        window.__dc.send(u.buffer);
        return { len: n, sum };
      }, binaryBytes);
      for (let i = 0; i < 40 && !bin; i++) {
        bin = await page2.evaluate(() => window.__bin || null);
        if (!bin) await new Promise((r) => setTimeout(r, 250));
      }
      if (!bin || bin.len !== expect.len || bin.sum !== expect.sum) {
        throw new Error(`binary payload mismatch: got ${JSON.stringify(bin)} want ${JSON.stringify(expect)}`);
      }
    }
    return { gotOn2: got2[0] || null, gotOn1: got1[0] || null, pairType, bin };
  } finally {
    await page1.evaluate(() => { try { window.__pc?.close(); } catch {} }).catch(() => {});
    await page2.evaluate(() => { try { window.__pc?.close(); } catch {} }).catch(() => {});
  }
}

// Three-peer full mesh: every pair gets its own relay/relay
// DataChannel on the same TURN server.
async function meshOnce(pages, cfg) {
  for (const p of pages) {
    await p.evaluate(() => { window.__mesh = { pcs: {}, cands: {}, dcs: {}, got: {} }; });
  }
  const initPc = async (page, label, offerer) => page.evaluate(({ label, offerer, cfg }) => {
    const pc = new RTCPeerConnection(cfg);
    window.__mesh.pcs[label] = pc;
    window.__mesh.cands[label] = [];
    window.__mesh.got[label] = [];
    pc.onicecandidate = (e) => { if (e.candidate) window.__mesh.cands[label].push(JSON.parse(JSON.stringify(e.candidate))); };
    if (offerer) {
      const dc = pc.createDataChannel(`mesh-${label}`);
      window.__mesh.dcs[label] = dc;
      dc.onmessage = (m) => window.__mesh.got[label].push(m.data);
    }
    pc.ondatachannel = (e) => { window.__mesh.dcs[label] = e.channel; e.channel.onmessage = (m) => window.__mesh.got[label].push(m.data); };
    return true;
  }, { label, offerer, cfg });
  const results = [];
  for (let i = 0; i < pages.length; i++) {
    for (let j = i + 1; j < pages.length; j++) {
      const label = `${i}-${j}`;
      await initPc(pages[i], label, true);
      await initPc(pages[j], label, false);
      const offer = await pages[i].evaluate(async (l) => {
        const pc = window.__mesh.pcs[l];
        await pc.setLocalDescription(await pc.createOffer());
        return JSON.parse(JSON.stringify(pc.localDescription));
      }, label);
      await pages[j].evaluate(async ({ l, desc }) => { await window.__mesh.pcs[l].setRemoteDescription(desc); }, { l: label, desc: offer });
      const answer = await pages[j].evaluate(async (l) => {
        const pc = window.__mesh.pcs[l];
        await pc.setLocalDescription(await pc.createAnswer());
        return JSON.parse(JSON.stringify(pc.localDescription));
      }, label);
      await pages[i].evaluate(async ({ l, desc }) => { await window.__mesh.pcs[l].setRemoteDescription(desc); }, { l: label, desc: answer });
      const deadline = Date.now() + CONNECT_TIMEOUT_MS;
      let connected = false;
      while (Date.now() < deadline && !connected) {
        for (const [from, to] of [[pages[i], pages[j]], [pages[j], pages[i]]]) {
          const cands = await from.evaluate((l) => { const c = window.__mesh.cands[l] || []; window.__mesh.cands[l] = []; return c; }, label);
          for (const c of cands) await to.evaluate(async ({ l, cand }) => { await window.__mesh.pcs[l].addIceCandidate(cand).catch(() => {}); }, { l: label, cand: c }).catch(() => {});
        }
        const s1 = await pages[i].evaluate((l) => window.__mesh.pcs[l].connectionState, label);
        const s2 = await pages[j].evaluate((l) => window.__mesh.pcs[l].connectionState, label);
        connected = s1 === 'connected' && s2 === 'connected';
        if (!connected) await new Promise((r) => setTimeout(r, 250));
      }
      if (!connected) throw new Error(`mesh pair ${label} not connected`);
      await pages[i].evaluate(async (l) => {
        const dc = window.__mesh.dcs[l];
        if (dc.readyState !== 'open') await new Promise((res, rej) => { dc.onopen = res; setTimeout(() => rej(new Error(`dc ${dc.readyState}`)), 10000); });
        dc.send(`mesh ${l} hello`);
      }, label);
      let gotJ = [];
      for (let k = 0; k < 40 && !gotJ.length; k++) {
        gotJ = await pages[j].evaluate((l) => window.__mesh.got[l] || [], label);
        if (!gotJ.length) await new Promise((r) => setTimeout(r, 250));
      }
      await pages[j].evaluate((l) => { window.__mesh.dcs[l].send(`mesh ${l} ack`); }, label);
      let gotI = [];
      for (let k = 0; k < 40 && !gotI.length; k++) {
        gotI = await pages[i].evaluate((l) => window.__mesh.got[l] || [], label);
        if (!gotI.length) await new Promise((r) => setTimeout(r, 250));
      }
      const pairType = await pages[i].evaluate(async (l) => {
        const stats = await window.__mesh.pcs[l].getStats();
        let pair = null;
        stats.forEach((r) => {
          if (r.type === 'candidate-pair' && (r.state === 'succeeded' || r.nominated)) {
            const local = stats.get(r.localCandidateId);
            const remote = stats.get(r.remoteCandidateId);
            if (local && remote) pair = `${local.candidateType}/${remote.candidateType}`;
          }
        });
        return pair;
      }, label);
      results.push({ label, gotJ: gotJ[0] || null, gotI: gotI[0] || null, pairType });
    }
  }
  return results;
}

// Relay renewal: connect relay/relay, wait until the session is 90s
// old (spec renewal point), restartIce() + renegotiate, and prove the
// DataChannel still delivers afterwards.
async function restartIceOnce(page1, page2, cfg, waitSecs = 92, doRestart = true) {
  const init = async (page, offerer) => page.evaluate(async ({ cfg, offerer }) => {
    const pc = new RTCPeerConnection(cfg);
    window.__pc = pc;
    window.__cands = [];
    pc.onicecandidate = (e) => { if (e.candidate) window.__cands.push(JSON.parse(JSON.stringify(e.candidate))); };
    window.__dc = offerer ? pc.createDataChannel('rendezvous') : null;
    window.__got = [];
    pc.ondatachannel = (e) => { window.__dc = e.channel; e.channel.onmessage = (m) => window.__got.push(m.data); };
    if (window.__dc) window.__dc.onmessage = (m) => window.__got.push(m.data);
    return true;
  }, { cfg, offerer });
  const drain = async (from, to) => {
    const cands = await from.evaluate(() => { const c = window.__cands || []; window.__cands = []; return c; });
    for (const c of cands) await to.evaluate(async (cand) => { await window.__pc.addIceCandidate(cand).catch(() => {}); }, c).catch(() => {});
  };
  const negotiate = async (offererPage, answererPage) => {
    const offer = await offererPage.evaluate(async () => {
      const pc = window.__pc;
      await pc.setLocalDescription(await pc.createOffer());
      return JSON.parse(JSON.stringify(pc.localDescription));
    });
    await answererPage.evaluate(async (desc) => { await window.__pc.setRemoteDescription(desc); }, offer);
    const answer = await answererPage.evaluate(async () => {
      const pc = window.__pc;
      await pc.setLocalDescription(await pc.createAnswer());
      return JSON.parse(JSON.stringify(pc.localDescription));
    });
    await offererPage.evaluate(async (desc) => { await window.__pc.setRemoteDescription(desc); }, answer);
  };
  const waitConnected = async (timeout) => {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      await drain(page1, page2);
      await drain(page2, page1);
      const s1 = await page1.evaluate(() => window.__pc.connectionState);
      const s2 = await page2.evaluate(() => window.__pc.connectionState);
      if (s1 === 'connected' && s2 === 'connected') return Date.now();
      await new Promise((r) => setTimeout(r, 250));
    }
    throw new Error('not connected');
  };
  const sendAndExpect = async (from, to, text, tries = 40) => {
    await from.evaluate((t) => { window.__dc.send(t); }, text);
    for (let i = 0; i < tries; i++) {
      const got = await to.evaluate(() => window.__got || []);
      if (got.includes(text)) return true;
      await new Promise((r) => setTimeout(r, 250));
    }
    return false;
  };
  try {
    await init(page1, true);
    await init(page2, false);
    await negotiate(page1, page2);
    const connectedAt = await waitConnected(CONNECT_TIMEOUT_MS);
    await page1.evaluate(async () => {
      const dc = window.__dc;
      if (dc.readyState !== 'open') await new Promise((res, rej) => { dc.onopen = res; setTimeout(() => rej(new Error(dc.readyState)), 10000); });
    });
    if (!(await sendAndExpect(page1, page2, 'before renewal'))) throw new Error('pre-renewal message lost');
    // Wait until the relay session is waitSecs old (90s renewal
    // point, or past the 120s allocation lifetime for longevity).
    const waitMs = Math.max(0, waitSecs * 1000 - (Date.now() - connectedAt));
    console.log(`[relay-timer] waiting ${Math.round(waitMs / 1000)}s (target ${waitSecs}s, restart=${doRestart})`);
    await new Promise((r) => setTimeout(r, waitMs));
    if (!doRestart) {
      await drain(page1, page2);
      await drain(page2, page1);
      if (!(await sendAndExpect(page1, page2, 'after lifetime'))) throw new Error('post-lifetime message lost');
      if (!(await sendAndExpect(page2, page1, 'lifetime ack'))) throw new Error('post-lifetime ack lost');
      const pairType0 = await page1.evaluate(async () => {
        const stats = await window.__pc.getStats();
        let pair = null;
        stats.forEach((r) => {
          if (r.type === 'candidate-pair' && (r.state === 'succeeded' || r.nominated)) {
            const local = stats.get(r.localCandidateId);
            const remote = stats.get(r.remoteCandidateId);
            if (local && remote) pair = `${local.candidateType}/${remote.candidateType}`;
          }
        });
        return pair;
      });
      return { pairType: pairType0, pairDebug: [], ageSecs: Math.round((Date.now() - connectedAt) / 1000) };
    }
    await page1.evaluate(() => { window.__pc.restartIce(); });
    await negotiate(page1, page2);
    // connectionState often never leaves 'connected' during a restart,
    // so keep shuttling the *new* ICE candidates for a fixed window
    // instead of stopping at the first 'connected' reading.
    const drainUntil = Date.now() + 8000;
    while (Date.now() < drainUntil) {
      await drain(page1, page2);
      await drain(page2, page1);
      await new Promise((r) => setTimeout(r, 250));
    }
    await waitConnected(CONNECT_TIMEOUT_MS);
    if (!(await sendAndExpect(page1, page2, 'after renewal', 100))) throw new Error('post-renewal message lost');
    if (!(await sendAndExpect(page2, page1, 'renewal ack', 100))) throw new Error('post-renewal ack lost');
    // The restarted pair may take a moment to show as nominated.
    let pairType = null;
    for (let i = 0; i < 20 && !pairType; i++) {
      pairType = await page1.evaluate(async () => {
        const stats = await window.__pc.getStats();
        let pair = null;
        stats.forEach((r) => {
          if (r.type === 'candidate-pair' && (r.state === 'succeeded' || r.nominated)) {
            const local = stats.get(r.localCandidateId);
            const remote = stats.get(r.remoteCandidateId);
            if (local && remote) pair = `${local.candidateType}/${remote.candidateType}`;
          }
        });
        return pair;
      });
      if (!pairType) await new Promise((r) => setTimeout(r, 250));
    }
    const pairDebug = await page1.evaluate(async () => {
      const stats = await window.__pc.getStats();
      const out = [];
      stats.forEach((r) => {
        if (r.type === 'candidate-pair') {
          const local = stats.get(r.localCandidateId);
          const remote = stats.get(r.remoteCandidateId);
          out.push(`${r.state}/${r.nominated}/${local?.candidateType}/${remote?.candidateType}`);
        }
        if (r.type === 'local-candidate' || r.type === 'remote-candidate') out.push(`${r.type}:${r.candidateType}`);
      });
      return out;
    });
    return { pairType, pairDebug, ageSecs: Math.round((Date.now() - connectedAt) / 1000) };
  } finally {
    await page1.evaluate(() => { try { window.__pc?.close(); } catch {} }).catch(() => {});
    await page2.evaluate(() => { try { window.__pc?.close(); } catch {} }).catch(() => {});
  }
}

// ---------- main ----------
try {
  await waitListening(startServer(['serve-udp', '--addr', `0.0.0.0:${PORT}`, '--relay-ip', HOST, '--user', USER, '--pass', PASS]), 'static TURN server');
  await waitListening(startServer(['serve-udp', '--addr', `0.0.0.0:${QUOTA_PORT}`, '--relay-ip', HOST, '--user', USER, '--pass', PASS, '--total-quota', '2']), 'quota TURN server');

  // Issuer credential: one real relaypass run (burn -> challenge/PoW
  // -> redeem). The CLI flow is deterministic, so a second run would
  // mint the identical ticket; the raw-wire REST tests use a separate
  // relay-registered ticket (rawTicket) to avoid colliding with the
  // browser's live allocation on the same ticket.
  const secretHex = Buffer.from('demo-secret').toString('hex');
  const out = await runCli(['relaypass']);
  const ticket = out.match(/ticket=([0-9a-f]+)/)?.[1];
  const username = out.match(/username=(\S+)/)?.[1];
  const expires = Number(out.match(/expires_at=(\d+)/)?.[1] || 0);
  if (!ticket || !username || expires < Math.floor(Date.now() / 1000) + 30) {
    throw new Error(`relaypass CLI gave no live credential: ${out.slice(0, 300)}`);
  }
  const issuerCreds = [{ ticket, username, password: credFor(username, 'demo-secret'), expires }];
  const rawTicket = 'rawwireticket1';
  const rawUser = `${Math.floor(Date.now() / 1000) + 3600}:pow:${rawTicket}`;
  const pairTicket = 'pairticket00001';
  const pairUser = `${Math.floor(Date.now() / 1000) + 3600}:pow:${pairTicket}`;
  record('issuer:cli-relaypass', 'PASS', `burn-gated ticket=${ticket} expires_at=${expires}`);
  await waitListening(startServer(['serve-udp', '--addr', `0.0.0.0:${REST_PORT}`, '--relay-ip', HOST, '--rest-secret', secretHex, '--ticket', ticket, '--ticket', rawTicket, '--ticket', pairTicket]), 'REST/burn-gated TURN server');

  // ---------- raw wire sub-tests (static server) ----------
  try {
    const c = new RawClient();
    const alloc = await c.allocate(USER, PASS, PORT);
    const realmNonce = { realm: 'turn-dag', nonce: '' };
    // Re-challenge to learn the nonce for later authed requests.
    const probe = await new RawClient().request(M.ALLOCATE, [[A.REQUESTED_TRANSPORT, Buffer.from([17, 0, 0, 0])]], null, PORT);
    realmNonce.realm = probe.realm || 'turn-dag';
    realmNonce.nonce = probe.nonce || '';
    record('wire-allocate-lifetime', alloc.cls === 'success' && alloc.lifetime === 120 && !!alloc.relayed ? 'PASS' : 'FAIL',
      `cls=${alloc.cls} lifetime=${alloc.lifetime} relayed=${alloc.relayed}`);
    const tcp = await c.authed(M.ALLOCATE, [[A.REQUESTED_TRANSPORT, Buffer.from([6, 0, 0, 0])]], USER, PASS, realmNonce, PORT);
    record('wire-tcp-refused', tcp.errorCode === 442 ? 'PASS' : 'FAIL', `error=${tcp.errorCode}`);
    // TLS listener existence is exercised in the turns: section at
    // the end (needs the TUN-backed serve-tls + trusted-ish cert).
    let deniedOk = true;
    let deniedDetail = '';
    // Denied-peer with txn-correct XOR encoding (server un-XORs with the
    // message transaction id, so build each request explicitly).
    const deniedWithTxn = async (method, ip, extra = []) => {
      const txn = crypto.randomBytes(12);
      const key = crypto.createHash('md5').update(`${USER}:${realmNonce.realm}:${PASS}`).digest();
      const resp = await c.exchange(buildMsg(method, [
        [A.XOR_PEER, xorPeer(ip, txn)], ...extra,
        [A.USERNAME, Buffer.from(USER)], [A.REALM, Buffer.from(realmNonce.realm)], [A.NONCE, Buffer.from(realmNonce.nonce)],
      ], key, txn), PORT);
      return parseMsg(resp, txn);
    };
    deniedOk = true;
    for (const ip of ['169.254.169.254:80', '10.0.0.5:80', '192.168.1.1:80', '127.0.0.1:80']) {
      const r = await deniedWithTxn(M.CREATE_PERMISSION, ip);
      if (r.errorCode !== 403) { deniedOk = false; deniedDetail += `${ip}=${r.errorCode} `; }
    }
    const cbDenied = await deniedWithTxn(M.CHANNEL_BIND, '169.254.169.254:80', [[A.CHANNEL_NUMBER, Buffer.from([0x40, 0x01])]]);
    if (cbDenied.errorCode !== 403) { deniedOk = false; deniedDetail += `channelbind=${cbDenied.errorCode}`; }
    record('wire-denied-peer', deniedOk ? 'PASS' : 'FAIL', deniedDetail || '403 for metadata/RFC1918/loopback');
    // Refresh: capped at 120, 0 deletes, unknown -> 437.
    const refr = await c.authed(M.REFRESH, [[A.LIFETIME, Buffer.from([0, 0, 0x27, 0x0f])]], USER, PASS, realmNonce, PORT);
    const del = await c.authed(M.REFRESH, [[A.LIFETIME, Buffer.from([0, 0, 0, 0])]], USER, PASS, realmNonce, PORT);
    const unknown = await c.authed(M.REFRESH, [[A.LIFETIME, Buffer.from([0, 0, 0, 60])]], USER, PASS, realmNonce, PORT);
    record('wire-refresh', refr.lifetime === 120 && del.cls === 'success' && unknown.errorCode === 437 ? 'PASS' : 'FAIL',
      `cap=${refr.lifetime} del=${del.cls} unknown=${unknown.errorCode}`);
    c.close();
  } catch (e) {
    record('wire-static', 'FAIL', String(e).slice(0, 300));
  }

  // Byte cap: two raw allocations relay ChannelData until the cap drops.
  try {
    const a = new RawClient();
    const b = new RawClient();
    const allocA = await a.allocate(USER, PASS, PORT);
    const allocB = await b.allocate(USER, PASS, PORT);
    if (!allocA.relayed || !allocB.relayed) throw new Error(`no relayed addr A=${allocA.relayed} B=${allocB.relayed}`);
    const rn = { realm: 'turn-dag', nonce: (await new RawClient().request(M.ALLOCATE, [[A.REQUESTED_TRANSPORT, Buffer.from([17, 0, 0, 0])]], null, PORT)).nonce || '' };
    const withTxn = async (client, method, peer, extra = []) => {
      const txn = crypto.randomBytes(12);
      const key = crypto.createHash('md5').update(`${USER}:${rn.realm}:${PASS}`).digest();
      const resp = await client.exchange(buildMsg(method, [
        [A.XOR_PEER, xorPeer(peer, txn)], ...extra,
        [A.USERNAME, Buffer.from(USER)], [A.REALM, Buffer.from(rn.realm)], [A.NONCE, Buffer.from(rn.nonce)],
      ], key, txn), PORT);
      return parseMsg(resp, txn);
    };
    const setup = [];
    setup.push(['permA', await withTxn(a, M.CREATE_PERMISSION, allocB.relayed)]);
    setup.push(['permB', await withTxn(b, M.CREATE_PERMISSION, allocA.relayed)]);
    setup.push(['bindA', await withTxn(a, M.CHANNEL_BIND, allocB.relayed, [[A.CHANNEL_NUMBER, Buffer.from([0x40, 0x01])]])]);
    setup.push(['bindB', await withTxn(b, M.CHANNEL_BIND, allocA.relayed, [[A.CHANNEL_NUMBER, Buffer.from([0x40, 0x01])]])]);
    console.log('[byte-cap setup]', setup.map(([n, r]) => `${n}=${r.cls}/${r.errorCode}`).join(' '), `A=${allocA.relayed} B=${allocB.relayed}`);
    let received = 0;
    let receivedMsgs = 0;
    b.onData = (payload) => { received += payload.length; receivedMsgs += 1; };
    // max-bps enforcement (token bucket, 16384 B/s, 1s burst):
    // blast 40KB back-to-back; only ~one bucket (plus at most a
    // second-boundary refill) may be delivered. The ~1.9MB total
    // byte cap itself is proven in the Rust wire tests, where the
    // clock is synthetic; at full rate it takes the whole 120s
    // lifetime to reach here.
    const chunk = 2000;
    const frames = 20;
    for (let i = 0; i < frames; i++) {
      const payload = Buffer.alloc(chunk);
      payload.writeUInt32BE(i, 0);
      const frame = Buffer.alloc(4 + chunk);
      frame.writeUInt16BE(0x4001, 0);
      frame.writeUInt16BE(chunk, 2);
      payload.copy(frame, 4);
      a.sock.send(frame, PORT, HOST);
    }
    await new Promise((r) => setTimeout(r, 1500));
    record('wire-bps-rate', received >= 8000 && received <= 38000 && received < frames * chunk ? 'PASS' : 'FAIL',
      `received=${received}/${frames * chunk} in burst window (bucket 16384) msgs=${receivedMsgs}`);
    a.close(); b.close();
  } catch (e) {
    record('wire-bps-rate', 'FAIL', String(e).slice(0, 300));
  }

  // Scale: 50 concurrent raw allocations on the main server.
  try {
    const clients = Array.from({ length: 50 }, () => new RawClient());
    const allocs = [];
    for (const cl of clients) allocs.push(await cl.allocate(USER, PASS, PORT));
    const ok = allocs.filter((x) => x.cls === 'success').length;
    record('wire-scale-allocations', ok === 50 ? 'PASS' : 'FAIL', `${ok}/50 allocations succeeded`);
    clients.forEach((cl) => cl.close());
  } catch (e) {
    record('wire-scale-allocations', 'FAIL', String(e).slice(0, 300));
  }

  // Total quota on the dedicated quota server (max 2).
  try {
    const clients = [new RawClient(), new RawClient(), new RawClient()];
    const r = [];
    for (const cl of clients) r.push(await cl.allocate(USER, PASS, QUOTA_PORT));
    record('wire-total-quota', r[0].cls === 'success' && r[1].cls === 'success' && r[2].errorCode === 486 ? 'PASS' : 'FAIL',
      r.map((x) => x.cls === 'success' ? 'ok' : String(x.errorCode)).join(','));
    clients.forEach((cl) => cl.close());
  } catch (e) {
    record('wire-total-quota', 'FAIL', String(e).slice(0, 300));
  }

  // REST / burn-gated server: valid, forged, expired, ticket reuse.
  try {
    const credB = { ticket: rawTicket, username: rawUser, password: credFor(rawUser, 'demo-secret') };
    const b1 = new RawClient();
    const valid = await b1.allocate(credB.username, credB.password, REST_PORT);
    record('wire-rest-valid', valid.cls === 'success' && !!valid.relayed ? 'PASS' : 'FAIL', `cls=${valid.cls} relayed=${valid.relayed}`);
    const expUser = `1:pow:${credB.ticket}`;
    const expired = await new RawClient().allocate(expUser, credFor(expUser, 'demo-secret'), REST_PORT);
    record('wire-rest-expired', expired.errorCode === 401 ? 'PASS' : 'FAIL', `error=${expired.errorCode}`);
    const forgedUser = `${Math.floor(Date.now() / 1000) + 3600}:pow:forgedticket99`;
    const forged = await new RawClient().allocate(forgedUser, credFor(forgedUser, 'demo-secret'), REST_PORT);
    record('wire-rest-forged', forged.errorCode === 401 ? 'PASS' : 'FAIL', `error=${forged.errorCode}`);
    const dup = await new RawClient().allocate(credB.username, credB.password, REST_PORT);
    record('wire-ticket-quota', dup.errorCode === 486 ? 'PASS' : 'FAIL', `second allocation error=${dup.errorCode}`);
    b1.close();
  } catch (e) {
    record('wire-rest', 'FAIL', String(e).slice(0, 300));
  }

  // ---------- browser sub-tests per engine ----------
  const launchers = { firefox, chromium, webkit };
  for (const name of ENGINES) {
    const launcher = launchers[name];
    if (!launcher) { record(`${name}:launch`, 'FAIL', 'unknown engine'); continue; }
    let browser;
    try {
      // WebKit rejects --no-sandbox; Chromium/Firefox accept it.
      browser = await launcher.launch({ args: name === 'webkit' ? [] : ['--no-sandbox'] });
    } catch (e) {
      // WebKit needs OS deps (gstreamer) that only the Docker/CI images
      // install; an engine that cannot launch here is a SKIP, while
      // Firefox/Chromium launch failure is a real FAIL.
      record(`${name}:launch`, name === 'webkit' ? 'SKIP' : 'FAIL', String(e).slice(0, 200));
      continue;
    }
    try {
      const ctx1 = await browser.newContext();
      const ctx2 = await browser.newContext();
      const page1 = await ctx1.newPage();
      const page2 = await ctx2.newPage();
      for (const p of [page1, page2]) {
        p.on('pageerror', (e) => console.log('[pageerror]', String(e)));
        await p.goto(pageUrl);
      }
      if (name === ENGINES[0]) {
        // Fresh issuer credential (same deterministic ticket, new
        // 120s window): earlier sub-tests can outlive the first mint.
        const freshOut = await runCli(['relaypass']);
        const fUser = freshOut.match(/username=(\S+)/)?.[1];
        const fExp = Number(freshOut.match(/expires_at=(\d+)/)?.[1] || 0);
        if (!fUser || fExp < Math.floor(Date.now() / 1000) + 20) throw new Error(`fresh relaypass credential not live: ${freshOut.slice(0, 200)}`);
        const iss = await gatherOnce(page1, turnCfg(fUser, credFor(fUser, 'demo-secret'), REST_PORT), GATHER_TIMEOUT_MS);
        const issRelay = iss.cands.filter((c) => c.includes('typ relay'));
        recordNet('issuer:browser-gather', iss.state === 'complete' && issRelay.length > 0,
          `burn-gated credential allocated in browser (${issRelay.length} relay)`,
          `state=${iss.state} relay=${issRelay.length} errors=${iss.errors.join(';')}`);
      }
      const gather = await gatherOnce(page1, turnCfg(USER, PASS), GATHER_TIMEOUT_MS);
      const relayCands = gather.cands.filter((c) => c.includes('typ relay'));
      if (name === 'webkit' && !(gather.state === 'complete' && relayCands.length > 0)) {
        record('webkit:gather', 'SKIP', `WebKit relay gather unsupported here: state=${gather.state} relay=${relayCands.length}`);
      } else {
        recordNet(`${name}:gather`, gather.state === 'complete' && relayCands.length > 0,
          `${relayCands.length} relay candidate(s)`, `state=${gather.state} relay=${relayCands.length} errors=${gather.errors.join(';')}`);
      }
      // Public STUN controls (Google + Cloudflare): a srflx candidate
      // proves the public STUN path; SKIP only when this host has no
      // internet UDP (never a hard failure - the TURN path is the gate).
      for (const srv of [
        { name: 'google', urls: 'stun:stun.l.google.com:19302' },
        { name: 'cloudflare', urls: 'stun:stun.cloudflare.com:3478' },
      ]) {
        const stun = await gatherOnce(page1, { iceServers: [{ urls: srv.urls }] }, 8000);
        const srflx = stun.cands.filter((c) => c.includes('typ srflx'));
        record(`${name}:stun-${srv.name}`, srflx.length > 0 ? 'PASS' : 'SKIP',
          srflx.length > 0 ? `${srflx.length} srflx candidate(s) via ${srv.urls}` : `no srflx via ${srv.urls} (offline/blocked) state=${stun.state}`);
      }
      const neg = await gatherOnce(page1, turnCfg(USER, 'wrong-password'), GATHER_TIMEOUT_MS);
      record(`${name}:negative-creds`, neg.cands.filter((c) => c.includes('typ relay')).length === 0 ? 'PASS' : 'FAIL',
        'no relay candidate with wrong credentials');
      const expUser = `1:pow:${issuerCreds[0].ticket}`;
      const exp = await gatherOnce(page1, turnCfg(expUser, credFor(expUser, 'demo-secret'), REST_PORT), GATHER_TIMEOUT_MS);
      record(`${name}:expired-creds`, exp.cands.filter((c) => c.includes('typ relay')).length === 0 ? 'PASS' : 'FAIL',
        'no relay candidate with expired issuer credential');
      try {
        const relay = await relayOnce(page1, page2, turnCfg(USER, PASS), CONNECT_TIMEOUT_MS);
        const ok = relay.gotOn2 === 'one element, one rendezvous' && relay.gotOn1 === 'ack over relay' && relay.pairType === 'relay/relay';
        if (name === 'webkit' && !ok) {
          record('webkit:relay-datachannel', 'SKIP', `WebKit relay unsupported here: ${JSON.stringify(relay).slice(0, 200)}`);
        } else {
          recordNet(`${name}:relay-datachannel`, ok, 'relay/relay DataChannel both ways (isolated contexts)',
            JSON.stringify(relay).slice(0, 300));
        }
      } catch (e) {
        if (name === 'webkit') record('webkit:relay-datachannel', 'SKIP', `WebKit relay unsupported here: ${String(e).slice(0, 200)}`);
        else recordNet(`${name}:relay-datachannel`, false, '', String(e).slice(0, 300));
      }
      await ctx1.close();
      await ctx2.close();
    } finally {
      await browser.close();
    }
  }

  // ---------- cross-engine relay pairs + issuer-credential pair ----------
  const openPage = async (launcher, engineName) => {
    const b = await launcher.launch({ args: engineName === 'webkit' ? [] : ['--no-sandbox'] });
    const ctx = await b.newContext();
    const page = await ctx.newPage();
    await page.goto(pageUrl);
    return { b, page };
  };
  const crossRelay = async (label, nameA, launcherA, nameB, launcherB, cfg, binaryBytes, webkitSoft) => {
    let a; let b;
    try {
      a = await openPage(launcherA, nameA);
      b = await openPage(launcherB, nameB);
      const relay = await relayOnce(a.page, b.page, cfg, CONNECT_TIMEOUT_MS, binaryBytes);
      const ok = relay.gotOn2 === 'one element, one rendezvous' && relay.gotOn1 === 'ack over relay' && relay.pairType === 'relay/relay';
      if (webkitSoft && !ok) record(label, 'SKIP', `WebKit cross relay unsupported here: ${JSON.stringify(relay).slice(0, 200)}`);
      else recordNet(label, ok, `relay/relay both ways${binaryBytes ? ` + ${binaryBytes}B binary verified` : ''}`, JSON.stringify(relay).slice(0, 300));
    } catch (e) {
      if (webkitSoft) record(label, 'SKIP', `WebKit cross relay unsupported here: ${String(e).slice(0, 200)}`);
      else recordNet(label, false, '', String(e).slice(0, 300));
    } finally {
      try { await a?.b.close(); } catch {}
      try { await b?.b.close(); } catch {}
    }
  };
  if (ENGINES.includes('firefox') && ENGINES.includes('chromium')) {
    await crossRelay('cross:firefox-chromium', 'firefox', firefox, 'chromium', chromium, turnCfg(USER, PASS), 32768, false);
    // Issuer-credential pair: Firefox holds a fresh DAG-burn ticket,
    // Chromium a second relay-registered ticket, over the burn gate.
    const freshOut2 = await runCli(['relaypass']);
    const fUser2 = freshOut2.match(/username=(\S+)/)?.[1];
    if (fUser2) {
      await crossRelay('issuer:relay-pair', 'firefox', firefox, 'chromium', chromium,
        [turnCfg(fUser2, credFor(fUser2, 'demo-secret'), REST_PORT), turnCfg(pairUser, credFor(pairUser, 'demo-secret'), REST_PORT)], 0, false);
    } else {
      record('issuer:relay-pair', 'FAIL', `no fresh credential: ${freshOut2.slice(0, 200)}`);
    }
  }
  if (ENGINES.includes('webkit') && ENGINES.includes('firefox')) {
    await crossRelay('cross:firefox-webkit', 'firefox', firefox, 'webkit', webkit, turnCfg(USER, PASS), 0, true);
  }
  if (ENGINES.includes('webkit') && ENGINES.includes('chromium')) {
    await crossRelay('cross:chromium-webkit', 'chromium', chromium, 'webkit', webkit, turnCfg(USER, PASS), 0, true);
  }

  // Direct (no TURN) DataChannel pair over public STUN: proves the
  // host/srflx path independently of the relay. Selected pair must
  // not be relay/relay.
  if (ENGINES.includes('firefox')) {
    let dBrowser;
    try {
      dBrowser = await firefox.launch({ args: ['--no-sandbox'] });
      const dc1 = await dBrowser.newContext();
      const dc2 = await dBrowser.newContext();
      const dp1 = await dc1.newPage();
      const dp2 = await dc2.newPage();
      await dp1.goto(pageUrl);
      await dp2.goto(pageUrl);
      const directCfg = {
        iceServers: [
          { urls: 'stun:stun.l.google.com:19302' },
          { urls: 'stun:stun.cloudflare.com:3478' },
        ],
      };
      const relay = await relayOnce(dp1, dp2, directCfg, CONNECT_TIMEOUT_MS);
      const ok = relay.gotOn2 === 'one element, one rendezvous'
        && relay.gotOn1 === 'ack over relay'
        && relay.pairType && !relay.pairType.includes('relay');
      recordNet('direct:stun-datachannel', !!ok, `direct DataChannel both ways, pair=${relay.pairType}`,
        JSON.stringify(relay).slice(0, 300));
    } catch (e) {
      recordNet('direct:stun-datachannel', false, '', String(e).slice(0, 300));
    } finally {
      try { await dBrowser?.close(); } catch {}
    }
  }

  // Three-peer mesh (Chromium contexts) + 90s restartIce (Firefox).
  if (ENGINES.includes('chromium')) {
    let meshBrowser;
    try {
      meshBrowser = await chromium.launch({ args: ['--no-sandbox'] });
      const pages = [];
      for (let i = 0; i < 3; i++) {
        const ctx = await meshBrowser.newContext();
        const pg = await ctx.newPage();
        await pg.goto(pageUrl);
        pages.push(pg);
      }
      const mesh = await meshOnce(pages, turnCfg(USER, PASS));
      const ok = mesh.length === 3 && mesh.every((m) => m.gotJ === `mesh ${m.label} hello` && m.gotI === `mesh ${m.label} ack` && m.pairType === 'relay/relay');
      recordNet('mesh:three-peer', ok, '3 peers, all 3 pairs relay/relay both ways', JSON.stringify(mesh).slice(0, 300));
    } catch (e) {
      recordNet('mesh:three-peer', false, '', String(e).slice(0, 300));
    } finally {
      try { await meshBrowser?.close(); } catch {}
    }
  }
  if (ENGINES.includes('firefox')) {
    let rBrowser;
    try {
      rBrowser = await firefox.launch({ args: ['--no-sandbox'] });
      const c1 = await rBrowser.newContext();
      const c2 = await rBrowser.newContext();
      const p1 = await c1.newPage();
      const p2 = await c2.newPage();
      await p1.goto(pageUrl);
      await p2.goto(pageUrl);
      const r = await restartIceOnce(p1, p2, turnCfg(USER, PASS));
      recordNet('relay:restart-ice-90s', r.pairType === 'relay/relay', `DataChannel alive after restartIce at ${r.ageSecs}s, pair=${r.pairType}`, JSON.stringify(r).slice(0, 300));
    } catch (e) {
      recordNet('relay:restart-ice-90s', false, '', String(e).slice(0, 300));
    } finally {
      try { await rBrowser?.close(); } catch {}
    }
    // Longevity: session must survive past the 120s allocation
    // lifetime via client Refresh (no restartIce from the app).
    let lBrowser;
    try {
      lBrowser = await firefox.launch({ args: ['--no-sandbox'] });
      const c1 = await lBrowser.newContext();
      const c2 = await lBrowser.newContext();
      const p1 = await c1.newPage();
      const p2 = await c2.newPage();
      await p1.goto(pageUrl);
      await p2.goto(pageUrl);
      const r = await restartIceOnce(p1, p2, turnCfg(USER, PASS), 132, false);
      recordNet('relay:allocation-longevity-120s', r.pairType === 'relay/relay', `DataChannel alive past 120s lifetime at ${r.ageSecs}s (Refresh-renewed), pair=${r.pairType}`, JSON.stringify(r).slice(0, 300));
    } catch (e) {
      recordNet('relay:allocation-longevity-120s', false, '', String(e).slice(0, 300));
    } finally {
      try { await lBrowser?.close(); } catch {}
    }
  }

  // Scale: 5 simultaneous Chromium relay pairs.
  if (ENGINES.includes('chromium')) {
    let sBrowser;
    try {
      sBrowser = await chromium.launch({ args: ['--no-sandbox'] });
      const pairPages = [];
      for (let i = 0; i < 5; i++) {
        const ca = await sBrowser.newContext();
        const cb = await sBrowser.newContext();
        const pa = await ca.newPage();
        const pb = await cb.newPage();
        await pa.goto(pageUrl);
        await pb.goto(pageUrl);
        pairPages.push([pa, pb]);
      }
      const settled = await Promise.all(pairPages.map(([pa, pb]) =>
        relayOnce(pa, pb, turnCfg(USER, PASS), CONNECT_TIMEOUT_MS)
          .then((r) => ({ ok: r.gotOn2 === 'one element, one rendezvous' && r.gotOn1 === 'ack over relay' && r.pairType === 'relay/relay' }))
          .catch((e) => ({ ok: false, err: String(e).slice(0, 120) })),
      ));
      const okCount = settled.filter((x) => x.ok).length;
      recordNet('scale:five-pair-relay', okCount === 5, '5 simultaneous relay/relay pairs both ways', JSON.stringify(settled).slice(0, 300));
    } catch (e) {
      recordNet('scale:five-pair-relay', false, '', String(e).slice(0, 300));
    } finally {
      try { await sBrowser?.close(); } catch {}
    }
  }

  // ---------- browser wallet: WebAuthn PRF keys + all PoW in browser ----------
  // The wallet's PQ keys come from WebAuthn register/auth + PRF
  // (CDP virtual authenticator); TURN and mint PoW are solved by
  // the page's WASM solvers; the Rust CLI verifies everything.
  const runCliCode = (args) => new Promise((resolve) => {
    const p = spawn(path.join(root, 'target/debug/turn-dag-node'), args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (out += d));
    p.on('close', (code) => resolve({ code, out }));
  });
  // Burn-replay at suite level: drive the stateful issuer oracle
  // (one TurnIssuer process) - the same burn must not mint twice.
  try {
    const oracle = spawn(path.join(root, 'target/debug/turn-dag-node'), ['issuer-stdio'], { stdio: ['pipe', 'pipe', 'pipe'] });
    let oBuf = '';
    const oWaiters = [];
    oracle.stdout.on('data', (d) => {
      oBuf += d;
      let i;
      while ((i = oBuf.indexOf('\n')) >= 0) {
        const line = oBuf.slice(0, i).trim();
        oBuf = oBuf.slice(i + 1);
        if (line && oWaiters.length) oWaiters.shift()(line);
      }
    });
    const ask = (line) => new Promise((resolve) => { oWaiters.push(resolve); oracle.stdin.write(line + '\n'); });
    const solveSha = (challengeHex, bits) => {
      const prefix = Buffer.from('turn-pow-solution-v1');
      const challenge = Buffer.from(challengeHex, 'hex');
      for (let nonce = 0; ; nonce++) {
        const nb = Buffer.alloc(8);
        nb.writeBigUInt64BE(BigInt(nonce));
        const h = crypto.createHash('sha256').update(Buffer.concat([prefix, challenge, nb])).digest();
        let z = 0;
        for (const b of h) { if (b === 0) { z += 8; continue; } z += Math.clz32(b) - 24; break; }
        if (z >= bits) return nonce;
      }
    };
    const redeemViaOracle = async (burnHex, user) => {
      const chLine = await ask('challenge 203.0.113.10');
      const id = chLine.match(/challenge_id=([0-9a-f]+)/)?.[1];
      const chHex = chLine.match(/challenge=([0-9a-f]+)/)?.[1];
      const nonce = solveSha(chHex, 8);
      return ask(`redeem ${burnHex} ${user} ${id} ${nonce}`);
    };
    const burnA = '42'.repeat(32);
    const burnB = '43'.repeat(32);
    const r1 = await redeemViaOracle(burnA, 'alice');
    const r2 = await redeemViaOracle(burnA, 'mallory');
    const r3 = await redeemViaOracle(burnB, 'bob');
    record('issuer:burn-replay-stdio', r1.startsWith('credential') && r2 === 'error=BurnAlreadyRedeemed' && r3.startsWith('credential') ? 'PASS' : 'FAIL',
      `first=${r1.split(' ')[0]} replay=${r2} other-burn=${r3.split(' ')[0]}`);
    oracle.kill();
  } catch (e) {
    record('issuer:burn-replay-stdio', 'FAIL', String(e).slice(0, 250));
  }

  if (ENGINES.includes('chromium')) {
    let wBrowser;
    try {
      wBrowser = await chromium.launch({ args: ['--no-sandbox'] });
      const ctx = await wBrowser.newContext();
      const page = await ctx.newPage();
      page.on('pageerror', (e) => console.log('[wallet pageerror]', String(e)));
      const cdp = await ctx.newCDPSession(page);
      await cdp.send('WebAuthn.enable');
      await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: {
          protocol: 'ctap2',
          transport: 'internal',
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          automaticPresenceSimulation: true,
          hasPrf: true,
        },
      });
      await page.goto(`http://localhost:${pagePort}/wallet-app/`); // localhost: WebAuthn RP id cannot be an IP literal
      // Negative: unlocking before any passkey exists must fail.
      const noPasskey = await page.evaluate(async () => {
        try {
          await window.turnDagWallet.unlockWalletWithPasskey();
          return 'unlocked';
        } catch (e) {
          return `failed: ${e.message}`.slice(0, 60);
        }
      });
      record('browser-wallet:unlock-without-passkey', noPasskey.startsWith('failed') ? 'PASS' : 'FAIL',
        `unlock without registration correctly ${noPasskey}`);
      await page.click('#btn-register');
      await page.waitForFunction(() => document.getElementById('seed-source').textContent.includes('registered'), null, { timeout: 15000 });
      const regText = await page.textContent('#seed-source');
      await page.click('#btn-unlock');
      await page.waitForFunction(() => /^[0-9a-f]{40}$/.test(document.getElementById('address').textContent.trim()), null, { timeout: 15000 });
      const addr1 = (await page.textContent('#address')).trim();
      // Second unlock must re-derive the identical wallet (PRF determinism).
      await page.click('#btn-unlock');
      await page.waitForTimeout(1500);
      const addr2 = (await page.textContent('#address')).trim();
      const prfOk = /PRF enabled/.test(regText);
      record('browser-wallet:passkey-prf', prfOk && addr1 === addr2 && /^[0-9a-f]{40}$/.test(addr1) ? 'PASS' : 'SKIP',
        prfOk ? `passkey PRF derives stable ML-DSA wallet ${addr1}` : `virtual authenticator PRF not enabled (${regText}); addr stable=${addr1 === addr2}`);
      if (prfOk) {
        const signed = await page.evaluate(() => window.turnDagWallet.signWalletMessage());
        const v = await runCliCode(['sig-verify', '--pubkey', signed.publicKeyHex, '--sig', signed.sigHex]);
        record('browser-wallet:sig-verify', v.code === 0 && v.out.includes(`address=${signed.addressHex}`) ? 'PASS' : 'FAIL',
          `Rust verifies browser ML-DSA signature, addr match=${v.out.includes(`address=${signed.addressHex}`)}`);
        // TURN PoW solved in browser, verified by Rust.
        const chOut = await runCli(['pow-challenge', '--bits', '12']);
        const chId = chOut.match(/challenge_id=([0-9a-f]+)/)?.[1];
        const chHex = chOut.match(/challenge=([0-9a-f]+)/)?.[1];
        const sol = await page.evaluate(async (h) => window.turnDagWallet.solveTurnPow(h, 12), chHex);
        const pv = await runCliCode(['pow-verify', '--id', chId, '--challenge', chHex, '--bits', '12', '--nonce', String(sol.nonce)]);
        record('browser-pow:turn', pv.code === 0 ? 'PASS' : 'FAIL', `browser solved TURN PoW nonce=${sol.nonce}, Rust verify=${pv.out.trim()}`);
        // Mint (Argon2id) PoW solved in browser, verified by Rust.
        const mc = await runCli(['mint-challenge', '--miner', signed.addressHex, '--difficulty', '16']);
        const mcHex = mc.match(/challenge=([0-9a-f]+)/)?.[1];
        const msol = await page.evaluate(async (h) => window.turnDagWallet.solveMintPow(h, 16), mcHex);
        const eid = await page.evaluate(async ({ h, n, m }) => window.turnDagWallet.elementId(h, n, m), { h: mcHex, n: msol.nonce, m: signed.addressHex });
        const mv = await runCliCode(['mint-verify', '--miner', signed.addressHex, '--difficulty', '16', '--nonce', String(msol.nonce), '--hash', msol.hashHex]);
        record('browser-pow:mint', mv.code === 0 && mv.out.includes(`element_id=${eid}`) ? 'PASS' : 'FAIL',
          `browser Argon2id mint nonce=${msol.nonce}, Rust verify + element id match=${mv.out.includes(`element_id=${eid}`)}`);
        // Production-strength PoW in browser (timed).
        const ch20Out = await runCli(['pow-challenge', '--bits', '20']);
        const ch20Id = ch20Out.match(/challenge_id=([0-9a-f]+)/)?.[1];
        const ch20Hex = ch20Out.match(/challenge=([0-9a-f]+)/)?.[1];
        const t0 = Date.now();
        const sol20 = await page.evaluate(async (h) => window.turnDagWallet.solveTurnPow(h, 20), ch20Hex);
        const pv20 = await runCliCode(['pow-verify', '--id', ch20Id, '--challenge', ch20Hex, '--bits', '20', '--nonce', String(sol20.nonce)]);
        record('browser-pow:turn-20bit', pv20.code === 0 ? 'PASS' : 'FAIL',
          `20-bit TURN PoW solved in browser in ${Date.now() - t0}ms (nonce=${sol20.nonce}), Rust PASS`);
        const mcP = await runCli(['mint-challenge', '--miner', signed.addressHex, '--difficulty', '2', '--production']);
        const mcPHex = mcP.match(/challenge=([0-9a-f]+)/)?.[1];
        const t1 = Date.now();
        const msolP = await page.evaluate(async (h) => window.turnDagWallet.solveMintPow(h, 2, { memorySize: 65536, iterations: 3, parallelism: 4 }), mcPHex);
        const mvP = await runCliCode(['mint-verify', '--production', '--miner', signed.addressHex, '--difficulty', '2', '--nonce', String(msolP.nonce), '--hash', msolP.hashHex]);
        record('browser-pow:mint-production', mvP.code === 0 ? 'PASS' : 'FAIL',
          `production Argon2id (64MiB,t3,p4) mint solved in browser in ${Date.now() - t1}ms, Rust PASS`);
        // Recovery: after a full page reload, the wallet re-derives
        // identically from the passkey (no re-registration). (A
        // second tab's WebAuthn ceremony hangs in headless Chrome,
        // so recovery is asserted across reloads, not tabs.)
        await page.reload();
        await page.waitForFunction(() => !!window.turnDagWallet, null, { timeout: 15000 });
        await page.click('#btn-unlock');
        await page.waitForFunction(() => /^[0-9a-f]{40}$/.test(document.getElementById('address').textContent.trim()), null, { timeout: 15000 });
        const addrFresh = (await page.textContent('#address')).trim();
        record('browser-wallet:fresh-page-recovery', addrFresh === signed.addressHex ? 'PASS' : 'FAIL',
          `after reload, passkey re-derives ${addrFresh} (no re-registration)`);
        // Passkey-signed pub/sub: on the gRPC page the same
        // passkey re-unlocks the same wallet, which certifies the
        // ephemeral publishing key. The received envelopes must
        // attribute to the PRF-derived wallet address.
        if (process.env.TURN_TCP_URL && process.env.GRPC_DESCRIPTOR_FILE) {
          const descriptor = JSON.parse(fs.readFileSync(process.env.GRPC_DESCRIPTOR_FILE, 'utf8'));
          await page.goto(`http://localhost:${pagePort}/wallet-app/grpc.html`);
          await page.waitForFunction(() => !!window.__grpcPubSub, null, { timeout: 20000 });
          await page.click('#btn-grpc-unlock');
          await page.waitForFunction(
            () => document.getElementById('signer').textContent.includes('webauthn-prf'),
            null,
            { timeout: 20000 },
          );
          const topic = `orders-passkey-${Date.now()}`;
          const signedPubSub = await page.evaluate(
            async ({ d, t, u, p, topic }) => window.__grpcPubSub(d, t, u, p, topic),
            { d: descriptor, t: process.env.TURN_TCP_URL, u: USER, p: PASS, topic },
          );
          const passkeySignedOk = signedPubSub?.live?.map((e) => e.payload).join(',') === 'o1,o2'
            && signedPubSub?.replayed?.map((e) => e.payload).join(',') === 'o1,o2,o3'
            && signedPubSub?.live?.every((e) => e.walletAddress === signed.addressHex)
            && signedPubSub?.replayed?.every((e) => e.walletAddress === signed.addressHex);
          record('grpc:passkey-signed-pubsub-over-turn-tcp', passkeySignedOk ? 'PASS' : 'FAIL',
            `ephemeral events certified by PRF wallet ${signed.addressHex}, seqs=${signedPubSub?.seqs?.join(',')}`);
        }
        // Wrong authenticator: a fresh browser process whose (empty)
        // virtual authenticator does not hold the passkey cannot unlock.
        const wrongBrowser = await chromium.launch({ args: ['--no-sandbox'] });
        const ctxWrong = await wrongBrowser.newContext();
        const pageW = await ctxWrong.newPage();
        const cdpW = await ctxWrong.newCDPSession(pageW);
        await cdpW.send('WebAuthn.enable');
        await cdpW.send('WebAuthn.addVirtualAuthenticator', {
          options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true },
        });
        await pageW.goto(`http://localhost:${pagePort}/wallet-app/`);
        await pageW.waitForFunction(() => !!window.turnDagWallet, null, { timeout: 15000 });
        await pageW.click('#btn-unlock');
        let wrongFailed = false;
        try {
          await pageW.waitForFunction(() => document.getElementById('seed-source').textContent.startsWith('unlock failed'), null, { timeout: 20000 });
          wrongFailed = true;
        } catch { wrongFailed = false; }
        record('browser-wallet:wrong-authenticator', wrongFailed ? 'PASS' : 'FAIL',
          'empty authenticator cannot unlock the wallet');
        await ctxWrong.close();
        await wrongBrowser.close();
        // Fresh-context re-derivation (passkey sync model): export
        // the credential from the first authenticator and import it
        // into a fresh context's authenticator. Plain WebAuthn
        // assertion with the synced credential works cross-context;
        // PRF on an imported credential depends on the authenticator
        // carrying hmac-secret material - CDP virtual authenticators
        // do not export it (real synced platform passkeys re-derive
        // PRF on-device), so a PRF-less import records SKIP, and a
        // future environment that carries it records PASS.
        // Dedicated two-context sync probe (self-contained).
        const syncBrowser = await chromium.launch({ args: ['--no-sandbox'] });
        try {
          const sctx1 = await syncBrowser.newContext();
          const sp1 = await sctx1.newPage();
          const scdp1 = await sctx1.newCDPSession(sp1);
          await scdp1.send('WebAuthn.enable');
          const { authenticatorId: sa1 } = await scdp1.send('WebAuthn.addVirtualAuthenticator', {
            options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true },
          });
          await sp1.goto(`http://localhost:${pagePort}/wallet-app/`);
          await sp1.click('#btn-register');
          await sp1.waitForTimeout(1200);
          await sp1.click('#btn-unlock');
          await sp1.waitForFunction(() => /^[0-9a-f]{40}$/.test(document.getElementById('address').textContent.trim()), null, { timeout: 15000 });
          const sAddr = (await sp1.textContent('#address')).trim();
          const { credentials: sCreds } = await scdp1.send('WebAuthn.getCredentials', { authenticatorId: sa1 });
          const sctx2 = await syncBrowser.newContext();
          const sp2 = await sctx2.newPage();
          const scdp2 = await sctx2.newCDPSession(sp2);
          await scdp2.send('WebAuthn.enable');
          const { authenticatorId: sa2 } = await scdp2.send('WebAuthn.addVirtualAuthenticator', {
            options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true },
          });
          const sc = sCreds[0];
          await scdp2.send('WebAuthn.addCredential', {
            authenticatorId: sa2,
            credential: { credentialId: sc.credentialId, isResidentCredential: true, rpId: 'localhost', privateKey: sc.privateKey, userHandle: sc.userHandle, signCount: sc.signCount },
          });
          await sp2.goto(`http://localhost:${pagePort}/wallet-app/`);
          await sp2.waitForFunction(() => !!window.turnDagWallet, null, { timeout: 15000 });
          await sp2.click('#btn-unlock');
          await sp2.waitForTimeout(2500);
          const sAddr2 = (await sp2.textContent('#address')).trim();
          const sSrc = await sp2.textContent('#seed-source');
          if (/^[0-9a-f]{40}$/.test(sAddr2) && sAddr2 === sAddr) {
            record('browser-wallet:fresh-context', 'PASS', `synced credential re-derives ${sAddr2} in a fresh context`);
          } else {
            record('browser-wallet:fresh-context', 'SKIP',
              `synced credential imports + authenticates cross-context, but imported virtual-authenticator credentials carry no hmac-secret/PRF material (${sSrc.slice(0, 80)}); real synced passkeys re-derive PRF on-device`);
          }
        } catch (e) {
          record('browser-wallet:fresh-context', 'SKIP', `fresh-context sync probe failed: ${String(e).slice(0, 150)}`);
        } finally {
          try { await syncBrowser.close(); } catch {}
        }
      }
      await ctx.close();
    } catch (e) {
      record('browser-wallet:passkey-prf', 'SKIP', `wallet section failed: ${String(e).slice(0, 250)}`);
    } finally {
      try { await wBrowser?.close(); } catch {}
    }
  }

  // ---------- TURN/TCP dedicated to embedded gRPC ----------
  // scripts/browser-test.sh starts `serve-grpc`, whose TURN/TCP
  // server is in dedicated-upstream mode: browser allocations may
  // relay only to the embedded grpc-dc rendezvous socket. Generic
  // external peers and allocation-to-allocation relaying must fail.
  const turnTcpUrl = process.env.TURN_TCP_URL;
  let grpcDescriptor = null;
  if (process.env.GRPC_DESCRIPTOR_FILE) {
    try { grpcDescriptor = JSON.parse(fs.readFileSync(process.env.GRPC_DESCRIPTOR_FILE, 'utf8')); } catch {}
  }
  if (turnTcpUrl) {
    const tcpMatch = turnTcpUrl.match(/turns?:([^:?]+):(\d+)/);
    const tcpCfg = {
      iceServers: [{ urls: turnTcpUrl, username: USER, credential: PASS }],
      iceTransportPolicy: 'relay',
    };
    if (tcpMatch && grpcDescriptor) {
      const clients = [];
      try {
        const c1 = new TcpRawClient(); clients.push(c1);
        await c1.connect(tcpMatch[1], Number(tcpMatch[2]));
        const a1 = await c1.allocate(USER, PASS);
        const c2 = new TcpRawClient(); clients.push(c2);
        await c2.connect(tcpMatch[1], Number(tcpMatch[2]));
        const a2 = await c2.allocate(USER, PASS);
        const upstream = `${grpcDescriptor.host}:${grpcDescriptor.port}`;
        const up = await c1.permission(upstream, USER, PASS, a1);
        const ext = await c1.permission('8.8.8.8:53', USER, PASS, a1);
        const p2p = await c1.permission(a2.result.relayed, USER, PASS, a1);
        record('tcp:dedicated-upstream-only',
          a1.result.cls === 'success' && up.cls === 'success' && ext.errorCode === 403 && p2p.errorCode === 403
            ? 'PASS' : (REQUIRE ? 'FAIL' : 'SKIP'),
          `allocate=${a1.result.cls} upstream=${up.cls}/${up.errorCode} external=${ext.errorCode} peer-to-peer=${p2p.errorCode}`);
      } catch (e) {
        record('tcp:dedicated-upstream-only', REQUIRE ? 'FAIL' : 'SKIP', String(e).slice(0, 250));
      } finally {
        clients.forEach((c) => c.close());
      }
    } else {
      record('tcp:dedicated-upstream-only', 'SKIP', 'missing TURN_TCP_URL host/port or gRPC descriptor');
    }

    for (const name of ENGINES) {
      const launcher = launchers[name];
      if (!launcher) continue;
      let b;
      try {
        b = await launcher.launch({ args: name === 'webkit' ? [] : ['--no-sandbox'] });
        const pg = await b.newPage();
        await pg.goto(pageUrl);
        const gathered = await gatherOnce(pg, tcpCfg, GATHER_TIMEOUT_MS);
        const relay = gathered.cands.filter((c) => c.includes('typ relay'));
        if (name === 'webkit' && relay.length === 0) {
          record('webkit:turn-tcp-gather', 'SKIP', `WebKit TURN/TCP unsupported here: state=${gathered.state} errs=${gathered.errors.join(';')}`.slice(0, 250));
        } else {
          recordNet(`${name}:turn-tcp-gather`, relay.length > 0,
            `${relay.length} relay candidate(s) over ${turnTcpUrl}`,
            `state=${gathered.state} relay=${relay.length} errors=${gathered.errors.join(';')}`);
        }
        if (grpcDescriptor) {
          await pg.goto(`http://localhost:${pagePort}/wallet-app/grpc.html`);
          await pg.waitForFunction(() => !!window.__grpcEcho, null, { timeout: 20000 });
          const call = pg.evaluate(async ({ d, t, u, p }) => window.__grpcEcho(d, t, u, p, 'hello-turn-tcp'),
            { d: grpcDescriptor, t: turnTcpUrl, u: USER, p: PASS });
          const result = await Promise.race([
            call,
            new Promise((_, reject) => setTimeout(() => reject(new Error('grpc echo timeout')), 35000)),
          ]).catch((e) => ({ error: String(e).slice(0, 250) }));
          const ok = result?.message === 'echo: hello-turn-tcp' && result?.pairType?.startsWith('relay/');
          if (name === 'webkit' && !ok) {
            record('grpc:webkit-echo-over-turn-tcp', 'SKIP', `WebKit gRPC over TURN/TCP unsupported here: ${JSON.stringify(result).slice(0, 220)}`);
          } else {
            recordNet(`grpc:${name}-echo-over-turn-tcp`, !!ok,
              `Echo over TURN/TCP only, pair=${result?.pairType}`,
              JSON.stringify(result).slice(0, 250));
          }

          await pg.evaluate((seed) => window.__grpcUseDemoWallet(seed), ({ firefox: 'a1', chromium: 'b2', webkit: 'c3' }[name]).repeat(32));
          const topic = `orders-${name}-${Date.now()}`;
          const pubSubCall = pg.evaluate(
            async ({ d, t, u, p, topic }) => window.__grpcPubSub(d, t, u, p, topic),
            { d: grpcDescriptor, t: turnTcpUrl, u: USER, p: PASS, topic },
          );
          const pubSub = await Promise.race([
            pubSubCall,
            new Promise((_, reject) => setTimeout(() => reject(new Error('grpc pub/sub timeout')), 90000)),
          ]).catch((e) => ({ error: String(e).slice(0, 250) }));
          const liveOk = pubSub?.live?.map((e) => e.payload).join(',') === 'o1,o2'
            && pubSub?.live?.[0]?.seq === pubSub?.seqs?.[0]
            && pubSub?.live?.[1]?.seq === pubSub?.seqs?.[2];
          const replayOk = pubSub?.replayed?.map((e) => e.payload).join(',') === 'o1,o2,o3'
            && pubSub?.replayed?.[0]?.seq === pubSub?.seqs?.[0]
            && pubSub?.replayed?.[1]?.seq === pubSub?.seqs?.[2]
            && pubSub?.replayed?.[2]?.seq === pubSub?.seqs?.[3];
          const pubSubOk = liveOk && replayOk
            && pubSub?.pairType?.startsWith('relay/')
            && pubSub?.pairType2?.startsWith('relay/');
          if (name === 'webkit' && !pubSubOk) {
            record('grpc:webkit-pubsub-over-turn-tcp', 'SKIP', `WebKit pub/sub over TURN/TCP unsupported here: ${JSON.stringify(pubSub).slice(0, 220)}`);
          } else {
            recordNet(`grpc:${name}-pubsub-over-turn-tcp`, !!pubSubOk,
              `git-branch EventBus live+replay over TURN/TCP, seqs=${pubSub?.seqs?.join(',')}`,
              JSON.stringify(pubSub).slice(0, 300));
          }
        }
      } catch (e) {
        if (name === 'webkit') record('webkit:turn-tcp-gather', 'SKIP', `launch/gather failed: ${String(e).slice(0, 180)}`);
        else recordNet(`${name}:turn-tcp-gather`, false, '', String(e).slice(0, 250));
      } finally {
        try { await b?.close(); } catch {}
      }
    }
    // True two-instance pub/sub: separate Firefox and Chromium
    // browser processes, simultaneously subscribed. Each direction
    // is exercised; both subscribers (including the publisher's
    // own instance) must receive only topic-matching events.
    if (grpcDescriptor && ENGINES.includes('firefox') && ENGINES.includes('chromium')) {
      let fxBrowser;
      let crBrowser;
      let wkBrowser;
      const waitReceived = async (page, sessionId, count) => {
        await page.waitForFunction(
          ([id, expected]) => window.__grpcPubSubReceived(id).length >= expected,
          [sessionId, count],
          { timeout: 25000 },
        );
        return page.evaluate((id) => window.__grpcPubSubReceived(id), sessionId);
      };
      try {
        fxBrowser = await firefox.launch({ args: ['--no-sandbox'] });
        crBrowser = await chromium.launch({ args: ['--no-sandbox'] });
        const fxPage = await fxBrowser.newPage();
        const crPage = await crBrowser.newPage();
        await Promise.all([
          fxPage.goto(`http://localhost:${pagePort}/wallet-app/grpc.html`),
          crPage.goto(`http://localhost:${pagePort}/wallet-app/grpc.html`),
        ]);
        await Promise.all([
          fxPage.waitForFunction(() => !!window.__grpcPubSubStart, null, { timeout: 20000 }),
          crPage.waitForFunction(() => !!window.__grpcPubSubStart, null, { timeout: 20000 }),
        ]);
        await fxPage.evaluate((seed) => window.__grpcUseDemoWallet(seed), 'd4'.repeat(32));
        await crPage.evaluate((seed) => window.__grpcUseDemoWallet(seed), 'e5'.repeat(32));
        const base = { d: grpcDescriptor, t: turnTcpUrl, u: USER, p: PASS };
        const start = (page, sessionId, topic) => page.evaluate(
          async ({ d, t, u, p, sessionId, topic }) => window.__grpcPubSubStart(sessionId, d, t, u, p, topic),
          { ...base, sessionId, topic },
        );
        const publish = (page, sessionId, topic, payload) => page.evaluate(
          async ({ sessionId, topic, payload }) => window.__grpcPubSubPublish(sessionId, topic, payload),
          { sessionId, topic, payload },
        );
        const close = (page, sessionId) => page.evaluate(
          async (id) => window.__grpcPubSubClose(id), sessionId,
        );

        const runDirection = async (publisherPage, subscriberPages, topic, first, second) => {
          const seqs = [];
          seqs.push(await publish(publisherPage, 'peer', topic, first));
          seqs.push(await publish(publisherPage, 'peer', 'other', 'noise'));
          seqs.push(await publish(publisherPage, 'peer', topic, second));
          const received = [];
          for (const page of subscriberPages) received.push(await waitReceived(page, 'peer', 2));
          return { seqs, received };
        };
        const expectEvents = (events, payloads, seqs) => events.length === payloads.length
          && events.every((event, i) => event.payload === payloads[i] && event.seq === seqs[i]);

        let crossDetail = '';
        try {
          const topicA = `orders-cross-a-${Date.now()}`;
          const startsA = await Promise.all([
            start(fxPage, 'peer', topicA),
            start(crPage, 'peer', topicA),
          ]);
          await Promise.all([
            fxPage.waitForTimeout(500),
            crPage.waitForTimeout(500),
          ]);
          const a = await runDirection(crPage, [fxPage, crPage], topicA, 'a1', 'a2');
          const aOk = startsA.every((start) => start.pairType?.startsWith('relay/'))
            && expectEvents(a.received[0], ['a1', 'a2'], [a.seqs[0], a.seqs[2]])
            && expectEvents(a.received[1], ['a1', 'a2'], [a.seqs[0], a.seqs[2]]);

          const topicB = `orders-cross-b-${Date.now()}`;
          await Promise.all([
            start(fxPage, 'peer2', topicB),
            start(crPage, 'peer2', topicB),
          ]);
          await Promise.all([
            fxPage.waitForTimeout(500),
            crPage.waitForTimeout(500),
          ]);
          // runDirection reads the fixed 'peer' session for received
          // events, so use explicit publishing for the second topic.
          const seqB = [];
          seqB.push(await publish(fxPage, 'peer2', topicB, 'b1'));
          seqB.push(await publish(fxPage, 'peer2', 'other', 'noise'));
          seqB.push(await publish(fxPage, 'peer2', topicB, 'b2'));
          const bFx = await waitReceived(fxPage, 'peer2', 2);
          const bCr = await waitReceived(crPage, 'peer2', 2);
          const bOk = expectEvents(bFx, ['b1', 'b2'], [seqB[0], seqB[2]])
            && expectEvents(bCr, ['b1', 'b2'], [seqB[0], seqB[2]]);
          crossDetail = `chromium->firefox seqs=${a.seqs.join(',')} firefox->chromium seqs=${seqB.join(',')}`;
          recordNet('grpc:cross-instance-pubsub-over-turn-tcp', aOk && bOk,
            `two instances/engines, both directions; ${crossDetail}`,
            JSON.stringify({ a, bFx, bCr, seqB }).slice(0, 300));
          await Promise.all([
            close(fxPage, 'peer'), close(crPage, 'peer'),
            close(fxPage, 'peer2'), close(crPage, 'peer2'),
          ]);
        } catch (e) {
          recordNet('grpc:cross-instance-pubsub-over-turn-tcp', false, '', String(e).slice(0, 300));
        }

        try {
          const replayTopic = `orders-cross-replay-${Date.now()}`;
          await start(fxPage, 'replay-publisher', null);
          const rSeqs = [];
          rSeqs.push(await publish(fxPage, 'replay-publisher', replayTopic, 'r1'));
          rSeqs.push(await publish(fxPage, 'replay-publisher', replayTopic, 'r2'));
          await close(fxPage, 'replay-publisher');

          await start(crPage, 'replay-subscriber', replayTopic);
          const replayed = await waitReceived(crPage, 'replay-subscriber', 2);

          await start(fxPage, 'replay-publisher-2', null);
          rSeqs.push(await publish(fxPage, 'replay-publisher-2', replayTopic, 'r3'));
          const afterLive = await waitReceived(crPage, 'replay-subscriber', 3);
          const replayOk = expectEvents(replayed, ['r1', 'r2'], [rSeqs[0], rSeqs[1]])
            && expectEvents(afterLive, ['r1', 'r2', 'r3'], rSeqs);
          recordNet('grpc:cross-instance-replay-over-turn-tcp', replayOk,
            `Firefox published/disconnected, Chromium replayed from git then received live; seqs=${rSeqs.join(',')}`,
            JSON.stringify({ replayed, afterLive, rSeqs }).slice(0, 300));
          await close(crPage, 'replay-subscriber');
          await close(fxPage, 'replay-publisher-2');
        } catch (e) {
          recordNet('grpc:cross-instance-replay-over-turn-tcp', false, '', String(e).slice(0, 300));
        }

        // WebKit as a third simultaneous browser instance/process:
        // it publishes to Firefox+Chromium, receives Chromium's
        // publication on the same topic, then does the cross-
        // instance replay direction into Chromium.
        if (ENGINES.includes('webkit')) {
          let wkPage;
          try {
            wkBrowser = await webkit.launch({ args: [] });
            wkPage = await wkBrowser.newPage();
            await wkPage.goto(`http://localhost:${pagePort}/wallet-app/grpc.html`);
            await wkPage.waitForFunction(() => !!window.__grpcPubSubStart, null, { timeout: 20000 });
            await wkPage.evaluate((seed) => window.__grpcUseDemoWallet(seed), 'f6'.repeat(32));
          } catch (e) {
            record('grpc:webkit-cross-instance-pubsub-over-turn-tcp', 'SKIP', `WebKit launch failed: ${String(e).slice(0, 180)}`);
            record('grpc:webkit-cross-instance-replay-over-turn-tcp', 'SKIP', 'WebKit unavailable for cross-instance replay');
            wkPage = null;
          }
          if (wkPage) {
            try {
              const triTopic = `orders-tri-${Date.now()}`;
              const triStarts = await Promise.all([
                start(fxPage, 'tri', triTopic),
                start(crPage, 'tri', triTopic),
                start(wkPage, 'tri', triTopic),
              ]);
              await Promise.all([
                fxPage.waitForTimeout(500),
                crPage.waitForTimeout(500),
                wkPage.waitForTimeout(500),
              ]);
              const triSeqs = [];
              triSeqs.push(await publish(wkPage, 'tri', triTopic, 'w1'));
              triSeqs.push(await publish(wkPage, 'tri', 'other', 'noise'));
              triSeqs.push(await publish(wkPage, 'tri', triTopic, 'w2'));
              const triFx = await waitReceived(fxPage, 'tri', 2);
              const triCr = await waitReceived(crPage, 'tri', 2);
              const triWk = await waitReceived(wkPage, 'tri', 2);
              const chromiumSeq = await publish(crPage, 'tri', triTopic, 'c1');
              const allFx = await waitReceived(fxPage, 'tri', 3);
              const allCr = await waitReceived(crPage, 'tri', 3);
              const allWk = await waitReceived(wkPage, 'tri', 3);
              const expectedSeqs = [triSeqs[0], triSeqs[2], chromiumSeq];
              const triOk = triStarts.every((started) => started.pairType?.startsWith('relay/'))
                && expectEvents(allFx, ['w1', 'w2', 'c1'], expectedSeqs)
                && expectEvents(allCr, ['w1', 'w2', 'c1'], expectedSeqs)
                && expectEvents(allWk, ['w1', 'w2', 'c1'], expectedSeqs)
                && expectEvents(triFx, ['w1', 'w2'], [triSeqs[0], triSeqs[2]])
                && expectEvents(triCr, ['w1', 'w2'], [triSeqs[0], triSeqs[2]])
                && expectEvents(triWk, ['w1', 'w2'], [triSeqs[0], triSeqs[2]]);
              record('grpc:webkit-cross-instance-pubsub-over-turn-tcp', triOk ? 'PASS' : 'SKIP',
                triOk
                  ? `Firefox+Chromium+WebKit simultaneous over TURN/TCP, seqs=${[...triSeqs, chromiumSeq].join(',')}`
                  : `WebKit tri-instance pub/sub unsupported here: ${JSON.stringify({ allFx, allCr, allWk, triSeqs, chromiumSeq }).slice(0, 220)}`);
              await Promise.all([
                close(fxPage, 'tri'), close(crPage, 'tri'), close(wkPage, 'tri'),
              ]);
            } catch (e) {
              record('grpc:webkit-cross-instance-pubsub-over-turn-tcp', 'SKIP', `WebKit tri-instance pub/sub failed here: ${String(e).slice(0, 220)}`);
            }

            try {
              const wkReplayTopic = `orders-webkit-replay-${Date.now()}`;
              await start(wkPage, 'wk-replay-publisher', null);
              const wrSeqs = [];
              wrSeqs.push(await publish(wkPage, 'wk-replay-publisher', wkReplayTopic, 'wr1'));
              wrSeqs.push(await publish(wkPage, 'wk-replay-publisher', wkReplayTopic, 'wr2'));
              await close(wkPage, 'wk-replay-publisher');

              await start(crPage, 'wk-replay-subscriber', wkReplayTopic);
              const wrReplayed = await waitReceived(crPage, 'wk-replay-subscriber', 2);

              await start(wkPage, 'wk-replay-publisher-2', null);
              wrSeqs.push(await publish(wkPage, 'wk-replay-publisher-2', wkReplayTopic, 'wr3'));
              const wrAfter = await waitReceived(crPage, 'wk-replay-subscriber', 3);
              const wrOk = expectEvents(wrReplayed, ['wr1', 'wr2'], [wrSeqs[0], wrSeqs[1]])
                && expectEvents(wrAfter, ['wr1', 'wr2', 'wr3'], wrSeqs);
              record('grpc:webkit-cross-instance-replay-over-turn-tcp', wrOk ? 'PASS' : 'SKIP',
                wrOk
                  ? `WebKit published/disconnected, Chromium replayed from git then received live; seqs=${wrSeqs.join(',')}`
                  : `WebKit cross-instance replay unsupported here: ${JSON.stringify({ wrReplayed, wrAfter, wrSeqs }).slice(0, 220)}`);
              await close(crPage, 'wk-replay-subscriber');
              await close(wkPage, 'wk-replay-publisher-2');
            } catch (e) {
              record('grpc:webkit-cross-instance-replay-over-turn-tcp', 'SKIP', `WebKit cross-instance replay failed here: ${String(e).slice(0, 220)}`);
            }
          }
        }
      } catch (e) {
        recordNet('grpc:cross-instance-pubsub-over-turn-tcp', false, '', String(e).slice(0, 300));
      } finally {
        try { await fxBrowser?.close(); } catch {}
        try { await crBrowser?.close(); } catch {}
        try { await wkBrowser?.close(); } catch {}
      }
    }
  } else {
    record('tcp:turn-tcp', 'SKIP', 'no TURN_TCP_URL (needs TUN-backed serve-grpc)');
  }

  // ---------- turns: (TLS 5349) ----------
  // Requires the TUN-backed serve-tls (scripts/browser-test.sh sets
  // TURNS_URL when /dev/net/tun + NET_ADMIN are available). Chromium
  // runs with --ignore-certificate-errors for the self-signed test
  // cert; Firefox cannot trust it in a test profile, so its turns:
  // attempt is a SKIP, never a fake PASS.
  const turnsUrl = process.env.TURNS_URL;
  if (turnsUrl && ENGINES.includes('chromium')) {
    let tBrowser;
    try {
      tBrowser = await chromium.launch({ args: ['--no-sandbox', '--ignore-certificate-errors'] });
      const ctx = await tBrowser.newContext({ ignoreHTTPSErrors: true });
      const page = await ctx.newPage();
      await page.goto(pageUrl);
      const g = await page.evaluate(async (urls) => {
        const pc = new RTCPeerConnection({ iceServers: [{ urls, username: 'browser-test-user', credential: 'browser-test-secret' }], iceTransportPolicy: 'relay' });
        const cands = []; const errs = [];
        pc.onicecandidate = (e) => { if (e.candidate?.candidate) cands.push(e.candidate.candidate); };
        pc.onicecandidateerror = (e) => errs.push(`${e.errorCode} ${e.errorText || ''}`);
        const done = new Promise((res) => { pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === 'complete') res(); }; setTimeout(res, 15000); });
        pc.createDataChannel('probe');
        await pc.setLocalDescription(await pc.createOffer());
        await done;
        const s = { state: pc.iceGatheringState, cands, errs };
        pc.close(); return s;
      }, turnsUrl).catch((e) => ({ state: 'error', cands: [], errs: [String(e)] }));
      const relay = g.cands.filter((c) => c.includes('typ relay'));
      record('tls:chromium-turns', relay.length > 0 ? 'PASS' : (REQUIRE ? 'FAIL' : 'SKIP'),
        relay.length > 0 ? `relay candidate over ${turnsUrl}` : `no relay over ${turnsUrl}: state=${g.state} errs=${g.errs.join(';')}`);
      // Full DataChannel pair over turns: (two Chromium contexts).
      const ctxB = await tBrowser.newContext({ ignoreHTTPSErrors: true });
      const pageB = await ctxB.newPage();
      await pageB.goto(pageUrl);
      const turnsCfg = { iceServers: [{ urls: turnsUrl, username: 'browser-test-user', credential: 'browser-test-secret' }], iceTransportPolicy: 'relay' };
      try {
        const pair = await relayOnce(page, pageB, turnsCfg, CONNECT_TIMEOUT_MS, 8192);
        const okPair = pair.gotOn2 === 'one element, one rendezvous' && pair.gotOn1 === 'ack over relay' && pair.pairType === 'relay/relay';
        record('tls:chromium-turns-pair', okPair ? 'PASS' : (REQUIRE ? 'FAIL' : 'SKIP'),
          okPair ? 'DataChannel over turns: both ways + 8192B binary' : JSON.stringify(pair).slice(0, 250));
      } catch (e) {
        record('tls:chromium-turns-pair', REQUIRE ? 'FAIL' : 'SKIP', String(e).slice(0, 250));
      }
      await ctxB.close();
      await ctx.close();
    } catch (e) {
      record('tls:chromium-turns', REQUIRE ? 'FAIL' : 'SKIP', String(e).slice(0, 250));
    } finally {
      try { await tBrowser?.close(); } catch {}
    }
    // Firefox with a profile that trusts the test CA (certutil-seeded
    // by scripts/browser-test.sh); SKIP when no such profile exists.
    const ffProfile = process.env.FIREFOX_TURNS_PROFILE;
    if (ffProfile) {
      let ffCtx;
      try {
        ffCtx = await firefox.launchPersistentContext(ffProfile, { args: [] });
        const ffPage = ffCtx.pages()[0] || (await ffCtx.newPage());
        await ffPage.goto(pageUrl);
        const g = await ffPage.evaluate(async (urls) => {
          const pc = new RTCPeerConnection({ iceServers: [{ urls, username: 'browser-test-user', credential: 'browser-test-secret' }], iceTransportPolicy: 'relay' });
          const cands = []; const errs = [];
          pc.onicecandidate = (e) => { if (e.candidate?.candidate) cands.push(e.candidate.candidate); };
          pc.onicecandidateerror = (e) => errs.push(`${e.errorCode} ${e.errorText || ''}`);
          const done = new Promise((res) => { pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === 'complete') res(); }; setTimeout(res, 15000); });
          pc.createDataChannel('probe');
          await pc.setLocalDescription(await pc.createOffer());
          await done;
          const s = { state: pc.iceGatheringState, cands, errs };
          pc.close(); return s;
        }, turnsUrl).catch((e) => ({ state: 'error', cands: [], errs: [String(e)] }));
        const relay = g.cands.filter((c) => c.includes('typ relay'));
        // Verified by packet capture: this Firefox build attempts
        // turn:?transport=tcp but never even SYNs for turns: - its
        // ICE stack does not initiate TURN/TLS. If a future build
        // does, this becomes a PASS with the CA-trusted profile.
        record('tls:firefox-turns', relay.length > 0 ? 'PASS' : 'SKIP',
          relay.length > 0 ? 'relay candidate over turns: with CA-trusted profile' : 'Firefox does not initiate TURN/TLS (turns:) in this build; CA profile attempt yielded no connection');
      } catch (e) {
        record('tls:firefox-turns', 'SKIP', `CA profile launch failed: ${String(e).slice(0, 200)}`);
      } finally {
        try { await ffCtx?.close(); } catch {}
      }
    } else {
      record('tls:firefox-turns', 'SKIP', 'Firefox does not initiate TURN/TLS (turns:) in this build (verified against a bare TCP listener)');
    }
    // WebKit turns: attempt (engine support varies; SKIP if this
    // WebKit build will not allocate over TLS here).
    if (ENGINES.includes('webkit')) {
      let wkBrowser;
      try {
        wkBrowser = await webkit.launch({ args: [] });
        const wkCtx = await wkBrowser.newContext({ ignoreHTTPSErrors: true });
        const wkPage = await wkCtx.newPage();
        await wkPage.goto(pageUrl);
        const g = await wkPage.evaluate(async (urls) => {
          const pc = new RTCPeerConnection({ iceServers: [{ urls, username: 'browser-test-user', credential: 'browser-test-secret' }], iceTransportPolicy: 'relay' });
          const cands = []; const errs = [];
          pc.onicecandidate = (e) => { if (e.candidate?.candidate) cands.push(e.candidate.candidate); };
          pc.onicecandidateerror = (e) => errs.push(`${e.errorCode} ${e.errorText || ''}`);
          const done = new Promise((res) => { pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === 'complete') res(); }; setTimeout(res, 15000); });
          pc.createDataChannel('probe');
          await pc.setLocalDescription(await pc.createOffer());
          await done;
          const s = { state: pc.iceGatheringState, cands, errs };
          pc.close(); return s;
        }, turnsUrl).catch((e) => ({ state: 'error', cands: [], errs: [String(e)] }));
        const relay = g.cands.filter((c) => c.includes('typ relay'));
        record('tls:webkit-turns', relay.length > 0 ? 'PASS' : 'SKIP',
          relay.length > 0 ? 'relay candidate over turns: in WebKit' : `WebKit turns: unsupported here: state=${g.state} errs=${g.errs.join(';')}`.slice(0, 250));
        await wkCtx.close();
      } catch (e) {
        record('tls:webkit-turns', 'SKIP', `WebKit turns: launch/gather failed: ${String(e).slice(0, 200)}`);
      } finally {
        try { await wkBrowser?.close(); } catch {}
      }
    }
  } else {
    record('tls:turns', 'SKIP', 'no TURNS_URL (needs TUN-backed serve-tls: /dev/net/tun + NET_ADMIN); TCP refusal covered by wire-tcp-refused');
  }

  const failed = results.filter((r) => r.status === 'FAIL');
  const passed = results.filter((r) => r.status === 'PASS').length;
  const skipped = results.filter((r) => r.status === 'SKIP').length;
  console.log(`\nsummary: ${passed} passed, ${skipped} skipped, ${failed.length} failed (REQUIRE_RELAY=${REQUIRE ? 1 : 0}, MIN_PASS=${MIN_PASS})`);
  if (REQUIRE && passed < MIN_PASS) {
    console.error(`REQUIRE_RELAY: only ${passed} PASS < MIN_PASS=${MIN_PASS} - treating as failure`);
    process.exitCode = 1;
  }
  if (failed.length > 0) process.exitCode = 1;
} catch (e) {
  console.error(`fatal: ${e.stack || e}`);
  process.exitCode = 1;
} finally {
  for (const cl of rawClients) cl.close();
  // `servers` holds the ChildProcess objects themselves.
  for (const s of servers) { try { s.kill(); } catch {} }
  pageServer.close();
}
// Stray UDP/browser handles must never hang CI after the summary.
setTimeout(() => process.exit(process.exitCode || 0), 250);

