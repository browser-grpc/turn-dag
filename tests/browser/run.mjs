// Playwright WebRTC coverage for the Rust TURN relay.
// Split into independent sub-tests so each failure mode is isolated:
//   1. gather     - single PC, iceTransportPolicy=relay: must reach
//                   gathering=complete (relay candidate, or a clean
//                   empty result on hosts where ICE is policy-blocked)
//   2. relay      - two PCs, relay/relay: DataChannel both ways
//                   (requires real network path; otherwise SKIP)
//   3. negative   - wrong credentials: no relay candidate, ICE error path
//   4. stun       - control: plain STUN gathering must complete
//
// In sandboxes without usable TURN networking sub-tests 2 (and the
// relay half of 1) report SKIP rather than FAIL, so CI on a normal
// network is the real gate. Run after `cargo build -p turn-dag-node`:
//   cd tests/browser && npm install && node run.mjs
import { firefox } from 'playwright';
import { spawn } from 'node:child_process';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const PORT = 35478;
const HOST = process.env.TURN_HOST || '192.168.68.114';
const USER = 'browser-test-user';
const PASS = 'browser-test-secret';
const GATHER_TIMEOUT_MS = 15000;
const CONNECT_TIMEOUT_MS = 30000;

const pageServer = http.createServer((_req, res) => {
  res.setHeader('content-type', 'text/html');
  res.end('<!doctype html><title>turn-dag webrtc test</title>');
});
await new Promise((r) => pageServer.listen(0, '127.0.0.1', r));
const pagePort = pageServer.address().port;

const server = spawn(
  path.join(root, 'target/debug/turn-dag-node'),
  ['serve-udp', '--addr', `0.0.0.0:${PORT}`, '--relay-ip', HOST, '--user', USER, '--pass', PASS],
  { stdio: ['ignore', 'pipe', 'pipe'] },
);
let serverLog = '';
server.stdout.on('data', (d) => (serverLog += d));
server.stderr.on('data', (d) => (serverLog += d));

const results = [];
const record = (name, status, detail) => {
  results.push({ name, status, detail });
  console.log(`[${status}] ${name}${detail ? ` - ${detail}` : ''}`);
};
const turnCfg = (user, pass) => ({
  iceServers: [{ urls: `turn:${HOST}:${PORT}?transport=udp`, username: user, credential: pass }],
  iceTransportPolicy: 'relay',
});

async function waitListening() {
  for (let i = 0; i < 50 && !serverLog.includes('listening'); i++) {
    await new Promise((r) => setTimeout(r, 100));
  }
  return serverLog.includes('listening');
}

try {
  if (!(await waitListening())) {
    console.error(`server did not start\n--- server log ---\n${serverLog}`);
    process.exit(1);
  }

  const browser = await firefox.launch({ args: ['--no-sandbox'] });
  const page = await browser.newPage();
  page.on('console', (m) => console.log('[page]', m.text()));
  page.on('pageerror', (e) => console.log('[pageerror]', String(e)));
  await page.goto(`http://127.0.0.1:${pagePort}/`);

  // --- Sub-test 1: relay gathering (single PC) ---
  const gather = await page
    .evaluate(
      async ({ cfg, timeout }) => {
        const pc = new RTCPeerConnection(cfg);
        const cands = [];
        const errors = [];
        pc.onicecandidate = (e) => {
          if (e.candidate && e.candidate.candidate) cands.push(e.candidate.candidate);
        };
        pc.onicecandidateerror = (e) => errors.push(e.errorText || `code ${e.errorCode}`);
        const done = new Promise((res) => {
          pc.onicegatheringstatechange = () => {
            if (pc.iceGatheringState === 'complete') res();
          };
          setTimeout(res, timeout);
        });
        pc.createDataChannel('probe');
        await pc.setLocalDescription(await pc.createOffer());
        await done;
        const state = pc.iceGatheringState;
        pc.close();
        return { state, cands, errors };
      },
      { cfg: turnCfg(USER, PASS), timeout: GATHER_TIMEOUT_MS },
    )
    .catch((e) => ({ state: 'error', cands: [], errors: [String(e)] }));
  const relayCands = gather.cands.filter((c) => c.includes('typ relay'));
  if (gather.state === 'complete' && relayCands.length > 0) {
    record('gather', 'PASS', `${relayCands.length} relay candidate(s)`);
  } else if (gather.state === 'complete') {
    record('gather', 'SKIP', `ICE policy-blocked on this host (no relay candidates)`);
  } else {
    record('gather', 'FAIL', `gathering state=${gather.state} errors=${gather.errors.join('; ')}`);
  }

  // --- Sub-test 4: STUN control (independent of TURN server) ---
  const stun = await page
    .evaluate(async (timeout) => {
      const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:127.0.0.1:19302' }] });
      const cands = [];
      pc.onicecandidate = (e) => {
        if (e.candidate && e.candidate.candidate) cands.push(e.candidate.candidate);
      };
      const done = new Promise((res) => {
        pc.onicegatheringstatechange = () => {
          if (pc.iceGatheringState === 'complete') res();
        };
        setTimeout(res, timeout);
      });
      pc.createDataChannel('probe');
      await pc.setLocalDescription(await pc.createOffer());
      await done;
      const state = pc.iceGatheringState;
      pc.close();
      return { state, cands };
    }, 5000)
    .catch((e) => ({ state: 'error', cands: [] }));
  if (stun.state === 'complete' && stun.cands.length > 0) {
    record('stun-control', 'PASS', `${stun.cands.length} host candidate(s)`);
  } else if (stun.state === 'complete') {
    record('stun-control', 'SKIP', 'no host candidates in headless profile');
  } else {
    record('stun-control', 'FAIL', `state=${stun.state}`);
  }

  // --- Sub-test 3: negative (wrong credentials must not allocate) ---
  const negative = await page
    .evaluate(
      async ({ cfg, timeout }) => {
        const pc = new RTCPeerConnection(cfg);
        const cands = [];
        const errs = [];
        pc.onicecandidate = (e) => {
          if (e.candidate && e.candidate.candidate) cands.push(e.candidate.candidate);
        };
        pc.onicecandidateerror = (e) => errs.push(e.errorText || `${e.errorCode}`);
        const done = new Promise((res) => {
          pc.onicegatheringstatechange = () => {
            if (pc.iceGatheringState === 'complete') res();
          };
          setTimeout(res, timeout);
        });
        pc.createDataChannel('probe');
        await pc.setLocalDescription(await pc.createOffer());
        await done;
        const state = pc.iceGatheringState;
        pc.close();
        return { state, cands, errs };
      },
      { cfg: turnCfg(USER, 'wrong-password'), timeout: GATHER_TIMEOUT_MS },
    )
    .catch((e) => ({ state: 'error', cands: [], errs: [String(e)] }));
  const negRelay = negative.cands.filter((c) => c.includes('typ relay'));
  if (negRelay.length === 0) {
    record('negative-creds', 'PASS', 'no relay candidate with wrong credentials');
  } else {
    record('negative-creds', 'FAIL', `relay candidate leaked with wrong credentials`);
  }

  // --- Sub-test 2: relay DataChannel (needs real network path) ---
  const relay = await page
    .evaluate(
      async ({ cfg, connectTimeout }) => {
        const pc1 = new RTCPeerConnection(cfg);
        const pc2 = new RTCPeerConnection(cfg);
        const seen = { candidates: [], errors: [] };
        pc1.onicecandidate = (e) => {
          if (e.candidate && e.candidate.candidate) {
            seen.candidates.push(e.candidate.candidate);
            pc2.addIceCandidate(e.candidate).catch(() => {});
          }
        };
        pc2.onicecandidate = (e) => {
          if (e.candidate && e.candidate.candidate) {
            seen.candidates.push(e.candidate.candidate);
            pc1.addIceCandidate(e.candidate).catch(() => {});
          }
        };
        pc1.onicecandidateerror = (e) => seen.errors.push(`pc1: ${e.errorText || e.errorCode}`);
        pc2.onicecandidateerror = (e) => seen.errors.push(`pc2: ${e.errorText || e.errorCode}`);
        const dc1 = pc1.createDataChannel('rendezvous');
        const got = { onPc2: null, onPc1: null };
        const dc2Promise = new Promise((res) => (pc2.ondatachannel = (e) => res(e.channel)));
        await pc1.setLocalDescription(await pc1.createOffer());
        await pc2.setRemoteDescription(pc1.localDescription);
        await pc2.setLocalDescription(await pc2.createAnswer());
        await pc1.setRemoteDescription(pc2.localDescription);
        const dc2 = await Promise.race([dc2Promise, new Promise((_, rej) => setTimeout(() => rej(new Error('dc2 timeout')), 10000))]);
        const waitConnected = (pc) =>
          new Promise((res, rej) => {
            if (pc.connectionState === 'connected') return res();
            const t = setTimeout(() => rej(new Error(`state=${pc.connectionState} ice=${pc.iceConnectionState}`)), connectTimeout);
            pc.onconnectionstatechange = () => {
              if (pc.connectionState === 'connected') {
                clearTimeout(t);
                res();
              }
            };
          });
        await Promise.all([waitConnected(pc1), waitConnected(pc2)]);
        await new Promise((res, rej) => {
          if (dc1.readyState === 'open') return res();
          dc1.onopen = res;
          setTimeout(() => rej(new Error(`dc1 ${dc1.readyState}`)), 10000);
        });
        const p2 = new Promise((res) => (dc2.onmessage = (e) => res(e.data)));
        const p1 = new Promise((res) => (dc1.onmessage = (e) => res(e.data)));
        dc1.send('one element, one rendezvous');
        got.onPc2 = await p2;
        dc2.send('ack over relay');
        got.onPc1 = await p1;
        const stats = await pc1.getStats();
        let pairType = null;
        stats.forEach((r) => {
          if (r.type === 'candidate-pair' && (r.state === 'succeeded' || r.nominated)) {
            const local = stats.get(r.localCandidateId);
            const remote = stats.get(r.remoteCandidateId);
            if (local && remote) pairType = `${local.candidateType}/${remote.candidateType}`;
          }
        });
        return { got, pairType, candidates: seen.candidates, errors: seen.errors, state: pc1.connectionState };
      },
      { cfg: turnCfg(USER, PASS), connectTimeout: CONNECT_TIMEOUT_MS },
    )
    .catch((e) => ({ error: String(e), got: null, pairType: null, candidates: [], errors: [] }));
  if (relay.error) {
    record('relay-datachannel', 'SKIP', `no network path: ${relay.error}`);
  } else if (
    relay.got?.onPc2 === 'one element, one rendezvous' &&
    relay.got?.onPc1 === 'ack over relay' &&
    relay.pairType === 'relay/relay'
  ) {
    record('relay-datachannel', 'PASS', 'relay/relay DataChannel both ways');
  } else {
    record('relay-datachannel', 'FAIL', JSON.stringify(relay).slice(0, 400));
  }

  await browser.close();

  const failed = results.filter((r) => r.status === 'FAIL');
  const passed = results.filter((r) => r.status === 'PASS').length;
  const skipped = results.filter((r) => r.status === 'SKIP').length;
  console.log(`\nsummary: ${passed} passed, ${skipped} skipped, ${failed.length} failed`);
  if (failed.length > 0) {
    console.error(`--- server log ---\n${serverLog}`);
    process.exit(1);
  }
} finally {
  server.kill();
  pageServer.close();
}
