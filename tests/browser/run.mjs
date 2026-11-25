// Playwright WebRTC test: two real Chromium RTCPeerConnections talk
// over the Rust TURN wire server with iceTransportPolicy=relay, so
// every packet must go through turn-dag's allocation/permission/
// channel relay. Run after `cargo build -p turn-dag-node`:
//   cd tests/browser && npm install && node run.mjs
import { firefox } from 'playwright';
import { spawn } from 'node:child_process';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';

// The headless shell crashes on WebRTC in some environments; prefer
// the full Chromium build from the Playwright cache when present.
function fullChromium() {
  const base = path.join(os.homedir(), '.cache/ms-playwright');
  try {
    for (const d of fs.readdirSync(base).filter((x) => /^chromium-\d+$/.test(x)).sort().reverse()) {
      for (const sub of ['chrome-linux-arm64/chrome', 'chrome-linux/chrome', 'chrome-mac/Chromium.app/Contents/MacOS/Chromium']) {
        const exe = path.join(base, d, sub);
        if (fs.existsSync(exe)) return exe;
      }
    }
  } catch {}
  return undefined;
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const PORT = 35478;
const HOST = process.env.TURN_HOST || '192.168.68.114';
const USER = 'browser-test-user';
const PASS = 'browser-test-secret';

// Page host for a secure context (test harness only, not product code).
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

const fail = (msg) => {
  console.error(`BROWSER-TEST FAIL: ${msg}\n--- server log ---\n${serverLog}`);
  server.kill();
  pageServer.close();
  process.exit(1);
};

try {
  // Wait for the listener line.
  for (let i = 0; i < 50 && !serverLog.includes('listening'); i++) {
    await new Promise((r) => setTimeout(r, 100));
  }
  if (!serverLog.includes('listening')) fail('server did not start');

  const browser = await firefox.launch({
    args: ['--disable-dev-shm-usage', '--no-sandbox'],
  });
  const page = await browser.newPage();
  page.on('console', (m) => console.log('[page]', m.text()));
  page.on('pageerror', (e) => console.log('[pageerror]', String(e)));
  await page.goto(`http://127.0.0.1:${pagePort}/`);

  const result = await page.evaluate(
    async ({ port, user, pass, host }) => {
      const cfg = {
        iceServers: [
          { urls: `turn:${host}:${port}?transport=udp`, username: user, credential: pass },
        ],
        iceTransportPolicy: 'relay',
      };
      const pc1 = new RTCPeerConnection(cfg);
      const pc2 = new RTCPeerConnection(cfg);
      const seen = { candidates: [], errors: [] };
      pc1.onicecandidate = (e) => {
        if (e.candidate && e.candidate.candidate) {
          seen.candidates.push(e.candidate.candidate);
          pc2.addIceCandidate(e.candidate).catch((err) => {}
        }
      };
      pc2.onicecandidate = (e) => {
        if (e.candidate && e.candidate.candidate) {
          seen.candidates.push(e.candidate.candidate);
          pc1.addIceCandidate(e.candidate).catch((err) => {}
        }
      };
      pc1.onicecandidateerror = (e) => seen.errors.push(`pc1 ice: ${e.errorText || e.type}`);
      pc2.onicecandidateerror = (e) => seen.errors.push(`pc2 ice: ${e.errorText || e.type}`);
      const dc1 = pc1.createDataChannel('rendezvous');
      const got = { onPc2: null, onPc1: null };
      const dc2Promise = new Promise((res) => (pc2.ondatachannel = (e) => res(e.channel)));
      const offer = await pc1.createOffer();
      await pc1.setLocalDescription(offer);
      await pc2.setRemoteDescription(pc1.localDescription);
      const answer = await pc2.createAnswer();
      await pc2.setLocalDescription(answer);
      await pc1.setRemoteDescription(pc2.localDescription);
      const dc2 = await dc2Promise;
      const waitState = (pc) =>
        new Promise((res, rej) => {
          if (pc.connectionState === 'connected') return res();
          const t = setTimeout(() => rej(new Error(`timeout state=${pc.connectionState} ice=${pc.iceConnectionState}`)), 20000);
          pc.onconnectionstatechange = () => {
            if (pc.connectionState === 'connected') {
              clearTimeout(t);
              res();
            }
          };
        });
      await Promise.all([waitState(pc1), waitState(pc2)]);
      await new Promise((res, rej) => {
        if (dc1.readyState === 'open') return res();
        dc1.onopen = res;
        setTimeout(() => rej(new Error(`dc1 state=${dc1.readyState}`)), 10000);
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
    { port: PORT, user: USER, pass: PASS, host: HOST },
  ).catch((e) => fail(`evaluate: ${e.message}`));

  console.log('result:', JSON.stringify(result, null, 2));
  if (result.got.onPc2 !== 'one element, one rendezvous') fail('pc2 did not receive payload');
  if (result.got.onPc1 !== 'ack over relay') fail('pc1 did not receive reply');
  if (result.pairType !== 'relay/relay') fail(`expected relay/relay pair, got ${result.pairType}`);
  if (!result.candidates.some((c) => c.includes('typ relay'))) fail('no relay candidates gathered');
  console.log('BROWSER-TEST PASS: WebRTC DataChannel over turn-dag relay (relay/relay)');
  await browser.close();
} finally {
  server.kill();
  pageServer.close();
}
