// gRPC Echo + EventBus pub/sub over a TURN/TCP relay via
// grpc-dc rendezvous. Dial: descriptor (published by
// turn-dag-node serve-grpc) + relay-only ICE with a single
// turn:?transport=tcp server.
import { rendezvousChannel } from '/grpc-vendor/src/rendezvous.js';
import { EchoRequest } from '/grpc-vendor/examples/echo_pb.js';
import { EchoClient } from '/grpc-vendor/examples/echo_grpc_dc.js';
import { EventBusClient, publishEvent, subscribeEvents, tagString } from '/grpc-vendor/src/eventbus.js';
import { registerPasskey, unlockWalletWithPasskey, deriveKeysFromSeed, hexToBytes } from './wallet.js';
import { createEphemeralSigner, signEventEnvelope, decodeSignedEventPayload } from './signed-pubsub.js';
import { Tag } from '/grpc-vendor/src/events_pb.js';

async function pairType(pc) {
  if (!pc) return null;
  const stats = await pc.getStats();
  let pair = null;
  stats.forEach((r) => {
    if (r.type === 'candidate-pair' && (r.state === 'succeeded' || r.nominated)) {
      const local = stats.get(r.localCandidateId);
      const remote = stats.get(r.remoteCandidateId);
      if (local && remote) pair = `${local.candidateType}/${remote.candidateType}`;
    }
  });
  return pair;
}

async function dial(descriptor, turnUrl, username, credential) {
  return rendezvousChannel(descriptor, {
    iceServers: [{ urls: turnUrl, username, credential }],
    iceTransportPolicy: 'relay',
    timeoutMs: 20000,
  });
}

// The persistent wallet key that certifies ephemeral publishing
// keys. In production it comes from WebAuthn PRF unlock; the demo
// seed path exists for engines without a test passkey authenticator.
let signingWallet = null;
function requireSigner() {
  if (!signingWallet) throw new Error('unlock the signing wallet before publishing');
  return createEphemeralSigner(signingWallet);
}
async function signedPublish(session, tags, payload) {
  const envelope = signEventEnvelope(session.signer, tags, payload);
  return publishEvent(
    session.client,
    tags,
    envelope,
    session.signer.wallet.addressHex,
  );
}
function unwrapEvent(event) {
  const decoded = decodeSignedEventPayload(event.payload);
  return {
    payload: new TextDecoder().decode(decoded.payload),
    seq: Number(event.seq),
    clientSeq: decoded.clientSeq,
    walletAddress: decoded.walletAddress,
  };
}

window.__grpcUseDemoWallet = (seedHex) => {
  signingWallet = deriveKeysFromSeed(hexToBytes(seedHex));
  signingWallet.seedSource = 'demo-seed-test-only';
  return signingWallet.addressHex;
};
window.__grpcUnlockSigner = async () => {
  // Register only when this origin has no stored credential id;
  // a second registration would create a different passkey and
  // therefore a different wallet.
  if (!localStorage.getItem('turndag-passkey-credential-id')) {
    await registerPasskey();
  }
  signingWallet = await unlockWalletWithPasskey();
  const el = document.getElementById('signer');
  if (el) el.textContent = `signer: webauthn-prf ${signingWallet.addressHex}`;
  return signingWallet.addressHex;
};
document.getElementById('btn-grpc-unlock')?.addEventListener('click', async () => {
  const el = document.getElementById('signer');
  try {
    const address = await window.__grpcUnlockSigner();
    if (el) el.textContent = `signer: webauthn-prf ${address}`;
  } catch (e) {
    if (el) el.textContent = `signer unlock failed: ${e.message}`;
  }
});

window.__grpcEcho = async (descriptor, turnUrl, username, credential, message) => {
  const channel = await dial(descriptor, turnUrl, username, credential);
  try {
    const client = new EchoClient(channel);
    const resp = await client.unary(new EchoRequest({ message, count: 0 }));
    return { message: resp.message, pairType: await pairType(channel.peerConnection) };
  } finally {
    channel.closeRendezvous();
  }
};

// Session-scoped pub/sub primitives let Playwright orchestrate
// multiple browser instances: one page can subscribe while a
// different browser process publishes, rather than both roles
// being folded into the single-page helper below.
const pubSubSessions = new Map();

window.__grpcPubSubStart = async (
  sessionId,
  descriptor,
  turnUrl,
  username,
  credential,
  topic = null,
) => {
  if (pubSubSessions.has(sessionId)) throw new Error(`duplicate pub/sub session ${sessionId}`);
  const channel = await dial(descriptor, turnUrl, username, credential);
  const session = {
    channel,
    client: new EventBusClient(channel),
    signer: requireSigner(),
    received: [],
    iterator: null,
    error: null,
    pairType: await pairType(channel.peerConnection),
  };
  pubSubSessions.set(sessionId, session);
  if (topic) {
    const stream = await subscribeEvents(session.client, [tagString(Tag.TOPIC, topic)]);
    session.iterator = stream[Symbol.asyncIterator]();
    session.collector = (async () => {
      try {
        for (;;) {
          const step = await session.iterator.next();
          if (step.done) return;
          session.received.push(unwrapEvent(step.value));
        }
      } catch (e) {
        session.error = String(e);
      }
    })();
  }
  return { pairType: session.pairType };
};

window.__grpcPubSubPublish = async (sessionId, topic, payload) => {
  const session = pubSubSessions.get(sessionId);
  if (!session) throw new Error(`unknown pub/sub session ${sessionId}`);
  const seq = await signedPublish(
    session,
    [tagString(Tag.TOPIC, topic)],
    new TextEncoder().encode(payload),
  );
  return Number(seq);
};

window.__grpcPubSubReceived = (sessionId) => {
  const session = pubSubSessions.get(sessionId);
  if (!session) throw new Error(`unknown pub/sub session ${sessionId}`);
  if (session.error) throw new Error(session.error);
  return [...session.received];
};

window.__grpcPubSubClose = async (sessionId) => {
  const session = pubSubSessions.get(sessionId);
  if (!session) return;
  await session.iterator?.return().catch(() => {});
  await session.collector?.catch(() => {});
  session.channel.closeRendezvous();
  pubSubSessions.delete(sessionId);
};

window.__grpcPubSub = async (descriptor, turnUrl, username, credential, topic = 'orders') => {
  const enc = (s) => new TextEncoder().encode(s);
  const dec = (b) => new TextDecoder().decode(b);
  const orders = [tagString(Tag.TOPIC, topic)];
  const other = [tagString(Tag.TOPIC, 'other')];

  const collectUntil = async (iterator, out, count) => {
    while (out.length < count) {
      const step = await iterator.next();
      if (step.done) throw new Error('subscription ended early');
      out.push(unwrapEvent(step.value));
    }
  };

  // Live delivery under tag filtering.
  const channel1 = await dial(descriptor, turnUrl, username, credential);
  const pair1 = await pairType(channel1.peerConnection);
  const client1 = new EventBusClient(channel1);
  const session1 = { client: client1, signer: requireSigner() };
  const stream1 = await subscribeEvents(client1, orders);
  const it1 = stream1[Symbol.asyncIterator]();
  const live = [];
  const liveDone = collectUntil(it1, live, 2);
  // Let Subscribe register before publishing.
  await new Promise((resolve) => setTimeout(resolve, 300));
  const seqs = [];
  seqs.push(Number(await signedPublish(session1, orders, enc('o1'))));
  seqs.push(Number(await signedPublish(session1, other, enc('noise'))));
  seqs.push(Number(await signedPublish(session1, orders, enc('o2'))));
  await liveDone;
  await it1.return();
  channel1.closeRendezvous();

  // A fresh dial+subscription replays matching branch history
  // before any new publish, then follows live events.
  const channel2 = await dial(descriptor, turnUrl, username, credential);
  const pair2 = await pairType(channel2.peerConnection);
  const client2 = new EventBusClient(channel2);
  const session2 = { client: client2, signer: requireSigner() };
  const stream2 = await subscribeEvents(client2, orders);
  const it2 = stream2[Symbol.asyncIterator]();
  const replayed = [];
  await collectUntil(it2, replayed, 2);
  seqs.push(Number(await signedPublish(session2, orders, enc('o3'))));
  await collectUntil(it2, replayed, 3);
  await it2.return();
  channel2.closeRendezvous();

  return { live, replayed, seqs, pairType: pair1, pairType2: pair2 };
};
document.getElementById('out').textContent = 'ready: call __grpcEcho(...) or __grpcPubSub(...)';
