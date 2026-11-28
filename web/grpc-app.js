// gRPC Echo + EventBus pub/sub over a TURN/TCP relay via
// grpc-dc rendezvous. Dial: descriptor (published by
// turn-dag-node serve-grpc) + relay-only ICE with a single
// turn:?transport=tcp server.
import { rendezvousChannel } from '/grpc-vendor/src/rendezvous.js';
import { EchoRequest } from '/grpc-vendor/examples/echo_pb.js';
import { EchoClient } from '/grpc-vendor/examples/echo_grpc_dc.js';
import { EventBusClient, publishEvent, subscribeEvents, tagString } from '/grpc-vendor/src/eventbus.js';
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
          session.received.push({
            payload: new TextDecoder().decode(step.value.payload),
            seq: Number(step.value.seq),
          });
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
  const seq = await publishEvent(
    session.client,
    [tagString(Tag.TOPIC, topic)],
    new TextEncoder().encode(payload),
    'browser-pubsub',
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
      out.push({ payload: dec(step.value.payload), seq: Number(step.value.seq) });
    }
  };

  // Live delivery under tag filtering.
  const channel1 = await dial(descriptor, turnUrl, username, credential);
  const pair1 = await pairType(channel1.peerConnection);
  const client1 = new EventBusClient(channel1);
  const stream1 = await subscribeEvents(client1, orders);
  const it1 = stream1[Symbol.asyncIterator]();
  const live = [];
  const liveDone = collectUntil(it1, live, 2);
  // Let Subscribe register before publishing.
  await new Promise((resolve) => setTimeout(resolve, 300));
  const seqs = [];
  seqs.push(Number(await publishEvent(client1, orders, enc('o1'), 'browser-pubsub')));
  seqs.push(Number(await publishEvent(client1, other, enc('noise'), 'browser-pubsub')));
  seqs.push(Number(await publishEvent(client1, orders, enc('o2'), 'browser-pubsub')));
  await liveDone;
  await it1.return();
  channel1.closeRendezvous();

  // A fresh dial+subscription replays matching branch history
  // before any new publish, then follows live events.
  const channel2 = await dial(descriptor, turnUrl, username, credential);
  const pair2 = await pairType(channel2.peerConnection);
  const client2 = new EventBusClient(channel2);
  const stream2 = await subscribeEvents(client2, orders);
  const it2 = stream2[Symbol.asyncIterator]();
  const replayed = [];
  await collectUntil(it2, replayed, 2);
  seqs.push(Number(await publishEvent(client2, orders, enc('o3'), 'browser-pubsub')));
  await collectUntil(it2, replayed, 3);
  await it2.return();
  channel2.closeRendezvous();

  return { live, replayed, seqs, pairType: pair1, pairType2: pair2 };
};
document.getElementById('out').textContent = 'ready: call __grpcEcho(...) or __grpcPubSub(...)';
