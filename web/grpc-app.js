// gRPC Echo over a TURN/TCP relay via grpc-dc rendezvous.
// Dial: descriptor (published by turn-dag-node serve-grpc) +
// relay-only ICE with a single turn:?transport=tcp server.
import { rendezvousChannel } from '/grpc-vendor/src/rendezvous.js';
import { EchoRequest } from '/grpc-vendor/examples/echo_pb.js';
import { EchoClient } from '/grpc-vendor/examples/echo_grpc_dc.js';

window.__grpcEcho = async (descriptor, turnUrl, username, credential, message) => {
  const channel = await rendezvousChannel(descriptor, {
    iceServers: [{ urls: turnUrl, username, credential }],
    iceTransportPolicy: 'relay',
    timeoutMs: 20000,
  });
  try {
    const client = new EchoClient(channel);
    const resp = await client.unary(new EchoRequest({ message, count: 0 }));
    let pairType = null;
    const pc = channel.peerConnection;
    if (pc) {
      const stats = await pc.getStats();
      stats.forEach((r) => {
        if (r.type === 'candidate-pair' && (r.state === 'succeeded' || r.nominated)) {
          const local = stats.get(r.localCandidateId);
          const remote = stats.get(r.remoteCandidateId);
          if (local && remote) pairType = `${local.candidateType}/${remote.candidateType}`;
        }
      });
    }
    return { message: resp.message, pairType };
  } finally {
    channel.closeRendezvous();
  }
};
document.getElementById('out').textContent = 'ready: call __grpcEcho(descriptor, turnUrl, user, pass, message)';
