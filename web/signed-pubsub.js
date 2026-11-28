// Signed EventBus payloads: the browser's persistent wallet key
// (derived from a WebAuthn PRF secret by unlockWalletWithPasskey)
// certifies a short-lived ephemeral ML-DSA-65 keypair, and the
// ephemeral key signs each event. Envelopes are CBOR and are
// verified by the Rust broker before it appends to git.
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { encode as cborEncode, decode as cborDecode } from 'cbor-x';
import { TagValue } from '/grpc-vendor/src/events_pb.js';

const hexToBytesLocal = (hex) => Uint8Array.from(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));

function tagsToPb(tags) {
  const parts = tags.map((tag) => TagValue.encode(tag));
  const total = parts.reduce((n, part) => n + 4 + part.length, 0);
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const part of parts) {
    view.setUint32(offset, part.length, false);
    offset += 4;
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function createEphemeralSigner(wallet, lifetimeMs = 3600000) {
  if (!wallet?.sign || !wallet?.publicKey || !wallet?.addressHex) {
    throw new Error('unlock the signing wallet before publishing');
  }
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const ephemeral = ml_dsa65.keygen(seed);
  const issuedAtMs = Date.now();
  const certCore = cborEncode({
    v: 1,
    wallet_addr: hexToBytesLocal(wallet.addressHex),
    wallet_pubkey: wallet.publicKey,
    ephemeral_pubkey: ephemeral.publicKey,
    issued_at_ms: BigInt(issuedAtMs),
    expires_at_ms: BigInt(issuedAtMs + lifetimeMs),
  });
  return {
    wallet,
    ephemeral,
    certCore,
    certSig: wallet.sign(certCore),
    certSha256: sha256(certCore),
    nextSeq: 1,
  };
}

export function signEventEnvelope(signer, tags, payload) {
  const clientSeq = signer.nextSeq;
  const eventCore = cborEncode({
    v: 1,
    cert_sha256: signer.certSha256,
    client_seq: BigInt(clientSeq),
    tags_pb: tagsToPb(tags),
    payload,
  });
  const eventSig = ml_dsa65.sign(eventCore, signer.ephemeral.secretKey);
  signer.nextSeq += 1;
  return cborEncode({
    cert_core: signer.certCore,
    cert_sig: signer.certSig,
    event_core: eventCore,
    event_sig: eventSig,
  });
}

export function decodeSignedEventPayload(bytes) {
  const envelope = cborDecode(bytes);
  const core = cborDecode(envelope.event_core);
  const cert = cborDecode(envelope.cert_core);
  return {
    payload: core.payload,
    clientSeq: Number(core.client_seq),
    walletAddress: [...cert.wallet_addr].map((b) => b.toString(16).padStart(2, '0')).join(''),
  };
}
