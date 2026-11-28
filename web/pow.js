// Browser PoW solvers. All proof-of-work for turn-dag happens here
// in the browser; Rust only verifies (one hash per solution).
//   TURN PoW : SHA256("turn-pow-solution-v1" || challenge || nonce_be)
//              with >= bits leading zero bits.
//   Mint PoW : Argon2id(challenge || nonce_be, salt=challenge[..16],
//              m=256KiB t=1 p=1 out=32) with hash < 2^256 / difficulty
//              (MinterConfig::cheap_for_tests parameters).
import { createSHA256, argon2id } from 'hash-wasm';

export const hexToBytes = (hex) => Uint8Array.from(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
export const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

function leadingZeroBits(hash) {
  let n = 0;
  for (const b of hash) {
    if (b === 0) { n += 8; continue; }
    n += Math.clz32(b) - 24;
    break;
  }
  return n;
}

function meetsDifficulty(hash, difficulty) {
  if (difficulty <= 1n) return true;
  const v = BigInt('0x' + bytesToHex(hash));
  return v < (1n << 256n) / difficulty;
}

export async function solveTurnPow(challengeHex, bits) {
  const challenge = hexToBytes(challengeHex);
  const prefix = new TextEncoder().encode('turn-pow-solution-v1');
  const hasher = await createSHA256();
  const msg = new Uint8Array(prefix.length + 32 + 8);
  msg.set(prefix, 0);
  msg.set(challenge, prefix.length);
  const view = new DataView(msg.buffer);
  for (let nonce = 0; ; nonce++) {
    view.setBigUint64(prefix.length + 32, BigInt(nonce), false);
    hasher.init();
    hasher.update(msg);
    const hash = hasher.digest('binary');
    if (leadingZeroBits(hash) >= bits) return { nonce, hashHex: bytesToHex(hash) };
  }
}

// Argon parameters default to MinterConfig::cheap_for_tests;
// pass the production shape (64MiB, t=3, p=4) to solve at
// production cost.
export async function solveMintPow(challengeHex, difficulty, params = {}) {
  const { memorySize = 256, iterations = 1, parallelism = 1 } = params;
  const challenge = hexToBytes(challengeHex);
  const diff = BigInt(difficulty);
  for (let nonce = 0; ; nonce++) {
    const password = new Uint8Array(40);
    password.set(challenge, 0);
    new DataView(password.buffer).setBigUint64(32, BigInt(nonce), false);
    const hash = await argon2id({
      password,
      salt: challenge.slice(0, 16),
      parallelism,
      iterations,
      memorySize,
      hashLength: 32,
      outputType: 'binary',
    });
    if (meetsDifficulty(hash, diff)) {
      return { nonce, hashHex: bytesToHex(hash) };
    }
  }
}

/// ElementId = SHA256(challenge || nonce_be || miner_addr20).
export async function elementId(challengeHex, nonce, minerHex) {
  const challenge = hexToBytes(challengeHex);
  const miner = hexToBytes(minerHex);
  const data = new Uint8Array(32 + 8 + 20);
  data.set(challenge, 0);
  new DataView(data.buffer).setBigUint64(32, BigInt(nonce), false);
  data.set(miner, 40);
  const hasher = await createSHA256();
  hasher.init();
  hasher.update(data);
  return bytesToHex(hasher.digest('binary'));
}
