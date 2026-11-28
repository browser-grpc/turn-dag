// Browser PQ wallet based on WebAuthn register/auth + PRF.
//
// Enroll: navigator.credentials.create() with the `prf` extension
// and a resident (discoverable) credential. Unlock: credentials.get()
// with prf.eval over a fixed domain salt returns a deterministic
// 32-byte PRF output from the authenticator; HKDF expands it into
// the ML-DSA-65 seed. The same passkey therefore always re-derives
// the same PQ keypair (address = SHA3-256(pubkey)[..20], exactly
// the Rust wallet derivation), and the seed never leaves the page.
//
// There is deliberately no silent fallback: if WebAuthn PRF is
// unavailable the wallet refuses to derive keys. (Tests and demos
// may pass an explicit demo seed to deriveKeysFromSeed, which is
// labeled as such wherever it is surfaced.)
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from './pow.js';

const PRF_SALT_LABEL = 'turn-dag-webauthn-prf-v1';
const CRED_ID_KEY = 'turndag-passkey-credential-id';

const b64urlToBytes = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const bytesToB64url = (b) => btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export function webauthnSupported() {
  return typeof PublicKeyCredential !== 'undefined' && !!navigator.credentials?.create;
}

async function randomChallenge() {
  return crypto.getRandomValues(new Uint8Array(32));
}

/// Register a passkey with PRF enabled and remember its credential id.
/// Returns { enabled } - whether the authenticator supports PRF.
export async function registerPasskey(username = 'turn-dag-user') {
  if (!webauthnSupported()) throw new Error('WebAuthn unavailable in this browser');
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: await randomChallenge(),
      rp: { id: location.hostname, name: 'turn-dag wallet' },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: username,
        displayName: username,
      },
      // ES256 first: authenticators pick the first supported alg,
      // and PRF/hmac-secret enablement is most reliable on ES256.
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: {
        residentKey: 'required',
        requireResidentKey: true,
        userVerification: 'required',
      },
      extensions: { prf: {} },
    },
  });
  if (!cred) throw new Error('passkey registration cancelled');
  localStorage.setItem(CRED_ID_KEY, bytesToB64url(new Uint8Array(cred.rawId)));
  const enabled = cred.getClientExtensionResults?.().prf?.enabled === true;
  return { credentialId: cred.id, prfEnabled: enabled };
}

/// Authenticate and evaluate PRF; expand the output into the wallet seed.
export async function deriveSeedFromPasskey() {
  if (!webauthnSupported()) throw new Error('WebAuthn unavailable in this browser');
  const salt = sha256(new TextEncoder().encode(PRF_SALT_LABEL));
  const stored = localStorage.getItem(CRED_ID_KEY);
  const allowCredentials = stored
    ? [{ type: 'public-key', id: b64urlToBytes(stored) }]
    : [];
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: await randomChallenge(),
      rpId: location.hostname,
      allowCredentials,
      userVerification: 'required',
      extensions: { prf: { eval: { first: salt } } },
    },
  });
  const prfFirst = assertion?.getClientExtensionResults?.().prf?.results?.first;
  if (!prfFirst) {
    throw new Error('authenticator did not return a PRF result (PRF unsupported)');
  }
  // Domain-separated expansion into the ML-DSA seed.
  return hkdf(sha256, new Uint8Array(prfFirst), new TextEncoder().encode('turn-dag'), new TextEncoder().encode('ml-dsa-65-seed-v1'), 32);
}

/// ML-DSA-65 keypair + turn-dag address from a 32-byte seed.
export function deriveKeysFromSeed(seedBytes) {
  const keys = ml_dsa65.keygen(seedBytes);
  const addressHex = bytesToHex(sha3_256(keys.publicKey).slice(0, 20));
  return {
    publicKey: keys.publicKey,
    secretKey: keys.secretKey,
    addressHex,
    sign: (msgBytes) => ml_dsa65.sign(msgBytes, keys.secretKey),
    verify: (sig, msgBytes) => ml_dsa65.verify(sig, msgBytes, keys.publicKey),
  };
}

/// Full passkey flow: auth + PRF + derive. This is THE wallet path.
export async function unlockWalletWithPasskey() {
  const seed = await deriveSeedFromPasskey();
  return { ...deriveKeysFromSeed(seed), seedSource: 'webauthn-prf' };
}

export { bytesToHex, hexToBytes };
