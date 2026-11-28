import {
  registerPasskey,
  unlockWalletWithPasskey,
  deriveKeysFromSeed,
  webauthnSupported,
  bytesToHex,
} from './wallet.js';
import { solveTurnPow, solveMintPow, elementId, hexToBytes } from './pow.js';

const $ = (id) => document.getElementById(id);
let wallet = null;

function showWallet(w, source) {
  wallet = w;
  $('address').textContent = w.addressHex;
  $('seed-source').textContent = source;
}

// API surface used by the Playwright suite (the suite drives the
// same code the buttons do).
window.turnDagWallet = {
  registerPasskey,
  unlockWalletWithPasskey,
  deriveKeysFromSeed,
  webauthnSupported,
  solveTurnPow,
  solveMintPow,
  elementId,
  signWalletMessage: () => {
    if (!wallet) throw new Error('unlock the wallet first');
    const msg = new TextEncoder().encode('turn-dag-browser-wallet-v1');
    return {
      addressHex: wallet.addressHex,
      publicKeyHex: bytesToHex(wallet.publicKey),
      sigHex: bytesToHex(wallet.sign(msg)),
    };
  },
};

$('btn-register').addEventListener('click', async () => {
  try {
    const r = await registerPasskey();
    $('seed-source').textContent = `passkey registered (PRF ${r.prfEnabled ? 'enabled' : 'NOT supported by this authenticator'})`;
  } catch (e) {
    $('seed-source').textContent = `register failed: ${e.message}`;
  }
});

$('btn-unlock').addEventListener('click', async () => {
  try {
    const w = await unlockWalletWithPasskey();
    showWallet(w, 'webauthn-prf');
  } catch (e) {
    $('seed-source').textContent = `unlock failed: ${e.message}`;
  }
});

$('btn-turn-pow').addEventListener('click', async () => {
  const out = $('turn-pow-out');
  out.textContent = 'solving...';
  try {
    const r = await solveTurnPow($('pow-challenge').value.trim(), Number($('pow-bits').value));
    out.textContent = `nonce=${r.nonce}\nhash=${r.hashHex}\nverify with: turn-dag-node pow-verify --challenge <hex> --bits ${$('pow-bits').value} --nonce ${r.nonce}`;
  } catch (e) {
    out.textContent = `failed: ${e.message}`;
  }
});

$('btn-mint-pow').addEventListener('click', async () => {
  const out = $('mint-pow-out');
  out.textContent = 'solving (Argon2id per nonce)...';
  try {
    const r = await solveMintPow($('mint-challenge').value.trim(), Number($('mint-difficulty').value));
    out.textContent = `nonce=${r.nonce}\nhash=${r.hashHex}\nverify with: turn-dag-node mint-verify --nonce ${r.nonce} --hash ${r.hashHex} ...`;
  } catch (e) {
    out.textContent = `failed: ${e.message}`;
  }
});

if (!webauthnSupported()) {
  $('seed-source').textContent = 'WebAuthn unavailable in this browser - passkey wallet disabled';
}
export { hexToBytes };
