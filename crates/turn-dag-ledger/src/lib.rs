//! Per-node serial ledger: the replacement for the distributed DAG.
//!
//! Each node keeps one append-only, hash-chained log of the coins it
//! itself originated. Coins are **bound to their originating node**:
//! a ledger only ever contains elements it minted, so it is the
//! single writer for them and a double spend is rejected atomically
//! at burn/transfer time instead of being detected after the fact
//! by representative voting. There are no bonds, no forks, no
//! quorum, and nothing to merge between nodes: a foreign node's
//! coins are simply absent here (see `LedgerError::ForeignOrUnknown`
//! in effect - unknown elements are not honored).
//!
//! Misbehavior is still *provable*: every entry is signed by the
//! actor, and burn entries are additionally countersigned by the
//! origin node into a [`BurnReceipt`] anyone can verify offline.
//! Two conflicting origin-signed receipts for one element are
//! cryptographic evidence of origin equivocation.

use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use turn_dag_element::ElementId;
use turn_dag_wallet::{HotWallet, PqAddress, PqWallet};

pub fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Burn sink address (transfers to it are ordinary burns; the
/// ledger-level `burn` below is the first-class operation).
pub fn burn_sink() -> PqAddress {
    turn_dag_element::burn_sink_address()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Mint,
    Transfer,
    Burn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedgerStatus {
    Unspent,
    Burned,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub owner: PqAddress,
    pub status: LedgerStatus,
    pub origin: PqAddress,
}

/// One serial log entry. `hash` chains to `prev_hash`, so any
/// rewrite of history breaks every later entry hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub seq: u64,
    pub kind: EntryKind,
    pub element_id: ElementId,
    pub from: Option<PqAddress>,
    pub to: PqAddress,
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
    /// Signature by the actor (miner/owner) over `hash`.
    pub actor_sig: Vec<u8>,
    /// Countersignature by the origin node over `hash`.
    pub origin_sig: Vec<u8>,
}

/// Origin-signed attestation that an element was burned at `seq`.
/// The relay-pass gate checks a receipt's hash against the ledger.
/// Receipts cross process/machine boundaries, so they have a
/// canonical CBOR encoding (`to_cbor`/`from_cbor`, serde).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BurnReceipt {
    pub element_id: ElementId,
    pub entry_hash: [u8; 32],
    pub seq: u64,
    pub origin: PqAddress,
    pub origin_pubkey: Vec<u8>,
    /// Origin signature over `entry_hash`.
    pub origin_sig: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct BurnReceiptWire {
    element_id: serde_bytes::ByteArray<32>,
    entry_hash: serde_bytes::ByteArray<32>,
    seq: u64,
    origin: serde_bytes::ByteArray<20>,
    origin_pubkey: serde_bytes::ByteBuf,
    origin_sig: serde_bytes::ByteBuf,
}

impl From<&BurnReceipt> for BurnReceiptWire {
    fn from(r: &BurnReceipt) -> Self {
        Self {
            element_id: serde_bytes::ByteArray::from(r.element_id.0),
            entry_hash: serde_bytes::ByteArray::from(r.entry_hash),
            seq: r.seq,
            origin: serde_bytes::ByteArray::from(r.origin.0),
            origin_pubkey: serde_bytes::ByteBuf::from(r.origin_pubkey.clone()),
            origin_sig: serde_bytes::ByteBuf::from(r.origin_sig.clone()),
        }
    }
}

impl From<BurnReceiptWire> for BurnReceipt {
    fn from(w: BurnReceiptWire) -> Self {
        Self {
            element_id: ElementId(w.element_id.into_array()),
            entry_hash: w.entry_hash.into_array(),
            seq: w.seq,
            origin: PqAddress(w.origin.into_array()),
            origin_pubkey: w.origin_pubkey.into_vec(),
            origin_sig: w.origin_sig.into_vec(),
        }
    }
}

impl BurnReceipt {
    /// Canonical CBOR encoding (byte strings, not arrays).
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(&BurnReceiptWire::from(self), &mut out)
            .expect("CBOR encoding of a receipt cannot fail");
        out
    }

    /// Decode a CBOR receipt; errors on malformed input, never panics.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, ciborium::de::Error<std::io::Error>> {
        let wire: BurnReceiptWire = ciborium::from_reader(bytes)?;
        Ok(wire.into())
    }

    /// Third-party verification: the receipt really is signed by
    /// the origin key it claims (ledger-existence is checked by
    /// `Ledger::verify_receipt` / `is_burned`).
    pub fn verify_signature(&self) -> bool {
        PqAddress::from_pubkey(&self.origin_pubkey) == self.origin
            && HotWallet::verify(&self.origin_pubkey, &self.entry_hash, &self.origin_sig)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerError {
    DuplicateElement,
    ElementNotFound,
    NotOwner,
    AlreadySpent,
    OriginKeyMismatch,
    AlreadyRedeemed,
}

fn entry_hash(
    seq: u64,
    prev: &[u8; 32],
    kind: EntryKind,
    element_id: &ElementId,
    from: Option<&PqAddress>,
    to: &PqAddress,
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"turn-dag-ledger-entry-v1");
    h.update(seq.to_be_bytes());
    h.update(prev);
    h.update([match kind {
        EntryKind::Mint => 1u8,
        EntryKind::Transfer => 2u8,
        EntryKind::Burn => 3u8,
    }]);
    h.update(element_id.0);
    h.update(from.map(|f| f.0).unwrap_or([0u8; 20]));
    h.update(to.0);
    h.finalize().into()
}

/// One node's ledger. Single-threaded by construction (the node
/// binary owns it); every mutation appends exactly one entry.
pub struct Ledger {
    origin: PqAddress,
    entries: Vec<Entry>,
    elements: HashMap<ElementId, Record>,
    /// Burn entry hashes already redeemed for a relay pass at this
    /// node (origin-side redemption registry: one burn = one pass,
    /// enforced across issuer sessions, not just per-process).
    redeemed: std::collections::HashSet<[u8; 32]>,
}

impl Ledger {
    pub fn new(origin: PqAddress) -> Self {
        Self {
            origin,
            entries: Vec::new(),
            elements: HashMap::new(),
            redeemed: Default::default(),
        }
    }

    pub fn origin(&self) -> PqAddress {
        self.origin
    }
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn record(&self, id: &ElementId) -> Option<&Record> {
        self.elements.get(id)
    }
    pub fn balance(&self, owner: &PqAddress) -> usize {
        self.elements
            .values()
            .filter(|r| r.owner == *owner && r.status == LedgerStatus::Unspent)
            .count()
    }

    fn check_origin_key(&self, origin_key: &HotWallet) -> Result<(), LedgerError> {
        if origin_key.address() != self.origin {
            return Err(LedgerError::OriginKeyMismatch);
        }
        Ok(())
    }

    fn append(
        &mut self,
        kind: EntryKind,
        element_id: ElementId,
        from: Option<PqAddress>,
        to: PqAddress,
        actor: &HotWallet,
        origin_key: &HotWallet,
    ) -> Entry {
        let seq = self.entries.len() as u64;
        let prev_hash = self.entries.last().map(|e| e.hash).unwrap_or([0u8; 32]);
        let hash = entry_hash(seq, &prev_hash, kind, &element_id, from.as_ref(), &to);
        let entry = Entry {
            seq,
            kind,
            element_id,
            from,
            to,
            prev_hash,
            hash,
            actor_sig: actor.sign(&hash),
            origin_sig: origin_key.sign(&hash),
        };
        self.entries.push(entry.clone());
        entry
    }

    /// Register a freshly minted element, bound to this node
    /// forever. PoW verification happens before this is called
    /// (minter layer); the ledger records the result serially.
    pub fn mint(
        &mut self,
        element_id: ElementId,
        owner: &HotWallet,
        origin_key: &HotWallet,
    ) -> Result<Entry, LedgerError> {
        self.check_origin_key(origin_key)?;
        if self.elements.contains_key(&element_id) {
            return Err(LedgerError::DuplicateElement);
        }
        let entry = self.append(
            EntryKind::Mint,
            element_id,
            None,
            owner.address(),
            owner,
            origin_key,
        );
        self.elements.insert(
            element_id,
            Record {
                owner: owner.address(),
                status: LedgerStatus::Unspent,
                origin: self.origin,
            },
        );
        Ok(entry)
    }

    /// Transfer an unspent element to a new owner. Atomic: any
    /// second spend of the same element fails with AlreadySpent.
    pub fn transfer(
        &mut self,
        element_id: ElementId,
        from: &HotWallet,
        to: PqAddress,
        origin_key: &HotWallet,
    ) -> Result<Entry, LedgerError> {
        self.check_origin_key(origin_key)?;
        let rec = self
            .elements
            .get(&element_id)
            .ok_or(LedgerError::ElementNotFound)?;
        if rec.owner != from.address() {
            return Err(LedgerError::NotOwner);
        }
        if rec.status != LedgerStatus::Unspent {
            return Err(LedgerError::AlreadySpent);
        }
        let entry = self.append(
            EntryKind::Transfer,
            element_id,
            Some(from.address()),
            to,
            from,
            origin_key,
        );
        self.elements.get_mut(&element_id).unwrap().owner = to;
        Ok(entry)
    }

    /// Burn an unspent element and return the origin-signed
    /// receipt (the relay-pass gate's input). Atomic, like transfer.
    pub fn burn(
        &mut self,
        element_id: ElementId,
        owner: &HotWallet,
        origin_key: &HotWallet,
    ) -> Result<BurnReceipt, LedgerError> {
        self.check_origin_key(origin_key)?;
        let rec = self
            .elements
            .get(&element_id)
            .ok_or(LedgerError::ElementNotFound)?;
        if rec.owner != owner.address() {
            return Err(LedgerError::NotOwner);
        }
        if rec.status != LedgerStatus::Unspent {
            return Err(LedgerError::AlreadySpent);
        }
        let entry = self.append(
            EntryKind::Burn,
            element_id,
            Some(owner.address()),
            burn_sink(),
            owner,
            origin_key,
        );
        self.elements.get_mut(&element_id).unwrap().status = LedgerStatus::Burned;
        Ok(BurnReceipt {
            element_id,
            entry_hash: entry.hash,
            seq: entry.seq,
            origin: self.origin,
            origin_pubkey: origin_key.public_key().to_vec(),
            origin_sig: entry.origin_sig.clone(),
        })
    }

    /// True iff this burn was already redeemed for a relay pass.
    pub fn is_redeemed(&self, entry_hash: &[u8; 32]) -> bool {
        self.redeemed.contains(entry_hash)
    }

    /// Consume a burn for relay-pass issuance. Fails with
    /// `AlreadySpent` if the burn does not exist here and with
    /// `AlreadyRedeemed` on any second redemption.
    pub fn mark_redeemed(&mut self, entry_hash: &[u8; 32]) -> Result<(), LedgerError> {
        if !self.is_burned(entry_hash) {
            return Err(LedgerError::ElementNotFound);
        }
        if !self.redeemed.insert(*entry_hash) {
            return Err(LedgerError::AlreadyRedeemed);
        }
        Ok(())
    }

    /// True iff `hash` is a burn entry in this ledger (relay-pass gate).
    pub fn is_burned(&self, entry_hash: &[u8; 32]) -> bool {
        self.entries
            .iter()
            .any(|e| e.kind == EntryKind::Burn && &e.hash == entry_hash)
    }

    /// Full receipt check against this ledger plus signature.
    pub fn verify_receipt(&self, receipt: &BurnReceipt) -> bool {
        receipt.verify_signature()
            && receipt.origin == self.origin
            && self.is_burned(&receipt.entry_hash)
            && self
                .entries
                .iter()
                .any(|e| e.hash == receipt.entry_hash && e.seq == receipt.seq)
    }

    /// Verify the hash chain end to end (tamper evidence for audits).
    pub fn verify_chain(&self) -> bool {
        let mut prev = [0u8; 32];
        for (i, e) in self.entries.iter().enumerate() {
            if e.seq != i as u64 || e.prev_hash != prev {
                return false;
            }
            if e.hash
                != entry_hash(
                    e.seq,
                    &e.prev_hash,
                    e.kind,
                    &e.element_id,
                    e.from.as_ref(),
                    &e.to,
                )
            {
                return false;
            }
            prev = e.hash;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wallet(seed: u8) -> HotWallet {
        HotWallet::generate(&[seed; 32]).unwrap()
    }

    #[test]
    fn mint_transfer_burn_serial_flow() {
        let origin = wallet(1);
        let alice = wallet(2);
        let bob = wallet(3);
        let mut l = Ledger::new(origin.address());
        let eid = ElementId([42u8; 32]);
        l.mint(eid, &alice, &origin).unwrap();
        assert_eq!(l.balance(&alice.address()), 1);
        assert_eq!(l.record(&eid).unwrap().origin, origin.address());
        l.transfer(eid, &alice, bob.address(), &origin).unwrap();
        assert_eq!(l.balance(&alice.address()), 0);
        assert_eq!(l.balance(&bob.address()), 1);
        let receipt = l.burn(eid, &bob, &origin).unwrap();
        assert!(l.verify_receipt(&receipt));
        assert!(receipt.verify_signature());
        assert!(l.is_burned(&receipt.entry_hash));
        assert!(l.verify_chain());
        assert_eq!(l.entries().len(), 3);
        assert_eq!(l.entries()[1].prev_hash, l.entries()[0].hash);
    }

    #[test]
    fn double_spend_is_atomic_rejection_not_a_fork() {
        let origin = wallet(1);
        let alice = wallet(2);
        let mut l = Ledger::new(origin.address());
        let eid = ElementId([7u8; 32]);
        l.mint(eid, &alice, &origin).unwrap();
        l.burn(eid, &alice, &origin).unwrap();
        // Every second spend fails at once; nothing to vote on.
        assert_eq!(l.burn(eid, &alice, &origin), Err(LedgerError::AlreadySpent));
        assert_eq!(
            l.transfer(eid, &alice, wallet(9).address(), &origin),
            Err(LedgerError::AlreadySpent)
        );
        assert_eq!(l.entries().len(), 2, "rejected spends are not logged");
    }

    #[test]
    fn foreign_coins_are_absent_and_wrong_owner_rejected() {
        let origin_a = wallet(1);
        let origin_b = wallet(5);
        let alice = wallet(2);
        let mut a = Ledger::new(origin_a.address());
        let mut b = Ledger::new(origin_b.address());
        let eid = ElementId([8u8; 32]);
        a.mint(eid, &alice, &origin_a).unwrap();
        // Node B never originated this coin: it cannot burn it.
        assert_eq!(
            b.burn(eid, &alice, &origin_b),
            Err(LedgerError::ElementNotFound)
        );
        // Only the current owner may transfer/burn at the origin.
        assert_eq!(
            a.transfer(eid, &wallet(9), wallet(3).address(), &origin_a),
            Err(LedgerError::NotOwner)
        );
        // Tampered receipt does not verify.
        let mut receipt = a.burn(eid, &alice, &origin_a).unwrap();
        receipt.entry_hash[0] ^= 1;
        assert!(!a.verify_receipt(&receipt));
        assert!(!receipt.verify_signature());
    }

    #[test]
    fn burn_receipt_cbor_roundtrip() {
        let origin = wallet(1);
        let alice = wallet(2);
        let mut l = Ledger::new(origin.address());
        let eid = ElementId([42u8; 32]);
        l.mint(eid, &alice, &origin).unwrap();
        let receipt = l.burn(eid, &alice, &origin).unwrap();
        let bytes = receipt.to_cbor();
        let back = BurnReceipt::from_cbor(&bytes).unwrap();
        assert_eq!(back, receipt);
        assert!(back.verify_signature());
        // Malformed input is an error, never a panic.
        assert!(BurnReceipt::from_cbor(&bytes[..bytes.len() / 2]).is_err());
        assert!(BurnReceipt::from_cbor(b"not cbor at all").is_err());
        // Byte-string encoding keeps it close to raw field sizes
        // (pubkey 1952 + sig 3309 dominate; framing adds only bytes).
        assert!(bytes.len() < 1952 + 3309 + 200, "cbor len {}", bytes.len());
    }

    #[test]
    fn origin_key_must_match_ledger_origin() {
        let origin = wallet(1);
        let alice = wallet(2);
        let impostor = wallet(9);
        let mut l = Ledger::new(origin.address());
        assert_eq!(
            l.mint(ElementId([1u8; 32]), &alice, &impostor),
            Err(LedgerError::OriginKeyMismatch)
        );
    }
}
