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

impl BurnReceipt {
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
}

impl Ledger {
    pub fn new(origin: PqAddress) -> Self {
        Self {
            origin,
            entries: Vec::new(),
            elements: HashMap::new(),
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
