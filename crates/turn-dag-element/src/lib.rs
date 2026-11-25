//! Indivisible mined elements. 1 element = 1 indivisible unit; elements cannot be subdivided.

use sha2::{Digest as _, Sha256};
use sha3::Sha3_256;
use std::collections::HashSet;
pub use turn_dag_wallet::PqAddress;

/// SHA256(challenge || nonce.to_be_bytes() || miner_address_bytes[20])
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ElementId(pub [u8; 32]);

impl ElementId {
    pub fn derive(challenge: &[u8], nonce: u64, miner: &PqAddress) -> Self {
        let mut h = Sha256::new();
        h.update(challenge);
        h.update(nonce.to_be_bytes());
        h.update(miner.0);
        Self(h.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElementStatus {
    Unspent,
    Spent,
    Burned,
    Bonded,
    Frozen,
    Orphaned,
    InFlight,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Element {
    pub id: ElementId,
    pub owner: PqAddress,
    pub status: ElementStatus,
    pub mint_epoch: u64,
}

/// Burn sink: SHA3-256("burn") truncated to the first 20 bytes as an address.
pub fn burn_sink_address() -> PqAddress {
    use sha3::Digest as _;
    let h = Sha3_256::digest(b"burn");
    let mut b = [0u8; 20];
    b.copy_from_slice(&h[..20]);
    PqAddress(b)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub element_id: ElementId,
    pub from_pubkey: Vec<u8>,
    pub to_address: PqAddress,
    pub nonce: u64,
}

impl Transfer {
    /// Canonical encoding, fixed order, big-endian:
    /// element_id[32] || from_pubkey_len:u32 || from_pubkey || to_address[20] || nonce:u64
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + self.from_pubkey.len() + 20 + 8);
        out.extend_from_slice(&self.element_id.0);
        out.extend_from_slice(&(self.from_pubkey.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.from_pubkey);
        out.extend_from_slice(&self.to_address.0);
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out
    }
    /// SHA3-256 of the canonical encoding; this is what gets signed.
    pub fn hash(&self) -> [u8; 32] {
        use sha3::Digest as _;
        Sha3_256::digest(self.canonical_bytes()).into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransferError {
    ElementNotFound,
    NotUnspent,
    OwnerMismatch,
    BadNonce,
    NonceUsed,
}

pub fn validate_transfer(
    element: Option<&Element>,
    transfer: &Transfer,
) -> Result<(), TransferError> {
    validate_transfer_with_used(element, transfer, &HashSet::new())
}

pub fn validate_transfer_with_used(
    element: Option<&Element>,
    transfer: &Transfer,
    used_nonces: &HashSet<u64>,
) -> Result<(), TransferError> {
    let el = element.ok_or(TransferError::ElementNotFound)?;
    if el.id != transfer.element_id {
        return Err(TransferError::ElementNotFound);
    }
    if el.status != ElementStatus::Unspent {
        return Err(TransferError::NotUnspent);
    }
    if PqAddress::from_pubkey(&transfer.from_pubkey) != el.owner {
        return Err(TransferError::OwnerMismatch);
    }
    // First (and only valid) spend nonce is 0.
    if transfer.nonce != 0 {
        return Err(TransferError::BadNonce);
    }
    if used_nonces.contains(&transfer.nonce) {
        return Err(TransferError::NonceUsed);
    }
    Ok(())
}

/// On success the old record is Spent/Burned and a new record with the
/// same id and the new owner is returned (provenance preserved).
pub fn apply_transfer(
    element: &Element,
    transfer: &Transfer,
    used_nonces: &HashSet<u64>,
) -> Result<Element, TransferError> {
    validate_transfer_with_used(Some(element), transfer, used_nonces)?;
    let burned = transfer.to_address == burn_sink_address();
    Ok(Element {
        id: element.id,
        owner: transfer.to_address,
        status: if burned {
            ElementStatus::Burned
        } else {
            ElementStatus::Unspent
        },
        mint_epoch: element.mint_epoch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn addr(b: u8) -> PqAddress {
        PqAddress([b; 20])
    }
    #[test]
    fn id_deterministic_and_sensitive() {
        let a = ElementId::derive(b"chal", 7, &addr(1));
        assert_eq!(a, ElementId::derive(b"chal", 7, &addr(1)));
        assert_ne!(a, ElementId::derive(b"chal", 8, &addr(1)));
        assert_ne!(a, ElementId::derive(b"chal", 7, &addr(2)));
        assert_ne!(a, ElementId::derive(b"chal2", 7, &addr(1)));
    }
    #[test]
    fn burn_sink() {
        use sha3::Digest as _;
        let h = Sha3_256::digest(b"burn");
        assert_eq!(burn_sink_address().0.as_slice(), &h[..20]);
    }
    fn fixture() -> (Element, Vec<u8>) {
        let pk = vec![9u8; 32];
        let owner = PqAddress::from_pubkey(&pk);
        (
            Element {
                id: ElementId([3u8; 32]),
                owner,
                status: ElementStatus::Unspent,
                mint_epoch: 4,
            },
            pk,
        )
    }
    #[test]
    fn hash_deterministic_and_nonce_rejected() {
        let (el, pk) = fixture();
        let tx = Transfer {
            element_id: el.id,
            from_pubkey: pk.clone(),
            to_address: addr(5),
            nonce: 0,
        };
        assert_eq!(tx.hash(), tx.clone().hash());
        assert_eq!(validate_transfer(Some(&el), &tx), Ok(()));
        let bad = Transfer {
            nonce: 1,
            ..tx.clone()
        };
        assert_eq!(
            validate_transfer(Some(&el), &bad),
            Err(TransferError::BadNonce)
        );
        let wrong = Transfer {
            from_pubkey: vec![1u8; 32],
            ..tx
        };
        assert_eq!(
            validate_transfer(Some(&el), &wrong),
            Err(TransferError::OwnerMismatch)
        );
        assert_eq!(
            validate_transfer(None, &wrong),
            Err(TransferError::ElementNotFound)
        );
    }
    #[test]
    fn burn_marks_burned() {
        let (el, pk) = fixture();
        let tx = Transfer {
            element_id: el.id,
            from_pubkey: pk,
            to_address: burn_sink_address(),
            nonce: 0,
        };
        let next = apply_transfer(&el, &tx, &HashSet::new()).unwrap();
        assert_eq!(next.status, ElementStatus::Burned);
        assert_eq!(next.id, el.id);
    }
}
