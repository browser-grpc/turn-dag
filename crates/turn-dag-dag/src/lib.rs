//! Block-lattice DAG + representative voting + bond + fraud proof / slash.
//! Spec: docs/bond-contract-fraud-proof-spec.pdf sections 2-6, 9, 10.
//! NOTE: no TURN allocation on local view alone - burn must reach
//! confirmation weight (>=67% sustained one 5s epoch) first; the 1-5s
//! latency tradeoff is intentional (spec section 6.3).

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};
pub use turn_dag_element::{ElementId, ElementStatus};
pub use turn_dag_wallet::{HotWallet, PqAddress, PqWallet};

pub const ZERO_HASH: [u8; 32] = [0u8; 32];
pub const BOND_SIZE: usize = 5;
/// 24h timelock modelled deterministically as epoch (tick) count: 24h / 5s.
pub const BOND_RELEASE_EPOCHS: u64 = 17_280;
pub const FINALITY_PERCENT: u64 = 67;

pub fn bond_pseudo_account(owner: &PqAddress) -> PqAddress {
    let mut h = Sha3_256::new();
    h.update(b"bond");
    h.update(owner.0);
    let d = h.finalize();
    let mut b = [0u8; 20];
    b.copy_from_slice(&d[..20]);
    PqAddress(b)
}
pub fn burn_sink() -> PqAddress {
    turn_dag_element::burn_sink_address()
}

// ---------- Block ----------
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BlockType {
    Mint,
    Send,
    Receive,
    Burn,
    BondLock,
    BondRelease,
    SlashClaim,
}
impl BlockType {
    pub fn code(self) -> u8 {
        match self {
            Self::Mint => 0,
            Self::Send => 1,
            Self::Receive => 2,
            Self::Burn => 3,
            Self::BondLock => 4,
            Self::BondRelease => 5,
            Self::SlashClaim => 6,
        }
    }
    pub fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            0 => Self::Mint,
            1 => Self::Send,
            2 => Self::Receive,
            3 => Self::Burn,
            4 => Self::BondLock,
            5 => Self::BondRelease,
            6 => Self::SlashClaim,
            _ => return None,
        })
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Send => "send",
            Self::Receive => "receive",
            Self::Burn => "burn",
            Self::BondLock => "bond_lock",
            Self::BondRelease => "bond_release",
            Self::SlashClaim => "slash_claim",
        }
    }
    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s {
            "mint" => Self::Mint,
            "send" => Self::Send,
            "receive" => Self::Receive,
            "burn" => Self::Burn,
            "bond_lock" => Self::BondLock,
            "bond_release" => Self::BondRelease,
            "slash_claim" => Self::SlashClaim,
            _ => return None,
        })
    }
    fn is_spend(self) -> bool {
        matches!(
            self,
            Self::Send | Self::Burn | Self::BondLock | Self::BondRelease
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub version: u8,
    pub block_type: BlockType,
    pub account: PqAddress,
    pub previous: [u8; 32],
    pub link_parent: [u8; 32],
    pub element_id: ElementId,
    pub to_address: PqAddress,
    pub nonce: u64,
    pub epoch: u64,
    pub work: Option<Vec<u8>>,
    pub issued_at: u64,
}
impl Block {
    pub fn new(
        block_type: BlockType,
        account: PqAddress,
        previous: [u8; 32],
        link_parent: [u8; 32],
        element_id: ElementId,
        to_address: PqAddress,
    ) -> Self {
        Self {
            version: 1,
            block_type,
            account,
            previous,
            link_parent,
            element_id,
            to_address,
            nonce: 0,
            epoch: 0,
            work: None,
            issued_at: 0,
        }
    }
    /// Canonical encoding: fixed order, BE ints, explicit null for work.
    /// version|type|account|previous|link_parent|element_id|to|nonce|epoch|work|issued_at
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut o = Vec::new();
        o.push(self.version);
        o.push(self.block_type.code());
        o.extend_from_slice(&self.account.0);
        o.extend_from_slice(&self.previous);
        o.extend_from_slice(&self.link_parent);
        o.extend_from_slice(&self.element_id.0);
        o.extend_from_slice(&self.to_address.0);
        o.extend_from_slice(&self.nonce.to_be_bytes());
        o.extend_from_slice(&self.epoch.to_be_bytes());
        match &self.work {
            None => o.push(0),
            Some(w) => {
                o.push(1);
                o.extend_from_slice(&(w.len() as u32).to_be_bytes());
                o.extend_from_slice(w);
            }
        }
        o.extend_from_slice(&self.issued_at.to_be_bytes());
        o
    }
    pub fn canonical_hash(&self) -> [u8; 32] {
        Sha3_256::digest(self.canonical_bytes()).into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedBlock {
    pub block: Block,
    pub signature: Vec<u8>,
    pub pubkey: Vec<u8>,
}
impl SignedBlock {
    /// block_hash = SHA3-256(canonical(block) || signature)
    pub fn block_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(self.block.canonical_bytes());
        h.update(&self.signature);
        h.finalize().into()
    }
    pub fn verify_signature(&self) -> bool {
        HotWallet::verify(&self.pubkey, &self.block.canonical_hash(), &self.signature)
    }
}
pub fn sign_block(block: Block, wallet: &HotWallet) -> SignedBlock {
    let sig = wallet.sign(&block.canonical_hash());
    SignedBlock {
        block,
        signature: sig,
        pubkey: wallet.public_key().to_vec(),
    }
}

// ---------- hex / base64 helpers ----------
pub fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.is_ascii() || s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
fn hex32(s: &str) -> Option<[u8; 32]> {
    let v = hex_decode(s)?;
    v.try_into().ok()
}
fn hex20(s: &str) -> Option<[u8; 20]> {
    let v = hex_decode(s)?;
    v.try_into().ok()
}
fn b64_encode(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

// ---------- Storage trait (SQLite can swap in later) ----------
pub trait Storage {
    fn put(&mut self, hash: [u8; 32], block: SignedBlock);
    fn get(&self, hash: &[u8; 32]) -> Option<&SignedBlock>;
    fn contains(&self, hash: &[u8; 32]) -> bool;
    fn hashes(&self) -> Vec<[u8; 32]>;
}
#[derive(Default)]
pub struct InMemoryStorage {
    map: HashMap<[u8; 32], SignedBlock>,
}
impl Storage for InMemoryStorage {
    fn put(&mut self, hash: [u8; 32], block: SignedBlock) {
        self.map.insert(hash, block);
    }
    fn get(&self, hash: &[u8; 32]) -> Option<&SignedBlock> {
        self.map.get(hash)
    }
    fn contains(&self, hash: &[u8; 32]) -> bool {
        self.map.contains_key(hash)
    }
    fn hashes(&self) -> Vec<[u8; 32]> {
        self.map.keys().copied().collect()
    }
}

// ---------- SQLite storage (spec §9.3 blocks table) ----------
fn encode_signed(s: &SignedBlock) -> Vec<u8> {
    let mut o = s.block.canonical_bytes();
    o.extend_from_slice(&(s.signature.len() as u32).to_be_bytes());
    o.extend_from_slice(&s.signature);
    o.extend_from_slice(&(s.pubkey.len() as u32).to_be_bytes());
    o.extend_from_slice(&s.pubkey);
    o
}
fn decode_signed(b: &[u8]) -> Option<SignedBlock> {
    // canonical layout: 1+1+20+32+32+32+20+8+8 + work-tag(+len) + 8 issued_at
    if b.len() < 162 {
        return None;
    }
    let version = b[0];
    let block_type = BlockType::from_code(b[1])?;
    let rd20 = |i: usize| -> PqAddress {
        let mut a = [0u8; 20];
        a.copy_from_slice(&b[i..i + 20]);
        PqAddress(a)
    };
    let rd32 = |i: usize| -> [u8; 32] {
        let mut a = [0u8; 32];
        a.copy_from_slice(&b[i..i + 32]);
        a
    };
    let rd64 =
        |i: usize| -> Option<u64> { Some(u64::from_be_bytes(b.get(i..i + 8)?.try_into().ok()?)) };
    let account = rd20(2);
    let previous = rd32(22);
    let link_parent = rd32(54);
    let element_id = ElementId(rd32(86));
    let to_address = rd20(118);
    let nonce = rd64(138)?;
    let epoch = rd64(146)?;
    let mut i = 154;
    let work = match b[i] {
        0 => {
            i += 1;
            None
        }
        1 => {
            let len = u32::from_be_bytes(b[i + 1..i + 5].try_into().ok()?) as usize;
            i += 5;
            let w = b.get(i..i + len)?.to_vec();
            i += len;
            Some(w)
        }
        _ => return None,
    };
    let issued_at = rd64(i)?;
    i += 8;
    let sig_len = u32::from_be_bytes(b.get(i..i + 4)?.try_into().ok()?) as usize;
    i += 4;
    let signature = b.get(i..i + sig_len)?.to_vec();
    i += sig_len;
    let pk_len = u32::from_be_bytes(b.get(i..i + 4)?.try_into().ok()?) as usize;
    i += 4;
    let pubkey = b.get(i..i + pk_len)?.to_vec();
    Some(SignedBlock {
        block: Block {
            version,
            block_type,
            account,
            previous,
            link_parent,
            element_id,
            to_address,
            nonce,
            epoch,
            work,
            issued_at,
        },
        signature,
        pubkey,
    })
}

/// SQLite-backed `Storage`: `blocks(block_hash PK, blob)` (spec §9.3 sketch).
/// Decoded blocks are cached so `get` can return references per the trait.
pub struct SqliteStorage {
    conn: std::cell::RefCell<rusqlite::Connection>,
    cache: std::cell::RefCell<HashMap<[u8; 32], SignedBlock>>,
}
impl SqliteStorage {
    pub fn open(path: &str) -> Result<Self, DagError> {
        let conn = rusqlite::Connection::open(path).map_err(|_| DagError::BadPrevious)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS blocks(block_hash BLOB PRIMARY KEY, blob BLOB NOT NULL);",
        )
        .map_err(|_| DagError::BadPrevious)?;
        Ok(Self {
            conn: std::cell::RefCell::new(conn),
            cache: std::cell::RefCell::new(HashMap::new()),
        })
    }
    pub fn in_memory() -> Result<Self, DagError> {
        Self::open(":memory:")
    }
}
impl Storage for SqliteStorage {
    fn put(&mut self, hash: [u8; 32], block: SignedBlock) {
        let blob = encode_signed(&block);
        let _ = self.conn.borrow().execute(
            "INSERT OR REPLACE INTO blocks(block_hash, blob) VALUES (?1, ?2)",
            rusqlite::params![&hash[..], &blob],
        );
        self.cache.borrow_mut().insert(hash, block);
    }
    fn get(&self, hash: &[u8; 32]) -> Option<&SignedBlock> {
        if !self.cache.borrow().contains_key(hash) {
            let blob: Option<Vec<u8>> = self
                .conn
                .borrow()
                .query_row(
                    "SELECT blob FROM blocks WHERE block_hash = ?1",
                    rusqlite::params![&hash[..]],
                    |r| r.get(0),
                )
                .ok();
            if let Some(b) = blob {
                if let Some(sb) = decode_signed(&b) {
                    self.cache.borrow_mut().insert(*hash, sb);
                }
            }
        }
        // SAFETY of borrow pattern: cache RefCell borrow is returned via a
        // leaked-then-reborrowed reference tied to &self lifetime by trait.
        let cache = self.cache.borrow();
        let ptr = cache.get(hash)? as *const SignedBlock;
        drop(cache);
        // The cache entry outlives this call (entries are never evicted).
        unsafe { Some(&*ptr) }
    }
    fn contains(&self, hash: &[u8; 32]) -> bool {
        if self.cache.borrow().contains_key(hash) {
            return true;
        }
        self.conn
            .borrow()
            .query_row(
                "SELECT 1 FROM blocks WHERE block_hash = ?1",
                rusqlite::params![&hash[..]],
                |r| r.get::<_, i64>(0),
            )
            .is_ok()
    }
    fn hashes(&self) -> Vec<[u8; 32]> {
        let conn = self.conn.borrow();
        let mut stmt = match conn.prepare("SELECT block_hash FROM blocks") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0));
        match rows {
            Ok(it) => it
                .filter_map(|r| r.ok())
                .filter_map(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

// ---------- Errors / outcomes ----------
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DagError {
    NonCanonical,
    BadSignature,
    AddressMismatch,
    Blacklisted,
    BadPrevious,
    NotElementOwner,
    AlreadySpent,
    NoBond,
    UnknownBlock,
    UnknownProof,
    InvalidSlashSplit,
    InsufficientBond,
    BadBlockTypeRule,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InsertOutcome {
    Inserted { hash: [u8; 32], fork: bool },
    Duplicate { hash: [u8; 32] },
    PendingMissingParent { hash: [u8; 32] },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockStatus {
    Pending,
    Confirmed,
    Orphaned,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElementRecord {
    pub owner: PqAddress,
    pub status: ElementStatus,
    pub bonded_by: Option<PqAddress>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ForkId {
    pub account: PqAddress,
    pub previous: [u8; 32],
    pub element_id: ElementId,
}
impl From<&Block> for ForkId {
    fn from(b: &Block) -> Self {
        Self {
            account: b.account,
            previous: b.previous,
            element_id: b.element_id,
        }
    }
}

// ---------- Spent-set CRDT: grow-only, union / weight-max merge ----------
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpentEntry {
    pub winning_hash: [u8; 32],
    pub weight: u64,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpentSet {
    pub entries: HashMap<ElementId, SpentEntry>,
    /// Fork evidence retained forever: element -> all conflicting hashes.
    pub conflicts: HashMap<ElementId, HashSet<[u8; 32]>>,
}
impl SpentSet {
    pub fn observe(&mut self, element_id: ElementId, hash: [u8; 32], weight: u64) {
        self.conflicts.entry(element_id).or_default().insert(hash);
        match self.entries.get(&element_id) {
            None => {
                self.entries.insert(
                    element_id,
                    SpentEntry {
                        winning_hash: hash,
                        weight,
                    },
                );
            }
            Some(e) if weight > e.weight || (weight == e.weight && hash < e.winning_hash) => {
                self.entries.insert(
                    element_id,
                    SpentEntry {
                        winning_hash: hash,
                        weight,
                    },
                );
            }
            _ => {}
        }
    }
    /// Union with weight-max per element; deterministic tie-break (smaller hash).
    pub fn merge(&mut self, other: &SpentSet) {
        for (id, hashes) in &other.conflicts {
            self.conflicts
                .entry(*id)
                .or_default()
                .extend(hashes.iter().copied());
        }
        for (id, e) in &other.entries {
            self.observe(*id, e.winning_hash, e.weight);
            // ensure the source winner itself is in conflict evidence
            self.conflicts
                .entry(*id)
                .or_default()
                .insert(e.winning_hash);
        }
    }
    pub fn winner(&self, id: &ElementId) -> Option<&SpentEntry> {
        self.entries.get(id)
    }
}

// ---------- Release / slash records ----------
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseRecord {
    pub owner: PqAddress,
    pub element_id: ElementId,
    pub block_hash: [u8; 32],
    pub unlock_epoch: u64,
    pub cancelled: bool,
    pub executed: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashOutcome {
    pub proof_hash: [u8; 32],
    pub owner: PqAddress,
    pub reporter: PqAddress,
    pub bounty_element: ElementId,
    pub burned_elements: Vec<ElementId>,
}
pub fn validate_slash_split(bounty: usize, burned: usize) -> bool {
    bounty == 1 && burned == 4
}

// ---------- Dag ----------
pub struct Dag<S: Storage = InMemoryStorage> {
    storage: S,
    statuses: HashMap<[u8; 32], BlockStatus>,
    sustain: HashMap<[u8; 32], u64>,
    epoch: u64,
    pending_missing: HashMap<[u8; 32], SignedBlock>,
    elements: HashMap<ElementId, ElementRecord>,
    delegations: HashMap<PqAddress, PqAddress>,
    online_reps: HashSet<PqAddress>,
    votes: HashMap<ForkId, HashMap<PqAddress, [u8; 32]>>,
    equivocated: HashMap<ForkId, HashSet<PqAddress>>,
    pub spent_set: SpentSet,
    releases: Vec<ReleaseRecord>,
    blacklist_pubkeys: HashSet<Vec<u8>>,
    blacklist_addrs: HashSet<PqAddress>,
    frozen: HashSet<PqAddress>,
    slashed: HashSet<PqAddress>,
    proofs: HashMap<[u8; 32], FraudProof>,
    proof_owner: HashMap<[u8; 32], (PqAddress, Vec<u8>)>,
    slash_votes: HashMap<[u8; 32], HashSet<PqAddress>>,
    slash_outcomes: HashMap<[u8; 32], SlashOutcome>,
    fork_snapshots: HashMap<ForkId, PqAddress>,
}
impl Default for Dag<InMemoryStorage> {
    fn default() -> Self {
        Self::new()
    }
}
impl Dag<InMemoryStorage> {
    pub fn new() -> Self {
        Self::with_storage(InMemoryStorage::default())
    }
}
impl<S: Storage> Dag<S> {
    pub fn with_storage(storage: S) -> Self {
        Self {
            storage,
            statuses: HashMap::new(),
            sustain: HashMap::new(),
            epoch: 0,
            pending_missing: HashMap::new(),
            elements: HashMap::new(),
            delegations: HashMap::new(),
            online_reps: HashSet::new(),
            votes: HashMap::new(),
            equivocated: HashMap::new(),
            spent_set: SpentSet::default(),
            releases: Vec::new(),
            blacklist_pubkeys: HashSet::new(),
            blacklist_addrs: HashSet::new(),
            frozen: HashSet::new(),
            slashed: HashSet::new(),
            proofs: HashMap::new(),
            proof_owner: HashMap::new(),
            slash_votes: HashMap::new(),
            slash_outcomes: HashMap::new(),
            fork_snapshots: HashMap::new(),
        }
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn get_block(&self, hash: &[u8; 32]) -> Option<&SignedBlock> {
        self.storage.get(hash)
    }
    pub fn block_status(&self, hash: &[u8; 32]) -> Option<BlockStatus> {
        self.statuses.get(hash).copied()
    }
    pub fn is_confirmed(&self, hash: &[u8; 32]) -> bool {
        self.block_status(hash) == Some(BlockStatus::Confirmed)
    }
    pub fn register_element(&mut self, id: ElementId, owner: PqAddress) {
        self.elements.entry(id).or_insert(ElementRecord {
            owner,
            status: ElementStatus::Unspent,
            bonded_by: None,
        });
    }
    pub fn element(&self, id: &ElementId) -> Option<&ElementRecord> {
        self.elements.get(id)
    }
    pub fn is_blacklisted_pubkey(&self, pk: &[u8]) -> bool {
        self.blacklist_pubkeys.contains(pk)
    }
    pub fn is_blacklisted_addr(&self, a: &PqAddress) -> bool {
        self.blacklist_addrs.contains(a)
    }
    pub fn is_frozen(&self, a: &PqAddress) -> bool {
        self.frozen.contains(a)
    }
    pub fn releases(&self) -> &[ReleaseRecord] {
        &self.releases
    }
    pub fn slash_outcome(&self, h: &[u8; 32]) -> Option<&SlashOutcome> {
        self.slash_outcomes.get(h)
    }
    fn siblings(&self, fid: &ForkId) -> Vec<[u8; 32]> {
        self.storage
            .hashes()
            .into_iter()
            .filter(|h| {
                self.storage
                    .get(h)
                    .map(|b| ForkId::from(&b.block) == *fid)
                    .unwrap_or(false)
            })
            .collect()
    }
    fn has_child(&self, hash: &[u8; 32], account: Option<PqAddress>) -> bool {
        self.storage.hashes().iter().any(|h| {
            self.storage
                .get(h)
                .map(|b| {
                    b.block.previous == *hash
                        && account.map(|a| b.block.account == a).unwrap_or(true)
                })
                .unwrap_or(false)
        })
    }
    pub fn tips(&self) -> Vec<[u8; 32]> {
        let mut t: Vec<_> = self
            .storage
            .hashes()
            .into_iter()
            .filter(|h| !self.has_child(h, None))
            .collect();
        t.sort();
        t
    }
    /// Prefer confirmed, then high cumulative weight, then not-own; deterministic.
    pub fn select_link_parent(&self, for_account: &PqAddress) -> Option<[u8; 32]> {
        let mut cands: Vec<[u8; 32]> = self
            .tips()
            .into_iter()
            .filter(|h| {
                self.storage
                    .get(h)
                    .map(|b| b.block.account != *for_account)
                    .unwrap_or(false)
            })
            .collect();
        if cands.is_empty() {
            return None;
        }
        cands.sort_by(|a, b| {
            let ca = self.is_confirmed(a);
            let cb = self.is_confirmed(b);
            cb.cmp(&ca)
                .then_with(|| self.cumulative_weight(b).cmp(&self.cumulative_weight(a)))
                .then_with(|| a.cmp(b))
        });
        cands.first().copied()
    }
    pub fn account_tip(&self, account: &PqAddress) -> Option<[u8; 32]> {
        let mut cands: Vec<[u8; 32]> = self
            .storage
            .hashes()
            .into_iter()
            .filter(|h| {
                self.storage
                    .get(h)
                    .map(|b| b.block.account == *account)
                    .unwrap_or(false)
                    && !self.has_child(h, Some(*account))
            })
            .collect();
        cands.sort_by(|a, b| {
            self.is_confirmed(b)
                .cmp(&self.is_confirmed(a))
                .then_with(|| self.cumulative_weight(b).cmp(&self.cumulative_weight(a)))
                .then_with(|| a.cmp(b))
        });
        cands.first().copied()
    }

    // ----- insert_block: ordered fail-closed validation (spec 9.4) -----
    pub fn insert_block(&mut self, signed: SignedBlock) -> Result<InsertOutcome, DagError> {
        let hash = signed.block_hash();
        if signed.block.version != 1 {
            return Err(DagError::NonCanonical);
        }
        if self.storage.contains(&hash) {
            return Ok(InsertOutcome::Duplicate { hash });
        }
        if self.pending_missing.contains_key(&hash) {
            return Ok(InsertOutcome::PendingMissingParent { hash });
        }
        let prev_missing =
            signed.block.previous != ZERO_HASH && !self.storage.contains(&signed.block.previous);
        let link_missing = signed.block.link_parent != ZERO_HASH
            && !self.storage.contains(&signed.block.link_parent);
        if prev_missing || link_missing {
            self.pending_missing.insert(hash, signed);
            return Ok(InsertOutcome::PendingMissingParent { hash });
        }
        if self.blacklist_pubkeys.contains(&signed.pubkey)
            || self.blacklist_addrs.contains(&signed.block.account)
        {
            return Err(DagError::Blacklisted);
        }
        if PqAddress::from_pubkey(&signed.pubkey) != signed.block.account {
            return Err(DagError::AddressMismatch);
        }
        if !signed.verify_signature() {
            return Err(DagError::BadSignature);
        }
        if signed.block.previous != ZERO_HASH {
            let prev = self
                .storage
                .get(&signed.block.previous)
                .ok_or(DagError::BadPrevious)?;
            if prev.block.account != signed.block.account
                && signed.block.block_type != BlockType::SlashClaim
            {
                return Err(DagError::BadPrevious);
            }
        }
        self.validate_element_rule(&signed)?;
        let fid = ForkId::from(&signed.block);
        let is_fork = !self.siblings(&fid).is_empty();
        if let Some(rec) = self.elements.get(&signed.block.element_id) {
            let owner = rec.owner;
            self.fork_snapshots.entry(fid).or_insert(owner);
        }
        if signed.block.block_type == BlockType::Mint {
            self.register_element(signed.block.element_id, signed.block.account);
        }
        let eid = signed.block.element_id;
        self.storage.put(hash, signed);
        self.statuses.insert(hash, BlockStatus::Pending);
        self.spent_set.observe(eid, hash, 0);
        let pending: Vec<SignedBlock> = self.pending_missing.values().cloned().collect();
        for p in pending {
            let ph = p.block_hash();
            let ready = (p.block.previous == ZERO_HASH || self.storage.contains(&p.block.previous))
                && (p.block.link_parent == ZERO_HASH
                    || self.storage.contains(&p.block.link_parent));
            if ready {
                self.pending_missing.remove(&ph);
                let _ = self.insert_block(p);
            }
        }
        Ok(InsertOutcome::Inserted {
            hash,
            fork: is_fork,
        })
    }

    fn validate_element_rule(&self, signed: &SignedBlock) -> Result<(), DagError> {
        let b = &signed.block;
        let fid = ForkId::from(b);
        let has_sibling = !self.siblings(&fid).is_empty();
        match b.block_type {
            BlockType::Mint => Ok(()),
            BlockType::SlashClaim => Ok(()),
            BlockType::Receive => {
                let send = self
                    .storage
                    .get(&b.link_parent)
                    .ok_or(DagError::BadPrevious)?;
                if send.block.block_type != BlockType::Send
                    || send.block.to_address != b.account
                    || send.block.element_id != b.element_id
                {
                    return Err(DagError::BadBlockTypeRule);
                }
                Ok(())
            }
            BlockType::BondLock => {
                if b.to_address != bond_pseudo_account(&b.account) {
                    return Err(DagError::BadBlockTypeRule);
                }
                self.check_owner(b, has_sibling)
            }
            BlockType::BondRelease => {
                let rec = self
                    .elements
                    .get(&b.element_id)
                    .ok_or(DagError::NotElementOwner)?;
                if rec.status != ElementStatus::Bonded || rec.bonded_by != Some(b.account) {
                    return Err(DagError::NotElementOwner);
                }
                Ok(())
            }
            BlockType::Send | BlockType::Burn => self.check_owner(b, has_sibling),
        }
    }
    fn check_owner(&self, b: &Block, has_sibling: bool) -> Result<(), DagError> {
        if has_sibling {
            return Ok(());
        }
        let rec = self
            .elements
            .get(&b.element_id)
            .ok_or(DagError::NotElementOwner)?;
        if rec.owner != b.account {
            return Err(DagError::NotElementOwner);
        }
        if rec.status != ElementStatus::Unspent {
            return Err(DagError::AlreadySpent);
        }
        if let Some(w) = self.spent_set.winner(&b.element_id).cloned() {
            if self.is_confirmed(&w.winning_hash) {
                if let Some(wb) = self.storage.get(&w.winning_hash) {
                    if wb.block.block_type.is_spend() && ForkId::from(&wb.block) != ForkId::from(b)
                    {
                        return Err(DagError::AlreadySpent);
                    }
                }
            }
        }
        Ok(())
    }

    // ----- delegation / voting / finality -----
    pub fn register_representative(&mut self, rep: PqAddress) {
        self.online_reps.insert(rep);
    }
    pub fn delegate(&mut self, delegator: PqAddress, rep: PqAddress) {
        self.delegations.insert(delegator, rep);
        self.online_reps.insert(rep);
    }
    pub fn account_weight(&self, account: &PqAddress) -> u64 {
        self.elements
            .values()
            .filter(|e| {
                e.owner == *account
                    && matches!(e.status, ElementStatus::Unspent | ElementStatus::Bonded)
            })
            .count() as u64
    }
    pub fn representative_weight(&self, rep: &PqAddress) -> u64 {
        let mut total = 0u64;
        let mut counted = HashSet::new();
        for (delegator, r) in &self.delegations {
            if r == rep {
                total += self.account_weight(delegator);
                counted.insert(*delegator);
            }
        }
        if !counted.contains(rep) && !self.delegations.contains_key(rep) {
            total += self.account_weight(rep);
        }
        total
    }
    pub fn online_weight(&self) -> u64 {
        let reps: Vec<PqAddress> = self.online_reps.iter().copied().collect();
        let mut seen = HashSet::new();
        let mut total = 0u64;
        for rep in &reps {
            for (delegator, r) in &self.delegations {
                if r == rep && seen.insert(*delegator) {
                    total += self.account_weight(delegator);
                }
            }
            if !self.delegations.contains_key(rep) && seen.insert(*rep) {
                total += self.account_weight(rep);
            }
        }
        total
    }
    pub fn has_confirmed_bond(&self, owner: &PqAddress) -> bool {
        if self.slashed.contains(owner) || self.blacklist_addrs.contains(owner) {
            return false;
        }
        self.elements
            .values()
            .filter(|e| e.status == ElementStatus::Bonded && e.bonded_by == Some(*owner))
            .count()
            >= BOND_SIZE
    }
    pub fn bonded_elements(&self, owner: &PqAddress) -> Vec<ElementId> {
        let mut v: Vec<ElementId> = self
            .elements
            .iter()
            .filter(|(_, e)| e.status == ElementStatus::Bonded && e.bonded_by == Some(*owner))
            .map(|(id, _)| *id)
            .collect();
        v.sort();
        v
    }
    /// Vote for exactly one fork branch. Equivocation discards both votes.
    /// Burn/Send votes are rejected without a confirmed unslashed bond.
    pub fn cast_vote(
        &mut self,
        rep: PqAddress,
        block_hash: [u8; 32],
    ) -> Result<VoteOutcome, DagError> {
        let signed = self
            .storage
            .get(&block_hash)
            .cloned()
            .ok_or(DagError::UnknownBlock)?;
        let b = signed.block.clone();
        if matches!(b.block_type, BlockType::Burn | BlockType::Send)
            && !self.has_confirmed_bond(&b.account)
        {
            return Err(DagError::NoBond);
        }
        self.online_reps.insert(rep);
        let fid = ForkId::from(&b);
        if self
            .equivocated
            .get(&fid)
            .map(|s| s.contains(&rep))
            .unwrap_or(false)
        {
            return Ok(VoteOutcome::EquivocatedDiscarded);
        }
        let entry = self.votes.entry(fid).or_default();
        if let Some(prev) = entry.get(&rep).copied() {
            if prev != block_hash {
                entry.remove(&rep);
                self.equivocated.entry(fid).or_default().insert(rep);
                return Ok(VoteOutcome::EquivocatedDiscarded);
            }
            return Ok(VoteOutcome::Counted);
        }
        entry.insert(rep, block_hash);
        Ok(VoteOutcome::Counted)
    }
    pub fn is_equivocated(&self, rep: &PqAddress, fid: &ForkId) -> bool {
        self.equivocated
            .get(fid)
            .map(|s| s.contains(rep))
            .unwrap_or(false)
    }
    /// Weight from representatives voting for this branch, excluding
    /// equivocators (spec 3.2).
    pub fn vote_weight(&self, block_hash: &[u8; 32]) -> u64 {
        let Some(signed) = self.storage.get(block_hash) else {
            return 0;
        };
        let fid = ForkId::from(&signed.block);
        let Some(votes) = self.votes.get(&fid) else {
            return 0;
        };
        let eq = self.equivocated.get(&fid);
        votes
            .iter()
            .filter(|(rep, h)| *h == block_hash && !eq.map(|s| s.contains(rep)).unwrap_or(false))
            .map(|(rep, _)| self.representative_weight(rep))
            .sum()
    }
    /// Weight a block accrues from later blocks that reference it,
    /// directly or through descendants (spec 3.2.3): each descendant
    /// contributes its account's confirmed unspent+bonded weight once.
    pub fn descendant_weight(&self, block_hash: &[u8; 32]) -> u64 {
        // Reverse edges: parent hash -> hashes of blocks naming it as
        // previous or link_parent.
        let mut children: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();
        for h in self.storage.hashes() {
            if let Some(s) = self.storage.get(&h) {
                for parent in [s.block.previous, s.block.link_parent] {
                    if parent != ZERO_HASH {
                        children.entry(parent).or_default().push(h);
                    }
                }
            }
        }
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut stack = vec![*block_hash];
        let mut total = 0u64;
        while let Some(cur) = stack.pop() {
            if let Some(kids) = children.get(&cur) {
                for k in kids {
                    if seen.insert(*k) {
                        if let Some(s) = self.storage.get(k) {
                            total += self.account_weight(&s.block.account);
                        }
                        stack.push(*k);
                    }
                }
            }
        }
        total
    }
    /// Spec 3.2.3: vote weight plus descendant-block weight.
    pub fn cumulative_weight(&self, block_hash: &[u8; 32]) -> u64 {
        self.vote_weight(block_hash) + self.descendant_weight(block_hash)
    }
    /// One deterministic 5s vote-epoch tick; no sleeps.
    pub fn confirm_step(&mut self) {
        self.epoch += 1;
        let online = self.online_weight();
        let hashes = self.storage.hashes();
        let mut to_confirm = Vec::new();
        for h in &hashes {
            if self.block_status(h) != Some(BlockStatus::Pending) {
                continue;
            }
            let w = self.cumulative_weight(h);
            let fid = ForkId::from(&self.storage.get(h).unwrap().block);
            let rival = self
                .siblings(&fid)
                .iter()
                .filter(|s| *s != h)
                .map(|s| self.cumulative_weight(s))
                .max()
                .unwrap_or(0);
            let ok = online > 0
                && w.saturating_mul(100) >= FINALITY_PERCENT.saturating_mul(online)
                && w > rival;
            if ok {
                let s = {
                    let e = self.sustain.entry(*h).or_insert(0);
                    *e += 1;
                    *e
                };
                if s >= 1 {
                    to_confirm.push(*h);
                }
            } else {
                self.sustain.insert(*h, 0);
            }
        }
        for h in to_confirm {
            self.confirm_block(h);
        }
        // mature bond releases
        let now = self.epoch;
        let mut matured = Vec::new();
        for (i, r) in self.releases.iter().enumerate() {
            if !r.cancelled
                && !r.executed
                && now >= r.unlock_epoch
                && self.is_confirmed(&r.block_hash)
            {
                matured.push(i);
            }
        }
        for i in matured {
            self.releases[i].executed = true;
            let eid = self.releases[i].element_id;
            if let Some(rec) = self.elements.get_mut(&eid) {
                if rec.status == ElementStatus::Bonded {
                    rec.status = ElementStatus::Unspent;
                    rec.bonded_by = None;
                }
            }
        }
    }
    pub fn advance_epochs(&mut self, n: u64) {
        for _ in 0..n {
            self.confirm_step();
        }
    }
    fn confirm_block(&mut self, hash: [u8; 32]) {
        if self.block_status(&hash) == Some(BlockStatus::Confirmed) {
            return;
        }
        let signed = self.storage.get(&hash).unwrap().clone();
        let b = signed.block.clone();
        self.statuses.insert(hash, BlockStatus::Confirmed);
        let fid = ForkId::from(&b);
        for sib in self.siblings(&fid) {
            if sib != hash && self.block_status(&sib) == Some(BlockStatus::Pending) {
                self.statuses.insert(sib, BlockStatus::Orphaned);
            }
        }
        let w = self.cumulative_weight(&hash);
        if b.block_type != BlockType::Receive {
            self.spent_set.observe(b.element_id, hash, w);
        }
        match b.block_type {
            BlockType::Mint => {
                self.elements.insert(
                    b.element_id,
                    ElementRecord {
                        owner: b.account,
                        status: ElementStatus::Unspent,
                        bonded_by: None,
                    },
                );
            }
            BlockType::Send => {
                if let Some(rec) = self.elements.get_mut(&b.element_id) {
                    rec.status = ElementStatus::InFlight;
                }
            }
            BlockType::Receive => {
                self.elements.insert(
                    b.element_id,
                    ElementRecord {
                        owner: b.account,
                        status: ElementStatus::Unspent,
                        bonded_by: None,
                    },
                );
            }
            BlockType::Burn => {
                if let Some(rec) = self.elements.get_mut(&b.element_id) {
                    rec.owner = burn_sink();
                    rec.status = ElementStatus::Burned;
                    rec.bonded_by = None;
                }
            }
            BlockType::BondLock => {
                if let Some(rec) = self.elements.get_mut(&b.element_id) {
                    rec.status = ElementStatus::Bonded;
                    rec.bonded_by = Some(b.account);
                }
            }
            BlockType::BondRelease => {
                self.releases.push(ReleaseRecord {
                    owner: b.account,
                    element_id: b.element_id,
                    block_hash: hash,
                    unlock_epoch: self.epoch + BOND_RELEASE_EPOCHS,
                    cancelled: false,
                    executed: false,
                });
            }
            BlockType::SlashClaim => {}
        }
    }

    // ----- bond release helpers -----
    pub fn request_release_record(&self, owner: &PqAddress) -> Option<&ReleaseRecord> {
        self.releases.iter().rev().find(|r| r.owner == *owner)
    }

    // ----- fraud proof / slash (impl continues below) -----
    pub fn receive_proof(&mut self, proof: FraudProof) -> Result<[u8; 32], FraudError> {
        let ph = self.verify_fraud_proof(&proof)?;
        let (owner, pubkey) = self.proof_owner_info(&proof)?;
        self.proofs.insert(ph, proof);
        self.proof_owner.insert(ph, (owner, pubkey));
        self.frozen.insert(owner);
        // cancel any in-window (not yet executed) release for this owner
        for r in self.releases.iter_mut() {
            if r.owner == owner && !r.executed && self.epoch < r.unlock_epoch {
                r.cancelled = true;
            }
        }
        Ok(ph)
    }
    pub fn cast_slash_vote(
        &mut self,
        rep: PqAddress,
        proof_hash: [u8; 32],
    ) -> Result<bool, DagError> {
        if !self.proofs.contains_key(&proof_hash) {
            return Err(DagError::UnknownProof);
        }
        self.online_reps.insert(rep);
        self.slash_votes.entry(proof_hash).or_default().insert(rep);
        let online = self.online_weight();
        let weight: u64 = self
            .slash_votes
            .get(&proof_hash)
            .unwrap()
            .iter()
            .map(|r| self.representative_weight(r))
            .sum();
        if online > 0 && weight.saturating_mul(100) >= FINALITY_PERCENT.saturating_mul(online) {
            self.execute_slash(proof_hash)?;
            return Ok(true);
        }
        Ok(false)
    }
    pub fn execute_slash(&mut self, proof_hash: [u8; 32]) -> Result<SlashOutcome, DagError> {
        let proof = self
            .proofs
            .get(&proof_hash)
            .cloned()
            .ok_or(DagError::UnknownProof)?;
        let (owner, pubkey) = self
            .proof_owner
            .get(&proof_hash)
            .cloned()
            .ok_or(DagError::UnknownProof)?;
        let reporter = proof
            .reporter_pq_address()
            .ok_or(DagError::BadBlockTypeRule)?;
        let bonded = self.bonded_elements(&owner);
        if bonded.len() != BOND_SIZE || !validate_slash_split(1, bonded.len().saturating_sub(1)) {
            return Err(DagError::InvalidSlashSplit);
        }
        let bounty = bonded[0];
        let burned = bonded[1..].to_vec();
        if let Some(rec) = self.elements.get_mut(&bounty) {
            rec.owner = reporter;
            rec.status = ElementStatus::Unspent;
            rec.bonded_by = None;
        }
        for id in &burned {
            if let Some(rec) = self.elements.get_mut(id) {
                rec.owner = burn_sink();
                rec.status = ElementStatus::Burned;
                rec.bonded_by = None;
            }
        }
        self.blacklist_pubkeys.insert(pubkey);
        self.blacklist_addrs.insert(owner);
        self.slashed.insert(owner);
        self.frozen.remove(&owner);
        let out = SlashOutcome {
            proof_hash,
            owner,
            reporter,
            bounty_element: bounty,
            burned_elements: burned,
        };
        self.slash_outcomes.insert(proof_hash, out.clone());
        Ok(out)
    }
    /// Freeze is local/reversible if the slash fails.
    pub fn fail_slash(&mut self, proof_hash: &[u8; 32]) -> Result<(), DagError> {
        let (owner, _) = self
            .proof_owner
            .get(proof_hash)
            .cloned()
            .ok_or(DagError::UnknownProof)?;
        self.frozen.remove(&owner);
        self.slash_votes.remove(proof_hash);
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoteOutcome {
    Counted,
    EquivocatedDiscarded,
}

// ---------- Fraud proof wire format (JSON via serde, spec 5.1) ----------
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockJson {
    pub version: u8,
    #[serde(rename = "type")]
    pub block_type: String,
    pub account: String,
    pub previous: String,
    pub link_parent: String,
    pub element_id: String,
    pub to_address: String,
    pub nonce: u64,
    pub epoch: u64,
    pub work: Option<String>,
    pub issued_at: u64,
}
impl BlockJson {
    pub fn from_block(b: &Block) -> Self {
        Self {
            version: b.version,
            block_type: b.block_type.as_str().to_string(),
            account: hex_encode(&b.account.0),
            previous: hex_encode(&b.previous),
            link_parent: hex_encode(&b.link_parent),
            element_id: hex_encode(&b.element_id.0),
            to_address: hex_encode(&b.to_address.0),
            nonce: b.nonce,
            epoch: b.epoch,
            work: b.work.as_ref().map(|w| b64_encode(w)),
            issued_at: b.issued_at,
        }
    }
    pub fn to_block(&self) -> Option<Block> {
        Some(Block {
            version: self.version,
            block_type: BlockType::from_name(&self.block_type)?,
            account: PqAddress(hex20(&self.account)?),
            previous: hex32(&self.previous)?,
            link_parent: hex32(&self.link_parent)?,
            element_id: ElementId(hex32(&self.element_id)?),
            to_address: PqAddress(hex20(&self.to_address)?),
            nonce: self.nonce,
            epoch: self.epoch,
            work: match &self.work {
                None => None,
                Some(s) => Some(b64_decode(s)?),
            },
            issued_at: self.issued_at,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBlock {
    pub block: BlockJson,
    pub signature: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkProof {
    pub previous: String,
    pub block_a: ProofBlock,
    pub block_b: ProofBlock,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FraudProof {
    pub version: u8,
    #[serde(rename = "type")]
    pub proof_type: String,
    pub element_id: String,
    pub owner_pubkey: String,
    pub fork: ForkProof,
    /// hex-encoded 20-byte bounty address
    pub reporter_address: String,
    pub observed_at: u64,
}
impl FraudProof {
    pub fn reporter_pq_address(&self) -> Option<PqAddress> {
        Some(PqAddress(hex20(&self.reporter_address)?))
    }
    pub fn decoded(&self) -> Option<(SignedBlock, SignedBlock, Vec<u8>, ElementId)> {
        let a = SignedBlock {
            block: self.fork.block_a.block.to_block()?,
            signature: b64_decode(&self.fork.block_a.signature)?,
            pubkey: b64_decode(&self.owner_pubkey)?,
        };
        let b = SignedBlock {
            block: self.fork.block_b.block.to_block()?,
            signature: b64_decode(&self.fork.block_b.signature)?,
            pubkey: a.pubkey.clone(),
        };
        let eid = ElementId(hex32(&self.element_id)?);
        Some((a, b, b64_decode(&self.owner_pubkey)?, eid))
    }
    /// proof_hash = SHA3-256(hash_a || hash_b || element_id)
    pub fn proof_hash(&self) -> Option<[u8; 32]> {
        let (a, b, _, eid) = self.decoded()?;
        let mut h = Sha3_256::new();
        h.update(a.block_hash());
        h.update(b.block_hash());
        h.update(eid.0);
        Some(h.finalize().into())
    }
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("fraud proof json")
    }
}
pub fn build_fraud_proof(
    a: &SignedBlock,
    b: &SignedBlock,
    reporter: PqAddress,
    observed_at: u64,
) -> FraudProof {
    FraudProof {
        version: 1,
        proof_type: "dag_double_spend".to_string(),
        element_id: hex_encode(&a.block.element_id.0),
        owner_pubkey: b64_encode(&a.pubkey),
        fork: ForkProof {
            previous: hex_encode(&a.block.previous),
            block_a: ProofBlock {
                block: BlockJson::from_block(&a.block),
                signature: b64_encode(&a.signature),
            },
            block_b: ProofBlock {
                block: BlockJson::from_block(&b.block),
                signature: b64_encode(&b.signature),
            },
        },
        reporter_address: hex_encode(&reporter.0),
        observed_at,
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FraudError {
    Malformed,
    /// condition 1: same previous/account/element
    DifferentForkPoint,
    /// condition 2: hashes differ
    IdenticalBlocks,
    /// condition 3: previous in confirmed history
    PreviousNotConfirmed,
    /// condition 4: address(pubkey)==account==owner at fork
    OwnerMismatch,
    /// condition 5: both signatures verify
    BadSignature,
}
impl<S: Storage> Dag<S> {
    fn proof_owner_info(&self, proof: &FraudProof) -> Result<(PqAddress, Vec<u8>), FraudError> {
        let (a, _, pubkey, _) = proof.decoded().ok_or(FraudError::Malformed)?;
        Ok((a.block.account, pubkey))
    }
    /// Offline verification, ALL 5 spec conditions (section 5.2).
    pub fn verify_fraud_proof(&self, proof: &FraudProof) -> Result<[u8; 32], FraudError> {
        if proof.version != 1 || proof.proof_type != "dag_double_spend" {
            return Err(FraudError::Malformed);
        }
        let (a, b, pubkey, eid) = proof.decoded().ok_or(FraudError::Malformed)?;
        let fork_prev = hex32(&proof.fork.previous).ok_or(FraudError::Malformed)?;
        // 1. same previous/account/element
        if a.block.previous != b.block.previous
            || a.block.previous != fork_prev
            || a.block.account != b.block.account
            || a.block.element_id != b.block.element_id
            || a.block.element_id != eid
        {
            return Err(FraudError::DifferentForkPoint);
        }
        // 2. hashes differ
        if a.block_hash() == b.block_hash() {
            return Err(FraudError::IdenticalBlocks);
        }
        // 3. shared previous exists and traces to confirmed history
        if a.block.previous == ZERO_HASH || !self.storage.contains(&a.block.previous) {
            return Err(FraudError::PreviousNotConfirmed);
        }
        let mut cur = a.block.previous;
        let mut traced = false;
        loop {
            if self.is_confirmed(&cur) {
                traced = true;
                break;
            }
            match self.storage.get(&cur) {
                Some(sb) if sb.block.previous != ZERO_HASH => {
                    cur = sb.block.previous;
                }
                _ => break,
            }
        }
        if !traced {
            return Err(FraudError::PreviousNotConfirmed);
        }
        // 4. address(pubkey)==account==recorded owner at fork point
        if PqAddress::from_pubkey(&pubkey) != a.block.account {
            return Err(FraudError::OwnerMismatch);
        }
        let fid = ForkId::from(&a.block);
        let owner_at_fork = self
            .fork_snapshots
            .get(&fid)
            .copied()
            .or_else(|| self.elements.get(&eid).map(|e| e.owner));
        if owner_at_fork != Some(a.block.account) {
            return Err(FraudError::OwnerMismatch);
        }
        // 5. both signatures verify under owner_pubkey
        if !a.verify_signature() || !b.verify_signature() {
            return Err(FraudError::BadSignature);
        }
        proof.proof_hash().ok_or(FraudError::Malformed)
    }
}
