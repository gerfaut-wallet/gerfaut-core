//! A descriptor read as a spending policy: which keys can spend, under
//! which timelocks, and whether each path is open right now.
//!
//! The engine only needs a descriptor to derive addresses. A person
//! needs to know what it says: "any 2 of 3 keys", "key B once a coin
//! has waited a year". This module lifts the descriptor to its semantic
//! policy with miniscript, splits it into its top-level alternatives
//! (the branches), and evaluates every timelock against the chain tip
//! and the wallet's coins. Pure: no I/O and no engine; the manager
//! hands it what it needs.
//!
//! Times are approximate by nature. A block lock is converted at ten
//! minutes a block, and a time lock is compared with the wall clock
//! while the chain judges it by the median time of the last eleven
//! blocks, which lags the clock by up to a couple of hours. Every
//! snapshot says so through its `time_basis`.

use std::collections::HashMap;
use std::str::FromStr;

use bdk_wallet::bitcoin::AddressType;
use bdk_wallet::bitcoin::address::{Address, NetworkUnchecked};
use bdk_wallet::miniscript::descriptor::SinglePubKey;
use bdk_wallet::miniscript::policy::Liftable;
use bdk_wallet::miniscript::policy::semantic::Policy;
use bdk_wallet::miniscript::{AbsLockTime, Descriptor, DescriptorPublicKey, RelLockTime};
use serde::{Deserialize, Serialize};

use crate::error::{CoreError, CoreResult};
use crate::input::ScriptKind;

/// Seconds a block takes on average; the basis of every estimate here.
const BLOCK_SECONDS: u64 = 600;
/// One unit of a time-based relative lock, per BIP 68.
const RELATIVE_TIME_UNIT: u64 = 512;
/// The low sixteen bits of a sequence number carry the lock's value;
/// bit 22 says whether it counts blocks or time units.
const SEQUENCE_VALUE_MASK: u32 = 0x0000_FFFF;

type Semantic = Policy<DescriptorPublicKey>;

// --- input ---------------------------------------------------------------

/// What the analysis needs: the descriptor, and the chain and coins to
/// evaluate its timelocks against.
#[derive(Debug, Clone)]
pub struct PolicyInput<'a> {
    /// The external (receive) descriptor. A multipath descriptor is
    /// read on its first path; both paths share one policy.
    pub external_descriptor: &'a str,
    pub script: ScriptKind,
    /// The wallet's unspent outputs: relative locks count from them.
    pub coins: Vec<Coin>,
    /// Chain tip height at the last sync.
    pub tip_height: u32,
    /// Wall clock, unix seconds.
    pub now_unix: u64,
}

/// One unspent output, reduced to what a timelock needs to know.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coin {
    pub outpoint: String,
    pub value_sats: u64,
    /// Confirmation height; `None` while the coin sits in the mempool.
    pub height: Option<u32>,
    /// Time of the confirming block, unix seconds, when known.
    pub timestamp: Option<u64>,
}

// --- snapshot ------------------------------------------------------------

/// The shape of a wallet's policy, at a glance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyKind {
    /// One key, nothing else.
    SingleKey,
    /// One threshold of plain keys (`multi`, `sortedmulti`, `multi_a`).
    Multisig,
    /// Anything with a timelock, a hash, or nested conditions.
    Miniscript,
    /// A watched address: no descriptor to read.
    Address,
}

/// What the time-based figures of a snapshot were measured against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeBasis {
    /// The device clock. The chain's median time trails it by up to a
    /// couple of hours, so a time lock reads as open a little before
    /// the chain agrees.
    WallClock,
}

/// One key of the policy. The same extended key on two derivation
/// paths is one key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyKey {
    /// Stable within the snapshot: `k0`, `k1`, ...
    pub id: String,
    /// `Key A`, `Key B`, ... then `Key 27` past the alphabet.
    pub label: String,
    /// Eight lowercase hex digits: the master fingerprint when the key
    /// carries an origin, else the fingerprint of the key itself.
    pub fingerprint: Option<String>,
    /// Origin path, `m/48'/1'/0'/2'`, when the key carries one.
    pub origin_path: Option<String>,
    /// The key as written, shortened: eight leading and six trailing
    /// characters around an ellipsis.
    pub key_short: String,
}

/// What a spending branch is for, guessed from its timelocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BranchRole {
    /// No timelock: the everyday path.
    Primary,
    /// The shortest timelocked path.
    Recovery,
    /// The second shortest timelocked path.
    Emergency,
    /// Further timelocked paths, and paths with no key or needing a
    /// hash preimage.
    Other,
}

/// A spending condition, as the policy states it.
///
/// A threshold with `k == n` is an "and", one with `k == 1` an "or";
/// the numbers are kept so the apps word them as they see fit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Condition {
    Key {
        key_id: String,
    },
    Thresh {
        k: u32,
        n: u32,
        items: Vec<Condition>,
    },
    After {
        lock: AbsoluteLock,
    },
    Older {
        lock: RelativeLock,
    },
    /// A hash whose preimage must be revealed: `sha256`, `hash256`,
    /// `ripemd160` or `hash160`.
    Preimage {
        hash: String,
    },
}

/// An absolute lock: `after(n)`. A consensus value of 500,000,000 or
/// more is a unix time, below it a block height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AbsoluteLock {
    Height { height: u32 },
    Time { unix: u64 },
}

/// A relative lock: `older(n)`, counted from each coin's confirmation.
/// A time-based one is stored in 512-second units; `seconds` is the
/// unit count already multiplied out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RelativeLock {
    Blocks { blocks: u32 },
    Seconds { seconds: u64 },
}

/// Which lock a [`Timelock`] entry is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TimelockRef {
    Absolute { lock: AbsoluteLock },
    Relative { lock: RelativeLock },
}

/// What still separates a lock from opening. Block figures come with
/// their ten-minute estimate; a time figure has no block count.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Remaining {
    pub remaining_blocks: Option<u32>,
    pub remaining_seconds: Option<u64>,
    pub unlocks_at_unix: Option<u64>,
}

/// Where one lock stands against the chain and the coins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LockState {
    /// An absolute lock the chain has passed.
    Unlocked,
    /// An absolute lock still ahead.
    Locked {
        remaining_blocks: Option<u32>,
        remaining_seconds: Option<u64>,
        unlocks_at_unix: Option<u64>,
    },
    /// A relative lock, counted coin by coin. `waiting` coins are not
    /// confirmed yet, so their count has not started; `next` is the
    /// locked coin that opens first.
    PerCoin {
        unlocked: u32,
        waiting: u32,
        locked: u32,
        next: Option<Remaining>,
    },
    /// A relative lock with no coin to count from: the raw duration.
    NoCoins {
        blocks: Option<u32>,
        seconds: Option<u64>,
    },
}

/// One timelock of a branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timelock {
    pub lock: TimelockRef,
    /// False when the lock sits under a threshold that can be met
    /// without it: it then never holds the branch back.
    pub required: bool,
    pub state: LockState,
}

/// Whether a branch can be spent from right now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BranchState {
    SpendableNow,
    /// Only absolute locks, and the chain has not passed them all.
    Locked {
        until: Remaining,
    },
    /// At least one relative lock: a coin is unlocked once every lock
    /// of the branch is met for it.
    PerCoin {
        unlocked: u32,
        waiting: u32,
        locked: u32,
        next: Option<Remaining>,
    },
    /// A relative lock with no coin to count from.
    NoCoins,
    /// The branch needs a hash preimage; keys and locks say nothing
    /// about whether one is at hand.
    NeedsPreimage,
}

/// One way to spend: a top-level alternative of the policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBranch {
    /// Stable within the snapshot: `b0`, `b1`, ...
    pub id: String,
    pub role: BranchRole,
    /// `Primary`, `Recovery`, `Emergency`, `Primary B`, `Recovery 3`...
    pub label: String,
    /// One sentence: "Key B, once a coin has waited 52,560 blocks".
    pub summary: String,
    pub condition: Condition,
    /// Every lock of the branch, optional ones included, in the order
    /// the policy names them.
    pub timelocks: Vec<Timelock>,
    pub state: BranchState,
    /// `state` is `SpendableNow`, for a quick test.
    pub spendable_now: bool,
}

/// A wallet's policy read against the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySnapshot {
    pub kind: PolicyKind,
    pub script: ScriptKind,
    /// The external descriptor as given, or the address of a watched
    /// address.
    pub descriptor: String,
    /// The normalized semantic policy with key labels in place of
    /// keys: `or(pk(Key A),and(pk(Key B),older(52560)))`.
    pub policy: String,
    pub keys: Vec<PolicyKey>,
    pub branches: Vec<PolicyBranch>,
    pub tip_height: u32,
    /// When the snapshot was computed, unix seconds.
    pub computed_at: u64,
    pub time_basis: TimeBasis,
    /// Number of coins the relative locks were counted over.
    pub coins: u32,
    pub has_timelocks: bool,
}

// --- analysis ------------------------------------------------------------

/// Reads a descriptor as spending branches and evaluates its timelocks.
///
/// Fails when the descriptor does not parse, when miniscript cannot
/// lift it to a policy, or when the policy lets anyone or no one spend.
pub fn analyze(input: PolicyInput<'_>) -> CoreResult<PolicySnapshot> {
    let descriptor = parse_descriptor(input.external_descriptor)?;
    let policy = descriptor
        .lift()
        .map_err(|e| CoreError::Descriptor(format!("the policy cannot be read: {e}")))?
        .normalized();
    match policy {
        Policy::Trivial => {
            return Err(CoreError::Descriptor(
                "the policy lets anyone spend".to_owned(),
            ));
        }
        Policy::Unsatisfiable => {
            return Err(CoreError::Descriptor(
                "the policy lets no one spend".to_owned(),
            ));
        }
        _ => {}
    }

    let book = KeyBook::collect(&policy);
    let clock = Clock {
        tip: input.tip_height,
        now: input.now_unix,
    };
    let drafts = disjuncts(&policy)
        .into_iter()
        .map(|branch| draft(branch, &book, &input.coins, &clock))
        .collect::<CoreResult<Vec<Draft>>>()?;
    let roles = assign_roles(&drafts, &clock);
    let branches: Vec<PolicyBranch> = drafts
        .into_iter()
        .zip(roles)
        .enumerate()
        .map(|(index, (draft, (role, label)))| PolicyBranch {
            id: format!("b{index}"),
            role,
            label,
            summary: summary(&draft.condition, &book),
            spendable_now: matches!(draft.state, BranchState::SpendableNow),
            condition: draft.condition,
            timelocks: draft.timelocks,
            state: draft.state,
        })
        .collect();

    Ok(PolicySnapshot {
        kind: kind_of(&policy),
        script: input.script,
        descriptor: input.external_descriptor.to_owned(),
        policy: render(&policy, &book),
        has_timelocks: branches.iter().any(|b| !b.timelocks.is_empty()),
        keys: book.keys,
        branches,
        tip_height: input.tip_height,
        computed_at: input.now_unix,
        time_basis: TimeBasis::WallClock,
        coins: input.coins.len() as u32,
    })
}

/// The snapshot of a watched address: no descriptor, so no keys and no
/// branches. The script type is what the address itself tells.
pub fn address_snapshot(
    address: &str,
    tip_height: u32,
    coins: u32,
    now_unix: u64,
) -> PolicySnapshot {
    PolicySnapshot {
        kind: PolicyKind::Address,
        script: script_of_address(address),
        descriptor: address.to_owned(),
        policy: "address".to_owned(),
        keys: Vec::new(),
        branches: Vec::new(),
        tip_height,
        computed_at: now_unix,
        time_basis: TimeBasis::WallClock,
        coins,
        has_timelocks: false,
    }
}

fn script_of_address(address: &str) -> ScriptKind {
    let Ok(parsed) = address.parse::<Address<NetworkUnchecked>>() else {
        return ScriptKind::Bare;
    };
    match parsed.assume_checked().address_type() {
        Some(AddressType::P2pkh) => ScriptKind::Legacy,
        Some(AddressType::P2sh) => ScriptKind::LegacyScript,
        Some(AddressType::P2wpkh) => ScriptKind::Segwit,
        Some(AddressType::P2wsh) => ScriptKind::WitnessScript,
        Some(AddressType::P2tr) => ScriptKind::Taproot,
        _ => ScriptKind::Bare,
    }
}

fn parse_descriptor(text: &str) -> CoreResult<Descriptor<DescriptorPublicKey>> {
    let invalid = |detail: String| CoreError::InvalidInput {
        kind: "descriptor",
        detail,
    };
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(text.trim())
        .map_err(|e| invalid(e.to_string()))?;
    if !descriptor.is_multipath() {
        return Ok(descriptor);
    }
    descriptor
        .into_single_descriptors()
        .map_err(|e| invalid(e.to_string()))?
        .into_iter()
        .next()
        .ok_or_else(|| invalid("multipath descriptor without a path".to_owned()))
}

/// The top-level alternatives: the items of an outer "or", flattened,
/// or the whole policy when it has none.
fn disjuncts(policy: &Semantic) -> Vec<&Semantic> {
    match policy {
        Policy::Thresh(thresh) if thresh.k() == 1 && thresh.n() > 1 => thresh
            .iter()
            .flat_map(|sub| disjuncts(sub.as_ref()))
            .collect(),
        other => vec![other],
    }
}

fn kind_of(policy: &Semantic) -> PolicyKind {
    match policy {
        Policy::Key(_) => PolicyKind::SingleKey,
        Policy::Thresh(thresh)
            if thresh
                .iter()
                .all(|sub| matches!(sub.as_ref(), Policy::Key(_))) =>
        {
            PolicyKind::Multisig
        }
        _ => PolicyKind::Miniscript,
    }
}

/// Pre-order visit of every node.
fn walk<'p>(policy: &'p Semantic, visit: &mut impl FnMut(&'p Semantic)) {
    visit(policy);
    if let Policy::Thresh(thresh) = policy {
        for sub in thresh.iter() {
            walk(sub.as_ref(), visit);
        }
    }
}

// --- keys ----------------------------------------------------------------

/// The keys of a policy, in order of first appearance, one entry per
/// distinct key material whatever its derivation path.
struct KeyBook {
    keys: Vec<PolicyKey>,
    index: HashMap<String, usize>,
}

impl KeyBook {
    fn collect(policy: &Semantic) -> KeyBook {
        let mut book = KeyBook {
            keys: Vec::new(),
            index: HashMap::new(),
        };
        walk(policy, &mut |node| {
            if let Policy::Key(pk) = node {
                let material = material(pk);
                if !book.index.contains_key(&material) {
                    let index = book.keys.len();
                    book.keys.push(describe_key(index, pk, &material));
                    book.index.insert(material, index);
                }
            }
        });
        book
    }

    fn key_of(&self, pk: &DescriptorPublicKey) -> &PolicyKey {
        &self.keys[self.index[&material(pk)]]
    }

    fn label_by_id<'a>(&'a self, id: &'a str) -> &'a str {
        self.keys
            .iter()
            .find(|key| key.id == id)
            .map_or(id, |key| key.label.as_str())
    }
}

/// The key as written, without origin, path or wildcard: what makes two
/// occurrences the same key.
fn material(pk: &DescriptorPublicKey) -> String {
    match pk {
        DescriptorPublicKey::XPub(xkey) => xkey.xkey.to_string(),
        DescriptorPublicKey::MultiXPub(xkey) => xkey.xkey.to_string(),
        DescriptorPublicKey::Single(single) => match single.key {
            SinglePubKey::FullKey(key) => key.to_string(),
            SinglePubKey::XOnly(key) => key.to_string(),
        },
    }
}

fn describe_key(index: usize, pk: &DescriptorPublicKey, material: &str) -> PolicyKey {
    let origin = match pk {
        DescriptorPublicKey::XPub(xkey) => xkey.origin.as_ref(),
        DescriptorPublicKey::MultiXPub(xkey) => xkey.origin.as_ref(),
        DescriptorPublicKey::Single(single) => single.origin.as_ref(),
    };
    PolicyKey {
        id: format!("k{index}"),
        label: format!("Key {}", letter(index)),
        fingerprint: Some(pk.master_fingerprint().to_string()),
        origin_path: origin.map(|(_, path)| {
            let path = path.to_string();
            if path.is_empty() {
                "m".to_owned()
            } else {
                format!("m/{path}")
            }
        }),
        key_short: shorten(material),
    }
}

/// `A` through `Z`, then the position itself: `27`, `28`...
fn letter(index: usize) -> String {
    match u8::try_from(index) {
        Ok(index) if index < 26 => char::from(b'A' + index).to_string(),
        _ => (index + 1).to_string(),
    }
}

fn shorten(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= 14 {
        return text.to_owned();
    }
    let head: String = chars[..8].iter().collect();
    let tail: String = chars[chars.len() - 6..].iter().collect();
    format!("{head}\u{2026}{tail}")
}

// --- conditions ----------------------------------------------------------

fn condition(policy: &Semantic, book: &KeyBook) -> CoreResult<Condition> {
    Ok(match policy {
        Policy::Key(pk) => Condition::Key {
            key_id: book.key_of(pk).id.clone(),
        },
        Policy::After(lock) => Condition::After {
            lock: absolute(*lock),
        },
        Policy::Older(lock) => Condition::Older {
            lock: relative(*lock),
        },
        Policy::Sha256(_) => preimage("sha256"),
        Policy::Hash256(_) => preimage("hash256"),
        Policy::Ripemd160(_) => preimage("ripemd160"),
        Policy::Hash160(_) => preimage("hash160"),
        Policy::Thresh(thresh) => Condition::Thresh {
            k: thresh.k() as u32,
            n: thresh.n() as u32,
            items: thresh
                .iter()
                .map(|sub| condition(sub.as_ref(), book))
                .collect::<CoreResult<Vec<Condition>>>()?,
        },
        Policy::Trivial | Policy::Unsatisfiable => {
            return Err(CoreError::Internal(
                "a normalized policy still holds a constant".to_owned(),
            ));
        }
    })
}

fn preimage(hash: &str) -> Condition {
    Condition::Preimage {
        hash: hash.to_owned(),
    }
}

fn absolute(lock: AbsLockTime) -> AbsoluteLock {
    let value = lock.to_consensus_u32();
    if lock.is_block_height() {
        AbsoluteLock::Height { height: value }
    } else {
        AbsoluteLock::Time {
            unix: u64::from(value),
        }
    }
}

fn relative(lock: RelLockTime) -> RelativeLock {
    let value = lock.to_consensus_u32() & SEQUENCE_VALUE_MASK;
    if lock.is_height_locked() {
        RelativeLock::Blocks { blocks: value }
    } else {
        RelativeLock::Seconds {
            seconds: u64::from(value) * RELATIVE_TIME_UNIT,
        }
    }
}

/// The policy in miniscript's own policy language, keys replaced by
/// their labels.
fn render(policy: &Semantic, book: &KeyBook) -> String {
    match policy {
        Policy::Unsatisfiable => "UNSATISFIABLE".to_owned(),
        Policy::Trivial => "TRIVIAL".to_owned(),
        Policy::Key(pk) => format!("pk({})", book.key_of(pk).label),
        Policy::After(lock) => format!("after({})", lock.to_consensus_u32()),
        Policy::Older(lock) => format!("older({})", lock.to_consensus_u32()),
        Policy::Sha256(hash) => format!("sha256({hash})"),
        Policy::Hash256(hash) => format!("hash256({hash})"),
        Policy::Ripemd160(hash) => format!("ripemd160({hash})"),
        Policy::Hash160(hash) => format!("hash160({hash})"),
        Policy::Thresh(thresh) => {
            let items: Vec<String> = thresh
                .iter()
                .map(|sub| render(sub.as_ref(), book))
                .collect();
            let items = items.join(",");
            if thresh.k() == thresh.n() {
                format!("and({items})")
            } else if thresh.k() == 1 {
                format!("or({items})")
            } else {
                format!("thresh({},{items})", thresh.k())
            }
        }
    }
}

// --- timelocks -----------------------------------------------------------

/// The chain as the analysis sees it.
struct Clock {
    tip: u32,
    now: u64,
}

#[derive(Clone, Copy)]
enum Lock {
    Absolute(AbsoluteLock),
    Relative(RelativeLock),
}

impl Lock {
    fn reference(self) -> TimelockRef {
        match self {
            Lock::Absolute(lock) => TimelockRef::Absolute { lock },
            Lock::Relative(lock) => TimelockRef::Relative { lock },
        }
    }

    /// Roughly how far off the lock is, in seconds, to rank branches:
    /// an absolute lock by its distance from the tip or the clock, a
    /// relative one by its full duration.
    fn magnitude(self, clock: &Clock) -> u64 {
        match self {
            Lock::Absolute(AbsoluteLock::Height { height }) => {
                u64::from(height.saturating_sub(clock.tip)) * BLOCK_SECONDS
            }
            Lock::Absolute(AbsoluteLock::Time { unix }) => unix.saturating_sub(clock.now),
            Lock::Relative(RelativeLock::Blocks { blocks }) => u64::from(blocks) * BLOCK_SECONDS,
            Lock::Relative(RelativeLock::Seconds { seconds }) => seconds,
        }
    }
}

impl Remaining {
    fn blocks(blocks: u32, now: u64) -> Remaining {
        let seconds = u64::from(blocks) * BLOCK_SECONDS;
        Remaining {
            remaining_blocks: Some(blocks),
            remaining_seconds: Some(seconds),
            unlocks_at_unix: Some(now + seconds),
        }
    }

    fn seconds(seconds: u64, unlocks_at: u64) -> Remaining {
        Remaining {
            remaining_blocks: None,
            remaining_seconds: Some(seconds),
            unlocks_at_unix: Some(unlocks_at),
        }
    }

    fn seconds_left(&self) -> u64 {
        self.remaining_seconds.unwrap_or(0)
    }

    fn later(self, other: Remaining) -> Remaining {
        if other.seconds_left() > self.seconds_left() {
            other
        } else {
            self
        }
    }

    fn sooner(self, other: Remaining) -> Remaining {
        if other.seconds_left() < self.seconds_left() {
            other
        } else {
            self
        }
    }
}

impl AbsoluteLock {
    /// What still separates the chain from this lock; `None` once the
    /// lock is behind it.
    fn remaining(self, clock: &Clock) -> Option<Remaining> {
        match self {
            AbsoluteLock::Height { height } => {
                // A transaction locked to height H is final in block
                // H + 1 and later. With the tip at H, the next block
                // can carry the spend: the lock is open at the tip.
                if clock.tip >= height {
                    return None;
                }
                Some(Remaining::blocks(height - clock.tip, clock.now))
            }
            AbsoluteLock::Time { unix } => {
                // Judged against the wall clock; the chain's median
                // time lags it by up to a couple of hours.
                if clock.now >= unix {
                    return None;
                }
                Some(Remaining::seconds(unix - clock.now, unix))
            }
        }
    }
}

/// Where one coin stands against one relative lock.
enum CoinLock {
    Unlocked,
    /// Unconfirmed, or without the timestamp a time lock needs: the
    /// count has not started.
    Waiting,
    Locked(Remaining),
}

impl RelativeLock {
    fn on_coin(self, coin: &Coin, clock: &Clock) -> CoinLock {
        let Some(height) = coin.height else {
            return CoinLock::Waiting;
        };
        match self {
            RelativeLock::Blocks { blocks } => {
                // A coin confirmed at height h has waited tip - h + 1
                // blocks by the next block, the first one a spend could
                // land in.
                let waited = clock.tip.saturating_sub(height).saturating_add(1);
                if waited >= blocks {
                    CoinLock::Unlocked
                } else {
                    CoinLock::Locked(Remaining::blocks(blocks - waited, clock.now))
                }
            }
            RelativeLock::Seconds { seconds } => {
                let Some(since) = coin.timestamp else {
                    return CoinLock::Waiting;
                };
                let waited = clock.now.saturating_sub(since);
                if waited >= seconds {
                    CoinLock::Unlocked
                } else {
                    CoinLock::Locked(Remaining::seconds(seconds - waited, since + seconds))
                }
            }
        }
    }
}

/// Coins sorted into unlocked, waiting and locked, with the locked one
/// that opens first.
#[derive(Default)]
struct Tally {
    unlocked: u32,
    waiting: u32,
    locked: u32,
    next: Option<Remaining>,
}

impl Tally {
    fn add(&mut self, state: CoinLock) {
        match state {
            CoinLock::Unlocked => self.unlocked += 1,
            CoinLock::Waiting => self.waiting += 1,
            CoinLock::Locked(remaining) => {
                self.locked += 1;
                self.next = Some(match self.next {
                    Some(next) => next.sooner(remaining),
                    None => remaining,
                });
            }
        }
    }
}

fn lock_state(lock: Lock, coins: &[Coin], clock: &Clock) -> LockState {
    match lock {
        Lock::Absolute(lock) => match lock.remaining(clock) {
            None => LockState::Unlocked,
            Some(remaining) => LockState::Locked {
                remaining_blocks: remaining.remaining_blocks,
                remaining_seconds: remaining.remaining_seconds,
                unlocks_at_unix: remaining.unlocks_at_unix,
            },
        },
        Lock::Relative(lock) => {
            if coins.is_empty() {
                return match lock {
                    RelativeLock::Blocks { blocks } => LockState::NoCoins {
                        blocks: Some(blocks),
                        seconds: None,
                    },
                    RelativeLock::Seconds { seconds } => LockState::NoCoins {
                        blocks: None,
                        seconds: Some(seconds),
                    },
                };
            }
            let mut tally = Tally::default();
            for coin in coins {
                tally.add(lock.on_coin(coin, clock));
            }
            LockState::PerCoin {
                unlocked: tally.unlocked,
                waiting: tally.waiting,
                locked: tally.locked,
                next: tally.next,
            }
        }
    }
}

/// The state of a branch from the locks it cannot do without.
fn branch_state(
    required: &[Lock],
    needs_preimage: bool,
    coins: &[Coin],
    clock: &Clock,
) -> BranchState {
    if needs_preimage {
        return BranchState::NeedsPreimage;
    }
    let absolute: Vec<AbsoluteLock> = required
        .iter()
        .filter_map(|lock| match lock {
            Lock::Absolute(lock) => Some(*lock),
            Lock::Relative(_) => None,
        })
        .collect();
    let relative: Vec<RelativeLock> = required
        .iter()
        .filter_map(|lock| match lock {
            Lock::Relative(lock) => Some(*lock),
            Lock::Absolute(_) => None,
        })
        .collect();

    if relative.is_empty() {
        // The branch opens when its last absolute lock does.
        let until = absolute
            .iter()
            .filter_map(|lock| lock.remaining(clock))
            .reduce(Remaining::later);
        return match until {
            None => BranchState::SpendableNow,
            Some(until) => BranchState::Locked { until },
        };
    }
    if coins.is_empty() {
        return BranchState::NoCoins;
    }

    let mut tally = Tally::default();
    for coin in coins {
        let mut worst = absolute
            .iter()
            .filter_map(|lock| lock.remaining(clock))
            .reduce(Remaining::later);
        let mut waiting = false;
        for lock in &relative {
            match lock.on_coin(coin, clock) {
                CoinLock::Unlocked => {}
                CoinLock::Waiting => waiting = true,
                CoinLock::Locked(remaining) => {
                    worst = Some(match worst {
                        Some(worst) => worst.later(remaining),
                        None => remaining,
                    });
                }
            }
        }
        tally.add(if waiting {
            CoinLock::Waiting
        } else if let Some(worst) = worst {
            CoinLock::Locked(worst)
        } else {
            CoinLock::Unlocked
        });
    }
    BranchState::PerCoin {
        unlocked: tally.unlocked,
        waiting: tally.waiting,
        locked: tally.locked,
        next: tally.next,
    }
}

// --- branches ------------------------------------------------------------

/// What a walk over one branch found.
#[derive(Default)]
struct Scan {
    /// Every lock, with whether the branch cannot be spent without it.
    locks: Vec<(Lock, bool)>,
    has_key: bool,
    /// A hash the branch cannot be spent without.
    needs_preimage: bool,
}

/// Walks a branch. A lock under a threshold that can be met without it
/// (`k < n`) is optional: it is listed, but it never holds the branch
/// back. This is a sound simplification, not a full satisfiability
/// analysis: `thresh(2, A, B, older(N))` is open to A and B today, and
/// that is what the state says.
fn scan_locks(policy: &Semantic, required: bool, scan: &mut Scan) {
    match policy {
        Policy::Key(_) => scan.has_key = true,
        Policy::After(lock) => scan.locks.push((Lock::Absolute(absolute(*lock)), required)),
        Policy::Older(lock) => scan.locks.push((Lock::Relative(relative(*lock)), required)),
        Policy::Sha256(_) | Policy::Hash256(_) | Policy::Ripemd160(_) | Policy::Hash160(_) => {
            scan.needs_preimage |= required;
        }
        Policy::Thresh(thresh) => {
            let required = required && thresh.k() == thresh.n();
            for sub in thresh.iter() {
                scan_locks(sub.as_ref(), required, scan);
            }
        }
        Policy::Trivial | Policy::Unsatisfiable => {}
    }
}

struct Draft {
    condition: Condition,
    timelocks: Vec<Timelock>,
    required: Vec<Lock>,
    has_key: bool,
    needs_preimage: bool,
    state: BranchState,
}

fn draft(policy: &Semantic, book: &KeyBook, coins: &[Coin], clock: &Clock) -> CoreResult<Draft> {
    let mut scan = Scan::default();
    scan_locks(policy, true, &mut scan);
    let required: Vec<Lock> = scan
        .locks
        .iter()
        .filter(|(_, required)| *required)
        .map(|(lock, _)| *lock)
        .collect();
    let timelocks = scan
        .locks
        .iter()
        .map(|(lock, required)| Timelock {
            lock: lock.reference(),
            required: *required,
            state: lock_state(*lock, coins, clock),
        })
        .collect();
    Ok(Draft {
        condition: condition(policy, book)?,
        timelocks,
        state: branch_state(&required, scan.needs_preimage, coins, clock),
        required,
        has_key: scan.has_key,
        needs_preimage: scan.needs_preimage,
    })
}

/// Roles and labels, one per draft, in the drafts' order.
///
/// Branches with no required lock are primary; those with one rank by
/// how far off their farthest lock is: the nearest is the recovery
/// path, the next the emergency one. A branch with no key, or one that
/// needs a hash preimage, is set apart as "other".
fn assign_roles(drafts: &[Draft], clock: &Clock) -> Vec<(BranchRole, String)> {
    let mut roles: Vec<Option<(BranchRole, String)>> = vec![None; drafts.len()];
    let mut primaries = 0usize;
    let mut others = 0usize;
    let mut timed: Vec<(usize, u64)> = Vec::new();
    for (index, draft) in drafts.iter().enumerate() {
        if !draft.has_key || draft.needs_preimage {
            others += 1;
            roles[index] = Some((BranchRole::Other, numbered("Other", others)));
        } else if draft.required.is_empty() {
            roles[index] = Some((BranchRole::Primary, lettered("Primary", primaries)));
            primaries += 1;
        } else {
            let magnitude = draft
                .required
                .iter()
                .map(|lock| lock.magnitude(clock))
                .max()
                .unwrap_or(0);
            timed.push((index, magnitude));
        }
    }
    timed.sort_by_key(|(_, magnitude)| *magnitude);
    for (rank, (index, _)) in timed.into_iter().enumerate() {
        roles[index] = Some(match rank {
            0 => (BranchRole::Recovery, "Recovery".to_owned()),
            1 => (BranchRole::Emergency, "Emergency".to_owned()),
            rank => (BranchRole::Other, numbered("Recovery", rank + 1)),
        });
    }
    roles
        .into_iter()
        .map(|role| role.expect("every branch was given a role"))
        .collect()
}

/// `Primary`, then `Primary B`, `Primary C`...
fn lettered(base: &str, index: usize) -> String {
    if index == 0 {
        base.to_owned()
    } else {
        format!("{base} {}", letter(index))
    }
}

/// `Other`, then `Other 2`, `Other 3`...
fn numbered(base: &str, count: usize) -> String {
    if count <= 1 {
        base.to_owned()
    } else {
        format!("{base} {count}")
    }
}

// --- wording -------------------------------------------------------------

/// One sentence for a branch: who, then the absolute locks, then the
/// relative ones. "Key B, once a coin has waited 52,560 blocks".
fn summary(condition: &Condition, book: &KeyBook) -> String {
    let parts: Vec<&Condition> = match condition {
        Condition::Thresh { k, n, items } if k == n => items.iter().collect(),
        other => vec![other],
    };
    let mut keys: Vec<&str> = Vec::new();
    let mut groups: Vec<String> = Vec::new();
    let mut preimages: Vec<String> = Vec::new();
    let mut afters: Vec<String> = Vec::new();
    let mut olders: Vec<String> = Vec::new();
    for part in parts {
        match part {
            Condition::Key { key_id } => keys.push(book.label_by_id(key_id)),
            Condition::Thresh { .. } => groups.push(group_phrase(part, book)),
            Condition::Preimage { hash } => preimages.push(preimage_phrase(hash)),
            Condition::After { lock } => afters.push(after_clause(*lock)),
            Condition::Older { lock } => olders.push(older_clause(*lock)),
        }
    }

    let mut subjects: Vec<String> = Vec::new();
    if !keys.is_empty() {
        subjects.push(key_list(&keys));
    }
    subjects.extend(groups);
    subjects.extend(preimages);
    let mut text = if subjects.is_empty() {
        "No key".to_owned()
    } else {
        capitalize(&join_and(subjects))
    };
    if !afters.is_empty() {
        text.push(' ');
        text.push_str(&join_and(afters));
    }
    if !olders.is_empty() {
        text.push_str(", ");
        text.push_str(&join_and(olders));
    }
    text
}

/// A threshold as a noun phrase: "Any 2 of 3 keys", "Keys A and B",
/// "Any 2 of: Key A, Key B, a coin having waited 100 blocks".
fn group_phrase(condition: &Condition, book: &KeyBook) -> String {
    let Condition::Thresh { k, n, items } = condition else {
        return noun(condition, book);
    };
    let all_keys = items
        .iter()
        .all(|item| matches!(item, Condition::Key { .. }));
    if all_keys {
        if k == n {
            let labels: Vec<&str> = items
                .iter()
                .filter_map(|item| match item {
                    Condition::Key { key_id } => Some(book.label_by_id(key_id)),
                    _ => None,
                })
                .collect();
            return key_list(&labels);
        }
        if *k == 1 {
            return format!("Any of {n} keys");
        }
        return format!("Any {k} of {n} keys");
    }
    let nouns: Vec<String> = items.iter().map(|item| noun(item, book)).collect();
    if k == n {
        join_and(nouns)
    } else {
        format!("Any {k} of: {}", nouns.join(", "))
    }
}

/// A condition as a noun phrase, for use inside a list.
fn noun(condition: &Condition, book: &KeyBook) -> String {
    match condition {
        Condition::Key { key_id } => book.label_by_id(key_id).to_owned(),
        Condition::Thresh { .. } => group_phrase(condition, book),
        Condition::Preimage { hash } => preimage_phrase(hash),
        Condition::After {
            lock: AbsoluteLock::Height { height },
        } => format!("block {} reached", digits(u64::from(*height))),
        Condition::After {
            lock: AbsoluteLock::Time { unix },
        } => format!("{} reached", date(*unix)),
        Condition::Older {
            lock: RelativeLock::Blocks { blocks },
        } => format!("a coin having waited {}", blocks_phrase(*blocks)),
        Condition::Older {
            lock: RelativeLock::Seconds { seconds },
        } => format!("a coin having waited {}", seconds_phrase(*seconds)),
    }
}

fn preimage_phrase(hash: &str) -> String {
    format!("the preimage of a {hash} hash")
}

fn after_clause(lock: AbsoluteLock) -> String {
    match lock {
        AbsoluteLock::Height { height } => format!("after block {}", digits(u64::from(height))),
        AbsoluteLock::Time { unix } => format!("after {}", date(unix)),
    }
}

fn older_clause(lock: RelativeLock) -> String {
    match lock {
        RelativeLock::Blocks { blocks } => {
            format!("once a coin has waited {}", blocks_phrase(blocks))
        }
        RelativeLock::Seconds { seconds } => {
            format!("once a coin has waited {}", seconds_phrase(seconds))
        }
    }
}

/// "Key A", "Keys A and B", "Keys A, B and C".
fn key_list(labels: &[&str]) -> String {
    let letters: Vec<String> = labels
        .iter()
        .map(|label| label.strip_prefix("Key ").unwrap_or(label).to_owned())
        .collect();
    match letters.as_slice() {
        [] => "No key".to_owned(),
        [only] => format!("Key {only}"),
        _ => format!("Keys {}", join_and(letters)),
    }
}

/// "a", "a and b", "a, b and c".
fn join_and(items: Vec<String>) -> String {
    match items.len() {
        0 => String::new(),
        1 => items.into_iter().next().unwrap_or_default(),
        n => {
            let (head, last) = items.split_at(n - 1);
            format!("{} and {}", head.join(", "), last[0])
        }
    }
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn blocks_phrase(blocks: u32) -> String {
    if blocks == 1 {
        "1 block".to_owned()
    } else {
        format!("{} blocks", digits(u64::from(blocks)))
    }
}

/// A duration in the largest round unit that still reads true: exact
/// days or hours when they divide, "about" otherwise, seconds below an
/// hour.
fn seconds_phrase(seconds: u64) -> String {
    const HOUR: u64 = 3_600;
    const DAY: u64 = 24 * HOUR;
    let unit = |amount: u64, name: &str, exact: bool| {
        let plural = if amount == 1 { "" } else { "s" };
        let about = if exact { "" } else { "about " };
        format!("{about}{} {name}{plural}", digits(amount))
    };
    if seconds >= DAY {
        unit(
            (seconds + DAY / 2) / DAY,
            "day",
            seconds.is_multiple_of(DAY),
        )
    } else if seconds >= HOUR {
        unit(
            (seconds + HOUR / 2) / HOUR,
            "hour",
            seconds.is_multiple_of(HOUR),
        )
    } else {
        unit(seconds, "second", true)
    }
}

/// Thousands separated by commas: 52,560.
fn digits(value: u64) -> String {
    let raw = value.to_string();
    let mut out = String::with_capacity(raw.len() + raw.len() / 3);
    for (index, digit) in raw.chars().enumerate() {
        if index > 0 && (raw.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// A unix time as a civil date, `2030-03-17`, UTC.
fn date(unix: u64) -> String {
    // Days since the epoch to a proleptic Gregorian date, after Howard
    // Hinnant's `civil_from_days`.
    let days = i64::try_from(unix / 86_400).unwrap_or(i64::MAX / 2);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP-32 test vectors: public keys anyone can look up, no funds
    // behind them.
    const A: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    const B: &str = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";
    const C: &str = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ";
    /// The signet fixture the manager tests use, origin included.
    const TPUB: &str = "[9a6a2580/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks";

    const TIP: u32 = 800_000;
    const NOW: u64 = 1_750_000_000;

    fn liana() -> String {
        format!("wsh(or_d(pk({A}/0/*),and_v(v:pkh({B}/0/*),older(52560))))")
    }

    fn coin(outpoint: &str, height: Option<u32>, timestamp: Option<u64>) -> Coin {
        Coin {
            outpoint: outpoint.to_owned(),
            value_sats: 100_000,
            height,
            timestamp,
        }
    }

    fn analyze_with(descriptor: &str, script: ScriptKind, coins: Vec<Coin>) -> PolicySnapshot {
        analyze(PolicyInput {
            external_descriptor: descriptor,
            script,
            coins,
            tip_height: TIP,
            now_unix: NOW,
        })
        .expect("policy")
    }

    fn wsh(descriptor: &str, coins: Vec<Coin>) -> PolicySnapshot {
        analyze_with(descriptor, ScriptKind::WitnessScript, coins)
    }

    #[test]
    fn a_single_key_is_one_open_branch() {
        let descriptor = format!("wpkh({TPUB}/0/*)");
        let snapshot = analyze_with(&descriptor, ScriptKind::Segwit, Vec::new());
        assert_eq!(snapshot.kind, PolicyKind::SingleKey);
        assert_eq!(snapshot.script, ScriptKind::Segwit);
        assert_eq!(snapshot.descriptor, descriptor);
        assert_eq!(snapshot.policy, "pk(Key A)");
        assert!(!snapshot.has_timelocks);
        assert_eq!(snapshot.coins, 0);
        assert_eq!(snapshot.tip_height, TIP);
        assert_eq!(snapshot.computed_at, NOW);
        assert_eq!(snapshot.time_basis, TimeBasis::WallClock);

        assert_eq!(
            snapshot.keys,
            vec![PolicyKey {
                id: "k0".into(),
                label: "Key A".into(),
                fingerprint: Some("9a6a2580".into()),
                origin_path: Some("m/84'/1'/0'".into()),
                key_short: "tpubDDnG\u{2026}so9Kks".into(),
            }]
        );
        assert_eq!(snapshot.branches.len(), 1);
        let branch = &snapshot.branches[0];
        assert_eq!(branch.id, "b0");
        assert_eq!(branch.role, BranchRole::Primary);
        assert_eq!(branch.label, "Primary");
        assert_eq!(branch.summary, "Key A");
        assert_eq!(
            branch.condition,
            Condition::Key {
                key_id: "k0".into()
            }
        );
        assert!(branch.timelocks.is_empty());
        assert_eq!(branch.state, BranchState::SpendableNow);
        assert!(branch.spendable_now);
    }

    #[test]
    fn a_sorted_multisig_is_any_k_of_n() {
        let snapshot = wsh(
            &format!("wsh(sortedmulti(2,{A}/0/*,{B}/0/*,{C}/0/*))"),
            Vec::new(),
        );
        assert_eq!(snapshot.kind, PolicyKind::Multisig);
        assert_eq!(snapshot.keys.len(), 3);
        assert_eq!(snapshot.keys[2].label, "Key C");
        assert_eq!(snapshot.policy, "thresh(2,pk(Key A),pk(Key B),pk(Key C))");
        assert_eq!(snapshot.branches.len(), 1);
        let branch = &snapshot.branches[0];
        assert_eq!(branch.summary, "Any 2 of 3 keys");
        assert_eq!(branch.role, BranchRole::Primary);
        assert!(branch.spendable_now);
        assert_eq!(
            branch.condition,
            Condition::Thresh {
                k: 2,
                n: 3,
                items: vec![
                    Condition::Key {
                        key_id: "k0".into()
                    },
                    Condition::Key {
                        key_id: "k1".into()
                    },
                    Condition::Key {
                        key_id: "k2".into()
                    },
                ],
            }
        );
    }

    #[test]
    fn a_recovery_path_counts_per_coin() {
        let snapshot = wsh(
            &liana(),
            vec![
                // Waited 100,001 blocks: long open.
                coin("aa:0", Some(700_000), Some(NOW - 60_000_000)),
                // Waited 10,001 blocks: 42,559 to go, the nearest.
                coin("bb:0", Some(790_000), Some(NOW - 6_000_000)),
                // Confirmed in the block before the tip: waited 2.
                coin("cc:1", Some(799_999), Some(NOW - 600)),
            ],
        );
        assert_eq!(snapshot.kind, PolicyKind::Miniscript);
        assert!(snapshot.has_timelocks);
        assert_eq!(snapshot.coins, 3);
        assert_eq!(snapshot.policy, "or(pk(Key A),and(pk(Key B),older(52560)))");
        assert_eq!(snapshot.keys.len(), 2);
        assert_eq!(snapshot.keys[0].fingerprint, Some("3442193e".into()));
        assert_eq!(snapshot.keys[0].origin_path, None);

        let [primary, recovery] = snapshot.branches.as_slice() else {
            panic!("two branches, got {:?}", snapshot.branches);
        };
        assert_eq!(primary.role, BranchRole::Primary);
        assert_eq!(primary.summary, "Key A");
        assert!(primary.spendable_now);

        assert_eq!(recovery.role, BranchRole::Recovery);
        assert_eq!(recovery.label, "Recovery");
        assert_eq!(
            recovery.summary,
            "Key B, once a coin has waited 52,560 blocks"
        );
        assert!(!recovery.spendable_now);
        let next = Remaining {
            remaining_blocks: Some(42_559),
            remaining_seconds: Some(42_559 * 600),
            unlocks_at_unix: Some(NOW + 42_559 * 600),
        };
        assert_eq!(
            recovery.state,
            BranchState::PerCoin {
                unlocked: 1,
                waiting: 0,
                locked: 2,
                next: Some(next),
            }
        );
        assert_eq!(recovery.timelocks.len(), 1);
        let lock = &recovery.timelocks[0];
        assert!(lock.required);
        assert_eq!(
            lock.lock,
            TimelockRef::Relative {
                lock: RelativeLock::Blocks { blocks: 52_560 }
            }
        );
        assert_eq!(
            lock.state,
            LockState::PerCoin {
                unlocked: 1,
                waiting: 0,
                locked: 2,
                next: Some(next),
            }
        );
    }

    #[test]
    fn an_unconfirmed_coin_is_waiting() {
        let snapshot = wsh(&liana(), vec![coin("aa:0", None, None)]);
        assert_eq!(
            snapshot.branches[1].state,
            BranchState::PerCoin {
                unlocked: 0,
                waiting: 1,
                locked: 0,
                next: None,
            }
        );
    }

    #[test]
    fn no_coins_leaves_a_relative_lock_uncounted() {
        let snapshot = wsh(&liana(), Vec::new());
        let recovery = &snapshot.branches[1];
        assert_eq!(recovery.state, BranchState::NoCoins);
        assert_eq!(
            recovery.timelocks[0].state,
            LockState::NoCoins {
                blocks: Some(52_560),
                seconds: None,
            }
        );
        assert!(snapshot.branches[0].spendable_now, "keys need no coin");
    }

    #[test]
    fn timed_branches_rank_by_duration() {
        // Written longest first: the ranking must not follow the text.
        let descriptor = format!(
            "wsh(or_d(pk({A}/0/*),or_i(and_v(v:pkh({B}/0/*),older(52560)),and_v(v:pkh({C}/0/*),older(4320)))))"
        );
        let snapshot = wsh(&descriptor, Vec::new());
        let roles: Vec<(BranchRole, &str)> = snapshot
            .branches
            .iter()
            .map(|b| (b.role, b.label.as_str()))
            .collect();
        assert_eq!(
            roles,
            vec![
                (BranchRole::Primary, "Primary"),
                (BranchRole::Emergency, "Emergency"),
                (BranchRole::Recovery, "Recovery"),
            ]
        );
        assert_eq!(
            snapshot.branches[2].summary,
            "Key C, once a coin has waited 4,320 blocks"
        );
    }

    #[test]
    fn an_absolute_height_lock_opens_at_the_tip() {
        let descriptor = format!("wsh(and_v(v:pk({A}/0/*),after(900000)))");
        let locked = analyze(PolicyInput {
            external_descriptor: &descriptor,
            script: ScriptKind::WitnessScript,
            coins: Vec::new(),
            tip_height: 899_999,
            now_unix: NOW,
        })
        .unwrap();
        let branch = &locked.branches[0];
        assert_eq!(branch.summary, "Key A after block 900,000");
        assert_eq!(branch.role, BranchRole::Recovery);
        assert_eq!(
            branch.state,
            BranchState::Locked {
                until: Remaining {
                    remaining_blocks: Some(1),
                    remaining_seconds: Some(600),
                    unlocks_at_unix: Some(NOW + 600),
                }
            }
        );
        assert_eq!(
            branch.timelocks[0].state,
            LockState::Locked {
                remaining_blocks: Some(1),
                remaining_seconds: Some(600),
                unlocks_at_unix: Some(NOW + 600),
            }
        );
        assert_eq!(
            branch.condition,
            Condition::Thresh {
                k: 2,
                n: 2,
                items: vec![
                    Condition::Key {
                        key_id: "k0".into()
                    },
                    Condition::After {
                        lock: AbsoluteLock::Height { height: 900_000 }
                    },
                ],
            }
        );

        // At the tip itself the next block can carry the spend.
        let open = analyze(PolicyInput {
            external_descriptor: &descriptor,
            script: ScriptKind::WitnessScript,
            coins: Vec::new(),
            tip_height: 900_000,
            now_unix: NOW,
        })
        .unwrap();
        assert_eq!(open.branches[0].state, BranchState::SpendableNow);
        assert_eq!(open.branches[0].timelocks[0].state, LockState::Unlocked);
    }

    #[test]
    fn an_absolute_time_lock_reads_the_clock() {
        let unix = 1_900_000_000u64;
        let descriptor = format!("wsh(and_v(v:pk({A}/0/*),after({unix})))");
        let snapshot = wsh(&descriptor, Vec::new());
        let branch = &snapshot.branches[0];
        assert_eq!(branch.summary, "Key A after 2030-03-17");
        assert_eq!(
            branch.state,
            BranchState::Locked {
                until: Remaining {
                    remaining_blocks: None,
                    remaining_seconds: Some(unix - NOW),
                    unlocks_at_unix: Some(unix),
                }
            }
        );
        assert_eq!(
            branch.timelocks[0].lock,
            TimelockRef::Absolute {
                lock: AbsoluteLock::Time { unix }
            }
        );

        let later = analyze(PolicyInput {
            external_descriptor: &descriptor,
            script: ScriptKind::WitnessScript,
            coins: Vec::new(),
            tip_height: TIP,
            now_unix: unix,
        })
        .unwrap();
        assert!(later.branches[0].spendable_now);
    }

    #[test]
    fn a_time_based_relative_lock_counts_seconds() {
        // Bit 22 set: 100 units of 512 seconds.
        let sequence = (1u32 << 22) | 100;
        let descriptor = format!("wsh(or_d(pk({A}/0/*),and_v(v:pkh({B}/0/*),older({sequence}))))");
        let snapshot = wsh(
            &descriptor,
            vec![
                coin("aa:0", Some(TIP - 10), Some(NOW - 20_000)),
                coin("bb:0", Some(TIP - 10), None),
                coin("cc:0", Some(TIP - 10), Some(NOW - 60_000)),
            ],
        );
        assert!(snapshot.policy.contains("older(4194404)"));
        let recovery = &snapshot.branches[1];
        assert_eq!(
            recovery.summary,
            "Key B, once a coin has waited about 14 hours"
        );
        assert_eq!(
            recovery.timelocks[0].lock,
            TimelockRef::Relative {
                lock: RelativeLock::Seconds { seconds: 51_200 }
            }
        );
        assert_eq!(
            recovery.state,
            BranchState::PerCoin {
                unlocked: 1,
                waiting: 1,
                locked: 1,
                next: Some(Remaining {
                    remaining_blocks: None,
                    remaining_seconds: Some(31_200),
                    unlocks_at_unix: Some(NOW - 20_000 + 51_200),
                }),
            }
        );
    }

    #[test]
    fn a_taproot_tree_has_a_branch_per_leaf() {
        let descriptor = format!("tr({A}/0/*,{{and_v(v:pk({B}/0/*),older(144)),pk({C}/0/*)}})");
        let snapshot = analyze_with(&descriptor, ScriptKind::Taproot, Vec::new());
        assert_eq!(snapshot.kind, PolicyKind::Miniscript);
        assert_eq!(snapshot.script, ScriptKind::Taproot);
        assert_eq!(
            snapshot.policy,
            "or(pk(Key A),and(pk(Key B),older(144)),pk(Key C))"
        );
        let roles: Vec<(BranchRole, &str, &str)> = snapshot
            .branches
            .iter()
            .map(|b| (b.role, b.label.as_str(), b.summary.as_str()))
            .collect();
        assert_eq!(
            roles,
            vec![
                (BranchRole::Primary, "Primary", "Key A"),
                (
                    BranchRole::Recovery,
                    "Recovery",
                    "Key B, once a coin has waited 144 blocks"
                ),
                (BranchRole::Primary, "Primary B", "Key C"),
            ]
        );
        // Keys without an origin still carry their own fingerprint.
        assert_eq!(snapshot.keys[0].fingerprint, Some("3442193e".into()));
        assert_eq!(snapshot.keys[1].fingerprint, Some("5c1bd648".into()));
        assert_eq!(snapshot.keys[0].origin_path, None);
    }

    #[test]
    fn a_hash_preimage_flags_the_branch() {
        let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let descriptor = format!("wsh(or_d(pk({A}/0/*),and_v(v:pk({B}/0/*),sha256({hash}))))");
        let snapshot = wsh(&descriptor, vec![coin("aa:0", Some(TIP), Some(NOW))]);
        let branch = &snapshot.branches[1];
        assert_eq!(branch.state, BranchState::NeedsPreimage);
        assert!(!branch.spendable_now);
        assert_eq!(branch.role, BranchRole::Other);
        assert_eq!(branch.label, "Other");
        assert_eq!(branch.summary, "Key B and the preimage of a sha256 hash");
        assert_eq!(
            branch.condition,
            Condition::Thresh {
                k: 2,
                n: 2,
                items: vec![
                    Condition::Key {
                        key_id: "k1".into()
                    },
                    Condition::Preimage {
                        hash: "sha256".into()
                    },
                ],
            }
        );
        assert!(snapshot.policy.contains(&format!("sha256({hash})")));
    }

    #[test]
    fn the_same_xpub_on_two_paths_is_one_key() {
        let descriptor = format!("wsh(or_d(pk({A}/0/*),and_v(v:pkh({A}/1/*),older(10))))");
        let snapshot = wsh(&descriptor, Vec::new());
        assert_eq!(snapshot.keys.len(), 1);
        assert_eq!(snapshot.policy, "or(pk(Key A),and(pk(Key A),older(10)))");
        assert_eq!(
            snapshot.branches[1].summary,
            "Key A, once a coin has waited 10 blocks"
        );
    }

    #[test]
    fn a_multipath_descriptor_is_read_on_its_first_path() {
        let descriptor = format!("wpkh({TPUB}/<0;1>/*)");
        let snapshot = analyze_with(&descriptor, ScriptKind::Segwit, Vec::new());
        assert_eq!(snapshot.kind, PolicyKind::SingleKey);
        assert_eq!(snapshot.descriptor, descriptor, "echoed as given");
        assert_eq!(snapshot.keys[0].fingerprint, Some("9a6a2580".into()));
    }

    #[test]
    fn an_optional_lock_does_not_close_a_branch() {
        let descriptor = format!("wsh(thresh(2,pk({A}/0/*),s:pk({B}/0/*),sln:older(100)))");
        let snapshot = wsh(&descriptor, Vec::new());
        assert_eq!(snapshot.branches.len(), 1, "a threshold is not an or");
        let branch = &snapshot.branches[0];
        assert_eq!(branch.role, BranchRole::Primary);
        assert_eq!(branch.state, BranchState::SpendableNow);
        assert_eq!(branch.timelocks.len(), 1);
        assert!(!branch.timelocks[0].required);
        assert_eq!(
            branch.timelocks[0].state,
            LockState::NoCoins {
                blocks: Some(100),
                seconds: None,
            }
        );
        assert!(snapshot.has_timelocks);
        assert_eq!(
            branch.summary,
            "Any 2 of: Key A, Key B, a coin having waited 100 blocks"
        );
    }

    #[test]
    fn keys_joined_in_an_and_read_as_a_list() {
        let descriptor = format!("wsh(and_v(v:pk({A}/0/*),and_v(v:pk({B}/0/*),pk({C}/0/*))))");
        let snapshot = wsh(&descriptor, Vec::new());
        assert_eq!(snapshot.kind, PolicyKind::Multisig, "3 of 3 is a threshold");
        assert_eq!(snapshot.branches[0].summary, "Keys A, B and C");
        assert_eq!(snapshot.policy, "and(pk(Key A),pk(Key B),pk(Key C))");
    }

    #[test]
    fn an_unreadable_descriptor_is_refused() {
        let garbage = analyze(PolicyInput {
            external_descriptor: "wsh(nothing)",
            script: ScriptKind::WitnessScript,
            coins: Vec::new(),
            tip_height: TIP,
            now_unix: NOW,
        });
        assert!(matches!(
            garbage,
            Err(CoreError::InvalidInput {
                kind: "descriptor",
                ..
            })
        ));

        // A height lock and a time lock on one path cannot be read as
        // one policy; miniscript refuses it, and so do we.
        let mixed = format!("wsh(and_v(v:pk({A}/0/*),and_v(v:after(900000),after(1900000000))))");
        assert!(
            analyze(PolicyInput {
                external_descriptor: &mixed,
                script: ScriptKind::WitnessScript,
                coins: Vec::new(),
                tip_height: TIP,
                now_unix: NOW,
            })
            .is_err()
        );
    }

    #[test]
    fn a_snapshot_survives_json_with_snake_case_tags() {
        let snapshot = wsh(&liana(), vec![coin("aa:0", Some(790_000), Some(NOW - 600))]);
        let json = serde_json::to_string(&snapshot).unwrap();
        for expected in [
            r#""kind":"miniscript""#,
            r#""script":"witness_script""#,
            r#""role":"recovery""#,
            r#""kind":"per_coin""#,
            r#""kind":"spendable_now""#,
            r#""kind":"relative""#,
            r#""kind":"blocks""#,
            r#""kind":"older""#,
            r#""kind":"thresh""#,
            r#""time_basis":"wall_clock""#,
            r#""spendable_now":true"#,
        ] {
            assert!(json.contains(expected), "{expected} missing in {json}");
        }
        let back: PolicySnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back, snapshot);
    }

    #[test]
    fn a_watched_address_has_nothing_to_read() {
        let snapshot = address_snapshot("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", 42, 1, NOW);
        assert_eq!(snapshot.kind, PolicyKind::Address);
        assert_eq!(snapshot.script, ScriptKind::Segwit);
        assert_eq!(snapshot.policy, "address");
        assert_eq!(
            snapshot.descriptor,
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        );
        assert!(snapshot.keys.is_empty());
        assert!(snapshot.branches.is_empty());
        assert_eq!(snapshot.tip_height, 42);
        assert_eq!(snapshot.coins, 1);
        assert!(!snapshot.has_timelocks);
    }

    #[test]
    fn wording_helpers_read_right() {
        assert_eq!(digits(0), "0");
        assert_eq!(digits(999), "999");
        assert_eq!(digits(52_560), "52,560");
        assert_eq!(digits(1_234_567), "1,234,567");
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(1_700_000_000), "2023-11-14");
        assert_eq!(date(1_900_000_000), "2030-03-17");
        assert_eq!(seconds_phrase(51_200), "about 14 hours");
        assert_eq!(seconds_phrase(3_600), "1 hour");
        assert_eq!(seconds_phrase(86_400 * 30), "30 days");
        assert_eq!(seconds_phrase(512 * 65_535), "about 388 days");
        assert_eq!(seconds_phrase(90), "90 seconds");
        assert_eq!(letter(0), "A");
        assert_eq!(letter(25), "Z");
        assert_eq!(letter(26), "27");
        assert_eq!(shorten("short"), "short");
        assert_eq!(
            join_and(vec!["a".into(), "b".into(), "c".into()]),
            "a, b and c"
        );
    }
}
