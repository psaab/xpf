// V3 sharded PMech session-owner directory (#9506 P2-forward).
//
// Greenfield core: exact transaction-owned forward/reverse/NAT wire/canonical
// aliases plus normalized plain-reply aliases. Sharded by seeded key hash so
// probes take at most one shard read lock; packet probes never touch the token
// index mutex. `active_claim_count` is the idle gate: packet probes Relaxed-load
// it first and return `Absent` with zero shard acquisition when it is 0.
//
// Count discipline (V3.5): increment BEFORE a claim becomes visible (while
// holding the target shard write locks, so probers block rather than miss);
// Pending -> UncertainDenied keeps the count unchanged; decrement only AFTER
// Live/removal/expiry is visible (locks released). Live/Absent share the same
// fall-through disposition, so skipping Live probes under the idle gate is safe.
//
// Lock order (deadlock-free): token-index mutex first, then key-shard write
// locks in ascending shard-index order. Probes take only one shard read lock.
// Token/waiter scan paths take only the token-index mutex.

use super::SessionKey;
use rustc_hash::FxSeededState;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::{
    Mutex, OnceLock, RwLock,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};

/// Fixed token capacity: one slot per D11 input slot (V4 D.2).
pub(crate) const PMECH_MAX_TRANSACTIONS: usize = 512;
/// Global cap on held reverse waiters (V4 E).
pub(crate) const PMECH_MAX_HELD_WAITERS_TOTAL: usize = 512;
/// Per-token cap on held reverse waiters (V4 E).
pub(crate) const PMECH_MAX_WAITERS_PER_TOKEN: usize = 4;

/// Fixed shard count. Must stay a power of two (`SHARD_MASK` relies on it).
const NUM_SHARDS: usize = 32;
const SHARD_MASK: usize = 31;

/// Packet direction a claim was reserved for. Preserved so callers can apply
/// V3.3 disposition: reverse Pending holds, duplicate-forward Pending refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum PMechDirection {
    Forward,
    Reverse,
}

/// Which Pending family a spec claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum PMechClaimKind {
    /// Ipsec-tagged exact forward/reverse/NAT alias.
    Pending,
    /// Normalized (`discriminator: None, routing_domain: 0`) plain-reply alias.
    PendingPlainAlias,
}

/// One key claim inside a `reserve_claims` plan.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PMechClaimSpec {
    pub key: SessionKey,
    pub kind: PMechClaimKind,
    pub direction: PMechDirection,
}

impl PMechClaimSpec {
    pub(crate) fn new(key: SessionKey, kind: PMechClaimKind, direction: PMechDirection) -> Self {
        Self { key, kind, direction }
    }
}

/// Packet-probe outcome. `Live`/`Absent` both fall through to ordinary
/// committed-session authority; `Pending`/`PendingPlainAlias` hold (reverse)
/// or refuse (duplicate forward); `UncertainDenied` drops fail-closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PMechDirectoryProbe {
    Absent,
    Pending { token: u64, owner_generation: u64, direction: PMechDirection },
    PendingPlainAlias { token: u64, owner_generation: u64, direction: PMechDirection },
    Live {
        token: u64,
        owner_generation: u64,
        direction: PMechDirection,
        forward_session_id: u64,
        reverse_session_id: u64,
    },
    UncertainDenied {
        token: u64,
        owner_generation: u64,
        direction: PMechDirection,
        plan_expiry_ns: u64,
    },
}

impl PMechDirectoryProbe {
    /// Hold (reverse) / refuse (duplicate forward): never install or deliver.
    pub(crate) fn is_hold(&self) -> bool {
        matches!(
            self,
            Self::Pending { .. } | Self::PendingPlainAlias { .. }
        )
    }
    /// Fail-closed drop with exactly-once recycle.
    pub(crate) fn is_drop(&self) -> bool {
        matches!(self, Self::UncertainDenied { .. })
    }
    /// Fall through to ordinary authority bit-identically.
    pub(crate) fn is_fallthrough(&self) -> bool {
        matches!(self, Self::Absent | Self::Live { .. })
    }
    pub(crate) fn token(&self) -> Option<u64> {
        match *self {
            Self::Absent => None,
            Self::Pending { token, .. }
            | Self::PendingPlainAlias { token, .. }
            | Self::Live { token, .. }
            | Self::UncertainDenied { token, .. } => Some(token),
        }
    }
}

/// Token-level state for the per-binding reverse-ring scan. Unlike packet
/// probes this is NOT idle-gated: a Live token must stay observable after
/// `active_claim_count` drops to 0 so the scan can replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PMechTokenProbe {
    /// Unknown, rolled back via `remove_token`, or reaped after expiry.
    Absent,
    Pending { owner_generation: u64 },
    Live { owner_generation: u64, forward_session_id: u64, reverse_session_id: u64 },
    UncertainDenied { owner_generation: u64, plan_expiry_ns: u64 },
}

impl PMechTokenProbe {
    /// Keep holding the ring entry.
    pub(crate) fn should_hold(&self) -> bool {
        matches!(self, Self::Pending { .. })
    }
    /// Replay the held descriptor once.
    pub(crate) fn should_replay(&self) -> bool {
        matches!(self, Self::Live { .. })
    }
    /// Recycle exactly once, no replay. Covers both fail-closed Uncertain and
    /// rollback/reap Absent: every terminal state recycles.
    pub(crate) fn should_recycle(&self) -> bool {
        matches!(self, Self::UncertainDenied { .. } | Self::Absent)
    }
}

/// Directory-minted waiter reference. Fixed two integers only; the `XdpDesc`
/// and UMEM slot stay owned by the arrival `BindingWorker` ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PMechWaiterRef {
    pub arrival_worker_id: u32,
    pub defer_id: u64,
}

/// Reserve failure. Conflicts never displace the prior value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PMechReserveError {
    /// Empty spec slice reserves nothing and mints no token.
    EmptyPlan,
    /// Reservation inputs do not identify a valid unidirectional IPsec plan.
    InvalidPlan,
    /// Live token count already at `PMECH_MAX_TRANSACTIONS`.
    CapacityExceeded,
    /// Key already owned (any state) or same key twice with different
    /// kind/direction inside one plan.
    Conflict { key: SessionKey },
}

impl std::fmt::Display for PMechReserveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyPlan => write!(f, "pmech reserve: empty plan"),
            Self::InvalidPlan => write!(f, "pmech reserve: invalid IPsec plan"),
            Self::CapacityExceeded => write!(f, "pmech reserve: transaction cap exceeded"),
            Self::Conflict { key } => write!(f, "pmech reserve: conflicting claim for {key:?}"),
        }
    }
}

impl std::error::Error for PMechReserveError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClaimState {
    Pending,
    PendingPlainAlias,
    Live { forward_session_id: u64, reverse_session_id: u64 },
    UncertainDenied { plan_expiry_ns: u64 },
}

impl ClaimState {
    fn is_counted(&self) -> bool {
        matches!(
            self,
            Self::Pending | Self::PendingPlainAlias | Self::UncertainDenied { .. }
        )
    }
}

#[derive(Clone, Debug)]
struct ClaimRecord {
    token: u64,
    owner_generation: u64,
    direction: PMechDirection,
    state: ClaimState,
}

impl ClaimRecord {
    fn to_probe(&self) -> PMechDirectoryProbe {
        match self.state {
            ClaimState::Pending => PMechDirectoryProbe::Pending {
                token: self.token,
                owner_generation: self.owner_generation,
                direction: self.direction,
            },
            ClaimState::PendingPlainAlias => PMechDirectoryProbe::PendingPlainAlias {
                token: self.token,
                owner_generation: self.owner_generation,
                direction: self.direction,
            },
            ClaimState::Live { forward_session_id, reverse_session_id } => {
                PMechDirectoryProbe::Live {
                    token: self.token,
                    owner_generation: self.owner_generation,
                    direction: self.direction,
                    forward_session_id,
                    reverse_session_id,
                }
            }
            ClaimState::UncertainDenied { plan_expiry_ns } => {
                PMechDirectoryProbe::UncertainDenied {
                    token: self.token,
                    owner_generation: self.owner_generation,
                    direction: self.direction,
                    plan_expiry_ns,
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenState {
    Pending,
    Live { forward_session_id: u64, reverse_session_id: u64 },
    UncertainDenied { plan_expiry_ns: u64 },
}

#[derive(Clone, Debug)]
struct TokenRecord {
    owner_generation: u64,
    state: TokenState,
    keys: Vec<SessionKey>,
    waiters: SmallVec<[PMechWaiterRef; 4]>,
    plan_expiry_ns: u64,
}

type ShardMap = HashMap<SessionKey, ClaimRecord, FxSeededState>;

/// Sharded global/session-owner PMech directory (V3 + V4 E).
///
/// All methods take `&self`; interior mutability (shard `RwLock`s, token
/// `Mutex`, atomics) makes the `global()` singleton shareable across workers.
pub(crate) struct PMechSessionDirectory {
    shards: [RwLock<ShardMap>; NUM_SHARDS],
    shard_hasher: FxSeededState,
    tokens: Mutex<HashMap<u64, TokenRecord>>,
    active_claim_count: AtomicUsize,
    held_waiters: AtomicUsize,
    next_token: AtomicU64,
    #[cfg(test)]
    shard_reads: AtomicUsize,
}

impl PMechSessionDirectory {
    pub(crate) fn new() -> Self {
        let seed = crate::hot_hash_seed::hot_path_hash_seed() as usize;
        Self {
            shards: std::array::from_fn(|_| {
                RwLock::new(HashMap::with_hasher(FxSeededState::with_seed(seed)))
            }),
            shard_hasher: FxSeededState::with_seed(seed),
            tokens: Mutex::new(HashMap::new()),
            active_claim_count: AtomicUsize::new(0),
            held_waiters: AtomicUsize::new(0),
            next_token: AtomicU64::new(1),
            #[cfg(test)]
            shard_reads: AtomicUsize::new(0),
        }
    }

    /// Process-global singleton.
    pub(crate) fn global() -> &'static Self {
        static GLOBAL: OnceLock<PMechSessionDirectory> = OnceLock::new();
        GLOBAL.get_or_init(Self::new)
    }

    /// Idle-gate counter: Pending + PendingPlainAlias + UncertainDenied keys.
    /// Live and absent do not count. Relaxed load.
    #[inline]
    pub(crate) fn active_claim_count(&self) -> usize {
        self.active_claim_count.load(Ordering::Relaxed)
    }

    /// Total held waiter refs across all tokens. Relaxed load.
    #[inline]
    pub(crate) fn held_waiter_count(&self) -> usize {
        self.held_waiters.load(Ordering::Relaxed)
    }

    #[inline]
    fn shard_index(&self, key: &SessionKey) -> usize {
        let mut hasher = self.shard_hasher.build_hasher();
        key.hash(&mut hasher);
        (hasher.finish() as usize) & SHARD_MASK
    }

    #[inline]
    fn read_shard(&self, idx: usize) -> std::sync::RwLockReadGuard<'_, ShardMap> {
        #[cfg(test)]
        self.shard_reads.fetch_add(1, Ordering::Relaxed);
        self.shards[idx].read().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// V3 hold probe: normalize `candidate` with the single existing
    /// `normalized_reply_alias_key` helper, then one sharded get. Idle-gated
    /// (zero shard acquisition when the count is 0); never skips on
    /// discriminator since the normalized key is `None` by construction.
    pub(crate) fn probe_normalized_alias(
        &self,
        candidate: &SessionKey,
    ) -> PMechDirectoryProbe {
        if self.active_claim_count.load(Ordering::Relaxed) == 0 {
            return PMechDirectoryProbe::Absent;
        }
        let normalized = super::normalized_reply_alias_key(candidate);
        let idx = self.shard_index(&normalized);
        let shard = self.read_shard(idx);
        shard.get(&normalized).map_or(PMechDirectoryProbe::Absent, |rec| rec.to_probe())
    }

    /// Exact single-shard get on `key` as given (no normalization). Callers
    /// seeking `PendingPlainAlias` pass an already-normalized key (e.g. from
    /// `ipsec_reply_alias_keys`); callers seeking Ipsec `Pending` pass the
    /// tagged key. Idle-gated. The directory enforces no discriminator skip;
    /// exact-key Ipsec call sites keep their `None` skip before calling.
    pub(crate) fn probe_normalized_key(&self, key: &SessionKey) -> PMechDirectoryProbe {
        if self.active_claim_count.load(Ordering::Relaxed) == 0 {
            return PMechDirectoryProbe::Absent;
        }
        let idx = self.shard_index(key);
        let shard = self.read_shard(idx);
        shard.get(key).map_or(PMechDirectoryProbe::Absent, |rec| rec.to_probe())
    }

    /// Alias for `probe_normalized_key` with exact-lookup naming for call sites
    /// that think in exact (Ipsec-tagged) terms. Identical semantics.
    #[inline]
    pub(crate) fn probe_exact(&self, key: &SessionKey) -> PMechDirectoryProbe {
        self.probe_normalized_key(key)
    }

    /// Probe the identity class relevant to one packet. Exact IPsec tuples
    /// use one tagged lookup; untagged packets use one normalized alias lookup.
    pub(crate) fn probe_packet_key(&self, key: &SessionKey) -> PMechDirectoryProbe {
        match key.discriminator {
            super::TunnelDiscriminator::Ipsec(if_id) if if_id != 0 => self.probe_exact(key),
            super::TunnelDiscriminator::None => self.probe_normalized_alias(key),
            _ => PMechDirectoryProbe::Absent,
        }
    }
    /// Return whether an ordinary install would collide with a non-fallthrough
    /// PMech claim. Forward installs check both normalized reply aliases;
    /// reverse installs check the normalized candidate key. Live claims fall
    /// through to committed session authority and do not fence installs.
    pub(crate) fn conflicts_with_install(
        &self,
        key: &SessionKey,
        nat: super::NatDecision,
        is_reverse: bool,
        exclude_token: Option<u64>,
    ) -> bool {
        if self.active_claim_count.load(Ordering::Relaxed) == 0 {
            return false;
        }
        if is_reverse {
            return self.install_key_conflicts(&super::normalized_reply_alias_key(key), exclude_token);
        }
        super::ipsec_reply_alias_keys(key, nat)
            .iter()
            .any(|alias| self.install_key_conflicts(alias, exclude_token))
    }

    #[inline]
    fn install_key_conflicts(&self, key: &SessionKey, exclude_token: Option<u64>) -> bool {
        let probe = self.probe_normalized_key(key);
        probe.token() != exclude_token && (probe.is_hold() || probe.is_drop())
    }

    #[cfg(test)]
    fn shard_read_count(&self) -> usize {
        self.shard_reads.load(Ordering::Relaxed)
    }

    /// Token state for the reverse-ring scan/wake path. NOT idle-gated and
    /// takes no shard lock (token index only) so Live stays observable after
    /// the count drops to 0. Scan contract: Pending holds, Live replays,
    /// UncertainDenied/Absent recycles exactly once.
    pub(crate) fn probe_token(&self, token: u64) -> PMechTokenProbe {
        let tokens = self.tokens.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match tokens.get(&token) {
            None => PMechTokenProbe::Absent,
            Some(rec) => match rec.state {
                TokenState::Pending => PMechTokenProbe::Pending {
                    owner_generation: rec.owner_generation,
                },
                TokenState::Live { forward_session_id, reverse_session_id } => {
                    PMechTokenProbe::Live {
                        owner_generation: rec.owner_generation,
                        forward_session_id,
                        reverse_session_id,
                    }
                }
                TokenState::UncertainDenied { plan_expiry_ns } => {
                    PMechTokenProbe::UncertainDenied {
                        owner_generation: rec.owner_generation,
                        plan_expiry_ns,
                    }
                }
            },
        }
    }

    /// Alias for `probe_token` for scan call sites that prefer the
    /// token-state naming. Identical semantics (no idle gate).
    #[inline]
    pub(crate) fn token_state(&self, token: u64) -> PMechTokenProbe {
        self.probe_token(token)
    }

    /// Atomically reserve every deduped spec under one fresh token. Stable
    /// lock order (token mutex, then shards ascending); all-or-nothing:
    /// any conflicting prior key (any state, never displaced) or a full
    /// 512-token table refuses without inserting. Count is incremented while
    /// holding the write locks, before the claims become visible.
    pub(crate) fn reserve_claims(
        &self,
        owner_generation: u64,
        plan_expiry_ns: u64,
        specs: &[PMechClaimSpec],
    ) -> Result<u64, PMechReserveError> {
        if specs.is_empty() {
            return Err(PMechReserveError::EmptyPlan);
        }
        let mut deduped: Vec<PMechClaimSpec> = Vec::with_capacity(specs.len());
        for spec in specs {
            if !deduped.iter().any(|d| d == spec) {
                deduped.push(spec.clone());
            }
        }
        for i in 0..deduped.len() {
            for other in deduped.iter().skip(i + 1) {
                if deduped[i].key == other.key {
                    return Err(PMechReserveError::Conflict { key: deduped[i].key.clone() });
                }
            }
        }

        let mut tokens = self.tokens.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if tokens.len() >= PMECH_MAX_TRANSACTIONS {
            return Err(PMechReserveError::CapacityExceeded);
        }

        let mut shard_idxs: Vec<usize> =
            deduped.iter().map(|spec| self.shard_index(&spec.key)).collect();
        shard_idxs.sort_unstable();
        shard_idxs.dedup();
        let mut guards = Vec::with_capacity(shard_idxs.len());
        for idx in &shard_idxs {
            guards.push(self.shards[*idx].write().unwrap_or_else(|poisoned| poisoned.into_inner()));
        }
        for spec in &deduped {
            let idx = self.shard_index(&spec.key);
            let Some(pos) = shard_idxs.iter().position(|candidate| *candidate == idx) else {
                debug_assert!(false, "reserve: shard index missing for own key");
                return Err(PMechReserveError::Conflict { key: spec.key.clone() });
            };
            if guards[pos].contains_key(&spec.key) {
                return Err(PMechReserveError::Conflict { key: spec.key.clone() });
            }
        }


        let mut token = self.next_token.fetch_add(1, Ordering::Relaxed);
        if token == 0 {
            token = self.next_token.fetch_add(1, Ordering::Relaxed);
        }
        debug_assert_ne!(token, 0);

        self.active_claim_count.fetch_add(deduped.len(), Ordering::Relaxed);

        let mut keys = Vec::with_capacity(deduped.len());
        for spec in &deduped {
            let idx = self.shard_index(&spec.key);
            let Some(pos) = shard_idxs.iter().position(|candidate| *candidate == idx) else {
                debug_assert!(false, "reserve: shard index missing on insert path");
                continue;
            };
            let guard = &mut guards[pos];
            let state = match spec.kind {
                PMechClaimKind::Pending => ClaimState::Pending,
                PMechClaimKind::PendingPlainAlias => ClaimState::PendingPlainAlias,
            };
            guard.insert(
                spec.key.clone(),
                ClaimRecord { token, owner_generation, direction: spec.direction, state },
            );
            keys.push(spec.key.clone());
        }
        tokens.insert(
            token,
            TokenRecord {
                owner_generation,
                state: TokenState::Pending,
                keys,
                waiters: SmallVec::new(),
                plan_expiry_ns,
            },
        );
        Ok(token)
    }

    /// Pending -> UncertainDenied on every key of `token`. Count unchanged so
    /// the DROP probes are never hidden by the idle gate. Idempotent when
    /// already Uncertain (keeps the first expiry); refuses Live/unknown and
    /// generation mismatches without touching the count.
    pub(crate) fn mark_uncertain(
        &self,
        token: u64,
        owner_generation: u64,
        plan_expiry_ns: u64,
    ) -> bool {
        let mut tokens = self.tokens.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(rec) = tokens.get_mut(&token) else {
            return false;
        };
        if rec.owner_generation != owner_generation {
            return false;
        }
        match rec.state {
            TokenState::Pending => {}
            TokenState::UncertainDenied { .. } => return true,
            TokenState::Live { .. } => return false,
        }
        let keys = rec.keys.clone();
        let mut shard_idxs: Vec<usize> =
            keys.iter().map(|key| self.shard_index(key)).collect();
        shard_idxs.sort_unstable();
        shard_idxs.dedup();
        let mut guards = Vec::with_capacity(shard_idxs.len());
        for idx in &shard_idxs {
            guards.push(self.shards[*idx].write().unwrap_or_else(|poisoned| poisoned.into_inner()));
        }
        for key in &keys {
            let idx = self.shard_index(key);
            let Some(pos) = shard_idxs.iter().position(|candidate| *candidate == idx) else {
                debug_assert!(false, "mark_uncertain: shard index missing for own key");
                continue;
            };
            if let Some(entry) = guards[pos].get_mut(key) {
                if entry.token == token {
                    entry.state = ClaimState::UncertainDenied { plan_expiry_ns };
                }
            }
        }
        if let Some(rec) = tokens.get_mut(&token) {
            rec.state = TokenState::UncertainDenied { plan_expiry_ns };
            rec.plan_expiry_ns = plan_expiry_ns;
        }
        true
    }

    /// Pending -> Live on every key of `token`, publishing the committed
    /// session ids. Decrements only after Live is visible (locks released).
    /// Leaves the Live token record until `remove_token` so the scan can
    /// replay; idempotent on same ids, refuses Uncertain/unknown, generation
    /// or id mismatches.
    pub(crate) fn mark_live(
        &self,
        token: u64,
        owner_generation: u64,
        forward_session_id: u64,
        reverse_session_id: u64,
    ) -> bool {
        let transitioned: usize;
        {
            let mut tokens = self.tokens.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(rec) = tokens.get_mut(&token) else {
                return false;
            };
            if rec.owner_generation != owner_generation {
                return false;
            }
            match rec.state {
                TokenState::Pending => {}
                TokenState::Live { forward_session_id: live_fwd, reverse_session_id: live_rev } => {
                    return live_fwd == forward_session_id && live_rev == reverse_session_id;
                }
                TokenState::UncertainDenied { .. } => return false,
            }
            let keys = rec.keys.clone();
            let mut shard_idxs: Vec<usize> =
                keys.iter().map(|key| self.shard_index(key)).collect();
            shard_idxs.sort_unstable();
            shard_idxs.dedup();
            let mut guards = Vec::with_capacity(shard_idxs.len());
            for idx in &shard_idxs {
                guards.push(
                    self.shards[*idx].write().unwrap_or_else(|poisoned| poisoned.into_inner()),
                );
            }
            let mut live_count = 0usize;
            for key in &keys {
                let idx = self.shard_index(key);
                let Some(pos) = shard_idxs.iter().position(|candidate| *candidate == idx) else {
                    debug_assert!(false, "mark_live: shard index missing for own key");
                    continue;
                };
                if let Some(entry) = guards[pos].get_mut(key) {
                    if entry.token == token {
                        if entry.state.is_counted() {
                            live_count += 1;
                        }
                        entry.state = ClaimState::Live { forward_session_id, reverse_session_id };
                    }
                }
            }
            if let Some(rec) = tokens.get_mut(&token) {
                rec.state = TokenState::Live { forward_session_id, reverse_session_id };
            }
            transitioned = live_count;
        }
        if transitioned > 0 {
            self.active_claim_count.fetch_sub(transitioned, Ordering::Relaxed);
        }
        true
    }

    /// Remove `token` entirely (rollback NothingWritten/pre-write-cancel, or
    /// post-replay cleanup after Live). Publishes removal before decrementing;
    /// Live keys do not decrement. Discarded waiter refs free the global hold
    /// budget; the scan recycles via the resulting Absent.
    pub(crate) fn remove_token(&self, token: u64, owner_generation: u64) -> bool {
        let removed_counted: usize;
        let freed_waiters: usize;
        {
            let mut tokens = self.tokens.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            match tokens.get(&token) {
                Some(rec) if rec.owner_generation == owner_generation => {}
                _ => return false,
            }
            let Some(rec) = tokens.remove(&token) else {
                return false;
            };
            freed_waiters = rec.waiters.len();
            let mut shard_idxs: Vec<usize> =
                rec.keys.iter().map(|key| self.shard_index(key)).collect();
            shard_idxs.sort_unstable();
            shard_idxs.dedup();
            let mut guards = Vec::with_capacity(shard_idxs.len());
            for idx in &shard_idxs {
                guards.push(
                    self.shards[*idx].write().unwrap_or_else(|poisoned| poisoned.into_inner()),
                );
            }
            let mut counted = 0usize;
            for key in &rec.keys {
                let idx = self.shard_index(key);
                let Some(pos) = shard_idxs.iter().position(|candidate| *candidate == idx) else {
                    debug_assert!(false, "remove_token: shard index missing for own key");
                    continue;
                };
                if let Some(entry) = guards[pos].remove(key) {
                    if entry.token == token && entry.state.is_counted() {
                        counted += 1;
                    } else if entry.token != token {
                        debug_assert!(false, "remove_token: key re-owned by another token");
                        guards[pos].insert(key.clone(), entry);
                    }
                }
            }
            removed_counted = counted;
        }
        if removed_counted > 0 {
            self.active_claim_count.fetch_sub(removed_counted, Ordering::Relaxed);
        }
        if freed_waiters > 0 {
            self.held_waiters.fetch_sub(freed_waiters, Ordering::Relaxed);
        }
        true
    }

    /// Reap UncertainDenied tokens at or past `now_ns`. Pending is never
    /// reaped here (the owner must terminalize via mark_live/mark_uncertain/
    /// remove_token). Returns the number of tokens reaped. Decrements after
    /// removal is visible.
    pub(crate) fn expire_uncertain(&self, now_ns: u64) -> usize {
        let removed_counted: usize;
        let freed_waiters: usize;
        let reaped: usize;
        {
            let mut tokens = self.tokens.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut expired: Vec<(u64, Vec<SessionKey>, usize)> = Vec::new();
            for (token, rec) in tokens.iter() {
                if let TokenState::UncertainDenied { plan_expiry_ns } = rec.state {
                    if plan_expiry_ns <= now_ns {
                        expired.push((*token, rec.keys.clone(), rec.waiters.len()));
                    }
                }
            }
            if expired.is_empty() {
                return 0;
            }
            let mut all: Vec<(u64, SessionKey)> = Vec::new();
            for (token, keys, _) in &expired {
                for key in keys {
                    all.push((*token, key.clone()));
                }
            }
            let mut shard_idxs: Vec<usize> =
                all.iter().map(|(_, key)| self.shard_index(key)).collect();
            shard_idxs.sort_unstable();
            shard_idxs.dedup();
            let mut guards = Vec::with_capacity(shard_idxs.len());
            for idx in &shard_idxs {
                guards.push(
                    self.shards[*idx].write().unwrap_or_else(|poisoned| poisoned.into_inner()),
                );
            }
            let mut counted = 0usize;
            for (token, key) in &all {
                let idx = self.shard_index(key);
                let Some(pos) = shard_idxs.iter().position(|candidate| *candidate == idx) else {
                    debug_assert!(false, "expire_uncertain: shard index missing for own key");
                    continue;
                };
                if let Some(entry) = guards[pos].remove(key) {
                    if entry.token == *token && entry.state.is_counted() {
                        counted += 1;
                    } else if entry.token != *token {
                        debug_assert!(false, "expire_uncertain: key re-owned by another token");
                        guards[pos].insert(key.clone(), entry);
                    }
                }
            }
            let mut waiters = 0usize;
            for (token, _, waiter_len) in &expired {
                if tokens.remove(token).is_some() {
                    waiters += *waiter_len;
                }
            }
            removed_counted = counted;
            freed_waiters = waiters;
            reaped = expired.len();
        }
        if removed_counted > 0 {
            self.active_claim_count.fetch_sub(removed_counted, Ordering::Relaxed);
        }
        if freed_waiters > 0 {
            self.held_waiters.fetch_sub(freed_waiters, Ordering::Relaxed);
        }
        reaped
    }

    /// Hold one reverse waiter on a Pending token. False when the token is
    /// unknown, generation-mismatched, already Live/Uncertain (caller must
    /// replay/drop instead of holding), per-token full (4), or globally full
    /// (512). Duplicate (worker, defer) registration is idempotent true.
    pub(crate) fn register_waiter(
        &self,
        token: u64,
        owner_generation: u64,
        arrival_worker_id: u32,
        defer_id: u64,
    ) -> bool {
        if self.held_waiters.load(Ordering::Relaxed) >= PMECH_MAX_HELD_WAITERS_TOTAL {
            return false;
        }
        let mut tokens = self.tokens.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(rec) = tokens.get_mut(&token) else {
            return false;
        };
        if rec.owner_generation != owner_generation {
            return false;
        }
        if !matches!(rec.state, TokenState::Pending) {
            return false;
        }
        if rec
            .waiters
            .iter()
            .any(|w| w.arrival_worker_id == arrival_worker_id && w.defer_id == defer_id)
        {
            return true;
        }
        if rec.waiters.len() >= PMECH_MAX_WAITERS_PER_TOKEN {
            return false;
        }
        loop {
            let current = self.held_waiters.load(Ordering::Relaxed);
            if current >= PMECH_MAX_HELD_WAITERS_TOTAL {
                return false;
            }
            match self.held_waiters.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
        rec.waiters.push(PMechWaiterRef { arrival_worker_id, defer_id });
        true
    }

    /// Release one waiter ref. True when a matching ref was present. Allowed
    /// in any token state so scan cleanup after Live/Uncertain still frees
    /// the budget; unknown tokens or generation mismatches return false.
    pub(crate) fn remove_waiter(
        &self,
        token: u64,
        owner_generation: u64,
        arrival_worker_id: u32,
        defer_id: u64,
    ) -> bool {
        let mut tokens = self.tokens.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(rec) = tokens.get_mut(&token) else {
            return false;
        };
        if rec.owner_generation != owner_generation {
            return false;
        }
        let Some(pos) = rec
            .waiters
            .iter()
            .position(|w| w.arrival_worker_id == arrival_worker_id && w.defer_id == defer_id)
        else {
            return false;
        };
        rec.waiters.swap_remove(pos);
        self.held_waiters.fetch_sub(1, Ordering::Relaxed);
        true
    }

    /// Drain every waiter ref for `token` (owner wake after Live). Frees the
    /// global budget by the drained length. Empty when unknown or mismatched.
    pub(crate) fn take_waiters(
        &self,
        token: u64,
        owner_generation: u64,
    ) -> SmallVec<[PMechWaiterRef; 4]> {
        let mut tokens = self.tokens.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(rec) = tokens.get_mut(&token) else {
            return SmallVec::new();
        };
        if rec.owner_generation != owner_generation {
            return SmallVec::new();
        }
        let taken = std::mem::take(&mut rec.waiters);
        if !taken.is_empty() {
            self.held_waiters.fetch_sub(taken.len(), Ordering::Relaxed);
        }
        taken
    }
}

impl Default for PMechSessionDirectory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ipsec_key() -> SessionKey {
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: crate::ip_proto::PROTO_UDP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 95, 6, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 95)),
            src_port: 40_950,
            dst_port: 443,
            discriminator: super::super::TunnelDiscriminator::Ipsec(95_006),
            routing_domain: 7,
        }
    }

    #[test]
    fn pending_and_uncertain_fence_aliases_then_live_idle_gates() {
        let directory = PMechSessionDirectory::new();
        let key = ipsec_key();
        let alias = SessionKey {
            addr_family: key.addr_family,
            protocol: key.protocol,
            src_ip: key.dst_ip,
            dst_ip: key.src_ip,
            src_port: key.dst_port,
            dst_port: key.src_port,
            discriminator: super::super::TunnelDiscriminator::None,
            routing_domain: 0,
        };
        let specs = [
            PMechClaimSpec::new(key.clone(), PMechClaimKind::Pending, PMechDirection::Forward),
            PMechClaimSpec::new(
                alias.clone(),
                PMechClaimKind::PendingPlainAlias,
                PMechDirection::Reverse,
            ),
        ];
        let token = directory
            .reserve_claims(7, 100, &specs)
            .expect("distinct IPsec and plain aliases reserve together");
        assert_eq!(directory.active_claim_count(), 2);
        assert!(matches!(
            directory.probe_packet_key(&key),
            PMechDirectoryProbe::Pending {
                token: found,
                direction: PMechDirection::Forward,
                ..
            } if found == token
        ));
        assert!(matches!(
            directory.probe_packet_key(&alias),
            PMechDirectoryProbe::PendingPlainAlias {
                token: found,
                direction: PMechDirection::Reverse,
                ..
            } if found == token
        ));
        assert!(directory.conflicts_with_install(
            &SessionKey {
                discriminator: super::super::TunnelDiscriminator::None,
                routing_domain: 0,
                ..key.clone()
            },
            crate::nat::NatDecision::default(),
            false,
            None,
        ));

        assert!(directory.mark_uncertain(token, 7, 100));
        assert_eq!(directory.active_claim_count(), 2);
        assert!(directory.probe_packet_key(&key).is_drop());
        assert!(directory.probe_packet_key(&alias).is_drop());
        assert_eq!(directory.expire_uncertain(100), 1);
        assert_eq!(directory.active_claim_count(), 0);

        let live_token = directory
            .reserve_claims(8, 200, &specs)
            .expect("expired uncertain claims are reusable");
        assert!(directory.mark_live(live_token, 8, 101, 102));
        assert_eq!(directory.active_claim_count(), 0);
        let reads = directory.shard_read_count();
        assert_eq!(directory.probe_packet_key(&key), PMechDirectoryProbe::Absent);
        assert_eq!(directory.probe_packet_key(&alias), PMechDirectoryProbe::Absent);
        assert_eq!(directory.shard_read_count(), reads);
        assert!(!directory.conflicts_with_install(
            &key,
            crate::nat::NatDecision::default(),
            false,
            None,
        ));
    }
}
