use super::*;
use crate::hot_hash_seed::HotPathSeededState;
use crate::session::{BareSessionTuple, SessionScope};
use std::collections::{HashMap, HashSet};
pub(in crate::afxdp) type FastMap<K, V> = FxHashMap<K, V>;
pub(in crate::afxdp) type FastSet<T> = FxHashSet<T>;
pub(in crate::afxdp) type OwnerRgSessionIndex = FastMap<i32, FastSet<SessionKey>>;
/// Per-wire-key owner multiset payload (#15106): the live forward owners
/// claiming one shared alias key, in publish order. Inline capacity 2 so
/// the common zero-/one-owner cases never heap-allocate a roster.
pub(in crate::afxdp) type WireOwnerRoster = smallvec::SmallVec<[SessionKey; 2]>;
/// Wire/catalogue-side key -> live owner roster (#15106).
pub(in crate::afxdp) type WireOwnerMultiset = FastMap<SessionKey, WireOwnerRoster>;
/// Bounded live history of reverse aliases. Domain-neutral owners let an
/// unstamped fabric reply reject a tuple that exists in multiple routing
/// instances. Once the live bound is reached, every such exception fails
/// closed until removals bring the live population back below the bound
/// (#15104: saturation is computed from the live size, never latched).
pub(in crate::afxdp) struct SharedNatAmbiguityIndex {
    aliases: FastMap<SessionKey, Option<SessionKey>>,
    /// #15106/#16561: per-wire-key live-owner multiset. Its LOCK is shared
    /// with `aliases` (the same mutex), so observe/remove and ambiguity
    /// state move together. The roster is NOT capped at the alias bound:
    /// its capacity is the shared-session ceiling (see `MAX_WIRE_KEYS`),
    /// so a roster that recorded every owner stays exact for every
    /// population the shared map can actually hold. Trust is a function
    /// of the LIVE population (#16561): a `wire_saturated` latch that
    /// never resets short of a full stop is forbidden — the only
    /// untrusted state is a live population at/above the roster ceiling,
    /// which removals clear without a helper restart (#15104 rule).
    wire_owners: WireOwnerMultiset,
    // #15104: per-alias owner multiset. `aliases` alone cannot tell a
    // removal whether another live forward entry still maps to the same
    // alias, so publish/remove maintain this count and `forget_owner`
    // drops the alias record only when its last owner leaves. Owners are
    // counted per (alias, owner) pair: re-publishing the same owner for
    // the same alias does not inflate the count.
    owners: FastMap<SessionKey, FastMap<SessionKey, u32>>,
    /// #16564: bounded FIFO of `(alias, owner)` claims whose `remember`
    /// was refused while saturated. `owners` records every claim even
    /// then, but the alias record itself is dropped, so without this list
    /// a session published inside a saturation excursion would stay
    /// unresolvable for its whole lifetime. The list is drained, in
    /// arrival order, only into free alias capacity (see
    /// `backfill_unrecorded`); it is not a second alias map and never
    /// grows the live population past `MAX_KEYS`.
    unrecorded: std::collections::VecDeque<(SessionKey, SessionKey)>,
    /// #16564: membership mirror of `unrecorded`, so re-observing the
    /// same claim (re-publish of a saturated-era owner, repeated
    /// removals) never duplicates a queued entry.
    unrecorded_set: FastSet<(SessionKey, SessionKey)>,
}

impl Default for SharedNatAmbiguityIndex {
    fn default() -> Self {
        Self {
            aliases: FastMap::default(),
            wire_owners: WireOwnerMultiset::default(),
            owners: FastMap::default(),
            unrecorded: std::collections::VecDeque::default(),
            unrecorded_set: FastSet::default(),
        }
    }
}

/// #16561 test seam: live wire-key population at/above this bound makes
/// the roster untrusted. Production always uses `MAX_WIRE_KEYS`; a test
/// override lets cells exercise the live saturation/recovery boundary
/// without publishing 2M sessions.
#[cfg(test)]
pub(in crate::afxdp) static WIRE_KEY_CAP_OVERRIDE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

impl SharedNatAmbiguityIndex {
    const MAX_KEYS: usize = 16_384;
    /// #16564: hard cap on the unrecorded-claims FIFO, equal to the alias
    /// bound. A deeper queue could never drain (each entry needs a free
    /// alias slot), so claims past the cap are shed — they keep failing
    /// closed, exactly as before this change.
    const MAX_UNRECORDED: usize = Self::MAX_KEYS;

    /// #16561: roster capacity, DECOUPLED from the alias cap above. The
    /// alias index fails closed at 16,384 live keys (#15104); the wire
    /// roster must stay exact for every population the shared session
    /// map can hold, so it is sized to the shared-session ceiling: the
    /// synced-import ENTRY cap is `2 * worker_count *
    /// DEFAULT_MAX_SESSIONS` (131,072 per worker, see
    /// `synced_import_cap_for`). The roster counts DISTINCT WIRE KEYS,
    /// at most one per live forward session, so the population it must
    /// cover is bounded by the number of live forwards. Sized here as a
    /// generous static bound (16 workers x 131,072) that covers the
    /// appliance ceiling without needing a runtime worker count in this
    /// index; above it the roster fails closed from the LIVE size (see
    /// `wire_saturated`), never from a latch.
    pub(in crate::afxdp) const MAX_WIRE_KEYS: usize = 16 * 131_072;
    pub(in crate::afxdp) fn wire_key_cap(&self) -> usize {
        #[cfg(test)]
        {
            let override_cap = WIRE_KEY_CAP_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed);
            if override_cap != 0 {
                return override_cap;
            }
        }
        Self::MAX_WIRE_KEYS
    }

    /// #16561: roster saturation as a function of the LIVE population —
    /// the roster holds a distinct wire key per live NAT'd forward, so
    /// it is saturated exactly while that population is at/above the
    /// roster ceiling. Removals drop the population and the roster
    /// recovers with no latch, no reseed and no helper restart (the
    /// #15104 rule that the old `wire_saturated` latch violated).
    pub(in crate::afxdp) fn wire_saturated(&self) -> bool {
        self.wire_owners.len() >= self.wire_key_cap()
    }

    /// Live distinct wire keys recorded in the roster (gauge/test).
    pub(in crate::afxdp) fn wire_key_len(&self) -> usize {
        self.wire_owners.len()
    }

    /// #15104: saturation is a function of the LIVE population. A live
    /// population at or above `MAX_KEYS` fails closed; once removals drop
    /// it below the bound the index recovers without a helper restart.
    pub(in crate::afxdp) fn saturated(&self) -> bool {
        self.aliases.len() >= Self::MAX_KEYS
    }

    pub(in crate::afxdp) fn len(&self) -> usize {
        self.aliases.len()
    }

    /// #16564: count of claims still waiting for alias capacity
    /// (test/diagnostic gauge).
    #[cfg(test)]
    pub(in crate::afxdp) fn unrecorded_len(&self) -> usize {
        self.unrecorded.len()
    }

    fn enqueue_unrecorded(&mut self, key: &SessionKey, owner: &SessionKey) {
        let claim = (key.clone(), owner.clone());
        if self.unrecorded_set.contains(&claim) {
            return;
        }
        if self.unrecorded.len() >= Self::MAX_UNRECORDED {
            return;
        }
        self.unrecorded_set.insert(claim.clone());
        self.unrecorded.push_back(claim);
    }

    fn dequeue_unrecorded(&mut self, key: &SessionKey, owner: &SessionKey) {
        let claim = (key.clone(), owner.clone());
        if self.unrecorded_set.remove(&claim) {
            self.unrecorded.retain(|queued| queued != &claim);
        }
    }

    /// #16564: insert alias records for claims that were refused while
    /// saturated, using only the alias capacity that is currently free.
    /// Drained from `forget_owner` (the one place capacity is freed) and
    /// from `observe` itself when it finds room, so no helper restart or
    /// background pass is needed. Each candidate is revalidated against
    /// the live `owners` multiset: a claim whose owner left, or whose
    /// alias now names a different live owner, is stale and discarded.
    /// When several live owners queue for one alias, the alias is
    /// inserted ambiguous (`None`) — resolution keeps failing closed
    /// for all of them, exactly as a never-saturated collision would.
    /// Queue entries whose alias has no free slot yet stay queued.
    fn backfill_unrecorded(&mut self) {
        if self.unrecorded.is_empty() || self.saturated() {
            return;
        }
        // Detach the queue so `remember` can run without borrow fights;
        // entries that still cannot be placed are re-queued in order.
        let pending = std::mem::take(&mut self.unrecorded);
        self.unrecorded_set.clear();
        for (key, owner) in pending {
            let live = matches!(
                self.owners.get(&key),
                Some(bucket) if bucket.contains_key(&owner)
            );
            if !live {
                continue;
            }
            if self.aliases.contains_key(&key) {
                // Already recorded (ambiguously or by a twin claim):
                // the queued claim adds no information.
                continue;
            }
            if self.saturated() {
                self.enqueue_unrecorded(&key, &owner);
                continue;
            }
            let contested = self.owners.get(&key).is_some_and(|bucket| bucket.len() > 1);
            if contested {
                self.aliases.insert(key, None);
            } else {
                self.aliases.insert(key, Some(owner));
            }
        }
    }

    fn remember(&mut self, key: SessionKey, owner: Option<SessionKey>) {
        if self.saturated() {
            // #16564: a `None` mark names no owner, so there is no claim
            // to backfill later; only owner claims are queued.
            if let Some(owner) = &owner {
                self.enqueue_unrecorded(&key, owner);
            }
            return;
        }
        if let Some(existing) = self.aliases.get(&key) {
            if existing != &owner {
                self.aliases.insert(key, None);
            }
            return;
        }
        // #16564: while queued claims still wait for capacity, a NEW
        // alias must not steal their slot — queue this claim behind
        // them instead. The one exception is a queued claim for this
        // very alias (a `track_owner`-only claim): recording it now is
        // exactly the backfill those claims wait for. Updates to an
        // already-recorded alias above are unaffected.
        if !self.unrecorded.is_empty() && !self.unrecorded.iter().any(|(queued, _)| queued == &key)
        {
            if let Some(owner) = owner {
                self.enqueue_unrecorded(&key, &owner);
            }
            return;
        }
        self.aliases.insert(key, owner);
    }

    pub(in crate::afxdp) fn mark(&mut self, key: SessionKey) {
        self.remember(key, None);
    }

    pub(in crate::afxdp) fn observe(&mut self, key: SessionKey, owner: SessionKey) {
        self.owners
            .entry(key.clone())
            .or_default()
            .entry(owner.clone())
            .or_insert(0);
        self.remember(key.clone(), Some(owner.clone()));
        if self.aliases.contains_key(&key) {
            self.dequeue_unrecorded(&key, &owner);
        }
    }

    /// #15104: record that `owner` claimed `key` without changing the
    /// unique/ambiguous verdict. Used for aliases (such as the canonical
    /// reverse alias) whose ambiguity is driven by displacement marks
    /// rather than by the observe that seeds the wire alias.
    pub(in crate::afxdp) fn track_owner(&mut self, key: SessionKey, owner: SessionKey) {
        self.owners
            .entry(key.clone())
            .or_default()
            .entry(owner.clone())
            .or_insert(0);
        // #16564: a tracked claim published while saturated must also be
        // recoverable, or the canonical alias of a saturated-era session
        // stays unrecorded just like its wire alias.
        if self.saturated() && !self.aliases.contains_key(&key) {
            self.enqueue_unrecorded(&key, &owner);
        }
    }

    /// #15104: drop `owner`'s claim on `key`. When no owner remains, the
    /// alias record is forgotten entirely, so the live population (and
    /// therefore saturation) shrinks. When exactly one owner remains and
    /// its only record is an ambiguity mark left by a displaced publish,
    /// the record is restored to that owner so the shared lookup can
    /// resolve again.
    pub(in crate::afxdp) fn forget_owner(&mut self, key: &SessionKey, owner: &SessionKey) {
        // #16564: this claim can no longer be backfilled, recorded or not.
        self.dequeue_unrecorded(key, owner);
        let mut bucket_empty = false;
        let mut sole_owner: Option<SessionKey> = None;
        if let Some(bucket) = self.owners.get_mut(key) {
            bucket.remove(owner);
            bucket_empty = bucket.is_empty();
            if bucket.len() == 1 {
                sole_owner = bucket.keys().next().cloned();
            }
        }
        if bucket_empty {
            self.owners.remove(key);
            self.aliases.remove(key);
        } else if let Some(sole) = sole_owner
            && matches!(self.aliases.get(key), Some(None))
        {
            self.aliases.insert(key.clone(), Some(sole));
        }
        // #16564: the removal above may have freed alias capacity; give
        // queued claims first use of it. A still-live sole owner whose
        // alias was never recorded is restored here too.
        if !bucket_empty
            && !self.aliases.contains_key(key)
            && let Some(bucket) = self.owners.get(key)
            && bucket.len() == 1
            && let Some(sole) = bucket.keys().next().cloned()
        {
            self.enqueue_unrecorded(key, &sole);
        }
        self.backfill_unrecorded();
    }

    pub(in crate::afxdp) fn contains(&self, key: &SessionKey) -> bool {
        self.saturated() || matches!(self.aliases.get(key), Some(None))
    }

    pub(in crate::afxdp) fn is_unique_for(&self, key: &SessionKey, owner: &SessionKey) -> bool {
        !self.saturated()
            && matches!(self.aliases.get(key), Some(Some(candidate)) if candidate == owner)
    }

    /// #14383: unconditionally record `owner` as the sole owner of `key`,
    /// overwriting any prior ambiguity mark. Used when a removal leaves a
    /// single surviving owner whose entry is re-published into the alias
    /// map. `observe`/`mark` cannot do this: `remember` keeps a `None`
    /// (ambiguous) record sticky forever.
    pub(in crate::afxdp) fn reset_to_owner(&mut self, key: SessionKey, owner: SessionKey) {
        // #16564: the record is (re)installed by this call, so any queued
        // claim for the same pair is satisfied.
        self.dequeue_unrecorded(&key, &owner);
        if self.saturated() && !self.aliases.contains_key(&key) {
            // #16564: do not drop survivor ownership on the floor (the
            // #14383 scan would have discarded it the same way): queue it
            // so the next freed slot restores the survivor.
            self.owners
                .insert(key.clone(), FastMap::from_iter([(owner.clone(), 0u32)]));
            self.enqueue_unrecorded(&key, &owner);
            return;
        }
        self.owners
            .insert(key.clone(), FastMap::from_iter([(owner.clone(), 0u32)]));
        match self.aliases.get(&key) {
            Some(existing) if existing.as_ref() == Some(&owner) => {}
            Some(_) => {
                self.aliases.insert(key, Some(owner));
            }
            None if self.aliases.len() == Self::MAX_KEYS => {
                // Saturated between the guard above and here cannot
                // happen (single lock hold, no re-entry); queue instead
                // of growing past the bound if it ever did.
                self.enqueue_unrecorded(&key, &owner);
            }
            None => {
                self.aliases.insert(key, Some(owner));
            }
        }
    }

    /// #14383: drop the record for `key` entirely. Used when a removal
    /// leaves no surviving owner for the alias.
    pub(in crate::afxdp) fn forget(&mut self, key: &SessionKey) {
        self.aliases.remove(key);
        self.owners.remove(key);
        // #16564: queued claims for a forgotten alias are dead.
        self.unrecorded_set.retain(|(queued, _)| queued != key);
        self.unrecorded.retain(|(queued, _)| queued != key);
    }

    pub(in crate::afxdp) fn unique_owner(&self, key: &SessionKey) -> Option<&SessionKey> {
        if self.saturated() {
            return None;
        }
        self.aliases.get(key).and_then(Option::as_ref)
    }

    pub(in crate::afxdp) fn clear(&mut self) {
        self.aliases.clear();
        self.wire_owners.clear();
        self.owners.clear();
        self.unrecorded.clear();
        self.unrecorded_set.clear();
    }

    // ---- #15106: per-wire-key live-owner multiset -------------------------
    //
    // Roster ops run under the SAME index mutex as `aliases`, so the
    // ambiguity record and the roster cannot drift apart at publish/remove.

    /// Record `owner` as claiming `wire_key`. Idempotent per owner: a
    /// same-session re-publish must not inflate the count. New wire keys
    /// above the ingest cap are not recorded (fail-closed saturation),
    /// matching the `remember` alias policy.
    pub(in crate::afxdp) fn observe_wire_owner(&mut self, wire_key: SessionKey, owner: SessionKey) {
        // #16561: do NOT consult the alias saturation here. The alias
        // index fails closed at 16,384 live keys, but the wire roster is
        // decoupled from that cap and must keep recording every owner
        // above it. The only refusal is a NEW wire key while the LIVE
        // roster population is at the roster ceiling: fail closed for
        // that key, recover automatically when removals drop the
        // population (`wire_saturated` is live).
        match self.wire_owners.get_mut(&wire_key) {
            Some(roster) => {
                if !roster.contains(&owner) {
                    roster.push(owner);
                }
            }
            None => {
                if self.wire_owners.len() >= self.wire_key_cap() {
                    return;
                }
                let mut roster = WireOwnerRoster::new();
                roster.push(owner);
                self.wire_owners.insert(wire_key, roster);
            }
        }
    }

    /// Remove `owner` from `wire_key`'s roster. Returns the remaining roster
    /// count, or 0 with `still_recorded` false when nothing was recorded
    /// (saturation or a wire key with no roster entry) so the caller keeps a
    /// fail-closed fallback instead of trusting an empty/missing roster.
    pub(in crate::afxdp) fn remove_wire_owner(
        &mut self,
        wire_key: &SessionKey,
        owner: &SessionKey,
    ) -> u32 {
        let Some(roster) = self.wire_owners.get_mut(wire_key) else {
            return 0;
        };
        if let Some(pos) = roster.iter().position(|candidate| candidate == owner) {
            roster.remove(pos);
        }
        let remaining = roster.len() as u32;
        if roster.is_empty() {
            self.wire_owners.remove(wire_key);
        }
        remaining
    }

    /// Whether a wire survivor answer from `wire_owners` can be trusted.
    /// #16561: a function of the LIVE populations only — false while the
    /// alias index is saturated or while the live roster population is
    /// at its own ceiling. Both clear on removal; neither latches.
    pub(in crate::afxdp) fn wire_owners_trusted(&self) -> bool {
        !self.wire_saturated() && !self.saturated()
    }

    /// #16561: trust predicate for the removal path in
    /// `remove_shared_session_if`. The roster is exact for a wire key
    /// when it recorded the removed owner and the live roster
    /// population is below its ceiling — regardless of the alias
    /// index's 16,384 saturation.
    pub(in crate::afxdp) fn wire_roster_trusted_for_removal(&self) -> bool {
        !self.wire_saturated()
    }

    /// The first (published-first) live owner recorded for `wire_key`, used
    /// only when the caller already knows the roster holds exactly one owner.
    pub(in crate::afxdp) fn wire_first_owner(&self, wire_key: &SessionKey) -> Option<SessionKey> {
        self.wire_owners
            .get(wire_key)
            .and_then(|roster| roster.first().cloned())
    }

    /// #15106: seed/reset `wire_key`'s roster from a survivors snapshot
    /// (legacy reseed when the roster lacks the removed owner) and return the
    /// remaining owner count. Mirrors the pre-#15106 scan's verdict: 0 = drop
    /// the alias and forget, 1 = restore that sole owner, 2+ = stay ambiguous.
    pub(in crate::afxdp) fn reset_wire_owners(
        &mut self,
        wire_key: SessionKey,
        owners: &[SessionKey],
    ) -> u32 {
        self.wire_owners.remove(&wire_key);
        if owners.is_empty() {
            return 0;
        }
        let count = owners.len() as u32;
        let mut roster = WireOwnerRoster::new();
        roster.extend(owners.iter().cloned());
        self.wire_owners.insert(wire_key, roster);
        count
    }

    /// #15106: live owner count recorded for `wire_key` (0 when absent).
    pub(in crate::afxdp) fn wire_owner_count(&self, wire_key: &SessionKey) -> u32 {
        self.wire_owners
            .get(wire_key)
            .map(|roster| roster.len() as u32)
            .unwrap_or(0)
    }

    /// #15106: total live wire-owner roster entries (test/diagnostic gauge).
    #[cfg(test)]
    pub(in crate::afxdp) fn wire_owner_entry_count(&self) -> usize {
        self.wire_owners.values().map(|roster| roster.len()).sum()
    }
}

enum SharedBareTupleScopes {
    One(SessionScope),
    Many(HashSet<SessionScope, HotPathSeededState>),
}

impl SharedBareTupleScopes {
    fn insert(&mut self, scope: SessionScope, state: &HotPathSeededState) {
        let replacement = match self {
            Self::One(existing) if *existing == scope => return,
            Self::One(existing) => {
                let mut scopes = HashSet::with_hasher(*state);
                scopes.insert(*existing);
                scopes.insert(scope);
                Some(Self::Many(scopes))
            }
            Self::Many(scopes) => {
                scopes.insert(scope);
                None
            }
        };
        if let Some(replacement) = replacement {
            *self = replacement;
        }
    }

    /// Remove a scope. Returns true when its tuple bucket becomes empty.
    fn remove(&mut self, scope: SessionScope) -> bool {
        let (empty, collapse_to) = match self {
            Self::One(existing) => return *existing == scope,
            Self::Many(scopes) => {
                if !scopes.remove(&scope) {
                    return false;
                }
                (
                    scopes.is_empty(),
                    (scopes.len() == 1).then(|| *scopes.iter().next().expect("one scope remains")),
                )
            }
        };
        if let Some(only) = collapse_to {
            *self = Self::One(only);
        }
        empty
    }

    fn has_other_scope(&self, scope: SessionScope) -> bool {
        match self {
            Self::One(existing) => *existing != scope,
            Self::Many(scopes) => {
                !scopes.is_empty() && (scopes.len() > 1 || !scopes.contains(&scope))
            }
        }
    }
}

pub(in crate::afxdp) struct SharedSessionBareTupleIndex {
    scopes: HashMap<BareSessionTuple, SharedBareTupleScopes, HotPathSeededState>,
    state: HotPathSeededState,
}

impl Default for SharedSessionBareTupleIndex {
    fn default() -> Self {
        Self::with_seed(crate::hot_hash_seed::hot_path_hash_seed())
    }
}

impl SharedSessionBareTupleIndex {
    fn with_seed(seed: u64) -> Self {
        let state = HotPathSeededState::new(seed);
        Self {
            scopes: HashMap::with_hasher(state),
            state,
        }
    }
}

impl SharedSessionBareTupleIndex {
    pub(in crate::afxdp) fn insert(&mut self, key: &SessionKey) {
        let bare_tuple = key.bare_tuple();
        let scope = key.scope();
        self.scopes
            .entry(bare_tuple)
            .and_modify(|scopes| scopes.insert(scope, &self.state))
            .or_insert(SharedBareTupleScopes::One(scope));
    }

    pub(in crate::afxdp) fn remove(&mut self, key: &SessionKey) {
        let bare_tuple = key.bare_tuple();
        let scope = key.scope();
        let remove_tuple = self
            .scopes
            .get_mut(&bare_tuple)
            .is_some_and(|scopes| scopes.remove(scope));
        if remove_tuple {
            self.scopes.remove(&bare_tuple);
        }
    }

    pub(in crate::afxdp) fn has_other_scope(&self, key: &SessionKey) -> bool {
        self.scopes
            .get(&key.bare_tuple())
            .is_some_and(|scopes| scopes.has_other_scope(key.scope()))
    }

    pub(in crate::afxdp) fn clear(&mut self) {
        self.scopes.clear();
    }
}

#[derive(Clone)]
pub(in crate::afxdp) struct SharedSessionOwnerRgIndexes {
    pub(in crate::afxdp) sessions: Arc<Mutex<OwnerRgSessionIndex>>,
    pub(in crate::afxdp) nat_sessions: Arc<Mutex<OwnerRgSessionIndex>>,
    pub(in crate::afxdp) forward_wire_sessions: Arc<Mutex<OwnerRgSessionIndex>>,
    pub(in crate::afxdp) reverse_prewarm_sessions: Arc<Mutex<OwnerRgSessionIndex>>,
    pub(in crate::afxdp) nat_ambiguities: Arc<Mutex<SharedNatAmbiguityIndex>>,
    // #14383: forward-wire counterpart of `nat_ambiguities` — records every
    // owner that ever claimed a forward-wire key so the shared wire lookup
    // can fail closed instead of resolving to the last-published session.
    pub(in crate::afxdp) wire_ambiguities: Arc<Mutex<SharedNatAmbiguityIndex>>,
    pub(in crate::afxdp) bare_tuple_sessions: Arc<Mutex<SharedSessionBareTupleIndex>>,
}

impl Default for SharedSessionOwnerRgIndexes {
    fn default() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(FastMap::default())),
            nat_sessions: Arc::new(Mutex::new(FastMap::default())),
            forward_wire_sessions: Arc::new(Mutex::new(FastMap::default())),
            reverse_prewarm_sessions: Arc::new(Mutex::new(FastMap::default())),
            nat_ambiguities: Arc::new(Mutex::new(SharedNatAmbiguityIndex::default())),
            wire_ambiguities: Arc::new(Mutex::new(SharedNatAmbiguityIndex::default())),
            bare_tuple_sessions: Arc::new(Mutex::new(SharedSessionBareTupleIndex::default())),
        }
    }
}

impl SharedSessionOwnerRgIndexes {
    /// #6653: RECOVERING locks, for the same reason as the session maps this
    /// mirrors. `if let Ok(..)` skipped a poisoned index, so a teardown could
    /// empty the maps and leave an index populated (or the reverse) — the
    /// indexes exist to mirror the maps, and a poisoned one that survives
    /// teardown is precisely the divergence they cannot represent.
    pub(in crate::afxdp) fn clear(
        &self,
        shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    ) {
        // Keep the primary map and bare-tuple index paired under the same
        // lock order used by publish, removal, and close validation.
        let mut sessions = crate::afxdp::shared_ops::lock_shared_recover(shared_sessions);
        let mut bare_tuple_sessions =
            crate::afxdp::shared_ops::lock_shared_recover(&self.bare_tuple_sessions);
        sessions.clear();
        bare_tuple_sessions.clear();
        drop(bare_tuple_sessions);
        drop(sessions);

        crate::afxdp::shared_ops::lock_shared_recover(&self.sessions).clear();
        crate::afxdp::shared_ops::lock_shared_recover(&self.nat_sessions).clear();
        crate::afxdp::shared_ops::lock_shared_recover(&self.forward_wire_sessions).clear();
        crate::afxdp::shared_ops::lock_shared_recover(&self.reverse_prewarm_sessions).clear();
        crate::afxdp::shared_ops::lock_shared_recover(&self.nat_ambiguities).clear();
        crate::afxdp::shared_ops::lock_shared_recover(&self.wire_ambiguities).clear();
    }
}
#[cfg(test)]
mod bare_tuple_keyed_hash_tests_12778 {
    use super::*;
    use std::hash::BuildHasher;
    use std::net::{IpAddr, Ipv6Addr};

    #[test]
    fn shared_bare_tuple_index_uses_keyed_hash_12778() {
        let placement = |seed| {
            let index = SharedSessionBareTupleIndex::with_seed(seed);
            (0..256u16)
                .map(|i| {
                    let key = SessionKey {
                        addr_family: libc::AF_INET6 as u8,
                        protocol: crate::afxdp::PROTO_UDP,
                        src_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, i, 0, 0, 0, 1)),
                        dst_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 2)),
                        src_port: 40_000,
                        dst_port: 443,
                        discriminator: Default::default(),
                        routing_domain: 0,
                    };
                    index.scopes.hasher().hash_one(&key.bare_tuple()) & 0x3f
                })
                .collect::<Vec<_>>()
        };
        for seed in [1, 42, 0x0123_4567_89ab_cdef, u64::MAX] {
            let buckets: std::collections::HashSet<_> = placement(seed).into_iter().collect();
            assert!(
                buckets.len() > 32,
                "seed {seed:#x} spread to only {} buckets",
                buckets.len()
            );
        }
        assert_ne!(
            placement(42),
            placement(43),
            "seed must change bare tuple layout"
        );
    }

    #[test]
    fn shared_bare_tuple_index_preserves_cross_scope_lookup_12778() {
        let key = SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: crate::afxdp::PROTO_UDP,
            src_ip: "192.0.2.1".parse().unwrap(),
            dst_ip: "198.51.100.2".parse().unwrap(),
            src_port: 40_000,
            dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 1,
        };
        let other_scope = SessionKey {
            routing_domain: 2,
            ..key
        };
        let mut index = SharedSessionBareTupleIndex::default();
        index.insert(&key);
        assert!(!index.has_other_scope(&key));
        index.insert(&other_scope);
        assert!(index.has_other_scope(&key));
        index.remove(&other_scope);
        assert!(!index.has_other_scope(&key));
    }
}
