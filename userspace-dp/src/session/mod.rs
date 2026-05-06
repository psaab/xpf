use crate::afxdp::{ForwardingDisposition, ForwardingResolution};
use crate::nat::NatDecision;
use crate::nat64::Nat64ReverseInfo;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::VecDeque;
use std::net::IpAddr;


// #1047 P2: SessionKey and the key-transform helpers (forward_wire_key,
// translated_session_key, reverse_canonical_key, reverse_wire_key,
// reply_matches_forward_session) live in session/key.rs. Re-exporting
// at pub(crate) keeps the existing crate::session::* surface intact.
mod key;
pub(crate) use key::*;
mod entry;
pub(crate) use entry::*;
mod wheel;
use wheel::{
    bucket_for_tick, target_tick_for, FAR_FUTURE_OFFSET, SessionWheel, WheelEntry, WHEEL_BUCKETS,
    WHEEL_TICK_NS,
};

const SESSION_GC_INTERVAL_NS: u64 = 1_000_000_000;
const DEFAULT_MAX_SESSIONS: usize = 131072;
const DEFAULT_TCP_SESSION_TIMEOUT_NS: u64 = 300_000_000_000;
const TCP_CLOSING_TIMEOUT_NS: u64 = 30_000_000_000;
const DEFAULT_UDP_SESSION_TIMEOUT_NS: u64 = 60_000_000_000;
const DEFAULT_ICMP_SESSION_TIMEOUT_NS: u64 = 60_000_000_000;
const OTHER_SESSION_TIMEOUT_NS: u64 = 30_000_000_000;


/// Per-call statistics for `expire_stale_entries` pop work, used by
/// the timer-wheel unit tests to assert K-bounds and entry
/// classification under specific synthetic workloads. Fields are
/// accumulated over all buckets popped in a single call.
#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct WheelPopStats {
    /// Total `WheelEntry`s scanned (popped from a bucket and
    /// classified) during the call.
    pub(crate) scanned: usize,
    /// Entries dropped because the canonical key is no longer in
    /// `sessions` (already removed by another path).
    pub(crate) dropped_gone: usize,
    /// Entries dropped because `wheel_tick != scheduled_tick` (a
    /// fresher entry has superseded this one).
    pub(crate) dropped_stale: usize,
    /// Entries that actually expired and were removed.
    pub(crate) expired: usize,
    /// Entries that were re-bucketed (long-timeout / not yet
    /// expired).
    pub(crate) re_bucketed: usize,
}

/// Configurable session timeout values (in nanoseconds).
#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionTimeouts {
    pub(crate) tcp_established_ns: u64,
    pub(crate) udp_ns: u64,
    pub(crate) icmp_ns: u64,
}

impl Default for SessionTimeouts {
    fn default() -> Self {
        Self {
            tcp_established_ns: DEFAULT_TCP_SESSION_TIMEOUT_NS,
            udp_ns: DEFAULT_UDP_SESSION_TIMEOUT_NS,
            icmp_ns: DEFAULT_ICMP_SESSION_TIMEOUT_NS,
        }
    }
}

impl SessionTimeouts {
    /// Build from snapshot timeout values (in seconds). A value of 0 means use
    /// the default.
    pub(crate) fn from_seconds(tcp_secs: u64, udp_secs: u64, icmp_secs: u64) -> Self {
        Self {
            tcp_established_ns: if tcp_secs > 0 {
                tcp_secs * 1_000_000_000
            } else {
                DEFAULT_TCP_SESSION_TIMEOUT_NS
            },
            udp_ns: if udp_secs > 0 {
                udp_secs * 1_000_000_000
            } else {
                DEFAULT_UDP_SESSION_TIMEOUT_NS
            },
            icmp_ns: if icmp_secs > 0 {
                icmp_secs * 1_000_000_000
            } else {
                DEFAULT_ICMP_SESSION_TIMEOUT_NS
            },
        }
    }
}
const MAX_SESSION_DELTAS: usize = 4096;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const PROTO_ICMPV6: u8 = 58;
const TCP_FIN: u8 = 0x01;
const TCP_RST: u8 = 0x04;

#[allow(unused_macros)]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug-log")]
        eprintln!($($arg)*);
    };
}


/// #789 fairness: sentinel for `installed_on_binding_slot` indicating
/// the install path didn't yet plumb the owning binding's slot. The
/// flow_steering controller treats `BINDING_SLOT_UNKNOWN` entries as
/// "not steerable for now" — they don't count toward any binding's
/// `active_ingress_flows_count` and aren't included in
/// `active_ingress_flows_sample`. Phase 1.5 plumbs the actual slot
/// through the install API surface; until then the sentinel keeps
/// the mechanism opt-in-by-instrumentation.
pub(crate) const BINDING_SLOT_UNKNOWN: u32 = u32::MAX;

#[derive(Clone, Debug)]
struct SessionEntry {
    decision: SessionDecision,
    metadata: SessionMetadata,
    origin: SessionOrigin,
    install_epoch: u64,
    last_seen_ns: u64,
    expires_after_ns: u64,
    closing: bool,
    /// #965: absolute wheel tick at which this session is scheduled to
    /// be checked for expiration. Updated on every push to the wheel.
    /// A WheelEntry whose `scheduled_tick != entry.wheel_tick` is a
    /// stale duplicate (lazy-delete discriminator).
    wheel_tick: u64,
    /// #789 Phase 1: monotonic nanoseconds at true session creation.
    /// Set ONCE at insert paths; PRESERVED across refresh / update /
    /// HA-owner-transition paths (which rewrite `install_epoch` as a
    /// counter). Lookup paths bump `last_seen_ns` but MUST NOT touch
    /// this field. Used by the flow-steering controller to compute
    /// `install_age_secs` for the stable-flow gate.
    installed_at_ns: u64,
    /// #789 Phase 1: slot of the binding whose worker installed this
    /// session. `BINDING_SLOT_UNKNOWN` means the install API didn't
    /// plumb the slot (Phase 1 sentinel default; Phase 1.5 plumbs the
    /// actual slot). Preserved across refresh paths same as
    /// `installed_at_ns`.
    installed_on_binding_slot: u32,
}

/// #964 Step 1: slab-resident record. Holds the canonical
/// SessionKey alongside the SessionEntry so any handle resolves to
/// both. Required because find_forward_nat_match() etc. must return
/// the canonical key, and lookup_with_origin's wheel push_to_wheel
/// needs the canonical key after dropping the entry borrow.
#[derive(Clone, Debug)]
struct SessionRecord {
    key: SessionKey,
    entry: SessionEntry,
}

pub(crate) struct SessionTable {
    /// #964 Step 1: slab-allocated session storage. Indexed by u32
    /// handle. Replaces the prior `sessions: FxHashMap<Key, Entry>`.
    entries: slab::Slab<SessionRecord>,
    /// #964 Step 1: forward-key → handle. Replaces the
    /// `sessions` HashMap's key-to-entry mapping.
    key_to_handle: FxHashMap<SessionKey, u32>,
    /// #964 Step 1: secondary indices map to u32 handles, not full keys.
    nat_reverse_index: FxHashMap<SessionKey, u32>,
    forward_wire_index: FxHashMap<SessionKey, u32>,
    reverse_translated_index: FxHashMap<SessionKey, u32>,
    /// #964 Step 1: owner-RG sets keyed by handle (was Key).
    owner_rg_sessions: FxHashMap<i32, FxHashSet<u32>>,
    deltas: VecDeque<SessionDelta>,
    last_gc_ns: u64,
    max_sessions: usize,
    timeouts: SessionTimeouts,
    epoch_counter: u64,
    expired: u64,
    create_drops: u64,
    delta_drops: u64,
    delta_drained: u64,
    /// #965: bucketed timer wheel that mirrors `entries`. Pop one
    /// bucket per tick (1 s) instead of scanning the whole HashMap.
    /// Wheel entries hold `(SessionKey, scheduled_tick)` — NOT the
    /// slab handle, because wheel lazy-delete needs a stable
    /// identifier (slab handle reuse after remove+insert would point
    /// stale wheel entries at the wrong session). See
    /// docs/pr/964-session-multi-index/plan.md §"Wheel STAYS key-based".
    wheel: SessionWheel,
    /// #965: stats from the most-recent `expire_stale_entries` call.
    /// Reset at the start of each call. Used by unit tests to assert
    /// K-bounds and classification (scanned / dropped_stale /
    /// dropped_gone / expired / re_bucketed). Accumulator overhead
    /// is 4-5 increments per popped entry — sub-µs at typical loads.
    last_pop_stats: WheelPopStats,
}

/// #789 Phase 1: per-flow snapshot returned by
/// [`SessionTable::ingress_active_flows_for_binding`]. Used by the
/// flow-steering controller to pick stable active flows for re-steer.
#[derive(Clone, Debug)]
pub(crate) struct ActiveFlowSample {
    pub(crate) key: SessionKey,
    pub(crate) installed_at_ns: u64,
    pub(crate) last_seen_ns: u64,
}

/// #789 Phase 1: per-binding inventory of recent ingress-active flows.
/// `count` is the total number of sessions where
/// `installed_on_binding_slot == requested_slot` AND
/// `now_ns - last_seen_ns < recency_window_ns`. `sample` is up to
/// MAX_ACTIVE_FLOW_SAMPLE entries (16) — the controller picks 1-2
/// from this sample with the stable-flow gate.
#[derive(Clone, Debug, Default)]
pub(crate) struct ActiveFlowInventory {
    pub(crate) count: u32,
    pub(crate) sample: Vec<ActiveFlowSample>,
}

pub(crate) const MAX_ACTIVE_FLOW_SAMPLE: usize = 16;

impl SessionTable {
    pub fn new() -> Self {
        Self {
            // Start with an empty slab and let it grow on demand.
            // `Slab::with_capacity(DEFAULT_MAX_SESSIONS)` would eagerly
            // allocate a 131072-slot backing Vec per worker (Copilot
            // review finding) — the prior FxHashMap grew on demand,
            // so match that to keep baseline RSS unchanged.
            entries: slab::Slab::new(),
            key_to_handle: FxHashMap::default(),
            nat_reverse_index: FxHashMap::default(),
            forward_wire_index: FxHashMap::default(),
            reverse_translated_index: FxHashMap::default(),
            owner_rg_sessions: FxHashMap::default(),
            deltas: VecDeque::with_capacity(MAX_SESSION_DELTAS.min(256)),
            last_gc_ns: 0,
            max_sessions: DEFAULT_MAX_SESSIONS,
            timeouts: SessionTimeouts::default(),
            epoch_counter: 0,
            expired: 0,
            create_drops: 0,
            delta_drops: 0,
            delta_drained: 0,
            wheel: SessionWheel::new(),
            last_pop_stats: WheelPopStats::default(),
        }
    }

    /// #965: stats from the most-recent `expire_stale_entries` call.
    /// Used by tests to validate K-bounds and entry classification.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn last_pop_stats(&self) -> WheelPopStats {
        self.last_pop_stats
    }

    /// #965: lazily initialize the wheel cursor to the first observed
    /// `now_ns`. SessionTable::new() does not have a `now_ns`, so we
    /// must initialize on the first call to any method that takes one.
    /// Without this, `now_tick = now_ns / TICK_NS` can be billions
    /// (monotonic time) and the pop loop would walk billions of empty
    /// buckets on the first GC.
    #[inline]
    fn wheel_observe(&mut self, now_ns: u64) {
        if !self.wheel.initialized {
            self.wheel.cursor_tick = now_ns / WHEEL_TICK_NS;
            self.wheel.initialized = true;
        }
    }

    /// #965: schedule (or re-schedule) `key` for an expiration check
    /// at the tick implied by its `last_seen_ns + expires_after_ns`.
    /// Throttled: only pushes when the canonical wheel tick changes,
    /// so per-second touches within the same tick produce zero new
    /// wheel entries.
    ///
    /// MUST be called only AFTER `last_seen_ns` / `expires_after_ns`
    /// have been written and the &mut borrow on `self.sessions` has
    /// dropped — otherwise the borrow checker will reject the
    /// `self.wheel.buckets[bucket].push_back(...)` line because it
    /// aliases `self` through both `self.sessions` and `self.wheel`.
    #[inline]
    fn push_to_wheel(&mut self, key: &SessionKey, now_ns: u64) {
        self.wheel_observe(now_ns);
        let new_tick = match self.entry_by_key_mut(key) {
            Some(entry) => {
                let nt = target_tick_for(
                    now_ns,
                    entry.last_seen_ns.saturating_add(entry.expires_after_ns),
                );
                if nt != entry.wheel_tick {
                    entry.wheel_tick = nt;
                    Some(nt)
                } else {
                    None
                }
            }
            None => return,
        };
        if let Some(tick) = new_tick {
            let bucket = bucket_for_tick(tick);
            self.wheel.buckets[bucket].push_back(WheelEntry {
                key: key.clone(),
                scheduled_tick: tick,
            });
        }
    }

    fn next_epoch(&mut self) -> u64 {
        self.epoch_counter += 1;
        self.epoch_counter
    }

    /// Update the configurable session timeouts.
    pub fn set_timeouts(&mut self, timeouts: SessionTimeouts) {
        self.timeouts = timeouts;
    }

    pub fn len(&self) -> usize {
        // Use key_to_handle (the authoritative primary index) so the
        // count reflects "installed sessions" even if the slab ever
        // held an orphan record from a partial cleanup path.
        self.key_to_handle.len()
    }

    /// #789 Phase 1: snapshot of ingress-active flows belonging to a
    /// specific binding's slot. Filters by:
    ///   - `entry.installed_on_binding_slot == slot`
    ///   - `now_ns - entry.last_seen_ns < recency_window_ns`
    /// Used by the flow-steering controller (see
    /// `docs/pr/789-fairness-via-ntuple/plan.md` §4.3) to pick
    /// stable active flows for re-steer.
    ///
    /// Sessions stamped with `BINDING_SLOT_UNKNOWN` are skipped — see
    /// the sentinel doc on `BINDING_SLOT_UNKNOWN`. Callers requesting
    /// `slot == BINDING_SLOT_UNKNOWN` get an empty inventory by
    /// construction.
    ///
    /// O(N) over `entries`. Called at 1 Hz cadence per binding by the
    /// worker — caller is expected to gate on the time interval (see
    /// `ACTIVE_FLOWS_PUBLISH_INTERVAL_NS` near `worker_loop`).
    pub(crate) fn ingress_active_flows_for_binding(
        &self,
        slot: u32,
        now_ns: u64,
        recency_window_ns: u64,
    ) -> ActiveFlowInventory {
        let mut count: u32 = 0;
        let mut sample: Vec<ActiveFlowSample> =
            Vec::with_capacity(MAX_ACTIVE_FLOW_SAMPLE);
        if slot == BINDING_SLOT_UNKNOWN {
            return ActiveFlowInventory { count, sample };
        }
        for record in self.entries.iter().map(|(_handle, rec)| rec) {
            let entry = &record.entry;
            if entry.installed_on_binding_slot != slot {
                continue;
            }
            if now_ns.saturating_sub(entry.last_seen_ns) >= recency_window_ns {
                continue;
            }
            count = count.saturating_add(1);
            if sample.len() < MAX_ACTIVE_FLOW_SAMPLE {
                sample.push(ActiveFlowSample {
                    key: record.key.clone(),
                    installed_at_ns: entry.installed_at_ns,
                    last_seen_ns: entry.last_seen_ns,
                });
            }
        }
        ActiveFlowInventory { count, sample }
    }

    // ── #964 Step 1 internal helpers ─────────────────────────────
    //
    // Centralize key→handle and handle→record resolution so the rest
    // of the impl uses these short forms instead of repeating
    // `self.key_to_handle.get(key).and_then(|h| self.entries.get(*h as usize))`
    // throughout 30+ call sites.

    /// Resolve the slab handle for a forward-key direct lookup.
    /// Returns None if the key isn't installed.
    #[inline]
    fn handle_for_key(&self, key: &SessionKey) -> Option<u32> {
        self.key_to_handle.get(key).copied()
    }

    /// Resolve to a slab record from a forward-key. Returns None if
    /// the key is unknown, the handle is stale, OR the resolved
    /// record's canonical key doesn't match the lookup key (defense
    /// vs reused-slot hazard — Copilot review).
    #[inline]
    fn record_by_key(&self, key: &SessionKey) -> Option<&SessionRecord> {
        let handle = self.handle_for_key(key)?;
        let record = self.entries.get(handle as usize)?;
        if record.key != *key {
            return None;
        }
        Some(record)
    }

    /// Mut version of `record_by_key`. Same key-equality validation.
    #[inline]
    fn record_by_key_mut(&mut self, key: &SessionKey) -> Option<&mut SessionRecord> {
        let handle = self.handle_for_key(key)?;
        let record = self.entries.get_mut(handle as usize)?;
        if record.key != *key {
            return None;
        }
        Some(record)
    }

    /// Convenience: borrow the entry only (skipping the canonical
    /// key field). Used by call sites that don't need the key.
    #[inline]
    fn entry_by_key(&self, key: &SessionKey) -> Option<&SessionEntry> {
        self.record_by_key(key).map(|r| &r.entry)
    }

    #[inline]
    fn entry_by_key_mut(&mut self, key: &SessionKey) -> Option<&mut SessionEntry> {
        self.record_by_key_mut(key).map(|r| &mut r.entry)
    }

    #[inline]
    fn contains_key(&self, key: &SessionKey) -> bool {
        self.key_to_handle.contains_key(key)
    }

    /// Update the last-seen timestamp for a session (prevents GC expiry).
    /// Used by the flow cache to amortize session keepalive.
    #[inline]
    pub fn touch(&mut self, key: &SessionKey, now_ns: u64) {
        if self.entry_by_key_mut(key).is_some_and(|e| {
            e.last_seen_ns = now_ns;
            true
        }) {
            self.push_to_wheel(key, now_ns);
        }
    }

    /// #965: GC pass over the timer wheel.
    ///
    /// Replaces the prior O(N) scan over `self.sessions` with a wheel
    /// pop. For each tick that has elapsed since the last call (up to
    /// `now_ns / WHEEL_TICK_NS`), drain the bucket at the current
    /// cursor and process its entries via the lazy-delete discriminator:
    ///
    ///   1. Entry gone (HashMap miss) → drop.
    ///   2. Stale duplicate (`wheel_tick != scheduled_tick`) → drop.
    ///   3. Expired (`now > last_seen + expires_after`) → remove,
    ///      emit delta + ExpiredSession.
    ///   4. Still alive → re-bucket at the new absolute target tick.
    ///
    /// See docs/pr/965-session-gc-timer-wheel/plan.md for the full
    /// algorithm and complexity analysis.
    pub fn expire_stale_entries(&mut self, now_ns: u64) -> Vec<ExpiredSession> {
        // Reset per-call stats BEFORE the gc-interval gate so that a
        // gated no-op call returns zeroed stats rather than leftovers
        // from a prior call (Codex impl-review round-2 non-blocking note).
        self.last_pop_stats = WheelPopStats::default();
        if self.last_gc_ns != 0 && now_ns.saturating_sub(self.last_gc_ns) < SESSION_GC_INTERVAL_NS {
            return Vec::new();
        }
        self.last_gc_ns = now_ns;
        self.wheel_observe(now_ns);
        let now_tick = now_ns / WHEEL_TICK_NS;
        let mut expired_entries: Vec<ExpiredSession> = Vec::new();
        while self.wheel.cursor_tick < now_tick {
            let bucket_idx = bucket_for_tick(self.wheel.cursor_tick);
            // Drain the bucket allocation-free: snapshot the length
            // before iterating, then `pop_front` exactly that many
            // times. Re-pushes targeting THIS bucket land at the back
            // of the VecDeque and are not popped during this BUCKET
            // drain (re-pushes into LATER buckets the outer loop
            // visits will be popped within the same call — by design).
            let due_count = self.wheel.buckets[bucket_idx].len();
            for _ in 0..due_count {
                let WheelEntry { key, scheduled_tick } = self.wheel.buckets[bucket_idx]
                    .pop_front()
                    .expect("len snapshot bounds the iteration");
                self.last_pop_stats.scanned += 1;
                // Case 1: entry already removed elsewhere — drop hint.
                let Some(entry) = self.entry_by_key(&key) else {
                    self.last_pop_stats.dropped_gone += 1;
                    continue;
                };
                // Case 2: stale duplicate — entry's canonical wheel_tick
                // has advanced past this scheduled_tick, so the new tick
                // already has its own wheel entry. Drop.
                if entry.wheel_tick != scheduled_tick {
                    self.last_pop_stats.dropped_stale += 1;
                    continue;
                }
                // Case 3 vs 4: canonical entry. Match today's strict `>`
                // expiration semantics.
                if now_ns.saturating_sub(entry.last_seen_ns) > entry.expires_after_ns {
                    if let Some(removed) = self.remove_entry(&key) {
                        self.last_pop_stats.expired += 1;
                        let decision = removed.decision;
                        let metadata = removed.metadata;
                        if key.protocol == PROTO_TCP {
                            debug_log!(
                                "SESS_EXPIRE: proto=TCP {}:{} -> {}:{} closing={} age_ns={} timeout_ns={} rev={} origin={} nat=({:?},{:?})",
                                key.src_ip,
                                key.src_port,
                                key.dst_ip,
                                key.dst_port,
                                removed.closing,
                                now_ns.saturating_sub(removed.last_seen_ns),
                                removed.expires_after_ns,
                                metadata.is_reverse,
                                removed.origin.as_str(),
                                decision.nat.rewrite_src,
                                decision.nat.rewrite_dst,
                            );
                        }
                        if !metadata.is_reverse
                            && !removed.origin.is_peer_synced()
                            && !removed.origin.is_transient_local_seed()
                        {
                            self.push_delta(SessionDelta {
                                kind: SessionDeltaKind::Close,
                                key: key.clone(),
                                decision,
                                metadata: metadata.clone(),
                                origin: removed.origin,
                                fabric_redirect_sync: false,
                            });
                        }
                        expired_entries.push(ExpiredSession {
                            key,
                            decision,
                            metadata,
                            origin: removed.origin,
                        });
                    }
                } else {
                    // Case 4: still alive — long-timeout (>= 256s) case
                    // or a session re-scheduled to exactly this tick.
                    // Re-bucket at the new absolute target tick. The
                    // entry was just read via `self.sessions.get(&key)`
                    // immediately above with no intervening mutation,
                    // so `get_mut(&key)` is a hard invariant — use
                    // `expect` instead of `if let Some` so an invariant
                    // violation surfaces loudly instead of silently
                    // pushing a stale-tick wheel entry (Copilot review).
                    let new_target_tick = target_tick_for(
                        now_ns,
                        entry.last_seen_ns.saturating_add(entry.expires_after_ns),
                    );
                    let new_bucket = bucket_for_tick(new_target_tick);
                    let entry_mut = self
                        .entry_by_key_mut(&key)
                        .expect("entry was just read via entry_by_key; no concurrent mutation");
                    entry_mut.wheel_tick = new_target_tick;
                    self.wheel.buckets[new_bucket].push_back(WheelEntry {
                        key,
                        scheduled_tick: new_target_tick,
                    });
                    self.last_pop_stats.re_bucketed += 1;
                }
            }
            self.wheel.cursor_tick = self.wheel.cursor_tick.saturating_add(1);
        }
        let expired = expired_entries.len() as u64;
        self.expired = self.expired.saturating_add(expired);
        expired_entries
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn expire_stale(&mut self, now_ns: u64) -> u64 {
        self.expire_stale_entries(now_ns).len() as u64
    }

    pub fn lookup(
        &mut self,
        key: &SessionKey,
        now_ns: u64,
        tcp_flags: u8,
    ) -> Option<SessionLookup> {
        self.lookup_with_origin(key, now_ns, tcp_flags)
            .map(|(lookup, _origin)| lookup)
    }

    pub fn lookup_with_origin(
        &mut self,
        key: &SessionKey,
        now_ns: u64,
        tcp_flags: u8,
    ) -> Option<(SessionLookup, SessionOrigin)> {
        // #964 Step 1: resolve handle from key. Direct-primary path
        // looks up via key_to_handle; alias path (NAT-translated
        // reverse key) goes via reverse_translated_index.
        let (handle, via_alias) = match self.key_to_handle.get(key) {
            Some(h) => (*h, false),
            None => match self.reverse_translated_index.get(key) {
                Some(h) => (*h, true),
                None => return None,
            },
        };
        // Pre-compute the timeout before borrowing &mut self.entries
        // so the inner block doesn't need to access self.timeouts.
        let timeouts = self.timeouts;
        // Scope the &mut self.entries borrow so it ends BEFORE we
        // touch self.wheel via push_to_wheel. Without this scoping
        // the &mut record would conflict with the second &mut self
        // via self.wheel.
        let (result, actual_key) = {
            let record = self.entries.get_mut(handle as usize)?;
            // #964 Step 1: path-specific validation defends against
            // a stale secondary index pointing at a slab slot that
            // was reused by a different session (release-mode guard,
            // not just debug). Direct-primary checks record.key ==
            // *key; alias path verifies the NAT-translation roundtrip.
            if !via_alias {
                if record.key != *key {
                    return None;
                }
            } else {
                let must_be_reverse = record.entry.metadata.is_reverse;
                let translated = translated_session_key(&record.key, record.entry.decision.nat);
                if !must_be_reverse || translated != *key {
                    return None;
                }
            }
            let entry = &mut record.entry;
            if matches!(key.protocol, PROTO_TCP) && (tcp_flags & (TCP_FIN | TCP_RST)) != 0 {
                if !entry.closing {
                    debug_log!(
                        "SESS_CLOSING: {} proto=TCP {}:{} -> {}:{} rev={} tcp_flags=0x{:02x}",
                        if (tcp_flags & TCP_RST) != 0 {
                            "RST"
                        } else {
                            "FIN"
                        },
                        key.src_ip,
                        key.src_port,
                        key.dst_ip,
                        key.dst_port,
                        entry.metadata.is_reverse,
                        tcp_flags,
                    );
                }
                entry.closing = true;
            }
            entry.last_seen_ns = now_ns;
            entry.expires_after_ns = if matches!(key.protocol, PROTO_TCP) && entry.closing {
                TCP_CLOSING_TIMEOUT_NS
            } else {
                session_timeout_ns(key.protocol, tcp_flags, &timeouts)
            };
            (
                (
                    SessionLookup {
                        decision: entry.decision,
                        metadata: entry.metadata.clone(),
                    },
                    entry.origin,
                ),
                record.key.clone(),
            )
        }; // <-- &mut self.entries borrow ends here
        // Push the canonical key (NOT the alias lookup `key`) into
        // the wheel. push_to_wheel re-reads the record to compute
        // the throttled target_tick — that matches the model in the
        // plan (~100 ns per FxHashMap lookup on the slow path).
        self.push_to_wheel(&actual_key, now_ns);
        Some(result)
    }

    pub fn find_forward_nat_match(&self, reply_key: &SessionKey) -> Option<ForwardSessionMatch> {
        let handle = *self.nat_reverse_index.get(reply_key)?;
        let record = self.entries.get(handle as usize)?;
        let entry = &record.entry;
        if entry.metadata.is_reverse
            || !reply_matches_forward_session(&record.key, entry.decision.nat, reply_key)
        {
            return None;
        }
        Some(ForwardSessionMatch {
            key: record.key.clone(),
            decision: entry.decision,
            metadata: entry.metadata.clone(),
        })
    }

    pub fn find_forward_wire_match(&self, wire_key: &SessionKey) -> Option<ForwardSessionMatch> {
        self.find_forward_wire_match_with_origin(wire_key)
            .map(|(matched, _origin)| matched)
    }

    pub fn find_forward_wire_match_with_origin(
        &self,
        wire_key: &SessionKey,
    ) -> Option<(ForwardSessionMatch, SessionOrigin)> {
        let handle = *self.forward_wire_index.get(wire_key)?;
        let record = self.entries.get(handle as usize)?;
        let entry = &record.entry;
        if entry.metadata.is_reverse
            || forward_wire_key(&record.key, entry.decision.nat) != *wire_key
        {
            return None;
        }
        Some((
            ForwardSessionMatch {
                key: record.key.clone(),
                decision: entry.decision,
                metadata: entry.metadata.clone(),
            },
            entry.origin,
        ))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn install_with_protocol(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
    ) -> bool {
        self.install_with_protocol_with_origin(
            key,
            decision,
            metadata,
            SessionOrigin::ForwardFlow,
            now_ns,
            protocol,
            tcp_flags,
        )
    }

    pub fn install_with_protocol_with_origin(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        origin: SessionOrigin,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
    ) -> bool {
        if self.len() >= self.max_sessions {
            self.create_drops = self.create_drops.saturating_add(1);
            return false;
        }
        // remove_entry's three debug_assert!s catch invariant
        // violations in tests:
        //   - stale-handle guard (entries.get returned None for a
        //     handle in key_to_handle)
        //   - PRIMARY-KEY GUARD (record.key != lookup key)
        //   - no_index_points_at (a secondary index still points
        //     at the freed handle after cleanup)
        // The first two guards restore the prior key_to_handle
        // mapping internally before returning None. In release we
        // proceed to insert the new record — the guard already
        // restored the prior mapping; the subsequent
        // self.key_to_handle.insert(...) overwrites it cleanly.
        let _previous = self.remove_entry(&key);
        let epoch = self.next_epoch();
        let record = SessionRecord {
            key: key.clone(),
            entry: SessionEntry {
                decision,
                metadata: metadata.clone(),
                origin,
                install_epoch: epoch,
                last_seen_ns: now_ns,
                expires_after_ns: session_timeout_ns(protocol, tcp_flags, &self.timeouts),
                closing: matches!(protocol, PROTO_TCP) && (tcp_flags & (TCP_FIN | TCP_RST)) != 0,
                wheel_tick: 0,
                // #789 Phase 1: stamped at true creation; refresh
                // paths preserve via `restore_entry`.
                installed_at_ns: now_ns,
                installed_on_binding_slot: BINDING_SLOT_UNKNOWN,
            },
        };
        let raw = self.entries.insert(record);
        let handle: u32 = raw.try_into().expect("slab handle exceeds u32");
        self.key_to_handle.insert(key.clone(), handle);
        self.index_forward_nat_key(&key, handle, decision, &metadata);
        // #965: schedule the new entry for expiration check.
        self.push_to_wheel(&key, now_ns);
        if !metadata.is_reverse && !origin.is_peer_synced() && !origin.is_transient_local_seed() {
            self.push_delta(SessionDelta {
                kind: SessionDeltaKind::Open,
                key,
                decision,
                metadata,
                origin,
                fabric_redirect_sync: false,
            });
        }
        true
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn upsert_synced(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
        allow_replace_local: bool,
    ) -> bool {
        self.upsert_synced_with_origin(
            key,
            decision,
            metadata,
            SessionOrigin::SyncImport,
            now_ns,
            protocol,
            tcp_flags,
            allow_replace_local,
        )
    }

    pub fn upsert_synced_with_origin(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        origin: SessionOrigin,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
        allow_replace_local: bool,
    ) -> bool {
        // Reject peer data that would clobber a locally-owned session
        // unless explicitly allowed (e.g. during HA activation).
        if matches!(self.entry_by_key(&key), Some(existing) if !existing.origin.is_peer_synced())
            && !allow_replace_local
        {
            return false;
        }
        // Same guard semantics as install_with_protocol_with_origin:
        // remove_entry has 3 debug_assert!s (stale-handle,
        // primary-key, no_index_points_at) that catch invariant
        // violations in tests. The first two restore the prior
        // key_to_handle mapping internally before returning None.
        let _previous = self.remove_entry(&key);
        let epoch = self.next_epoch();
        let record = SessionRecord {
            key: key.clone(),
            entry: SessionEntry {
                decision,
                metadata: metadata.clone(),
                origin,
                install_epoch: epoch,
                last_seen_ns: now_ns,
                expires_after_ns: session_timeout_ns(protocol, tcp_flags, &self.timeouts),
                closing: matches!(protocol, PROTO_TCP) && (tcp_flags & (TCP_FIN | TCP_RST)) != 0,
                wheel_tick: 0,
                // #789 Phase 1: stamped at true creation.
                installed_at_ns: now_ns,
                installed_on_binding_slot: BINDING_SLOT_UNKNOWN,
            },
        };
        let raw = self.entries.insert(record);
        let handle: u32 = raw.try_into().expect("slab handle exceeds u32");
        let index_key = key.clone();
        self.key_to_handle.insert(key, handle);
        self.index_forward_nat_key(&index_key, handle, decision, &metadata);
        // #965: schedule the synced entry for expiration check.
        self.push_to_wheel(&index_key, now_ns);
        true
    }

    /// Unified session update function replacing promote_synced,
    /// refresh_local, and refresh_for_ha_activation.
    ///
    /// Collision rules:
    /// - `ha_activation=true`: always updates (highest priority, used by
    ///   RefreshOwnerRGs to re-resolve all sessions with local state)
    /// - Peer-synced entries (origin.is_peer_synced()): local traffic can
    ///   promote them (sets new origin + emits delta)
    /// - Local entries (!origin.is_peer_synced()): rejects older peer data
    pub fn update_session(
        &mut self,
        key: &SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        origin: SessionOrigin,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
        ha_activation: bool,
    ) -> bool {
        let Some(mut entry) = self.remove_entry(key) else {
            return false;
        };
        if !ha_activation {
            if entry.origin.is_peer_synced() && !origin.is_peer_synced() {
                // Peer-synced entry being promoted by local traffic — allow
            } else if entry.origin.is_peer_synced() && origin.is_peer_synced() {
                // Both peer-synced: reject (refresh_local on synced entry)
                self.restore_entry(key.clone(), entry);
                return false;
            } else if !entry.origin.is_peer_synced() && origin.is_peer_synced() {
                // Local entry: reject peer data trying to overwrite
                self.restore_entry(key.clone(), entry);
                return false;
            }
            // Both local: allow (local refresh of local entry)
        }
        let was_peer_synced = entry.origin.is_peer_synced();
        entry.decision = decision;
        entry.metadata = metadata.clone();
        entry.origin = origin;
        entry.install_epoch = self.next_epoch();
        entry.last_seen_ns = now_ns;
        entry.expires_after_ns = session_timeout_ns(protocol, tcp_flags, &self.timeouts);
        entry.closing = matches!(protocol, PROTO_TCP) && (tcp_flags & (TCP_FIN | TCP_RST)) != 0;
        self.restore_entry(key.clone(), entry);
        // #965: schedule the refreshed entry. Last_seen / expires_after
        // were rewritten above; push_to_wheel is throttled and will only
        // emit a new wheel entry if the canonical tick changed.
        self.push_to_wheel(key, now_ns);
        // Emit open delta when promoting a peer-synced entry to local
        if was_peer_synced && !origin.is_peer_synced() && !metadata.is_reverse {
            self.push_delta(SessionDelta {
                kind: SessionDeltaKind::Open,
                key: key.clone(),
                decision,
                metadata,
                origin,
                fabric_redirect_sync: false,
            });
        }
        true
    }

    /// Thin wrapper for local-only refresh (non-HA-activation path).
    /// Keeps the existing origin; skips peer-synced entries.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn refresh_local(
        &mut self,
        key: &SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        now_ns: u64,
        tcp_flags: u8,
    ) -> bool {
        let origin = self
            .entry_by_key(key)
            .map(|e| e.origin)
            .unwrap_or(SessionOrigin::ForwardFlow);
        self.update_session(
            key,
            decision,
            metadata,
            origin,
            now_ns,
            key.protocol,
            tcp_flags,
            false,
        )
    }

    /// Convenience: refresh for HA activation (always updates regardless
    /// of origin). Preserves existing origin.
    pub fn refresh_for_ha_activation(
        &mut self,
        key: &SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        now_ns: u64,
        tcp_flags: u8,
    ) -> bool {
        let origin = self
            .entry_by_key(key)
            .map(|e| e.origin)
            .unwrap_or(SessionOrigin::ForwardFlow);
        self.update_session(
            key,
            decision,
            metadata,
            origin,
            now_ns,
            key.protocol,
            tcp_flags,
            true,
        )
    }

    /// Refresh an existing session for an HA path transition while
    /// preserving its origin and current liveness state.
    pub fn refresh_for_ha_transition(
        &mut self,
        key: &SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        now_ns: u64,
    ) -> bool {
        let Some(mut entry) = self.remove_entry(key) else {
            return false;
        };
        entry.decision = decision;
        entry.metadata = metadata;
        entry.install_epoch = self.next_epoch();
        entry.last_seen_ns = now_ns;
        self.restore_entry(key.clone(), entry);
        // #965: schedule the refreshed entry for expiration check.
        self.push_to_wheel(key, now_ns);
        true
    }

    /// Promote a peer-synced session to local ownership.
    /// Convenience wrapper around update_session.
    pub fn promote_synced_with_origin(
        &mut self,
        key: &SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        origin: SessionOrigin,
        now_ns: u64,
        protocol: u8,
        tcp_flags: u8,
    ) -> bool {
        self.update_session(
            key, decision, metadata, origin, now_ns, protocol, tcp_flags, false,
        )
    }

    pub fn emit_open_delta_with_origin(
        &mut self,
        key: SessionKey,
        decision: SessionDecision,
        metadata: SessionMetadata,
        origin: SessionOrigin,
        fabric_redirect_sync: bool,
    ) {
        if metadata.is_reverse {
            return;
        }
        self.push_delta(SessionDelta {
            kind: SessionDeltaKind::Open,
            key,
            decision,
            metadata,
            origin,
            fabric_redirect_sync,
        });
    }

    pub fn delete(&mut self, key: &SessionKey) {
        self.remove_entry(key);
    }

    pub fn entry_with_origin(
        &self,
        key: &SessionKey,
    ) -> Option<(SessionDecision, SessionMetadata, SessionOrigin)> {
        self.entry_by_key(key)
            .map(|entry| (entry.decision, entry.metadata.clone(), entry.origin))
    }

    pub fn owner_rg_session_keys(&self, owner_rgs: &[i32]) -> Vec<SessionKey> {
        // #964 Step 1: handles → keys via the slab. Each session is
        // in at most one owner-RG set, so total iteration is
        // O(owner-sessions), same complexity as today's key-based
        // index returned.
        let mut handles: FxHashSet<u32> = FxHashSet::default();
        for owner_rg_id in owner_rgs {
            if let Some(set) = self.owner_rg_sessions.get(owner_rg_id) {
                handles.extend(set.iter().copied());
            }
        }
        handles
            .into_iter()
            .filter_map(|h| self.entries.get(h as usize).map(|r| r.key.clone()))
            .collect()
    }

    pub fn take_synced_local(&mut self, key: &SessionKey) -> Option<SessionLookup> {
        let entry = self.entry_by_key(key)?;
        if !entry.origin.is_peer_synced()
            || entry.metadata.is_reverse
            || entry.decision.resolution.disposition != ForwardingDisposition::LocalDelivery
        {
            return None;
        }
        self.remove_entry(key).map(|entry| SessionLookup {
            decision: entry.decision,
            metadata: entry.metadata,
        })
    }

    pub fn demote_owner_rg(&mut self, owner_rg_id: i32) -> Vec<crate::session::SessionKey> {
        if owner_rg_id <= 0 {
            return Vec::new();
        }
        let mut demoted_keys = Vec::new();
        for key in self.owner_rg_session_keys(&[owner_rg_id]) {
            let Some(entry) = self.entry_by_key_mut(&key) else {
                continue;
            };
            if !entry.origin.is_peer_synced() {
                entry.origin = SessionOrigin::SyncImport;
            }
            demoted_keys.push(key);
        }
        demoted_keys
    }

    pub fn drain_deltas(&mut self, max: usize) -> Vec<SessionDelta> {
        let drain = max.max(1).min(self.deltas.len());
        let mut out = Vec::with_capacity(drain);
        for _ in 0..drain {
            if let Some(delta) = self.deltas.pop_front() {
                out.push(delta);
            }
        }
        self.delta_drained = self.delta_drained.saturating_add(out.len() as u64);
        out
    }

    pub fn has_pending_deltas(&self) -> bool {
        !self.deltas.is_empty()
    }

    pub fn iter_with_origin(
        &self,
        mut f: impl FnMut(&SessionKey, SessionDecision, &SessionMetadata, SessionOrigin),
    ) {
        // Walk via key_to_handle (the primary index) so any orphan
        // slab record without a forward-key mapping is skipped —
        // matches the plan's "primary index is authoritative" model.
        for (key, handle) in &self.key_to_handle {
            if let Some(record) = self.entries.get(*handle as usize) {
                f(key, record.entry.decision, &record.entry.metadata, record.entry.origin);
            }
        }
    }

    /// Iterate over all session entries with idle time (in nanoseconds).
    pub fn iter_with_idle(
        &self,
        now_ns: u64,
        mut f: impl FnMut(&SessionKey, SessionDecision, &SessionMetadata, u64),
    ) {
        self.iter_with_idle_and_origin(now_ns, |key, decision, metadata, _origin, idle_ns| {
            f(key, decision, metadata, idle_ns)
        });
    }

    pub fn iter_with_idle_and_origin(
        &self,
        now_ns: u64,
        mut f: impl FnMut(&SessionKey, SessionDecision, &SessionMetadata, SessionOrigin, u64),
    ) {
        for (key, handle) in &self.key_to_handle {
            if let Some(record) = self.entries.get(*handle as usize) {
                let entry = &record.entry;
                let idle_ns = now_ns.saturating_sub(entry.last_seen_ns);
                f(key, entry.decision, &entry.metadata, entry.origin, idle_ns);
            }
        }
    }

    fn push_delta(&mut self, delta: SessionDelta) {
        if self.deltas.len() >= MAX_SESSION_DELTAS {
            self.delta_drops = self.delta_drops.saturating_add(1);
            return;
        }
        self.deltas.push_back(delta);
    }

    /// #964 Step 1: centralized session removal. Eager-cleanup
    /// invariant — every handle-valued internal index MUST be
    /// cleaned BEFORE the slab slot is returned to the free list.
    /// All session removal goes through this helper.
    fn remove_entry(&mut self, key: &SessionKey) -> Option<SessionEntry> {
        let handle = self.key_to_handle.remove(key)?;
        // Read the record (still in slab) to learn what to clean.
        // `.get` not `.remove` — we'll remove from slab last.
        // Fallible: a stale key_to_handle pointing at a freed slot
        // returns None and we restore the mapping. Should never
        // fire under correct cleanup; release-mode safety net
        // (Copilot review — was `.expect()` which panicked).
        let Some(record) = self.entries.get(handle as usize) else {
            debug_assert!(
                false,
                "remove_entry: key_to_handle had stale handle {} for {:?}",
                handle, key
            );
            // Restore the primary-index mapping so a failed remove
            // doesn't mutate len() / leave the table inconsistent
            // (Codex round-3 finding).
            self.key_to_handle.insert(key.clone(), handle);
            return None;
        };
        // PRIMARY-KEY GUARD: defend against a stale key_to_handle
        // pointing at a reused slab slot for a different session.
        // Should never fire under correct cleanup; release-mode
        // safety net (returns None instead of corrupting another
        // session's indices).
        if record.key != *key {
            debug_assert!(
                false,
                "remove_entry: stale key_to_handle for {:?}",
                key
            );
            self.key_to_handle.insert(key.clone(), handle);
            return None;
        }
        let decision = record.entry.decision;
        let metadata = record.entry.metadata.clone();
        // Borrow on `record` ends here; subsequent calls take
        // &mut self (cleanup helpers) without conflict.
        let _ = record;
        // Clean every handle-valued internal index. Each cleanup is
        // VALUE-GUARDED via guarded_remove — only remove if the
        // stored handle still equals our handle. Mirrors today's
        // matches!(... existing == key) pattern.
        self.remove_forward_nat_index(key, handle, decision, &metadata);
        remove_owner_rg_index_entry(
            &mut self.owner_rg_sessions,
            metadata.owner_rg_id,
            handle,
        );
        // Mandatory debug assertion: NO handle-valued index still
        // points at the freed handle. Catches eager-cleanup
        // invariant violations before slab slot reuse.
        debug_assert!(
            self.no_index_points_at(handle),
            "remove_entry leaked handle {} in a secondary index",
            handle
        );
        // Only AFTER all indices are clean, return slot to slab.
        let record = self.entries.remove(handle as usize);
        Some(record.entry)
    }

    /// #964 Step 1: re-insert an entry that was just `remove_entry`'d.
    /// Returns None always — kept return type for API compatibility
    /// with the prior FxHashMap-based shape.
    fn restore_entry(&mut self, key: SessionKey, entry: SessionEntry) -> Option<SessionEntry> {
        let record = SessionRecord {
            key: key.clone(),
            entry,
        };
        let raw = self.entries.insert(record);
        let handle: u32 = raw.try_into().expect("slab handle exceeds u32");
        self.key_to_handle.insert(key.clone(), handle);
        // Clone metadata + decision out of the slab record for
        // index_forward_nat_key (which takes &mut self).
        let (decision, metadata) = {
            let record = &self.entries[handle as usize];
            (record.entry.decision, record.entry.metadata.clone())
        };
        self.index_forward_nat_key(&key, handle, decision, &metadata);
        None
    }

    /// #964 Step 1: insert all secondary indices for a freshly-stored
    /// session. Mirrors today's gates exactly:
    /// - reverse_translated_index for reverse entries when translated
    ///   != key.
    /// - nat_reverse_index for reverse_wire (always) and
    ///   reverse_canonical (when != key) on forward entries.
    /// - forward_wire_index ONLY when forward_wire != key
    ///   (Codex round-4 finding #2 — was unconditional in v4).
    /// - owner_rg_sessions ONLY when owner_rg_id > 0
    ///   (Codex round-4 finding #2).
    fn index_forward_nat_key(
        &mut self,
        key: &SessionKey,
        handle: u32,
        decision: SessionDecision,
        metadata: &SessionMetadata,
    ) {
        if metadata.is_reverse {
            let translated = translated_session_key(key, decision.nat);
            if translated != *key {
                self.reverse_translated_index.insert(translated, handle);
            }
        } else {
            self.nat_reverse_index
                .insert(reverse_wire_key(key, decision.nat), handle);
            let reverse_canonical = reverse_canonical_key(key, decision.nat);
            if reverse_canonical != *key {
                self.nat_reverse_index.insert(reverse_canonical, handle);
            }
            let forward_wire = forward_wire_key(key, decision.nat);
            if forward_wire != *key {
                self.forward_wire_index.insert(forward_wire, handle);
            }
        }
        if metadata.owner_rg_id > 0 {
            self.owner_rg_sessions
                .entry(metadata.owner_rg_id)
                .or_default()
                .insert(handle);
        }
    }

    /// #964 Step 1: value-guarded removal of secondary indices —
    /// only remove an index entry if its stored handle still equals
    /// the handle we're removing. Mirrors today's `matches!(... existing == key)`
    /// shape, just keyed on u32 handle instead of SessionKey.
    fn remove_forward_nat_index(
        &mut self,
        key: &SessionKey,
        handle: u32,
        decision: SessionDecision,
        metadata: &SessionMetadata,
    ) {
        if metadata.is_reverse {
            let translated = translated_session_key(key, decision.nat);
            if matches!(
                self.reverse_translated_index.get(&translated),
                Some(stored) if *stored == handle
            ) {
                self.reverse_translated_index.remove(&translated);
            }
            return;
        }
        let reverse_wire = reverse_wire_key(key, decision.nat);
        if matches!(self.nat_reverse_index.get(&reverse_wire), Some(stored) if *stored == handle) {
            self.nat_reverse_index.remove(&reverse_wire);
        }
        let reverse_canonical = reverse_canonical_key(key, decision.nat);
        if matches!(
            self.nat_reverse_index.get(&reverse_canonical),
            Some(stored) if *stored == handle
        ) {
            self.nat_reverse_index.remove(&reverse_canonical);
        }
        let forward_wire = forward_wire_key(key, decision.nat);
        if matches!(self.forward_wire_index.get(&forward_wire), Some(stored) if *stored == handle) {
            self.forward_wire_index.remove(&forward_wire);
        }
    }

    /// #964 Step 1 mandatory debug assertion: scan every
    /// handle-valued internal index for the freed handle. Used by
    /// `remove_entry` to enforce the eager-cleanup invariant in
    /// debug builds. O(N) per call — acceptable for tests, no-op in
    /// release.
    #[cfg(debug_assertions)]
    fn no_index_points_at(&self, handle: u32) -> bool {
        !self.key_to_handle.values().any(|h| *h == handle)
            && !self.nat_reverse_index.values().any(|h| *h == handle)
            && !self.forward_wire_index.values().any(|h| *h == handle)
            && !self
                .reverse_translated_index
                .values()
                .any(|h| *h == handle)
            && !self
                .owner_rg_sessions
                .values()
                .any(|set| set.contains(&handle))
    }

    #[cfg(not(debug_assertions))]
    #[inline]
    fn no_index_points_at(&self, _handle: u32) -> bool {
        true
    }
}

fn remove_owner_rg_index_entry(
    index: &mut FxHashMap<i32, FxHashSet<u32>>,
    owner_rg_id: i32,
    handle: u32,
) {
    if owner_rg_id <= 0 {
        return;
    }
    if let Some(entries) = index.get_mut(&owner_rg_id) {
        entries.remove(&handle);
        if entries.is_empty() {
            index.remove(&owner_rg_id);
        }
    }
}

fn session_timeout_ns(protocol: u8, tcp_flags: u8, timeouts: &SessionTimeouts) -> u64 {
    match protocol {
        PROTO_TCP => {
            if (tcp_flags & (TCP_FIN | TCP_RST)) != 0 {
                TCP_CLOSING_TIMEOUT_NS
            } else {
                timeouts.tcp_established_ns
            }
        }
        PROTO_UDP => timeouts.udp_ns,
        PROTO_ICMP | PROTO_ICMPV6 => timeouts.icmp_ns,
        _ => OTHER_SESSION_TIMEOUT_NS,
    }
}


#[cfg(test)]
#[path = "tests.rs"]
mod tests;
