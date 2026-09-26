use crate::afxdp::{ForwardingDisposition, ForwardingResolution};
use crate::nat::NatDecision;
use crate::nat64::Nat64ReverseInfo;
use rustc_hash::{FxHashMap, FxHashSet, FxSeededState};
use smallvec::SmallVec;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

/// #2364: session-index maps keyed by attacker-controllable values (the
/// externally-chosen 5-tuple `SessionKey`, per-IP `IpAddr`) use a SEEDED
/// FxHasher instead of the unkeyed `FxBuildHasher`. With the default
/// unseeded hasher an off-box sender can construct keys whose buckets
/// collide, building collision chains that amplify lookup/insert/remove
/// CPU — and for the maps placed behind `Arc<Mutex<..>>` in
/// `coordinator/session_manager.rs`, lock-hold time as well. The seed is
/// the per-boot, per-process secret (`crate::hot_hash_seed`): node-local
/// (HA sync transmits explicit keys, never hash values, so peers re-bucket
/// under their own seed), stable for the process lifetime (so a key's
/// bucket is consistent across the session's life), and reshuffled per
/// restart. Cost is one extra `usize` in the BuildHasher state and a seed
/// write per hasher — no per-packet allocation.
type SeededKeyMap<V> = HashMap<SessionKey, V, FxSeededState>;
type SeededIpMap<V> = HashMap<IpAddr, V, FxSeededState>;

/// #4399/#4438: the 1:N bucket type shared by ALL THREE NAT session lookup
/// indexes — `nat_reverse_index`, `forward_wire_index`, and
/// `reverse_translated_index`. Each is a multimap because NAT can be
/// non-bijective: one reverse / forward-wire / translated key legitimately maps
/// to more than one session under interface-mode SNAT with no port translation,
/// DNAT-to-shared-backend, NAT64, or non-bijective static NAT — the latent
/// #1758 collision (pool-mode SNAT is bijective, so its buckets stay length 1).
/// Inline capacity 2 keeps the common non-colliding case — one handle per key,
/// which most deployments never exceed — ZERO-alloc, and absorbs the typical
/// 2-way collision without spilling to the heap. Two inline `u32` slots cost
/// the same as one: the heap variant `(ptr, cap)` dominates the SmallVec union
/// size, so N=2 is free relative to N=1. Before #4399/#4438 each index was a
/// single-value `SeededKeyMap<u32>`: a colliding install DISPLACED the earlier
/// handle, so the displaced session's traffic was mis-delivered (a session
/// hijack) or (once the later session closed) dropped.
type NatIndexBucket = SmallVec<[u32; 2]>;
type SeededReverseIndex = HashMap<SessionKey, NatIndexBucket, FxSeededState>;
type SeededForwardWireIndex = HashMap<SessionKey, NatIndexBucket, FxSeededState>;
type SeededReverseTranslatedIndex = HashMap<SessionKey, NatIndexBucket, FxSeededState>;
/// #10130/#10674: address-only index key for session-gated reply fragments.
type SeededL3ReverseIndex = HashMap<L3ReverseKey, NatIndexBucket, FxSeededState>;

// #1047 P2: SessionKey and the key-transform helpers (forward_wire_key,
// translated_session_key, reverse_canonical_key, reverse_wire_key,
// reply_matches_forward_session) live in session/key.rs. Re-exporting
// at pub(crate) keeps the existing crate::session::* surface intact.
mod discriminator;
mod key;
pub(crate) mod pptp;
pub(crate) mod pptp_control;
// #7188: `WireDiscriminator` is exported alongside the class enum because the
// HA session-sync receiver has to distinguish "the peer stated a class" from
// "the peer could not state one" — two answers a plain `TunnelDiscriminator`
// cannot carry.
pub(crate) use discriminator::{TunnelDiscriminator, WireDiscriminator};
// #7239: the routing domain's HA-wire encoding. Reserved-zero, three-state
// decode — #7188's shape, for #7188's reason.
mod routing_domain_wire;
pub(crate) use key::*;
pub(crate) use routing_domain_wire::{
    QUARANTINED_ROUTING_DOMAIN,
    // #9546: named at the crate level so the conntrack mirror states absence
    // with the codec's own constant rather than a bare literal.
    WIRE_ABSENT as ROUTING_DOMAIN_WIRE_ABSENT,
    WireRoutingDomain,
    install_table_identity,
    routing_domain_from_wire,
    routing_domain_to_wire,
};
mod entry;
pub(crate) use entry::*;
mod ctx;
pub(crate) use ctx::*;
// #6949: the HA-carried policy attribution (policy_id, counter idx, app
// timeout, NAT64 pool source) derived ONCE for BOTH session-delta producers —
// the binary open frame and the JSON RPC-fallback delta.
mod sync_attribution;
pub(crate) use sync_attribution::*;
mod wheel;
use wheel::SessionWheel;

const SESSION_GC_INTERVAL_NS: u64 = 1_000_000_000;
/// #10591: test-only names for the production cadence constants. The window
/// harness must derive its MAX values from the same values that gate the real
/// worker sweep and advance the real timer wheel; a copied literal can make a
/// cadence drift silently green.
#[cfg(test)]
pub(crate) const SESSION_GC_INTERVAL_NS_FOR_TEST: u64 = SESSION_GC_INTERVAL_NS;
#[cfg(test)]
pub(crate) const WHEEL_TICK_NS_FOR_TEST: u64 = wheel::WHEEL_TICK_NS;
#[cfg(test)]
pub(crate) const WHEEL_BUCKETS_FOR_TEST: usize = wheel::WHEEL_BUCKETS;
const DEFAULT_MAX_SESSIONS: usize = 131072;
/// #9856: one page of deferred terminal removals per worker. Overflow is
/// counted and makes the active export fail closed rather than growing an
/// unbounded `ExpiredSession` queue.
pub(crate) const MAX_TOMBSTONES_FOR_EXPORT: usize = 8192;
const DEFAULT_TCP_SESSION_TIMEOUT_NS: u64 = 300_000_000_000;
/// #3152: short half-open / opening timeout for a TCP session whose
/// three-way handshake has not completed. A session created by a bare SYN
/// (SYN set, ACK clear) starts in the OPENING state and is held only for
/// this window; it is promoted to the full `tcp_established_ns` idle window
/// once the handshake completes (the first ACK-bearing segment after the
/// SYN — the SYN-ACK on the reverse half and the handshake-completing ACK
/// on the forward half). Without this, a bare SYN landed on the full 300 s
/// established timeout, so a low-rate SYN flood (SYN with no follow-up ACK)
/// could pin half-open entries in the bounded `max_sessions` table far
/// longer than a legitimate incomplete handshake needs and eventually deny
/// new flows. 20 s matches the Junos `tcp-initial-timeout` default. This
/// is the SYN-flood/half-open sibling of the #3046 RST-reap window.
const DEFAULT_TCP_OPENING_TIMEOUT_NS: u64 = 20_000_000_000;
const TCP_CLOSING_TIMEOUT_NS: u64 = 30_000_000_000;
/// #3046: a session torn down by RST is reaped far faster than a graceful
/// FIN close. A RST abruptly aborts the socket — there is no half-closed /
/// delayed-ACK / retransmit window to keep state alive for, so holding the
/// entry for the full 30s `TCP_CLOSING_TIMEOUT_NS` only lets a reset-flood (or
/// any high-churn reset workload) saturate the session table with dead
/// connections and delay port reuse. 2s matches the "reap RST quickly"
/// posture of Junos and is well under Linux conntrack's CLOSE timeout while
/// still tolerating a stray reordered segment after the RST.
const TCP_RST_TIMEOUT_NS: u64 = 2_000_000_000;
const DEFAULT_UDP_SESSION_TIMEOUT_NS: u64 = 60_000_000_000;
const DEFAULT_ICMP_SESSION_TIMEOUT_NS: u64 = 60_000_000_000;
const OTHER_SESSION_TIMEOUT_NS: u64 = 30_000_000_000;

/// #2220: flow-cache keepalive divisor. A cache-served session is
/// re-stamped once its idle time reaches `expires_after_ns /
/// SESSION_KEEPALIVE_DIVISOR` (a quarter of its own timeout). An
/// actively-forwarding flow is therefore re-stamped each time its idle
/// time crosses `expires_after_ns / N`, so its age stays ~`T/N` in
/// steady state and it is NEVER reaped while its inter-packet gaps stay
/// below the full timeout `T` — independent of co-resident flow rates.
/// Four leaves three full refresh windows of
/// slack before natural expiry — far enough from the edge that ordinary
/// GC jitter (1 s `SESSION_GC_INTERVAL_NS`) never reaps an active flow,
/// yet large enough that the steady-state refresh only writes/re-buckets
/// a few times per timeout window rather than per packet.
const SESSION_KEEPALIVE_DIVISOR: u64 = 4;

/// #2120: stale-synced ceiling multiplier. A peer-synced session HELD
/// by the standby retention gate is reaped once it has been held longer
/// than `min(STALE_SYNCED_CEILING_MULT × expires_after_ns,
/// STALE_SYNCED_CEILING_ABS_NS)`. RELATIVE because configured timeouts
/// can reach `MaxDurationSeconds`, so a fixed ceiling would reap a live
/// long-timeout session on the standby before failover. Multiplier ≈ 3
/// gives the primary several full idle windows to deliver its Close
/// delta (or the journal/reconnect path to reconcile) before the
/// standby reaps on its own.
pub(crate) const STALE_SYNCED_CEILING_MULT: u64 = 3;

/// #2120: stale-synced ceiling absolute cap (≈7 days). Bounds the
/// pathological long-`inactivity-timeout` config (a 30-day-timeout flow
/// would otherwise allow a leaked held entry to be pinned for 90 days at
/// MULT×). 7 days is generously ≥ the largest realistic standby idle
/// window a legitimate failover could need, so the cap reaps only leaked
/// standby state, never a live local flow (a held entry is by definition
/// NOT forwarding on this node). See plan §4.4 / §6.5.
pub(crate) const STALE_SYNCED_CEILING_ABS_NS: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

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
    /// Entries that were re-bucketed (kept on the wheel rather than
    /// removed). Covers the long-timeout / not-yet-expired Case-4 entries
    /// AND, since #2120, idle-crossed entries kept alive by the standby
    /// gate (HOLD and SELF-HEAL both re-bucket). Telemetry/tests must not
    /// read this as "long-timeout only".
    pub(crate) re_bucketed: usize,
    /// #2120: peer-synced (or whole-node-standby `owner_rg_id==0`)
    /// entries that crossed their idle timeout but were HELD instead of
    /// expired because this node does not currently forward their RG.
    /// Restores the dead Go-GC `IsLocalPrimary` retention contract into
    /// the userspace wheel — without it the standby silently reaps
    /// long-lived synced sessions and breaks them on failover (#131
    /// reintroduced by the eBPF→userspace migration).
    pub(crate) held_standby: usize,
    /// #2120: HELD entries reaped anyway because they have been held
    /// past the stale-synced ceiling (`min(MULT × timeout, ABS_CAP)`
    /// measured from `first_held_ns`). Bounds the lost-primary-delete
    /// leak — a held entry whose Close delta and journal entry were both
    /// lost cannot be pinned forever.
    pub(crate) reaped_stale_synced: usize,
    /// #2120: HELD entries re-stamped (kept alive with a fresh
    /// `last_seen_ns`) because this node has STARTED forwarding their RG
    /// but the entry's recorded epoch predates the activation — the
    /// edge-triggered self-heal that closes the promotion command-apply
    /// race (RefreshOwnerRGS may not have landed yet).
    pub(crate) healed_on_promote: usize,
    /// #2120: peer-synced `owner_rg_id==0` entries AGED on an
    /// otherwise-active node (one RG active, the entry belongs to a
    /// standby RG path). This is the known active/active under-retention
    /// residual (plan §4.4 / A2#4); counted so it is OBSERVABLE in the
    /// field rather than a silent drop.
    pub(crate) aged_owner_rg_zero_active_node: usize,
    /// #4380: idle-crossed entries KEPT ALIVE because their forward↔reverse
    /// companion is still within its idle window — Junos single-session
    /// semantics (a session's idle time is measured from the last activity
    /// in EITHER direction, so a flow active on only one direction must not
    /// reap its quiet half). Re-stamped from the companion and re-bucketed
    /// instead of removed; counted so the asymmetric-flow retention is
    /// observable rather than a silent divergence from the raw wheel.
    pub(crate) kept_alive_by_companion: usize,
}

/// #2441: largest configured session timeout (in seconds) that survives the
/// seconds→nanoseconds conversion without overflowing `u64`. This MUST stay in
/// lockstep with the Go commit-time gate `config.MaxDurationSeconds`
/// (`math.MaxInt64 / 1e9 = 9_223_372_036`, schema_validators.go) and the
/// build-time coercion `coerceWireSessionTimeout` (pkg/dataplane/userspace/
/// flow.go). The Go side is the operator-facing reject; this const is the
/// runtime saturation backstop so an out-of-band snapshot or a future caller
/// that bypasses the Go gate can NEVER wrap `secs * 1_000_000_000`.
///
/// `i64::MAX / 1_000_000_000`. Bound to the i64 (not u64) ceiling on purpose:
/// the wire field originates as a Go int64, and matching the Go bound exactly
/// means a value the Go gate accepts is one this boundary leaves unchanged, and
/// a value the Go gate would reject is one this boundary saturates rather than
/// wraps.
pub(crate) const MAX_SESSION_TIMEOUT_SECS: u64 = (i64::MAX / 1_000_000_000) as u64;

/// Maximum representable session timeout in nanoseconds — the saturation
/// ceiling for `from_seconds`. `MAX_SESSION_TIMEOUT_SECS * 1_000_000_000`
/// fits in `u64` by construction.
pub(crate) const MAX_SESSION_TIMEOUT_NS: u64 = MAX_SESSION_TIMEOUT_SECS * 1_000_000_000;

const _: () = assert!(
    MAX_SESSION_TIMEOUT_SECS
        .checked_mul(1_000_000_000)
        .is_some(),
    "MAX_SESSION_TIMEOUT_SECS * 1e9 must not overflow u64"
);

/// Convert a configured timeout in seconds to nanoseconds, SATURATING at
/// `MAX_SESSION_TIMEOUT_NS` instead of wrapping (#2441). A snapshot boundary
/// must never panic and must never silently shrink a huge timeout into a tiny
/// one (the wrap bug). Saturating fails toward a longer-lived session, the
/// opposite of premature expiry.
#[inline]
pub(crate) fn secs_to_ns_saturating(secs: u64) -> u64 {
    secs.checked_mul(1_000_000_000)
        .unwrap_or(MAX_SESSION_TIMEOUT_NS)
        .min(MAX_SESSION_TIMEOUT_NS)
}

/// #3714: upper bound (in SECONDS) on a per-application inactivity timeout,
/// mirroring the Go commit-time gate `appTimeoutMax = 86400`
/// (`pkg/config/compiler_applications.go`). Go rejects a custom
/// `set applications application <a> inactivity-timeout <n>` with `n > 86400`
/// at commit, so a well-formed snapshot never carries a larger value; this
/// const is the runtime backstop that clamps a corrupt / mixed-version wire
/// value (config-snapshot `PolicyApplicationSnapshot.inactivity_timeout` OR the
/// HA `SessionSyncRequest.inactivity_timeout`) so a bogus `4294967295` cannot
/// stamp an effectively never-expiring idle timeout — diverging session GC from
/// the commit-time contract. This is the per-application analogue of the
/// `MAX_SESSION_TIMEOUT_SECS` overflow backstop above: the Go side is the
/// operator-facing reject, this bound is the dataplane's clamp. Keep the two
/// values in lockstep with the Go `appTimeoutMax`.
pub(crate) const APP_INACTIVITY_TIMEOUT_MAX_SECS: u32 = 86400;

/// #3227: convert a matched application's per-application inactivity timeout
/// (`PolicyEvaluationResult.inactivity_timeout`, in SECONDS) to the nanosecond
/// session override stamped on `SessionMetadata.inactivity_timeout_ns`. `None`
/// (or 0 seconds) maps to `None` (use the global per-protocol timeout — the
/// historical behavior); a positive value is first clamped to
/// `APP_INACTIVITY_TIMEOUT_MAX_SECS` (#3714 — mirrors the Go 86400 s commit
/// gate so a corrupt/mixed-version wire value can't produce a never-expiring
/// session) and then saturates at `MAX_SESSION_TIMEOUT_NS`, so a pathological
/// config cannot wrap into a tiny window.
///
/// This is the single seconds→ns conversion authority for BOTH ingress paths —
/// the local config-snapshot policy match (`parse_applications` →
/// `PolicyEvaluationResult`) and the HA session-sync receive
/// (`SessionSyncRequest.inactivity_timeout`) — so clamping here bounds every
/// value that persists on a session or rides the sync wire to a peer.
#[inline]
pub(crate) fn app_inactivity_timeout_ns(secs: Option<u32>) -> Option<u64> {
    match secs {
        Some(s) if s > 0 => Some(secs_to_ns_saturating(u64::from(
            s.min(APP_INACTIVITY_TIMEOUT_MAX_SECS),
        ))),
        _ => None,
    }
}

/// Configurable session timeout values (in nanoseconds).
#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionTimeouts {
    pub(crate) tcp_established_ns: u64,
    /// #3152: short half-open timeout for a handshake-incomplete (OPENING)
    /// TCP session. Not operator-configurable yet — held at
    /// `DEFAULT_TCP_OPENING_TIMEOUT_NS` (the Junos `tcp-initial-timeout`
    /// default) on every construction path. A future config knob would set
    /// it here without touching the state machine.
    pub(crate) tcp_opening_ns: u64,
    /// #7342: `security flow tcp-session closing-timeout`, the Junos CLOSING
    /// window — a FIN has been seen in ONE direction and the close handshake has
    /// not completed. Held at `TCP_CLOSING_TIMEOUT_NS` when the operator has not
    /// set the leaf, which is the window this state has always reaped on.
    pub(crate) tcp_closing_ns: u64,
    /// #7342: `security flow tcp-session time-wait-timeout`, the Junos TIME_WAIT
    /// window — a FIN has been seen in BOTH directions.
    ///
    /// Before #7342 there was no such state: `session_timeout_ns` split a TCP
    /// close only into RST and not-RST, so a fully-closed session reaped on the
    /// same window as a half-closed one. That is why #6539 could annotate
    /// `time-wait-timeout` as "no TIME_WAIT state" rather than "no wire
    /// carrier" — there was nothing for a carrier to drive. The default is
    /// `TCP_CLOSING_TIMEOUT_NS`, so an operator who sets neither leaf sees
    /// byte-identical reaping to pre-#7342.
    pub(crate) tcp_time_wait_ns: u64,
    pub(crate) udp_ns: u64,
    pub(crate) icmp_ns: u64,
}

/// #7342: the three `security flow tcp-session` windows #6539 documented as
/// accepted-only, in seconds, as they arrive on the wire. `0` means "unset —
/// keep the dataplane default".
///
/// A named-field struct rather than three more positional `u64`s on
/// `from_seconds`: the three are same-typed and adjacent, so a transposition
/// would be silent, and it would be silent in the direction that matters —
/// closing and time-wait differ by 4s versus 150s of Junos default session
/// lifetime, not by a type error.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct TcpSessionWindowSecs {
    pub(crate) initial: u64,
    pub(crate) closing: u64,
    pub(crate) time_wait: u64,
}

impl Default for SessionTimeouts {
    fn default() -> Self {
        Self {
            tcp_established_ns: DEFAULT_TCP_SESSION_TIMEOUT_NS,
            tcp_opening_ns: DEFAULT_TCP_OPENING_TIMEOUT_NS,
            tcp_closing_ns: TCP_CLOSING_TIMEOUT_NS,
            tcp_time_wait_ns: TCP_CLOSING_TIMEOUT_NS,
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
                secs_to_ns_saturating(tcp_secs)
            } else {
                DEFAULT_TCP_SESSION_TIMEOUT_NS
            },
            // #3152/#7342: the half-open window's own leaf
            // (`tcp-session initial-timeout`) arrives through
            // `with_tcp_session_windows`; this base keeps the Junos-parity
            // default, which is what an unset leaf leaves in place. The two
            // windows are independent — a configured established-timeout has
            // never governed the half-open state.
            tcp_opening_ns: DEFAULT_TCP_OPENING_TIMEOUT_NS,
            tcp_closing_ns: TCP_CLOSING_TIMEOUT_NS,
            tcp_time_wait_ns: TCP_CLOSING_TIMEOUT_NS,
            udp_ns: if udp_secs > 0 {
                secs_to_ns_saturating(udp_secs)
            } else {
                DEFAULT_UDP_SESSION_TIMEOUT_NS
            },
            icmp_ns: if icmp_secs > 0 {
                secs_to_ns_saturating(icmp_secs)
            } else {
                DEFAULT_ICMP_SESSION_TIMEOUT_NS
            },
        }
    }

    /// #7342: layer the three `security flow tcp-session` windows onto a base
    /// built by [`SessionTimeouts::from_seconds`].
    ///
    /// Separate from `from_seconds` so its existing three arguments keep their
    /// meaning and their call sites, and so the three new windows arrive as
    /// NAMED fields. `0` in any of them means unset and leaves that window at
    /// its dataplane default, which is the same `0 = default` convention the
    /// established / UDP / ICMP seconds already use on this wire — so a snapshot
    /// from a control plane that does not send them at all (`serde(default)`)
    /// produces byte-identical windows to pre-#7342.
    pub(crate) fn with_tcp_session_windows(mut self, secs: TcpSessionWindowSecs) -> Self {
        if secs.initial > 0 {
            self.tcp_opening_ns = secs_to_ns_saturating(secs.initial);
        }
        if secs.closing > 0 {
            self.tcp_closing_ns = secs_to_ns_saturating(secs.closing);
        }
        if secs.time_wait > 0 {
            self.tcp_time_wait_ns = secs_to_ns_saturating(secs.time_wait);
        }
        self
    }
}

/// #7342: which close window a TCP session reaps on.
///
/// Junos distinguishes CLOSING (after the first FIN) from TIME_WAIT (after the
/// close handshake completes); before #7342 this dataplane had ONE post-FIN
/// window and so could express neither leaf. `Reset` is not a Junos leaf at all
/// — it is #3046's abort window, an xpf control that keeps a reset flood from
/// pinning table entries — and it is deliberately NOT operator-configurable
/// here: `rst-invalidate-session` is the Junos knob for that behaviour and is
/// tracked separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TcpCloseClass {
    /// #3046: a RST was observed. Sticky — a later graceful FIN cannot promote
    /// the entry back to a longer window.
    Reset,
    /// Junos CLOSING: a FIN in ONE direction; the close is in progress.
    Closing,
    /// Junos TIME_WAIT: a FIN in BOTH directions; the close completed.
    TimeWait,
}

impl TcpCloseClass {
    /// The class a SINGLE packet can establish on its own.
    ///
    /// Never `TimeWait`: one packet carries one direction's FIN, and TIME_WAIT
    /// is a statement about both. A session installed BY a closing packet is
    /// therefore CLOSING, which is also what it was before #7342.
    #[inline]
    fn from_packet(tcp_flags: u8) -> Self {
        if has_rst(tcp_flags) {
            Self::Reset
        } else {
            Self::Closing
        }
    }

    /// #9412: the HA wire encoding of a close class. `0` is reserved for "not
    /// carried / not closing", so an older peer's absent byte reads as today's
    /// behaviour and no class ever encodes to it.
    #[inline]
    pub(crate) fn to_wire(self) -> u8 {
        match self {
            Self::Closing => 1,
            Self::TimeWait => 2,
            Self::Reset => 3,
        }
    }

    /// #9412: decode a wire close class. `0`, and any value this build does not
    /// know, is `None` ("not carried"), so a class a newer peer invents imports
    /// as not-closing rather than on a guessed window.
    #[inline]
    pub(crate) fn from_wire(wire: u8) -> Option<Self> {
        match wire {
            1 => Some(Self::Closing),
            2 => Some(Self::TimeWait),
            3 => Some(Self::Reset),
            _ => None,
        }
    }
}

impl SessionEntry {
    /// #7342: the close class this entry's accumulated state puts it in.
    ///
    /// Only meaningful once `closing` is set; the callers all check that first,
    /// because an OPEN session's window comes from `session_timeout_ns` instead.
    #[inline]
    fn tcp_close_class(&self) -> TcpCloseClass {
        if self.reset {
            TcpCloseClass::Reset
        } else if self.fin_own && self.fin_peer {
            TcpCloseClass::TimeWait
        } else {
            TcpCloseClass::Closing
        }
    }

    /// #9412: this entry's close class on the HA wire, `0` while it is open.
    #[inline]
    pub(crate) fn tcp_close_class_wire(&self) -> u8 {
        if self.closing {
            self.tcp_close_class().to_wire()
        } else {
            0
        }
    }
}

/// #7342: THE close-window formula. Four sites used to carry their own copy of
/// "RST → 2s, else 30s" — `session_timeout_ns`, the read path in `lookup.rs`,
/// the companion mirror in `propagate_tcp_state_to_companion`, and the HA
/// promote in `update_session` — and adding a third arm to each is exactly the
/// drift this repo's one-formula rule exists to prevent. They all call here.
#[inline]
pub(crate) fn tcp_close_window_ns(class: TcpCloseClass, timeouts: &SessionTimeouts) -> u64 {
    match class {
        TcpCloseClass::Reset => TCP_RST_TIMEOUT_NS,
        TcpCloseClass::Closing => timeouts.tcp_closing_ns,
        TcpCloseClass::TimeWait => timeouts.tcp_time_wait_ns,
    }
}
const MAX_SESSION_DELTAS: usize = 4096;
use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};
// #2151: TCP flag bits from the shared crate::tcp_flags SSOT. Re-exported
// so the conntrack submodules (install, lookup, expire) keep referencing
// TCP_FIN/TCP_RST via `super::*`. The session-closing test is the shared
// `is_closing` predicate.
use crate::tcp_flags::{
    TCP_FIN, TCP_RST, has_fin, has_rst, is_closing, is_initial_syn, is_syn_ack,
};

#[allow(unused_macros)]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        #[cfg(feature = "debug-log")]
        eprintln!($($arg)*);
    };
}

// #2005 pure code-motion split: the conntrack fast path is split into
// focused submodules that all attach `impl SessionTable` blocks. These
// declarations sit AFTER `debug_log!` so the macro is in textual scope
// for the child modules that call it (`expire`, `lookup`). The
// coordinator/table definition and the #1752/#1855 in-place-refresh
// contract (update_session / refresh_for_ha_transition + the
// secondary-index re-assert + #964 eager cleanup helpers) stay in
// mod.rs. Submodule methods keep their original visibility; the only
// widening is `push_to_wheel` (module-private `fn` → `pub(in
// crate::session)`) because callers in mod.rs / install / lookup cross
// the module boundary into `expire`.
mod expire;
mod install;
mod lookup;
// #7342: the read path's close/promotion signal bundle, applied to the
// forward<->reverse companion by `propagate_tcp_state_to_companion` below.
pub(crate) use lookup::ExportWalkOutcome;
use lookup::TcpStatePropagation;

/// #7212: the `(config generation, logical ingress interface)` pair a session's
/// static input-filter verdict was derived under.
///
/// Both halves are needed because the verdict is a function of BOTH: the
/// generation says WHICH filter snapshot judged it, the interface says WHOSE
/// filter did. A stamp carrying only the generation silently claims an
/// interface change was already adjudicated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FilterRevalidationStamp {
    generation: u64,
    logical_ingress_ifindex: i32,
}

impl FilterRevalidationStamp {
    /// "No static input-filter verdict has been derived for this entry."
    ///
    /// It can never collide with a live stamp: generation `0` is the value
    /// `SessionTable` holds before the first poll pass publishes one, and the Go
    /// control plane's snapshot generation is a monotone counter that starts at
    /// 1 — so no live packet is ever classified at generation 0
    /// (`classify_metadata` also requires `snapshot_installed`).
    pub(crate) const UNVALIDATED: Self = Self {
        generation: 0,
        logical_ingress_ifindex: 0,
    };

    fn live(generation: u64, logical_ingress_ifindex: i32) -> Self {
        Self {
            generation,
            logical_ingress_ifindex,
        }
    }
}

/// #8114 item 2: the three answers [`SessionTable::filter_revalidation_target`]
/// can give about a wire tuple.
///
/// It replaces an `Option<SessionKey>` in which TWO of these collapsed onto
/// `None`, and that collapse was the defect. `Fresh` means "this entry's static
/// input-filter verdict was already derived under the live (generation,
/// ingress) pair" — the answer for every packet but one per session per pair,
/// and correctly nothing to do. `NoLocalEntry` means "this worker holds no
/// entry this tuple may safely name": the #2120 transient peer-synced hit that
/// was served from the shared map without a local install, the reverse-NAT
/// repair whose install was refused at `max_sessions`, or a stale primary
/// handle. Those packets have a RESOLVED forwarding decision and are being
/// forwarded, so reading them as `Fresh` meant a newly added static deny was
/// never applied to them — fail-open, and for the `max_sessions` population for
/// as long as the table stays full.
///
/// The distinction is worth a type because the two need OPPOSITE handling and
/// look identical at the call site: `Fresh` must cost nothing, `NoLocalEntry`
/// must still derive the verdict. The verdict needs the flow and the interface;
/// only the STAMP and the table teardown need the entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FilterRevalidationTarget {
    /// The entry exists and already carries a verdict for the live
    /// `(generation, ingress)` pair. Nothing to derive, nothing to apply.
    Fresh,
    /// The entry exists and its verdict is stale. Carries the CANONICAL key —
    /// the primary-index key, which on the NAT reverse-translated alias path is
    /// NOT the wire tuple that found it — so a teardown acts on the session
    /// that was actually judged.
    Stale(SessionKey),
    /// No entry this tuple may safely name. Derive the verdict anyway; do not
    /// stamp and do not tear down.
    NoLocalEntry,
}

/// #8356: the zone-policy sibling of [`FilterRevalidationTarget`]. Same three
/// answers, same resolution rules; it differs only in comparing a
/// generation-only stamp (see `SessionEntry::policy_revalidated_gen` for why
/// the ingress ifindex is not part of this key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PolicyRevalidationTarget {
    /// The entry exists and its zone-policy verdict was already derived under
    /// the live generation.
    Fresh,
    /// The entry exists and its verdict is stale. Carries the CANONICAL key so
    /// a teardown acts on the session that was actually judged.
    Stale(SessionKey),
    /// No entry this tuple may safely name — the #2120 transient synced-hit
    /// path, or a reused slab slot. Nothing to stamp, nothing to tear down.
    NoLocalEntry,
}
/// #10507: receiver-local provenance for the zone-policy stamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PolicyRevalidationKind {
    /// Constructor/upsert default; generation 0 remains stale.
    Unvalidated,
    /// Permit derived using a current local forwarding egress.
    LiveEgress,
    /// Permit derived from a recorded (non-current) egress: the non-local
    /// `FabricRedirect` case by design, or a stored forward egress consumed
    /// on the reverse path (§4.3). Either way it must re-judge before it may
    /// authorize local forwarding.
    RecordedEgress,
}

/// #10507: the packet-time CURRENT forwarding posture the gate judges the
/// stamp against. Interpreted from the disposition by the afxdp caller, which
/// owns `ForwardingDisposition` semantics; the gate only combines it with
/// the single probe below. Intent and egress validity are SEPARATE: a
/// would-forward disposition without a valid egress is rule-4 fail-closed,
/// never "non-local".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PolicyGateCurrent {
    /// Would locally forward with a valid egress (§4.2 rules 1/3).
    LocalForwarding,
    /// Would locally forward but has no valid egress (§4.2 rule 4).
    LocalForwardingNoEgress,
    /// Non-local: redirect, seed, terminal, or host delivery.
    NonLocal,
}

/// #10507: one probe answering the combined freshness/authority question
/// (§4.2: "one helper ... rather than sprinkling origin tests beside the old
/// generation compare"). The caller supplies the packet-time posture; every
/// field below derives from it plus a SINGLE `revalidation_record` probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PolicyGateAnswer {
    /// Generation-only freshness, exactly what `policy_revalidation_target`
    /// answers (kept so callers keep one match shape).
    pub target: PolicyRevalidationTarget,
    /// Stamped provenance (`Unvalidated` when no entry resolves).
    pub kind: PolicyRevalidationKind,
    /// Rules 3/4: run the cold walk even when `target` is `Fresh`.
    pub force_cold: bool,
    /// A cold-walk `Decline` must revoke rather than stand.
    pub fail_closed_decline: bool,
    /// A type-armed ICMP exit must revoke rather than decline.
    pub fail_closed_icmp: bool,
}

#[derive(Clone, Debug)]
struct SessionEntry {
    decision: SessionDecision,
    metadata: SessionMetadata,
    origin: SessionOrigin,
    install_epoch: u64,
    last_seen_ns: u64,
    /// #2465: monotonic (`CLOCK_MONOTONIC`) nanosecond timestamp at which this
    /// entry was first installed. Unlike `last_seen_ns` it is write-once: it is
    /// NOT re-stamped by `touch`/`update_session`/`refresh_for_ha_transition`,
    /// so it preserves the true session age across the lifetime of the entry.
    /// Carried into the close `SessionDelta` so the RT_FLOW SESSION_CLOSE frame
    /// reports a real flow StartTime (`#2465`) instead of the packet-count
    /// heuristic. A re-import (`upsert_synced`) or a fresh install stamps it to
    /// the install `now_ns`.
    created_ns: u64,
    expires_after_ns: u64,
    closing: bool,
    /// #7342: a FIN was observed in THIS entry's own direction.
    ///
    /// Forward and reverse are two independent entries, so "this entry's
    /// direction" is exactly the direction its own packets travel. Set on the
    /// read path when a FIN arrives here, and mirrored onto the companion's
    /// `fin_peer` by `propagate_tcp_state_to_companion` — so both halves
    /// converge on the same `(own, peer)` pair from either side.
    ///
    /// FIN specifically, not `is_closing`: that predicate is FIN **or** RST, and
    /// a RST is an abort with no close handshake to complete. A reset session
    /// takes `TcpCloseClass::Reset` and never reaches TIME_WAIT.
    ///
    /// It could not be derived from the state that already existed.
    /// `observed_tcp_flags` looks like the answer and is not: `account_packet`
    /// OR-folds BOTH directions' flags onto the FORWARD entry on purpose, so
    /// NetFlow's `tcpControlBits` reports the whole flow. `observed_tcp_flags &
    /// TCP_FIN` is therefore true after ONE fin, and a TIME_WAIT detector built
    /// on it would put every half-closed session straight into TIME_WAIT — a
    /// mistake no single-FIN test could see.
    ///
    /// Node-local derived state, like `established` and `handshake_pending`:
    /// `SessionEntry` carries no serde, so this is on no wire.
    fin_own: bool,
    /// #7342: a FIN was observed in the COMPANION's direction. Written only by
    /// `propagate_tcp_state_to_companion`; see `fin_own`.
    fin_peer: bool,
    /// #3046: set once this TCP session has been seen carrying a RST. It is
    /// sticky (never cleared back to false while the entry lives) so that a
    /// stray reordered non-RST segment arriving after the RST cannot promote
    /// the entry back to the 30s graceful-FIN `TCP_CLOSING_TIMEOUT_NS`. When
    /// set together with `closing`, the timeout selection uses the short
    /// `TCP_RST_TIMEOUT_NS` instead of the FIN close timeout.
    reset: bool,
    /// #3152/#10889/#10891: per-entry promotion state used to derive the idle
    /// class. For TCP, false means OPENING: bare-SYN and SYN-ACK-first pickups
    /// start false. A reverse SYN-ACK promotes a SYN-first flow while
    /// `handshake_pending` keeps it on `tcp_opening_ns`; SYN-ACK-first pickups
    /// stay false until their reverse ACK completes the handshake. Other TCP
    /// midstream pickups start true. For non-TCP sessions with a custom app
    /// timeout, false keeps the global protocol timeout until a genuine reverse
    /// packet promotes both halves; sessions without an app override start true.
    ///
    /// Node-local derived state: this is not serialized. TCP peer-synced entries
    /// remain established; non-TCP app-timeout imports remain gated because
    /// reply evidence is not carried on the HA wire.
    established: bool,
    /// #6752/#10891: `handshake_pending` marks the gap after a SYN-ACK is seen
    /// (or a SYN-ACK-first session is installed) but before its completing ACK.
    /// For a SYN-first session that is the reverse SYN-ACK then the forward
    /// ACK; a SYN-ACK-first pickup waits for the reverse ACK.
    ///
    /// It exists because two correct changes combined into an incorrect
    /// outcome. #4109 (2026-07-04) promoted on the SYN-ACK and deliberately did
    /// NOT extend the forward half's expiry, "so a handshake the client never
    /// completes still reaps on the short opening window". #4380 (2026-07-07)
    /// then added the companion probe, which is protocol- and
    /// handshake-agnostic: at the forward half's 20s deadline it saw the
    /// reverse half alive on its brand-new 300s window, kept the forward half
    /// and re-stamped it. Neither change was wrong; together they held BOTH
    /// halves of a never-completed handshake for ~300s, and #4109's comment
    /// went on asserting the conservative behaviour, which is why nobody
    /// re-checked it.
    ///
    /// Two things consult it, and they close DIFFERENT-SIZED leaks — stated
    /// separately because an earlier revision of this comment claimed both were
    /// needed for the 300s case, and a mutation showed that was false:
    ///   * the idle-window selection treats `established && !handshake_pending`
    ///     as the established class, so the SYN-ACK stamps the OPENING window
    ///     rather than 300s. THIS is what closes the ~300s hold; with it in
    ///     place and no further traffic, both halves reap at ~20s on their own.
    ///   * `companion_keeps_alive` refuses to extend a half whose companion is
    ///     still pending. This closes a SMALLER, retransmission-driven leak: a
    ///     server retransmitting its SYN-ACK slides the reverse half's window
    ///     forward, and a handshake-agnostic probe would re-stamp the forward
    ///     half off it for as long as the retransmissions continue
    ///     (`retransmitted_synack_does_not_resurrect_the_forward_half_6752`).
    ///
    /// Node-local derived state, like `established`: `SessionEntry` is not
    /// serialized, so this is not on any wire and an HA peer re-derives it from
    /// the segments it sees.
    handshake_pending: bool,
    /// #10891: the OPENING session was installed from a SYN-ACK. While true,
    /// only a non-SYN ACK on the reverse half completes the handshake; this
    /// prevents a retransmitted SYN-ACK in the installing direction from
    /// clearing `handshake_pending`.
    syn_ack_first: bool,
    /// #965: absolute wheel tick at which this session is scheduled to
    /// be checked for expiration. Updated on every push to the wheel.
    /// A WheelEntry whose `scheduled_tick != entry.wheel_tick` is a
    /// stale duplicate (lazy-delete discriminator).
    wheel_tick: u64,
    /// #7212: the `(config generation, logical ingress interface)` this
    /// direction's static input-filter verdict was last derived under, or
    /// [`FilterRevalidationStamp::UNVALIDATED`].
    ///
    /// A purely STATIC (address / protocol / port) input filter's verdict is a
    /// pure function of `(ingress interface, family, 5-tuple)`. The 5-tuple and
    /// the family are the session key; the other two are what this records, so
    /// the stamp names EVERY input the verdict depended on. An earlier revision
    /// recorded only the generation, which made the stamp claim more than it
    /// knew: at a fixed generation, a same-direction packet arriving on a
    /// DIFFERENT interface (asymmetric routing, a redundancy-group member
    /// change) is adjudicated by that interface's filter, and a
    /// generation-only stamp reported the session already judged.
    ///
    /// It is written ONLY by `mark_filter_revalidated`, from the established-hit
    /// path that actually ran the interface's filter. Every INSTALL — forward,
    /// reverse companion, peer-synced import alike — stamps `UNVALIDATED`, and
    /// that uniformity is deliberate rather than lazy:
    ///
    ///   * the REVERSE companion is pre-installed alongside the forward session
    ///     and its ingress is explicitly UNOBSERVED at that point (the same
    ///     reason `SessionMetadata::ingress_ifindex` is `0` for it, #4983), so
    ///     no filter has adjudicated it and a live stamp would be a false claim
    ///     that one had;
    ///   * a PEER-SYNCED import carries the peer's adjudication, made against
    ///     the peer's interfaces, which is the failover fence;
    ///   * the FORWARD install's verdict WAS just computed by the session-MISS
    ///     path, so a live stamp would be truthful there — but it would be the
    ///     only truthful case, and buying it costs a per-install branch to keep
    ///     one static term walk off each new session's second packet. That walk
    ///     is side-effect free and is paid only on an interface with an input
    ///     filter attached, which is the gate every arm passes through first.
    ///
    /// The established-session HIT path compares this against
    /// `(SessionTable::filter_revalidation_gen, the packet's logical ingress)`;
    /// on a mismatch it re-derives the static verdict ONCE, re-stamps here on
    /// ACCEPT, and revokes the session on DENY. A DENY deliberately does NOT
    /// re-stamp — see `afxdp/poll_descriptor/filter.rs`.
    ///
    /// `config_generation` is a SUPERSET trigger: it advances on every commit,
    /// not only on filter edits. It does NOT advance on a `BumpFIBGeneration` —
    /// `Coordinator::bump_fib_generation` assigns `validation.fib_generation`
    /// alone and republishes, reusing the published forwarding `Arc` so the
    /// #1188 worker short-circuit still hits — which an earlier revision of this
    /// comment claimed, over-stating the cost. That is
    /// deliberate and safe — the re-derivation can only DROP a session the
    /// current filter denies, so an extra revalidation of a permitted flow is a
    /// no-op, and its cost is gated behind a single `iface_filter_v{4,6}_fast`
    /// lookup that only an interface with an input filter attached ever passes.
    /// A generation bump already invalidates every flow-cache entry
    /// (`FlowCacheStamp::config_generation`), so the packet that pays for the
    /// revalidation is one already taking the session path.
    ///
    /// Node-local derived state, like `established` and `handshake_pending`:
    /// `SessionEntry` carries no serde, so this is on no wire and is not part of
    /// session identity.
    filter_revalidated: FilterRevalidationStamp,
    /// #8356: the `config_generation` this entry's ZONE-POLICY verdict was last
    /// derived under. `0` is UNVALIDATED and can never collide with a live
    /// generation, for the same reason `FilterRevalidationStamp::UNVALIDATED`
    /// cannot: the Go control plane's snapshot generation is a monotone counter
    /// starting at 1, and `classify_metadata` additionally requires
    /// `snapshot_installed`.
    ///
    /// GENERATION-ONLY, deliberately unlike `filter_revalidated`, which is keyed
    /// `(generation, logical ingress ifindex)`. An input filter is a
    /// per-INTERFACE object, so the same session reached on a different ingress
    /// has a different filter to re-derive. A zone-policy verdict is keyed on
    /// the (from_zone, to_zone) PAIR, and BOTH come from this entry —
    /// `metadata.ingress_zone` and `decision.resolution.egress_ifindex` — never
    /// from the interface a given packet happened to arrive on. Adding the
    /// ifindex to this key would only make the stamp go spuriously stale and
    /// re-walk policy terms that cannot produce a different verdict.
    ///
    /// Read only for the FORWARD direction. The reverse companion carries
    /// SWAPPED zones (`afxdp/shared_ops.rs`, `afxdp/poll_descriptor/mod.rs`
    /// both build it with `ingress_zone`/`egress_zone` exchanged), and this is a
    /// STATEFUL firewall: the reply is permitted because the session exists, not
    /// because a policy admits (to_zone -> from_zone). Re-deriving on the
    /// reverse entry would deny the reply of every ordinary one-way-permitted
    /// flow. See `poll_descriptor/policy_revalidation.rs`.
    ///
    /// Node-local derived state, like `filter_revalidated` beside it:
    /// `SessionEntry` carries no serde, so this is on no wire and is not part of
    /// session identity.
    policy_revalidated_gen: u64,
    /// #10507: receiver-local provenance for the zone-policy stamp. This is
    /// intentionally not carried on the HA wire.
    policy_revalidation_kind: PolicyRevalidationKind,
    /// #2120: the RG epoch (`rg_epochs[owner_rg_id]`, or the node-level
    /// `rg_epochs[0]` for `owner_rg_id <= 0`) recorded the last time this
    /// entry was self-healed (the expire pass observed this node START
    /// forwarding the RG). The expire pass compares the current epoch
    /// against it to detect the activation edge and fire the self-heal
    /// re-stamp exactly once per activation. This field is NOT
    /// write-once — it is reset and re-stamped over the entry's life:
    ///   - SELF-HEAL stamps it to the current epoch (the only write that
    ///     records a live epoch).
    ///   - `install` / `upsert_synced`, `update_session` (real-traffic
    ///     refresh), and `refresh_for_ha_transition` (promotion refresh)
    ///     RESET it to 0. A reset means "epoch unknown; re-stamp on the
    ///     next SELF-HEAL", and is load-bearing: it guarantees the first
    ///     forwarding pass after any epoch-bumping activation observes
    ///     `current_epoch != seen_rg_epoch` and fires the self-heal.
    /// The HOLD branch deliberately does NOT write it — the worker reads
    /// the HA map and `rg_epochs` as separate loads, so a HOLD can see an
    /// old (inactive) map with a new (already-bumped) epoch; stamping that
    /// epoch on a hold would make the next (active-map) pass skip the
    /// self-heal and age the synced session (the Codex old-map/new-epoch
    /// race). An epoch of 0 is the standalone / never-self-healed default.
    seen_rg_epoch: u32,
    /// #2120: monotonic timestamp (ns) at which this entry FIRST entered
    /// the held (non-forwarding standby) state, or 0 when not held. The
    /// stale-synced ceiling measures the hold duration from here, NOT
    /// from `last_seen_ns`, so a self-heal re-stamp on a flapping RG
    /// cannot reset the leak clock. Cleared (→0) ONLY when the entry
    /// genuinely leaves the held world: real-traffic refresh
    /// (`update_session`), promotion refresh
    /// (`refresh_for_ha_transition`), or re-import (`upsert_synced`).
    first_held_ns: u64,
    /// #2501: per-session forward/reverse byte and packet counters,
    /// accumulated on the AF_XDP forwarding hot path. Forward = the
    /// initiator→responder direction (the direction the session was keyed
    /// in); reverse = the reply direction (`metadata.is_reverse` packets).
    ///
    /// These are PLAIN `u64`s, not atomics: the `SessionTable` is
    /// worker-owned and single-threaded (every increment site runs under
    /// `&mut self` on the owning worker — see the `create_drops` /
    /// `admission_refused` precedent above), so a session entry is never
    /// touched by two cores concurrently. The hot-path cost is a single
    /// `saturating_add` per counter (no allocation, no atomic, no
    /// cross-core cache-line traffic). They are surfaced two ways without
    /// any new wire field:
    ///   - periodically mirrored into the BPF conntrack map by
    ///     `refresh_bpf_conntrack_last_seen` (~1s GC cadence) so `show
    ///     security flow session` reports live volume;
    ///   - snapshotted onto the close `SessionDelta` so the SESSION_CLOSE
    ///     RT_FLOW frame (#2460) carries the real NetFlow/IPFIX volume in
    ///     the already-reserved [56:64]/[64:72]/[112:120]/[120:128] wire
    ///     slots (previously hard-zeroed with `(#2501)` markers).
    counters: SessionCounters,
    /// #2749: the IP ToS byte observed on the FORWARD direction of this
    /// session (DSCP in the high 6 bits, ECN cleared — the shim meta carries
    /// only the 6-bit DSCP). Stamped from `meta.dscp << 2` on every forward
    /// packet (`account_packet`, last-wins — DSCP is stable for the life of a
    /// flow in practice), 0 until the first forward packet is accounted.
    /// Snapshotted onto the close `SessionDelta` so the SESSION_CLOSE RT_FLOW
    /// frame carries the real NetFlow/IPFIX class-of-service value. A plain
    /// `u8` for the same worker-owned single-threaded reason as `counters`.
    observed_tos: u8,
    /// #2749: the OR of every TCP control-flag byte seen on this session, in
    /// BOTH directions (`account_packet` ORs `meta.tcp_flags` on every
    /// forwarded packet). Yields the cumulative `tcpControlBits` a collector
    /// expects (SYN|ACK|FIN|RST|… over the flow). 0 for non-TCP flows.
    observed_tcp_flags: u8,
    /// #4915: the STABLE, node-unique session id assigned at install
    /// (`SessionTable::alloc_session_id`). Write-once — never re-stamped over the
    /// entry's life — so a session's SESSION_CREATE and SESSION_CLOSE RT_FLOW
    /// records carry the SAME id, and a reused 5-tuple (same worker, later
    /// install) gets a DISTINCT id. Harvested onto the Open/Close `SessionDelta`
    /// and encoded at RT_FLOW [152:160]. The high 16 bits namespace the id by
    /// worker so it is unique across the node's shared-nothing worker tables; the
    /// low 48 bits are a per-worker monotonic counter starting at 1, so a real id
    /// is never 0 (0 is the "unknown/legacy" wire sentinel). A peer-synced import
    /// (`upsert_synced`) is assigned a FRESH node-local id — cross-node id
    /// identity is a documented follow-up (see docs).
    session_id: u64,
    /// #9901 (F-077): GCRA theoretical-arrival-time gating embedded ICMP
    /// error delivery FOR this session (burst 64 / rate 64/s — see
    /// `ICMP_ERROR_BURST`). Without it, one quoter can steer an UNBOUNDED
    /// error stream onto a live session (forged PTB/TE as a PMTUD /
    /// throughput weapon). Init 0 = full by construction (a fresh session
    /// delivers its first 64 errors immediately). A plain `u64`, not an
    /// atomic: the table is worker-owned and single-threaded. Node-local
    /// derived state, like `established`: `SessionEntry` carries no serde,
    /// so this is on no HA wire and a peer re-derives its own budget.
    last_icmp_error_tat: u64,
}

/// Snapshot of one live half after a policy rebind. The worker uses this
/// narrow copy to restamp the shared-session and BPF mirrors without exposing
/// the worker-owned `SessionEntry`.
#[derive(Clone, Debug)]
pub(crate) struct PolicyRebindEntry {
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) origin: SessionOrigin,
    pub(crate) protocol: u8,
    pub(crate) tcp_flags: u8,
    pub(crate) session_id: u64,
    pub(crate) tcp_close_class: u8,
}

/// #2501: per-session traffic accounting, split by direction. A `Copy`
/// snapshot type so callers can read the four counters out of a session
/// entry in one move (the BPF-map refresh and the close-delta harvest both
/// need the whole set).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SessionCounters {
    pub(crate) fwd_packets: u64,
    pub(crate) fwd_bytes: u64,
    pub(crate) rev_packets: u64,
    pub(crate) rev_bytes: u64,
}

impl SessionCounters {
    /// Account a single forwarded packet of `len` bytes in the given
    /// direction. `saturating_add` so a (practically impossible) overflow
    /// pins at `u64::MAX` rather than wrapping a volume counter to a tiny
    /// value — branchless, predictable codegen on the hot path.
    #[inline]
    fn account(&mut self, is_reverse: bool, len: u64) {
        if is_reverse {
            self.rev_packets = self.rev_packets.saturating_add(1);
            self.rev_bytes = self.rev_bytes.saturating_add(len);
        } else {
            self.fwd_packets = self.fwd_packets.saturating_add(1);
            self.fwd_bytes = self.fwd_bytes.saturating_add(len);
        }
    }
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

/// The `session_id` high-16 NAMESPACE value RESERVED for the Go control plane
/// (#6198). `nextUserspaceSyncedSessionID`
/// (`pkg/daemon/daemon_ha_userspace_convert.go`) mints
/// `0xFFFF << 48 | counter48` for the peer-synced sessions the daemon installs,
/// and those land in the SAME BPF conntrack mirror field this table stamps. A
/// `SessionTable` must never take this as its namespace — see
/// `set_session_id_namespace`, which enforces it.
pub(crate) const CONTROL_PLANE_SESSION_ID_WORKER_HI: u64 = 0xFFFF;

/// #6311: bit position, WITHIN the 16-bit session-id namespace field, of the
/// NODE discriminator. The namespace is `node_bit << 15 | worker_id`, so the
/// worker half narrows from 16 bits to 15 — still ~256x the hard cap on worker
/// ids (`MAX_NAT_HOLDER_WORKERS` = 128, enforced where `binding.worker_id` is
/// minted in `server/helpers/planning.rs`), so nothing real loses room.
pub(crate) const SESSION_ID_NODE_BIT_SHIFT: u32 = 15;

/// #6311: the largest worker id representable in the narrowed worker half. A
/// worker id above this would carry into the node bit and mint ids in the PEER's
/// namespace — a silent cross-node collision, strictly worse than the aliasing
/// the pre-#6311 mask produced, so `set_session_id_namespace` refuses it rather
/// than masking it away.
pub(crate) const SESSION_ID_MAX_WORKER: u64 = (1u64 << SESSION_ID_NODE_BIT_SHIFT) - 1;

/// #9901 (F-077): per-session embedded-ICMP-error budget — burst 64 at rate
/// 64/s. Sized for mtr (30 same-session probes/second all pass) and
/// traceroute multi-quoter same-id sessions: a 1s min-interval would break
/// both, while 64/64 bounds a forgery flood to ~64 deliveries per session
/// per burst. Enforced by `SessionTable::note_icmp_error_delivered` in ONE
/// u64 TAT per session (init 0 = full by construction).
const ICMP_ERROR_BURST: u64 = 64;
/// 1e9 / 64 — exact (15_625_000ns).
const ICMP_ERROR_INTERVAL_NS: u64 = 1_000_000_000 / 64;
const ICMP_ERROR_HORIZON_NS: u64 = ICMP_ERROR_INTERVAL_NS * (ICMP_ERROR_BURST - 1);
/// #9901 (F-077): cap on the error-budget side table (shared/peer matches
/// with no local entry). At cap the insert path prunes fully-recovered
/// budgets, then conservatively REFUSES unknown keys (suppressed + counted)
/// rather than evicting — evict-and-admit would let a 1025-key round-robin
/// exceed 64/s per session indefinitely. 1024 bounds the worst-case scan
/// and memory while dwarfing any legitimate concurrent peer-error population.
const ICMP_ERROR_SIDE_TABLE_CAP: usize = 1024;

/// #9901 (F-077): embedded ICMP errors suppressed by the per-session GCRA —
/// errors that MATCHED a session but were over that session's 64/64 budget.
/// Bumped in `icmp_error_tat_take`, the single consume site. Read as a delta
/// in tests; surfaced as
/// `xpf_userspace_embedded_error_per_session_suppressed_total`.
pub(crate) static EMBEDDED_ERROR_PER_SESSION_SUPPRESSED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Single-TAT GCRA consume on a worker-owned `u64` (no atomics: every call
/// site runs under `&mut` on the owning worker). Init 0 = full: `0 -
/// horizon` saturates to 0, which is `<=` any `now`. On deny bumps the
/// suppression counter; the caller drops the error.
fn icmp_error_tat_take(tat: &mut u64, now_ns: u64) -> bool {
    if tat.saturating_sub(ICMP_ERROR_HORIZON_NS) > now_ns {
        EMBEDDED_ERROR_PER_SESSION_SUPPRESSED_TOTAL.fetch_add(1, AtomicOrdering::Relaxed);
        return false;
    }
    *tat = (*tat).max(now_ns).saturating_add(ICMP_ERROR_INTERVAL_NS);
    true
}
/// Inverse of `icmp_error_tat_take` for a charge whose error was NOT
/// delivered (policy-refused, TTL-expired, or CoS-dropped AFTER the matcher
/// took its token — #10667). A take sets `tat = max(old, now) + interval`,
/// so subtracting one interval restores `max(old, now)`: exact when the
/// budget was live (`old > now`), and full-equivalent when it was idle
/// (`old <= now` — `now` admits the same future takes as `0`, since time
/// never runs backward). Pairing is single-take to single-refund: every
/// matcher `Match` flows to exactly one terminal outcome, and only the
/// non-delivery terminals refund. A double refund would mint credit — the
/// call sites return/`continue` immediately after refunding so no `Match`
/// can reach two of them. Never inserts: a missing slot means the take
/// denied (no `Match`, nothing owed) — fail-closed, nothing to restore.
fn icmp_error_tat_refund(tat: &mut u64) {
    *tat = tat.saturating_sub(ICMP_ERROR_INTERVAL_NS);
}

/// #9856: why a removal is happening — gates tombstone capture.
///
/// Only `Terminal` (the session is really gone) logs a tombstone for the
/// export window. `Replace` (same-key reinstall eviction) and `Transfer`
/// (ownership handoff to another table) suppress it: the key lives on,
/// and a close for the evicted incarnation would race the replacement's
/// open with no inter-channel ordering (key-matched application would
/// kill the live incarnation). Replacement convergence comes from
/// overwrite + the replacement's ordered incremental open instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RemovalKind {
    /// Genuine terminal removal (expire, teardown, purge, RST, synced
    /// delete): harvest a tombstone if export-visible.
    Terminal,
    /// Same-key eviction for an incoming local reinstall: the old
    /// incarnation dies but the key lives on — no tombstone.
    Replace,
    /// Ownership transfer out (`take_synced_local`): the entry continues
    /// elsewhere — no tombstone (moot under the ownership filter anyway,
    /// since transfers only take peer-synced entries).
    Transfer,
}

pub(crate) struct SessionTable {
    /// #7699: the PPTP call associations THIS worker can resolve.
    ///
    /// Per-worker, and deliberately not shared behind a lock: `resolve` runs on
    /// the data path for every PPTP GRE packet, and this tree keeps the packet
    /// path lock-free (shared maps exist only for HA import). Workers are fed
    /// by `WorkerCommand::InstallPptpCall` / `ForgetPptpCall`, so every worker
    /// holds the same set and a call resolves on whichever worker RSS lands its
    /// data packets on — which is generally NOT the one that saw its control
    /// channel.
    ///
    /// It lives inside `SessionTable` because it is per-worker session-identity
    /// state with exactly this lifetime, and because `SessionTable` is already
    /// threaded `&mut` through the drain — a separate parameter would be the
    /// same data with more plumbing.
    pptp: crate::session::pptp::PptpAssociations,
    /// #964 Step 1: slab-allocated session storage. Indexed by u32
    /// handle. Replaces the prior `sessions: FxHashMap<Key, Entry>`.
    entries: slab::Slab<SessionRecord>,
    /// #6297: high-watermark of the live slot extent — `1 + the highest
    /// slot index this slab has ever handed out`. The budgeted conntrack
    /// refresh (`iter_with_idle_budgeted`) bounds its round-robin walk to
    /// this instead of `entries.capacity()`. The slab NEVER shrinks
    /// (`capacity()` is monotonic, no `shrink_to_fit`), so after a
    /// session-count spike drains, `capacity()` stays at the doubled peak
    /// and the walk re-visits tens of thousands of now-vacant slots every
    /// 10s cycle. The watermark tracks the true peak extent instead, which
    /// is <= `capacity()` (the Vec doubles past the peak), so the walk
    /// wraps at the live extent.
    ///
    /// INVARIANT: `slot_high_watermark >= 1 + every currently-occupied slot
    /// index` at all times. Maintained by bumping it on every insert
    /// (`insert_record`); it is NEVER shrunk on removal. A slightly-high
    /// watermark only costs a few skipped vacant visits (safe), but if it
    /// EVER dropped below a live slot, that session's `last_seen` would
    /// stop being mirrored into the BPF conntrack map and the entry would
    /// look idle — a premature-expiry correctness bug. So: only grow it,
    /// never let it fall below an occupied slot.
    slot_high_watermark: usize,
    /// #964 Step 1: forward-key → handle. Replaces the
    /// `sessions` HashMap's key-to-entry mapping.
    key_to_handle: SeededKeyMap<u32>,
    /// Forward keys for local TCP sessions whose handshake is incomplete.
    /// Seeded and maintained with insert, promotion, and removal so pressure
    /// arbitration does not scan the session table.
    pressure_shed_openings: SeededKeyMap<()>,
    /// #9951: per-session inter-VRF leak incarnation, kept outside
    /// `SessionDecision` so the WAN-pinning decision and its wire shape remain
    /// unchanged. Only sessions created on this worker are stamped; peer
    /// imports are re-resolved on receipt before they can forward.
    leak_incarnations: SeededKeyMap<u64>,
    /// #964 Step 1: secondary indices map to u32 handles, not full keys.
    /// #4399: `nat_reverse_index` is a 1:N multimap (`SeededReverseIndex`) —
    /// a bucket of handles per reverse key — so a reverse-key collision keeps
    /// BOTH colliding forward sessions resolvable instead of displacing the
    /// earlier one. `find_forward_nat_match` validates each candidate against
    /// the full reply tuple.
    nat_reverse_index: SeededReverseIndex,
    /// #4438: `forward_wire_index` is a 1:N multimap (`SeededForwardWireIndex`)
    /// — a bucket of forward handles per forward-wire key — so a forward-wire
    /// collision (interface-mode SNAT with no port translation, and the other
    /// non-bijective NAT classes) keeps BOTH colliding forward sessions
    /// resolvable instead of displacing the earlier one.
    /// `find_forward_wire_match_with_origin` validates each candidate against
    /// the full forward-wire tuple.
    forward_wire_index: SeededForwardWireIndex,
    /// #4438: `reverse_translated_index` is a 1:N multimap
    /// (`SeededReverseTranslatedIndex`) — a bucket of reverse handles per
    /// translated (alias) key — so a translated-key collision keeps BOTH
    /// colliding reverse sessions resolvable instead of displacing the earlier
    /// one.
    reverse_translated_index: SeededReverseTranslatedIndex,
    /// #10130/#10674: forward-session handles indexed by reply fragment
    /// family and addresses before reverse NAT. Ports are absent because a
    /// non-first fragment has no L4 header; its protocol is validated per
    /// candidate, or treated as unknown when metadata carries the shim's 255
    /// sentinel.
    l3_reverse_index: SeededL3ReverseIndex,
    /// #964 Step 1: owner-RG sets keyed by handle (was Key).
    owner_rg_sessions: FxHashMap<i32, FxHashSet<u32>>,
    /// RGs demoted during the current ownership epoch. The owner-RG index is
    /// retained for transition scans, so the export walk needs this separate
    /// authority bit to reject stale same-RG bulk requests until activation.
    demoted_owner_rgs: FxHashSet<i32>,
    deltas: VecDeque<SessionDelta>,
    last_gc_ns: u64,
    max_sessions: usize,
    timeouts: SessionTimeouts,
    /// #3527: per-screened-zone override of the global half-open
    /// (`tcp_opening_ns`) TCP timeout window, keyed by ingress zone id. Built
    /// from `security screen ids-option <p> tcp syn-flood timeout <N>` (the
    /// Junos half-completed-connection queue window) and pushed alongside
    /// `set_timeouts` from the worker's applied forwarding snapshot
    /// (`set_opening_overrides`). When a bare-SYN OPENING session's ingress
    /// zone has an entry here, `session_timeout_ns` reaps it at the override
    /// instead of `DEFAULT_TCP_OPENING_TIMEOUT_NS`, so a per-zone syn-flood
    /// `timeout` actually bounds how long that zone's half-opens linger. Config
    /// is identical on both HA nodes, so this is re-derived per node from the
    /// snapshot — it never crosses the session-sync wire (a synced session is
    /// imported ESTABLISHED, so the opening branch is never taken for it; see
    /// `upsert_synced_with_origin`). Empty = no zone configures a syn-flood
    /// timeout, byte-identical to pre-#3527.
    opening_overrides: FxHashMap<u16, u64>,
    /// #7212: the live `ValidationState::config_generation` this worker is
    /// forwarding under. The established-hit static input-filter revalidation
    /// compares a session's stamp against it, and `mark_filter_revalidated`
    /// writes it. Refreshed from the same `validation` the poll pass classifies
    /// packets against (`poll_binding_process_descriptor`), so the generation a
    /// session is stamped with and the generation it is compared to can never
    /// come from different publishes. `0` until the first poll pass, which is
    /// also `FilterRevalidationStamp::UNVALIDATED`'s generation and is never
    /// live.
    filter_revalidation_gen: u64,
    /// #8356: the live `config_generation` a zone-policy verdict is judged
    /// against, published once per poll pass from the SAME `ValidationState`
    /// the pass classifies packets with — so the stamp an entry carries and the
    /// generation it is later compared to can never come from different
    /// publishes. Separate from `filter_revalidation_gen` in ROLE but published
    /// from the same source; they are two independent verdicts and must not
    /// share a stamp, or one verdict's re-stamp suppresses the other's
    /// re-derivation.
    policy_revalidation_gen: u64,
    epoch_counter: u64,
    expired: u64,
    create_drops: u64,
    /// #7919: why a by-key session lookup MISSED, split by cause.
    ///
    /// `record_by_key` / `record_by_key_mut` both bail SILENTLY on a miss
    /// (`None => return` at their call sites), so a flow whose key does not
    /// resolve is neither accounted nor touched and NOTHING says so. That is
    /// the measured shape of #7919: `show security flow session` reports
    /// `Pkts: 0, Bytes: 0` for a live transit flow while a sibling flow on the
    /// same box accounts perfectly, and every frozen row has `idle ~= age` —
    /// `last_seen` never moved either, which is only possible if BOTH
    /// `touch_if_stale` and `account_packet` missed the same lookup.
    ///
    /// Split by cause because the three need different fixes and the issue is
    /// explicit that guessing costs half the time. `AtomicU64` rather than the
    /// plain `u64` its sibling counters use because `record_by_key` takes
    /// `&self`.
    ///
    /// No handle in the key index at all — the session was never installed
    /// under this key, or was removed.
    lookup_miss_no_handle: AtomicU64,
    /// A handle resolved but pointed outside the slab — a stale handle
    /// surviving its record.
    lookup_miss_stale_handle: AtomicU64,
    /// A handle resolved to a LIVE record whose stored key differs from the
    /// one asked for: the key index and the slab disagree, so the lookup finds
    /// a session and correctly refuses to account against it.
    ///
    /// CORRECTION: this was previously labelled "the interesting one for
    /// #7919". That is a prediction, not a fact, and it is wrong for the whole
    /// class of causes it was written for. `handle_for_key` is
    /// `key_to_handle.get(key)` over the WHOLE SessionKey, so a probe whose key
    /// differs in any field finds no entry at all and lands on
    /// `lookup_miss_no_handle`. Reaching THIS counter requires the index and
    /// the slab to disagree about a key that IS present — a reused-slot hazard,
    /// not a key-construction difference.
    ///
    /// Someone reading `no_handle` while primed to expect `key_mismatch` would
    /// reasonably conclude the session was never installed and go looking at
    /// the install path. Read the three as equals.
    lookup_miss_key_mismatch: AtomicU64,
    /// #1861 §5.1: pair-admission preflight refusals — one per REFUSED
    /// FLOW (not per missing slot). Bumped by `note_admission_refused`
    /// from the new-flow refusal arms when `can_admit` fails at/near
    /// `max_sessions`. Worker-owned, single-threaded — plain u64, no
    /// atomics (mirrors `create_drops`).
    admission_refused: u64,
    /// #1861 §5.2: impossible-by-construction release residuals — an
    /// install that failed AFTER a passing `can_admit` preflight on the
    /// same descriptor iteration. Expected to stay 0 forever; nonzero
    /// means the preflight/install pairing has a bug (debug builds panic
    /// via `debug_assert!` at the call sites instead, per the #1855
    /// contract). Plain u64 like `create_drops`.
    install_partial: u64,
    /// #9604: reverse-triggered re-derivation declines on invariant-violating
    /// input — a degenerate companion inversion or a forward-companion slot
    /// holding a reverse entry. Bumped by
    /// `note_policy_revalidation_loud_decline`, whose call sites pair it with
    /// `debug_assert!(false, ...)` per the #1855 contract. Worker-owned,
    /// single-threaded — plain u64, no atomics (mirrors `install_partial`).
    policy_revalidation_loud_declines: u64,
    delta_drops: u64,
    /// #2442: loss-of-sync latch. Set true the moment `push_delta` drops a
    /// delta because the ring is full (a HA-relevant open/close event that the
    /// downstream session-sync consumer will NEVER see). Cleared by
    /// `take_delta_loss`, which the worker loop calls once per drain cycle. A
    /// true value tells the worker "the incremental stream went lossy; rescan
    /// the table truth" — it triggers a full owner-RG export so the peer
    /// re-derives the session view from a complete snapshot instead of
    /// silently diverging. The latch is a single bool, so a burst that drops N
    /// deltas before the worker reads it raises EXACTLY ONE resync (debounce by
    /// construction — see `take_delta_loss`).
    delta_loss_pending: bool,
    delta_drained: u64,
    /// #1760: cumulative count of NAT reverse-key displacement events on
    /// `nat_reverse_index`. Incremented whenever the per-flow secondary-
    /// index insert (`index_forward_nat_key_parts`, the `reverse_wire_key`
    /// insert) displaces a DIFFERENT handle for the same reverse key K —
    /// i.e. two distinct sessions resolved to the same external reverse
    /// tuple, the latent 1:N collision the #1758 research documented
    /// (interface-mode SNAT / DNAT-to-shared-backend / NAT64 / non-
    /// bijective static NAT — pool-mode SNAT is immune).
    ///
    /// This is a near-precise upper bound on live 1:N collisions, NOT an
    /// exact distinct-flow-pair count: it counts *bucket-growth* events
    /// (a distinct handle appended to an already-occupied reverse-key
    /// bucket), so a re-assert of the same handle on the per-packet refresh
    /// (#1753) does NOT re-count (the append dedups). A zero counter is
    /// strong evidence the collision never fires; a nonzero value quantifies
    /// how often two forward sessions shared one reverse key.
    ///
    /// #4399/#4438: the structural mitigation now ships — all three NAT
    /// session indexes (`nat_reverse_index`, `forward_wire_index`,
    /// `reverse_translated_index`) are 1:N multimaps, so a collision no longer
    /// DISPLACES the earlier session; both handles coexist in the bucket and
    /// the lookup walks them, validating each against the full tuple. This
    /// counter is retained as observability and, as of #4438, AGGREGATES
    /// bucket-growth across ALL THREE indexes (it was reverse-index-only
    /// before). Because one non-bijective flow-pair collides on several indexes
    /// at once (e.g. interface-mode SNAT collapses both `reverse_wire` and
    /// `forward_wire`), a single logical collision can bump this counter more
    /// than once — reinforcing its upper-bound, not-a-pair-census character.
    /// Worker-owned, single-threaded — plain u64, no atomics (mirrors
    /// `create_drops`).
    nat_reverse_key_collisions: u64,
    /// #6751: the subset of `nat_reverse_key_collisions` where the colliding
    /// sessions come from DIFFERENT internal sources.
    ///
    /// WHY THE SUBSET IS THE DECISION-GRADE NUMBER. The aggregate counts every
    /// reverse-key bucket growth, which is at least three populations with
    /// different fixes:
    ///
    ///   * two distinct internal hosts picking the same source port to the
    ///     same server under interface-mode SNAT — the #6751 cross-session
    ///     leak, and the ONLY one that PAT-on-collision fixes;
    ///   * ONE host reusing an ephemeral port while its previous session is
    ///     still resident — same bucket growth, no leak between hosts, and
    ///     PAT would not be the remedy;
    ///   * `port no-translation` / static SNAT pairs, which the allocator
    ///     admits DELIBERATELY because `AddressOnlyReverseKey` includes
    ///     dst_ip/dst_port (#6745 governs their steering row instead).
    ///
    /// The loss cluster reads 2 on the aggregate today with ONE LAN host
    /// configured, so the population it is actually producing is port reuse —
    /// which is exactly why the aggregate cannot answer "does the #6751 shape
    /// happen". This counter can: it is nonzero only when the colliding
    /// sessions have different `src_ip`.
    ///
    /// NOT a mode discriminator, and that is measured rather than deferred by
    /// preference: `NatDecision` is documented as wire-serialized over the HA
    /// fabric with "field shape and derive set must be preserved bit-for-bit",
    /// and its equality drives both the reindex decision (`old_nat !=
    /// decision.nat`) and whether NAT is applied to a packet at all (`nat !=
    /// NatDecision::default()`), so a mode bit cannot go there. Threading one
    /// through `install_with_protocol` instead would touch 120 call sites. So
    /// interface-mode and address-only pool mode stay indistinguishable here;
    /// distinct-source is the axis that is both free and decisive.
    ///
    /// Worker-owned, single-threaded — plain u64, no atomics, like its sibling.
    nat_reverse_key_collisions_distinct_src: u64,
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
    /// #2134: OFF-gate for per-IP session-limit accounting. True iff any
    /// screen profile configures `limit-session source-ip-based` /
    /// `destination-ip-based`. When false (the ~99% deployment), every
    /// counter-maintenance op below short-circuits so install/remove pay
    /// nothing for an unconfigured feature (#1357 codegen-sensitivity).
    /// Set by `set_session_limit_active`, driven from the worker's
    /// forwarding/screen-profile snapshot apply.
    session_limit_active: bool,
    /// #2134/#3122/#10310: per-source-IP count of PRESENT forward-direction
    /// logical sessions. The shared counted-class predicate is
    /// `!is_reverse && install::session_limit_origin_counted(origin)`: true
    /// HA-peer-synced sessions count for failover enforcement, while a
    /// WorkerLocalImport replica does not consume a second logical slot.
    /// Incremented at the two create sinks (fresh install + synced import),
    /// decremented at the sole removal sink (`remove_entry`); in-place HA
    /// transitions are balanced, with only an uncounted-replica→local
    /// promotion adding a slot. Evicted the moment a count hits 0 so the map
    /// is bounded by distinct IPs with >=1 live logical session (#2128 — no
    /// phantom-zero entries). Read non-mutating at the new-flow check.
    session_limit_src_counts: SeededIpMap<u32>,
    /// #2134: per-destination-IP mirror of `session_limit_src_counts`.
    session_limit_dst_counts: SeededIpMap<u32>,
    /// #4915: per-worker monotonic session-id counter. Starts at 1 (so a real
    /// id is never 0 — 0 is the "unknown" wire sentinel) and is bumped once per
    /// `alloc_session_id`. Worker-owned and single-threaded like every other
    /// counter here, so a plain `u64` (no atomic). Combined with
    /// `session_id_worker_hi` to form the STABLE `SessionEntry.session_id`.
    next_session_id: u64,
    /// #4915 + #6311: this table's session-id NAMESPACE, shifted into the high
    /// 16 bits — `(node_bit << 15 | worker_id) << 48`. The worker half makes a
    /// session id unique across the node's shared-nothing per-worker
    /// `SessionTable`s; the node half makes it unique across the CLUSTER, so a
    /// peer id adopted verbatim on import (#5212) can never collide with an id
    /// this node mints. 0 for a table whose namespace was never set (the test
    /// default and any single-table context) — harmless there because a lone
    /// table's monotonic counter is already unique.
    session_id_worker_hi: u64,
    /// #9901 (F-077): per-session ICMP-error TATs for matches with NO local
    /// entry — shared/peer sessions resolved through the HA import maps.
    /// Those have no `SessionEntry` to carry a TAT, so the budget lives here,
    /// keyed by the SAME matched key the gate resolves. Bounded (cap 1024,
    /// prune-then-deny at cap — see `note_icmp_error_delivered`) and seeded
    /// (`SeededKeyMap` — attacker-keyed), so it is neither growable nor
    /// hash-floodable. Local matches use the entry TAT and never touch this
    /// map. Node-local (never synced).
    icmp_error_side_tats: SeededKeyMap<u64>,
    /// #9856: terminal-removal harvests awaiting export (`remove_entry`
    /// with `RemovalKind::Terminal`). Drained every tick by the worker
    /// loop (`take_tombstones_into`) — pushed when a window is open,
    /// discarded when idle — so it holds at most one page of deletions.
    tombstone_log: Vec<ExpiredSession>,
    /// Tombstones refused by the bounded log. The active export transfers
    /// this count to its dedicated buffer's fail-closed drop metric.
    tombstone_drops: u64,
}

impl SessionTable {
    /// #7699: the PPTP call associations this worker can resolve.
    pub(crate) fn pptp(&self) -> &crate::session::pptp::PptpAssociations {
        &self.pptp
    }

    /// #9951: record the incarnation of the inter-VRF leak used by a local
    /// session's creation-time resolution. Zero means the resolution did not
    /// ride a leak and is deliberately not stored.
    pub(crate) fn stamp_leak_incarnation(&mut self, key: &SessionKey, incarnation: u64) {
        if incarnation != 0 {
            self.leak_incarnations.insert(key.clone(), incarnation);
        }
    }

    /// #9951: return the leak incarnation recorded for a local session.
    pub(crate) fn leak_incarnation(&self, key: &SessionKey) -> Option<u64> {
        self.leak_incarnations.get(key).copied()
    }
    /// Mutable access, for the `WorkerCommand` drain that installs and forgets
    /// associations and for the unassociated counter.
    pub(crate) fn pptp_mut(&mut self) -> &mut crate::session::pptp::PptpAssociations {
        &mut self.pptp
    }
    /// Clear demotion markers when the requested owner RGs become active again.
    pub(crate) fn activate_owner_rgs(&mut self, owner_rgs: &[i32]) {
        for owner_rg_id in owner_rgs {
            if *owner_rg_id > 0 {
                self.demoted_owner_rgs.remove(owner_rg_id);
            }
        }
    }

    pub fn new() -> Self {
        // #2364: the per-boot, per-process secret seed for the
        // attacker-keyed session indices. Drawn once (process-global
        // OnceLock), so every worker's SessionTable on this node shares
        // the same seed — fine, the seed only needs to be unknowable
        // off-box and stable within the boot, not unique per table. A
        // `usize` truncation of the 64-bit seed is the FxSeededState width.
        let seed = crate::hot_hash_seed::hot_path_hash_seed() as usize;
        let state = FxSeededState::with_seed(seed);
        Self {
            pptp: crate::session::pptp::PptpAssociations::default(),
            // Start with an empty slab and let it grow on demand.
            // `Slab::with_capacity(DEFAULT_MAX_SESSIONS)` would eagerly
            // allocate a 131072-slot backing Vec per worker (Copilot
            // review finding) — the prior FxHashMap grew on demand,
            // so match that to keep baseline RSS unchanged.
            entries: slab::Slab::new(),
            // #6297: no slots handed out yet — an empty slab has a live
            // extent of 0, so the budgeted refresh walk is a no-op until
            // the first install bumps this via `insert_record`.
            slot_high_watermark: 0,
            // #2364: SessionKey-keyed indices use the per-boot secret seed
            // so attacker-chosen 5-tuples cannot construct collision chains.
            // `state` is the shared `FxSeededState` (carries the seed; a
            // `Clone` per map is just a `usize` copy).
            key_to_handle: HashMap::with_hasher(state.clone()),
            pressure_shed_openings: HashMap::with_hasher(state.clone()),
            nat_reverse_index: HashMap::with_hasher(state.clone()),
            forward_wire_index: HashMap::with_hasher(state.clone()),
            reverse_translated_index: HashMap::with_hasher(state.clone()),
            l3_reverse_index: HashMap::with_hasher(state.clone()),
            leak_incarnations: HashMap::with_hasher(state.clone()),
            // owner_rg_sessions is keyed by i32 RG/ifindex (not an
            // attacker-chosen 5-tuple) with inner sets of internally
            // allocated u32 handles — neither is the hash-flood surface, so
            // it stays on the default FxHasher (#2364 scope note).
            owner_rg_sessions: FxHashMap::default(),
            demoted_owner_rgs: FxHashSet::default(),
            deltas: VecDeque::with_capacity(MAX_SESSION_DELTAS.min(256)),
            last_gc_ns: 0,
            max_sessions: DEFAULT_MAX_SESSIONS,
            timeouts: SessionTimeouts::default(),
            // #3527: empty until a forwarding snapshot with a per-zone
            // syn-flood timeout is applied via `set_opening_overrides`.
            opening_overrides: FxHashMap::default(),
            // #7212: no poll pass has published a generation yet.
            filter_revalidation_gen: 0,
            policy_revalidation_gen: 0,
            epoch_counter: 0,
            expired: 0,
            create_drops: 0,
            lookup_miss_no_handle: AtomicU64::new(0),
            lookup_miss_stale_handle: AtomicU64::new(0),
            lookup_miss_key_mismatch: AtomicU64::new(0),
            admission_refused: 0,
            install_partial: 0,
            policy_revalidation_loud_declines: 0,
            delta_drops: 0,
            delta_loss_pending: false,
            delta_drained: 0,
            nat_reverse_key_collisions: 0,
            nat_reverse_key_collisions_distinct_src: 0,
            wheel: SessionWheel::new(),
            last_pop_stats: WheelPopStats::default(),
            session_limit_active: false,
            // #2364: per-IP session-limit counters are keyed by the
            // attacker-chosen source/destination IP — seed them too.
            session_limit_src_counts: HashMap::with_hasher(state.clone()),
            session_limit_dst_counts: HashMap::with_hasher(state.clone()),
            // #9901 (F-077): the error-budget side table is keyed by the
            // attacker-influenced matched key — seed it too.
            icmp_error_side_tats: HashMap::with_hasher(state),
            // #4915: monotonic session-id counter starts at 1 (0 = "unknown"
            // sentinel on the wire); the node/worker namespace defaults to 0
            // until `set_session_id_namespace` is called at worker setup.
            next_session_id: 1,
            session_id_worker_hi: 0,
            tombstone_log: Vec::new(),
            tombstone_drops: 0,
        }
    }

    fn next_epoch(&mut self) -> u64 {
        self.epoch_counter += 1;
        self.epoch_counter
    }
    /// #9856: current install-epoch counter value (no bump). Read at export
    /// command accept as the window's kick epoch: the cursor exports entries
    /// with `install_epoch <= kick_epoch`.
    pub(crate) fn current_epoch(&self) -> u64 {
        self.epoch_counter
    }

    /// #9901 (F-077): per-session embedded-ICMP-error gate. Returns true when
    /// an error for `key` MAY be delivered (its session budget had a token)
    /// and consumes one token; false when the session is over budget and the
    /// error MUST be suppressed (the suppression counter is bumped inside).
    ///
    /// Budget: burst 64 / rate 64/s in ONE u64 TAT — sized for mtr (30/s
    /// same-session probes all pass) and traceroute multi-quoter same-id
    /// sessions, NOT a 1s min-interval (which would break both), while
    /// bounding a forgery flood to ~64 deliveries per session. A local entry
    /// carries its TAT on `SessionEntry::last_icmp_error_tat`; a match with
    /// NO local entry (shared/peer) is budgeted in the bounded side table.
    /// The caller passes the key it already holds (`fwd.key`, a local, or
    /// `ResolvedSessionLookup.key.as_ref(query)`) — `SessionLookup` is never
    /// widened. Node-local scope: budgets are not HA-synced.
    pub(crate) fn note_icmp_error_delivered(&mut self, key: &SessionKey, now_ns: u64) -> bool {
        if let Some(handle) = self.key_to_handle.get(key).copied() {
            if let Some(record) = self.entries.get_mut(handle as usize) {
                // Reused-slab guard (the #7919 shape): a handle resolving to
                // a DIFFERENT key must not spend that session's budget — fall
                // through to the side table instead.
                if record.key == *key {
                    return icmp_error_tat_take(&mut record.entry.last_icmp_error_tat, now_ns);
                }
            }
        }
        if let Some(tat) = self.icmp_error_side_tats.get_mut(key) {
            return icmp_error_tat_take(tat, now_ns);
        }
        if self.icmp_error_side_tats.len() >= ICMP_ERROR_SIDE_TABLE_CAP {
            // At cap: first prune fully-recovered budgets (a TAT at or behind
            // `now` carries no outstanding debt — dropping it loses nothing).
            // O(cap) scan, cold path (shared/peer matches only), cap 1024.
            self.icmp_error_side_tats.retain(|_, tat| *tat > now_ns);
            if self.icmp_error_side_tats.len() >= ICMP_ERROR_SIDE_TABLE_CAP {
                // Still full: conservative refusal. Every resident budget holds
                // live debt, so the population exceeds the legitimate bound — the
                // error is suppressed (and counted), never admitted on a fresh
                // budget. Evict-and-admit here would let a 1025-key round-robin
                // exceed 64/s per session indefinitely (each evicted key
                // re-enters with full credit).
                EMBEDDED_ERROR_PER_SESSION_SUPPRESSED_TOTAL.fetch_add(1, AtomicOrdering::Relaxed);
                return false;
            }
        }
        let mut tat = 0u64;
        let admitted = icmp_error_tat_take(&mut tat, now_ns);
        self.icmp_error_side_tats.insert(key.clone(), tat);
        admitted
    }
    /// #10667: refund a per-session error token taken by
    /// `note_icmp_error_delivered` for an error that was then NOT delivered.
    /// The matcher charges BEFORE the poll arm knows the outcome (build,
    /// CoS, zone policy), so every post-match non-delivery terminal refunds:
    /// policy-refuse after `Queued` (both flowless arms), TTL-expire drop,
    /// and CoS drop. Without the refund, 64 policy-refused errors exhaust
    /// the 64-burst and a genuine permitted error is `BudgetDenied` —
    /// refused errors starve permitted ones.
    ///
    /// Mirrors the take's slot selection exactly (local entry with the
    /// #7919 reused-slab guard, else the side table); never inserts.
    /// `now_ns` is unused — the TAT inversion needs no clock — but kept so
    /// the take/refund call shapes stay symmetric at the call sites.
    pub(crate) fn refund_icmp_error_not_delivered(&mut self, key: &SessionKey, _now_ns: u64) {
        if let Some(handle) = self.key_to_handle.get(key).copied() {
            if let Some(record) = self.entries.get_mut(handle as usize) {
                if record.key == *key {
                    icmp_error_tat_refund(&mut record.entry.last_icmp_error_tat);
                    return;
                }
            }
        }
        if let Some(tat) = self.icmp_error_side_tats.get_mut(key) {
            icmp_error_tat_refund(tat);
        }
    }

    /// #4915 + #6311: namespace this table's session ids so the STABLE session
    /// id (`SessionEntry.session_id`) is unique across the CLUSTER. Called once
    /// at worker setup. The high 16 bits carry `node_bit << 15 | worker_id`,
    /// leaving the low 48 for the per-worker monotonic counter.
    ///
    /// **Why the node half exists (#6311).** Before it, the namespace was the
    /// worker id alone — and both HA nodes run the SAME worker set (queue
    /// indices 0..N) with per-worker counters that both start at 1. Under #5212
    /// a standby ADOPTS the primary's id verbatim on import, so an adopted
    /// `(w << 48) | c` collided with the importing node's OWN worker-`w` id
    /// `(w << 48) | c`. In active/active — a supported, tested mode
    /// (`test-active-active`) — low-counter collisions early after boot were
    /// essentially guaranteed. That also REGRESSED pre-#5212 same-node
    /// uniqueness: before adoption, every import got a fresh local id, so a
    /// node's own RT_FLOW stream was internally unique.
    ///
    /// The node bit fixes it structurally rather than by bookkeeping: an adopted
    /// id carries the ORIGINATING node's bit, which by construction differs from
    /// every id this node mints. That is also why `upsert_synced_with_origin`
    /// deliberately does NOT reconcile `next_session_id` against an adopted id —
    /// the two live in disjoint namespaces, so a later local alloc cannot
    /// re-hand-out an adopted id.
    ///
    /// `node_id` is the chassis-cluster node id (0 or 1 — `parseNodeIDFileContent`
    /// and the config compiler both bound it, and `IsSupportedClusterNodeID`
    /// pins the 2-node topology). It is narrowed with `& 1` rather than
    /// asserted: it arrives on the wire from the daemon, and a helper that
    /// aborts on a wire value is a worse failure than one that folds an
    /// impossible third node onto node 0. A standalone (non-cluster) node passes
    /// 0 and gets exactly the pre-#6311 layout.
    ///
    /// **RESERVED: namespace `0xFFFF` belongs to the Go control plane (#6198).**
    /// Both allocators write into the SAME BPF conntrack mirror field: this table
    /// stamps `session_id` for sessions the helper owns, and
    /// `nextUserspaceSyncedSessionID` (pkg/daemon/daemon_ha_userspace_convert.go)
    /// mints `0xFFFF << 48 | counter48` for a peer-synced session the daemon
    /// installs. `0xFFFF` is node-bit-1 plus worker `0x7FFF`, so the reservation
    /// survives the re-partition unchanged — and the assert now guards the
    /// COMBINED namespace, not just the worker half, which is what keeps it
    /// meaningful after the split.
    ///
    /// Both assertions are hard `assert!`s rather than `debug_assert!`s because
    /// `make test-rust` and the shipped helper both build `--release`, where a
    /// debug assertion is stripped and would guard nothing. This is a config-time
    /// invariant (called once per worker, with a queue index), so per
    /// `docs/engineering-style.md` a hard failure beats running with ids that
    /// silently alias the control plane's or the peer node's.
    pub fn set_session_id_namespace(&mut self, node_id: u8, worker_id: u32) {
        assert!(
            (worker_id as u64) <= SESSION_ID_MAX_WORKER,
            "worker id {worker_id} does not fit the {SESSION_ID_NODE_BIT_SHIFT}-bit \
             session-id worker field (#6311): it would carry into the node \
             discriminator and mint ids inside the PEER node's namespace"
        );
        let node_bit = ((node_id as u64) & 1) << SESSION_ID_NODE_BIT_SHIFT;
        let namespace = node_bit | (worker_id as u64 & SESSION_ID_MAX_WORKER);
        assert_ne!(
            namespace, CONTROL_PLANE_SESSION_ID_WORKER_HI,
            "node {node_id} worker {worker_id} maps onto the session-id namespace \
             reserved for the Go control plane (#6198): nextUserspaceSyncedSessionID \
             mints {CONTROL_PLANE_SESSION_ID_WORKER_HI:#x} << 48 | counter into the \
             same BPF conntrack mirror field"
        );
        self.session_id_worker_hi = namespace << 48;
    }

    /// #4915 + #6311: allocate the next STABLE session id for a freshly-installed
    /// entry. Node bit + worker id in the high 16 bits, per-worker monotonic
    /// counter (masked to 48 bits) in the low bits; the counter starts at 1 so the returned id is never
    /// 0 (0 is the "unknown/legacy" wire sentinel). The 48-bit counter space is
    /// ~281 trillion ids per worker — unreachable in a process lifetime — but the
    /// mask + the `== 0` guard keep the id well-formed even in the impossible
    /// wrap case rather than aliasing the worker bits or emitting the 0 sentinel.
    fn alloc_session_id(&mut self) -> u64 {
        let counter = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);
        let low = counter & 0x0000_FFFF_FFFF_FFFF;
        let low = if low == 0 { 1 } else { low };
        self.session_id_worker_hi | low
    }

    /// Update the configurable session timeouts.
    pub fn set_timeouts(&mut self, timeouts: SessionTimeouts) {
        self.timeouts = timeouts;
    }

    /// #7212: publish the config generation this worker is forwarding under.
    /// Called once per poll pass from `poll_binding_process_descriptor` with the
    /// SAME `ValidationState` the pass classifies packets against, so a verdict
    /// derived during the pass is stamped with the generation it was actually
    /// derived under.
    pub(crate) fn set_filter_revalidation_gen(&mut self, generation: u64) {
        self.filter_revalidation_gen = generation;
    }

    /// #7212: the generation installs stamp and the established-hit
    /// revalidation compares against.
    pub(crate) fn filter_revalidation_gen(&self) -> u64 {
        self.filter_revalidation_gen
    }

    /// #7212: resolve a WIRE tuple to the entry it names, and answer in ONE
    /// probe whether that entry still lacks a static input-filter verdict
    /// derived under the live generation on `logical_ingress_ifindex`.
    ///
    /// `Some(canonical key)` means "stale — re-derive, then stamp THIS key".
    /// `None` means either "already judged under this (generation, ingress)" or
    /// "this worker holds no entry for the tuple".
    ///
    /// **Why the two questions are one call.** The caller is on the
    /// established-hit path, which has already resolved this key once inside
    /// `lookup_with_origin`. Asking separately cost a second `key_to_handle`
    /// hash plus a third for the staleness probe, and a `SessionKey` clone,
    /// on EVERY packet of every session on an interface with an input filter —
    /// the entire population the feature serves — to answer a question that is
    /// "no" for all but one packet per session per generation. Folded, the
    /// common answer costs one hash and one comparison, and the clone happens
    /// only on the rare stale exit.
    ///
    /// **Why a wire tuple has to be resolved at all.**
    /// `ResolvedFlowSessionDecision::key` is `ResolvedSessionKey::QueryKey` on a
    /// local session-table hit — the tuple the packet carried — and a reverse
    /// entry reached through the NAT reverse-translated ALIAS index is stored
    /// under a DIFFERENT key than the one that found it. A primary-index-only
    /// probe reports such an entry fresh forever: never revalidated, never
    /// revoked, never re-stamped, and a teardown handed the wire tuple deletes
    /// nothing.
    ///
    /// Resolution mirrors `lookup_with_origin` exactly, including its
    /// stale-handle guard: a `key_to_handle` hit whose stored key does NOT match
    /// is a freed-and-reused slab slot and yields `None` rather than falling
    /// through to the alias index — where a live alias entry for the same tuple
    /// would resolve a DIFFERENT session, which the caller would then revoke.
    pub(crate) fn filter_revalidation_target(
        &self,
        key: &SessionKey,
        logical_ingress_ifindex: i32,
    ) -> FilterRevalidationTarget {
        let Some(record) = self.revalidation_record(key) else {
            return FilterRevalidationTarget::NoLocalEntry;
        };
        let live =
            FilterRevalidationStamp::live(self.filter_revalidation_gen, logical_ingress_ifindex);
        if record.entry.filter_revalidated == live {
            FilterRevalidationTarget::Fresh
        } else {
            FilterRevalidationTarget::Stale(record.key.clone())
        }
    }

    /// #7212/#8356: resolve the entry record a WIRE tuple names, for the
    /// revalidation probes. Extracted so the FILTER and POLICY stamps cannot
    /// drift on WHICH entry a tuple resolves to — that resolution took two bugs
    /// to get right (#7212's alias path, #8114 item 2's stale-handle guard) and
    /// a second copy of it is a second place for them to come back.
    ///
    /// Mirrors `lookup_with_origin` exactly: the primary key WITH its
    /// stale-handle guard (a `key_to_handle` hit whose stored key does NOT match
    /// is a freed-and-reused slab slot and must NOT fall through to the alias
    /// index, where a live alias entry for the same tuple would resolve a
    /// DIFFERENT session that the caller would then revoke), then the
    /// reverse-translated index.
    fn revalidation_record(&self, key: &SessionKey) -> Option<&SessionRecord> {
        match self.key_to_handle.get(key).copied() {
            Some(handle) => {
                let record = self.entries.get(handle as usize)?;
                if record.key != *key {
                    // #8114 item 2: a reused slab slot is `None`, not a hit. The
                    // caller can still DERIVE a verdict — that needs the flow and
                    // the interface, not the entry — it simply has no entry it
                    // may safely stamp or tear down. Reporting it as resolved
                    // would be the fail-open this guard exists for.
                    return None;
                }
                Some(record)
            }
            None => {
                let handle = self.resolve_reverse_translated_handle(key)?;
                self.entries.get(handle as usize)
            }
        }
    }

    /// #9519: the CANONICAL key a WIRE tuple resolves to, through the same
    /// resolution the revalidation probes use, or `None` when it names no live
    /// local entry. For a revocation decided outside the policy stamp — a
    /// foreign packet on the session's own admitting interface — which has no
    /// `PolicyRevalidationTarget::Stale(key)` to read the key from.
    pub(crate) fn revalidation_canonical_key(&self, key: &SessionKey) -> Option<SessionKey> {
        self.revalidation_record(key)
            .map(|record| record.key.clone())
    }

    /// #7212 test view: the CANONICAL key the probe resolves, or `None` when it
    /// does not resolve a stale entry. A view over
    /// [`SessionTable::filter_revalidation_target`], not a second
    /// implementation, so it cannot answer differently from production.
    #[cfg(test)]
    pub(crate) fn stale_filter_revalidation_key(
        &self,
        key: &SessionKey,
        logical_ingress_ifindex: i32,
    ) -> Option<SessionKey> {
        match self.filter_revalidation_target(key, logical_ingress_ifindex) {
            FilterRevalidationTarget::Stale(canonical) => Some(canonical),
            FilterRevalidationTarget::Fresh | FilterRevalidationTarget::NoLocalEntry => None,
        }
    }

    /// #7212: record that this direction's static input-filter verdict has been
    /// re-derived under the live generation on `logical_ingress_ifindex`.
    ///
    /// Takes the CANONICAL key — the one
    /// [`SessionTable::stale_filter_revalidation_key`] just handed back — so it
    /// is a primary-index write. Idempotent; a miss is a no-op (the session was
    /// torn down between the probe and here).
    pub(crate) fn mark_filter_revalidated(
        &mut self,
        key: &SessionKey,
        logical_ingress_ifindex: i32,
    ) {
        let stamp =
            FilterRevalidationStamp::live(self.filter_revalidation_gen, logical_ingress_ifindex);
        if let Some(handle) = self.key_to_handle.get(key).copied()
            && let Some(record) = self.entries.get_mut(handle as usize)
            && record.key == *key
        {
            record.entry.filter_revalidated = stamp;
        }
    }
    /// #10467: keep a route-transition hit stale until the pair teardown has
    /// completed. If teardown is refused or delayed, the surviving entry must
    /// not look freshly judged under the new generation while still carrying
    /// the old route decision.
    pub(crate) fn clear_filter_revalidation(&mut self, key: &SessionKey) {
        if let Some(handle) = self.key_to_handle.get(key).copied()
            && let Some(record) = self.entries.get_mut(handle as usize)
            && record.key == *key
        {
            record.entry.filter_revalidated = FilterRevalidationStamp::UNVALIDATED;
        }
    }

    /// #7212 test view: the boolean half of
    /// [`SessionTable::stale_filter_revalidation_key`]. A `.is_some()` over the
    /// SAME call, not a second implementation, so it cannot answer differently
    /// from what production asks.
    #[cfg(test)]
    pub(crate) fn filter_revalidation_stale(
        &self,
        key: &SessionKey,
        logical_ingress_ifindex: i32,
    ) -> bool {
        matches!(
            self.filter_revalidation_target(key, logical_ingress_ifindex),
            FilterRevalidationTarget::Stale(_)
        )
    }

    /// #8356: publish the live generation zone-policy verdicts are judged
    /// against. Called from the same place, and with the same value, as
    /// `set_filter_revalidation_gen`.
    pub(crate) fn set_policy_revalidation_gen(&mut self, generation: u64) {
        self.policy_revalidation_gen = generation;
    }

    #[cfg(test)]
    pub(crate) fn policy_revalidation_gen(&self) -> u64 {
        self.policy_revalidation_gen
    }

    /// #8356 test seam: age one entry without changing the live generation.
    ///
    /// The strict-SYN admission witness first hits the forward tuple to seed
    /// its cache entry.  Controls that exercise reverse-only stamping need
    /// that tuple stale again while keeping the harness generation fixed.
    #[cfg(test)]
    pub(crate) fn age_policy_revalidation_for_test(&mut self, key: &SessionKey) {
        if let Some(handle) = self.key_to_handle.get(key).copied()
            && let Some(record) = self.entries.get_mut(handle as usize)
            && record.key == *key
        {
            record.entry.policy_revalidated_gen = 0;
        }
    }

    /// #8356: resolve the entry this WIRE tuple names and report whether its
    /// zone-policy verdict is stale, in ONE probe.
    ///
    /// Resolution is delegated to `filter_revalidation_target`'s own resolver so
    /// the two features cannot drift on WHICH entry a tuple names — including
    /// the stale-handle guard and the NAT reverse-translated alias path, both of
    /// which took a bug to get right (#7212, #8114 item 2). Only the staleness
    /// COMPARISON differs, and it is made here against the generation-only
    /// stamp.
    ///
    /// #10507: production now answers through `policy_revalidation_gate`
    /// (freshness AND authority, one probe); this accessor is retained for
    /// test assertions of the generation-only stamp shape.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn policy_revalidation_target(&self, key: &SessionKey) -> PolicyRevalidationTarget {
        let Some(record) = self.revalidation_record(key) else {
            return PolicyRevalidationTarget::NoLocalEntry;
        };
        if record.entry.policy_revalidated_gen == self.policy_revalidation_gen {
            PolicyRevalidationTarget::Fresh
        } else {
            PolicyRevalidationTarget::Stale(record.key.clone())
        }
    }

    /// #10507: resolve the entry this WIRE tuple names and answer freshness
    /// AND authority against the packet-time posture, in ONE probe.
    ///
    /// `force_cold` is rule 3 (+ the rule-4 Fresh sub-case): a non-live stamp
    /// plus a would-forward packet is always stale, even generation-equal
    /// (the A1/A2 reset shape). A Fresh stamp plus a would-forward packet
    /// without a valid egress is likewise always stale, even `LiveEgress`:
    /// rule 4 is fail-closed, never a fast-path coast. (A stale no-egress
    /// packet already runs cold via the `Stale` arm; no force bit is needed.)
    /// `fail_closed_decline` fires on fenced authority: `Recorded` + intent
    /// (fresh or stale — recorded authorization exists to fence), Fresh
    /// non-live + intent (rule-3 forced, incl. A1/A2 reset), or ANY
    /// no-egress (rule 4 unconditional). Only a stale with-egress walk with
    /// no recorded authorization — stale `Live` or never-validated stale
    /// `Unvalidated` (#8618) — keeps `Decline` (#9513 survives; its
    /// no-route retention is `NonLocal`, not no-egress).
    /// `fail_closed_icmp` is §4.4 rule 3: recorded + now-local + type-armed
    /// revokes, as does the generation-equal `Unvalidated` stamp (the A1/A2
    /// reset case), and any no-egress packet even when live or stale. A
    /// never-validated stale WITH-EGRESS entry keeps the #8618 decline: it
    /// carries no derived Permit, so no recorded authorization exists to
    /// fence, and revoking it would reintroduce the manufactured-DENY harm
    /// #8618 accepted its residual to avoid.
    pub(crate) fn policy_revalidation_gate(
        &self,
        key: &SessionKey,
        current: PolicyGateCurrent,
    ) -> PolicyGateAnswer {
        let Some(record) = self.revalidation_record(key) else {
            return PolicyGateAnswer {
                target: PolicyRevalidationTarget::NoLocalEntry,
                kind: PolicyRevalidationKind::Unvalidated,
                force_cold: false,
                fail_closed_decline: false,
                fail_closed_icmp: false,
            };
        };
        let fresh = record.entry.policy_revalidated_gen == self.policy_revalidation_gen;
        let kind = record.entry.policy_revalidation_kind;
        let target = if fresh {
            PolicyRevalidationTarget::Fresh
        } else {
            PolicyRevalidationTarget::Stale(record.key.clone())
        };
        let non_live = !matches!(kind, PolicyRevalidationKind::LiveEgress);
        let intent = !matches!(current, PolicyGateCurrent::NonLocal);
        let no_egress = matches!(current, PolicyGateCurrent::LocalForwardingNoEgress);
        // Rule 4 is unconditional: any would-forward disposition without a
        // valid egress fails closed, regardless of freshness or kind. #9513's
        // lookup-failure retention lives on the `NonLocal` branch (NoRoute,
        // HAInactive, redirect with egress 0), never here. Recorded
        // authorization exists to fence whether fresh or stale; Unvalidated
        // fences only when fresh (A1/A2 reset — a prior verdict was
        // distrusted), never when never-validated stale (#8618).
        let fenced_provenance = matches!(kind, PolicyRevalidationKind::RecordedEgress)
            || (matches!(kind, PolicyRevalidationKind::Unvalidated) && fresh);
        PolicyGateAnswer {
            target,
            kind,
            force_cold: fresh && intent && (non_live || no_egress),
            fail_closed_decline: no_egress || (intent && fenced_provenance),
            fail_closed_icmp: no_egress || (intent && fenced_provenance),
        }
    }

    /// #10507: the receiver-local provenance paired with the zone policy
    /// stamp. The hit-row fast path answers freshness+authority through
    /// [`SessionTable::policy_revalidation_gate`] (one probe on the hit key);
    /// this single-probe accessor serves the reverse forward-companion check,
    /// which names a DIFFERENT key and therefore costs its own hash by
    /// necessity, not a double hash. A missing entry is conservatively
    /// unvalidated.
    pub(crate) fn policy_revalidation_kind(
        &self,
        key: &SessionKey,
    ) -> PolicyRevalidationKind {
        self.revalidation_record(key)
            .map(|record| record.entry.policy_revalidation_kind)
            .unwrap_or(PolicyRevalidationKind::Unvalidated)
    }
    /// #10635: does this entry carry fenced provenance — a recorded
    /// authorization (or reset-distrust) the #10507 companion fence may act
    /// on? Mirrors the gate's `fenced_provenance` rule
    /// (`policy_revalidation_gate`): `RecordedEgress`, or `Unvalidated`
    /// at the live generation (A1/A2 reset — a prior verdict was
    /// distrusted). Stale `Unvalidated` (never validated, #8618) carries
    /// no recorded authorization: fencing it would manufacture a DENY.
    /// A missing key is unfenced (the caller decides the no-companion arm).
    pub(crate) fn policy_revalidation_fenced(&self, key: &SessionKey) -> bool {
        let Some(record) = self.revalidation_record(key) else {
            return false;
        };
        matches!(
            record.entry.policy_revalidation_kind,
            PolicyRevalidationKind::RecordedEgress
        ) || (matches!(
            record.entry.policy_revalidation_kind,
            PolicyRevalidationKind::Unvalidated
        ) && record.entry.policy_revalidated_gen == self.policy_revalidation_gen)
    }

    /// #8356/#10507: record that this entry's zone-policy verdict has been
    /// re-derived under the live generation and retain how that verdict was
    /// derived. Takes the CANONICAL key; a miss is a no-op.
    pub(crate) fn mark_policy_revalidated(
        &mut self,
        key: &SessionKey,
        kind: PolicyRevalidationKind,
    ) {
        let live_gen = self.policy_revalidation_gen;
        if let Some(handle) = self.key_to_handle.get(key).copied()
            && let Some(record) = self.entries.get_mut(handle as usize)
            && record.key == *key
        {
            record.entry.policy_revalidated_gen = live_gen;
            record.entry.policy_revalidation_kind = kind;
        }
    }

    /// #3527: install the per-screened-zone half-open (`tcp_opening_ns`)
    /// timeout overrides (zone id → ns), driven from each zone's `syn-flood
    /// timeout`. Called at worker startup and on every runtime
    /// forwarding-snapshot rotation, right next to `set_timeouts`. A full
    /// replace (not a merge): a zone whose timeout was removed from the config
    /// drops out of the new map and reverts to the global default on the next
    /// install/refresh. Empty map = no per-zone override (global default for
    /// every zone), the pre-#3527 behavior.
    pub fn set_opening_overrides(&mut self, overrides: FxHashMap<u16, u64>) {
        self.opening_overrides = overrides;
    }

    /// #3527: resolve the half-open opening-window override for an ingress
    /// zone, or `None` to use the global `tcp_opening_ns`. The common case
    /// (no zone configures a syn-flood timeout) is an empty map and a single
    /// missed lookup.
    #[inline]
    fn opening_override_for(&self, ingress_zone: u16) -> Option<u64> {
        if self.opening_overrides.is_empty() {
            return None;
        }
        self.opening_overrides.get(&ingress_zone).copied()
    }

    /// #2134: drive the per-IP session-limit OFF-gate from the worker's
    /// applied screen-profile snapshot. `active` is "any zone configures
    /// `limit-session source-ip-based`/`destination-ip-based`" (mirrors
    /// `ScreenState::has_advanced_features`'s limit predicate). Called at
    /// startup and on every runtime forwarding-snapshot rotation, right
    /// next to `set_timeouts` / `ScreenState::update_profiles`.
    ///
    /// Clear-on-disable: when the gate transitions to false, both count
    /// maps are cleared. Removing `limit-session` at runtime stops the
    /// decrement paths, so without this the maps would freeze at stale,
    /// over-counted values and a later re-enable would resume from wrong
    /// values and spuriously block an under-limit IP. Mirrors the
    /// `ScreenState::update_profiles` retain discipline.
    ///
    /// #4377 back-count-on-enable: on the OFF->ON edge the maps are
    /// REBUILT from the live slab so they reflect EVERY session that will
    /// later fire the decrement. Not back-counting is NOT benign for the
    /// decrement side: the sole removal sink (`remove_entry`) decrements
    /// for any forward non-seed entry whenever the gate is active at
    /// removal, with no per-entry record of whether the entry was ever
    /// counted. A forward session installed while the gate was OFF (or
    /// after a disable cleared the maps) is therefore uncounted, yet its
    /// teardown while ON still decrements — an increment-less decrement
    /// that drives `count[X]` BELOW the live counted-session count for X.
    /// `saturating_sub` + evict-at-0 hide the underflow, so X's count can
    /// reach 0 while sessions are live and X is handed a fresh full
    /// allotment (cap bypass). Rebuilding on enable makes every decrement
    /// balance an increment. The walk uses the same shared counted-class
    /// predicate as the install/decrement sinks (`!is_reverse &&
    /// install::session_limit_origin_counted(origin)`): true peer-SYNCED
    /// sessions are counted, while WorkerLocalImport replicas are excluded
    /// and only the two transient-local seeds remain uncounted. O(N) once per
    /// rare enable, no per-entry memory cost.
    pub fn set_session_limit_active(&mut self, active: bool) {
        if !active {
            self.session_limit_src_counts.clear();
            self.session_limit_dst_counts.clear();
        } else if !self.session_limit_active {
            // #4377: OFF->ON edge — rebuild the count maps from every live
            // counted-class session so decrements always balance an
            // increment. Walk via `key_to_handle` (the authoritative
            // primary index, matching `iter_with_origin`) so an orphan
            // slab record without a forward-key mapping is skipped.
            // Disjoint-field borrows (`key_to_handle` / `entries` read,
            // count maps mutated) — inline the increment rather than call
            // `session_limit_inc`, which would take `&mut self` whole.
            for (key, handle) in &self.key_to_handle {
                if let Some(record) = self.entries.get(*handle as usize) {
                    if !record.entry.metadata.is_reverse
                        && install::session_limit_origin_counted(record.entry.origin)
                    {
                        let c = self.session_limit_src_counts.entry(key.src_ip).or_insert(0);
                        *c = c.saturating_add(1);
                        let c = self.session_limit_dst_counts.entry(key.dst_ip).or_insert(0);
                        *c = c.saturating_add(1);
                    }
                }
            }
        }
        self.session_limit_active = active;
    }

    /// #2134: non-mutating read of the live local-session count for a
    /// source IP. Used by the new-flow check before a session is created
    /// so the (limit+1)-th new flow from an over-limit IP is dropped.
    /// Read-only by construction — an absent IP reads 0 and never inserts
    /// a phantom entry (#2128).
    #[inline]
    pub fn session_limit_src_count(&self, ip: IpAddr) -> u32 {
        self.session_limit_src_counts.get(&ip).copied().unwrap_or(0)
    }

    /// #2134: non-mutating read of the live local-session count for a
    /// destination IP. Mirror of [`session_limit_src_count`].
    #[inline]
    pub fn session_limit_dst_count(&self, ip: IpAddr) -> u32 {
        self.session_limit_dst_counts.get(&ip).copied().unwrap_or(0)
    }

    /// #2134/#3122/#10310: increment the per-IP counts for a freshly-counted
    /// session. Caller MUST have already evaluated the shared counted-class
    /// predicate (`!is_reverse &&
    /// install::session_limit_origin_counted(origin)`) — this helper only
    /// adds the OFF-gate guard so an unconfigured deployment pays one branch.
    /// `saturating_add` never wraps (#1357 / overflow policy); the count
    /// is bounded by `max_sessions`.
    #[inline]
    fn session_limit_inc(&mut self, src_ip: IpAddr, dst_ip: IpAddr) {
        if !self.session_limit_active {
            return;
        }
        let c = self.session_limit_src_counts.entry(src_ip).or_insert(0);
        *c = c.saturating_add(1);
        let c = self.session_limit_dst_counts.entry(dst_ip).or_insert(0);
        *c = c.saturating_add(1);
    }

    /// #2134: decrement the per-IP counts for a removed counted session
    /// and evict the map entry the moment its count reaches 0 (#2128 —
    /// keeps the maps bounded by live counted sessions). Caller MUST have
    /// evaluated the counted-class predicate; this helper only adds the
    /// OFF-gate guard. `saturating_sub` never underflows.
    #[inline]
    fn session_limit_dec(&mut self, src_ip: IpAddr, dst_ip: IpAddr) {
        if !self.session_limit_active {
            return;
        }
        if let Some(c) = self.session_limit_src_counts.get_mut(&src_ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.session_limit_src_counts.remove(&src_ip);
            }
        }
        if let Some(c) = self.session_limit_dst_counts.get_mut(&dst_ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.session_limit_dst_counts.remove(&dst_ip);
            }
        }
    }

    /// #2134 test helper: live source-IP count-map entry count. Pins the
    /// #2128 evict-on-zero invariant (the map stays bounded; no phantom
    /// zero entries survive).
    #[cfg(test)]
    pub(crate) fn session_limit_src_map_len(&self) -> usize {
        self.session_limit_src_counts.len()
    }

    /// #2134 test helper: live destination-IP count-map entry count.
    #[cfg(test)]
    pub(crate) fn session_limit_dst_map_len(&self) -> usize {
        self.session_limit_dst_counts.len()
    }

    pub fn len(&self) -> usize {
        // Use key_to_handle (the authoritative primary index) so the
        // count reflects "installed sessions" even if the slab ever
        // held an orphan record from a partial cleanup path.
        self.key_to_handle.len()
    }

    pub fn max_sessions(&self) -> usize {
        self.max_sessions
    }

    /// #6297 test helper: the monotonic backing-slab capacity. The budgeted
    /// refresh walk deliberately does NOT bound to this after a drain — it
    /// bounds to `slot_high_watermark` instead. Used by the fail-on-revert
    /// test to assert the walk visits < `capacity()` slots.
    #[cfg(test)]
    pub(crate) fn entries_capacity_for_test(&self) -> usize {
        self.entries.capacity()
    }

    /// #6297 test helper: the live-extent high-watermark the budgeted refresh
    /// walk bounds to (`1 + the highest slot index ever handed out`).
    #[cfg(test)]
    pub(crate) fn slot_high_watermark_for_test(&self) -> usize {
        self.slot_high_watermark
    }

    /// #1760: cumulative NAT reverse-key displacement events on
    /// `nat_reverse_index` (see the field doc). Published per-worker on
    /// the ~1 Hz runtime cadence and aggregated into
    /// `ProcessStatus.nat_reverse_key_collisions` for operators.
    pub fn nat_reverse_key_collisions(&self) -> u64 {
        self.nat_reverse_key_collisions
    }

    /// #6751: the DIFFERENT-SOURCE subset of `nat_reverse_key_collisions`.
    /// Published on the same per-worker cadence and aggregated into
    /// `ProcessStatus.nat_reverse_key_collisions_distinct_src`.
    pub fn nat_reverse_key_collisions_distinct_src(&self) -> u64 {
        self.nat_reverse_key_collisions_distinct_src
    }

    // ── #964 Step 1 internal helpers ─────────────────────────────
    //
    // Centralize key→handle and handle→record resolution so the rest
    // of the impl uses these short forms instead of repeating
    // `self.key_to_handle.get(key).and_then(|h| self.entries.get(*h as usize))`
    // throughout 30+ call sites.

    /// #10890: identifies locally-owned, handshake-incomplete TCP forward
    /// entries eligible for pressure shedding. Peer imports, transient
    /// seeds, fabric-ingress rows and reverse companions are not candidates.
    #[inline]
    fn is_pressure_shed_opening(
        key: &SessionKey,
        entry: &SessionEntry,
        expect_reverse: bool,
    ) -> bool {
        key.protocol == PROTO_TCP
            && entry.metadata.is_reverse == expect_reverse
            && !entry.metadata.fabric_ingress
            && (!entry.established || entry.handshake_pending)
            && !entry.origin.is_peer_synced()
            && !entry.origin.is_transient_local_seed()
            && !entry.origin.is_local_tun_origin()
    }

    /// #6297: insert a record into the session slab and advance the
    /// live-extent high-watermark. This is the SOLE slab-insert choke
    /// point so the `slot_high_watermark` invariant holds for every insert
    /// path (fresh install, synced import, and the test-only
    /// `restore_entry`). The slab hands back the slot index it used —
    /// reusing a vacant slot from its free list when one exists, extending
    /// the backing Vec otherwise — so `raw + 1` is the extent this record
    /// occupies. Bumping the watermark to at least that guarantees
    /// `slot_high_watermark >= 1 + every occupied slot index`, which the
    /// budgeted refresh walk relies on to never skip a live session.
    ///
    /// #10890: register eligible forward opening records here so every
    /// insert path maintains the pressure-shed candidate index.
    #[inline]
    fn insert_record(&mut self, record: SessionRecord) -> usize {
        let opening_key =
            Self::is_pressure_shed_opening(&record.key, &record.entry, false)
                .then(|| record.key.clone());
        let raw = self.entries.insert(record);
        if let Some(key) = opening_key {
            self.pressure_shed_openings.insert(key, ());
        }
        // Only grows, never shrinks — see the `slot_high_watermark` field
        // doc for why a stale-low watermark would be a correctness bug but
        // a slightly-high one is merely a few wasted vacant visits.
        if raw + 1 > self.slot_high_watermark {
            self.slot_high_watermark = raw + 1;
        }
        raw
    }

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
        // #7919: count the miss HERE rather than at the call sites. The two
        // callers (`touch_if_stale`, `account_packet`) are textually
        // near-identical to other lookups in the same file, and instrumenting
        // the wrong one of such a pair is a mistake this campaign has already
        // made once. Counting inside the resolver cannot pick the wrong site.
        let Some(handle) = self.handle_for_key(key) else {
            self.lookup_miss_no_handle
                .fetch_add(1, AtomicOrdering::Relaxed);
            return None;
        };
        let Some(record) = self.entries.get(handle as usize) else {
            self.lookup_miss_stale_handle
                .fetch_add(1, AtomicOrdering::Relaxed);
            return None;
        };
        if record.key != *key {
            self.lookup_miss_key_mismatch
                .fetch_add(1, AtomicOrdering::Relaxed);
            return None;
        }
        Some(record)
    }

    /// Mut version of `record_by_key`. Same key-equality validation.
    #[inline]
    fn record_by_key_mut(&mut self, key: &SessionKey) -> Option<&mut SessionRecord> {
        // #7919: same three causes as the shared-ref twin above, incrementing
        // the SAME three counters.
        //
        // CORRECTION: an earlier version of this comment said the split was
        // per-function — that `account_packet` resolving through here and
        // `touch_if_stale` resolving through the twin made a
        // frozen-counters-but-live-idle-timer split visible. It does not.
        // There are three counters, split by CAUSE, and both functions add to
        // all three; nothing here records WHICH resolver missed. That sentence
        // described instrumentation that was never built, and it read as a
        // statement of fact, so it was relayed into a work assignment as an
        // available discriminator. It is not one.
        //
        // The counting is in both functions so that no miss goes UNCOUNTED,
        // which is a weaker and true claim. If the per-function split is ever
        // actually wanted, it needs new fields — do not infer it from these.
        let Some(handle) = self.handle_for_key(key) else {
            self.lookup_miss_no_handle
                .fetch_add(1, AtomicOrdering::Relaxed);
            return None;
        };
        let Some(record) = self.entries.get_mut(handle as usize) else {
            self.lookup_miss_stale_handle
                .fetch_add(1, AtomicOrdering::Relaxed);
            return None;
        };
        if record.key != *key {
            self.lookup_miss_key_mismatch
                .fetch_add(1, AtomicOrdering::Relaxed);
            return None;
        }
        Some(record)
    }

    /// #7919 TEST SEAM: point `key` at `handle` in the key index, bypassing
    /// install.
    ///
    /// The stale-handle and key-mismatch causes are INTERNAL INCONSISTENCIES —
    /// the index disagreeing with the slab — and are unreachable through the
    /// public API by construction. That is exactly why they are worth counting
    /// (either one means a real bug), and exactly why a cell cannot reach them
    /// without a seam.
    ///
    /// Without this, a test can only exercise the no-handle cause, and a
    /// mutation collapsing the three counters into one ESCAPES — measured. A
    /// test named "separates the three causes" that exercises one is a false
    /// claim in its own name.
    #[cfg(test)]
    pub(crate) fn debug_force_handle(&mut self, key: &SessionKey, handle: u32) {
        self.key_to_handle.insert(key.clone(), handle);
    }

    /// #7919 TEST SEAM: the handle currently indexed for `key`.
    #[cfg(test)]
    pub(crate) fn debug_handle_for_key(&self, key: &SessionKey) -> Option<u32> {
        self.handle_for_key(key)
    }

    /// #7919: cumulative by-key lookup misses on this worker's table, split by
    /// cause: (no handle, stale handle, key mismatch).
    pub(crate) fn lookup_miss_counts(&self) -> (u64, u64, u64) {
        (
            self.lookup_miss_no_handle.load(AtomicOrdering::Relaxed),
            self.lookup_miss_stale_handle.load(AtomicOrdering::Relaxed),
            self.lookup_miss_key_mismatch.load(AtomicOrdering::Relaxed),
        )
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

    /// #5213: the STABLE session id (`SessionEntry.session_id`, #4915) for the
    /// live entry keyed by `key`, or `0` when no live entry exists. Used by the
    /// conntrack-mirror publish (`show security flow session`) so its id matches
    /// the one RT_FLOW emits for the same session; `0` keeps the legacy ordinal
    /// fallback on the Go render side. Mirrors the same `entry_by_key(...).
    /// session_id` read the Open/Close delta harvest already performs.
    #[inline]
    pub(crate) fn session_id_for(&self, key: &SessionKey) -> u64 {
        self.entry_by_key(key).map(|e| e.session_id).unwrap_or(0)
    }
    /// Return the live session identity for any incarnation of the same
    /// canonical bare tuple, ignoring routing-domain and tunnel discriminator.
    /// Used by delayed close drains to reject an old scoped close after a
    /// collision survivor has been installed.
    #[inline]
    pub(crate) fn session_id_for_bare_tuple(&self, key: &SessionKey) -> u64 {
        let mut canonical = key.clone();
        canonical.routing_domain = 0;
        canonical.discriminator = Default::default();
        self.entries
            .iter()
            .find_map(|record| {
                let mut candidate = record.1.key.clone();
                candidate.routing_domain = 0;
                candidate.discriminator = Default::default();
                (candidate == canonical).then_some(record.1.entry.session_id)
            })
            .unwrap_or(0)
    }

    /// Return whether any live incarnation occupies the canonical bare tuple,
    /// including rows whose legacy session id is zero.
    pub(crate) fn contains_bare_tuple(&self, key: &SessionKey) -> bool {
        let mut canonical = key.clone();
        canonical.routing_domain = 0;
        canonical.discriminator = Default::default();
        self.entries.iter().any(|(_, record)| {
            let mut candidate = record.key.clone();
            candidate.routing_domain = 0;
            candidate.discriminator = Default::default();
            candidate == canonical
        })
    }
    /// #9582: true when `session_id` was minted by ANOTHER worker and carried here.
    ///
    /// `alloc_session_id` puts this table's namespace, `(node_bit << 15 | worker_id)
    /// << 48`, in the high 16 bits of every id it mints. So a non-zero id whose high
    /// bits differ was adopted from the publisher (for a local session's replica,
    /// the installer). An id minted here, or 0, is not carried.
    pub(in crate::session) fn session_id_carried_from_another_worker(
        &self,
        session_id: u64,
    ) -> bool {
        const NAMESPACE_MASK: u64 = 0xFFFF_u64 << 48;
        session_id != 0 && (session_id & NAMESPACE_MASK) != self.session_id_worker_hi
    }

    /// #9412: the live entry's close class on the HA wire (`0` if open or
    /// absent), for the Open deltas that re-announce an existing session.
    pub(crate) fn close_class_wire_for(&self, key: &SessionKey) -> u8 {
        self.entry_by_key(key)
            .map(|e| e.tcp_close_class_wire())
            .unwrap_or(0)
    }

    /// #8125: the session's OWN inactivity window, in whole seconds, for the
    /// `Timeout:` column of `show security flow session`.
    ///
    /// That column read a hardcoded `1800` for every session regardless of the
    /// window actually in force — the Junos default for `established-timeout`,
    /// stamped by the conntrack publisher and never corrected. It was wrong in
    /// both directions at once: 1800 for an ESTABLISHED session whose real
    /// window is 300 s unless configured, and 1800 for a half-closed session on
    /// a 30 s (or a configured 3 s) closing window. The reap behaviour proved
    /// the windows differed by an order of magnitude while the column read the
    /// same number for both.
    ///
    /// `expires_after_ns` is the per-entry window the expiry wheel itself uses,
    /// so this reports what actually governs the session rather than a
    /// re-derivation that could disagree with it. After #7342 that is one of
    /// established / initial / closing / time-wait / the RST abort window,
    /// selected on the entry as its state moves.
    ///
    /// Returns 0 for an absent key. The publisher treats 0 as "no live entry"
    /// and leaves the previous value rather than stamping a zero window, which
    /// would render as an immediate expiry the session is not on.
    pub(crate) fn timeout_secs_for(&self, key: &SessionKey) -> u32 {
        self.entry_by_key(key)
            .map(|e| (e.expires_after_ns / 1_000_000_000) as u32)
            .unwrap_or(0)
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

    /// Return whether a local backing session exists and is within its
    /// protocol-specific idle deadline. This probe is read-only so callers
    /// can reject stale flow-cache hits before any packet side effects.
    #[inline]
    pub fn session_is_live_at(&self, key: &SessionKey, now_ns: u64) -> bool {
        self.record_by_key(key).is_some_and(|record| {
            now_ns.saturating_sub(record.entry.last_seen_ns) <= record.entry.expires_after_ns
        })
    }

    /// #2220: per-session keepalive throttle for the flow-cache fast
    /// path. Refreshes the matched session's `last_seen_ns` ONLY when it
    /// has gone idle for at least `expires_after_ns / SESSION_KEEPALIVE_DIVISOR`
    /// — i.e. it is a quarter of the way to its OWN expiry. An
    /// actively-forwarding cached flow is thus re-stamped whenever its
    /// idle time crosses `expires_after_ns / N`, keeping its age ~`T/N`
    /// in steady state regardless of co-resident flow rates, so it can
    /// never be GC'd mid-flow (reaped only if a real gap exceeds `T`).
    /// #10885: closing TCP entries still serve cache hits inside their
    /// deadline, but only a non-FINed, non-reset direction may move it. A
    /// FIN-owning side and either side of RST/TIME_WAIT keep the close timer
    /// fixed, allowing the closing entry to expire despite matching traffic.
    ///
    /// Why this replaces the prior binding-global modulo-64 counter: that
    /// counter incremented across ALL flows on the binding and touched
    /// only the flow that happened to land on a global multiple of 64.
    /// A low-rate flow co-resident with a saturating flow could be served
    /// entirely from the cache for the whole timeout window without its
    /// session ever being touched, then be reaped while still forwarding
    /// (HA Close delta to the peer + BPF redirect-key deletion + a stale
    /// flow-cache descriptor out-living its session). See issue #2220.
    ///
    /// HOT PATH: a single `key_to_handle` hash probe (the same probe
    /// `touch` performs) plus a Copy field read; the `last_seen_ns` write
    /// and the throttled `push_to_wheel` run only when actually stale, so
    /// the steady-state per-cache-hit cost is one lookup and an integer
    /// compare. Allocation-free.
    #[inline]
    pub fn touch_if_stale(&mut self, key: &SessionKey, now_ns: u64) -> bool {
        let (stale, refresh_allowed) = match self.record_by_key(key) {
            Some(record) => {
                let entry = &record.entry;
                let age = now_ns.saturating_sub(entry.last_seen_ns);
                // Keep the flow-cache keepalive from resurrecting a session
                // after the same strict deadline enforced by packet lookup
                // and the expiry wheel. The wheel still owns physical
                // removal, including HA HOLD/SELF-HEAL retention.
                if age > entry.expires_after_ns {
                    return false;
                }
                let refresh_after = entry.expires_after_ns.max(SESSION_KEEPALIVE_DIVISOR)
                    / SESSION_KEEPALIVE_DIVISOR;
                (
                    age >= refresh_after,
                    !entry.closing || (!entry.reset && !entry.fin_own),
                )
            }
            None => return false,
        };
        if stale && refresh_allowed {
            self.touch(key, now_ns);
        }
        true
    }

    /// #2501: account a single forwarded packet (of on-wire length `len`,
    /// `UserspaceDpMeta.pkt_len`) against the session whose THIS-PACKET key is
    /// `key`. The direction is derived from the resolved entry — the caller
    /// does NOT supply it, because the only per-packet direction signal the
    /// hot path otherwise has (the flow-cache `metadata.is_reverse`) is
    /// always `false` (every cache entry is built from a forward-build
    /// decision), so trusting it would book all reverse traffic as forward.
    ///
    /// Both directions' counters are folded onto the SINGLE canonical FORWARD
    /// entry so the BPF-conntrack mirror (`refresh_bpf_conntrack_last_seen`,
    /// which walks only forward entries) and the SESSION_CLOSE harvest
    /// (forward-entry only) see the complete fwd+rev volume with no
    /// cross-entry combine and no dependence on the two entries' independent
    /// expiry ordering:
    ///   - a forward packet keys directly to the forward entry
    ///     (`is_reverse == false`) → bump its `fwd`;
    ///   - a reverse packet keys to the REVERSE entry
    ///     (`is_reverse == true`); `reverse_session_key(rev.key, nat)`
    ///     recovers the forward entry's wire tuple → bump that forward
    ///     entry's `rev`.
    ///
    /// HOT PATH: the dominant (forward) direction is a SINGLE `key_to_handle`
    /// hash probe (`entry_by_key_mut` resolves the record once; the direction
    /// is read and the `fwd` counters mutated under that same `&mut` borrow)
    /// plus one `saturating_add`. The reverse direction copies the bits
    /// needed to recover the forward tuple out of that first borrow, then pays
    /// one extra probe to hop reverse-entry → forward-entry. Worker-owned
    /// `&mut self`: plain stores, no atomic, no allocation, no cross-core
    /// traffic. A miss (session reaped between resolution and accounting) is a
    /// no-op — the same fail-open posture as `touch`.
    ///
    /// #2749: `tcp_flags` (the packet's TCP control-flag byte, 0 for non-TCP)
    /// and `dscp` (the packet's 6-bit DSCP) are observed alongside the volume
    /// so the SESSION_CLOSE RT_FLOW frame can carry real NetFlow/IPFIX
    /// class-of-service and TCP-flags values. The flags are OR-accumulated in
    /// BOTH directions (the cumulative `tcpControlBits` a collector expects);
    /// the ToS byte (`dscp << 2`) is stamped only from the FORWARD direction
    /// (the initiator's class of service). Both fold onto the canonical
    /// FORWARD entry, exactly like the reverse counters, so a single close
    /// harvest sees the whole flow.
    #[inline]
    pub fn account_packet(&mut self, key: &SessionKey, len: u64, tcp_flags: u8, dscp: u8) {
        // Single resolve. For the dominant FORWARD case this is the only
        // session probe `account_packet` does — read the direction and mutate
        // the `fwd` counters under this one `&mut record` borrow. For the
        // REVERSE case, snapshot the (Copy) bits needed to recover the forward
        // tuple and fall out of this borrow before the second resolve.
        let (record_key, nat) = match self.record_by_key_mut(key) {
            Some(record) => {
                if !record.entry.metadata.is_reverse {
                    // Forward packet → forward entry. Bump `fwd` in place and
                    // stamp the forward-direction ToS + OR the TCP flags.
                    record.entry.counters.account(false, len);
                    record.entry.observed_tos = dscp << 2;
                    record.entry.observed_tcp_flags |= tcp_flags;
                    return;
                }
                (record.key.clone(), record.entry.decision.nat)
            }
            None => return,
        };
        // Reverse packet → reverse entry. Fold onto the forward entry's `rev`.
        // The reverse direction does NOT overwrite the forward ToS (it carries
        // the responder's class of service), but its TCP flags ARE OR-folded
        // so the cumulative tcpControlBits reflects both half-flows.
        let fwd_key = reverse_session_key(&record_key, nat);
        if let Some(entry) = self.entry_by_key_mut(&fwd_key) {
            entry.counters.account(true, len);
            entry.observed_tcp_flags |= tcp_flags;
        } else if let Some(entry) = self.entry_by_key_mut(key) {
            // Forward entry already gone (independent expiry) — fall back to
            // the reverse entry so the count is not silently dropped.
            entry.counters.account(true, len);
            entry.observed_tcp_flags |= tcp_flags;
        }
    }

    /// #4109: mirror a TCP close (F17) or handshake promotion (F16) onto the
    /// matched entry's forward↔reverse companion so both halves of a flow stay
    /// in sync. Forward and reverse are two independent `SessionEntry`s in this
    /// same worker-owned table; the read path only ever mutates the ONE entry a
    /// packet's wire tuple resolves, so without this a unidirectional FIN/RST
    /// leaves the other half pinned on the full established idle window (F17),
    /// and a bare-SYN half-open flow could be pushed to ESTABLISHED by a
    /// client-only ACK with no server reply (F16).
    ///
    /// The companion key is recovered exactly as `account_packet` hops
    /// reverse→forward: `reverse_session_key` on the matched entry's OWN
    /// canonical key + its own `nat` yields the other half's key (the transform
    /// is its own inverse given the reversed decision, so it works from either
    /// direction). `matched_key` MUST be the entry's canonical `record.key`, not
    /// an alias/translated lookup key.
    ///
    /// A missing companion (e.g. a `FabricRedirect` flow with no local reverse
    /// entry, or a half already independently reaped) is a no-op — the same
    /// fail-open posture as `account_packet`'s reverse hop.
    /// #7342: takes the `TcpStatePropagation` the read path already builds,
    /// rather than its fields spread over five positional `bool`s. Adding the
    /// FIN signal would have made that eight arguments, four of them same-typed
    /// and adjacent — the repeated-parameter-cluster shape this repo's API rule
    /// says to fold into a context struct, and one where a transposition
    /// between `close`, `reset` and `fin` would be silent.
    /// #9412: push a close-state `Update` for the session `matched_key` belongs
    /// to, iff its close class changed from `class_before` (wire form).
    ///
    /// Keyed on the FORWARD entry, which is what every sync delta names. A FIN
    /// seen on the reverse half resolves its forward companion the way
    /// `propagate_tcp_state_to_companion` does.
    ///
    /// A peer-synced copy never announces: that would echo the owner's own
    /// state back to it, the same sync loop the install-time Open avoids.
    ///
    /// Volume, against #8593: at most one delta per class TRANSITION, and a
    /// retransmitted FIN in the same class emits nothing. A session can
    /// therefore emit at most three over its life (CLOSING, TIME_WAIT, RST).
    pub(in crate::session) fn emit_close_state_update(
        &mut self,
        matched_key: &SessionKey,
        class_before: u8,
    ) {
        let Some(matched) = self.entry_by_key(matched_key) else {
            return;
        };
        let class_after = matched.tcp_close_class_wire();
        if class_after == class_before {
            return;
        }
        let forward_key = if matched.metadata.is_reverse {
            reverse_session_key(matched_key, matched.decision.nat)
        } else {
            matched_key.clone()
        };
        let Some(forward) = self.entry_by_key(&forward_key) else {
            return;
        };
        if forward.metadata.is_reverse {
            return;
        }
        // #9582: a worker REPLICA of a session this node owns (`WorkerLocalImport`)
        // announces too, because a close it alone sees (the server's FIN or RST on
        // another RSS queue) reaches no other worker. It announces only with the
        // installer's CARRIED id: announcing with an id this worker minted would hand
        // the #9412 sender memo a foreign id, which drops the installer's record and
        // lets the next sweep resend class 0. Peer imports stay silent.
        // #10038 item 5: TUN-origin stays silent too (the peer holds no copy
        // — nothing Opened — so an Update would plant TUN-derived state).
        if forward.origin.is_local_tun_origin()
            || (forward.origin.is_peer_synced()
                && !(forward.origin == SessionOrigin::WorkerLocalImport
                    && self.session_id_carried_from_another_worker(forward.session_id)))
        {
            return;
        }
        // The metadata clone bumps the bound policy-counter Arc (#5445). That is
        // acceptable here only because this runs on a class transition, never
        // on the per-packet path.
        let delta = SessionDelta {
            provenance: crate::session::ExportProvenance::Incremental,
            kind: SessionDeltaKind::Update,
            key: forward_key.clone(),
            decision: forward.decision,
            metadata: forward.metadata.clone(),
            origin: forward.origin,
            fabric_redirect_sync: false,
            created_ns: forward.created_ns,
            last_seen_ns: forward.last_seen_ns,
            counters: SessionCounters::default(),
            observed_tos: forward.observed_tos,
            observed_tcp_flags: forward.observed_tcp_flags,
            session_id: forward.session_id,
            bulk_resync: false,
            tcp_close_class: class_after,
            purge_retirement: false,
        };
        self.push_delta(delta);
    }

    pub(in crate::session) fn propagate_tcp_state_to_companion(
        &mut self,
        matched_key: &SessionKey,
        now_ns: u64,
        propagate: TcpStatePropagation,
    ) {
        let TcpStatePropagation {
            nat: matched_nat,
            close,
            reset,
            fin,
            established,
            handshake_completed,
        } = propagate;
        let companion_key = reverse_session_key(matched_key, matched_nat);
        // Copy the windows out before the `&mut self.entries` borrow below:
        // `SessionTimeouts` is `Copy`, so this is a register move, not a clone.
        let timeouts = self.timeouts;
        let mut rebucket = false;
        if let Some(entry) = self.entry_by_key_mut(&companion_key) {
            if established && matches!(companion_key.protocol, PROTO_TCP) {
                // A reverse SYN-ACK after SYN-first install, or a reverse ACK
                // after SYN-ACK-first install, promotes the TCP half and its
                // companion. A completing ACK clears the pending gap below.
                //
                // #6752: keep both halves in the opening class until the
                // handshake completes, so a client that never ACKs the SYN-ACK
                // cannot hold the pair on the full established window.
                entry.established = true;
                entry.handshake_pending = true;
            } else if established {
                // #10889: the reverse datagram is real activity for the whole
                // bidirectional session. Start both halves' application idle
                // clocks together and schedule the forward half on its new
                // window.
                entry.established = true;
                entry.last_seen_ns = now_ns;
                entry.expires_after_ns = session_timeout_ns(
                    companion_key.protocol,
                    0,
                    true,
                    &timeouts,
                    entry.metadata.inactivity_timeout_ns,
                    None,
                );
                rebucket = true;
            }
            if handshake_completed {
                // #6752/#10891: the completing segment clears the matched half's
                // gap; clear the companion too so the established half can
                // retain its full idle window.
                entry.handshake_pending = false;
                entry.syn_ack_first = false;
            }
            if close {
                // F17: a FIN/RST on one half kills the whole flow. Stamp the
                // same close/reset state on the companion and pull it onto the
                // short close window (#3046 2s RST / #3489 30s FIN) so the dead
                // half reaps with its sibling instead of lingering the full 300s
                // established window. `reset` is sticky exactly like the matched
                // entry (a graceful FIN cannot clear an already-observed RST).
                entry.closing = true;
                entry.reset |= reset;
                // #7342: the matched half's FIN is the COMPANION's peer-side
                // FIN. Once both halves have seen a FIN in each direction the
                // close handshake is complete and both reap on TIME_WAIT rather
                // than CLOSING. Mirrored rather than derived: an entry cannot
                // see the other direction's segments, and `observed_tcp_flags`
                // cannot stand in for this — it is OR-folded across both
                // directions on purpose (#2749), so it is already true after
                // ONE fin.
                entry.fin_peer |= fin;
                entry.last_seen_ns = now_ns;
                entry.expires_after_ns = tcp_close_window_ns(entry.tcp_close_class(), &timeouts);
                rebucket = true;
            }
        }
        if handshake_completed {
            // Completion can be observed from either direction (including the
            // reverse-half ACK path), so retire both possible key orientations.
            self.pressure_shed_openings.remove(matched_key);
            self.pressure_shed_openings.remove(&companion_key);
        }
        if rebucket {
            // The companion's lifetime changed; re-bucket it so GC checks the
            // new deadline instead of its install-time or prior deadline.
            self.push_to_wheel(&companion_key, now_ns);
        }
    }

    /// #2501: read the four per-direction traffic counters for the session
    /// keyed by `key`, or `None` if no live entry exists. Cold path
    /// (BPF-conntrack-map refresh on the ~1s GC cadence); a single lookup +
    /// a `Copy` of the four-`u64` snapshot.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn session_counters(&self, key: &SessionKey) -> Option<SessionCounters> {
        self.entry_by_key(key).map(|e| e.counters)
    }

    /// #2749/#6997: read the two SESSION_CLOSE observation fields — the
    /// OR-accumulated TCP control bits and the forward-direction ToS byte —
    /// for the session keyed by `key`, or `None` if no live entry exists.
    ///
    /// Sibling of `session_counters` above and same cost profile (one lookup +
    /// a `Copy` of two bytes). It exists because these two fields were
    /// observable ONLY through an expiry-driven Close delta, which forces a
    /// caller that wants to bind them at their SOURCE to drive GC and drain the
    /// delta ring first — enough machinery that #6997's call site went unbound
    /// rather than under-asserted.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn observed_close_fields(&self, key: &SessionKey) -> Option<(u8, u8)> {
        self.entry_by_key(key)
            .map(|e| (e.observed_tcp_flags, e.observed_tos))
    }

    /// #918/#6997: read the session's liveness timestamp, or `None` if no live
    /// entry exists. Same idiom and same reason as `observed_close_fields`:
    /// `touch_if_stale`'s only externally visible effect is this field moving,
    /// so a caller binding that call site has to be able to read it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn last_seen_ns(&self, key: &SessionKey) -> Option<u64> {
        self.entry_by_key(key).map(|e| e.last_seen_ns)
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
    #[inline]
    pub fn update_session(&mut self, req: SessionUpdate<'_>, ha_activation: bool) -> bool {
        let SessionUpdate {
            key,
            decision,
            metadata,
            origin,
            now_ns,
            protocol,
            tcp_flags,
        } = req;
        // #1752 Path E: in-place refresh. The prior implementation did
        // `remove_entry` + mutate + `restore_entry`, which tore down and rebuilt
        // every index (key_to_handle map, slab slot with a NEW handle, all four
        // secondary indices) plus ~3 SessionMetadata clones on EVERY packet of an
        // established flow, only to bump timestamps. We now mutate the slab record
        // in place, gating secondary-index REMOVES on key-relevant input changes
        // (nat / is_reverse / owner_rg_id) while still re-asserting
        // secondary-index ADDS every refresh (restore_entry parity). Behavior is
        // byte-identical (modulo the opaque slab handle value); see
        // docs/pr/1752-session-inplace-refresh/plan.md.
        let Some(&handle) = self.key_to_handle.get(key) else {
            return false;
        };
        // Stale-handle + primary-key guard (parity with remove_entry): never
        // index the slab raw — a stale key_to_handle could point at a vacant or
        // reused slot. On mismatch behave like remove_entry returning None.
        //
        // #1855 contract: a stale/vacant mapping is impossible-by-construction
        // (single-writer `&mut self`, #964 eager cleanup), so debug builds
        // assert loudly (logic-bug detector) while release builds tolerate and
        // return false without touching the reused-slot session — the
        // remove_entry #964 "release-mode safety net" precedent. See
        // docs/research/1855-inplace-contract/plan.md.
        let Some(record) = self.entries.get(handle as usize) else {
            debug_assert!(
                false,
                "update_session: key_to_handle had stale handle {} for {:?}",
                handle, key
            );
            return false;
        };
        if record.key != *key {
            debug_assert!(false, "update_session: stale key_to_handle for {:?}", key);
            return false;
        }
        // Snapshot the OLD index-relevant + collision-relevant state (all Copy).
        let old_origin = record.entry.origin;
        let old_nat = record.entry.decision.nat;
        let old_is_reverse = record.entry.metadata.is_reverse;
        let old_owner_rg = record.entry.metadata.owner_rg_id;
        // #10310: a WorkerLocalImport replica is not counted, but a promote
        // to a local origin becomes one logical limit-session unit.
        let old_counted = !old_is_reverse && install::session_limit_origin_counted(old_origin);
        if !ha_activation {
            let new_peer = origin.is_peer_synced();
            // Reject: both peer-synced (refresh_local on a synced entry) OR peer
            // data trying to overwrite a local entry. The prior code reached this
            // via remove_entry + restore_entry + return false, and restore_entry
            // unconditionally re-asserts the entry's own secondary ADDS. To stay
            // byte-identical (incl. re-winning a displaced secondary-index
            // collision), re-assert the OLD adds before bailing.
            let should_reject_update = new_peer;
            if should_reject_update {
                self.index_forward_nat_key_parts(
                    key,
                    handle,
                    old_nat,
                    old_is_reverse,
                    old_owner_rg,
                );
                return false;
            }
            // Else: peer→local promote, or local→local refresh — fall through.
        }
        let was_peer_synced = old_origin.is_peer_synced();

        // Reindex only when a secondary-index input changed (§2 of the plan:
        // indices depend only on key + nat + is_reverse + owner_rg_id, and key +
        // handle are invariant here). Gates only the value-guarded REMOVES.
        let reindex = old_nat != decision.nat
            || old_is_reverse != metadata.is_reverse
            || old_owner_rg != metadata.owner_rg_id;
        if reindex {
            self.remove_forward_nat_index_parts(key, handle, old_nat, old_is_reverse);
            remove_owner_rg_index_entry(&mut self.owner_rg_sessions, old_owner_rg, handle);
        }

        // #3527: resolve the per-zone half-open override before borrowing the
        // record mutably (the timeout selection below cannot re-borrow self).
        let opening_override_ns = self.opening_override_for(metadata.ingress_zone);
        // #10507 A1: live policy generation for the Fresh-only reset below.
        let live_policy_gen = self.policy_revalidation_gen;
        {
            let record = self
                .entries
                .get_mut(handle as usize)
                .expect("handle validated above");
            record.entry.decision = decision;
            record.entry.metadata = metadata.clone();
            record.entry.origin = origin;
            // #10507 A1 (Main-approved deviation from §4.5 unconditional —
            // Option A, Stale retains its fence): a peer-to-local promotion
            // revokes provenance only when Fresh. A Fresh Recorded Permit
            // must not coast into local forwarding — reset to Unvalidated
            // so the next local packet cold-judges. A Stale row already
            // re-judges via the Stale arm; resetting Stale Recorded to
            // Unvalidated would launder a fenced recorded authorization
            // into the never-validated carve-out (Decline instead of
            // fail-closed on type-armed ICMP / unidentified arrival).
            // Preserving the Stale kind keeps the Recorded fence through
            // the transition. Fresh behavior is bit-identical to
            // unconditional; packet-time fencing stays authoritative.
            if was_peer_synced
                && !origin.is_peer_synced()
                && record.entry.policy_revalidated_gen == live_policy_gen
            {
                record.entry.policy_revalidation_kind =
                    PolicyRevalidationKind::Unvalidated;
            }
            // #9856: install_epoch is write-once per incarnation — a refresh must not move it.
            record.entry.last_seen_ns = now_ns;
            // #3046: RST is sticky — once observed it keeps the entry on the
            // short RST timeout even if a later (reordered) segment lacks RST.
            // Set it BEFORE selecting the timeout so the expires decision below
            // consults the sticky flag (mirrors lookup.rs). Otherwise a
            // peer-synced entry that already had reset=true, promoted via a
            // non-RST FIN trigger, would wrongly revert to the 30s FIN window.
            record.entry.reset |= matches!(protocol, PROTO_TCP) && has_rst(tcp_flags);
            // #3489: `closing` is sticky, exactly like `reset` (#3046) and
            // `established` (#3152) and the read-path in lookup.rs. Once a FIN
            // or RST has moved the session into the short close window, a later
            // non-closing segment (e.g. a reordered data-ACK, flags=0x10) on
            // the HA shared-promote path must NOT revert it to the 300s
            // established window. A plain assignment here let that happen,
            // leaving a FIN'd session lingering 10× too long (#3489).
            record.entry.closing |= matches!(protocol, PROTO_TCP) && is_closing(tcp_flags);
            // #7342: sticky like `closing`/`reset`. The peer bit is not
            // knowable here — this path promotes a peer-synced entry from one
            // node's view, and the FIN-direction pair is node-local derived
            // state that does not cross the HA wire — so a promoted half-closed
            // session reaps on CLOSING until this node observes the other
            // direction's FIN itself. That is the shorter window of the two by
            // Junos default, so the failure direction is a session reaped early
            // rather than one held past its close.
            record.entry.fin_own |= matches!(protocol, PROTO_TCP) && has_fin(tcp_flags);
            // #3152/#4109: TCP promotes on a genuine reverse SYN-ACK. #10889:
            // a non-TCP app-managed session promotes on a genuine reverse
            // packet; a forward-only refresh cannot open the long idle window.
            record.entry.established |=
                (matches!(protocol, PROTO_TCP) && is_syn_ack(tcp_flags) && metadata.is_reverse)
                    || (!matches!(protocol, PROTO_TCP)
                        && metadata.is_reverse
                        && metadata.inactivity_timeout_ns.is_some());
            record.entry.expires_after_ns = if record.entry.closing {
                tcp_close_window_ns(record.entry.tcp_close_class(), &self.timeouts)
            } else {
                // #3227: a real-traffic refresh re-stamps the idle window from
                // the (possibly updated) metadata's per-app override.
                // #3152: an un-established TCP session uses the short opening
                // window via session_timeout_ns(established=false).
                session_timeout_ns(
                    protocol,
                    tcp_flags,
                    record.entry.established,
                    &self.timeouts,
                    metadata.inactivity_timeout_ns,
                    // #3527: opening-window override for an OPENING refresh
                    // (a SYN retransmit on a still-half-open session). Ignored
                    // once `established`.
                    opening_override_ns,
                )
            };
            // wheel_tick deliberately preserved (parity with restore_entry).
            // #2120: a real-traffic refresh (or a peer→local promote) means
            // this entry now genuinely lives on this node — it leaves the
            // held world. Clear the hold clock so the stale-synced ceiling
            // restarts cleanly if it is ever held again, and reset the
            // self-healed-epoch to the never-self-healed default (a later
            // SELF-HEAL, if this node forwards the RG, records the live
            // epoch; the HOLD branch never writes seen_rg_epoch).
            record.entry.first_held_ns = 0;
            record.entry.seen_rg_epoch = 0;
        }
        if protocol == PROTO_TCP && !metadata.is_reverse {
            let remains_opening = self
                .entry_by_key(key)
                .is_some_and(|entry| Self::is_pressure_shed_opening(key, entry, false));
            if remains_opening {
                self.pressure_shed_openings.insert(key.clone(), ());
            } else {
                self.pressure_shed_openings.remove(key);
            }
        }
        // #10310: keep count maintenance balanced across in-place origin
        // transitions (notably WorkerLocalImport -> local promotion).
        let new_counted = !metadata.is_reverse && install::session_limit_origin_counted(origin);
        if new_counted && !old_counted {
            self.session_limit_inc(key.src_ip, key.dst_ip);
        } else if old_counted && !new_counted {
            self.session_limit_dec(key.src_ip, key.dst_ip);
        }
        // Always re-assert the secondary ADDS — byte-identical to restore_entry's
        // unconditional index_forward_nat_key. For the no-reindex case this
        // re-inserts the same keys→handle (idempotent when unique, re-wins on a
        // collision); for the reindex case it installs the NEW keys after the
        // removes above.
        self.index_forward_nat_key_parts(
            key,
            handle,
            decision.nat,
            metadata.is_reverse,
            metadata.owner_rg_id,
        );
        // #965: schedule the refreshed entry. Last_seen / expires_after were
        // rewritten above; push_to_wheel is throttled and will only emit a new
        // wheel entry if the canonical tick changed.
        self.push_to_wheel(key, now_ns);
        // Emit open delta when promoting a peer-synced entry to local
        if was_peer_synced && !origin.is_peer_synced() && !metadata.is_reverse {
            // #3122/#10310: a counted peer import -> local promote is
            // COUNT-NEUTRAL because the slot was charged at import. A
            // WorkerLocalImport -> local promote was uncounted and the
            // transition bookkeeping above adds its one slot. In both cases
            // this Open-delta branch must not increment again: it only
            // announces the new local ownership to this node's peers.
            // #2465: a promote keeps the original entry's write-once
            // created_ns (the update block above does not touch it); pair it
            // with the refresh instant as last_seen. Informational on an Open
            // delta (the SESSION_CREATE frame reports no duration).
            let created_ns = self
                .entry_by_key(key)
                .map(|e| e.created_ns)
                .unwrap_or(now_ns);
            // #2501: a promote keeps the entry's accumulated counters
            // (informational on an Open delta — SESSION_CREATE reports no
            // volume — but consistent with reading created_ns off the same
            // entry).
            let counters = self
                .entry_by_key(key)
                .map(|e| e.counters)
                .unwrap_or_default();
            // #2749: a promote keeps the entry's observed ToS / TCP flags
            // (informational on an Open delta — consistent with counters).
            let (observed_tos, observed_tcp_flags) = self
                .entry_by_key(key)
                .map(|e| (e.observed_tos, e.observed_tcp_flags))
                .unwrap_or((0, 0));
            // #4915: a promote keeps the entry's stable session id (read off the
            // same entry as created_ns/counters), so the Open delta announcing
            // the new local ownership carries the id already assigned at import.
            let session_id = self.entry_by_key(key).map(|e| e.session_id).unwrap_or(0);
            // #9412: a promote re-announces the session, so it carries the close
            // class the entry already holds.
            let tcp_close_class = self.close_class_wire_for(key);
            self.push_delta(SessionDelta {
                provenance: crate::session::ExportProvenance::Incremental,
                tcp_close_class,
                purge_retirement: false,
                kind: SessionDeltaKind::Open,
                key: key.clone(),
                decision,
                metadata,
                origin,
                fabric_redirect_sync: false,
                created_ns,
                last_seen_ns: now_ns,
                counters,
                observed_tos,
                observed_tcp_flags,
                session_id,
                bulk_resync: false,
            });
        }
        true
    }

    /// Rebind both halves of a retained policy session to the new rule
    /// identity selected by commit-time rematching. Policy and zone fields are
    /// not secondary-index inputs, so the update is atomic with respect to the
    /// worker's single-writer session table.
    pub(crate) fn rebind_policy_pair(
        &mut self,
        key: &SessionKey,
        policy_id: u32,
        policy_counter_idx: u32,
        policy_counter: std::sync::Arc<crate::policy::PolicyRuleCounter>,
        ingress_zone: u16,
        egress_zone: u16,
    ) -> bool {
        let Some(forward) = self.entry_by_key(key) else {
            return false;
        };
        if forward.metadata.is_reverse {
            return false;
        }
        let companion_key = reverse_session_key(key, forward.decision.nat);
        if companion_key != *key {
            let Some(companion) = self.entry_by_key(&companion_key) else {
                return false;
            };
            if !companion.metadata.is_reverse {
                return false;
            }
        }

        // A non-NAT flow has an identical reverse key. Mutate it once; a
        // second pass would swap the zones back and leave the pair unchanged.
        let mut rebound = false;
        if let Some(record) = self.entry_by_key_mut(key) {
            record.metadata.policy_id = policy_id;
            record.metadata.policy_counter_idx = policy_counter_idx;
            record.metadata.policy_counter = Some(policy_counter.clone());
            record.metadata.ingress_zone = ingress_zone;
            record.metadata.egress_zone = egress_zone;
            rebound = true;
        }
        if companion_key != *key {
            if let Some(record) = self.entry_by_key_mut(&companion_key) {
                record.metadata.policy_id = policy_id;
                record.metadata.policy_counter_idx = policy_counter_idx;
                record.metadata.policy_counter = Some(policy_counter);
                record.metadata.ingress_zone = egress_zone;
                record.metadata.egress_zone = ingress_zone;
                rebound = true;
            }
        }
        rebound
    }

    /// Return the live forward/reverse halves after a policy rebind so mirror
    /// layers can be restamped with the same policy identity.
    pub(crate) fn policy_rebind_pair_entries(
        &self,
        key: &SessionKey,
    ) -> Option<Vec<PolicyRebindEntry>> {
        let forward = self.entry_by_key(key)?;
        if forward.metadata.is_reverse {
            return None;
        }
        let companion_key = reverse_session_key(key, forward.decision.nat);
        if companion_key != *key {
            let companion = self.entry_by_key(&companion_key)?;
            if !companion.metadata.is_reverse {
                return None;
            }
        }

        let mut entries = Vec::with_capacity(2);
        let mut append_entry = |candidate: &SessionKey| {
            if let Some(entry) = self.entry_by_key(candidate) {
                entries.push(PolicyRebindEntry {
                    key: candidate.clone(),
                    decision: entry.decision,
                    metadata: entry.metadata.clone(),
                    origin: entry.origin,
                    protocol: candidate.protocol,
                    tcp_flags: entry.observed_tcp_flags,
                    session_id: entry.session_id,
                    tcp_close_class: entry.tcp_close_class_wire(),
                });
            }
        };
        append_entry(key);
        if companion_key != *key {
            append_entry(&companion_key);
        }
        Some(entries)
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
        let protocol = key.protocol;
        self.update_session(
            SessionUpdate {
                key,
                decision,
                metadata,
                origin,
                now_ns,
                protocol,
                tcp_flags,
            },
            false,
        )
    }

    /// Convenience: refresh for HA activation (always updates regardless
    /// of origin). Preserves existing origin.
    #[cfg_attr(not(test), allow(dead_code))]
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
        let protocol = key.protocol;
        self.update_session(
            SessionUpdate {
                key,
                decision,
                metadata,
                origin,
                now_ns,
                protocol,
                tcp_flags,
            },
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
        // #1752 Path E: in-place (mirrors update_session, minus collision rules
        // — this path always applies). No expires_after_ns / closing rewrite,
        // matching the prior behavior.
        let Some(&handle) = self.key_to_handle.get(key) else {
            return false;
        };
        // #1855 contract (same as update_session's guards): impossible state
        // by construction — debug asserts, release tolerates + returns false.
        let Some(record) = self.entries.get(handle as usize) else {
            debug_assert!(
                false,
                "refresh_for_ha_transition: stale handle {} for {:?}",
                handle, key
            );
            return false;
        };
        if record.key != *key {
            debug_assert!(
                false,
                "refresh_for_ha_transition: stale key_to_handle for {:?}",
                key
            );
            return false;
        }
        let old_nat = record.entry.decision.nat;
        let old_is_reverse = record.entry.metadata.is_reverse;
        let old_owner_rg = record.entry.metadata.owner_rg_id;
        // Capture the new index parts before `metadata` is moved into the record.
        let new_nat = decision.nat;
        let new_is_reverse = metadata.is_reverse;
        let new_owner_rg = metadata.owner_rg_id;

        let reindex =
            old_nat != new_nat || old_is_reverse != new_is_reverse || old_owner_rg != new_owner_rg;
        if reindex {
            self.remove_forward_nat_index_parts(key, handle, old_nat, old_is_reverse);
            remove_owner_rg_index_entry(&mut self.owner_rg_sessions, old_owner_rg, handle);
        }
        // #10507 A2: live policy generation for the Fresh-only reset below.
        let live_policy_gen = self.policy_revalidation_gen;

        {
            let record = self
                .entries
                .get_mut(handle as usize)
                .expect("handle validated above");
            record.entry.decision = decision;
            record.entry.metadata = metadata;
            // #10507 A2 (Main-approved deviation, Option A — see A1): Fresh-only.
            // Stale retains its Recorded fence; Fresh resets to force cold.
            // Packet-time fencing remains authoritative if delayed/skipped.
            if record.entry.policy_revalidated_gen == live_policy_gen {
                record.entry.policy_revalidation_kind = PolicyRevalidationKind::Unvalidated;
            }
            // #9856: install_epoch is write-once per incarnation — a refresh must not move it.
            record.entry.last_seen_ns = now_ns;
            // #2120: promotion refresh re-stamps `last_seen_ns` (the entry
            // now ages from a full timeout on the promoted node), so it
            // leaves the held world. Clear the hold clock and reset the
            // observed epoch (§6.4 write-site contract). NOTE: the
            // edge-triggered self-heal in the expire pass leaves
            // `first_held_ns` UNTOUCHED — only a genuine departure from the
            // held state (here, real-traffic refresh, or re-import) clears
            // it, so a flapping RG cannot reset the leak ceiling.
            record.entry.first_held_ns = 0;
            record.entry.seen_rg_epoch = 0;
        }
        self.index_forward_nat_key_parts(key, handle, new_nat, new_is_reverse, new_owner_rg);
        // #965: schedule the refreshed entry for expiration check.
        self.push_to_wheel(key, now_ns);
        true
    }

    /// Promote a peer-synced session to local ownership.
    /// Convenience wrapper around update_session that hides the
    /// `ha_activation` flag (always false on this path).
    #[inline]
    pub fn promote_synced_with_origin(&mut self, req: SessionUpdate<'_>) -> bool {
        self.update_session(req, false)
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

    /// Requeue drained deltas at the front when a tuple gate could not be
    /// acquired for their binding-queue cleanup. Reversing preserves the
    /// original FIFO order when pushing each item to the front.
    pub(crate) fn requeue_deltas_front(&mut self, deltas: &[SessionDelta]) {
        for delta in deltas.iter().rev() {
            if self.deltas.len() >= MAX_SESSION_DELTAS {
                self.delta_drops = self.delta_drops.saturating_add(1);
                self.delta_loss_pending = true;
                continue;
            }
            self.deltas.push_front(delta.clone());
        }
    }
    /// #9856: drain tombstones harvested by terminal removals for an active
    /// owner-RG export. Entries outside this window are discarded because a
    /// future export cannot include an already-removed incarnation.
    ///
    /// The callback returns false when the dedicated export buffer is full.
    /// Matching tombstones then remain queued and the worker retries them
    /// on a later pass without advancing its export cursor.
    pub(crate) fn take_tombstones_for_export(
        &mut self,
        kick_epoch: u64,
        owner_rgs: &[i32],
        mut f: impl FnMut(&ExpiredSession) -> bool,
    ) -> bool {
        let tombstones = std::mem::take(&mut self.tombstone_log);
        let mut deferred = Vec::new();
        let mut complete = true;
        for tombstone in tombstones {
            if tombstone.install_epoch <= kick_epoch
                && owner_rgs.contains(&tombstone.metadata.owner_rg_id)
            {
                if !f(&tombstone) {
                    complete = false;
                    deferred.push(tombstone);
                }
            }
        }
        self.tombstone_log.extend(deferred);
        complete
    }
    /// Discard tombstones collected before a fresh export kick. A tombstone
    /// predating the kick has no matching open in that export window; retaining
    /// it could close a reused key on the peer. This also bounds idle retention:
    /// terminal removals are harvested only between the kick and its terminal
    /// page.
    pub(crate) fn discard_tombstones_for_export(&mut self) {
        self.tombstone_log.clear();
        self.tombstone_drops = 0;
    }
    /// Transfer tombstone-log overflow into the active export's drop metric.
    pub(crate) fn take_tombstone_drops_for_export(&mut self) -> u64 {
        let drops = self.tombstone_drops;
        self.tombstone_drops = 0;
        drops
    }
    pub fn has_pending_deltas(&self) -> bool {
        !self.deltas.is_empty()
    }

    /// #2442: read-and-clear the loss-of-sync latch. Returns true iff
    /// `push_delta` dropped at least one delta since the last call — i.e. the
    /// incremental session-sync stream went lossy and the downstream consumer's
    /// view may have silently diverged from the table truth. The worker loop
    /// calls this once per drain cycle; a true result drives a full owner-RG
    /// export so the peer re-derives the session view from a complete snapshot.
    ///
    /// DEBOUNCE: the latch is a single bool cleared here, so a burst dropping N
    /// deltas before this read raises exactly one resync (one episode → one
    /// trigger). A fresh drop AFTER the clear re-arms it for the next episode.
    #[inline]
    pub fn take_delta_loss(&mut self) -> bool {
        let lossy = self.delta_loss_pending;
        self.delta_loss_pending = false;
        lossy
    }

    /// #2874: latch loss-of-sync from OUTSIDE `push_delta` — specifically when
    /// the EVENT-STREAM producer (`flush_session_deltas`) could not queue a
    /// session open/close delta losslessly (the shared event-stream channel was
    /// wedged or the peer disconnected). Like the #2442 in-ring overflow path
    /// this forces the worker loop's `take_delta_loss` resync to re-export the
    /// full owner-RG snapshot, so the peer re-derives a complete session view
    /// instead of silently missing the dropped open/close. Single bool, so a
    /// burst raises exactly one resync (debounced by `take_delta_loss`).
    #[inline]
    pub fn set_delta_loss(&mut self) {
        self.delta_loss_pending = true;
    }

    /// #2442: cumulative count of deltas dropped on ring overflow. Surfaced for
    /// health/status telemetry so operators can see the loss-of-sync episodes
    /// (each one forces a resync). Test/diagnostic accessor.
    pub fn delta_drops(&self) -> u64 {
        self.delta_drops
    }

    fn push_delta(&mut self, delta: SessionDelta) {
        if self.deltas.len() >= MAX_SESSION_DELTAS {
            self.delta_drops = self.delta_drops.saturating_add(1);
            // #2442: a dropped delta is a HA-relevant open/close event the
            // downstream session-sync consumer will never observe — the
            // incremental stream is now lossy. Latch loss-of-sync so the
            // worker loop forces a full owner-RG export (table-truth rescan).
            // Single bool: a burst that overflows repeatedly before the worker
            // reads it raises exactly one resync (see `take_delta_loss`). Hot
            // path: a plain branch + bool store, no allocation, no syscall.
            self.delta_loss_pending = true;
            return;
        }
        self.deltas.push_back(delta);
    }

    /// #964 Step 1: centralized session removal. Eager-cleanup
    /// invariant — every handle-valued internal index MUST be
    /// cleaned BEFORE the slab slot is returned to the free list.
    /// All session removal goes through this helper.
    ///
    /// #9856: `kind` gates export-tombstone harvest. Only `Terminal`
    /// (the session is really gone) logs a tombstone, and only when
    /// the removed entry satisfies the STATIC part of the owner-RG
    /// export predicate (forward, locally-owned, non-seed,
    /// non-fabric-ingress, exportable disposition); the window parts
    /// (owner-RG set, `install_epoch <= kick_epoch`) are checked at
    /// push time by the worker loop via
    /// `ExpiredSession::in_export_window`.
    fn remove_entry(&mut self, key: &SessionKey, kind: RemovalKind) -> Option<SessionEntry> {
        self.leak_incarnations.remove(key);
        // The pressure-shed index contains only forward opening entries.
        // Remove by key here so every terminal and replacement path keeps it
        // paired with the authoritative session record.
        self.pressure_shed_openings.remove(key);
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
            debug_assert!(false, "remove_entry: stale key_to_handle for {:?}", key);
            self.key_to_handle.insert(key.clone(), handle);
            return None;
        }
        let decision = record.entry.decision;
        let metadata = record.entry.metadata.clone();
        // #2134: snapshot the counted-class predicate inputs (all Copy)
        // before the borrow ends so the per-IP count can be decremented
        // for a removed counted session. This is the sole removal sink —
        // expire, explicit delete (clear / RST / fabric-cancel /
        // promote-purge), and take_synced_local all funnel through here,
        // so the decrement cannot be forgotten by a future delete site.
        let removed_origin = record.entry.origin;
        let removed_is_reverse = metadata.is_reverse;
        // Borrow on `record` ends here; subsequent calls take
        // &mut self (cleanup helpers) without conflict.
        let _ = record;
        // Clean every handle-valued internal index. Each cleanup is
        // VALUE-GUARDED via guarded_remove — only remove if the
        // stored handle still equals our handle. Mirrors today's
        // matches!(... existing == key) pattern.
        self.remove_forward_nat_index(key, handle, decision, &metadata);
        remove_owner_rg_index_entry(&mut self.owner_rg_sessions, metadata.owner_rg_id, handle);
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
        // #2134/#3122/#10310: decrement the per-IP count for a removed
        // counted session (success path ONLY — the two early `None` guards
        // above RESTORE the mapping and do not decrement). The shared
        // counted-class predicate charges true HA peer imports, but not a
        // WorkerLocalImport replica, so removal balances the matching create
        // or promotion transition exactly.
        if !removed_is_reverse && install::session_limit_origin_counted(removed_origin) {
            self.session_limit_dec(key.src_ip, key.dst_ip);
        }
        // #9856: harvest an export tombstone for genuine terminal
        // removals of export-visible entries. A session deleted after
        // the kick but before the cursor reaches it would otherwise
        // leave the peer holding a zombie open; the tombstone is the
        // export-window repair (the incremental Close stays the
        // backstop). `Replace`/`Transfer` log nothing: the key lives
        // on and a close for the evicted incarnation would race the
        // replacement's open with no inter-channel ordering.
        // `record` is an owned local past the slab remove, so this
        // borrow is disjoint from the `&mut self` push below.
        let entry = &record.entry;
        if kind == RemovalKind::Terminal {
            if !entry.metadata.is_reverse
                && !self.demoted_owner_rgs.contains(&entry.metadata.owner_rg_id)
                && entry.origin != SessionOrigin::WorkerLocalImport
                && !entry.origin.is_transient_local_seed()
                && !entry.origin.is_local_tun_origin()
                && matches!(
                    entry.decision.resolution.disposition,
                    ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
                )
            {
                if self.tombstone_log.len() >= MAX_TOMBSTONES_FOR_EXPORT {
                    self.tombstone_drops = self.tombstone_drops.saturating_add(1);
                } else {
                    self.tombstone_log.push(ExpiredSession {
                        key: key.clone(),
                        decision: entry.decision,
                        metadata: entry.metadata.clone(),
                        origin: entry.origin,
                        session_id: entry.session_id,
                        close_class: entry.tcp_close_class_wire(),
                        install_epoch: entry.install_epoch,
                        overflow_close: None,
                    });
                }
            }
        }
        Some(record.entry)
    }

    /// #964 Step 1: re-insert an entry that was just `remove_entry`'d.
    /// Returns None always — kept return type for API compatibility
    /// with the prior FxHashMap-based shape.
    ///
    /// #1752 Path E: no longer used by the refresh paths (`update_session` /
    /// `refresh_for_ha_transition` now mutate in place). Retained as the
    /// reference half of the remove+restore round-trip the differential tests
    /// compare against, so in release builds it is retained as dead-code-allowed
    /// test reference logic (not conditionally compiled out).
    #[cfg_attr(not(test), allow(dead_code))]
    fn restore_entry(&mut self, key: SessionKey, entry: SessionEntry) -> Option<SessionEntry> {
        let record = SessionRecord {
            key: key.clone(),
            entry,
        };
        // #6297: same slab-insert choke point as the production installs —
        // keep the live-extent high-watermark correct even on this
        // test-only restore path.
        let raw = self.insert_record(record);
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
        self.index_forward_nat_key_parts(
            key,
            handle,
            decision.nat,
            metadata.is_reverse,
            metadata.owner_rg_id,
        );
    }

    /// #1752 Path E: secondary-index insert from the Copy parts the index
    /// actually depends on (`nat`, `is_reverse`, `owner_rg_id`). Lets the
    /// in-place refresh path re-assert (and reindex) without cloning a
    /// `SessionMetadata` / `SessionDecision`. `index_forward_nat_key` delegates
    /// here so the two stay bit-identical.
    fn index_forward_nat_key_parts(
        &mut self,
        key: &SessionKey,
        handle: u32,
        nat: NatDecision,
        is_reverse: bool,
        owner_rg_id: i32,
    ) {
        if is_reverse {
            let translated = translated_session_key(key, nat);
            if translated != *key {
                // #4438: APPEND to the translated (alias) bucket (1:N multimap)
                // instead of DISPLACING a prior occupant. Two reverse sessions
                // whose translated tuples collide (DNAT-to-shared-backend,
                // NAT64, interface-mode SNAT — the non-bijective classes) now
                // coexist, so the earlier reverse session's inbound alias
                // lookup is no longer stolen by the later install.
                // #6751: NOT attributed. This is the REVERSE/alias index, so
                // `key.src_ip` is the EXTERNAL server, not an internal source
                // — two reverse sessions with different servers would look
                // like "distinct sources" and inflate the one number this
                // counter exists to make trustworthy. Attribution is confined
                // to the forward branch below, where src_ip really is the
                // internal host. The aggregate still counts this collision.
                nat_index_bucket_push(
                    &mut self.reverse_translated_index,
                    &mut self.nat_reverse_key_collisions,
                    &mut u64::default(),
                    &self.entries,
                    key.src_ip,
                    translated,
                    handle,
                );
            }
        } else {
            // #4399: APPEND `handle` to the reverse-key bucket (1:N multimap)
            // instead of DISPLACING a prior occupant (#1758/#1760). A
            // different handle already present in the bucket means a distinct
            // session previously resolved to this reverse key K — the latent
            // 1:N collision. The push keeps BOTH handles (so the earlier
            // session's reply is no longer lost), dedups a re-assert of the
            // same handle on the per-packet refresh (#1753), and bumps
            // `nat_reverse_key_collisions` when the bucket grows.
            nat_index_bucket_push(
                &mut self.nat_reverse_index,
                &mut self.nat_reverse_key_collisions,
                &mut self.nat_reverse_key_collisions_distinct_src,
                &self.entries,
                key.src_ip,
                reverse_wire_key(key, nat),
                handle,
            );
            let reverse_canonical = reverse_canonical_key(key, nat);
            if reverse_canonical != *key {
                nat_index_bucket_push(
                    &mut self.nat_reverse_index,
                    &mut self.nat_reverse_key_collisions,
                    &mut self.nat_reverse_key_collisions_distinct_src,
                    &self.entries,
                    key.src_ip,
                    reverse_canonical,
                    handle,
                );
            }
            let forward_wire = forward_wire_key(key, nat);
            if forward_wire != *key {
                // #4438: forward_wire_index is now a 1:N multimap too — the
                // forward-wire key collides under the SAME non-bijective NAT
                // (interface-mode SNAT collapses both the reverse-wire and the
                // forward-wire tuples), so it needs the identical append-not-
                // displace discipline. `find_forward_wire_match_with_origin`
                // validates each bucket candidate against the full tuple.
                nat_index_bucket_push(
                    &mut self.forward_wire_index,
                    &mut self.nat_reverse_key_collisions,
                    &mut self.nat_reverse_key_collisions_distinct_src,
                    &self.entries,
                    key.src_ip,
                    forward_wire,
                    handle,
                );
            }
        }
        if !is_reverse && let Some(l3_key) = l3_reverse_key_for_forward(key, nat) {
            // #10130/#10674: the index buckets by family and reverse addresses;
            // its real protocol is validated at lookup, with 255 acting as the
            // native-fragment wildcard. The bucket stays indexed by hash rather
            // than requiring a scan across every session for sentinel probes.
            let index_key = l3_reverse_fragment_index_key(l3_key);
            let bucket = self.l3_reverse_index.entry(index_key).or_default();
            if !bucket.contains(&handle) {
                bucket.push(handle);
            }
        }
        if owner_rg_id > 0 {
            self.owner_rg_sessions
                .entry(owner_rg_id)
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
        self.remove_forward_nat_index_parts(key, handle, decision.nat, metadata.is_reverse);
    }

    /// #1752 Path E: value-guarded secondary-index removal from the Copy parts
    /// (`nat`, `is_reverse`). Used by the in-place reindex teardown so it needs
    /// no `SessionMetadata`/`SessionDecision` clone. `remove_forward_nat_index`
    /// delegates here.
    fn remove_forward_nat_index_parts(
        &mut self,
        key: &SessionKey,
        handle: u32,
        nat: NatDecision,
        is_reverse: bool,
    ) {
        if is_reverse {
            // #4438: per-HANDLE removal from the 1:N translated (alias)
            // bucket. A colliding sibling reverse session in the same bucket is
            // untouched; the key drops only once its bucket empties — so
            // closing one of two reverse sessions that share a translated key
            // leaves the survivor's inbound alias lookup intact (the
            // single-value map wiped the whole key and stranded it).
            nat_index_bucket_remove(
                &mut self.reverse_translated_index,
                &translated_session_key(key, nat),
                handle,
            );
            return;
        }
        // #4399: value-guarded per-HANDLE removal from the 1:N reverse-key
        // buckets. A colliding sibling in the same bucket is untouched; the
        // key is dropped only once its bucket empties. This is what leaves a
        // surviving colliding session's return path intact when the other
        // closes (the single-value map wiped the whole key and stranded it).
        nat_index_bucket_remove(
            &mut self.nat_reverse_index,
            &reverse_wire_key(key, nat),
            handle,
        );
        nat_index_bucket_remove(
            &mut self.nat_reverse_index,
            &reverse_canonical_key(key, nat),
            handle,
        );
        // #4438: forward_wire_index gets the identical per-handle removal.
        nat_index_bucket_remove(
            &mut self.forward_wire_index,
            &forward_wire_key(key, nat),
            handle,
        );
        if let Some(l3_key) = l3_reverse_key_for_forward(key, nat) {
            let index_key = l3_reverse_fragment_index_key(l3_key);
            l3_reverse_bucket_remove(&mut self.l3_reverse_index, &index_key, handle);
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
            // #4399/#4438: all three NAT indexes hold multiple handles per key
            // — the freed handle must be absent from EVERY bucket, not just a
            // stored scalar.
            && !self
                .nat_reverse_index
                .values()
                .any(|bucket| bucket.contains(&handle))
            && !self
                .forward_wire_index
                .values()
                .any(|bucket| bucket.contains(&handle))
            && !self
                .reverse_translated_index
                .values()
                .any(|bucket| bucket.contains(&handle))
            && !self
                .l3_reverse_index
                .values()
                .any(|bucket| bucket.contains(&handle))
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

pub(crate) const fn default_max_sessions() -> usize {
    DEFAULT_MAX_SESSIONS
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

/// #4399/#4438: append `handle` to the 1:N bucket for `key` in one of the NAT
/// session lookup indexes (`nat_reverse_index`, `forward_wire_index`,
/// `reverse_translated_index`), growing the multimap instead of DISPLACING a
/// prior occupant (#1758/#1760). A re-assert of a handle already present is a
/// no-op (dedup), so the per-packet refresh re-index (#1753) neither
/// double-inserts nor mis-counts. When the bucket already holds a DIFFERENT
/// handle the append records a genuine 1:N collision by bumping `collisions`
/// (the shared `nat_reverse_key_collisions` telemetry) — both handles now
/// coexist and the lookup validates each candidate against the full tuple, so
/// the earlier session's traffic is PRESERVED alongside the later one rather
/// than hijacked or dropped. A free function (not a method) so the caller can
/// pass disjoint `&mut` borrows of the specific index map and the counter.
fn nat_index_bucket_push(
    map: &mut HashMap<SessionKey, NatIndexBucket, FxSeededState>,
    collisions: &mut u64,
    distinct_src_collisions: &mut u64,
    entries: &slab::Slab<SessionRecord>,
    forward_src: IpAddr,
    key: SessionKey,
    handle: u32,
) {
    let bucket = map.entry(key).or_default();
    if bucket.contains(&handle) {
        // Idempotent re-assert (refresh / reject re-add). No growth, no new
        // collision — the handle already owns this key.
        return;
    }
    let collided = !bucket.is_empty();
    // #6751: attribute the collision BEFORE the push, while the bucket still
    // holds only the prior occupants. Resolving them after would compare the
    // arriving session against itself.
    //
    // Cost is on the COLLISION path only — an empty bucket short-circuits, and
    // buckets are tiny. Nothing here runs for the overwhelmingly common
    // no-collision install.
    //
    // A handle that no longer resolves is skipped rather than counted: a stale
    // bucket entry is not evidence of a distinct source, and guessing would
    // inflate the one number this counter exists to make trustworthy.
    let distinct_src = collided
        && bucket.iter().any(|prior| {
            entries
                .get(*prior as usize)
                .is_some_and(|record| record.key.src_ip != forward_src)
        });
    bucket.push(handle);
    if collided {
        *collisions = collisions.saturating_add(1);
        if distinct_src {
            *distinct_src_collisions = distinct_src_collisions.saturating_add(1);
        }
    }
}
/// #4399/#4438: remove ONLY `handle` from the 1:N bucket for `key` in one of
/// the NAT session lookup indexes, dropping the key entirely once its bucket
/// empties. Value-guarded per handle: a colliding sibling in the same bucket is
/// untouched, so closing one of two sessions that share a key leaves the
/// survivor's lookup path intact (the single-value map wiped the whole key and
/// stranded it). No-op when the key is absent.
fn nat_index_bucket_remove(
    map: &mut HashMap<SessionKey, NatIndexBucket, FxSeededState>,
    key: &SessionKey,
    handle: u32,
) {
    if let Some(bucket) = map.get_mut(key) {
        bucket.retain(|h| *h != handle);
        if bucket.is_empty() {
            map.remove(key);
        }
    }
}

fn l3_reverse_bucket_remove(map: &mut SeededL3ReverseIndex, key: &L3ReverseKey, handle: u32) {
    if let Some(bucket) = map.get_mut(key) {
        bucket.retain(|h| *h != handle);
        if bucket.is_empty() {
            map.remove(key);
        }
    }
}

/// Select the idle expiry for a session.
///
/// #3227/#10889: `app_override_ns` is the admitting application's per-app
/// inactivity timeout in nanoseconds, or `None` to use the global per-protocol
/// `SessionTimeouts`. When `Some`, it replaces the idle window only after the
/// protocol's promotion gate opens: TCP requires its handshake to complete;
/// UDP, ICMP, and other non-TCP sessions require a genuine reverse packet.
/// That first reply opens the app timeout for both halves. An unreplied
/// datagram remains on its global per-protocol window. The app timeout never
/// extends TCP closing/RST reap windows.
///
/// #3152: for TCP, `established=false` means a non-closing bare-SYN
/// half-open and selects the short `tcp_opening_ns` window. For non-TCP,
/// `established=false` suppresses only the custom app timeout; it selects the
/// global protocol window. A TCP close returns its close window before either
/// established-class decision.
///
/// #3527: `opening_override_ns` is the ingress zone's `syn-flood timeout`
/// mapped to the half-open window (ns), or `None` for the global
/// `tcp_opening_ns`. When `Some`, it replaces the OPENING-branch window ONLY
/// (it is the half-completed-connection queue window, not an established idle
/// timeout — it never touches the established / closing / RST branches). A
/// half-open session in a zone with `syn-flood timeout N` therefore reaps `N`
/// seconds after install instead of the 20 s default, so a flood that stops is
/// forgotten on the operator's window. `None` is byte-identical to pre-#3527.
fn session_timeout_ns(
    protocol: u8,
    tcp_flags: u8,
    established: bool,
    timeouts: &SessionTimeouts,
    app_override_ns: Option<u64>,
    opening_override_ns: Option<u64>,
) -> u64 {
    match protocol {
        PROTO_TCP => {
            if is_closing(tcp_flags) {
                // #3046: a RST close is reaped on the short abort window.
                // #7342: everything else is CLOSING — a single packet cannot
                // establish TIME_WAIT, which is a statement about BOTH
                // directions, so the entry-state callers
                // (`SessionEntry::tcp_close_class`) are the only ones that can
                // reach it. #3227: the per-app override never extends a closing
                // session's reap window.
                tcp_close_window_ns(TcpCloseClass::from_packet(tcp_flags), timeouts)
            } else if !established {
                // #3152: handshake-incomplete (OPENING / half-open) — the
                // short opening window. The per-app override does NOT apply
                // here (it is the established-session idle timeout); a
                // half-open session reaps fast regardless. #3527: a per-zone
                // `syn-flood timeout` overrides the global opening window for
                // this zone's half-opens.
                opening_override_ns.unwrap_or(timeouts.tcp_opening_ns)
            } else {
                app_override_ns.unwrap_or(timeouts.tcp_established_ns)
            }
        }
        PROTO_UDP => {
            if established {
                app_override_ns.unwrap_or(timeouts.udp_ns)
            } else {
                timeouts.udp_ns
            }
        }
        PROTO_ICMP | PROTO_ICMPV6 => {
            if established {
                app_override_ns.unwrap_or(timeouts.icmp_ns)
            } else {
                timeouts.icmp_ns
            }
        }
        _ => {
            if established {
                app_override_ns.unwrap_or(OTHER_SESSION_TIMEOUT_NS)
            } else {
                OTHER_SESSION_TIMEOUT_NS
            }
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

// #7342: the CLOSING vs TIME_WAIT close-state split and the three
// `security flow tcp-session` windows it makes configurable.
#[cfg(test)]
#[path = "tcp_close_state_7342_tests.rs"]
mod tcp_close_state_7342_tests;
// #10885: closing-entry refresh must respect reset and FIN direction in lookup,
// flow-cache keepalive, and companion retention.
#[cfg(test)]
#[path = "close_refresh_gate_10885_tests.rs"]
mod close_refresh_gate_10885_tests;

// #9412: pins that the production HA import path carries `tcp_flags: 0`, so the
// close bits derived from it are vacuous and an imported session ages on the
// ESTABLISHED window. Deliberately two-sided — it FAILS when #9412 is fixed.
#[cfg(test)]
#[path = "tcp_flags_zero_on_sync_path_9412_tests.rs"]
mod tcp_flags_zero_on_sync_path_9412_tests;

// #9412 ACCEPTANCE: install OPEN, close on the primary, fail over with no
// traffic, reap on the close window. Written before the fix; compiles at base.
#[cfg(test)]
#[path = "close_state_sync_9412_acceptance_tests.rs"]
mod close_state_sync_9412_acceptance_tests;
// #9582: a close seen only by a worker replica of a local session is announced, with
// the installer's id. Written before the fix.
#[cfg(test)]
#[path = "replica_close_announce_9582_tests.rs"]
mod replica_close_announce_9582_tests;

// #7212: the static input-filter revalidation stamp lifecycle. Its own file
// rather than another block in the 8k-line `tests.rs`, per the modularity rule
// on test files.
#[cfg(test)]
#[path = "filter_revalidation_7212_tests.rs"]
mod filter_revalidation_7212_tests;
#[cfg(test)]
#[path = "policy_revalidation_8356_tests.rs"]
mod policy_revalidation_8356_tests;
// #9901 (F-077): per-session embedded-ICMP-error budget (burst 64 / rate
// 64/s) math, refill, independence, and the shared/peer side table.
#[cfg(test)]
#[path = "icmp_error_budget_9901_tests.rs"]
mod icmp_error_budget_9901_tests;
// #9895: reverse NAT lookup must refuse a validating pass-2 candidate when
// both the reply and candidate carry different non-zero routing domains.
#[cfg(test)]
#[path = "reverse_domain_9895_tests.rs"]
mod reverse_domain_9895_tests;
// #9990/#9991: pre-decision probes and strict hit-path expiry.
#[cfg(test)]
#[path = "session_lifetime_9990_9991_tests.rs"]
mod session_lifetime_9990_9991_tests;
// #10889: datagram app inactivity timeout requires a genuine reverse packet.
#[cfg(test)]
#[path = "datagram_reply_promotion_10889_tests.rs"]
mod datagram_reply_promotion_10889_tests;
