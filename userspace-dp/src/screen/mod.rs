//! Screen/IDS attack protection checks for the userspace dataplane.
//!
//! Implements pre-session packet validation that mirrors the eBPF screen stage
//! (`bpf/xdp/xdp_screen.c`). The stateless + rate-based checks run on every
//! packet BEFORE session lookup. The stateful scan/sweep detectors
//! (port-scan, IP-sweep) and the per-IP session limit are NOT pre-session —
//! they run at the NEW-FLOW / session-MISS decision in `poll_descriptor`
//! (`scan_sweep_drop_on_new_flow` here, `new_flow_session_limit_drop`
//! there) so an established flow's mid-stream packets never count toward a
//! scan/sweep or a session limit (#2210 / #2134 ACK-evasion contract).
//!
//! Supported checks:
//! - Land attack (src_ip == dst_ip, any L4 ports — #2215 BPF parity)
//! - TCP SYN+FIN
//! - TCP no-flag (null scan)
//! - TCP FIN without ACK
//! - WinNuke (URG to port 139)
//! - Ping of death (IPv4 fragment whose offset+total-length would
//!   reassemble past 65535 bytes — #893/#2215 formula, any protocol)
//! - Teardrop (overlapping fragments, plus a non-first fragment with no
//!   /negative payload `ip_total_len <= hdr_len` — #3027)
//! - ICMP fragment
//! - IP source route — IPv4 LSRR/SSRR options and IPv6 Routing Header
//!   (source-route routing type), not every IHL>5 packet (#2973)
//! - Rate limiting (ICMP, UDP flood) — per-DESTINATION cap (Junos parity:
//!   ICMP per destination IP, UDP per destination IP+port; #4112) with the
//!   per-zone aggregate retained as a coarser secondary zone-saturation ceiling
//! - SYN flood (per-zone aggregate + per-source/per-destination sub-caps, #3315;
//!   per-destination evaluated before the aggregate cookie/Drop verdict, #4112)
//!
//! ## Missing-screen-profile signal (#3082)
//!
//! A zone may REFERENCE a screen profile that was never defined. #3078 closed
//! the COMMIT path (strict reject / lenient-load warn, #1960), but the
//! dataplane still has no resolved profile for such a zone and so cannot run
//! screen checks for it. This is reachable on the lenient/HA-sync path
//! (older-binary `active.json` on upgrade, or an HA sync from an un-upgraded
//! primary). The Go control plane now threads the set of zones that reference a
//! missing profile (`ConfigSnapshot.screen_missing_profile_zones`) so the
//! None branch can distinguish "zone has no screen configured" (legit Pass,
//! silent) from "zone references a MISSING screen". For the latter it emits a
//! runtime WARN, rate-limited to one per zone per second (sustained traffic
//! produces essentially one WARN until it subsides) so a packet flood to a
//! misconfigured zone cannot spam the log. BOTH the flow-present
//! (`check_packet_with_zone_id`) and the flowless (`check_flowless_screens`,
//! #3908) None branches call `maybe_warn_missing_profile`, so a flowless packet
//! (non-first fragment / non-query ICMP) to a broken-profile zone is as
//! observable as a flow-bearing one.
//!
//! #7168 resolved the posture that #3082 deferred, and the verdict is no longer
//! Pass. Neither endpoint of the old fork was right: failing OPEN silently
//! removes a configured security control, while failing CLOSED turns a
//! config-reference typo into a per-zone outage on the one path whose reason to
//! exist is #1960 no-brick. Instead, an unresolved reference is evaluated
//! against `ScreenProfile::conservative_default()` — the threshold-free
//! malformed-packet subset, with NO rate/scan/session-limit checks synthesised,
//! because those are the ones whose safe value is site-specific and a guess
//! there is itself an outage risk. Both None branches route through
//! `missing_profile_verdict`. A zone with no screen configured still passes
//! silently; only a zone that REFERENCES an unresolved profile is substituted.
//!
//! Layout (#1543, Wave-5): the runtime is split across focused
//! sibling submodules so SYN-cookie crypto can be audited
//! independently from packet policy:
//!
//! - `packet`        — shared `ScreenPacketInfo`, `ScreenProfile`,
//!                     `ScreenVerdict`, protocol/flag constants.
//! - `syncookie`     — `SynCookieCodec`, `SipHash24`,
//!                     `SynCookieValidatedCache`, all cookie types.
//! - `rate`          — per-zone sliding 1-second window `RateCounter`
//!                     (two-bucket counter; no fixed wall-second reset, #2937).
//! - `stateless`     — side-effect-free packet-policy helpers, including the
//!                     shared `check_fragment_and_route` tail (#6238).
//! - `scan`          — port-scan + IP-sweep windowed trackers.
//! - `session_limit` — per-IP session-count tracker.
//! - `extract`       — allocation-free IP/TCP header parser.
//! - `zone`          — `ZoneScreenState` (the #4969 consolidated per-zone
//!                     state) + the per-zone flood enforcement helpers:
//!                     ICMP/UDP admission, the #6238 shared rate-flood block,
//!                     and the #6437 two-phase SYN-flood gate.
//! - `tests`         — relocated screen_tests.rs (loaded via #[path]).
//!
//! ## Per-zone state consolidation (#4969)
//!
//! All HOT, mutable per-zone screen state — the resolved `ScreenProfile` plus
//! the flood aggregates, per-destination/per-source flood sketches, and
//! SYN-cookie fields — lives in a single [`ZoneScreenState`] value (in
//! `zone.rs` since #6437) stored in one
//! `FxHashMap<String, ZoneScreenState>` (`ScreenState::zones`, keyed by zone
//! name). Before #4969 these were ~13 PARALLEL `FxHashMap<String, _>` tables
//! synchronised only by manual prepopulation/retention discipline in
//! `update_profiles`. The consolidation buys two things:
//!
//! 1. **No fail-open by construction.** [`ZoneScreenState::from_profile`] builds
//!    the profile and ALL of its threshold-gated sub-state together, so
//!    `Some ⟺ configured` for every per-destination/per-source sketch. A
//!    configured limiter can NEVER be silently absent on the screened path
//!    (the pre-#4969 "missed a prepopulation step → missing map entry →
//!    `if let Some(..)` falls through to Pass" class). The removed
//!    `debug_assert!` guarding a missing SYN-cookie active-until entry is now a
//!    compile-time impossibility.
//! 2. **One lookup per screened packet.** The ICMP/UDP/initial-SYN hot paths do
//!    a single `zones.get_mut(zone)` and touch fields on the returned
//!    `&mut ZoneScreenState`, instead of re-hashing the zone name into several
//!    tables. The global SYN-cookie machinery (codec, validated cache, epoch
//!    cache) and the per-worker diagnostic counters stay DISJOINT `ScreenState`
//!    fields, so a `zstate` borrow coexists with them; the sole whole-`self`
//!    method used on the hot path (`current_syn_cookie_full_epoch`) is reached
//!    only on the SYN-cookie mint RETURN path, after `zstate`'s last use.
//!
//! Non-hot bookkeeping that is NOT keyed on a resolved-profile zone —
//! `missing_profile_refs` / `missing_profile_warn_counters` (#3082, keyed by
//! zones that have NO resolved profile) and the per-IP scan/sweep trackers —
//! stays separate; folding it in would muddy the "one value per configured
//! zone" invariant. `update_profiles` rebuilds `zones` per reconfigure,
//! carrying over each persisting zone's in-flight state and reconciling its
//! threshold-gated sub-state (see `ZoneScreenState::reconcile_substate`),
//! preserving the exact pre-#4969 retention/reset behaviour. String keys are
//! retained for now; numeric zone-id keying is deferred to #4421.
//!
//! ## Source-independent screen single-sourcing (#6238)
//!
//! Two entry points enforce the SOURCE-INDEPENDENT screens:
//! `check_packet_with_zone_id_opts` (a packet with a real transport flow) and
//! `check_flowless_screens_opts` (a non-first IP fragment / non-query ICMP
//! control message that parses flowless, #2344/#3290). They historically
//! HAND-MIRRORED the same checks in the same order, and a divergence between
//! them was the fail-open class that bit #3902 (the flowless path once ran
//! only the three fragment screens, bypassing source-route + the flood
//! counters). Two helpers now single-source the shared orchestration so a
//! future addition covers BOTH paths by construction:
//!
//! - [`stateless::check_fragment_and_route`] — the already-contiguous common
//!   stateless tail: ping-of-death → teardrop → icmp-fragment → source-route.
//!   Both paths call it at the SAME precedence slot.
//! - [`ZoneScreenState::enforce_common_rate_floods`] — the common ICMP-flood
//!   then UDP-flood block, called right after each path's fabric
//!   `skip_rate_flood` gate.
//!
//! Deliberately NOT unified (a mega-helper would flip drop precedence, and the
//! reason string selects the per-reason drop-counter ordinal via
//! [`screen_reason_drop_index`], so a flip is operationally observable):
//!
//! - **LAND** stays a per-call at each site — UNCONDITIONAL on the full path,
//!   `addrs_known`-gated on the flowless path — and on the full path it runs
//!   BEFORE the TCP-flag screens. Folding it into the shared tail would drop
//!   the flowless guard or reorder it across the TCP-flag screens.
//! - **TCP-flag screens** and the whole **SYN-flood / SYN-cookie** block are
//!   full-path only. The TCP-flag screens are INTERPOSED between LAND and the
//!   shared tail on the full path and stay in place immediately before it.
//!
//! The full drop precedence is therefore, on the full path: LAND → TCP-flags →
//! [fragment/route tail] → fabric-skip → [ICMP/UDP flood] → SYN-flood; and on
//! the flowless path: LAND(`addrs_known`) → [fragment/route tail] →
//! fabric-skip → [ICMP/UDP flood] → Pass. `skip_rate_flood` and LAND remain
//! residual per-path mirrors; the extraction narrows the mirror surface, it
//! does not eliminate it (issue #6238; the accepted-design plan lives on the
//! `research/6238-unify-source-independent-screen` branch).
//!
//! ## Two-phase SYN-flood gate (#6437)
//!
//! The full-path SYN-flood / SYN-cookie enforcement block itself is extracted
//! to [`ZoneScreenState::syn_flood_gate`] (`zone.rs`): PHASE 1 performs every
//! zone-local mutation (aggregate counter → per-destination cap → aggregate
//! verdict → alarm cadence → per-source cap, the #3315/#4112 F19 order) and
//! returns an owned `SynFloodGate`; this function's PHASE 2 applies the
//! whole-`ScreenState` side effects (validated-cache consume is PHASE 0;
//! diagnostic counters, `syn_alarm_pending`, and the cookie mint are PHASE 2)
//! after the `zones` borrow is released. Drop precedence, reason strings (and
//! therefore the `screen_reason_drop_index` ordinals), the count-min sketch
//! semantics, the #3527 half-open `tcp_opening_ns` override consumers, and the
//! SYN-cookie interaction are all unchanged — pure code motion.

use rustc_hash::FxHashMap;
use std::time::{SystemTime, UNIX_EPOCH};

mod extract;
mod packet;
mod rate;
mod scan;
mod stateless;
mod syn_rate;
mod syncookie;
mod unresolved;
mod zone;

pub(crate) use extract::extract_screen_info;
pub(crate) use packet::{ScreenPacketInfo, ScreenProfile, ScreenVerdict};
pub(crate) use unresolved::InertProfileRef;
// `ScreenParseError` is named only by `extract.rs` (via the `packet`
// path) and by the test module. Production call sites in `afxdp/`
// consume the error by calling `.screen_reason()` on the value returned
// from `extract_screen_info`, so the crate-wide re-export is test-only
// (#2189 removed the last non-test consumer in `afxdp/mod.rs`).
#[cfg(test)]
pub(crate) use packet::ScreenParseError;
pub(crate) use syncookie::{
    SYN_COOKIE_MSS_VALUES, SynCookieAckVerdict, SynCookieChallenge, SynCookieCodec,
    SynCookieClientKey, SynCookieKeyRing, SynCookieTuple, SynCookieValidation,
};

// Test-only re-exports — screen/tests.rs constructs SipHash24 and
// SynCookieValidatedCache directly in vector / eviction tests and
// inspects bit-layout constants when validating the cookie codec
// output. Production builds never see these symbols outside the
// crypto submodule (they are imported via `use syncookie::...`
// below for `ScreenState` to use, but not re-exported except under
// `cfg(test)`).
#[cfg(test)]
pub(crate) use syncookie::{
    SYN_COOKIE_EPOCH_MASK, SYN_COOKIE_EPOCH_SHIFT, SYN_COOKIE_ISN_BITS, SYN_COOKIE_LAYOUT_BITS,
    SYN_COOKIE_MSS_MASK, SYN_COOKIE_MSS_SHIFT, SipHash24, SynCookieValidatedCache,
};

/// #3343: number of per-screen-reason DROP counters published to the Go
/// control plane. Each ordinal maps 1:1 to a `GlobalCtrScreen*` index on the
/// Go side (`pkg/dataplane.ScreenReasonCounters`, which is a fixed-size array
/// of exactly this many entries). The wire array `BindingStatus.screen_reason_drops`
/// carries one u64 per ordinal; the committed `tests/fixtures/protocol_wire_v1.json`
/// fixture pins the length so a divergence between the two sides fails the
/// `wire_invariant_default_specimens` test.
pub(crate) const SCREEN_REASON_DROP_COUNT: usize = 15;

/// Map a screen DROP reason string to its published per-reason counter ordinal
/// (#3343), or `None` for reasons that are surfaced only through the aggregate
/// `screen_drops` counter (SYN-cookie challenge/validation drops,
/// ICMP-fragment, IP-malformed parse-error). The ordinal order MUST stay in
/// lockstep with `pkg/dataplane.ScreenReasonCounters`. The two `session-limit-*`
/// reasons fold onto the single `session-limit` ordinal because the Go side
/// exposes one combined `GlobalCtrScreenSessionLimit` counter.
#[inline]
pub(crate) fn screen_reason_drop_index(reason: &str) -> Option<usize> {
    Some(match reason {
        "syn-flood" => 0,
        "icmp-flood" => 1,
        "udp-flood" => 2,
        "port-scan" => 3,
        "ip-sweep" => 4,
        "land-attack" => 5,
        "ping-of-death" => 6,
        "teardrop" => 7,
        "tcp-syn-fin" => 8,
        "tcp-no-flag" => 9,
        "tcp-fin-no-ack" => 10,
        "winnuke" => 11,
        "ip-source-route" => 12,
        "syn-frag" => 13,
        "session-limit-src" | "session-limit-dst" => 14,
        _ => return None,
    })
}

use crate::tcp_flags::{is_closing, is_initial_syn};
use packet::{PROTO_TCP, TCP_ACK, TCP_SYN};
// #2151: production screen no longer references these directly (the
// FIN/closing checks moved to is_closing); the screen test module still
// builds flag bytes with the named bits, so keep them test-visible.
// #6437: the ICMP/UDP protocol constants moved to `zone.rs` with the flood
// helpers; they stay test-visible here for the relocated test module.
#[cfg(test)]
use packet::{PROTO_ICMP, PROTO_ICMPV6, PROTO_UDP, TCP_FIN, TCP_URG};
use rate::RateCounter;
#[cfg(test)]
use rate::TokenBucket;
use scan::{IpSweepTracker, PortScanTracker};
#[cfg(test)]
use syn_rate::SynRateSketch;
use syncookie::SYN_COOKIE_STANDBY_ACK_VALIDATION_RATE_LIMIT_PER_SEC;
#[cfg(not(test))]
use syncookie::SynCookieValidatedCache;
use zone::{SynFloodGate, ZoneScreenState};

/// Global screen state: one consolidated per-zone map plus the cross-zone
/// SYN-cookie machinery, per-IP scan/sweep trackers, missing-profile
/// bookkeeping, and per-worker diagnostic counters.
pub(crate) struct ScreenState {
    /// zone_name -> consolidated per-zone screen state (#4969). Single source
    /// of truth for a zone's screen configuration AND its hot flood/cookie
    /// state, so a screened packet does one lookup and a configured limiter can
    /// never be silently absent. `has_profiles`/enumeration read `.profile`.
    zones: FxHashMap<String, ZoneScreenState>,
    // --- Global SYN-cookie machinery (NOT per-zone) ---
    syn_cookie_codec: Option<SynCookieCodec>,
    /// #9173: key bases that derive each rotation period's key; consulted only
    /// while `syn_cookie_codec` (the legacy key) is present, so a cleared key
    /// still fails closed.
    syn_cookie_key_ring: SynCookieKeyRing,
    syn_cookie_validated: SynCookieValidatedCache,
    syn_cookie_last_full_epoch: u64,
    /// #3032: Unix wall-clock seconds cached for SYN-cookie epoch math,
    /// refreshed at most once per monotonic second (see
    /// `current_syn_cookie_full_epoch`) so the SYN-flood hot path does not
    /// read the OS clock per packet.
    syn_cookie_epoch_wall_secs: u64,
    /// #3032: the monotonic second at which `syn_cookie_epoch_wall_secs` was
    /// last refreshed. `u64::MAX` is the "never refreshed" sentinel so the
    /// first cookie mint/validate always samples the wall clock.
    syn_cookie_epoch_clock_mono_secs: u64,
    #[cfg(test)]
    syn_cookie_full_epoch_override: Option<u64>,
    // Advanced screen trackers (shared across all zones since they track per-IP)
    port_scan: PortScanTracker,
    ip_sweep: IpSweepTracker,
    last_cleanup_secs: u64,
    /// #3082: zone → name of a screen profile the zone REFERENCES but that was
    /// undefined when the snapshot was built (lenient/HA-sync path). A zone in
    /// this map but absent from `zones` is enforced against the #7168
    /// SUBSTITUTED conservative default — the `None` branch of
    /// `check_packet_with_zone_id` distinguishes it from a zone with no screen
    /// configured, emits a rate-limited runtime WARN, and evaluates the
    /// malformed-packet subset rather than passing outright. Kept
    /// SEPARATE from `zones` (#4969): its keys are zones that have NO resolved
    /// profile, so they never appear in `zones` and folding them in would muddy
    /// the "one value per configured zone" invariant.
    missing_profile_refs: FxHashMap<String, String>,
    /// #7888: zone -> profile name for zones whose screen profile IS DEFINED
    /// but enables no check (the #7059 third state). A zone in this map is
    /// enforced against the SAME #7168 substituted conservative default as an
    /// undefined reference, and emits its OWN runtime WARN text.
    ///
    /// Deliberately a SECOND map rather than a flag inside
    /// `missing_profile_refs`. The verdict is identical for both, but the WARN
    /// text is not, and one map holding both states would make that text
    /// undecidable at the point it is emitted -- which is the defect #7888
    /// exists to fix, reintroduced one layer down. With two maps the three
    /// states are read off membership directly, and the legitimate silent
    /// `Pass` is "in NEITHER map".
    ///
    /// The two are disjoint by construction: the Go builders each skip the
    /// other's case. Should a malformed or future sender ever put a zone in
    /// both, `unresolved_screen_kind` resolves Undefined first -- the verdict
    /// is the same either way, so only the WARN wording is affected.
    ///
    /// #9425: the value carries the profile's `alarm-without-drop` alongside
    /// its name (see `InertProfileRef`), because an inert zone has no `zones`
    /// entry and this map is the ONLY place the operator's audit request
    /// survives for it.
    inert_profile_refs: FxHashMap<String, InertProfileRef>,
    /// #3082: per-zone rate counter that bounds the missing-profile WARN to
    /// `MISSING_PROFILE_WARN_RATE_LIMIT_PER_SEC` per zone so a flood of packets
    /// to a misconfigured zone cannot spam the log (CLAUDE.md log-flood rule).
    missing_profile_warn_counters: FxHashMap<String, RateCounter>,
    /// #7888: the inert-profile WARN's own per-zone rate counters. Separate
    /// from `missing_profile_warn_counters` so each set's `retain` on config
    /// update cannot evict the other's counters.
    inert_profile_warn_counters: FxHashMap<String, RateCounter>,
    /// #3082: count of WARNs actually emitted (post rate-limit). Test seam so a
    /// unit test can assert the WARN path was taken without scraping stderr.
    missing_profile_warn_count: u64,
    /// #7888: count of inert-profile WARNs actually emitted (post rate-limit).
    /// Test seam, and separately assertable from the missing-profile count so
    /// a test can prove the RIGHT warning fired, not merely that one did.
    inert_profile_warn_count: u64,
    /// #7168: packets DROPPED by the conservative default substituted for an
    /// unresolved screen reference. Distinct from the ordinary screen drop
    /// counters on purpose: a drop here means a zone whose real profile never
    /// resolved is being protected by the substitute, which is a configuration
    /// fault being masked. Counting it separately is what stops the masking
    /// from being silent — the substitution keeps traffic safe, but the
    /// operator still has a broken screen reference to fix.
    substituted_default_drops: u64,
    /// #3315: set when the just-checked packet crossed `alarm-threshold` (below
    /// attack-threshold) and the per-zone cadence admits a new alarm. Drained by
    /// `take_syn_alarm_event()` at the poll stage (which has the packet/zone in
    /// scope to emit the out-of-band alarm event). The verdict is NOT a drop.
    syn_alarm_pending: bool,
    /// #3315: sub-attribution test seams (per-worker). The drop verdict reuses
    /// the existing `"syn-flood"` reason id (no Go gRPC/CLI change), so these
    /// counters let tests assert WHICH sub-threshold tripped without scraping
    /// the event stream. Surfacing them on `show security screen` is a tracked
    /// follow-up; the drops are already counted via `screen_drops` and emit a
    /// `syn-flood` event, and the alarm emits a `syn-flood-alarm` event.
    syn_flood_dst_drops: u64,
    syn_flood_src_drops: u64,
    syn_flood_alarm_events: u64,
    /// Count of screen DROP verdicts SUPPRESSED because the ingress zone's
    /// profile is in `alarm-without-drop` (audit/log-only) mode: the packet
    /// forwarded and a log-only alarm event was raised instead. Bumped by the
    /// verdict consumers (`poll_stages`/`poll_descriptor`) via
    /// `record_alarm_without_drop`. Like `syn_flood_alarm_events` this is a
    /// per-worker test/diagnostic seam — the production signal is the emitted
    /// screen ALARM event; surfacing it on `show security screen` is a tracked
    /// follow-up.
    alarm_without_drop_events: u64,
}

/// #3082: at most one missing-screen-profile WARN per zone per second.
const MISSING_PROFILE_WARN_RATE_LIMIT_PER_SEC: u32 = 1;

/// Nanoseconds per second. Used by the second-granularity convenience wrappers
/// (`check_packet` / `check_packet_with_zone_id` / `check_flowless_screens`) to
/// derive a monotonic-ns value for the token-bucket consumers from `now_secs`.
/// The production dataplane path threads the real batch-cached `loop_now_ns`
/// through the `_opts` variants instead (#3607), so the token buckets get
/// sub-second resolution where the #2937 micro-burst bound matters.
const NANOS_PER_SEC: u64 = 1_000_000_000;

impl ScreenState {
    pub fn new() -> Self {
        Self {
            zones: FxHashMap::default(),
            syn_cookie_codec: None,
            syn_cookie_key_ring: SynCookieKeyRing::default(),
            syn_cookie_validated: SynCookieValidatedCache::default(),
            syn_cookie_last_full_epoch: 0,
            syn_cookie_epoch_wall_secs: 0,
            syn_cookie_epoch_clock_mono_secs: u64::MAX,
            #[cfg(test)]
            syn_cookie_full_epoch_override: None,
            port_scan: PortScanTracker::default(),
            ip_sweep: IpSweepTracker::default(),
            last_cleanup_secs: 0,
            missing_profile_refs: FxHashMap::default(),
            inert_profile_refs: FxHashMap::default(),
            missing_profile_warn_counters: FxHashMap::default(),
            inert_profile_warn_counters: FxHashMap::default(),
            missing_profile_warn_count: 0,
            inert_profile_warn_count: 0,
            substituted_default_drops: 0,
            syn_alarm_pending: false,
            syn_flood_dst_drops: 0,
            syn_flood_src_drops: 0,
            syn_flood_alarm_events: 0,
            alarm_without_drop_events: 0,
        }
    }

    /// #3082: number of missing-profile WARNs actually emitted (post
    /// rate-limit). Test seam.
    #[cfg(test)]
    /// #7168: packets dropped by the substituted conservative default.
    pub(crate) fn substituted_default_drops(&self) -> u64 {
        self.substituted_default_drops
    }

    pub(crate) fn missing_profile_warn_count(&self) -> u64 {
        self.missing_profile_warn_count
    }

    /// #7888: number of inert-profile WARNs actually emitted (post rate-limit).
    /// Test seam, separate from `missing_profile_warn_count` so a test can
    /// assert WHICH warning fired rather than that some warning did.
    pub(crate) fn inert_profile_warn_count(&self) -> u64 {
        self.inert_profile_warn_count
    }

    /// Replace all screen profiles (called on config update).
    ///
    /// #4969: rebuild the consolidated `zones` map from the incoming profiles.
    /// A zone present in BOTH the old and new config carries over its in-flight
    /// mutable flood/cookie state (aggregate counters, cookie active-until,
    /// standby budget, profile generation, alarm cadence, and any
    /// still-configured per-destination/per-source sketch) via
    /// `ZoneScreenState::reconcile_substate`; a zone removed from the config is
    /// dropped entirely (memory tracks live config). This preserves the exact
    /// pre-#4969 retention/reset behaviour — previously ~13 parallel `retain` +
    /// `or_insert` passes — as a single per-zone rebuild, and makes the
    /// "configured limiter always has its sub-state" property hold by
    /// construction rather than by prepopulation discipline.
    pub fn update_profiles(&mut self, profiles: FxHashMap<String, ScreenProfile>) {
        let mut old_zones = std::mem::take(&mut self.zones);
        let mut new_zones = FxHashMap::default();
        new_zones.reserve(profiles.len());
        for (zone, profile) in profiles {
            let new_sig = Self::syn_cookie_profile_signature(&profile);
            let zstate = match old_zones.remove(&zone) {
                Some(mut old) => {
                    // Zone persists: carry over live mutable state, reconciling
                    // the threshold-gated sub-state against the new profile.
                    // #2446: bump the SYN-cookie profile generation when a
                    // SYN-cookie-relevant field changes — only `syn_cookie` and
                    // `syn_flood_threshold` gate the validated cache, so
                    // unrelated edits (teardrop, port-scan, …) do NOT churn it.
                    let old_sig = Self::syn_cookie_profile_signature(&old.profile);
                    if old_sig != new_sig {
                        old.syn_cookie_profile_gen = old.syn_cookie_profile_gen.wrapping_add(1);
                    }
                    old.profile = profile;
                    old.reconcile_substate();
                    old
                }
                None => {
                    // New zone: fresh state from the profile. The pre-#4969
                    // parallel maps bumped a brand-new zone's generation from 0
                    // to 1 (`old_sig` None != `Some(new_sig)`); match that so a
                    // cookie validated before a same-name zone is (re-)created
                    // is treated as a miss under the new generation.
                    let mut z = ZoneScreenState::from_profile(profile);
                    z.syn_cookie_profile_gen = z.syn_cookie_profile_gen.wrapping_add(1);
                    z
                }
            };
            new_zones.insert(zone, zstate);
        }
        self.zones = new_zones;
    }

    /// #3315: drain a pending SYN-flood alarm. Returns true at most once per
    /// second per zone (the cadence is enforced at set-time in the SYN check).
    /// The poll stage calls this immediately after `check_packet_with_zone_id`
    /// — where the packet/zone are in scope — to emit the out-of-band alarm
    /// event. The packet still forwards (the alarm is log-only, not a drop).
    pub fn take_syn_alarm_event(&mut self) -> bool {
        let pending = self.syn_alarm_pending;
        self.syn_alarm_pending = false;
        pending
    }

    /// True when the ingress zone's screen profile is in Junos
    /// `alarm-without-drop` (audit/log-only) mode. The verdict consumers
    /// (`poll_stages`/`poll_descriptor`) query this AFTER a `ScreenVerdict::Drop`
    /// (or the flow-path `SynCookieChallenge`) to decide whether to suppress the
    /// packet drop and raise a log-only alarm instead. An absent profile (no
    /// screen configured for the zone) returns false — a zone with no profile
    /// never produces a drop verdict in the first place.
    ///
    /// #9425: the `zones` lookup is NOT sufficient on its own. A zone whose
    /// profile is DEFINED but enables no check is INERT: it gets no `zones`
    /// entry (`buildScreenSnapshots`'s `enforcesAnyCheck` gate skips it), yet
    /// since #7888 it DOES produce drop verdicts — `missing_profile_verdict`
    /// substitutes `conservative_default()` and drops the malformed-packet set.
    /// So the resolved lookup missed exactly where a verdict existed to
    /// suppress, and an operator who wrote
    /// `set security screen ids-option p alarm-without-drop` and nothing else
    /// — the single most likely route into the inert state, and an explicit
    /// request for audit mode — received the exact inverse of what they asked
    /// for, on a commit that reported success with zero warnings.
    ///
    /// Honouring the flag here changes only the TERMINAL DISPOSITION. The
    /// substituted checks still run and still count (`substituted_default_drops`
    /// is incremented before the verdict is returned), and the consumers turn
    /// the Drop into a log-only alarm plus a forward. #7888's decision — do not
    /// silently PASS an inert zone — is untouched; that was drop-over-pass, and
    /// this is alarm-over-drop.
    ///
    /// The UNDEFINED set is deliberately not consulted: there is no profile to
    /// have carried the modifier, so there is no operator statement to honour.
    #[inline]
    pub(crate) fn alarm_without_drop(&self, zone: &str) -> bool {
        if let Some(z) = self.zones.get(zone) {
            return z.profile.alarm_without_drop;
        }
        self.inert_profile_refs
            .get(zone)
            .is_some_and(|r| r.alarm_without_drop)
    }

    /// Record one screen drop SUPPRESSED by `alarm-without-drop` mode (the
    /// packet forwarded and a log-only alarm was emitted instead). Called by the
    /// verdict consumers once per suppressed drop.
    #[inline]
    pub(crate) fn record_alarm_without_drop(&mut self) {
        self.alarm_without_drop_events = self.alarm_without_drop_events.wrapping_add(1);
    }

    /// #3315: sub-attribution test seams (per-destination / per-source drops,
    /// alarm events). Used by unit tests to assert WHICH SYN-flood sub-threshold
    /// tripped without scraping the event stream.
    #[cfg(test)]
    pub(crate) fn syn_flood_dst_drops(&self) -> u64 {
        self.syn_flood_dst_drops
    }
    #[cfg(test)]
    pub(crate) fn syn_flood_src_drops(&self) -> u64 {
        self.syn_flood_src_drops
    }
    #[cfg(test)]
    pub(crate) fn syn_flood_alarm_events(&self) -> u64 {
        self.syn_flood_alarm_events
    }
    /// Test seam: count of drops suppressed by `alarm-without-drop` mode.
    #[cfg(test)]
    pub(crate) fn alarm_without_drop_events(&self) -> u64 {
        self.alarm_without_drop_events
    }

    /// #2446: the SYN-cookie-relevant slice of a zone profile. Two profiles
    /// with the same signature are interchangeable for the validated-ACK
    /// cache: a tuple validated under one may bypass the SYN-flood counter
    /// under the other without changing the security posture. Any change here
    /// bumps the zone's profile generation and invalidates its cached
    /// validations. `(syn_cookie, syn_flood_threshold)` — NOT the stateless
    /// screens, scan/sweep, or other flood thresholds, which never gate the
    /// validated cache.
    fn syn_cookie_profile_signature(profile: &ScreenProfile) -> (bool, u32) {
        (profile.syn_cookie, profile.syn_flood_threshold)
    }

    /// #2446: current SYN-cookie profile generation for a zone (0 if the zone
    /// has no profile or has never been configured). Stamped into validated-
    /// cache entries on insert and compared on consume.
    fn syn_cookie_profile_gen(&self, zone: &str) -> u64 {
        self.zones.get(zone).map_or(0, |z| z.syn_cookie_profile_gen)
    }

    /// Publish the cluster-wide SYN-cookie master key into this worker's screen
    /// state. Production snapshots derive this key from committed config and
    /// the cookie epoch is based on Unix wall-clock seconds, so HA peers use
    /// the same epoch/MAC material across failover when clocks are in sync.
    /// `None` still clears the codec and validated-client cache fail-closed.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn update_syn_cookie_master_key(&mut self, master_key: Option<[u8; 16]>) {
        if let Some(master_key) = master_key {
            let codec = SynCookieCodec::new(master_key);
            self.syn_cookie_validated
                .set_hash_keys(codec.cache_hash_keys());
            self.syn_cookie_codec = Some(codec);
        } else {
            self.syn_cookie_codec = None;
            self.syn_cookie_validated.clear();
        }
    }

    /// #9173: install the legacy key and the key ring (its bases) together, as
    /// every snapshot delivery does. Only the legacy key sets the validated-client
    /// cache hash keys, and `set_hash_keys` clears the cache only when they change.
    /// A snapshot newly built in a later period carries that period's key and so
    /// clears it; a republish of the last snapshot keeps its key, and rotation
    /// between snapshots (`SynCookieKeyRing::refresh`) is local, so neither does.
    /// Entries live one 64-second cookie epoch, so the cost is a re-challenge.
    pub(crate) fn update_syn_cookie_keys(
        &mut self,
        master_key: Option<[u8; 16]>,
        ring: SynCookieKeyRing,
    ) {
        self.update_syn_cookie_master_key(master_key);
        self.syn_cookie_key_ring = ring;
    }

    /// Current SYN-cookie full epoch, latched non-decreasing (SynCookieKeyRing::latch).
    ///
    /// `mono_now_secs` is the batch-cached `CLOCK_MONOTONIC` second already
    /// threaded into `check_packet_with_zone_id` / the standby-ACK path. It
    /// is used ONLY as a once-per-second refresh gate (#3032): the actual
    /// epoch is derived from a cached *Unix wall-clock* sample, not from
    /// `mono_now_secs`. The monotonic clock is unsuitable as the epoch input
    /// because HA peers have unrelated monotonic bases — the wall clock is
    /// the shared (NTP-synced) domain that lets a cookie minted on one node
    /// validate on its peer. The OS wall clock is read at most once per
    /// monotonic second, so a SYN flood no longer pays `SystemTime::now()`
    /// per packet (every cookie in the same second shares one 64s epoch).
    fn current_syn_cookie_full_epoch(&mut self, mono_now_secs: u64) -> u64 {
        #[cfg(test)]
        if let Some(epoch) = self.syn_cookie_full_epoch_override {
            self.syn_cookie_key_ring.refresh(epoch);
            return epoch;
        }
        if self.syn_cookie_epoch_clock_mono_secs != mono_now_secs {
            self.syn_cookie_epoch_wall_secs = Self::read_unix_wall_secs();
            self.syn_cookie_epoch_clock_mono_secs = mono_now_secs;
        }
        let epoch = SynCookieCodec::current_full_epoch(self.syn_cookie_epoch_wall_secs);
        // #9173: non-decreasing (SynCookieKeyRing::latch), which also derives
        // this period's keys.
        self.syn_cookie_last_full_epoch = self
            .syn_cookie_key_ring
            .latch(self.syn_cookie_last_full_epoch, epoch);
        self.syn_cookie_last_full_epoch
    }

    /// Read Unix wall-clock seconds. The single OS-clock read behind the
    /// SYN-cookie epoch (#3032); kept off the per-packet leaf
    /// (`SynCookieCodec::current_full_epoch`, which is pure).
    fn read_unix_wall_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    }

    #[cfg(test)]
    fn set_syn_cookie_full_epoch_for_test(&mut self, full_epoch: u64) {
        self.syn_cookie_full_epoch_override = Some(full_epoch);
    }

    /// #4969: standby SYN-cookie ACK validation budget check — the per-zone
    /// `TokenBucket` now lives on `ZoneScreenState`. An absent zone (no profile)
    /// returns `true` (limited), preserving the pre-#4969 `unwrap_or(true)`.
    fn standby_syn_cookie_ack_validation_limited(&mut self, zone: &str, now_ns: u64) -> bool {
        self.zones
            .get_mut(zone)
            .map(|z| {
                z.syn_cookie_standby_ack_counter
                    .admit_is_over(now_ns, SYN_COOKIE_STANDBY_ACK_VALIDATION_RATE_LIMIT_PER_SEC)
            })
            .unwrap_or(true)
    }

    /// Returns true if any zone has a RESOLVED screen profile.
    ///
    /// Note what this deliberately does NOT include: a zone that references a
    /// profile which does not exist. Unresolved references live in
    /// `missing_profile_refs` and never touch `zones` (see
    /// `update_missing_profiles`), so this predicate answers "is there anything
    /// to enforce?" and nothing else. That is the right question for a
    /// short-circuit that skips ENFORCEMENT.
    ///
    /// It is the wrong question for a short-circuit that also skips the
    /// missing-profile WARN -- see `has_screen_state` (#6860).
    pub fn has_profiles(&self) -> bool {
        !self.zones.is_empty()
    }

    /// Returns true if this state has anything a screen stage needs to act on:
    /// a resolved profile to ENFORCE, or an unresolved reference to REPORT.
    ///
    /// #6860: `stage_screen_check` gated on `has_profiles()`, which consults
    /// only the resolved map. When a zone references a profile and NO profile
    /// resolves anywhere, the stage returned before either missing-profile WARN
    /// branch could run -- so the rate-limited runtime warning that #3082 and
    /// #3908 shipped never fired in the one configuration it was written for.
    ///
    /// The state is reachable only through the tolerant paths, which is exactly
    /// what makes the missing signal matter: strict commit rejects a dangling
    /// reference, so a zone left screening NOTHING can only arrive via a
    /// tolerant startup on an older or externally modified active.json, an HA
    /// config-sync from a schema-skewed peer, or a rolling-upgrade interval
    /// where the producing side does not emit the stanza. In every one of those
    /// the operator believes a screen profile is applied and none is, and the
    /// warning was the only thing that would have said so.
    ///
    /// Partial resolution was never affected: with one profile resolved,
    /// `has_profiles()` is already true and the WARN fires normally. This
    /// closes the all-or-nothing case only.
    /// #7888: the inert set counts too. A config whose ONLY screen reference is
    /// an inert one publishes no `zones` entry and no missing-profile ref, so
    /// without this arm the whole screen stage would be skipped for it and the
    /// substituted default would never run -- the same all-or-nothing hole
    /// #6860 closed for the undefined case.
    pub fn has_screen_state(&self) -> bool {
        !self.zones.is_empty()
            || !self.missing_profile_refs.is_empty()
            || !self.inert_profile_refs.is_empty()
    }

    /// Run all screen checks for a packet arriving on the given zone.
    /// Returns `ScreenVerdict::Pass` if the packet is clean, or
    /// `ScreenVerdict::Drop(reason)` if it should be dropped.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn check_packet(
        &mut self,
        zone: &str,
        pkt: &ScreenPacketInfo,
        now_secs: u64,
    ) -> ScreenVerdict {
        self.check_packet_with_zone_id(zone, 0, pkt, now_secs)
    }

    /// Run all screen checks with the stable numeric zone id available to
    /// SYN-cookie MACs. `check_packet` remains for callers/tests that do not
    /// need cookie mode.
    pub fn check_packet_with_zone_id(
        &mut self,
        zone: &str,
        zone_id: u16,
        pkt: &ScreenPacketInfo,
        now_secs: u64,
    ) -> ScreenVerdict {
        // Second-granularity convenience wrapper (tests / non-cookie callers):
        // derive a monotonic-ns value for the #3607 token-bucket consumers.
        // The production path calls `check_packet_with_zone_id_opts` directly
        // with the real batch `loop_now_ns`.
        let now_ns = now_secs.saturating_mul(NANOS_PER_SEC);
        self.check_packet_with_zone_id_opts(zone, zone_id, pkt, now_ns, now_secs, false)
    }

    /// As `check_packet_with_zone_id`, but `skip_rate_flood` suppresses the
    /// rate-based flood counters (icmp/udp/syn-flood + SYN-cookie) while still
    /// running the stateless per-packet screens.
    ///
    /// #4155: fabric-redirected traffic in a chassis cluster was already
    /// rate-screened on the ingress node before it crossed the fabric link.
    /// The RG owner must NOT re-run the rate counters on that same packet —
    /// re-counting double-counts it against the per-zone / per-destination
    /// flood thresholds, so a legit high-pps synced session can false-trip a
    /// flood Drop and defeat fabric cross-chassis forwarding
    /// (`docs/fabric-cross-chassis-fwd.md`). The caller passes
    /// `skip_rate_flood = (meta.meta_flags & FABRIC_INGRESS_FLAG) != 0`.
    pub fn check_packet_with_zone_id_opts(
        &mut self,
        zone: &str,
        zone_id: u16,
        pkt: &ScreenPacketInfo,
        now_ns: u64,
        now_secs: u64,
        skip_rate_flood: bool,
    ) -> ScreenVerdict {
        // #2209 perf: borrow the profile instead of cloning it. The
        // stateless/rate checks below read `self.profiles` immutably while
        // mutating disjoint per-zone counter fields (`icmp_counters`,
        // `syn_counters`, …) and the SYN-cookie sub-state — Rust's
        // disjoint-field borrow rules permit holding `&self.profiles[..]`
        // across `self.<other_field>.get_mut(..)`. The pre-#2209 per-packet
        // `ScreenProfile::clone()` was a convenience to dodge a borrow
        // conflict that does not actually exist; on the screen hot path it
        // was a full-struct copy on every screened packet. Helper methods
        // that need `&mut self` (SYN-cookie codec/epoch/validated-cache)
        // copy the small fields they need out of `*profile` first so the
        // immutable `profiles` borrow is not held across them.
        // #4969: ONE lookup for the whole screened packet. `zstate` holds the
        // profile AND every mutable per-zone flood/cookie counter, so the
        // stateless checks read `&zstate.profile` and the rate checks below
        // mutate disjoint sub-fields of the SAME value — no re-hashing the zone
        // name per check. The global SYN-cookie machinery (`syn_cookie_codec`,
        // `syn_cookie_validated`, the epoch cache) and the diagnostic counters
        // are DISJOINT `self` fields, so a `zstate` borrow coexists with a
        // `self.syn_cookie_validated`/`self.syn_flood_*` access. #6437: the
        // zone-local SYN-flood mutations live in `ZoneScreenState::syn_flood_gate`,
        // which returns an OWNED `SynFloodGate`, so the `zstate` borrow ends at
        // the gate call and the only whole-`self` method used below
        // (`current_syn_cookie_full_epoch`) — reached solely on the SYN-cookie
        // mint RETURN path — is borrow-trivial.
        let Some(zstate) = self.zones.get_mut(zone) else {
            // #3082 + #7168: no resolved profile for this zone. A zone with no
            // screen configured passes silently; a zone that REFERENCES a
            // missing profile gets the rate-limited WARN *and* is now evaluated
            // against the conservative default rather than passed outright
            // (#7168 replaced the deferred fail-open with a substitution — see
            // ScreenProfile::conservative_default).
            //
            // The full L3 addresses are known on the flow-present path, so LAND
            // is evaluated here.
            return self.missing_profile_verdict(zone, pkt, now_secs, true);
        };

        // --- Stateless checks (side-effect-free) ---
        if let Some(reason) = stateless::check_land(&zstate.profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }
        if let Some(reason) = stateless::check_tcp_flag_screens(&zstate.profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }
        // #6238: the common stateless tail (ping-of-death → teardrop →
        // icmp-fragment → source-route) shared with the flowless path, called
        // at the SAME precedence slot — immediately AFTER the full-only
        // TCP-flag screens and BEFORE the fabric-skip gate. Byte-identical to
        // the open-coded run it replaces (see `stateless::check_fragment_and_route`).
        if let Some(reason) = stateless::check_fragment_and_route(&zstate.profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }

        // #4155: fabric-redirected traffic was already rate-screened on the
        // ingress node before it crossed the fabric link. Skip the rate-based
        // flood counters (icmp/udp/syn-flood + SYN-cookie) so the same packet
        // is not counted a SECOND time against the per-zone / per-destination
        // flood thresholds on the RG owner. Re-counting would let a legit
        // high-pps synced session false-trip a flood Drop, dropping exactly
        // the traffic fabric cross-chassis forwarding exists to protect during
        // failback / asymmetric-routing windows (vSRX does not re-screen
        // fabric-forwarded traffic). The stateless per-packet screens above
        // already ran and are idempotent; only the RATE counters must fire
        // once, on the true ingress node. The per-destination flood sketches
        // (#4132) are left intact — this skips the re-count, it does not
        // disable the screen. A `SynCookieBypass` verdict is likewise
        // suppressed: a fabric-redirected SYN belongs to a session the peer
        // already admitted, so the owner mints no cookie challenge/bypass.
        if skip_rate_flood {
            return ScreenVerdict::Pass;
        }

        // --- Rate-based flood checks ---
        // Copy the two SYN scalars the caller-side phases need out of the
        // profile up front so the shared `&zstate.profile` borrow is released
        // before the mutable per-zone sub-field accesses below (the ICMP/UDP
        // flood helper, the SYN-flood gate, and the whole-`self` SYN-cookie
        // epoch call on the mint path). #4969: `zstate.profile` and the
        // mutable sub-fields are disjoint, but pulling the scalars up front —
        // BEFORE the rate mutation — keeps the borrow story trivial. #6238:
        // the ICMP/UDP flood thresholds are read inside
        // `enforce_common_rate_floods`, which owns the shared flood block.
        // #6437: the remaining SYN thresholds/flags (`alarm_without_drop`,
        // `syn_flood_{alarm,dst,src}_threshold`) are read inside
        // `ZoneScreenState::syn_flood_gate`, which owns the zone-local
        // enforcement mutations.
        let syn_flood_threshold = zstate.profile.syn_flood_threshold;
        let syn_cookie = zstate.profile.syn_cookie;
        // Scan/sweep moved to the new-flow hook (`scan_sweep_drop_on_new_flow`),
        // so the advanced trackers are not touched on this per-packet path
        // anymore (#2210).

        let mut syn_cookie_bypassed = false;

        // #6238: ICMP flood then UDP flood — the source-independent rate block
        // shared with the flowless path (`enforce_common_rate_floods`). Same
        // precedence, same reason strings, same per-destination-cap (PRIMARY) +
        // per-zone aggregate ceiling (SECONDARY) as before (#4112 F18); the
        // full-path SYN-flood block below is layered AFTER it, unchanged.
        // `pkt.dst_port` is passed through so the #4567 zero-port fold stays
        // inside `udp_flood_drop`.
        if let Some(reason) = zstate.enforce_common_rate_floods(pkt, now_ns) {
            return ScreenVerdict::Drop(reason);
        }

        // SYN flood: count TCP SYN (without ACK) per zone.
        //
        // #6437: the enforcement itself is the two-phase
        // `ZoneScreenState::syn_flood_gate` (`zone.rs`) — PHASE 1 mutates only
        // zone-local state in the #3315 + #4112 F19 order (aggregate →
        // per-destination → aggregate verdict → alarm cadence → per-source)
        // and returns an owned `SynFloodGate`; the match below is PHASE 2 and
        // applies the whole-`ScreenState` side effects. A validated returning
        // SYN-cookie client bypasses the gate entirely.
        if syn_flood_threshold > 0 && pkt.protocol == PROTO_TCP {
            let tf = pkt.tcp_flags;
            if is_initial_syn(tf) {
                // PHASE 0 — validated-cache consume. #4969: read the profile
                // generation from the held `zstate` (not
                // `self.syn_cookie_profile_gen(zone)`, which would borrow all
                // of `self` and conflict with the live `zstate`). The
                // validated cache is a DISJOINT `self` field, so
                // `self.syn_cookie_validated.take_valid(..)` coexists with the
                // `zstate` borrow.
                //
                // #9419: `contains_valid` (a PEEK on a source-scoped key),
                // not the old `take_valid` on the full 4-tuple. The
                // challenge path RSTs the client after a valid cookie ACK,
                // so the retry that is supposed to consume this entry
                // arrives from a NEW ephemeral port — a port-scoped,
                // single-use entry could never match it.
                let profile_gen = zstate.syn_cookie_profile_gen;
                let syn_cookie_validated = syn_cookie
                    && self.syn_cookie_validated.contains_valid(
                        zone_id,
                        profile_gen,
                        SynCookieClientKey::from_packet(pkt),
                        now_secs,
                    );
                if syn_cookie_validated {
                    syn_cookie_bypassed = true;
                } else {
                    // PHASE 1: the zone-local gate. `codec_available` snapshots
                    // the DISJOINT `self.syn_cookie_codec` presence flag so the
                    // gate can pick `MintChallenge` vs `DropCookieUnavailable`
                    // without borrowing the codec; nothing mutates the codec
                    // across the call, so a `MintChallenge` result still sees
                    // `Some` below. The gate returns an OWNED enum, so NLL
                    // releases the `zstate` borrow at the call — PHASE 2's
                    // whole-`self` applications (diagnostic counters,
                    // `syn_alarm_pending`, the `current_syn_cookie_full_epoch`
                    // mint path) are then borrow-trivial.
                    let codec_available = self.syn_cookie_codec.is_some();
                    match zstate.syn_flood_gate(pkt, now_ns, now_secs, codec_available) {
                        SynFloodGate::Admit { alarm } => {
                            if alarm {
                                self.syn_alarm_pending = true;
                                self.syn_flood_alarm_events =
                                    self.syn_flood_alarm_events.wrapping_add(1);
                            }
                        }
                        SynFloodGate::DropDst => {
                            self.syn_flood_dst_drops =
                                self.syn_flood_dst_drops.wrapping_add(1);
                            return ScreenVerdict::Drop("syn-flood");
                        }
                        SynFloodGate::DropAggregate => {
                            return ScreenVerdict::Drop("syn-flood");
                        }
                        SynFloodGate::DropCookieUnavailable => {
                            return ScreenVerdict::Drop("syn-cookie-unavailable");
                        }
                        SynFloodGate::DropSrc { alarm } => {
                            if alarm {
                                self.syn_alarm_pending = true;
                                self.syn_flood_alarm_events =
                                    self.syn_flood_alarm_events.wrapping_add(1);
                            }
                            self.syn_flood_src_drops =
                                self.syn_flood_src_drops.wrapping_add(1);
                            return ScreenVerdict::Drop("syn-flood");
                        }
                        SynFloodGate::MintChallenge => {
                            let Some(legacy_codec) = self.syn_cookie_codec else {
                                return ScreenVerdict::Drop("syn-cookie-unavailable");
                            };
                            let full_epoch = self.current_syn_cookie_full_epoch(now_secs);
                            // #9173: SynCookieKeyRing::mint_codec_or_legacy.
                            let Some(codec) = self
                                .syn_cookie_key_ring
                                .mint_codec_or_legacy(full_epoch, legacy_codec)
                            else {
                                return ScreenVerdict::Drop("syn-cookie-unavailable");
                            };
                            let cookie_isn = codec.mint_isn(
                                SynCookieTuple::from_packet(pkt),
                                zone_id,
                                full_epoch,
                                pkt.tcp_mss,
                            );
                            return ScreenVerdict::SynCookieChallenge(SynCookieChallenge {
                                cookie_isn,
                                peer_mss: pkt.tcp_mss,
                            });
                        }
                    }
                }
            }
        }

        // #2210: port-scan / IP-sweep are NOT evaluated here. They used to
        // run on this per-packet pre-session stage, so IP-sweep counted
        // EVERY packet — including mid-flow established TCP ACKs/data and
        // UDP — before the dataplane knew whether a session already
        // existed. A single legitimate high-fan-out client (one host with
        // live connections to many backends) would trip ip-sweep without
        // ever sending a probe, and the original #867 ACK-evasion contract
        // ("an ACK that matches a live session is not a sweep probe") was
        // lost. The scan/sweep mutation now lives in
        // `scan_sweep_drop_on_new_flow`, invoked from the new-flow /
        // session-MISS decision in `poll_descriptor` (the same hook that
        // owns the #2134 per-IP session-limit check), so only a genuinely
        // new flow counts toward a scan/sweep.

        // #2134: per-IP session limits are NOT checked here either, for the
        // same reason — they live at the new-flow / session-MISS decision in
        // `poll_descriptor`, where they fire exactly once per new flow
        // before that flow's session exists. See
        // `session::SessionTable::session_limit_{src,dst}_count` and the
        // count maintenance at the install/remove sinks.

        if syn_cookie_bypassed {
            ScreenVerdict::SynCookieBypass
        } else {
            ScreenVerdict::Pass
        }
    }

    /// #3064 + #3902: run the SOURCE-INDEPENDENT screens for a packet that
    /// has NO transport flow — a non-first IP fragment or a non-query
    /// ICMP/ICMPv6 control message that `parse_session_flow_from_bytes`
    /// deliberately leaves flowless (#2344, to avoid treating fragment
    /// payload as L4 ports; #3290, to avoid keying a session on a non-port
    /// ICMP control word). Every screen evaluated here is genuinely
    /// flow/session-INDEPENDENT — it reads only the L3 header (and per-zone
    /// rate counters keyed on protocol), never a per-flow tuple:
    ///
    ///   - **LAND anti-spoof** (`src_ip == dst_ip`): reads only the L3
    ///     addresses. The caller derives the REAL source/destination from
    ///     the IP header and sets `addrs_known`; when it could not (frame too
    ///     short to hold the addresses) LAND is skipped so a placeholder
    ///     `src == dst == unspecified` is not mistaken for a spoofed frame.
    ///   - **ping-of-death / teardrop / icmp-fragment** (#3064): the L3
    ///     fragment screens — fragment offset, total/payload length,
    ///     protocol only.
    ///   - **ip-source-route** (IPv4 LSRR/SSRR, IPv6 RH0/RH1): read from the
    ///     IP-header options / extension-header chain by `extract.rs`.
    ///   - **ICMP flood / UDP flood**: per-zone rate counters keyed purely
    ///     on protocol.
    ///
    /// Before #3902 the flowless branch ran ONLY the three fragment screens,
    /// so a crafted non-first fragment / non-query ICMP BYPASSED LAND,
    /// ip-source-route, and the ICMP/UDP flood counters (screen fail-open) —
    /// an attack the operator explicitly enabled the screen to block
    /// transited on the flowless path.
    ///
    /// Flow/session-dependent screens (TCP-flag bits, the SYN-flood
    /// per-source/per-destination sketches, scan/sweep, SYN-cookie) require
    /// a flow / real TCP header and stay gated on the flow-present
    /// `check_packet_with_zone_id` path. The drop precedence of the screens
    /// run here matches that method's relative order exactly (LAND →
    /// ping-of-death → teardrop → icmp-fragment → source-route → icmp-flood
    /// → udp-flood).
    ///
    /// When the zone has no resolved profile this mirrors the flow-present
    /// path's None branch (#3908): a zone that REFERENCES a screen profile
    /// undefined at snapshot-build time gets a rate-limited runtime WARN via
    /// `maybe_warn_missing_profile`, while a zone with no screen configured
    /// passes silently. The verdict is `Pass` in both cases (watch-log-only,
    /// no drop-behavior change — see the #3082 module note).
    pub(crate) fn check_flowless_screens(
        &mut self,
        zone: &str,
        pkt: &ScreenPacketInfo,
        addrs_known: bool,
        now_secs: u64,
    ) -> ScreenVerdict {
        // Second-granularity convenience wrapper; see `check_packet_with_zone_id`.
        let now_ns = now_secs.saturating_mul(NANOS_PER_SEC);
        self.check_flowless_screens_opts(zone, pkt, addrs_known, now_ns, now_secs, false)
    }

    /// As `check_flowless_screens`, but `skip_rate_flood` suppresses the
    /// source-independent rate-based flood counters (icmp/udp-flood) while
    /// still running the stateless source-independent screens.
    ///
    /// #4155: a fabric-redirected non-first fragment / non-query ICMP control
    /// message was already rate-screened on the ingress node; the RG owner
    /// must not re-count it. See `check_packet_with_zone_id_opts`.
    pub(crate) fn check_flowless_screens_opts(
        &mut self,
        zone: &str,
        pkt: &ScreenPacketInfo,
        addrs_known: bool,
        now_ns: u64,
        now_secs: u64,
        skip_rate_flood: bool,
    ) -> ScreenVerdict {
        // #4969: ONE lookup — `zstate` supplies the profile for the stateless
        // screens and the per-zone flood counters (via `icmp_flood_drop` /
        // `udp_flood_drop`) for the rate screens.
        let Some(zstate) = self.zones.get_mut(zone) else {
            // #3908: mirror the flow-present `check_packet_with_zone_id` None
            // branch so the flowless path is as observable as the flow path.
            // A zone that REFERENCES a screen profile undefined at
            // snapshot-build time (lenient/HA-sync fail-open) gets a
            // rate-limited runtime WARN; a zone with no screen configured
            // passes silently (the helper distinguishes the two). Verdict is
            // still Pass in BOTH cases — watch-log-only, no drop-behavior
            // change (the fail-closed-vs-pass posture is the deferred #3082
            // design decision). O(1): one hashmap lookup + a rate-limited
            // increment; no unwrap/panic on the hot flowless path.
            // #7168: substituted conservative default rather than a bare Pass.
            // `addrs_known` is forwarded so LAND is skipped when the caller had
            // no real L3 addresses, exactly as the resolved path below does.
            return self.missing_profile_verdict(zone, pkt, now_secs, addrs_known);
        };
        // --- Stateless, source-independent checks (side-effect-free) ---
        // LAND is address-dependent: only evaluate it when the caller
        // supplied the real L3 addresses (`addrs_known`).
        if addrs_known && let Some(reason) = stateless::check_land(&zstate.profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }
        // #6238: the SAME common stateless tail the flow-present path runs
        // (ping-of-death → teardrop → icmp-fragment → source-route), at the
        // SAME precedence slot — after the `addrs_known`-gated LAND and before
        // the fabric-skip gate. Single-sourcing this run is the anti-mirror
        // guarantee: a future addition to `check_fragment_and_route` covers
        // BOTH entry points by construction (the #3902 fail-open class).
        if let Some(reason) = stateless::check_fragment_and_route(&zstate.profile, pkt) {
            return ScreenVerdict::Drop(reason);
        }
        // #4155: fabric-redirected flowless traffic was already rate-screened
        // on the ingress node — skip the re-count (see
        // `check_packet_with_zone_id_opts`). Stateless source-independent
        // screens above already ran and are idempotent.
        if skip_rate_flood {
            return ScreenVerdict::Pass;
        }
        // --- Rate-based flood checks (source-independent, per-zone) ---
        // #6238: ICMP flood then UDP flood via the SAME shared block the
        // flow-present path runs, inserted at the SAME slot (right after the
        // fabric `skip_rate_flood` gate). Per-destination cap (PRIMARY) + per-zone
        // aggregate ceiling (SECONDARY), same as the flow-present path (#4112
        // F18). A flowless non-first fragment has no L4 port, so `dst_port` is 0
        // here; the helper passes it through UNCHANGED and `udp_flood_drop` folds
        // it into the per-destination-IP `increment(dst_ip)` bucket rather than a
        // stray `(ip, 0)` cell (#4567) — so no flowless-specific mode flag.
        if let Some(reason) = zstate.enforce_common_rate_floods(pkt, now_ns) {
            return ScreenVerdict::Drop(reason);
        }

        ScreenVerdict::Pass
    }

    /// #2210 + #2209: port-scan / IP-sweep evaluation at the NEW-FLOW
    /// decision, mirroring the #2134 session-limit-on-miss hook.
    ///
    /// This MUST be called only after the caller has determined the packet
    /// is a session MISS (no established session matched). That is what
    /// preserves the ACK-evasion contract: an established flow's mid-stream
    /// packets are session HITS and never reach this hook, so they never
    /// inflate the sweep counter (the #2210 false-positive root cause).
    /// port-scan additionally keeps its TCP-initial-SYN gate; IP-sweep
    /// counts the new flow on any protocol.
    ///
    /// State is keyed by `(zone_id, src_ip)` (per-zone, #2209) and bounded
    /// (per-zone source cap + per-source unique-entry cap, fail-safe on
    /// overflow — see `scan.rs`). Returns the screen-drop reason if the new
    /// flow crosses a threshold, or `None` to proceed. Cold path
    /// (session-miss only).
    pub fn scan_sweep_drop_on_new_flow(
        &mut self,
        zone: &str,
        zone_id: u16,
        pkt: &ScreenPacketInfo,
        now_micros: u64,
    ) -> Option<&'static str> {
        let Some(zstate) = self.zones.get(zone) else {
            return None;
        };
        // #4114: the Junos `threshold` is a MICROSECOND detection WINDOW (not a
        // count). The detection COUNT is the fixed `SCAN_DETECT_COUNT` in
        // `scan.rs`. `port_scan_threshold`/`ip_sweep_threshold` carry that
        // per-zone window (u32 us); 0 = the check is disabled.
        let port_scan_window = u64::from(zstate.profile.port_scan_threshold);
        let ip_sweep_window = u64::from(zstate.profile.ip_sweep_threshold);
        // `zstate` borrow ends here (NLL): the per-IP scan/sweep trackers are
        // global `&mut self` fields, reached below only after this point.
        if port_scan_window == 0 && ip_sweep_window == 0 {
            // Still tick the cleanup so a config with the feature briefly
            // enabled-then-disabled cannot strand tracker state.
            self.maybe_cleanup_trackers(now_micros);
            return None;
        }

        // Port scan: count unique dst ports per (zone, src) on initial SYN
        // within the configured microsecond window.
        if port_scan_window > 0
            && pkt.protocol == PROTO_TCP
            && is_initial_syn(pkt.tcp_flags)
            && self.port_scan.check(
                zone_id,
                pkt.src_ip,
                pkt.dst_port,
                now_micros,
                port_scan_window,
            )
        {
            self.maybe_cleanup_trackers(now_micros);
            return Some("port-scan");
        }

        // IP sweep: count unique dst IPs per (zone, src) for the new flow
        // (any protocol) within the configured microsecond window. Because
        // this only runs on a session MISS, an established flow's packets
        // never count.
        if ip_sweep_window > 0
            && self
                .ip_sweep
                .check(zone_id, pkt.src_ip, pkt.dst_ip, now_micros, ip_sweep_window)
        {
            self.maybe_cleanup_trackers(now_micros);
            return Some("ip-sweep");
        }

        self.maybe_cleanup_trackers(now_micros);
        None
    }

    /// Periodic (>=30s) budgeted cleanup of the scan/sweep trackers. Driven
    /// from the new-flow hook so it is co-located with the only site that
    /// mutates the trackers. `now_micros` is a monotonic microsecond clock;
    /// the 30s throttle derives seconds from it (#4114).
    ///
    /// #4379: the reap floor is WINDOW-AWARE. The `threshold` is a per-zone
    /// configurable MICROSECOND detection window that the compiler PRESERVES
    /// even above the Junos 1s max (warn-only, no clamp — see
    /// `pkg/config/compiler_security_screen.go`). A fixed 1s cleanup floor
    /// reaped an accumulating distinct-destination set before the detection
    /// count was reached for any operator window > 1s, so a slow scan spread
    /// across the operator's window EVADED detection (fail-open). Each tracker
    /// is reaped at the LONGEST window configured for its check across all live
    /// profiles, so state survives for the full configured window (the reap
    /// floor is clamped to a documented ceiling inside `cleanup` — #4418 raised
    /// that ceiling to the u32 `threshold` type maximum so it never bites a
    /// configurable window, closing the >5min residual; memory stays bounded by
    /// the per-source/zone caps regardless).
    fn maybe_cleanup_trackers(&mut self, now_micros: u64) {
        let now_secs = now_micros / 1_000_000;
        if now_secs.saturating_sub(self.last_cleanup_secs) >= 30 {
            let (port_scan_floor, ip_sweep_floor) = self.scan_cleanup_floors();
            self.port_scan.cleanup(now_micros, port_scan_floor);
            self.ip_sweep.cleanup(now_micros, ip_sweep_floor);
            self.last_cleanup_secs = now_secs;
        }
    }

    /// #4379: compute the window-aware cleanup reap floors — the LONGEST
    /// configured port-scan and ip-sweep detection windows (microseconds)
    /// across all live screen profiles. A tracker's state must survive for at
    /// least the longest window that could still detect a slow scan; reaping
    /// earlier (the pre-#4379 fixed 1s floor) discards an in-progress
    /// distinct-destination set and lets a slow scan evade detection. A window
    /// of 0 (feature disabled for that zone) contributes nothing; if every
    /// profile disables a check the floor is 0 and cleanup reclaims all of that
    /// tracker's now-idle state. `cleanup` clamps each floor to
    /// `MAX_CLEANUP_WINDOW_MICROS` (the u32 `threshold` type maximum, #4418) so
    /// a floor beyond any configurable window cannot retain dead weight
    /// indefinitely; a configured window is never clamped, so the >5min
    /// slow-scan evasion residual is closed.
    fn scan_cleanup_floors(&self) -> (u64, u64) {
        let mut port_scan_floor = 0u64;
        let mut ip_sweep_floor = 0u64;
        for zstate in self.zones.values() {
            port_scan_floor = port_scan_floor.max(u64::from(zstate.profile.port_scan_threshold));
            ip_sweep_floor = ip_sweep_floor.max(u64::from(zstate.profile.ip_sweep_threshold));
        }
        (port_scan_floor, ip_sweep_floor)
    }

    /// #2209: total scan/sweep records skipped because a per-zone source
    /// cap or per-source unique-entry cap was hit (fail-safe overflow
    /// pressure). Pure observability; never affects a verdict.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn scan_sweep_skipped_pressure(&self) -> u64 {
        self.port_scan.skipped_pressure() + self.ip_sweep.skipped_pressure()
    }

    /// #2234/#4418: total bounded evictions on the scan/sweep source-saturation
    /// path. A non-zero value means the per-zone source table hit its cap and
    /// the detector displaced the least-suspicious sources to keep a fresh real
    /// scanner trackable (it no longer silently drops new sources on a full
    /// table). Pure observability; never affects a verdict.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn scan_sweep_evicted_pressure(&self) -> u64 {
        self.port_scan.evicted_pressure() + self.ip_sweep.evicted_pressure()
    }

    /// #2234: returns `true` on a rare (logarithmic) eviction-rate threshold
    /// crossing, signalling the caller to emit a `scan-table-pressure` screen
    /// event so the operator is told the scan/sweep detector is saturated.
    /// Fires at most a handful of times under a sustained flood (powers of
    /// two in the cumulative eviction count) — NEVER per flow, honouring the
    /// no-per-packet-logging rule. The crossing is consumed on read.
    pub fn take_scan_table_pressure_event(&mut self) -> bool {
        // Evaluate BOTH so each tracker's epoch advances independently; the
        // `|` (not `||`) avoids short-circuiting the second take.
        let port = self.port_scan.take_pressure_event();
        let sweep = self.ip_sweep.take_pressure_event();
        port | sweep
    }

    /// Validate a returning SYN-cookie ACK only after the caller has already
    /// established that no normal session matched. This preserves established
    /// ACK traffic and prevents random ACKs from installing sessions while a
    /// cookie flood is active.
    pub fn validate_syn_cookie_ack_on_session_miss(
        &mut self,
        zone: &str,
        zone_id: u16,
        pkt: &ScreenPacketInfo,
        now_ns: u64,
        now_secs: u64,
    ) -> SynCookieAckVerdict {
        // #4969: one shared `zones` lookup for the profile applicability gate
        // AND the cookie active-until read. The borrow ends at `locally_active`
        // (a copied bool), before the whole-`self` epoch call below; the standby
        // budget and profile-gen reads later go through their own helpers (this
        // is the cold session-miss ACK path, not the per-packet hot path).
        let Some(zstate) = self.zones.get(zone) else {
            return SynCookieAckVerdict::NotApplicable;
        };
        if !zstate.profile.syn_cookie
            || zstate.profile.syn_flood_threshold == 0
            || pkt.protocol != PROTO_TCP
        {
            return SynCookieAckVerdict::NotApplicable;
        }
        let flags = pkt.tcp_flags;
        if (flags & TCP_ACK) == 0 || (flags & TCP_SYN) != 0 {
            return SynCookieAckVerdict::NotApplicable;
        }
        let locally_active = zstate.syn_cookie_active_until_secs > now_secs;
        if is_closing(flags) {
            return if locally_active {
                SynCookieAckVerdict::Invalid
            } else {
                SynCookieAckVerdict::NotApplicable
            };
        }
        let Some(legacy_codec) = self.syn_cookie_codec else {
            return if locally_active {
                SynCookieAckVerdict::Invalid
            } else {
                SynCookieAckVerdict::NotApplicable
            };
        };
        let cookie_isn = pkt.tcp_ack.wrapping_sub(1);
        let current_epoch = self.current_syn_cookie_full_epoch(now_secs);
        if !locally_active {
            if !SynCookieCodec::wire_epoch_matches_validation_window(current_epoch, cookie_isn) {
                return SynCookieAckVerdict::NotApplicable;
            }
            if self.standby_syn_cookie_ack_validation_limited(zone, now_ns) {
                return SynCookieAckVerdict::NotApplicable;
            }
        }
        // The cookie MAC binds the full 4-tuple (that is what makes the
        // cookie unforgeable for this connection); the whitelist it seeds is
        // source-scoped (#9419) because the client that comes back does so on
        // a different ephemeral port.
        let tuple = SynCookieTuple::from_packet(pkt);
        // #9173: the cookie is checked against the key for ITS OWN period
        // (SynCookieKeyRing::validates).
        let validated = SynCookieCodec::cookie_full_epoch(current_epoch, cookie_isn)
            .is_some_and(|full_epoch| {
                self.syn_cookie_key_ring
                    .validates(legacy_codec, tuple, zone_id, full_epoch, cookie_isn)
            });
        if validated {
            let profile_gen = self.syn_cookie_profile_gen(zone);
            self.syn_cookie_validated.insert(
                zone_id,
                profile_gen,
                SynCookieClientKey::from_packet(pkt),
                now_secs,
            );
            SynCookieAckVerdict::Validated
        } else if locally_active {
            SynCookieAckVerdict::Invalid
        } else {
            SynCookieAckVerdict::NotApplicable
        }
    }

    #[cfg(test)]
    fn syn_cookie_validated_len(&self) -> usize {
        self.syn_cookie_validated.len()
    }

    #[cfg(test)]
    fn syn_cookie_active_zone_count(&self) -> usize {
        // #4969: every configured zone carries a `syn_cookie_active_until_secs`
        // field by construction, so the configured-zone count IS the number of
        // zones (matching the pre-#4969 `syn_cookie_active_until_secs.len()`,
        // which had one prepopulated entry per profile zone).
        self.zones.len()
    }

    /// #3607: whole tokens still available in a zone's standby SYN-cookie ACK
    /// validation budget. Test seam replacing the old `RateCounter::count`
    /// accessor: `0` means the budget is fully spent for this instant.
    #[cfg(test)]
    fn syn_cookie_standby_ack_available(&self, zone: &str) -> u64 {
        self.zones
            .get(zone)
            .map(|z| z.syn_cookie_standby_ack_counter.available_tokens())
            .unwrap_or(0)
    }

    /// #3607: true if a zone's standby SYN-cookie ACK budget bucket has never
    /// been charged — i.e. the validate path rejected the ACK BEFORE reaching
    /// the standby limiter, so no SipHash budget was spent. Test seam.
    #[cfg(test)]
    fn syn_cookie_standby_ack_untouched(&self, zone: &str) -> bool {
        self.zones
            .get(zone)
            .map(|z| z.syn_cookie_standby_ack_counter.is_cold())
            .unwrap_or(true)
    }

    /// #4969: test seam — force a zone SYN-cookie-active until `until_secs`
    /// (replaces the pre-#4969 direct `syn_cookie_active_until_secs.insert`).
    #[cfg(test)]
    fn force_syn_cookie_active_for_test(&mut self, zone: &str, until_secs: u64) {
        if let Some(z) = self.zones.get_mut(zone) {
            z.syn_cookie_active_until_secs = until_secs;
        }
    }

    /// #4969: test seam — true iff a zone's per-DESTINATION / per-SOURCE
    /// SYN-flood sketch is allocated (present). Mirrors the pre-#4969
    /// `syn_dst_sketch.contains_key` / `syn_src_sketch.contains_key`.
    #[cfg(test)]
    fn syn_dst_sketch_present(&self, zone: &str) -> bool {
        self.zones.get(zone).is_some_and(|z| z.syn_dst_sketch.is_some())
    }
    #[cfg(test)]
    fn syn_src_sketch_present(&self, zone: &str) -> bool {
        self.zones.get(zone).is_some_and(|z| z.syn_src_sketch.is_some())
    }

    /// #4969: test seam — mutable access to a zone's per-DESTINATION UDP flood
    /// sketch (for the #4567 cell-saturation discriminator test). Panics if the
    /// zone or sketch is absent, matching the pre-#4969 `.get(...).unwrap()`.
    #[cfg(test)]
    fn udp_dst_sketch_mut_for_test(&mut self, zone: &str) -> &mut SynRateSketch<TokenBucket> {
        self.zones
            .get_mut(zone)
            .and_then(|z| z.udp_dst_sketch.as_mut())
            .expect("udp_dst_sketch present for a zone with udp_flood_threshold > 0")
    }

    /// Returns true if any zone has session limits, port scan, or IP sweep enabled.
    #[allow(dead_code)]
    pub fn has_advanced_features(&self) -> bool {
        self.zones.values().any(|z| {
            z.profile.session_limit_src > 0
                || z.profile.session_limit_dst > 0
                || z.profile.port_scan_threshold > 0
                || z.profile.ip_sweep_threshold > 0
        })
    }

    /// #2134: true iff any zone configures a per-IP session limit
    /// (`limit-session source-ip-based` / `destination-ip-based`). Drives
    /// the `SessionTable` session-limit OFF-gate so install/remove pay
    /// nothing when the feature is unconfigured. Separate from
    /// `has_advanced_features` (which also covers port-scan / ip-sweep,
    /// neither of which touches the SessionTable count).
    pub fn any_session_limit_configured(&self) -> bool {
        self.zones
            .values()
            .any(|z| z.profile.session_limit_src > 0 || z.profile.session_limit_dst > 0)
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
