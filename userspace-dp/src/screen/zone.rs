//! Per-zone screen state and its per-packet flood enforcement helpers.
//!
//! Split out of `screen/mod.rs` in #6437: `ZoneScreenState` (the #4969
//! consolidated per-zone value) plus every helper that mutates ONLY that one
//! zone's state — the ICMP/UDP flood admission helpers, the shared
//! source-independent rate-flood block (#6238), and the SYN-flood enforcement
//! gate (#3315/#4112 F19). `screen/mod.rs` keeps the cross-zone `ScreenState`
//! (the `zones` map, the global SYN-cookie machinery, the scan/sweep trackers,
//! and the diagnostic counters) and the two public check entry points.
//!
//! ## The two-phase SYN-flood gate (#6437)
//!
//! The SYN-flood enforcement mutates zone-local state (aggregate counter,
//! per-destination/per-source sketches, cookie active-until, alarm cadence,
//! cookie-OFF attack bucket) but its verdict also needs WHOLE-`ScreenState`
//! state the zone cannot borrow while a `&mut ZoneScreenState` is live: the
//! validated-client cache, the cookie codec + wall-clock epoch cache (a
//! whole-`self` method), and the per-worker diagnostic counters
//! (`syn_flood_dst_drops` / `syn_flood_src_drops` / `syn_alarm_pending` /
//! `syn_flood_alarm_events`). [`ZoneScreenState::syn_flood_gate`] is therefore
//! PHASE 1 only: it performs every zone-local mutation in the exact
//! historical order and returns an owned [`SynFloodGate`] describing the
//! verdict. The caller (`check_packet_with_zone_id_opts`) then runs PHASE 2 —
//! diagnostic-counter bumps, the pending-alarm flag, and the cookie mint —
//! after the gate call, when NLL has already released the `zones` borrow, so
//! the whole-`self` applications are borrow-trivial. The validated-cache peek
//! (a disjoint `ScreenState` field) stays in the caller as PHASE 0; #9945
//! validated hits still charge the aggregate and per-destination state.

use rustc_hash::FxHashMap;
use std::net::IpAddr;

use super::packet::{PROTO_ICMP, PROTO_ICMPV6, PROTO_UDP, ScreenPacketInfo, ScreenProfile};
use super::rate::{RateCounter, TokenBucket};
use super::syn_rate::SynRateSketch;
use super::syncookie::{SynCookieCodec, SynCookieZoneTag, syn_cookie_zone_tag};

/// #14635 secondary zone-wide SYN cookie-OFF ceiling multiplier (#4112).
const SYN_SECONDARY_CEILING_MULT: u32 = 8;

/// #4112: multiplier for the per-zone ICMP/UDP flood aggregate SECONDARY
/// ceiling. Junos measures the ICMP/UDP flood rate PER DESTINATION, so the
/// per-destination sketch (threshold `T`) is the PRIMARY cap. The per-zone
/// aggregate `RateCounter` is retained as a coarse zone-saturation backstop that
/// fires at `SECONDARY_FLOOD_CEILING_MULT × T`: a zone with up to this many
/// simultaneously-hot legitimate destinations (each under the per-destination
/// cap) is NOT false-dropped (the #4112 F18 fix — two legit high-volume services
/// no longer SUM into one counter), while a flood spread thin across many
/// destinations is still bounded zone-wide (an operator relying on the zone-wide
/// cap still gets it). The aggregate counts only per-destination-ADMITTED
/// packets (the per-destination check short-circuits first), so it bounds the
/// admitted zone-wide rate. There is no separate Junos knob for this ceiling, so
/// it is derived from the single configured per-destination threshold.
const SECONDARY_FLOOD_CEILING_MULT: u32 = 8;

/// #4969: consolidated per-zone screen state — the profile plus every HOT,
/// mutable per-packet flood/cookie datum for one zone, in a SINGLE value.
/// (Lives in `zone.rs` since #6437; the `zones` map itself stays in
/// `screen/mod.rs`.)
///
/// Before #4969 these lived in ~13 parallel `FxHashMap<String, _>` tables on
/// `ScreenState`, synchronised only by manual prepopulation/retention
/// discipline in `update_profiles`. That was fail-open by construction: a
/// missed prepopulation step silently turned a configured limiter into a
/// missing-entry default (`false`/`0`/Pass) on the screened path, and every
/// screened packet re-hashed the same zone name into several tables.
///
/// A `ZoneScreenState` is built by [`ZoneScreenState::from_profile`], which
/// initialises the profile AND all of its threshold-gated sub-state together,
/// so a configured zone can NEVER present a missing (fail-open) sub-state on
/// the screened path — refresh drift is impossible by construction, not by
/// discipline. A screened packet does ONE `zones` lookup and then touches
/// these fields directly.
///
/// Threshold-gated sketches are `Option`: `Some` iff the corresponding
/// threshold is configured (`> 0`). This preserves the "allocate only when
/// configured; memory tracks live config" behaviour while making
/// `Some ⟺ configured` a construction-time invariant.
pub(super) struct ZoneScreenState {
    /// Resolved screen profile for the zone (typed thresholds/flags).
    pub(super) profile: ScreenProfile,
    /// #4112 SECONDARY per-zone ICMP flood ceiling (checked at
    /// `SECONDARY_FLOOD_CEILING_MULT × threshold`). #3607: a monotonic-ns
    /// `TokenBucket` shaper so a sustained-at-ceiling zone is admitted.
    icmp_counter: TokenBucket,
    /// #4112 SECONDARY per-zone UDP flood ceiling (`TokenBucket` shaper).
    udp_counter: TokenBucket,
    /// #14635 PRIMARY per-(dst,port) count-all attack/alarm sketch.
    syn_attack_sketch: SynRateSketch<RateCounter>,
    /// #14635 PRIMARY per-(dst,port) cookie-OFF token-bucket drop sketch.
    syn_off_attack_sketch: SynRateSketch<TokenBucket>,
    /// #14635 SECONDARY zone-wide ceilings (8x threshold), count only
    /// per-dst admitted packets.
    syn_zone_counter: RateCounter,
    syn_zone_off_bucket: TokenBucket,
    /// #4112/#5805 per-DESTINATION-IP ICMP flood sketch (PRIMARY cap). `Some`
    /// iff `icmp_flood_threshold > 0`. Monotonic-ns `TokenBucket` cells.
    pub(super) icmp_dst_sketch: Option<SynRateSketch<TokenBucket>>,
    /// #4112/#5805 per-DESTINATION (IP+PORT) UDP flood sketch (PRIMARY cap).
    /// `Some` iff `udp_flood_threshold > 0`. `TokenBucket` cells.
    pub(super) udp_dst_sketch: Option<SynRateSketch<TokenBucket>>,
    /// #3315 per-DESTINATION SYN-flood rate sketch (PRIMARY, spoof-resistant).
    /// `Some` iff `syn_flood_dst_threshold > 0`; runs even when cookie-active.
    pub(super) syn_dst_sketch: Option<SynRateSketch<TokenBucket>>,
    /// #3315 per-SOURCE SYN-flood rate sketch (SECONDARY/best-effort). `Some`
    /// iff `syn_flood_src_threshold > 0`; SKIPPED while the zone is
    /// SYN-cookie active.
    pub(super) syn_src_sketch: Option<SynRateSketch<TokenBucket>>,
    /// #13952/#14324 post-MAC failed-attempt sketch, shared by active and
    /// standby validation. Charged ONLY after a failed MAC so valid cookies
    /// never consume it and spoofed failures cannot starve them (#13700).
    /// `Some` iff SYN cookies are enabled; fixed-capacity and collision-biased
    /// fail closed for invalid ACKs.
    syn_cookie_ack_attempt_sketch: Option<SynRateSketch<TokenBucket>>,

    pub(super) syn_cookie_active_until_secs: u64,
    /// #14635 per-(dst,port) cookie activation; bounded, perishable.
    pub(super) syn_cookie_active_per_dst: FxHashMap<(IpAddr, u16), u64>,
    /// #14635 per-(dst,port) alarm cadence.
    syn_alarm_last_emit_per_dst: FxHashMap<(IpAddr, u16), u64>,
    /// #3607 standby SYN-cookie ACK validation budget (`TokenBucket`).
    pub(super) syn_cookie_standby_ack_counter: TokenBucket,
    /// #9902 F-023 flood-ACTIVE SYN-cookie ACK validation budget (`TokenBucket`).
    /// Separate from the standby budget: the standby arm validates rare misses
    /// opportunistically (fail-open), while the active arm validates every
    /// session-miss ACK during a flood (fail-closed) — one bucket would couple
    /// background misses to flood defense. Per worker per zone, like all screen
    /// budgets: aggregate allowance scales with workers and zones.
    pub(super) syn_cookie_active_ack_counter: TokenBucket,
    /// #2446 per-zone SYN-cookie profile generation. Bumped by `update_profiles`
    /// whenever a zone's SYN-cookie-relevant profile fields (`syn_cookie`,
    /// `syn_flood_threshold`, `syn_flood_src_threshold` — #12876) change
    /// (including gaining/losing a profile). The current generation is stamped
    /// into a validated-cache entry on insert and compared on consume, so a
    /// tuple validated under an old profile is a cache miss after the profile
    /// changes and is re-validated under the new one.
    /// Values come from `ScreenState`'s single generation counter, so a zone that
    /// is removed and re-created never reuses a generation its previous
    /// incarnation's validated entries carry (#9740).
    pub(super) syn_cookie_profile_gen: u64,
    /// #9740: this zone's SYN-cookie identity, `syn_cookie_zone_tag` of its name.
    /// Computed once, here, so the cookie MAC, the per-epoch secret and the
    /// validated-client key read it instead of hashing the name per packet.
    pub(super) syn_cookie_zone_tag: SynCookieZoneTag,
    /// #3315 last second a SYN-flood alarm was raised for the zone, enforcing
    /// the ≤1/sec/zone cadence. `u64::MAX` = never emitted; only consulted when
    /// `syn_flood_alarm_threshold > 0`.
    syn_alarm_last_emit_sec: u64,
}

/// #6437 PHASE-1 result of [`ZoneScreenState::syn_flood_gate`]: the SYN-flood
/// verdict, expressed without touching any whole-`ScreenState` state. The
/// caller (`check_packet_with_zone_id_opts`) applies PHASE 2 — diagnostic
/// counter bumps, the pending-alarm flag, and the SYN-cookie mint — after the
/// gate call, when the `zones` borrow is already released.
///
/// The variants map 1:1 onto the historical `ScreenVerdict` outcomes of the
/// inlined block; the reason strings stay in the caller so the per-reason
/// drop-counter ordinal mapping (`screen_reason_drop_index`) is unchanged.
pub(super) enum SynFloodGate {
    /// Below every applicable cap; the packet continues to the Pass /
    /// SynCookieBypass tail. `alarm` is true when the measured aggregate rate
    /// crossed `alarm-threshold` (but NOT `attack-threshold`) and the
    /// ≤1/sec/zone cadence admitted a new alarm — the caller sets
    /// `syn_alarm_pending` and bumps `syn_flood_alarm_events` (log-only; the
    /// verdict stays non-drop).
    Admit { alarm: bool },
    /// #4112 F19 per-DESTINATION cap tripped (PRIMARY): hard drop
    /// `"syn-flood"`; the caller bumps `syn_flood_dst_drops`.
    DropDst,
    /// #3607 cookie-OFF per-zone aggregate attack bucket over: drop
    /// `"syn-flood"` with NO sub-attribution counter (the aggregate bucket is
    /// the sole drop authority when `syn-cookie` is OFF).
    DropAggregate,
    /// Aggregate over-attack with `syn-cookie` ON but no codec published:
    /// drop `"syn-cookie-unavailable"`. (The gate already set the zone
    /// cookie-active window, mirroring the historical ordering.)
    DropCookieUnavailable,
    /// #3315 per-SOURCE cap tripped (SECONDARY): hard drop `"syn-flood"`;
    /// the caller bumps `syn_flood_src_drops`. `alarm` as in `Admit`.
    DropSrc { alarm: bool },
    /// Aggregate over-attack with `syn-cookie` ON and a codec present: the
    /// caller mints the `SynCookieChallenge` (the zone cookie-active window
    /// was already set by the gate unless the profile is in
    /// `alarm-without-drop` audit mode).
    MintChallenge,
}

impl ZoneScreenState {
    /// #4969: construct a zone's screen state from its profile, allocating ALL
    /// threshold-gated sub-state (per-destination / per-source flood sketches)
    /// up front, so a configured limiter can NEVER be silently absent on the
    /// screened path. Aggregate counters and cookie fields start at their cold
    /// defaults (`TokenBucket`/`RateCounter::default`, active-until 0, gen 0,
    /// alarm-last `u64::MAX`). `Some ⟺ threshold configured` is the invariant.
    /// `zone` is the zone's name; its SYN-cookie tag is derived from it here.
    pub(super) fn from_profile(zone: &str, profile: ScreenProfile) -> Self {
        let icmp_dst_sketch =
            (profile.icmp_flood_threshold > 0).then(SynRateSketch::for_flood_dst);
        let udp_dst_sketch =
            (profile.udp_flood_threshold > 0).then(SynRateSketch::for_flood_dst);
        let syn_dst_sketch = (profile.syn_flood_dst_threshold > 0).then(SynRateSketch::for_dst);
        let syn_src_sketch = (profile.syn_flood_src_threshold > 0).then(SynRateSketch::for_src);
        let syn_cookie_ack_attempt_sketch =
            profile.syn_cookie.then(SynRateSketch::for_flood_dst);
        Self {
            profile,
            icmp_counter: TokenBucket::default(),
            udp_counter: TokenBucket::default(),
            syn_attack_sketch: SynRateSketch::for_syn_dst_port(),
            syn_off_attack_sketch: SynRateSketch::for_syn_dst_port_token(),
            syn_zone_counter: RateCounter::default(),
            syn_zone_off_bucket: TokenBucket::default(),
            icmp_dst_sketch,
            udp_dst_sketch,
            syn_dst_sketch,
            syn_src_sketch,
            syn_cookie_ack_attempt_sketch,
            syn_cookie_active_until_secs: 0,
            syn_cookie_active_per_dst: FxHashMap::default(),
            syn_alarm_last_emit_per_dst: FxHashMap::default(),
            syn_cookie_standby_ack_counter: TokenBucket::default(),
            syn_cookie_active_ack_counter: TokenBucket::default(),
            syn_cookie_profile_gen: 0,
            syn_cookie_zone_tag: syn_cookie_zone_tag(zone),
            syn_alarm_last_emit_sec: u64::MAX,
        }
    }

    /// #4969: reconcile a persisting zone's threshold-gated sub-state against
    /// its (already-updated) `profile`, preserving in-flight counters exactly
    /// where the pre-#4969 parallel-map `retain` + `or_insert_with` did. A
    /// limiter newly enabled allocates its sketch; a disabled one drops it; a
    /// still-configured one keeps its live sketch. The SYN-flood alarm cadence
    /// is reset to `u64::MAX` when the alarm is disabled (mirroring the old
    /// remove-on-disable so a later re-enable starts fresh) and otherwise
    /// preserved. Aggregate counters, standby budget, and profile generation are
    /// inherited untouched from the retained value; the cookie-active latch is
    /// cleared on the two conditions documented below (#9425, #12876).
    ///
    /// #9425 member 2: the SYN-cookie active-until latch is NO LONGER inherited
    /// unconditionally. A zone under a live flood latches cookie-active for
    /// `SynCookieCodec::EPOCH_SECS` (64 s). If the operator then commits
    /// `alarm-without-drop` on that zone TO STOP THE DROPS, the latch was
    /// inherited here, `locally_active` stayed true in
    /// `validate_syn_cookie_ack_on_session_miss` (which checks `syn_cookie`,
    /// the threshold, the protocol and `locally_active` — but never
    /// `alarm_without_drop`), and parse-valid session-miss ACKs kept taking the
    /// `Invalid` arm and hard-dropping for up to 64 seconds AFTER the commit
    /// that was supposed to stop exactly that.
    ///
    /// The defect is in the COMPOSITION of two individually deliberate
    /// mechanisms — #4969 preserves per-zone state across commits, #2446
    /// selectively invalidates the cookie GENERATION — neither of which resets
    /// this latch on an audit transition. The freshly-configured-audit case was
    /// already guarded (`syn_flood_gate` does not set the latch under
    /// `alarm_without_drop`, pinned by
    /// `syn_cookie_alarm_without_drop_forwards_session_miss_ack_l10`); this is
    /// the ENFORCE -> AUDIT transition, which that guard cannot reach because
    /// the latch was set before the transition.
    ///
    /// Clearing it whenever the NEW profile is in audit mode is idempotent with
    /// that guard: audit mode never sets the latch, so under audit the only
    /// value it can hold is one inherited from a pre-audit epoch.
    ///
    /// #12876: the same composition defect survived every OTHER edit to the
    /// latch's activation slice. The latch is derived state — "the aggregate
    /// crossed `syn_flood_threshold` while `syn_cookie` was on" — measured
    /// under the OLD profile, yet it was inherited across a `syn-cookie`
    /// disable/re-enable cycle and across an attack-threshold INCREASE: a zone
    /// whose operator had just raised the threshold (or cycled cookies off and
    /// back on inside one 64 s epoch) kept skipping the configured per-source
    /// sketch and hard-dropping unrelated session-miss ACKs as `Invalid` for up
    /// to `EPOCH_SECS` after the commit, on terms the latch was never measured
    /// under. `activation_slice_changed` (computed by `update_profiles` from
    /// `(syn_cookie, syn_flood_threshold)` — exactly the fields that gate
    /// whether `syn_flood_gate` may set the latch) clears it here. Fail-closed
    /// in the only direction that matters: a still-real flood re-latches on its
    /// next over-attack SYN because the count-all aggregate counter IS carried
    /// over; only the stale window is dropped. A `syn_flood_src_threshold`-only
    /// edit does NOT clear the latch — the source cap never gates the latch,
    /// and cookie-active deliberately skips it (D3/#9945); that edit instead
    /// invalidates the validated-client cache via
    /// `syn_cookie_profile_signature`.
    pub(super) fn reconcile_substate(&mut self, activation_slice_changed: bool) {
        reconcile_flood_sketch(
            &mut self.icmp_dst_sketch,
            self.profile.icmp_flood_threshold > 0,
            SynRateSketch::for_flood_dst,
        );
        reconcile_flood_sketch(
            &mut self.udp_dst_sketch,
            self.profile.udp_flood_threshold > 0,
            SynRateSketch::for_flood_dst,
        );
        reconcile_flood_sketch(
            &mut self.syn_dst_sketch,
            self.profile.syn_flood_dst_threshold > 0,
            SynRateSketch::for_dst,
        );
        reconcile_flood_sketch(
            &mut self.syn_src_sketch,
            self.profile.syn_flood_src_threshold > 0,
            SynRateSketch::for_src,
        );
        reconcile_flood_sketch(
            &mut self.syn_cookie_ack_attempt_sketch,
            self.profile.syn_cookie,
            SynRateSketch::for_flood_dst,
        );
        if self.profile.syn_flood_alarm_threshold == 0 {
            self.syn_alarm_last_emit_sec = u64::MAX;
            self.syn_alarm_last_emit_per_dst.clear();
        }

        // #9425 member 2 and #12876 — see the doc comment above.
        if self.profile.alarm_without_drop || activation_slice_changed {
            self.syn_cookie_active_until_secs = 0;
            self.syn_cookie_active_per_dst.clear();
        }
    }
    /// #13952/#14324: consume one post-MAC FAILED ACK attempt for
    /// `(src, dst, dport)`. Called only after `ring.validates()` fails, so
    /// valid cookies never charge it. Shared across active/standby role
    /// changes. `true` means limited.
    pub(super) fn syn_cookie_ack_attempt_limited(
        &mut self,
        pkt: &ScreenPacketInfo,
        now_ns: u64,
    ) -> bool {
        self.syn_cookie_ack_attempt_sketch
            .as_mut()
            .is_none_or(|sketch| {
                sketch.increment_cookie_client_key(
                    &pkt.src_ip,
                    &pkt.dst_ip,
                    pkt.dst_port,
                    now_ns,
                    super::syncookie::SYN_COOKIE_FAILED_ATTEMPT_RATE_LIMIT_PER_SEC,
                )
            })
    }

    /// #4112 F18: ICMP flood admission. (1) the per-DESTINATION count-min
    /// sketch is the PRIMARY cap at `threshold`; (2) the per-zone aggregate is a
    /// coarse SECONDARY zone-saturation ceiling at `SECONDARY_FLOOD_CEILING_MULT
    /// × threshold`. The per-destination check short-circuits, so the aggregate
    /// counts only per-destination-admitted packets. Returns true when the
    /// packet must be dropped as an ICMP flood. #5805: monotonic-ns
    /// `TokenBucket` cells keep a destination parked at `threshold` admitted
    /// steadily while limiting an over-threshold destination.
    fn icmp_flood_drop(&mut self, dst_ip: &IpAddr, threshold: u32, now_ns: u64) -> bool {
        if let Some(sketch) = self.icmp_dst_sketch.as_mut()
            && sketch.increment(dst_ip, now_ns, threshold)
        {
            return true;
        }
        self.icmp_counter
            .admit_is_over(now_ns, threshold.saturating_mul(SECONDARY_FLOOD_CEILING_MULT))
    }

    /// #4112 F18: UDP flood admission — like `icmp_flood_drop`, but the PRIMARY
    /// per-destination cap keys on `(dst_ip, dst_port)` (Junos `udp flood
    /// threshold` caps per destination IP AND port). #4567: a flowless non-first
    /// fragment carries `dst_port == 0`, so it folds into the per-destination-IP
    /// `increment(dst_ip)` cell (the same abstraction `icmp_flood_drop` uses),
    /// not a stray `(ip, 0)` cell; a first/atomic fragment or normal datagram
    /// always carries its real port and counts at `(dst_ip, dst_port)`.
    fn udp_flood_drop(
        &mut self,
        dst_ip: &IpAddr,
        dst_port: u16,
        threshold: u32,
        now_ns: u64,
    ) -> bool {
        if let Some(sketch) = self.udp_dst_sketch.as_mut() {
            let over = if dst_port == 0 {
                sketch.increment(dst_ip, now_ns, threshold)
            } else {
                sketch.increment_ip_port(dst_ip, dst_port, now_ns, threshold)
            };
            if over {
                return true;
            }
        }
        self.udp_counter
            .admit_is_over(now_ns, threshold.saturating_mul(SECONDARY_FLOOD_CEILING_MULT))
    }

    /// #6238: the common SOURCE-INDEPENDENT rate-flood block shared by the
    /// flow-present (`check_packet_with_zone_id_opts`) and flowless
    /// (`check_flowless_screens_opts`) paths — ICMP flood then UDP flood, in the
    /// exact order and with the exact reason strings both paths already used.
    ///
    /// Both flood calls mutate DISJOINT sub-fields (`icmp_*` / `udp_*`) of THIS
    /// already-looked-up `ZoneScreenState`, so routing both paths through this
    /// one method keeps the #4969 single-`zones.get_mut`-per-packet invariant:
    /// the caller still performs exactly one lookup and hands the borrow here.
    /// The ICMP/UDP thresholds are copied out of `self.profile` up front so the
    /// immutable profile read is released before the `&mut self` flood mutations
    /// (the same disjoint-borrow discipline the open-coded block used).
    ///
    /// `pkt.dst_port` is passed through UNCHANGED so the #4567 flowless
    /// zero-port fold stays INSIDE `udp_flood_drop` (a `dst_port == 0` fragment
    /// folds into the per-destination-IP bucket). No flowless mode flag is
    /// needed. Worker-local counters only; no allocation, lock, or dynamic
    /// dispatch on the packet path. Returns the drop reason or `None`.
    #[inline]
    pub(super) fn enforce_common_rate_floods(
        &mut self,
        pkt: &ScreenPacketInfo,
        now_ns: u64,
    ) -> Option<&'static str> {
        let icmp_flood_threshold = self.profile.icmp_flood_threshold;
        if icmp_flood_threshold > 0
            && (pkt.protocol == PROTO_ICMP || pkt.protocol == PROTO_ICMPV6)
            && self.icmp_flood_drop(&pkt.dst_ip, icmp_flood_threshold, now_ns)
        {
            return Some("icmp-flood");
        }

        let udp_flood_threshold = self.profile.udp_flood_threshold;
        if udp_flood_threshold > 0
            && pkt.protocol == PROTO_UDP
            && self.udp_flood_drop(&pkt.dst_ip, pkt.dst_port, udp_flood_threshold, now_ns)
        {
            return Some("udp-flood");
        }
        None
    }

    /// #6437 PHASE 1 of the SYN-flood enforcement: every zone-local mutation of
    /// the historical inlined block, in the exact historical order, returning an
    /// owned [`SynFloodGate`] for the caller's PHASE 2.
    ///
    /// The caller invokes this for every initial SYN while the zone's
    /// `syn_flood_threshold` is enabled. `validated_client` is true only when
    /// PHASE 0 found a current SYN-cookie validation for this source/service.
    /// #9945: even that proven-live client MUST charge the aggregate and
    /// per-destination cap. It skips only the per-source limiter (the source
    /// proved liveness) and the aggregate's recoverable challenge response;
    /// the caller preserves its `SynCookieBypass` fast-path verdict.
    ///
    /// #3315 + #4112 F19 + #14635 enforcement order (per-(dst,port) counts
    /// first, per-dst-IP authoritative over the per-dst cookie/Drop verdict,
    /// per-src additive):
    ///   1. per-(dst,port) `attack-threshold` (+ `alarm-threshold`) — ALWAYS
    ///      counts via a SINGLE window advance so its cookie-activation
    ///      side-effect can never be skipped. Junos counts SYNs to the same
    ///      destination address (+port) per second, never per zone (#14635).
    ///   2. per-DESTINATION-IP cap (primary, spoof-resistant) — evaluated
    ///      BEFORE the per-dst over-attack early-return (#4112 F19), so a
    ///      per-dst-IP trip HARD-DROPS the flooded victim even while its
    ///      service is over attack-threshold and minting cookies. Runs even
    ///      when cookie-active and for validated clients (#9945).
    ///   3. per-(dst,port) over-attack verdict — mint a SYN-cookie challenge
    ///      per key (or drop via the per-dst token bucket when cookies are
    ///      disabled, subject to the 8x zone ceiling). A validated client
    ///      keeps its bypass after charging (#9945).
    ///   4. per-SOURCE cap (secondary) — SKIPPED while THIS destination is
    ///      cookie-active, or for a validated client (the client proved
    ///      liveness; the #9945 exception).
    ///
    /// `codec_available` is the caller-observed `self.syn_cookie_codec.is_some()`
    /// snapshot, taken immediately before the call — the codec cannot change
    /// across the gate, so a `MintChallenge` result guarantees the caller's
    /// PHASE-2 `syn_cookie_codec` is still `Some`. Worker-local counters only;
    /// no allocation, lock, or dynamic dispatch on the packet path.
    /// `cookie_activation_allowed` is false for session-miss SYN-ACKs. Those
    /// packets are still flood-metered and dropped over the per-dst
    /// threshold, but cannot trigger an unanswerable challenge or poison the
    /// cookie-active window used by later initial SYNs.
    #[inline]
    pub(super) fn syn_flood_gate(
        &mut self,
        pkt: &ScreenPacketInfo,
        now_ns: u64,
        now_secs: u64,
        codec_available: bool,
        validated_client: bool,
        cookie_activation_allowed: bool,
    ) -> SynFloodGate {
        // Copy the small SYN scalar thresholds/flags out of the profile up
        // front so the immutable profile read is released before the mutable
        // sub-field accesses below (the same disjoint-borrow discipline the
        // open-coded block used).
        let syn_flood_threshold = self.profile.syn_flood_threshold;
        let syn_cookie = self.profile.syn_cookie;
        // Profile-wide `alarm-without-drop` audit mode. Used to gate the
        // cookie-active marking below so audit mode does not arm the
        // returning-ACK drop.
        let alarm_without_drop = self.profile.alarm_without_drop;
        // #3315: SYN-flood sub-thresholds (0 = disabled).
        let syn_alarm_threshold = self.profile.syn_flood_alarm_threshold;
        let syn_dst_threshold = self.profile.syn_flood_dst_threshold;
        let syn_src_threshold = self.profile.syn_flood_src_threshold;

        // #14635: PRIMARY per-(dst_ip,dst_port) attack/alarm measurement.
        let alarm_arg = if syn_alarm_threshold > 0 {
            syn_alarm_threshold
        } else {
            u32::MAX
        };
        let (over_attack, over_alarm) = self.syn_attack_sketch.increment_ip_port_and_classify(
            &pkt.dst_ip,
            pkt.dst_port,
            now_secs,
            syn_flood_threshold,
            alarm_arg,
        );
        let dst_key = (pkt.dst_ip, pkt.dst_port);
        if syn_dst_threshold > 0
            && let Some(sketch) = self.syn_dst_sketch.as_mut()
            && sketch.increment(&pkt.dst_ip, now_ns, syn_dst_threshold)
        {
            return SynFloodGate::DropDst;
        }
        if syn_cookie {
            if over_attack {
                if validated_client {
                    return SynFloodGate::Admit { alarm: false };
                }
                if !cookie_activation_allowed {
                    return SynFloodGate::DropAggregate;
                }
                if !alarm_without_drop {
                    // #14635: activate cookies PER KEY. The zone latch is
                    // retained as the legacy/secondary state read by forced
                    // test seams and the #13699 latch assertion; live ACK
                    // and per-source decisions key on the per-dst map below,
                    // so this latch no longer widens enforcement zone-wide.
                    let until = now_secs.saturating_add(SynCookieCodec::EPOCH_SECS);
                    self.syn_cookie_active_per_dst.retain(|_, v| *v > now_secs);
                    if self.syn_cookie_active_per_dst.len() < 4096
                        || self.syn_cookie_active_per_dst.contains_key(&dst_key)
                    {
                        self.syn_cookie_active_per_dst.insert(dst_key, until);
                    }
                    self.syn_cookie_active_until_secs =
                        self.syn_cookie_active_until_secs.max(until);
                }
                if !codec_available {
                    return SynFloodGate::DropCookieUnavailable;
                }
                return SynFloodGate::MintChallenge;
            }
        } else {
            let per_dst_over = self.syn_off_attack_sketch.increment_ip_port_token(
                &pkt.dst_ip,
                pkt.dst_port,
                now_ns,
                syn_flood_threshold,
            );
            if per_dst_over {
                return SynFloodGate::DropAggregate;
            }
            if self.syn_zone_off_bucket.admit_is_over(
                now_ns,
                syn_flood_threshold.saturating_mul(SYN_SECONDARY_CEILING_MULT),
            ) {
                return SynFloodGate::DropAggregate;
            }
            let _ = self
                .syn_zone_counter
                .increment_and_classify(now_secs, u32::MAX, u32::MAX);
        }
        // Alarm band: per (dst,port) in enforce mode. The pre-#14635 zone-wide
        // <=1/sec audit cadence is preserved only in alarm-without-drop mode,
        // where alarms are the only enforcement signal (many existing audit
        // cells count exactly one event per zone-second).
        let mut alarm_raised = false;
        if syn_alarm_threshold > 0 && over_alarm && !over_attack {
            if alarm_without_drop {
                if self.syn_alarm_last_emit_sec != now_secs {
                    self.syn_alarm_last_emit_sec = now_secs;
                    alarm_raised = true;
                }
            } else {
                let last = self
                    .syn_alarm_last_emit_per_dst
                    .get(&dst_key)
                    .copied()
                    .unwrap_or(u64::MAX);
                if last != now_secs {
                    self.syn_alarm_last_emit_per_dst
                        .retain(|_, v| *v >= now_secs.saturating_sub(1));
                    if self.syn_alarm_last_emit_per_dst.len() < 4096
                        || self.syn_alarm_last_emit_per_dst.contains_key(&dst_key)
                    {
                        self.syn_alarm_last_emit_per_dst.insert(dst_key, now_secs);
                    }
                    alarm_raised = true;
                }
            }
        }
        // Per-source skip keys on THIS destination only (plus audit mode,
        // which never arms cookie state). The zone latch must not disable
        // per-source protection for unrelated services (#14635).
        let cookie_active = syn_cookie
            && !alarm_without_drop
            && (self
                .syn_cookie_active_per_dst
                .get(&dst_key)
                .is_some_and(|&u| u > now_secs)
                || (self.syn_cookie_active_per_dst.is_empty()
                    && self.syn_cookie_active_until_secs > now_secs));
        if syn_src_threshold > 0
            && !validated_client
            && !cookie_active
            && let Some(sketch) = self.syn_src_sketch.as_mut()
            && sketch.increment(&pkt.src_ip, now_ns, syn_src_threshold)
        {
            return SynFloodGate::DropSrc {
                alarm: alarm_raised,
            };
        }
        SynFloodGate::Admit {
            alarm: alarm_raised,
        }
    }
}

/// #4969: reconcile one threshold-gated flood sketch against its enable state,
/// mirroring the pre-#4969 `retain(threshold>0)` + `or_insert_with(make)`
/// semantics: allocate a FRESH sketch when a limiter is newly enabled, drop the
/// sketch (and its in-flight counters) when disabled, and PRESERVE the live
/// sketch across an unrelated profile edit. `Some ⟺ want` after this returns.
fn reconcile_flood_sketch<S>(slot: &mut Option<S>, want: bool, make: fn() -> S) {
    if want {
        if slot.is_none() {
            *slot = Some(make());
        }
    } else {
        *slot = None;
    }
}
