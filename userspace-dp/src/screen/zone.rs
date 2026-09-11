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
//! the whole-`self` applications are borrow-trivial. The validated-cache
//! consume (a disjoint `ScreenState` field) stays in the caller as PHASE 0.

use std::net::IpAddr;

use super::packet::{PROTO_ICMP, PROTO_ICMPV6, PROTO_UDP, ScreenPacketInfo, ScreenProfile};
use super::rate::{RateCounter, TokenBucket};
use super::syn_rate::SynRateSketch;
use super::syncookie::{SynCookieCodec, SynCookieZoneTag, syn_cookie_zone_tag};

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
    /// #3315 per-zone SYN aggregate — count-all `RateCounter`; its admission
    /// activates SYN cookies / drives the alarm (the deliberate
    /// sustained-at-threshold over-throttle, see rate.rs).
    syn_counter: RateCounter,
    /// #3607 per-zone SYN-flood aggregate DROP shaper, the SOLE drop gate when
    /// `syn-cookie` is OFF (capacity = refill = `syn_flood_threshold`). Unused
    /// while `syn-cookie` is ON.
    syn_off_attack_bucket: TokenBucket,
    /// #4112/#5805 per-DESTINATION-IP ICMP flood sketch (PRIMARY cap). `Some`
    /// iff `icmp_flood_threshold > 0`. Monotonic-ns `TokenBucket` cells.
    pub(super) icmp_dst_sketch: Option<SynRateSketch<TokenBucket>>,
    /// #4112/#5805 per-DESTINATION (IP+PORT) UDP flood sketch (PRIMARY cap).
    /// `Some` iff `udp_flood_threshold > 0`. `TokenBucket` cells.
    pub(super) udp_dst_sketch: Option<SynRateSketch<TokenBucket>>,
    /// #3315 per-DESTINATION SYN-flood rate sketch (PRIMARY, spoof-resistant).
    /// `Some` iff `syn_flood_dst_threshold > 0`; runs even when cookie-active.
    pub(super) syn_dst_sketch: Option<SynRateSketch>,
    /// #3315 per-SOURCE SYN-flood rate sketch (SECONDARY/best-effort). `Some`
    /// iff `syn_flood_src_threshold > 0`; SKIPPED while the zone is
    /// SYN-cookie active.
    pub(super) syn_src_sketch: Option<SynRateSketch>,
    /// Monotonic seconds until which the zone is SYN-cookie active (0 = never).
    pub(super) syn_cookie_active_until_secs: u64,
    /// #3607 standby SYN-cookie ACK validation budget (`TokenBucket`).
    pub(super) syn_cookie_standby_ack_counter: TokenBucket,
    /// #2446 per-zone SYN-cookie profile generation. Bumped by `update_profiles`
    /// whenever a zone's SYN-cookie-relevant profile fields (`syn_cookie`,
    /// `syn_flood_threshold`) change (including gaining/losing a profile). The
    /// current generation is stamped into a validated-cache entry on insert and
    /// compared on consume, so a tuple validated under an old profile is a cache
    /// miss after the profile changes and is re-validated under the new one.
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
        Self {
            profile,
            icmp_counter: TokenBucket::default(),
            udp_counter: TokenBucket::default(),
            syn_counter: RateCounter::default(),
            syn_off_attack_bucket: TokenBucket::default(),
            icmp_dst_sketch,
            udp_dst_sketch,
            syn_dst_sketch,
            syn_src_sketch,
            syn_cookie_active_until_secs: 0,
            syn_cookie_standby_ack_counter: TokenBucket::default(),
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
    /// inherited untouched from the retained value.
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
    pub(super) fn reconcile_substate(&mut self) {
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
        if self.profile.syn_flood_alarm_threshold == 0 {
            self.syn_alarm_last_emit_sec = u64::MAX;
        }
        // #9425 member 2 — see the doc comment above.
        if self.profile.alarm_without_drop {
            self.syn_cookie_active_until_secs = 0;
        }
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
    /// owned [`SynFloodGate`] for the caller's PHASE 2. Must be called ONLY in
    /// the enforcement regime — an initial SYN (`syn && !ack`) on a TCP packet
    /// for a zone with `syn_flood_threshold > 0` whose tuple was NOT consumed
    /// from the validated-client cache (the caller's PHASE 0).
    ///
    /// #3315 + #4112 F19 enforcement order (aggregate counts first, per-dst
    /// authoritative over the aggregate cookie/Drop verdict, per-src additive):
    ///   1. aggregate `attack-threshold` (+ `alarm-threshold`) — ALWAYS counts
    ///      via a SINGLE window advance so its cookie-activation side-effect
    ///      can never be skipped. It does NOT return here.
    ///   2. per-DESTINATION cap (primary, spoof-resistant) — evaluated BEFORE
    ///      the aggregate over-attack early-return (#4112 F19), so a per-dst
    ///      trip HARD-DROPS the flooded victim even while the zone is over
    ///      attack-threshold and minting cookies for validated clients. Runs
    ///      even when cookie-active.
    ///   3. aggregate over-attack verdict — mint a SYN-cookie challenge (or
    ///      Drop when cookies are disabled); UNCHANGED for the case where the
    ///      per-dst cap did not trip.
    ///   4. per-SOURCE cap (secondary) — SKIPPED while the zone is cookie-
    ///      active (the cookie governs the spoofed-flood regime; per-source is
    ///      spoof-defeated there and the sketch would over-throttle).
    /// A validated returning SYN-cookie client bypasses ALL of the above (the
    /// caller never reaches this gate for one).
    ///
    /// `codec_available` is the caller-observed `self.syn_cookie_codec.is_some()`
    /// snapshot, taken immediately before the call — the codec cannot change
    /// across the gate, so a `MintChallenge` result guarantees the caller's
    /// PHASE-2 `syn_cookie_codec` is still `Some`. Worker-local counters only;
    /// no allocation, lock, or dynamic dispatch on the packet path.
    #[inline]
    pub(super) fn syn_flood_gate(
        &mut self,
        pkt: &ScreenPacketInfo,
        now_ns: u64,
        now_secs: u64,
        codec_available: bool,
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

        // (1) Aggregate dual-threshold in a SINGLE window advance (D7): one
        // compare against attack, one against alarm. When alarm is disabled,
        // pass u32::MAX so `over_alarm` is always false and the alarm branch
        // is dead.
        let alarm_arg = if syn_alarm_threshold > 0 {
            syn_alarm_threshold
        } else {
            u32::MAX
        };
        let (over_attack, over_alarm) =
            self.syn_counter
                .increment_and_classify(now_secs, syn_flood_threshold, alarm_arg);
        // (2) per-DESTINATION cap — PRIMARY. Evaluated BEFORE the aggregate
        // over-attack early-return (#4112 F19) so a per-destination trip
        // HARD-DROPS the flooded victim even while the zone is over
        // attack-threshold and minting cookies for validated clients.
        // destination-threshold's purpose (shield a single over-threshold
        // backend even from cookie-completing clients) was otherwise defeated
        // in exactly the high-load regime it is configured for: `if
        // over_attack` returned the cookie challenge before the per-dst sketch
        // at the old site (2) was ever reached. The aggregate counter above
        // ALWAYS counts first (its cookie-activation side-effect is never
        // skipped); a per-dst trip never flips zone cookie state. Runs even
        // when the zone is cookie-active.
        if syn_dst_threshold > 0
            && let Some(sketch) = self.syn_dst_sketch.as_mut()
            && sketch.increment(&pkt.dst_ip, now_secs, syn_dst_threshold)
        {
            return SynFloodGate::DropDst;
        }
        // (3) aggregate over-attack verdict.
        //   - `syn-cookie` ON: the MEASURED count-all `over_attack` mints a
        //     SYN-cookie challenge / activates cookies (UNCHANGED). Admitting
        //     a sustained-at-threshold stream here would let `threshold`
        //     spoofed SYNs/s bypass the cookie AND the per-source cap — the
        //     round-1 BLOCKER — so the count-all latch is deliberately
        //     retained.
        //   - `syn-cookie` OFF (#3607): there is no cookie to bypass, so a
        //     sustained-at-threshold legit SYN stream MUST be admitted. The
        //     per-zone `TokenBucket` is the SOLE drop authority, consulted on
        //     EVERY initial SYN and decoupled from the measured `over_attack`.
        //     One gate ⇒ no double-quota; the cold-start-full burst is bounded
        //     to capacity = `threshold`, preserving #2937.
        if syn_cookie {
            if over_attack {
                // In `alarm-without-drop` (audit) mode do NOT mark the zone
                // SYN-cookie-active. The challenge minted by the caller is
                // converted to a log-only alarm + Pass by the verdict consumer
                // (no cookie is actually put on the wire), so a returning
                // session-miss ACK never carries a valid cookie. Marking the
                // zone active would flip `locally_active` true in
                // `validate_syn_cookie_ack_on_session_miss`, which then DROPS
                // every such ACK as `Invalid` -- escaping the profile-wide
                // audit contract (observe the flood, forward the traffic).
                // Leaving it inactive makes that path return `NotApplicable`
                // so the ACK forwards. The per-source cap below is likewise
                // not skipped in audit mode, which is correct: the check
                // should still run and alarm.
                if !alarm_without_drop {
                    // #4969: active-until is a field on the zone's
                    // consolidated state, present by construction — the
                    // pre-#4969 `debug_assert!` guarding a missing
                    // prepopulated entry is now a compile-time impossibility.
                    self.syn_cookie_active_until_secs =
                        now_secs.saturating_add(SynCookieCodec::EPOCH_SECS);
                }
                if !codec_available {
                    return SynFloodGate::DropCookieUnavailable;
                }
                return SynFloodGate::MintChallenge;
            }
        } else if self
            .syn_off_attack_bucket
            .admit_is_over(now_ns, syn_flood_threshold)
        {
            return SynFloodGate::DropAggregate;
        }
        // Alarm-threshold crossed but below attack: raise a log-only alarm at
        // most once per second per zone. The verdict is unaffected — the
        // packet continues to the per-source check and (if clean) forwards.
        // #3607: the cookie-OFF token bucket may ADMIT a SYN whose MEASURED
        // arrival rate is over-attack, so gate the alarm EXPLICITLY on the
        // measured `!over_attack` (previously implied by the cookie-OFF
        // over-attack early return) so `syn-flood-alarm` still fires only in
        // the warning band between alarm- and attack-threshold (AGY r4). The
        // cadence mutation is zone-local (PHASE 1); the `syn_alarm_pending` /
        // `syn_flood_alarm_events` application is the caller's PHASE 2 via the
        // returned `alarm` flag.
        let mut alarm_raised = false;
        if syn_alarm_threshold > 0
            && over_alarm
            && !over_attack
            && self.syn_alarm_last_emit_sec != now_secs
        {
            self.syn_alarm_last_emit_sec = now_secs;
            alarm_raised = true;
        }
        // (4) per-SOURCE cap — SECONDARY, skipped while the zone is SYN-cookie
        // active (D3). The cookie-active window is the high-cardinality
        // spoofed-flood regime where per-source is both spoof-defeated and
        // prone to sketch over-throttling.
        let cookie_active = syn_cookie && self.syn_cookie_active_until_secs > now_secs;
        if syn_src_threshold > 0
            && !cookie_active
            && let Some(sketch) = self.syn_src_sketch.as_mut()
            && sketch.increment(&pkt.src_ip, now_secs, syn_src_threshold)
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
