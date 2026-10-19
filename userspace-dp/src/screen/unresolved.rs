//! #7888: what the dataplane does with a zone whose screen reference does not
//! resolve.
//!
//! Extracted from `screen/mod.rs` when #7888 pushed that file past the 1500 LOC
//! [WATCH] threshold. `docs/engineering-style.md` says to split the module and
//! land the feature on the smaller pieces rather than clean up afterwards, so
//! this is a PURE MOVE -- no behaviour change -- committed separately from the
//! feature so the two can be reviewed apart.
//!
//! The unit is coherent on its own terms: a zone's screen reference has THREE
//! outcomes, and everything here exists to tell them apart and act on each.
//! Two of the three are faults with the same consequence (the #7168 substituted
//! conservative default) and different diagnoses, and keeping the diagnosis
//! decidable is why the two reference sets are separate maps rather than one
//! map with a flag.
//!
//! This is a CHILD module of `screen`, so it reaches `ScreenState`'s private
//! fields directly -- the split costs no visibility widening.

use super::{
    MISSING_PROFILE_WARN_RATE_LIMIT_PER_SEC, ScreenPacketInfo, ScreenProfile, ScreenState,
    ScreenVerdict, stateless,
};
use rustc_hash::FxHashMap;

/// #7888: which way a zone's screen reference failed to resolve.
///
/// A zone's screen reference has THREE outcomes, and only two of them are a
/// fault. This enum names the two faults; the third -- no `screen` statement on
/// the zone at all -- is a legitimate configuration and is represented by
/// `None` from `unresolved_screen_kind`, never by a variant here.
///
/// Both variants take the SAME verdict, the #7168 substituted conservative
/// default. They exist to select the WARN text, because "the profile does not
/// exist" and "the profile exists and enforces nothing" send an operator to
/// two different places.
/// #9425: what an INERT screen reference carries beyond the profile name.
///
/// The map value was a bare `String` (the profile name). It is a struct now
/// because the inert state must also carry the operator's `alarm-without-drop`
/// request: an inert zone has no `zones` entry, so
/// `ScreenState::alarm_without_drop`'s resolved lookup misses and the #7888
/// substituted conservative default HARD-DROPS — the exact inverse of what an
/// operator who wrote `alarm-without-drop` and nothing else asked for, and that
/// is the single most likely way to reach the inert state at all.
///
/// Deliberately NOT a second parallel map keyed on zone: two structures keyed
/// the same way can disagree about which zones they cover, and the disagreement
/// is silent.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct InertProfileRef {
    pub profile: String,
    /// The profile IS defined and carries `alarm-without-drop`. Honouring it
    /// changes only the terminal disposition: the substituted checks still RUN,
    /// still count, and now ALARM instead of dropping. The #7888 posture (do
    /// not silently pass an inert zone) is preserved — this is drop-vs-alarm,
    /// not drop-vs-pass.
    pub alarm_without_drop: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum UnresolvedScreen {
    /// The referenced profile is not defined at all (#3082). Strict commit
    /// rejects this, so it arrives only through tolerant paths (HA config-sync
    /// from a schema-skewed peer, tolerant load of an older active.json).
    Undefined,
    /// The referenced profile IS defined but enables no check (#7059). This
    /// passes strict commit with zero warnings, which makes it strictly more
    /// reachable than `Undefined` -- and it is the state that looks correct to
    /// an operator, which is why it went unnoticed.
    Inert,
}

/// #3082/#7168: the WARN text for a zone referencing an UNDEFINED screen
/// profile. Extracted from the `eprintln!` so the wording is a testable value
/// rather than a side effect -- #7888 turns on these two texts being tellable
/// apart, and a property asserted only inside a formatting macro cannot be
/// asserted at all.
///
/// Allocates, but only on the emit path, which is rate-limited to one per zone
/// per second and is already past a `zone.to_string()` in the rate-counter
/// lookup. Not a per-packet path.
pub(super) fn missing_profile_warn_message(zone: &str, profile: &str) -> String {
    format!(
        "xpf-userspace-dp: screen WARN: zone {zone:?} references undefined \
         screen profile {profile:?}; enforcing the SUBSTITUTED conservative \
         default (malformed-packet checks only — no flood/scan/session-limit \
         thresholds) for this zone (#7168 lenient/HA-sync path) — fix the \
         config or upgrade the HA peer to restore the configured profile",
        zone = zone,
        profile = profile,
    )
}

/// #7888: the WARN text for a zone whose screen profile IS DEFINED but enables
/// no check.
///
/// This must be tellable apart from `missing_profile_warn_message` by an
/// OPERATOR, not just by a parser. That message is word-for-word the strict
/// commit-time validation error in
/// `pkg/config/compiler_validate_strict_screen.go`, so emitting it here would
/// send someone hunting for an `ids-option` stanza that is present -- and this
/// state passes strict commit with zero warnings, so there is no commit-time
/// evidence to reconcile it against. Hence: lead with IS DEFINED, name the
/// actual cause (a modifier is not a check), and give a different remedy.
pub(super) fn inert_profile_warn_message(zone: &str, profile: &str) -> String {
    format!(
        "xpf-userspace-dp: screen WARN: zone {zone:?} resolves to screen \
         profile {profile:?}, which IS DEFINED but enables no check — every \
         statement under it is a modifier (alarm-without-drop, a threshold) \
         rather than a check, so the profile enforces nothing; enforcing the \
         SUBSTITUTED conservative default (malformed-packet checks only — no \
         flood/scan/session-limit thresholds) for this zone (#7888) — add at \
         least one check to the profile, or remove the zone's screen \
         statement if no enforcement is intended",
        zone = zone,
        profile = profile,
    )
}
impl ScreenState {
    /// #3082: replace the set of zones that reference an undefined screen
    /// profile (called on config update alongside `update_profiles`). Retains
    /// only the WARN rate counters for zones still in the set so a removed /
    /// fixed reference stops warning and frees its counter.
    pub fn update_missing_profiles(&mut self, missing: FxHashMap<String, String>) {
        self.missing_profile_warn_counters
            .retain(|k, _| missing.contains_key(k));
        self.missing_profile_refs = missing;
    }

    /// #7888: replace the set of zones that resolve to a DEFINED screen profile
    /// which enables no check (called on config update alongside
    /// `update_missing_profiles`). Retains only the WARN rate counters for
    /// zones still in the set, so a profile that gains a check stops warning
    /// and frees its counter.
    pub fn update_inert_profiles(&mut self, inert: FxHashMap<String, InertProfileRef>) {
        self.inert_profile_warn_counters
            .retain(|k, _| inert.contains_key(k));
        self.inert_profile_refs = inert;
    }

    /// #7168: the verdict for a zone whose configured screen reference does NOT
    /// resolve.
    ///
    /// Both `None` branches (flow-present and flowless) route here instead of
    /// returning `ScreenVerdict::Pass` unconditionally. A zone with NO screen
    /// configured still passes silently — that is a legitimate configuration,
    /// not a fault. A zone that REFERENCES a profile which did not resolve is
    /// evaluated against `ScreenProfile::conservative_default()`: the
    /// threshold-free malformed-packet subset, and none of the rate checks.
    ///
    /// Only STATELESS checks are run, and that is structural rather than a
    /// choice made here — the rate checks need per-zone tracker/sketch state
    /// that lives in `ZoneScreenState`, which by definition does not exist for
    /// an unresolved zone. So "the substitution cannot synthesise a rate check"
    /// is enforced by construction, not by remembering not to.
    ///
    /// Recovery is automatic: the substitution is a property of the resolved
    /// map, so the next snapshot in which the profile appears displaces it with
    /// no restart.
    ///
    /// `addrs_known` mirrors the flowless path's constraint — LAND compares
    /// source and destination, so it is only meaningful when the caller
    /// supplied real L3 addresses.
    // `pub(super)` only because the two `None` branches that call it stayed in
    // `screen/mod.rs`. Not a widening: `super` IS the screen module, which is
    // exactly who could call it before the split.
    pub(super) fn missing_profile_verdict(
        &mut self,
        zone: &str,
        pkt: &ScreenPacketInfo,
        now_secs: u64,
        addrs_known: bool,
    ) -> ScreenVerdict {
        // #7888: THREE states reach here, not two, and they are read off
        // membership in two disjoint maps. "In neither map" is the legitimate
        // silent Pass -- a zone with no `screen` statement at all -- and it
        // must stay the only arm that passes without a signal.
        let Some(kind) = self.unresolved_screen_kind(zone) else {
            // No screen configured for this zone at all — nothing to
            // substitute, and nothing to warn about. Legitimate configuration.
            return ScreenVerdict::Pass;
        };
        // The WARN is rate-limited and now selects its text from `kind`: an
        // undefined profile and a defined-but-inert one are DIFFERENT operator
        // problems with different fixes, and #7888 exists because they were
        // rendered identically.
        self.maybe_warn_unresolved_profile(zone, kind, now_secs);
        let profile = ScreenProfile::conservative_default();
        if addrs_known && let Some(reason) = stateless::check_land(&profile, pkt) {
            self.substituted_default_drops = self.substituted_default_drops.wrapping_add(1);
            return ScreenVerdict::Drop(reason);
        }
        if let Some(reason) = stateless::check_tcp_flag_screens(&profile, pkt) {
            self.substituted_default_drops = self.substituted_default_drops.wrapping_add(1);
            return ScreenVerdict::Drop(reason);
        }
        if let Some(reason) = stateless::check_fragment_and_route(&profile, pkt) {
            self.substituted_default_drops = self.substituted_default_drops.wrapping_add(1);
            return ScreenVerdict::Drop(reason);
        }
        ScreenVerdict::Pass
    }

    /// #7888: which of the two UNRESOLVED states `zone` is in, or `None` when
    /// the zone has no screen configured at all.
    ///
    /// This is the single place the three states are separated, and it reads
    /// membership rather than a flag so that adding a fourth state means adding
    /// a map and an arm, not widening the meaning of an existing value.
    fn unresolved_screen_kind(&self, zone: &str) -> Option<UnresolvedScreen> {
        if self.missing_profile_refs.contains_key(zone) {
            Some(UnresolvedScreen::Undefined)
        } else if self.inert_profile_refs.contains_key(zone) {
            Some(UnresolvedScreen::Inert)
        } else {
            None
        }
    }

    /// #7888: emit the rate-limited runtime WARN for an unresolved screen
    /// reference, choosing the text from `kind`. The verdict is the caller's
    /// (`missing_profile_verdict`) and is the SAME substituted conservative
    /// default for both kinds; only the diagnosis differs.
    fn maybe_warn_unresolved_profile(&mut self, zone: &str, kind: UnresolvedScreen, now_secs: u64) {
        match kind {
            UnresolvedScreen::Undefined => self.maybe_warn_missing_profile(zone, now_secs),
            UnresolvedScreen::Inert => self.maybe_warn_inert_profile(zone, now_secs),
        }
    }

    /// #7888: the WARN for a zone whose screen profile IS DEFINED but enables
    /// no check.
    ///
    /// The text must be distinguishable from the undefined-profile WARN by more
    /// than tone. That message is word-for-word the strict commit-time
    /// validation error in `pkg/config/compiler_validate_strict_screen.go`, so
    /// an operator who saw it here for an inert profile would go looking for an
    /// `ids-option` stanza that is present, and then have to reconcile "the
    /// config defines it" with "the daemon says undefined" -- with no
    /// commit-time evidence to check against, because this state passes strict
    /// commit with zero warnings. So this text leads with IS DEFINED, names the
    /// actual cause (every statement under the profile is a modifier rather
    /// than a check), and gives a different remedy.
    fn maybe_warn_inert_profile(&mut self, zone: &str, now_secs: u64) {
        if !self.inert_profile_refs.contains_key(zone) {
            return;
        }
        let counter = match self.inert_profile_warn_counters.get_mut(zone) {
            Some(counter) => counter,
            None => self
                .inert_profile_warn_counters
                .entry(zone.to_string())
                .or_default(),
        };
        let limited = counter.increment(now_secs, MISSING_PROFILE_WARN_RATE_LIMIT_PER_SEC);
        if !limited {
            self.inert_profile_warn_count = self.inert_profile_warn_count.wrapping_add(1);
            let profile = &self
                .inert_profile_refs
                .get(zone)
                .expect("inert profile checked above")
                .profile;
            eprintln!("{}", inert_profile_warn_message(zone, profile));
        }
    }

    /// #3082: emit a rate-limited runtime WARN if `zone` references a screen
    /// profile that was undefined at snapshot-build time. This emits the SIGNAL
    /// only; the verdict is decided by the caller, `missing_profile_verdict`,
    /// which since #7168 evaluates the substituted conservative default rather
    /// than returning Pass. O(1) lookup; the WARN is bounded to one per zone
    /// per second.
    fn maybe_warn_missing_profile(&mut self, zone: &str, now_secs: u64) {
        if !self.missing_profile_refs.contains_key(zone) {
            // Zone has no screen configured at all — legit Pass, no signal.
            return;
        }
        let counter = match self.missing_profile_warn_counters.get_mut(zone) {
            Some(counter) => counter,
            None => self
                .missing_profile_warn_counters
                .entry(zone.to_string())
                .or_default(),
        };
        let limited = counter.increment(now_secs, MISSING_PROFILE_WARN_RATE_LIMIT_PER_SEC);
        if !limited {
            self.missing_profile_warn_count = self.missing_profile_warn_count.wrapping_add(1);
            let profile = self
                .missing_profile_refs
                .get(zone)
                .expect("missing profile checked above");
            eprintln!("{}", missing_profile_warn_message(zone, profile));
        }
    }
}
