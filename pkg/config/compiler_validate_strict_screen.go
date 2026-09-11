package config

import (
	"fmt"
	"sort"
)

// validateScreenProfileReferencesStrict hard-rejects a security zone whose
// `screen <name>` references a screen-ids-option profile the configuration
// never defines under `set security screen ids-option <name>` (#3066).
//
// Before this gate the reference was WARNED only (ValidateConfig /
// compiler_validate_warn.go), so the commit succeeded with an unenforceable
// reference. When #3066 landed, the userspace dataplane failed OPEN for a
// missing profile (ScreenVerdict::Pass), skipping every screen check for the
// zone. Since #7168 it no longer does: both `None` branches in
// userspace-dp/src/screen/mod.rs call `missing_profile_verdict`
// (userspace-dp/src/screen/unresolved.rs), which evaluates the zone against
// `ScreenProfile::conservative_default()` — the threshold-free malformed-packet
// checks only, with no flood, scan or session-limit thresholds. The zone keeps
// that floor, but none of the checks the operator configured are in effect, so
// the reference is still wrong. Junos rejects an undefined `screen ids-option`
// reference at commit, and this validator keeps that parity (#9415).
//
// Strict on the commit / commit-check path (CompileConfig — hard-reject);
// downgraded to a cfg.Warnings entry on the tolerant load / peer-sync paths
// (CompileConfigLenient / CompileConfigForNodeLenient, flag
// lenientScreenProfileRefs) so an already-persisted or peer-synced config that
// an older binary accepted still BOOTS (#1960 fail-closed-on-load doctrine).
// On that tolerant path the dataplane substitutes the conservative default
// (#7168), so the zone keeps the malformed-packet checks but loses every
// configured threshold; the warning is the operator's only signal that the
// configured profile is not in effect, and the strict commit gate is what keeps
// a bad reference from reaching the dataplane in the first place. Iteration is over cfg.Security.Zones in sorted name order so the
// first-reported error is deterministic.
func validateScreenProfileReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		zone := cfg.Security.Zones[name]
		if zone == nil || zone.ScreenProfile == "" {
			continue
		}
		if _, ok := cfg.Security.Screen[zone.ScreenProfile]; !ok {
			return fmt.Errorf(
				"security zone %q references undefined screen profile %q; define `set security screen ids-option %s` in the same commit; otherwise none of the zone's configured screen checks are in effect and the dataplane applies only the substituted conservative default (malformed-packet checks, no flood, scan or session-limit thresholds; #7168)",
				name, zone.ScreenProfile, zone.ScreenProfile)
		}
	}
	return nil
}

// sortedScreenNames returns the screen-profile names in deterministic order so
// the strict validators report the first offender stably across runs.
func sortedScreenNames(screens map[string]*ScreenProfile) []string {
	names := make([]string, 0, len(screens))
	for name := range screens {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// validateScreenNumericStrict hard-rejects a screen profile carrying a numeric
// threshold / count leaf whose explicitly-provided value is not a positive
// integer — #3317.
//
// Screen threshold leaves (icmp/udp flood, ip ip-sweep threshold, tcp port-scan
// threshold, the tcp syn-flood alarm/attack/source/destination-threshold and
// timeout subfields, and limit-session source/destination-ip-based) are untyped
// in the schema. Before this gate compileScreen swallowed the strconv.Atoi
// failure and silently fell back to a Junos default (icmp/udp flood, ip-sweep,
// port-scan, syn-flood attack-threshold via #3024/#3230) or to zero/disabled
// (the other syn-flood subfields and limit-session). A typo'd value
// (`attack-threshold abc`, `udp flood 99999999999999999999`, `source-ip-based
// -1`) therefore committed cleanly while the enforced control was materially
// different from — usually weaker or fully disabled relative to — what the
// operator authored: a silent fail-open. SRX rejects a non-numeric screen value
// at commit.
//
// compileScreen records every explicitly-provided value that does not parse as
// a positive integer on ScreenProfile.BadNumeric (path + raw value); an EMPTY
// value is the "enabled without an explicit threshold" case and is NOT recorded
// (it legitimately takes the Junos default — #3230). This gate makes the
// refusal operator-visible at commit, naming the screen profile, the leaf path,
// and the offending value. The walk is deterministic (profiles sorted by name,
// BadNumeric in config order). On the tolerant load / peer-sync path the caller
// downgrades the returned error to a warning (#1960 no-brick); compileScreen
// applied the default for the bad value independently, so a leniently-loaded
// profile is no worse than the pre-gate behavior — but the operator never
// reaches that state through a commit. Mirrors validateFilterDSCPStrict.
func validateScreenNumericStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	for _, name := range sortedScreenNames(cfg.Security.Screen) {
		profile := cfg.Security.Screen[name]
		if profile == nil || len(profile.BadNumeric) == 0 {
			continue
		}
		bad := profile.BadNumeric[0]
		return fmt.Errorf(
			"security screen ids-option %q: `%s` value %q is not a positive "+
				"integer (an unparseable value is silently dropped and the leaf "+
				"falls back to a default or to zero/disabled, so the protection "+
				"is weaker than — or fully different from — what was configured)",
			name, bad.Path, bad.Value)
	}
	return nil
}

// validateScreenUnknownStrict hard-rejects a screen profile carrying a leaf the
// dataplane does NOT support — #3318.
//
// The screen schema subtrees are open (schema_security.go: `icmp`, `tcp`, `ip`,
// `udp` model only their named children; an unknown keyword resolves to a nil
// schema child and returns no error), and compileScreen switched only on the
// known child names with no default arm. A misspelled or unsupported leaf
// (`icmp pong-death`, `tcp syn-flood whitelist`, `ip bad-option`, an unsupported
// SRX screen such as `tcp sweep`/`ip block-frag`) therefore committed cleanly
// and was silently DROPPED — the operator believed a protection was enabled when
// it was entirely absent, a "configured but not enforced" posture with no
// warning. SRX fails commit on an unknown screen option.
//
// The supported set is EXACTLY the compileScreen switch cases: icmp
// {ping-death, fragment, flood}; ip {source-route-option, tear-drop, ip-sweep
// {threshold}}; tcp {land, winnuke, syn-frag, syn-fin, no-flag, fin-no-ack,
// syn-flood {alarm/attack/source/destination-threshold, timeout}, port-scan
// {threshold}}; udp {flood}; limit-session {source-ip-based,
// destination-ip-based}. These are the leaves compileScreen ACCEPTS (records a
// typed field for) — most also map to a field the userspace screen engine
// (userspace-dp/src/screen) enforces. This gate's contract is "rejects what
// compileScreen does NOT model", not "guarantees every accepted leaf is
// enforced" — those are different claims and the second is not made here.
//
// #8942: this comment used to illustrate that distinction with the syn-flood
// alarm-threshold / source-threshold / destination-threshold / timeout
// subfields, calling them compiled-but-not-emitted and deferring the publish
// gap to #3315. That is no longer true of any of the four. The live userspace
// publish path emits all of them (pkg/dataplane/userspace/screens.go, into
// SYNFloodAlarmThreshold / SYNFloodSrcThreshold / SYNFloodDstThreshold /
// SYNFloodTimeout on the zone snapshot), and `timeout` in particular is
// enforced as a per-zone override of the half-open window under #3527. The
// contract sentence above stands on its own; the example did not, and a
// reader who trusted it would think four configurable screen controls were
// inert.
// compileScreen's default arms record every
// other leaf — at the top-level family, per-family, and per-subtree depth — on
// ScreenProfile.UnknownLeaves (the full `<family> <leaf>` path); this gate makes
// the refusal operator-visible at commit. No NEW screening is implemented — the
// unsupported leaf is rejected, which is the fail-closed-correct outcome. The
// walk is deterministic (profiles sorted by name, UnknownLeaves in config
// order). On the tolerant load / peer-sync path the caller downgrades the
// returned error to a warning (#1960 no-brick); the dataplane never represented
// the leaf, so a leniently-loaded profile runs without it independently — but
// the operator never reaches that state through a commit. Mirrors
// validateFilterFromMatchStrict.
func validateScreenUnknownStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	for _, name := range sortedScreenNames(cfg.Security.Screen) {
		profile := cfg.Security.Screen[name]
		if profile == nil || len(profile.UnknownLeaves) == 0 {
			continue
		}
		return fmt.Errorf(
			"security screen ids-option %q: `%s` is not a supported screen "+
				"option (the dataplane does not enforce it, so it would be "+
				"silently dropped and the protection the operator believes is "+
				"enabled would be absent); remove it or use a supported option "+
				"such as icmp ping-death/fragment/flood, ip source-route-option/tear-drop/"+
				"ip-sweep, tcp land/winnuke/syn-frag/syn-fin/no-flag/fin-no-ack/"+
				"syn-flood/port-scan, udp flood, or limit-session",
			name, profile.UnknownLeaves[0])
	}
	return nil
}
