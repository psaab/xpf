package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// lenient_permit_widening_5575_test.go is the end-to-end fail-on-revert guard
// for #5575: a policy the TOLERANT compile path (CompileConfigLenient — the
// persisted-load / HA-sync path) accepts only by DOWNGRADING a #3044
// missing-match / #3113 unsupported-match-leaf / #3114 unsupported-then-permit
// reject to a WARNING must lower to a NEVER-MATCH rule — it must carry the
// __unsupported__ application sentinel so the Rust integrity preflight rejects
// the WHOLE snapshot (previous-good retained; fresh-boot default-deny) — NOT a
// wildcard permit.
//
// Pre-fix the compiler dropped the offending match/permit constraint and left
// the dimension EMPTY, which expandUserspacePolicyApplications /
// expandUserspacePolicyAddresses lower to match-ANY: the leniently-loaded
// permit widened to permit-more-than-configured (a security fail-open). The
// sentinel subtests here flip RED if either the compilePolicy
// LenientContentDropped flag OR the buildOneRuleSnapshot poison is reverted (the
// rule collapses back to match-any → no sentinel → empty PolicyContentRejected).
// The clean subtest pins that an INTENTIONAL wildcard (explicit `any`) stays
// match-any (no sentinel), preserving the empty-vs-dropped distinction.

func lenientSnapshot5575(t *testing.T, cmds [][]string) *ConfigSnapshot {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		if err := tree.SetPath(cmd); err != nil {
			t.Fatalf("SetPath(%v): %v", cmd, err)
		}
	}
	// The tolerant load / peer-sync path — the exact path #5575 fails open on.
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	return snap
}

func snapshotHasAppSentinel5575(snap *ConfigSnapshot) bool {
	for _, pol := range snap.Policies {
		for _, term := range pol.ApplicationTerms {
			if term.Protocol == unsupportedApplicationSentinel || term.Name == unsupportedApplicationSentinel {
				return true
			}
		}
	}
	return false
}

func TestLenientWidenedPolicyLowersToSentinel5575(t *testing.T) {
	zones := [][]string{
		{"security", "zones", "security-zone", "trust"},
		{"security", "zones", "security-zone", "untrust"},
	}
	p := func(rest ...string) []string {
		return append([]string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p", "match"}, rest...)
	}
	then := func(rest ...string) []string {
		return append([]string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p", "then"}, rest...)
	}
	cases := []struct {
		name string
		cmds [][]string
	}{
		{
			// #3044 — the core permit-widening repro: a permit with only
			// source-address any. Pre-fix dst=[]/apps=[] → match-any → permits
			// EVERYTHING trust->untrust. Must now carry the sentinel.
			name: "permit missing destination+application",
			cmds: append(append([][]string{}, zones...),
				p("source-address", "any"),
				then("permit"),
			),
		},
		{
			// #3113 — unsupported match leaf (dynamic-application) dropped.
			name: "permit with unsupported match leaf",
			cmds: append(append([][]string{}, zones...),
				p("source-address", "any"),
				p("destination-address", "any"),
				p("application", "any"),
				p("dynamic-application", "junos:FTP"),
				then("permit"),
			),
		},
		{
			// #3114 — unsupported then-permit service chain dropped.
			name: "permit with unsupported then-permit modifier",
			cmds: append(append([][]string{}, zones...),
				p("source-address", "any"),
				p("destination-address", "any"),
				p("application", "any"),
				then("permit", "application-services", "utm-policy", "strict"),
			),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := lenientSnapshot5575(t, tc.cmds)
			if !snapshotHasAppSentinel5575(snap) {
				t.Fatalf("no __unsupported__ sentinel term: the leniently-loaded widened permit lowered to match-any — the Rust preflight would NOT reject it (permit-widening fail-open, #5575)")
			}
			if len(snap.Capabilities.PolicyContentRejected) == 0 {
				t.Fatal("PolicyContentRejected empty: the fail-closed whole-snapshot reject diagnostic must be recorded for a lenient-dropped policy")
			}
		})
	}
}

// TestLenientMalformedDenyLowersToSentinel5575 covers the deny case the issue
// calls out: a malformed deny (missing match dimensions) over a DEFAULT-PERMIT
// rulebase must NOT be silently turned into a broader default-permit. The
// __unsupported__ sentinel rejects the whole snapshot (default-deny / last-good)
// instead of collapsing the deny to a match-any (or, worse under a per-rule
// never-match, letting it fall through to default-permit).
func TestLenientMalformedDenyLowersToSentinel5575(t *testing.T) {
	snap := lenientSnapshot5575(t, [][]string{
		{"security", "policies", "default-policy", "permit-all"},
		{"security", "zones", "security-zone", "trust"},
		{"security", "zones", "security-zone", "untrust"},
		{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p", "match", "source-address", "any"},
		{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p", "then", "deny"},
	})
	if !snapshotHasAppSentinel5575(snap) {
		t.Fatal("malformed deny did not lower to the __unsupported__ sentinel: without the whole-snapshot reject it would collapse to match-any and, over a default-permit rulebase, risk widening to permit (#5575 deny guard)")
	}
	if len(snap.Capabilities.PolicyContentRejected) == 0 {
		t.Fatal("PolicyContentRejected empty for a malformed deny; want the fail-closed diagnostic")
	}
}

// TestLenientCompleteAnyPermitStaysMatchAny5575 is the empty-vs-dropped
// boundary: a permit that names all three dimensions as explicit `any` is a
// legitimate match-any permit and must NOT be poisoned — no sentinel, no
// content rejection. A revert that keys the fail-close on "empty dimension"
// rather than "dropped constraint" would over-poison this and RED here.
func TestLenientCompleteAnyPermitStaysMatchAny5575(t *testing.T) {
	snap := lenientSnapshot5575(t, [][]string{
		{"security", "zones", "security-zone", "trust"},
		{"security", "zones", "security-zone", "untrust"},
		{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p", "match", "source-address", "any"},
		{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p", "match", "destination-address", "any"},
		{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p", "match", "application", "any"},
		{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "p", "then", "permit"},
	})
	if snapshotHasAppSentinel5575(snap) {
		t.Fatal("an explicit any->any:any permit must stay match-any, not be poisoned with the sentinel (empty-vs-dropped distinction, #5575)")
	}
	if len(snap.Capabilities.PolicyContentRejected) != 0 {
		t.Fatalf("PolicyContentRejected = %v, want empty for a legitimate match-any permit", snap.Capabilities.PolicyContentRejected)
	}
}
func TestMalformedFromListZonePairRefusesSnapshot12039(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, command := range []string{
		"set security zones security-zone A",
		"set security zones security-zone B",
		"set security zones security-zone C",
		"set security policies from-zone [ A C ] to-zone B policy p1 match source-address any",
		"set security policies from-zone [ A C ] to-zone B policy p1 match destination-address any",
		"set security policies from-zone [ A C ] to-zone B policy p1 match application any",
		"set security policies from-zone [ A C ] to-zone B policy p1 then deny",
		"set security policies global policy g-permit match source-address any",
		"set security policies global policy g-permit match destination-address any",
		"set security policies global policy g-permit match application any",
		"set security policies global policy g-permit then permit",
		"set security policies default-policy permit-all",
	} {
		path, quoted, grouped, err := config.ParseSetCommandGrouped(command)
		if err != nil {
			t.Fatalf("ParseSetCommandGrouped(%q): %v", command, err)
		}
		if err := tree.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
			t.Fatalf("SetPathQuotedGrouped(%q): %v", command, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if got := config.LenientDroppedPolicyLocator(cfg); got == "" {
		t.Error("grouped from-zone list left NO poisoned global carrier — the dropped deny is not represented by the existing synthetic-global-poison path (#12039)")
	}
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if !snapshotHasAppSentinel5575(snap) {
		t.Error("snapshot has no __unsupported__ sentinel for the grouped from-zone list — the Rust integrity preflight would not refuse it and A->B/C->B can fall through to the global permit (#12039)")
	}
	if len(snap.Capabilities.PolicyContentRejected) == 0 {
		t.Error("snapshot PolicyContentRejected is empty — the helper would not refuse this grouped from-zone list (#12039)")
	}
}
