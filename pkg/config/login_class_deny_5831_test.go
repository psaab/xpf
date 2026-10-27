package config

import (
	"testing"
)

// #5831 — a custom `system login class` may carry deny-commands /
// deny-configuration. Historically (before #5831) such a config committed
// cleanly and enforced nothing: the operator held a config saying a verb
// was denied and a box on which it was allowed. #5831/#6838 therefore
// hard-rejected the class at commit and folded it to a repair floor on
// the tolerant path. #7172 implemented real regex enforcement and cut 6
// retired both the rejection and the fold (see
// TestDenyClassCommitsAndIsNotFolded_7172).
//
// These tests now pin the surviving invariants: leaf presence is recorded
// (an empty regex differs from an absent one), the classification tables
// stay in step with the schema and drive the compiler, the additive
// allow-* half is recorded as allowlists, and a deny-* class commits
// unfolded on both paths.

// buildLoginTree5831 builds a ConfigTree from flat `set` lines. It uses
// ParseSetCommand + SetPath and NEVER NewParser: the parser treats newlines as
// whitespace and would merge every line into one node, silently invalidating
// the test.
func buildLoginTree5831(t *testing.T, cmds []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestLoginClassValidStillCommits is the POSITIVE CONTROL. Without it the
// rejection tests above cannot distinguish "rejects the bad config" from
// "rejects everything".
//
// It also pins the DIRECTIONALITY finding: allow-commands / allow-configuration
// are ADDITIVE in Junos (they grant access beyond the permission bits), so
// ignoring them yields a SUBSET of what the operator wrote — fail-closed. They
// must keep committing with the #4304 advisory. Rejecting them would break
// configs that are already safe.
func TestLoginClassValidStillCommits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{"plain class", []string{
			"set system login class limited permissions view",
		}},
		{"permissions all", []string{
			"set system login class limited permissions all",
		}},
		{"allow-commands (additive, fail-closed when ignored)", []string{
			"set system login class limited permissions view",
			`set system login class limited allow-commands "show interfaces"`,
		}},
		{"allow-configuration (additive, fail-closed when ignored)", []string{
			"set system login class limited permissions view",
			`set system login class limited allow-configuration "interfaces"`,
		}},
		{"both allow leaves plus idle-timeout", []string{
			"set system login class limited permissions clear",
			`set system login class limited allow-commands "show interfaces"`,
			`set system login class limited allow-configuration "interfaces"`,
			"set system login class limited idle-timeout 30",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := append([]string{}, tc.lines...)
			lines = append(lines, "set system login user carol class limited")
			cfg, err := CompileConfig(buildLoginTree5831(t, lines))
			if err != nil {
				t.Fatalf("a class with no restrictive regex must still commit; got %v", err)
			}
			if cfg.System.Login == nil || len(cfg.System.Login.Classes) != 1 {
				t.Fatalf("expected the class to survive the commit; got %+v", cfg.System.Login)
			}
		})
	}
}

// TestLoginClassDenyGateIsScopedToRestrictiveLeaves proves the gate does not
// fire on the additive half even on the tolerant path — an allow-only class
// must keep its permissions untouched. A gate that folded every class carrying
// any of the four regexes would be scoped WIDER than its claim and would
// silently strip access the operator legitimately granted.
func TestLoginClassDenyGateIsScopedToRestrictiveLeaves(t *testing.T) {
	tree := buildLoginTree5831(t, []string{
		"set system login class helper permissions all",
		`set system login class helper allow-commands "show interfaces"`,
		`set system login class helper allow-configuration "interfaces"`,
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	lc := cfg.System.Login.Classes[0]
	if len(lc.DenyLeavesPresent) != 0 {
		t.Fatalf("allow-* leaves must not be recorded as restrictive; got %v", lc.DenyLeavesPresent)
	}
	found := false
	for _, p := range lc.MappedPermissions {
		if p == PermAll {
			found = true
		}
	}
	if !found {
		t.Fatalf("an allow-only class must keep its permissions; got %v", lc.MappedPermissions)
	}
}

// TestLoginClassDenyPresenceSurvivesEmptyValue is the unit-level statement of
// the quoted-empty edge: presence must be recorded even when the value is
// empty, because that is precisely the case a value test cannot see.
func TestLoginClassDenyPresenceSurvivesEmptyValue(t *testing.T) {
	tree := buildLoginTree5831(t, []string{
		"set system login class limited permissions view",
		`set system login class limited deny-commands ""`,
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	lc := cfg.System.Login.Classes[0]
	if lc.DenyCommands != "" {
		t.Fatalf("precondition: expected the quoted-empty regex to flatten to \"\"; got %q", lc.DenyCommands)
	}
	if len(lc.DenyLeavesPresent) != 1 || lc.DenyLeavesPresent[0] != "deny-commands" {
		t.Fatalf("presence of a quoted-empty deny-commands was LOST — a value-based gate "+
			"would accept the most restrictive regex an operator can write; got %v", lc.DenyLeavesPresent)
	}
}

// TestLoginClassSchemaLeavesAreClassified_5831 is the schema-drift canary for
// the deny gate (#6838 review M3), the sibling of
// TestLoginInstanceKeywordsMatchSchema_6662 for the packed gate.
//
// loginClassLeafRestrictive is what decides whether a `login class`
// sub-statement is gated as restrictive. A leaf added to the schema without a
// row there parses, compiles, and configures NOTHING — silently reinstating the
// exact fail-open #5831 exists to close, one statement over. Junos has several
// candidates this project does not model yet: deny-hidden-commands,
// access-start / access-end, allowed-days.
//
// Pinning the key set in BOTH directions is the point. Schema-not-classified is
// the fail-open. Classified-not-schema is a row that gates nothing and would
// make the table look more complete than it is.
func TestLoginClassSchemaLeavesAreClassified_5831(t *testing.T) {
	class := setSchema.children["system"].children["login"].children["class"]
	if class == nil || len(class.children) == 0 {
		t.Fatal("setSchema has no `system login class` node with children")
	}

	// #7172 cut 6 added the second table, and BOTH are pinned here. A leaf
	// classified in one and forgotten in the other fails open: an unclassified
	// restrictive leaf loses its presence record — the only thing separating an
	// empty regex from an absent one — and an unclassified allow leaf silently
	// stops being an allowlist.
	for _, tbl := range []struct {
		name  string
		table map[string]bool
	}{
		{"loginClassLeafRestrictive", loginClassLeafRestrictive},
		{"loginClassLeafAllowRegex", loginClassLeafAllowRegex},
	} {
		for name := range class.children {
			if _, ok := tbl.table[name]; !ok {
				t.Errorf("`login class %s` is in the schema but NOT classified in %s — a "+
					"regex leaf with no row loses its PRESENCE record, and presence is the "+
					"only thing separating an empty pattern from an absent one; if the leaf "+
					"is neither restrictive nor an allow regex, say so with an explicit "+
					"`false` row", name, tbl.name)
			}
		}
		for name := range tbl.table {
			if _, ok := class.children[name]; !ok {
				t.Errorf("%s classifies %q, which is not a `login class` schema child — the "+
					"row records nothing and overstates the table's coverage", tbl.name, name)
			}
		}
	}
}

// TestLoginClassRestrictiveClassificationIsEnforced_5831 closes the canary's
// other half: the classification must DRIVE the compiler, not merely describe
// it. Without it, a correct table paired with a compiler that ignored it would
// still fail open and the key-set canary above would stay green.
//
// #7172 cut 6 INVERTED one arm and kept the other, and the distinction is worth
// reading carefully. What it used to assert:
//
//	restrictive leaf -> recorded in DenyLeavesPresent AND REJECTED at commit
//
// The rejection was #5831/#6838's admission gate, which existed only because
// the regexes were not enforced. They are now, so the same config must COMMIT.
// That arm is not loosened, it is FALSIFIED — keeping it would pin the very
// gate this feature exists to remove.
//
// The presence arm is unchanged and was always the load-bearing one:
// DenyLeavesPresent is the only thing separating `deny-commands ""` (an empty
// POSIX regex — denies EVERY command) from an absent leaf (denies nothing). The
// gate is gone; the table it was built on outlives it.
func TestLoginClassRestrictiveClassificationIsEnforced_5831(t *testing.T) {
	for leaf, restrictive := range loginClassLeafRestrictive {
		if leaf == "permissions" {
			continue // the identity leaf, not a sub-statement with a regex value
		}
		t.Run(leaf, func(t *testing.T) {
			tree := buildLoginTree5831(t, []string{
				"set system login class limited permissions view",
				"set system login class limited " + leaf + " 1",
			})
			cfg, strictErr := CompileConfig(tree)
			if strictErr != nil {
				t.Fatalf("%q must COMMIT on the strict path now that #7172 cut 6 retired the "+
					"#5831/#6838 admission gate: the regexes are enforced, so refusing the "+
					"statement would be refusing a control we implement: %v", leaf, strictErr)
			}
			got := len(cfg.System.Login.Classes[0].DenyLeavesPresent) > 0
			if got != restrictive {
				t.Fatalf("loginClassLeafRestrictive[%q]=%v but DenyLeavesPresent recorded=%v — "+
					"the table and the compiler disagree about this leaf", leaf, restrictive, got)
			}
		})
	}
}

// TestLoginClassAllowClassificationIsRecorded_7172 is the same property for the
// ALLOW table cut 6 added.
//
// Not decoration: an allow leaf whose presence is not recorded stops being an
// allowlist, and the config that makes a value test wrong is the one Juniper
// documents by name — `allow-commands ""` beside `deny-commands ""` puts the
// IDENTICAL pattern in both leaves, which is precedence tier 1, where allow
// wins and the class is allowed everything. Lose the allow presence and the
// same config denies everything instead.
func TestLoginClassAllowClassificationIsRecorded_7172(t *testing.T) {
	for leaf, isAllow := range loginClassLeafAllowRegex {
		if leaf == "permissions" {
			continue
		}
		t.Run(leaf, func(t *testing.T) {
			tree := buildLoginTree5831(t, []string{
				"set system login class limited permissions view",
				"set system login class limited " + leaf + " 1",
			})
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			got := len(cfg.System.Login.Classes[0].AllowLeavesPresent) > 0
			if got != isAllow {
				t.Fatalf("loginClassLeafAllowRegex[%q]=%v but AllowLeavesPresent recorded=%v",
					leaf, isAllow, got)
			}
		})
	}
}

// THE RETIREMENT, asserted as behaviour rather than as an absence.
//
// A config carrying deny-commands was REJECTED at commit before cut 6 and
// commits now — and takes effect. This is the upgrade note in executable form.
//
// The permissions arm is the half a reader is most likely to miss. The tolerant
// path used to FOLD such a class to a repair floor, because an unenforceable
// restriction had to be resolved in the restrictive direction somehow. With the
// regexes enforced, folding would narrow the class a SECOND time on top of its
// own regexes — so the fold went with the gate, and this pins that the
// permission set arrives untouched on BOTH paths.
func TestDenyClassCommitsAndIsNotFolded_7172(t *testing.T) {
	lines := []string{
		"set system login class limited permissions all",
		`set system login class limited deny-commands "request system zeroize"`,
	}
	for _, tc := range []struct {
		name    string
		compile func(*ConfigTree) (*Config, error)
	}{
		{"strict", CompileConfig},
		{"lenient", CompileConfigLenient},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := tc.compile(buildLoginTree5831(t, lines))
			if err != nil {
				t.Fatalf("a deny-commands class must commit after the retirement: %v", err)
			}
			lc := cfg.System.Login.Classes[0]
			if lc.DenyCommands != "request system zeroize" {
				t.Errorf("the pattern must survive compilation verbatim, got %q", lc.DenyCommands)
			}
			if len(lc.DenyLeavesPresent) != 1 || lc.DenyLeavesPresent[0] != "deny-commands" {
				t.Errorf("presence must still be recorded, got %v", lc.DenyLeavesPresent)
			}
			// COMPARATIVE, not a literal: assert the permission set is what the
			// SAME class gets without the deny leaf. Pinning a literal here
			// would encode today's mapping of `permissions all` and would go
			// red for a reason that has nothing to do with folding.
			base, err := tc.compile(buildLoginTree5831(t, lines[:1]))
			if err != nil {
				t.Fatalf("control compile: %v", err)
			}
			want := base.System.Login.Classes[0].MappedPermissions
			if len(want) == 0 {
				t.Fatal("the control class has no mapped permissions, so this comparison " +
					"would hold for a class folded to nothing")
			}
			if len(lc.MappedPermissions) != len(want) {
				t.Fatalf("the deny leaf changed the permission set: got %v, want %v (the "+
					"same class without the leaf). The repair-floor fold was #5831's answer "+
					"to an UNENFORCEABLE restriction; with the regexes enforced it would "+
					"narrow the class twice.", lc.MappedPermissions, want)
			}
			for i := range want {
				if lc.MappedPermissions[i] != want[i] {
					t.Fatalf("the deny leaf changed the permission set: got %v, want %v",
						lc.MappedPermissions, want)
				}
			}
		})
	}
}

// THE CASE THAT JUSTIFIES AllowLeavesPresent, and the only one that separates
// presence-detection from value-detection for the ALLOW leaf.
//
// Found by mutation: replacing `allowSet := containsLoginLeaf(...)` with
// `allowSet := allow != ""` left the whole suite green. Every other cell in
// this issue uses a NON-EMPTY allow pattern, where the two readings agree — so
// the long comment on AllowLeavesPresent explaining why they differ had no
// guard at all, which is a claim, not a check.
//
// They differ here, and in opposite directions:
//
//	allow-commands "";  deny-commands "";
//
//	presence: allowSet=true, denySet=true, and the two patterns are IDENTICAL —
//	          precedence tier 1, where allow wins. Everything is ALLOWED.
//	value:    allowSet=false (the value is ""), denySet=true. A deny-only class
//	          whose empty POSIX regex matches every command. Everything is DENIED.
//
// Tier 1 is Juniper's, stated outright, so the presence reading is the parity
// answer. It also happens to be the permissive one, which is why this needs a
// test rather than an argument: a reviewer hardening the value reading would be
// choosing "safer" over correct, and nothing would have contradicted them.
func TestEmptyAllowBesideEmptyDenyIsTier1_7172(t *testing.T) {
	cfg, err := CompileConfig(buildLoginTree5831(t, []string{
		"set system login class edge permissions all",
		`set system login class edge allow-commands ""`,
		`set system login class edge deny-commands ""`,
	}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	lc := cfg.System.Login.Classes[0]
	// PRECONDITION: both leaves must be recorded present. Without this the cell
	// would pass for a config that carried neither, which is a third outcome
	// entirely.
	if len(lc.AllowLeavesPresent) != 1 || len(lc.DenyLeavesPresent) != 1 {
		t.Fatalf("both leaves must be recorded PRESENT despite empty values; "+
			"allow=%v deny=%v", lc.AllowLeavesPresent, lc.DenyLeavesPresent)
	}

	rules, ok, err := OperationalLoginRegexesFor(cfg, "edge")
	if err != nil || !ok {
		t.Fatalf("the class must yield compiled rules (ok=%v err=%v)", ok, err)
	}
	d := rules.Evaluate("request system reboot")
	if !d.Allowed {
		t.Errorf("identical patterns in both leaves is precedence TIER 1, where allow wins "+
			"— Juniper states it outright. Denying here means the empty allow was read as "+
			"ABSENT, which turns the config into a deny-everything class: %s", d.Reason)
	}
	if d.DecidedBy != LoginRegexAllow {
		t.Errorf("tier 1 must be decided by ALLOW, got %v (%s)", d.DecidedBy, d.Reason)
	}

	// THE CONTROL that makes the cell mean something: the SAME empty deny with
	// NO allow leaf denies everything. Without this arm, a gate that allowed
	// everything unconditionally would also pass.
	cfgDenyOnly, err := CompileConfig(buildLoginTree5831(t, []string{
		"set system login class edge permissions all",
		`set system login class edge deny-commands ""`,
	}))
	if err != nil {
		t.Fatalf("compile deny-only: %v", err)
	}
	denyOnly, ok, err := OperationalLoginRegexesFor(cfgDenyOnly, "edge")
	if err != nil || !ok {
		t.Fatalf("deny-only class must yield rules (ok=%v err=%v)", ok, err)
	}
	if denyOnly.Evaluate("request system reboot").Allowed {
		t.Error("an empty deny with no allow leaf matches every command and must deny — " +
			"if this permits, the presence record is not reaching the matcher at all")
	}
}
