package config

import (
	"strings"
	"testing"
)

// #16867: `ValidateFRRObjectName` (the #9493 commit validator for
// prefix-list names) had no length bound, and `frrName` passed operator
// names through unchanged. A prefix-list name longer than FRR's 128-byte
// YANG `list-name` limit committed strict-clean; FRR rejected the leaf
// with "Unsatisfied length" but left a half-built match-condition node,
// and the next `show running-config` — the first step of every
// frr-reload.py run — SIGABRT'd five routing daemons.
//
// FAIL-ON-REVERT: reverting the keyValidator on the prefix-list leaf to
// ValidateFRRObjectName (or dropping the length check from
// ValidateFRRPrefixListName) makes the 129-byte and 137-byte rows commit
// clean below; reverting the frrName belt is pinned separately in
// pkg/frr (TestFRRNameOverlongAlias16867).

func TestValidateFRRPrefixListName16867(t *testing.T) {
	at := strings.Repeat("a", FRRNameMaxLen)
	if err := ValidateFRRPrefixListName(at); err != nil {
		t.Errorf("a %d-byte prefix-list name is at FRR's limit and must be accepted: %v", FRRNameMaxLen, err)
	}
	for _, n := range []int{FRRNameMaxLen + 1, 137, 300} {
		name := strings.Repeat("a", n)
		err := ValidateFRRPrefixListName(name)
		if err == nil {
			t.Errorf("a %d-byte prefix-list name must be refused at commit (#16867)", n)
			continue
		}
		if !strings.Contains(err.Error(), "128") || !strings.Contains(err.Error(), "#16867") {
			t.Errorf("%d-byte rejection must name the 128-byte bound and #16867: %v", n, err)
		}
	}
	// The shared single-token gate still fires through the wrapper.
	if err := ValidateFRRPrefixListName("a b"); err == nil {
		t.Error("a whitespace name must still be refused")
	}
	if err := ValidateFRRPrefixListName(""); err == nil {
		t.Error("an empty name must still be refused")
	}
}

// The measured FRR length bound gates ONLY the YANG `list-name` leaf
// at commit: route-map and community-list names are not length-bounded,
// and neither are as-path DEFINITION names (the 1..128
// `filter:access-list-name` bound applies to `match as-path` references
// and is enforced by the render belt). The shared validator must stay
// unbounded — bounding it would refuse names this product already
// accepts.
func TestValidateFRRObjectNameUnbounded16867(t *testing.T) {
	long := strings.Repeat("a", 200)
	if err := ValidateFRRObjectName(long); err != nil {
		t.Errorf("a 200-byte route-map/community/as-path name must stay accepted (FRR does not bound those classes): %v", err)
	}
	// Pair gate: the same overlong name ALONE (no literal alias beside
	// it) is clean — it strictly rejects only as a prefix-list, and the
	// pair gate fires on the PAIR, not the singleton.
	alone := &Config{PolicyOptions: PolicyOptionsConfig{PolicyStatements: map[string]*PolicyStatement{
		long: {Name: long},
	}}}
	if err := validateFRRNameAliasCollisionStrict(alone); err != nil {
		t.Errorf("an overlong name alone must pass the pair gate: %v", err)
	}
}

// Strict commit (SchemaValidate, the commit/commit-check path) must
// reject the defect cell — a 137-byte prefix-list name referenced by a
// policy term — while the control at exactly 128 bytes and an overlong
// policy-statement (route-map) name commit clean.
func TestLongPrefixListNameRejectedAtStrictCommit16867(t *testing.T) {
	build := func(plName, psName string) *ConfigTree {
		tree := &ConfigTree{}
		for _, c := range []string{
			`set policy-options prefix-list "` + plName + `" 10.0.0.0/8`,
			`set policy-options policy-statement "` + psName + `" term t1 from prefix-list "` + plName + `"`,
			`set policy-options policy-statement "` + psName + `" term t1 then accept`,
		} {
			path, err := ParseSetCommand(c)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", c, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", c, err)
			}
		}
		return tree
	}

	// Defect cell: 137-byte prefix-list name (the source report's l1).
	longPL := strings.Repeat("a", 137)
	if err := SchemaValidate(build(longPL, "EXPORT")); err == nil {
		t.Fatal("strict commit ACCEPTED a 137-byte prefix-list name — FRR would reject the " +
			"list-name leaf, leave a half-built match-condition, and abort the routing " +
			"daemons on the next show running-config (#16867)")
	} else if !strings.Contains(err.Error(), "128") {
		t.Errorf("strict rejection does not name the 128-byte bound: %v", err)
	}

	// Control at the boundary: exactly 128 bytes commits clean.
	atLimit := strings.Repeat("a", FRRNameMaxLen)
	if err := SchemaValidate(build(atLimit, "EXPORT")); err != nil {
		t.Errorf("control: a 128-byte prefix-list name must commit clean, got: %v", err)
	}

	// Ungated classes: a 137-byte policy-statement (route-map) name is
	// not YANG-length-bounded in FRR and must still commit clean.
	longPS := strings.Repeat("b", 137)
	if err := SchemaValidate(build("PL", longPS)); err != nil {
		t.Errorf("a 137-byte policy-statement name must commit clean (route-maps are not length-bounded), got: %v", err)
	}
}

// Kimi gate (PR #17819): the frrName alias map must be injective against
// operator names. An overlong raw name L and the literal A = frrName(L)
// are BOTH commit-valid individually (A is a fine single token within
// 128 bytes), yet render as one FRR object — silently merging two
// distinct policies. The alias marker is therefore RESERVED: any name
// carrying it is refused at the leaf, so a literal alias can never be
// committed beside (or instead of) its source.
//
// FAIL-ON-REVERT: dropping the marker check from ValidateFRRObjectName
// makes the literal-alias row below commit clean.
func TestFRRAliasMarkerReserved16867(t *testing.T) {
	// An alias as the renderer derives it for an overlong name
	// (fragment truncated to 128 - len(marker) - 8, plus marker + 8 hex).
	alias := strings.Repeat("a", FRRNameMaxLen-len(FRRNameEscapeMarker)-8) + FRRNameEscapeMarker + "0123abcd"
	if len(alias) > FRRNameMaxLen {
		t.Fatalf("fixture alias is %d bytes, over the bound", len(alias))
	}
	for _, tc := range []struct{ name, raw string }{
		{"literal alias of the overlong name", alias},
		{"short forged alias", "PL" + FRRNameEscapeMarker + "deadbeef"},
		{"marker anywhere in the name", "x" + FRRNameEscapeMarker + "y"},
	} {
		if err := ValidateFRRObjectName(tc.raw); err == nil {
			t.Errorf("%s: ValidateFRRObjectName(%q) accepted a name carrying the reserved alias marker", tc.name, tc.raw)
		} else if !strings.Contains(err.Error(), "reserved") || !strings.Contains(err.Error(), "#16867") {
			t.Errorf("%s: rejection must name the reservation and #16867: %v", tc.name, err)
		}
		if err := ValidateFRRPrefixListName(tc.raw); err == nil {
			t.Errorf("%s: ValidateFRRPrefixListName(%q) accepted the reserved marker", tc.name, tc.raw)
		}
	}
	// Controls: ordinary names, including dash/underscore lookalikes that
	// do NOT carry the marker, stay accepted.
	for _, ok := range []string{"EXPORT", "my-policy_v2", "a-xpf-chain", "xpfesc", "a-xpfesc", "xpfesc-"} {
		if err := ValidateFRRObjectName(ok); err != nil {
			t.Errorf("control %q must stay accepted: %v", ok, err)
		}
	}
	// The L/A pair at strict commit: L itself is refused (overlong), and
	// A is refused (marker) — the pair can never coexist in a commit.
	build := func(plName string) *ConfigTree {
		tree := &ConfigTree{}
		for _, c := range []string{
			`set policy-options prefix-list "` + plName + `" 10.0.0.0/8`,
			`set policy-options policy-statement EXPORT term t1 from prefix-list "` + plName + `"`,
			`set policy-options policy-statement EXPORT term t1 then accept`,
		} {
			path, err := ParseSetCommand(c)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", c, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", c, err)
			}
		}
		return tree
	}
	if err := SchemaValidate(build(alias)); err == nil {
		t.Fatal("strict commit ACCEPTED the literal frrName alias as a prefix-list name — " +
			"it could collide with the alias of its overlong source name and merge policies (#16867)")
	}
}

// The compiled-config pair gate (validateFRRNameAliasCollisionStrict) is
// the backstop for pairs the leaf gate cannot see in isolation: it
// evaluates the compiled PolicyOptions with the same alias derivation
// the renderer uses. It is exercised directly here because a pair that
// survives the leaf gate cannot be built through the public commit path
// by construction.
func TestFRRNameAliasCollisionPairGate16867(t *testing.T) {
	long := strings.Repeat("a", 137)
	// Derive the TRUE alias of `long` through the mirror so the fixture
	// pair is exact, not hand-computed.
	alias := frrNameAlias16867(long)
	if alias == long || len(alias) > FRRNameMaxLen {
		t.Fatalf("mirror alias %q is not a bounded distinct alias", alias)
	}
	pair := &Config{PolicyOptions: PolicyOptionsConfig{PrefixLists: map[string]*PrefixList{
		long:  {Name: long, Prefixes: []string{"10.0.0.0/8"}},
		alias: {Name: alias, Prefixes: []string{"192.168.0.0/16"}},
	}}}
	if err := validateFRRNameAliasCollisionStrict(pair); err == nil {
		t.Fatal("the L/A pair passed the collision gate — the two prefix-lists would render " +
			"as one FRR list and silently merge (#16867)")
	} else if !strings.Contains(err.Error(), "#16867") {
		t.Errorf("pair rejection must cite #16867: %v", err)
	}
	// Controls: distinct names, and the SAME name in DIFFERENT classes
	// (FRR namespaces are per-class), are clean.
	clean := &Config{PolicyOptions: PolicyOptionsConfig{
		PrefixLists:      map[string]*PrefixList{"PL": {Name: "PL"}, alias + "z": {Name: alias + "z"}},
		Communities:      map[string]*CommunityDef{long: {Name: long}},
		PolicyStatements: map[string]*PolicyStatement{"EXPORT": {Name: "EXPORT"}},
	}}
	if err := validateFRRNameAliasCollisionStrict(clean); err != nil {
		t.Errorf("control config must be clean, got: %v", err)
	}
	if err := validateFRRNameAliasCollisionStrict(nil); err != nil {
		t.Errorf("nil config must be clean: %v", err)
	}
	if err := validateFRRNameAliasCollisionStrict(&Config{}); err != nil {
		t.Errorf("empty config must be clean: %v", err)
	}
}
