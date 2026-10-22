package config

import (
	"strings"
	"testing"
)

// compileSetLines builds a ConfigTree from flat-set lines and compiles it,
// returning the compiled config. It fails the test on parse/compile errors.
func compileSetLines(t *testing.T, lines []string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// TestStaticNATFromZoneCompiles anchors the existing behavior: the static
// NAT rule-set `from zone` is compiled onto StaticNATRuleSet.FromZone and
// the rule body survives. This guards against a regression that would drop
// the zone scoping the dataplane relies on (static_nat.rs match_dnat).
func TestStaticNATFromZoneCompiles(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security zones security-zone untrust",
		"set security zones security-zone trust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 203.0.113.5/32",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32",
	})

	if len(cfg.Security.NAT.Static) != 1 {
		t.Fatalf("expected 1 static NAT rule-set, got %d", len(cfg.Security.NAT.Static))
	}
	rs := cfg.Security.NAT.Static[0]
	if rs.FromZone != "untrust" {
		t.Fatalf("expected FromZone=untrust, got %q", rs.FromZone)
	}
	if len(rs.Rules) != 1 || rs.Rules[0].Match != "203.0.113.5/32" {
		t.Fatalf("rule body not compiled: %+v", rs.Rules)
	}
}

// TestStaticNATFromZoneUndefinedWarns is the H15 regression: an undefined
// from-zone on a static NAT rule-set silently produces a rule that the
// dataplane will never match (static_nat.rs match_dnat requires an exact
// ingress-zone string match), with no commit warning. Source NAT already
// validates its from/to zones; static NAT did not. The validator must now
// surface the typo'd zone the same way.
//
// Reverting the static-NAT branch in ValidateConfig's "Validate NAT zone
// references" loop makes this test fail (no warning emitted).
func TestStaticNATFromZoneUndefinedWarns(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security zones security-zone untrust",
		// Note: "untrsut" is a deliberate typo — not a defined zone.
		"set security nat static rule-set rs1 from zone untrsut",
		"set security nat static rule-set rs1 rule r1 match destination-address 203.0.113.5/32",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32",
	})

	warnings := ValidateConfig(cfg)
	var saw bool
	for _, w := range warnings {
		if strings.Contains(w, "static-nat") &&
			strings.Contains(w, "untrsut") &&
			strings.Contains(w, "not defined") {
			saw = true
		}
	}
	if !saw {
		t.Fatalf("expected static-nat undefined from-zone warning, got %v", warnings)
	}
}

// TestStaticNATValidFromZoneNoWarn ensures a correctly-spelled from-zone
// does NOT produce a spurious warning (the validator must only fire on
// genuinely undefined zones).
func TestStaticNATValidFromZoneNoWarn(t *testing.T) {
	cfg := compileSetLines(t, []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 203.0.113.5/32",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32",
	})
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "static-nat") && strings.Contains(w, "not defined") {
			t.Fatalf("unexpected static-nat zone warning for defined zone: %q", w)
		}
	}
}

// TestStaticNATSchemaAcceptsFromZone is the schema-hardening half of H15:
// the static NAT rule-set schema node must declare `from { zone }` so the
// from-zone slot gains CLI completion (`from` keyword + `zone` keyword +
// zone-name value hint), matching destination/source NAT. Before the fix
// the static-NAT rule-set was an opaque `children: nil` passthrough that
// offered no completion for `from`.
//
// Reverting the schema fill drops the `from` completion under a static-NAT
// rule-set and the `zone` completion under `from`, failing this test.
func TestStaticNATSchemaAcceptsFromZone(t *testing.T) {
	// `from` must be offered as a child of a static-NAT rule-set instance.
	fromResults := CompleteSetPathWithValues(
		[]string{"security", "nat", "static", "rule-set", "rs1"}, nil)
	if !containsCompletionName(fromResults, "from") {
		t.Fatalf("expected %q completion under static-nat rule-set, got %v",
			"from", completionNames(fromResults))
	}

	// `zone` must be offered as a child of `from`.
	zoneResults := CompleteSetPathWithValues(
		[]string{"security", "nat", "static", "rule-set", "rs1", "from"}, nil)
	if !containsCompletionName(zoneResults, "zone") {
		t.Fatalf("expected %q completion under static-nat rule-set from, got %v",
			"zone", completionNames(zoneResults))
	}

	// The zone value slot must surface the zone-name value hint so the CLI
	// can complete configured zone names. The provider records the hint it
	// is asked for.
	var hints []ValueHint
	provider := func(h ValueHint, _ []string) []SchemaCompletion {
		hints = append(hints, h)
		return nil
	}
	_ = CompleteSetPathWithValues(
		[]string{"security", "nat", "static", "rule-set", "rs1", "from", "zone"}, provider)
	sawZoneHint := false
	for _, h := range hints {
		if h == ValueHintZoneName {
			sawZoneHint = true
		}
	}
	if !sawZoneHint {
		t.Fatalf("expected ValueHintZoneName for static-nat from zone value slot, got %v", hints)
	}

	// A fully-specified static-NAT rule-set with a defined from-zone must
	// still pass schema validation (no false rejection from the new node).
	good := &ConfigTree{}
	for _, line := range []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address 203.0.113.5/32",
		"set security nat static rule-set rs1 rule r1 then static-nat prefix 10.0.0.5/32",
	} {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := good.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	_, err := CompileConfig(good)
	if err != nil {
		t.Fatalf("CompileConfig(good): %v", err)
	}
	if err := SchemaValidate(good); err != nil {
		t.Fatalf("SchemaValidate(good) rejected a valid static-nat from-zone: %v", err)
	}
}
