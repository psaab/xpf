package config

import "testing"

// #6942: ResolveSyslogSourceAddr and ValidateSyslogSourceInterface judge the
// SAME string and disagreed about it in two ways — the validator rejects where
// the resolver silently substituted a default.
//
// The fixture gives unit 0 an address DIFFERENT from unit 100's, because that is
// what makes the defect observable: if unit 0 had no address, or the same one,
// a wrong-unit resolution would be indistinguishable from a correct one and
// every cell below would pass against the unfixed code.
func syslogFixture6942() *Config {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"reth1": {
			Name: "reth1",
			Units: map[int]*InterfaceUnit{
				0:   {PrimaryAddress: "10.0.0.1/24"},
				100: {PrimaryAddress: "10.0.100.1/24"},
			},
		},
	}
	return cfg
}

// TestResolverRefusesAnUnparseableUnit6942 is the defect-1 guard.
//
// RED-on-revert: restore the `unitNum` fallback (drop `unitOK`) and "reth1.abc"
// resolves to 10.0.0.1 — unit 0's address — instead of "". Asserting the
// returned ADDRESS rather than merely "not unit 100" is what catches it: both
// the fixed and unfixed code fail to return unit 100's address, and only the
// unfixed one returns unit 0's.
func TestResolverRefusesAnUnparseableUnit6942(t *testing.T) {
	cfg := syslogFixture6942()
	for _, bad := range []string{"reth1.abc", "reth1.", "reth1.99999999999999999999"} {
		got := ResolveSyslogSourceAddr(cfg, bad)
		if got == "10.0.0.1" {
			t.Errorf("ResolveSyslogSourceAddr(%q) = %q — unit 0's address. An unparseable "+
				"logical unit silently bound syslog to the WRONG unit, which is exactly what "+
				"ValidateSyslogSourceInterface's own error message warns about (#6942).", bad, got)
		}
		if got != "" {
			t.Errorf("ResolveSyslogSourceAddr(%q) = %q, want \"\" so the caller falls through "+
				"to the global source rather than binding a guessed unit", bad, got)
		}
	}
}

// TestResolverStillHonoursValidInputs6942 is the paired control, and it is what
// stops the guard above from being satisfied by a resolver that refuses
// everything.
//
// It also pins the case the fix must NOT break: a BARE interface name
// legitimately means unit 0. That is why the skip is conditioned on
// `hasUnit && parse-failed` rather than on `unitNum == 0` — the latter would
// have broken every bare-name caller while passing the defect-1 cell.
func TestResolverStillHonoursValidInputs6942(t *testing.T) {
	cfg := syslogFixture6942()
	for in, want := range map[string]string{
		"reth1":     "10.0.0.1",   // bare name -> unit 0, and it MUST still work
		"reth1.0":   "10.0.0.1",   // explicit unit 0
		"reth1.100": "10.0.100.1", // explicit non-zero unit
	} {
		if got := ResolveSyslogSourceAddr(cfg, in); got != want {
			t.Errorf("ResolveSyslogSourceAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestResolverTrimsLikeTheValidator6942 is the defect-2 guard.
//
// The validator trims before judging, so on the strict path a padded value is
// approved in its trimmed form and then handed to the resolver untrimmed. The
// callers only guard `!= ""`, which a whitespace-only value passes.
//
// RED-on-revert: drop the TrimSpace and " reth1.100 " resolves to "" (no such
// interface) instead of unit 100's address.
func TestResolverTrimsLikeTheValidator6942(t *testing.T) {
	cfg := syslogFixture6942()
	if got := ResolveSyslogSourceAddr(cfg, " reth1.100 "); got != "10.0.100.1" {
		t.Errorf("ResolveSyslogSourceAddr(%q) = %q, want %q — the validator trims before it "+
			"judges, so the resolver must trim before it resolves", " reth1.100 ", got, "10.0.100.1")
	}
}

// TestResolverAndValidatorAgree6942 asserts the AGREEMENT rather than pinning
// either side to a literal.
//
// Which side is authoritative is exactly the question a literal would silently
// answer, so the property is stated as an implication instead: if the validator
// REJECTS a value, the resolver must not return a config-derived address for it.
// A resolver that answers from config for input the validator refuses is the
// #6942 defect in its general form, whatever the specific string.
func TestResolverAndValidatorAgree6942(t *testing.T) {
	cfg := syslogFixture6942()
	cases := []string{
		"reth1", "reth1.0", "reth1.100", " reth1.100 ",
		"reth1.abc", "reth1.", "reth1.-1", "reth1.99999999999999999999",
		".100", "", "   ",
	}
	rejected := 0
	for _, in := range cases {
		verr := ValidateSyslogSourceInterface(in)
		got := ResolveSyslogSourceAddr(cfg, in)
		if verr == nil {
			continue
		}
		rejected++
		if got != "" {
			t.Errorf("disagreement on %q: validator rejects (%v) but resolver returned %q. "+
				"A value the validator refuses must not yield a config-derived address — "+
				"the strict path masks this, the lenient path does not (#6942).", in, verr, got)
		}
	}
	// Non-vacuity: if nothing in the corpus is rejected the loop above asserts
	// nothing, and would pass against a validator that accepts everything.
	if rejected < 4 {
		t.Fatalf("only %d of %d inputs were rejected by the validator; this corpus must "+
			"contain rejected values or the agreement assertion is vacuous", rejected, len(cases))
	}
}
