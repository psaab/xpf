package config

import (
	"strings"
	"testing"
)

// compile9821 compiles the given set-lines strictly, failing the test on
// parse errors (the corpus must be well-formed set syntax; only the COMPILE
// verdict is under test).
func compile9821(t *testing.T, lines ...string) (*Config, error) {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		tree.SetPath(path)
	}
	return CompileConfig(tree)
}

// tunnelCollisionCorpus9821 is the #8994 corpus: `gr-0/0/0` unit 0 carries a
// tunnel while `gr-0/0/0.0` is separately declared. It COMPILES (both strict
// gates before #9821 accept it) — the collision only becomes observable
// when a routing-instance member claims the shared key.
var tunnelCollisionCorpus9821 = []string{
	"set interfaces gr-0/0/0 unit 0 tunnel mode gre",
	"set interfaces gr-0/0/0 unit 0 tunnel source 10.0.0.1",
	"set interfaces gr-0/0/0 unit 0 tunnel destination 10.0.0.2",
	"set interfaces gr-0/0/0.0 unit 0 family inet address 10.9.2.1/24",
}

func TestRIMemberDeclaredCollisionStrictRejects9821(t *testing.T) {
	lines := append(append([]string{}, tunnelCollisionCorpus9821...),
		"set routing-instances RA interface gr-0/0/0.0")
	_, err := compile9821(t, lines...)
	if err == nil {
		t.Fatal("member gr-0/0/0.0 over the tunnel-collision corpus compiled; want #9821 hard-reject")
	}
	for _, want := range []string{"RA", "gr-0/0/0.0", "unit 0", "gr-0/0/0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q (member, key, unit and other interface must all be actionable)", err, want)
		}
	}
	if !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("error %q is not the #9821 collision error (want the 'ambiguous' marker)", err)
	}
}

// The bare tunnel-side spelling fans down onto the colliding key, so it
// rejects too — the member CLAIMS gr-0/0/0.0 even though it does not spell it.
func TestRIMemberDeclaredCollisionBareFansDown9821(t *testing.T) {
	lines := append(append([]string{}, tunnelCollisionCorpus9821...),
		"set routing-instances RA interface gr-0/0/0")
	_, err := compile9821(t, lines...)
	if err == nil {
		t.Fatal("bare member gr-0/0/0 over the tunnel-collision corpus compiled; want #9821 hard-reject via fan-down")
	}
	if !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("error %q is not the #9821 collision error (want the 'ambiguous' marker)", err)
	}
}

// A padded alias folds onto the same canonical key, so it rejects identically.
func TestRIMemberDeclaredCollisionAliasFolds9821(t *testing.T) {
	lines := append(append([]string{}, tunnelCollisionCorpus9821...),
		"set routing-instances RA interface gr-0/0/0.00")
	_, err := compile9821(t, lines...)
	if err == nil {
		t.Fatal("alias member gr-0/0/0.00 over the tunnel-collision corpus compiled; want #9821 hard-reject via canonical fold")
	}
	if !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("error %q is not the #9821 collision error (want the 'ambiguous' marker)", err)
	}
}

// The non-tunnel triple (declared `p.0` unit 1 + declared `p.0.1`) trips the
// #7795 kernel-device gate BEFORE #9821's dead-last gate runs — pinning the
// wiring order: the operator sees 7795's error, not the ambiguity error.
func TestRIMemberDeclaredCollisionYieldsTo7795Order9821(t *testing.T) {
	_, err := compile9821(t,
		"set interfaces p.0 unit 1 family inet address 10.9.3.1/24",
		"set interfaces p.0.1 unit 0 family inet address 10.9.4.1/24",
		"set routing-instances RA interface p.0.1",
	)
	if err == nil {
		t.Fatal("triple-collision corpus compiled; want a hard-reject (either gate)")
	}
	if !strings.Contains(err.Error(), "both resolve to the same Linux device name") {
		t.Errorf("error %q is not #7795's — the dead-last #9821 gate must not steal the first-error slot", err)
	}
	if strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("error %q carries the #9821 marker — #7795 must win the first-error slot", err)
	}
}

// A self-unit member whose key is NOT declared (`p.0.1` with no `p.0.1`
// stanza) is not a collision and compiles — the gate only fires when BOTH
// objects exist.
func TestRIMemberDeclaredCollisionUndeclaredKeyCompiles9821(t *testing.T) {
	cfg, err := compile9821(t,
		"set interfaces p.0 unit 1 family inet address 10.9.3.1/24",
		"set routing-instances RA interface p.0.1",
	)
	if err != nil {
		t.Fatalf("non-colliding member p.0.1 rejected: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "ambiguous") {
			t.Errorf("non-colliding member drew collision warning %q", w)
		}
	}
}

// A config tripping BOTH the #5933 malformed-suffix gate and #9821 yields
// #5933's error — pinning that the dead-last gate runs after the mid-phase
// reference gates, not just after #7795.
func TestRIMemberDeclaredCollisionYieldsToUnitrefOrder9821(t *testing.T) {
	lines := append(append([]string{}, tunnelCollisionCorpus9821...),
		"set routing-instances RA interface gr-0/0/0.0",
		"set routing-instances RA interface ge-0/0/9.99x",
	)
	_, err := compile9821(t, lines...)
	if err == nil {
		t.Fatal("dual-violation corpus compiled; want a hard-reject (either gate)")
	}
	if strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("error %q carries the #9821 marker — the #5933 gate must win the first-error slot", err)
	}
}

// Ordinary unit-ref members are untouched by the gate.
func TestRIMemberDeclaredCollisionOrdinaryControl9821(t *testing.T) {
	_, err := compile9821(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.9.5.1/24",
		"set routing-instances RA interface ge-0/0/0.0",
	)
	if err != nil {
		t.Fatalf("ordinary unit-ref member rejected: %v", err)
	}
}

// Two colliding members in two RIs: the alphabetically-first RI wins the
// stable first-error slot regardless of config order.
func TestRIMemberDeclaredCollisionStableFirstError9821(t *testing.T) {
	lines := append(append([]string{}, tunnelCollisionCorpus9821...),
		"set routing-instances zz interface gr-0/0/0.0",
		"set routing-instances aa interface gr-0/0/0")
	_, err := compile9821(t, lines...)
	if err == nil {
		t.Fatal("dual-collision corpus compiled; want #9821 hard-reject")
	}
	if !strings.Contains(err.Error(), `"aa"`) {
		t.Errorf("error %q does not name the sorted-first RI aa (stable first-error)", err)
	}
}

// On the tolerant path the collision downgrades to a warning and the config
// still boots (#1960 no-brick).
func TestRIMemberDeclaredCollisionLenientWarns9821(t *testing.T) {
	tree := &ConfigTree{}
	for _, l := range append(append([]string{}, tunnelCollisionCorpus9821...),
		"set routing-instances RA interface gr-0/0/0.0") {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		tree.SetPath(path)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of colliding member rejected: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "downgraded to warning") && strings.Contains(w, "ambiguous") {
			found = true
		}
	}
	if !found {
		t.Errorf("lenient load drew no downgraded collision warning (warnings: %q)", cfg.Warnings)
	}
}

// TestRIMemberDeclaredCollisionPaddedSpellingCompiles9821 pins that #23
// rejects STRING collisions, not numeric equivalence (review): a declared
// `p.01` shares no row key with generated `p.1` (unit 1 of `p`), and a
// declared `p.00` shares none with `p.0` — so neither member refuses.
// Raw-exact precedence holds: the declared spelling names its own object.
func TestRIMemberDeclaredCollisionPaddedSpellingCompiles9821(t *testing.T) {
	for _, tc := range []struct {
		name   string
		iface  string
		unit   int
		member string
	}{
		{"padded unit-one", "p.01", 1, "p.01"},
		{"padded unit-zero", "p.00", 0, "p.00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := compile9821(t,
				"set interfaces p unit 1 family inet address 10.9.0.1/24",
				"set interfaces p unit 0 family inet address 10.9.0.2/24",
				"set interfaces "+tc.iface+" unit 0 family inet address 10.9.1.1/24",
				"set routing-instances RA interface "+tc.member,
			)
			if err != nil {
				t.Fatalf("numeric-equivalent member %q rejected: %v (want compile — no shared row key)", tc.member, err)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "ambiguous") {
					t.Errorf("member %q drew collision warning %q", tc.member, w)
				}
			}
		})
	}
}
