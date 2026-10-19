package config

import (
	"strconv"
	"strings"
	"testing"
)

// #8667: the NAT64 prefix gate's operator-facing messages described a failure
// mode #3888 removed. These cells pin the two properties that were wrong, so a
// future change to either side cannot quietly re-break them.

// A message that tells the operator the whole forwarding pipeline is frozen
// sends them looking for a wedged dataplane and may cost them a rollback of
// good config. The truth is one skipped rule. Assert on the message TEXT
// because the message IS the defect here — there is no behavioural symptom to
// observe.
func TestNAT64PrefixMessagesDescribeAScopedSkip8667(t *testing.T) {
	cfg := nat64CfgWithPrefix8667("64:ff9b::/64")

	_, strictErr := validateNAT64PrefixStrict(cfg, false)
	if strictErr == nil {
		t.Fatal("a /64 NAT64 prefix must still be rejected at commit")
	}
	warns, lenientErr := validateNAT64PrefixStrict(cfg, true)
	if lenientErr != nil {
		t.Fatalf("lenient must not hard-fail: %v", lenientErr)
	}
	if len(warns) != 1 {
		t.Fatalf("expected exactly one lenient warning, got %d: %v", len(warns), warns)
	}

	// #3888 made NAT64 fail SCOPED. Nothing user-visible may claim otherwise.
	stale := []string{
		"aborts the entire forwarding rebuild",
		"rejects the whole forwarding snapshot",
		"try_from_snapshots",
		"every later config change",
		"previous live state is kept",
	}
	for _, text := range []string{strictErr.Error(), warns[0]} {
		for _, bad := range stale {
			if strings.Contains(text, bad) {
				t.Errorf("message still claims the pre-#3888 whole-snapshot abort (%q):\n  %s", bad, text)
			}
		}
		// And it must say what DOES happen, or it is merely vague.
		if !strings.Contains(text, "SKIP") {
			t.Errorf("message must state that the dataplane skips this rule-set:\n  %s", text)
		}
	}
}

// The lenient warning makes a claim about the dataplane, so it must fire only
// when the dataplane will really skip the rule. This is the K62 case: "/+96" is
// rejected at commit but ACCEPTED by the helper (measured: installed, active,
// prefix_bytes byte-identical to a canonical /96).
func TestLenientWarningOnlyFiresWhenTheDataplaneWouldSkip8667(t *testing.T) {
	for _, tc := range []struct {
		prefix     string
		wantStrict bool // commit must reject
		wantWarn   bool // lenient must warn
	}{
		{"64:ff9b::/96", false, false}, // canonical
		{"64:ff9b::/+96", true, false}, // K62: rejected at commit, LIVE in the dataplane
		{"64:ff9b::/64", true, true},   // genuinely skipped
		{"64:ff9b::/abc", true, true},  // genuinely skipped
		{"64:ff9b::", true, true},      // no mask, genuinely skipped
		{"64:ff9b::/96/x", true, true}, // extra segment, genuinely skipped
	} {
		cfg := nat64CfgWithPrefix8667(tc.prefix)
		_, err := validateNAT64PrefixStrict(cfg, false)
		if got := err != nil; got != tc.wantStrict {
			t.Errorf("prefix %q: strict rejected=%v, want %v (err=%v)", tc.prefix, got, tc.wantStrict, err)
		}
		warns, lerr := validateNAT64PrefixStrict(cfg, true)
		if lerr != nil {
			t.Errorf("prefix %q: lenient hard-failed: %v", tc.prefix, lerr)
		}
		if got := len(warns) > 0; got != tc.wantWarn {
			t.Errorf("prefix %q: lenient warned=%v, want %v (warnings=%v)", tc.prefix, got, tc.wantWarn, warns)
		}
	}
}

// THE SAFETY DIRECTION, which is the invariant that actually matters and the
// one a future edit is most likely to break: the dataplane must never REJECT a
// prefix the commit gate ACCEPTED. A backstop stricter than its gate silently
// disables a cleanly-committed rule. The reverse (backstop laxer) is safe.
//
// Swept over a corpus rather than a handful of literals, so a change to either
// predicate is caught wherever it lands.
func TestCommitGateIsNeverLaxerThanTheDataplane8667(t *testing.T) {
	alphabet := "0123456789+-_ xX.eE"
	var toks []string
	var gen func(string, int)
	gen = func(p string, d int) {
		toks = append(toks, p)
		if d == 0 {
			return
		}
		for _, c := range alphabet {
			gen(p+string(c), d-1)
		}
	}
	gen("", 3)

	checked, divergent := 0, 0
	for _, tok := range toks {
		canonical := false
		// The canonical spelling the strict gate demands, spelled out here
		// rather than calling into the validator so the two cannot drift
		// together and hide a divergence.
		if n, err := strconv.ParseUint(tok, 10, 8); err == nil && n == 96 {
			canonical = true
		}
		dataplaneOK := dataplaneAcceptsNAT64Mask(tok)
		checked++
		if canonical && !dataplaneOK {
			t.Errorf("token %q: the commit gate ACCEPTS it but the dataplane would REJECT it — "+
				"a cleanly-committed NAT64 rule would be silently skipped", tok)
		}
		if !canonical && dataplaneOK {
			divergent++
			if !strings.HasPrefix(tok, "+") {
				t.Errorf("token %q: dataplane-only acceptance outside the known leading-'+' class; "+
					"the mirror predicate has drifted from the Rust parse", tok)
			}
		}
	}
	if checked == 0 {
		t.Fatal("corpus was empty — this cell is blind")
	}
	// Degeneracy control: a predicate that accepted nothing would pass every
	// assertion above. The known divergence must actually be observed.
	if divergent == 0 {
		t.Fatal("no dataplane-only acceptance found; dataplaneAcceptsNAT64Mask no longer " +
			"mirrors the Rust leading-'+' laxness, so this cell proves nothing")
	}
	t.Logf("#8667: %d tokens checked, %d dataplane-only (all leading '+')", checked, divergent)
}

func nat64CfgWithPrefix8667(prefix string) *Config {
	return &Config{
		Security: SecurityConfig{
			NAT: NATConfig{
				SourcePools: map[string]*NATPool{"p64": {Name: "p64", Addresses: []string{"100.64.0.7/32"}}},
				NAT64:       []*NAT64RuleSet{{Name: "rs1", Prefix: prefix, SourcePool: "p64"}},
			},
		},
	}
}
