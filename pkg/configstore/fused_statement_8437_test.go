package configstore

import (
	"strings"
	"testing"
)

const fusedBase8437 = `
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24; } } } }
security { zones { security-zone trust { interfaces { ge-0/0/0.0; } } } }
system { host-name p; }
`

func psTerm8437(fromBody string) string {
	return fusedBase8437 + `policy-options { policy-statement ps1 { term t1 { from { ` +
		fromBody + ` } then accept; } } }`
}

// #8437. A missing semicolon FUSES two hierarchical statements: the lexer has
// no terminator to stop at, the next statement's keyword and value are absorbed
// onto this node's Keys, and the compiler drops the second statement silently.
// `show configuration` still renders the fused line, so the operator's own
// verification confirms a constraint the dataplane does not enforce.
//
// THIS ASSERTS THE WIDENING, NOT THE PARSE. A cell checking "the route-filter
// prefix and match-type survived" stays GREEN on the defective input — both ARE
// intact. What is lost is the `protocol` dimension, so the assertion has to be
// that the compiled term's match dimensions equal the statements authored.
func TestFusedStatementDoesNotSilentlyDropADimension_8437(t *testing.T) {
	// The one-character pair. Both members are required: the control proves the
	// stanza compiles at all, so a failure distinguishes "fusion happened" from
	// "this fixture never reached the compiler".
	const authored = "route-filter 10.0.0.0/8 orlonger; protocol static;"
	const fused = "route-filter 10.0.0.0/8 orlonger protocol static;"

	cfg, err := CheckText(psTerm8437(authored), 0)
	if err != nil {
		t.Fatalf("CONTROL: the correctly-terminated form was rejected: %v", err)
	}
	ps := cfg.PolicyOptions.PolicyStatements["ps1"]
	if ps == nil || len(ps.Terms) == 0 {
		t.Fatal("CONTROL: no policy term compiled; this cell would assert nothing")
	}
	if len(ps.Terms[0].FromProtocols) != 1 || ps.Terms[0].FromProtocols[0] != "static" {
		t.Fatalf("CONTROL: FromProtocols=%v, want [static] — the fixture is not "+
			"exercising the dimension this test is about", ps.Terms[0].FromProtocols)
	}
	if len(ps.Terms[0].RouteFilters) != 1 {
		t.Fatalf("CONTROL: RouteFilters=%d, want 1", len(ps.Terms[0].RouteFilters))
	}

	// The fused form must not COMMIT while missing a dimension the control has.
	cfg2, err := CheckText(psTerm8437(fused), 0)
	if err != nil {
		return // rejected: the term never exists, so it cannot under-match
	}
	ps2 := cfg2.PolicyOptions.PolicyStatements["ps1"]
	if ps2 == nil || len(ps2.Terms) == 0 {
		t.Fatal("the fused form committed but produced no term")
	}
	if len(ps2.Terms[0].FromProtocols) == 0 {
		t.Errorf("the fused form COMMITTED with FromProtocols=[] while the "+
			"one-character-different control has %v — the protocol dimension was "+
			"silently dropped and `show configuration` still displays it",
			ps.Terms[0].FromProtocols)
	}
}

// The discriminator is that an absorbed token NAMES A SIBLING statement. These
// are the shapes that must keep committing: several leaves legitimately carry
// trailing tokens whose grammar lives in the compiler rather than in setSchema,
// and a plain arity check condemns them.
func TestFusedStatementGateDoesNotCondemnValidTrailingTokens_8437(t *testing.T) {
	cases := map[string]string{
		"route-filter upto":                "route-filter 10.0.0.0/8 upto /24;",
		"route-filter prefix-length-range": "route-filter 10.0.0.0/8 prefix-length-range /24-/28;",
		"route-filter exact":               "route-filter 10.0.0.0/8 exact;",
		"route-filter then protocol":       "route-filter 10.0.0.0/8 orlonger; protocol static;",
	}
	for name, body := range cases {
		if _, err := CheckText(psTerm8437(body), 0); err != nil {
			t.Errorf("%s REJECTED: %v", name, strings.SplitN(err.Error(), "\n", 2)[0])
		}
	}
	// `then static-nat prefix <cidr>` is the worked example of an UNDER-DECLARED
	// leaf: setSchema gives it no args and no children, its grammar lives in the
	// compiler, and an arity-based gate rejects it. It must still commit — this
	// is the case that ruled out the simpler check.
	staticNAT := fusedBase8437 + `security { nat { static { rule-set rs1 { from zone trust;
		rule r1 { match { destination-address 10.0.9.5/32; }
		then { static-nat prefix 10.0.0.5/32; } } } } } }`
	if _, err := CheckText(staticNAT, 0); err != nil {
		t.Errorf("`then static-nat prefix <cidr>` REJECTED — an under-declared leaf's "+
			"legitimate trailing tokens must not be read as a fused statement: %v",
			strings.SplitN(err.Error(), "\n", 2)[0])
	}
}

// #12067. A non-keyword route-filter tail is silently ignored by the compiler
// and is not covered by #11779's unsupported-from gate. Reject it during the
// operator commit-check, before the term can be installed as an unconstrained
// orlonger match.
func TestRouteFilterUnconsumedTailRejectedBeforeCompile_12067(t *testing.T) {
	_, err := CheckText(psTerm8437("route-filter 10.0.0.0/8 orlonger foo;"), 0)
	if err == nil {
		t.Fatal("commit-check accepted an unconsumed route-filter tail")
	}
	if !strings.Contains(err.Error(), "route-filter") {
		t.Fatalf("commit-check error must name the route-filter leaf: %v", err)
	}
	if !strings.Contains(err.Error(), "foo") {
		t.Fatalf("commit-check error must identify the unconsumed token: %v", err)
	}
}
