package config

import (
	"strings"
	"testing"
)

// #9932: `family inet dhcp;` with the `family` brace elided compiled DHCP=false,
// committed clean, and emitted no warning. The interface ended up with no
// address and no DHCP client — and that is the canonical way to write a DHCP
// interface, so an interface whose ONLY address source is DHCP came up with
// nothing while `show configuration` still displayed the statement.
//
// `family inet6 dhcpv6-client …` had the same gap on the properly declared
// keyword.
//
// Measured at origin/master 371e2b594:
//
//	family inet { dhcp; }   DHCP=true     family inet dhcp;             DHCP=false
//	family inet6 { dhcpv6-client {…} }    family inet6 dhcpv6-client …  DHCPv6=false
//
// The FLAT-SET path was already correct, and that fact bounds the exposure:
// `SetPath` builds the head as a CHILD, while the hierarchical text parser
// leaves it on the container head's Keys where `afNode.FindChild` never looks.
// So this only ever bit configuration TEXT — a saved config, `load merge`, a
// restored backup — which is why the interactive CLI never showed it.

// The claim is EQUALITY with the braced spelling, for every elision depth. Both
// families are driven in one table so a fix that reached only one is visible.
func TestDhcpClientFoldsLikeBraced9932(t *testing.T) {
	for _, tc := range []struct{ name, elided, braced string }{
		{
			name:   "inet, family brace elided",
			elided: "interfaces { ge-0/0/0 { unit 0 { family inet dhcp; } } }",
			braced: "interfaces { ge-0/0/0 { unit 0 { family inet { dhcp; } } } }",
		},
		{
			name:   "inet, unit AND family elided",
			elided: "interfaces { ge-0/0/0 { unit 0 family inet dhcp; } }",
			braced: "interfaces { ge-0/0/0 { unit 0 { family inet { dhcp; } } } }",
		},
		{
			name:   "inet, dhcp keeps its braced body",
			elided: "interfaces { ge-0/0/0 { unit 0 { family inet dhcp { lease-time 3600; } } } }",
			braced: "interfaces { ge-0/0/0 { unit 0 { family inet { dhcp { lease-time 3600; } } } } }",
		},
		{
			name:   "inet6, family brace elided",
			elided: "interfaces { ge-0/0/0 { unit 0 { family inet6 dhcpv6-client { client-type stateful; } } } }",
			braced: "interfaces { ge-0/0/0 { unit 0 { family inet6 { dhcpv6-client { client-type stateful; } } } } }",
		},
		{
			// CONTROL: an address beside the client, so the fix cannot be "fold
			// everything under a family into one statement".
			name:   "inet, dhcp beside an address",
			elided: "interfaces { ge-0/0/0 { unit 0 { family inet dhcp address 10.0.0.1/24; } } }",
			braced: "interfaces { ge-0/0/0 { unit 0 { family inet { dhcp; address 10.0.0.1/24; } } } }",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			se, je := compiledConfigJSON9620(t, tc.elided)
			sb, jb := compiledConfigJSON9620(t, tc.braced)
			if se != "OK" || sb != "OK" {
				t.Fatalf("both spellings must commit: elided=%s braced=%s", se, sb)
			}
			if je != jb {
				t.Fatalf("the elided spelling must compile like the braced one\nelided: %s\nbraced: %s", je, jb)
			}
		})
	}
}

// CONTROL, and the fact that bounds the severity: the flat-set path was correct
// before this change and must stay correct. If this ever fails, the exposure is
// no longer text-only and the issue's severity statement is wrong.
func TestDhcpFlatSetPathStaysCorrect9932(t *testing.T) {
	for _, tc := range []struct {
		name string
		sets []string
		want string
	}{
		{
			name: "set … family inet dhcp",
			sets: []string{"set interfaces ge-0/0/0 unit 0 family inet dhcp"},
			want: `"DHCP":true`,
		},
		{
			name: "set dhcp then an address",
			sets: []string{
				"set interfaces ge-0/0/0 unit 0 family inet dhcp",
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			},
			want: `"DHCP":true`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := &ConfigTree{}
			for _, s := range tc.sets {
				toks, err := ParseSetCommand(s)
				if err != nil {
					t.Fatalf("parse %q: %v", s, err)
				}
				if err := tree.SetPath(toks); err != nil {
					t.Fatalf("setpath %q: %v", s, err)
				}
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient: %v", err)
			}
			var found bool
			for _, i := range cfg.Interfaces.Interfaces {
				for _, u := range i.Units {
					if u.DHCP {
						found = true
					}
				}
			}
			if !found {
				t.Fatalf("the flat-set path must set DHCP; want %s", tc.want)
			}
		})
	}
}

// #9932 leaves the sub-option CHAIN unadmitted, and this pins that boundary so
// it is a decision rather than an oversight.
//
// `family inet dhcp lease-time 3600;` — the FULLY elided run — still loses the
// lease-time, because `(dhcp, lease-time)` is not admitted. The head itself now
// folds, so the outer pair is no longer the blocker.
//
// The chain is measured and ready: all four `dhcp` children and all six
// `dhcpv6-client` children reach exactly one schema path each and every one is
// empty-equivalent, so each satisfies this pass's admission precondition.
// Completing both chains is ten more pairs, each owing rows in the #8763,
// #8768, #8852 and #9446 registers — a wider change than the flag-level fix,
// filed rather than folded in.
//
// If this cell starts FAILING, the chain was admitted and the register notes on
// those sites need re-measuring with it.
func TestDhcpSubOptionChainIsStillUnadmitted9932(t *testing.T) {
	_, fully := compiledConfigJSON9620(t,
		"interfaces { ge-0/0/0 { unit 0 { family inet dhcp lease-time 3600; } } }")
	_, braced := compiledConfigJSON9620(t,
		"interfaces { ge-0/0/0 { unit 0 { family inet { dhcp { lease-time 3600; } } } } }")
	if fully == braced {
		t.Fatalf("the dhcp sub-option chain now folds; admit it deliberately and re-measure the " +
			"#9446 register notes for every `dhcp`/`dhcpv6-client` sub-option site")
	}
	// The HEAD still folds even on that run — only the sub-option is lost.
	if !strings.Contains(fully, `"DHCP":true`) {
		t.Fatalf("the dhcp head must fold even when its sub-option does not: %s", fully)
	}
}
