package userspace

import (
	"strings"
	"testing"
)

// #9595 on the wire: an unrecognized statement that dropped a match constraint
// from an otherwise protocol-wide application refuses the policy (the #3261
// sentinel), and #6524's stray statement beside a retained port does not.

func TestLostConstraintStatementRefusesThePolicy9595(t *testing.T) {
	for _, c := range []struct{ name, apps string }{
		{"tcp + destination-poort 22 under a permit", `application a { protocol tcp; destination-poort 22; }`},
		{"set member applicaton junos-ssh", `application-set a { application junos-telnet; applicaton junos-ssh; }`},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := lenientHier9571(t, policyText9525(c.apps, "a", "permit", "deny-all"))
			terms := wireTerms9525(t, cfg)
			if len(terms) != 1 || terms[0].Protocol != unsupportedApplicationSentinel {
				t.Fatalf("the policy must lower to the __unsupported__ sentinel alone; wire terms: %+v", terms)
			}
			reasons := PolicyContentRejectionReasons(cfg, nil)
			if len(reasons) != 1 || !strings.Contains(reasons[0], `application "a"`) {
				t.Fatalf("want one mirror reason naming application \"a\"; got %q", reasons)
			}
		})
	}
}

func TestStrayStatementBesideARetainedPortKeepsItsWire9595(t *testing.T) {
	cfg := lenientHier9571(t, policyText9525(`application a { protocol tcp; destination-port 8080; bogus value; }`, "a", "permit", "deny-all"))
	terms := wireTerms9525(t, cfg)
	if len(terms) != 1 || terms[0].Protocol != "tcp" || terms[0].DestinationPort != "8080" {
		t.Fatalf("#6524: a stray statement must leave tcp/8080 installed; wire terms: %+v", terms)
	}
	if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) != 0 {
		t.Fatalf("#6524: the stray statement must not refuse the policy; reasons %q", reasons)
	}
}
