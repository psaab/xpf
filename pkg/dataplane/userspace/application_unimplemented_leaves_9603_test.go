package userspace

import (
	"strings"
	"testing"
)

// #9603 on the wire: a real Junos statement xpf does not implement, beside a
// retained port, refuses the policy (the #3261 sentinel). A near miss of the
// same statement is a stray, and it keeps tcp/135 installed.
func TestUnimplementedJunosStatementRefusesThePolicy9603(t *testing.T) {
	cfg := lenientHier9571(t, policyText9525(`application a { protocol tcp; destination-port 135; uuid 1be617c0-31a5-11cf-a7d8-00805f48a135; }`, "a", "permit", "deny-all"))
	terms := wireTerms9525(t, cfg)
	if len(terms) != 1 || terms[0].Protocol != unsupportedApplicationSentinel {
		t.Fatalf("the policy must lower to the __unsupported__ sentinel alone; wire terms: %+v", terms)
	}
	reasons := PolicyContentRejectionReasons(cfg, nil)
	if len(reasons) != 1 || !strings.Contains(reasons[0], `application "a"`) {
		t.Fatalf("want one mirror reason naming application \"a\"; got %q", reasons)
	}

	stray := lenientHier9571(t, policyText9525(`application a { protocol tcp; destination-port 135; uuidd word; }`, "a", "permit", "deny-all"))
	if st := wireTerms9525(t, stray); len(st) != 1 || st[0].Protocol != "tcp" || st[0].DestinationPort != "135" {
		t.Fatalf("control: a near miss is a stray and must leave tcp/135 installed; wire terms: %+v", st)
	}
	if r := PolicyContentRejectionReasons(stray, nil); len(r) != 0 {
		t.Fatalf("control: a near miss must not refuse the policy; reasons %q", r)
	}
}
