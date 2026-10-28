package policymatch

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestSharedRequestValidateEvaluate17198 pins #17198: shared validation
// runs config-independent grammar before the cfg==nil boot-window verdict,
// Assemble owns debt/family assembly, VerdictFrom carries the typed
// unsupported_tuple_family bit. RED pre-fix: Evaluate/Verdict did not exist
// and gRPC returned default-deny for these malformed no-config requests.
func TestSharedRequestValidateEvaluate17198(t *testing.T) {
	malformed := []Request{
		{},
		{FromZone: "trust"},
		{FromZone: "trust", ToZone: "untrust", SrcIP: "not-an-ip"},
		{FromZone: "trust", ToZone: "untrust", DstIP: "10.0.0.999"},
		{FromZone: "trust", ToZone: "untrust", Protocol: "tcpp"},
	}
	for i, r := range malformed {
		if _, err := Evaluate(nil, r, Live{}); err == nil {
			t.Fatalf("case %d: Evaluate(nil, %+v) err=nil, want grammar error before nil-config verdict", i, r)
		}
	}
	// Well-formed boot-window query: fail-closed default deny.
	res, err := Evaluate(nil, Request{FromZone: "trust", ToZone: "untrust"}, Live{})
	if err != nil || !res.DefaultUsed || res.Action != config.PolicyDeny {
		t.Fatalf("nil-config well-formed = %+v, %v", res, err)
	}
	// Assemble: family + debt derivation.
	cfg := &config.Config{}
	q := Assemble(cfg, Request{FromZone: "trust", ToZone: "untrust", SrcIP: "192.0.2.1", DstIP: "2001:db8::1"}, Live{Feeds: map[string]FeedInfo{"bad": {PublicationDebt: true}, "good": {}}})
	if q.SrcFamily != "v4" || q.DstFamily != "v6" || !q.FeedPublicationDebt["bad"] || q.FeedPublicationDebt["good"] {
		t.Fatalf("Assemble = %+v", q)
	}
	// Verdict: unsupported tuple typed bit + action string.
	v := VerdictFrom(Result{UnsupportedTupleFamily: true, Action: config.PolicyDeny}, "trust", "untrust")
	if !v.UnsupportedTupleFamily || !strings.Contains(v.Action, "unsupported tuple") {
		t.Fatalf("Verdict = %+v", v)
	}
	// SelectorArgs.Request reuses the shared path (retired Query builder).
	sel, err := ParseSelectorArgs([]string{"from-zone", "trust", "to-zone", "untrust", "source-ip", "192.0.2.1", "destination-ip", "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	q2 := Assemble(cfg, sel.Request(), Live{})
	if q2.SrcFamily != "v4" || q2.DstFamily != "v6" {
		t.Fatalf("SelectorArgs Assemble = %+v", q2)
	}
}
