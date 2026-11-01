package nftables

import (
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// #18721: the #9506 host-input fence readback must accept the #16841
// zero-hop-limit DROP ahead of the overlay (that rule leads every host-input
// chain by design) and must keep refusing any rule ahead of the overlay that
// can admit a packet.
//
// These cells judge the rules buildHostInboundNetlink really emits, through
// the same verifyHostOverlayRuleChain the kernel readback runs. The live
// install + readback twin is the forced kernel cell
// TestHostInputFenceLiveReadbackAndRestore9506 (make test-daemon-kernel-lib).

func overlay18721() HostInputFenceOverlay {
	return CanonicalHostInputFenceOverlay(HostInputFenceOverlay{
		MasterSet:       []string{"st0"},
		Generation:      7,
		PermitEpoch:     11,
		CloseRequestSeq: 13,
		CloseRequestKey: "3/7/[xfrmi:st0]",
		WatchGeneration: 7,
		State:           "CLOSING",
	})
}

// inputRules18721 builds the host-inbound table for spec and returns its
// input-chain rules in emission order, as nftables.Rule values.
func inputRules18721(t *testing.T, spec HostInboundSpec) []*nftables.Rule {
	t.Helper()
	p := newBuildPlan(t, HostInboundTableName, hostInboundPriority)
	buildHostInboundNetlink(p, spec)
	if p.err != nil {
		t.Fatalf("build host inbound: %v", p.err)
	}
	var rules []*nftables.Rule
	for i, exprs := range p.rules {
		if p.ruleChains[i] == "input" {
			rules = append(rules, &nftables.Rule{Exprs: exprs})
		}
	}
	if len(rules) == 0 {
		t.Fatal("fixture: the host-inbound build emitted no input rules")
	}
	return rules
}

func verify18721(rules []*nftables.Rule, o HostInputFenceOverlay) error {
	return verifyHostOverlayRuleChain(rules, map[string][]string{}, HostInputFenceOverlayCounterName(o), o)
}

// The defect cell: the production default (zero-hop DROP on) puts that DROP
// first and the overlay second. Before #18721 this read "host overlay leading
// rule absent" — the production apply then failed (daemon_nft.go).
func TestOverlayReadbackAcceptsTheZeroHopDropAhead18721(t *testing.T) {
	o := overlay18721()
	rules := inputRules18721(t, HostInboundSpec{Overlay: &o})
	marker := HostInputFenceOverlayCounterName(o)
	if _, _, markerSeen, _ := decodeHostOverlayRule(rules[0], nil, marker); markerSeen {
		t.Fatal("fixture: rule 0 is the overlay; the zero-hop DROP no longer leads, so this cell does not reach the defect")
	}
	if !hostInputRuleIsDropOnly(rules[0]) {
		t.Fatalf("fixture: rule 0 should be the #16841 zero-hop DROP, got %#v", rules[0].Exprs)
	}
	if err := verify18721(rules, o); err != nil {
		t.Fatalf("readback of the production rule order failed: %v", err)
	}
}

// The other order: with the knob set there is no zero-hop rule and the
// overlay leads. That must still verify.
func TestOverlayReadbackAcceptsTheOverlayFirst18721(t *testing.T) {
	o := overlay18721()
	rules := inputRules18721(t, HostInboundSpec{Overlay: &o, NoIPv6RejectZeroHopLimit: true})
	if _, _, markerSeen, _ := decodeHostOverlayRule(rules[0], nil, HostInputFenceOverlayCounterName(o)); !markerSeen {
		t.Fatal("fixture: with the knob set the overlay should be rule 0")
	}
	if err := verify18721(rules, o); err != nil {
		t.Fatalf("readback with the overlay first failed: %v", err)
	}
}

// The property the fence exists for: nothing that can admit a packet may run
// before it. Each shape below, put ahead of the real overlay (after the real
// zero-hop DROP, or alone), must fail the readback.
func TestOverlayReadbackRefusesAnAdmittingRuleAhead18721(t *testing.T) {
	o := overlay18721()
	knobSet := inputRules18721(t, HostInboundSpec{Overlay: &o, NoIPv6RejectZeroHopLimit: true})
	withZeroHop := inputRules18721(t, HostInboundSpec{Overlay: &o})
	zeroHop := withZeroHop[0]
	admitting := map[string]*nftables.Rule{
		"accept":                      {Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}},
		"return to the accept policy": {Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictReturn}}},
		"jump":                        {Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictJump, Chain: "junos-host"}}},
		"goto":                        {Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictGoto, Chain: "junos-host"}}},
		"verdict map then drop": {Exprs: []expr.Any{
			&expr.Lookup{SourceRegister: 1, DestRegister: 0, IsDestRegSet: true, SetName: "vm"},
			&expr.Verdict{Kind: expr.VerdictDrop},
		}},
		"queue then drop": {Exprs: []expr.Any{
			&expr.Queue{Num: 1},
			&expr.Verdict{Kind: expr.VerdictDrop},
		}},
		"accept then drop": {Exprs: []expr.Any{
			&expr.Verdict{Kind: expr.VerdictAccept},
			&expr.Verdict{Kind: expr.VerdictDrop},
		}},
		"no verdict (falls through)": {Exprs: []expr.Any{&expr.Counter{}}},
	}
	for name, rule := range admitting {
		for prefixName, prefix := range map[string][]*nftables.Rule{
			"alone":              {rule},
			"after the zero-hop": {zeroHop, rule},
		} {
			rules := append(append([]*nftables.Rule(nil), prefix...), knobSet...)
			err := verify18721(rules, o)
			if err == nil || !strings.Contains(err.Error(), "leading rule absent") {
				t.Errorf("%s (%s) ahead of the overlay: readback = %v, want \"leading rule absent\"", name, prefixName, err)
			}
		}
	}
}

// A DROP-only prefix does not stand in for the overlay: with no overlay rule
// at all the readback still fails.
func TestOverlayReadbackStillNeedsTheOverlayRule18721(t *testing.T) {
	o := overlay18721()
	withZeroHop := inputRules18721(t, HostInboundSpec{Overlay: &o})
	if err := verify18721(withZeroHop[:1], o); err == nil || !strings.Contains(err.Error(), "leading rule absent") {
		t.Fatalf("a chain holding only the zero-hop DROP verified as a fence: %v", err)
	}
	// And the overlay must follow the prefix directly: a DROP-only rule, then
	// an ACCEPT, then the overlay is refused (covered above); a mismatched
	// overlay after the prefix is still a mismatch.
	other := o
	other.MasterSet = []string{"st1"}
	if err := verify18721(withZeroHop, other); err == nil {
		t.Fatal("readback accepted an overlay for a different master set")
	}
}

func TestHostInputRuleIsDropOnly18721(t *testing.T) {
	for name, tc := range map[string]struct {
		exprs []expr.Any
		want  bool
	}{
		"drop":                 {[]expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}}, true},
		"accept":               {[]expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}, false},
		"two drops":            {[]expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}, &expr.Verdict{Kind: expr.VerdictDrop}}, false},
		"no verdict":           {[]expr.Any{&expr.Counter{}}, false},
		"set lookup then drop": {[]expr.Any{&expr.Lookup{SourceRegister: 1, SetName: "s"}, &expr.Verdict{Kind: expr.VerdictDrop}}, true},
		"map lookup then drop": {[]expr.Any{&expr.Lookup{SourceRegister: 1, IsDestRegSet: true, SetName: "m"}, &expr.Verdict{Kind: expr.VerdictDrop}}, false},
		"queue then drop":      {[]expr.Any{&expr.Queue{Num: 2}, &expr.Verdict{Kind: expr.VerdictDrop}}, false},
	} {
		if got := hostInputRuleIsDropOnly(&nftables.Rule{Exprs: tc.exprs}); got != tc.want {
			t.Errorf("%s: hostInputRuleIsDropOnly = %v, want %v", name, got, tc.want)
		}
	}
}
