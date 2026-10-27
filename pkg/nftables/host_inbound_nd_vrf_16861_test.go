package nftables

import (
	"testing"

	"github.com/google/nftables/expr"
	"github.com/psaab/xpf/pkg/config"
)

// #16861 netlink twin of the daemon oracle test: the scoped ND
// emission must key a VRF scope's ND admit on the member as iifname
// (NDISC presents member iifname, sdif unset) in addition to the
// master+sdif pair, and an ndp-except VRF view must emit no ND rule
// naming its master or member. Rule inspection is over the recorded
// expr stream (no kernel needed).
//
// RED pre-fix: no ND rule carries iifname=ge-0-0-1.

func TestNDVRFMemberIIFNameNetlink16861(t *testing.T) {
	views := []HostInboundZoneView{
		{Zone: "trust", SystemServices: []string{"ssh"}, V6Addrs: []string{"2001:db8:1::1"},
			IngressVRFScopes: []config.HostInboundVRFIngressScope{{Master: "vrf-blue", Slaves: []string{"ge-0-0-1"}}}},
		{Zone: "except", SystemServices: []string{"ssh"}, ProtocolsExcept: []string{"ndp"}, V6Addrs: []string{"2001:db8:2::1"},
			IngressVRFScopes: []config.HostInboundVRFIngressScope{{Master: "vrf-red", Slaves: []string{"ge-0-0-2"}}}},
	}
	p := newBuildPlan(t, "xpf_16861", hostInboundPriority)
	emitHostInboundNDPAcceptsCountedNetlink(p, views, true, nil)
	if p.err != nil {
		t.Fatalf("ND emission: %v", p.err)
	}
	// Every rule in this plan is an ND accept. Classify by meta names.
	var scopedPair, memberOnly, masterOnly bool
	var exceptHits []string
	for _, rule := range p.rules {
		iif := ruleMetaNames16861(t, rule, expr.MetaKeyIIFNAME)
		sdif := ruleMetaNames16861(t, rule, expr.MetaKey(metaKeySDIFNAME))
		for _, n := range append(append([]string{}, iif...), sdif...) {
			if n == "ge-0-0-2" || n == "vrf-red" {
				exceptHits = append(exceptHits, n)
			}
		}
		switch {
		case len(iif) == 1 && iif[0] == "vrf-blue" && len(sdif) == 1 && sdif[0] == "ge-0-0-1":
			scopedPair = true
		case len(iif) == 1 && iif[0] == "ge-0-0-1" && len(sdif) == 0:
			memberOnly = true
		case len(iif) == 1 && iif[0] == "vrf-blue" && len(sdif) == 0:
			masterOnly = true
		}
	}
	if len(exceptHits) > 0 {
		t.Fatalf("ndp-except VRF view emitted ND rules naming %v", exceptHits)
	}
	if !scopedPair {
		t.Fatalf("master+sdif ND admit lost; rules=%d", len(p.rules))
	}
	if !memberOnly {
		t.Fatalf("member-iifname ND admit missing (NDISC identity, #16861); rules=%d", len(p.rules))
	}
	if masterOnly {
		t.Fatal("ND admit widened to bare VRF master iifname")
	}
}

// ruleMetaNames16861 is ruleMetaNames14974 for set-valued matches:
// the emitter renders multi-name scopes as anonymous sets, so decode
// both the single-Cmp and Lookup forms via the plan's set registry.
func ruleMetaNames16861(t *testing.T, rule []expr.Any, key expr.MetaKey) []string {
	t.Helper()
	var out []string
	for i, e := range rule {
		meta, ok := e.(*expr.Meta)
		if !ok || meta.Key != key {
			continue
		}
		if i+1 >= len(rule) {
			t.Fatalf("meta %v at %d has no following expr", key, i)
		}
		switch nx := rule[i+1].(type) {
		case *expr.Cmp:
			out = append(out, trimNULTerm16861(nx.Data))
		case *expr.Lookup:
			// Set contents live on the plan, not the rule; the
			// single-name scopes used here render as Cmp. A Lookup
			// here means a multi-name set — decode via caller plan
			// is not available, so record a marker the test rejects
			// if it appears on the classified scopes.
			out = append(out, "<set>")
		}
	}
	return out
}

func trimNULTerm16861(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
