package nftables

import (
	"bytes"
	"sort"
	"testing"

	"github.com/google/nftables/expr"

	"github.com/psaab/xpf/pkg/config"
)

// metaMatchNames returns names matched by a positive Meta predicate. Set
// lookups are included, as nft represents multi-name equality that way.
func metaMatchNames13404(t *testing.T, p *nlPlan, exprs []expr.Any, key expr.MetaKey) []string {
	t.Helper()
	var out []string
	for i, e := range exprs {
		meta, ok := e.(*expr.Meta)
		if !ok || meta.Key != key || i+1 >= len(exprs) {
			continue
		}
		switch cmp := exprs[i+1].(type) {
		case *expr.Cmp:
			if cmp.Op == expr.CmpOpEq {
				out = append(out, string(bytes.TrimRight(cmp.Data, "\x00")))
			}
		case *expr.Lookup:
			if !cmp.Invert {
				for _, el := range p.setElementsForID(cmp.SetID) {
					out = append(out, string(bytes.TrimRight(el.Key, "\x00")))
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// TestHostInboundStaleReplyNetlinkMultiScope13404 (#13404): a guard carrying
// two distinct VRF scopes must expand to one netlink rule per scope. Pre-fix
// the emitter ANDs both masters' iifname predicates onto a single rule,
// which no packet can satisfy, so stale-reply protection silently vanishes.
func TestHostInboundStaleReplyNetlinkMultiScope13404(t *testing.T) {
	guards := []StaleReplyGuardRule{{
		Family: "ip", Proto: config.HostInboundProtoTCP, Ports: []uint16{22},
		Addresses: []string{"192.0.2.1"},
		IngressVRFScopes: []config.HostInboundVRFIngressScope{
			{Master: "vrf-blue", Slaves: []string{"ge-0-0-1"}},
			{Master: "vrf-red", Slaves: []string{"ge-0-0-2"}},
		},
	}}
	p := newBuildPlan(t, "xpf_test_stale_13404", 10)
	emitHostInboundStaleReplyGuards(p, guards)
	if p.err != nil {
		t.Fatalf("netlink guard build failed: %v", p.err)
	}
	if len(p.rules) != 2 {
		t.Fatalf("netlink emitted %d rules for one 2-scope guard, want 2 (one per scope)", len(p.rules))
	}
	wantByMaster := map[string]string{"vrf-blue": "ge-0-0-1", "vrf-red": "ge-0-0-2"}
	seen := map[string]bool{}
	for i, exprs := range p.rules {
		masters := metaMatchNames13404(t, p, exprs, expr.MetaKeyIIFNAME)
		if len(masters) != 1 {
			t.Fatalf("rule %d: iifname masters = %v, want exactly one", i, masters)
		}
		slaves := metaMatchNames13404(t, p, exprs, expr.MetaKey(metaKeySDIFNAME))
		wantSlave, ok := wantByMaster[masters[0]]
		if !ok || len(slaves) != 1 || slaves[0] != wantSlave {
			t.Fatalf("rule %d: sdifname slaves = %v, want [%s] for master %s", i, slaves, wantSlave, masters[0])
		}
		seen[masters[0]] = true
		last := exprs[len(exprs)-1]
		vd, ok := last.(*expr.Verdict)
		if !ok || vd.Kind != expr.VerdictDrop {
			t.Fatalf("rule %d: last expr = %#v, want DROP verdict", i, last)
		}
	}
	if !seen["vrf-blue"] || !seen["vrf-red"] {
		t.Fatalf("expanded rules cover masters %v, want both vrf-blue and vrf-red", seen)
	}
}
