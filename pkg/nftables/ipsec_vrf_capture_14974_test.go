package nftables

import (
	"bytes"
	"strings"
	"testing"

	gnft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// #14974 D32-01: a VRF-enslaved st0.<N> xfrmi presents its VRF master as
// iifname and itself as sdifname. An iifname-only divert rule never matches
// it (capture bypass), and an iifname-only host-input fence overlay scoped
// to the VRF master drops every co-member of that VRF (over-drop), not just
// the tunnel.

func ruleMetaNames14974(t *testing.T, rule []expr.Any, key expr.MetaKey) []string {
	t.Helper()
	var out []string
	for i, e := range rule {
		meta, ok := e.(*expr.Meta)
		if !ok || meta.Key != key {
			continue
		}
		if i+1 >= len(rule) {
			t.Fatalf("meta %v at %d has no following compare", key, i)
		}
		cmp, ok := rule[i+1].(*expr.Cmp)
		if !ok {
			t.Fatalf("meta %v at %d followed by %T, want Cmp (single name)", key, i, rule[i+1])
		}
		out = append(out, string(bytes.TrimRight(cmp.Data, "\x00")))
	}
	return out
}

func TestIpsecDivertVRFEnslavedCapture14974(t *testing.T) {
	for _, hookName := range []string{"forward", "input"} {
		hook := gnft.ChainHookForward
		if hookName == "input" {
			hook = gnft.ChainHookInput
		}
		tbl := &gnft.Table{Family: gnft.TableFamilyINet, Name: IpsecDivertTableName}
		chain := ipsecDivertChain(tbl, hookName, hook)
		p := newBuildPlan(t, IpsecDivertTableName, IpsecDivertPriority)
		p.chain = chain
		emitIpsecDivertRules(p, []IpsecDivertRule{{Ifname: "st0.0", Master: "vrf-blue", Queue: 1497}})
		if p.err != nil {
			t.Fatalf("%s render: %v", hookName, p.err)
		}
		if len(p.rules) != 1 {
			t.Fatalf("%s rendered %d rules, want 1 sdifname-scoped queue rule", hookName, len(p.rules))
		}
		rule := p.rules[0]
		if got := ruleMetaNames14974(t, rule, expr.MetaKeyIIFNAME); len(got) != 1 || got[0] != "vrf-blue" {
			t.Fatalf("%s iifname scope = %v, want [vrf-blue] (VRF master is LOCAL_IN/forward iifname)", hookName, got)
		}
		if got := ruleMetaNames14974(t, rule, expr.MetaKey(metaKeySDIFNAME)); len(got) != 1 || got[0] != "st0.0" {
			t.Fatalf("%s sdifname scope = %v, want [st0.0] (enslaved tunnel member)", hookName, got)
		}
		queue, ok := rule[len(rule)-1].(*expr.Queue)
		if !ok || queue.Num != 1497 || queue.Flag != 0 {
			t.Fatalf("%s last expr = %#v, want queue 1497 no-bypass", hookName, rule[len(rule)-1])
		}
	}
}

func TestIpsecDivertUnenslavedUnchanged14974(t *testing.T) {
	tbl := &gnft.Table{Family: gnft.TableFamilyINet, Name: IpsecDivertTableName}
	chain := ipsecDivertChain(tbl, "input", gnft.ChainHookInput)
	p := newBuildPlan(t, IpsecDivertTableName, IpsecDivertPriority)
	p.chain = chain
	emitIpsecDivertRules(p, []IpsecDivertRule{{Ifname: "st0", Queue: 1498}})
	if p.err != nil {
		t.Fatalf("render: %v", p.err)
	}
	if len(p.rules) != 1 {
		t.Fatalf("rendered %d rules, want 1", len(p.rules))
	}
	rule := p.rules[0]
	if got := ruleMetaNames14974(t, rule, expr.MetaKeyIIFNAME); len(got) != 1 || got[0] != "st0" {
		t.Fatalf("iifname scope = %v, want [st0]", got)
	}
	if got := ruleMetaNames14974(t, rule, expr.MetaKey(metaKeySDIFNAME)); len(got) != 0 {
		t.Fatalf("unenslaved rule gained sdifname scope %v, want none", got)
	}
}

func TestHostInputFenceOverlayScopedToTunnel14974(t *testing.T) {
	overlay := &HostInputFenceOverlay{
		MasterSlavePairs: []HostInputFencePair{{Master: "vrf-blue", Slave: "st0.0"}},
		SlaveSet:         []string{"st0.0"},
		Generation:       7,
		PermitEpoch:      9,
		CloseRequestSeq:  11,
		CloseRequestKey:  "UNSAFE/7",
		WatchGeneration:  7,
		State:            "CLOSING",
	}
	p := newBuildPlan(t, HostInboundTableName, 0)
	buildHostInboundNetlink(p, HostInboundSpec{Overlay: overlay})
	if p.err != nil {
		t.Fatalf("render: %v", p.err)
	}
	var rule []expr.Any
	for _, r := range p.rules {
		if got := ruleMetaNames14974(t, r, expr.MetaKey(metaKeySDIFNAME)); len(got) == 1 && got[0] == "st0.0" {
			rule = r
			break
		}
	}
	if rule == nil {
		t.Fatalf("no slave-scoped overlay drop rendered; rules=%d (unscoped master drop would fence every VRF co-member)", len(p.rules))
	}
	if got := ruleMetaNames14974(t, rule, expr.MetaKeyIIFNAME); len(got) != 1 || got[0] != "vrf-blue" {
		t.Fatalf("overlay iifname = %v, want [vrf-blue]", got)
	}
	if got := ruleMetaNames14974(t, rule, expr.MetaKey(metaKeySDIFNAME)); len(got) != 1 || got[0] != "st0.0" {
		t.Fatalf("overlay sdifname = %v, want [st0.0]", got)
	}
	other := *overlay
	other.SlaveSet = []string{"st1.0"}
	other.MasterSlavePairs = []HostInputFencePair{{Master: "vrf-blue", Slave: "st1.0"}}
	if HostInputFenceOverlayCounterName(*overlay) == HostInputFenceOverlayCounterName(other) {
		t.Fatal("overlay marker does not change with slave scope")
	}
	dup := *overlay
	dup.SlaveSet = []string{"st1.0", "st0.0", "st1.0"}
	canon := CanonicalHostInputFenceOverlay(dup)
	if strings.Join(canon.SlaveSet, ",") != "st0.0,st1.0" {
		t.Fatalf("canonical slave set = %v, want [st0.0 st1.0]", canon.SlaveSet)
	}
}

func TestHostInputFenceOverlayUnenslavedUnchanged14974(t *testing.T) {
	overlay := &HostInputFenceOverlay{
		MasterSet:       []string{"st0"},
		Generation:      7,
		PermitEpoch:     9,
		CloseRequestSeq: 11,
		CloseRequestKey: "UNSAFE/7",
		WatchGeneration: 7,
		State:           "CLOSING",
	}
	p := newBuildPlan(t, HostInboundTableName, 0)
	buildHostInboundNetlink(p, HostInboundSpec{Overlay: overlay})
	if p.err != nil {
		t.Fatalf("render: %v", p.err)
	}
	var rule []expr.Any
	for _, r := range p.rules {
		if got := ruleMetaNames14974(t, r, expr.MetaKeyIIFNAME); len(got) == 1 && got[0] == "st0" {
			rule = r
			break
		}
	}
	if rule == nil {
		t.Fatal("overlay rendered no st0 drop rule")
	}
	if got := ruleMetaNames14974(t, rule, expr.MetaKey(metaKeySDIFNAME)); len(got) != 0 {
		t.Fatalf("unenslaved overlay gained sdifname scope %v, want none", got)
	}
}
