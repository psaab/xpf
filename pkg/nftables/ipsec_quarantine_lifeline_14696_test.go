package nftables

import (
	"testing"

	gnft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// #14696: quarantine input must admit lifeline iifnames (and VRF-enslaved
// lifelines via sdifname) before the terminal drop, mirroring the gap-fence
// exception. Forward and non-input hooks keep the strict drop shape.

func assertIpsecQuarantineLifelineAccept14696(t *testing.T, rule []expr.Any, wantNames []string) {
	t.Helper()
	if len(rule) == 0 {
		t.Fatal("lifeline rule is empty")
	}
	verdict, ok := rule[len(rule)-1].(*expr.Verdict)
	if !ok || verdict.Kind != expr.VerdictAccept {
		t.Fatalf("lifeline rule verdict = %#v, want ACCEPT", rule[len(rule)-1])
	}
	// Must match at least one of the wanted names via iifname/sdifname.
	found := map[string]bool{}
	for _, e := range rule {
		if cmp, ok := e.(*expr.Cmp); ok {
			for _, want := range wantNames {
				if string(cmp.Data) == string(ifname16(want)) {
					found[want] = true
				}
			}
		}
		if lookup, ok := e.(*expr.Lookup); ok {
			_ = lookup
		}
	}
	// Single-name case uses Cmp; multi-name uses set lookup (names in plan sets).
	if len(wantNames) == 1 && !found[wantNames[0]] {
		t.Fatalf("lifeline rule does not match %q: %#v", wantNames[0], rule)
	}
	if len(wantNames) > 1 && len(found) == 0 {
		// Set form: verify a Lookup exists; element membership is in plan anon sets.
		hasLookup := false
		for _, e := range rule {
			if _, ok := e.(*expr.Lookup); ok {
				hasLookup = true
			}
		}
		if !hasLookup {
			t.Fatalf("multi-name lifeline rule has neither Cmp name nor Lookup: %#v", rule)
		}
	}
}

func TestIpsecQuarantineInputAdmitsLifeline14696(t *testing.T) {
	spec := normalizeIpsecQuarantineSpec(IpsecDivertSpec{
		QuarantineAll:        true,
		QuarantineGeneration: 7,
		LifelineNetdevs:      []string{"fxp0", "ge-0-0-0.100"},
		CandidateIfindices:   []uint32{17},
	})
	for _, tc := range []struct {
		name   string
		family string
		hook   string
	}{
		{"inet-input", "inet", "input"},
		{"bridge-input", "bridge", "input"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tbl := &gnft.Table{Family: gnft.TableFamilyINet, Name: IpsecQuarantineTableName}
			if tc.family == "bridge" {
				tbl.Family = gnft.TableFamilyBridge
			}
			p := newBuildPlan(t, IpsecQuarantineTableName, IpsecQuarantinePriority)
			hooknum := gnft.ChainHookInput
			p.chain = ipsecDenyChain(tbl, "input", hooknum, IpsecQuarantinePriority)
			emitIpsecQuarantineRules(p, tc.family, tc.hook, spec, false)
			if p.err != nil {
				t.Fatalf("render: %v", p.err)
			}
			// lo + lifeline iif + lifeline sdif + candidate + base = 5
			if len(p.rules) != 5 {
				t.Fatalf("rule count = %d, want 5 (lo, lifeline iif, lifeline sdif, candidate, base): %#v", len(p.rules), p.rules)
			}
			assertIpsecQuarantineLoopbackAccept9506(t, p.rules[0])
			assertIpsecQuarantineLifelineAccept14696(t, p.rules[1], spec.LifelineNetdevs)
			assertIpsecQuarantineLifelineAccept14696(t, p.rules[2], spec.LifelineNetdevs)
			// sdif rule must use sdif key
			meta, ok := p.rules[2][0].(*expr.Meta)
			if !ok || meta.Key != expr.MetaKey(metaKeySDIFNAME) {
				t.Fatalf("sdif rule first expr = %#v, want sdifname meta", p.rules[2][0])
			}
			// Last rule remains terminal DROP
			last := p.rules[len(p.rules)-1]
			v, ok := last[len(last)-1].(*expr.Verdict)
			if !ok || v.Kind != expr.VerdictDrop {
				t.Fatalf("base verdict = %#v, want DROP", last[len(last)-1])
			}
		})
	}
}

func TestIpsecQuarantineForwardHasNoLifeline14696(t *testing.T) {
	spec := normalizeIpsecQuarantineSpec(IpsecDivertSpec{
		QuarantineAll:      true,
		LifelineNetdevs:    []string{"fxp0"},
		CandidateIfindices: []uint32{17},
	})
	tbl := &gnft.Table{Family: gnft.TableFamilyINet, Name: IpsecQuarantineTableName}
	p := newBuildPlan(t, IpsecQuarantineTableName, IpsecQuarantinePriority)
	p.chain = ipsecDenyChain(tbl, "forward", gnft.ChainHookForward, IpsecQuarantinePriority)
	emitIpsecQuarantineRules(p, "inet", "forward", spec, true)
	if p.err != nil {
		t.Fatalf("render: %v", p.err)
	}
	if len(p.rules) != 3 {
		t.Fatalf("forward rule count = %d, want 3 (lo, candidate, base) — no lifeline on forward", len(p.rules))
	}
}

func TestIpsecQuarantineInputNoLifelineKeepsStrict14696(t *testing.T) {
	spec := normalizeIpsecQuarantineSpec(IpsecDivertSpec{QuarantineAll: true})
	tbl := &gnft.Table{Family: gnft.TableFamilyINet, Name: IpsecQuarantineTableName}
	p := newBuildPlan(t, IpsecQuarantineTableName, IpsecQuarantinePriority)
	p.chain = ipsecDenyChain(tbl, "input", gnft.ChainHookInput, IpsecQuarantinePriority)
	emitIpsecQuarantineRules(p, "inet", "input", spec, false)
	if p.err != nil {
		t.Fatalf("render: %v", p.err)
	}
	if len(p.rules) != 2 {
		t.Fatalf("rule count = %d, want 2 (lo, base) without lifelines", len(p.rules))
	}
}

func TestIpsecQuarantineNormalizeLifelines14696(t *testing.T) {
	spec := normalizeIpsecQuarantineSpec(IpsecDivertSpec{
		QuarantineAll:   true,
		LifelineNetdevs: []string{"fxp0", "fxp0", "", "em0"},
	})
	if len(spec.LifelineNetdevs) != 2 || spec.LifelineNetdevs[0] != "em0" || spec.LifelineNetdevs[1] != "fxp0" {
		t.Fatalf("normalized lifelines = %v, want sorted unique [em0 fxp0]", spec.LifelineNetdevs)
	}
	// Non-quarantine spec must not have lifelines forced.
	plain := normalizeIpsecQuarantineSpec(IpsecDivertSpec{LifelineNetdevs: []string{"fxp0"}})
	if len(plain.LifelineNetdevs) != 0 {
		t.Fatalf("non-quarantine spec retained lifelines %v, want cleared", plain.LifelineNetdevs)
	}
}
