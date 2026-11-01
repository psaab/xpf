package nftables

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// #18746 fix 1: the #12128 uncertain-ACK recovery compares the installed
// table with the plan. The #16841 zero-hop rule carries an expr.Byteorder,
// which google/nftables v0.3.0 drops on readback, so before this fix rule 0
// never compared equal and recovery always reported the install failed. The
// kernel cell is TestLargeReplaceRecoversUncertainAck12128 (netns).

// zeroHopPlanRule18746 returns the #16841 zero-hop rule exactly as the
// host-inbound build emits it, plus the set-name map the comparison needs.
func zeroHopPlanRule18746(t *testing.T) ([]expr.Any, map[uint32]string) {
	t.Helper()
	p := newBuildPlan(t, HostInboundTableName, hostInboundPriority)
	EmitZeroHopLimitLocalDrop(p, false)
	if p.err != nil || len(p.rules) != 1 {
		t.Fatalf("fixture: zero-hop build = %d rules, %v", len(p.rules), p.err)
	}
	setNames := map[uint32]string{}
	for _, e := range p.rules[0] {
		if l, ok := e.(*expr.Lookup); ok {
			setNames[l.SetID] = l.SetName
		}
	}
	return p.rules[0], setNames
}

// kernelReadback18746 is what GetRules returns for a planned rule: the plan
// minus every decoder-dropped kind.
func kernelReadback18746(want []expr.Any) []expr.Any {
	var got []expr.Any
	for _, e := range want {
		if decoderDroppedExprName(e) == "" {
			got = append(got, e)
		}
	}
	return got
}

func TestUncertainAckReadbackMatchesTheZeroHopRule18746(t *testing.T) {
	want, setNames := zeroHopPlanRule18746(t)
	names := []string{"meta", "cmp", "payload", "cmp", "fib", "byteorder", "lookup", "immediate"}
	if len(names) != len(want) {
		t.Fatalf("fixture: the zero-hop rule has %d expressions, the names list %d", len(want), len(names))
	}
	got := kernelReadback18746(want)
	if len(got) != len(want)-1 {
		t.Fatalf("fixture: exactly the byteorder should be dropped, got %d of %d", len(got), len(want))
	}
	fam := byte(nftables.TableFamilyINet)

	// The defect: the pre-#18746 comparison over the typed decode alone.
	if ok, _ := expressionsMatch(fam, want, got, setNames); ok {
		t.Fatal("fixture: the plain typed comparison already matches; this cell no longer reaches the defect")
	}
	if ok, err := ruleMatchesPlan(fam, want, got, names, setNames); err != nil || !ok {
		t.Errorf("the zero-hop rule's readback does not match its plan: %v, %v", ok, err)
	}

	// Fail-closed cases.
	for name, kn := range map[string][]string{
		"the kernel lacks the byteorder":          {"meta", "cmp", "payload", "cmp", "fib", "lookup", "immediate"},
		"another kind where the byteorder is":     {"meta", "cmp", "payload", "cmp", "fib", "bitwise", "lookup", "immediate"},
		"a dropped kind at a decodable position":  {"meta", "cmp", "payload", "cmp", "rt", "byteorder", "lookup", "immediate"},
		"an extra kernel expression":              {"meta", "cmp", "payload", "cmp", "fib", "byteorder", "lookup", "counter", "immediate"},
		"the byteorder moved to another position": {"meta", "cmp", "byteorder", "payload", "cmp", "fib", "lookup", "immediate"},
	} {
		if ok, _ := ruleMatchesPlan(fam, want, got, kn, setNames); ok {
			t.Errorf("%s: readback matched the plan", name)
		}
	}
	accept := append([]expr.Any(nil), got...)
	accept[len(accept)-1] = &expr.Verdict{Kind: expr.VerdictAccept}
	if ok, _ := ruleMatchesPlan(fam, want, accept, names, setNames); ok {
		t.Error("a typed verdict that differs from the plan matched")
	}
}
