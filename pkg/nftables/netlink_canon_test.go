package nftables

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// netlink_canon_test.go renders a built rule's []expr.Any into a stable,
// human-readable canonical string for the T1b golden and mutation-sensitivity
// tests. Anonymous set names/IDs (non-deterministic across runs) are normalized
// to the set's sorted element CONTENTS, so a widened lookup set — a fail-open
// that leaves the Lookup expr byte-identical — still changes the canonical form
// and is caught. This canonicalizer is a TEST oracle for the expr stream; it is
// NOT the parity oracle (that is the exec-`nft` text + kernel diff, T1).

// canonRules renders every emitted rule of a plan to one newline-joined string.
func canonRules(p *nlPlan) string {
	var b strings.Builder
	for i, r := range p.rules {
		fmt.Fprintf(&b, "r%02d: %s\n", i, canonRule(p, r))
	}
	return b.String()
}

func canonRule(p *nlPlan, exprs []expr.Any) string {
	parts := make([]string, 0, len(exprs))
	for _, e := range exprs {
		parts = append(parts, canonExpr(p, e))
	}
	return strings.Join(parts, " ")
}

func canonExpr(p *nlPlan, e expr.Any) string {
	switch x := e.(type) {
	case *expr.Meta:
		return fmt.Sprintf("meta(key=%d,reg=%d)", x.Key, x.Register)
	case *expr.Ct:
		return fmt.Sprintf("ct(key=%d,reg=%d)", x.Key, x.Register)
	case *expr.Cmp:
		return fmt.Sprintf("cmp(op=%d,reg=%d,%s)", x.Op, x.Register, hex.EncodeToString(x.Data))
	case *expr.Bitwise:
		return fmt.Sprintf("bitwise(len=%d,mask=%s,xor=%s)", x.Len, hex.EncodeToString(x.Mask), hex.EncodeToString(x.Xor))
	case *expr.Payload:
		return fmt.Sprintf("payload(base=%d,off=%d,len=%d,reg=%d)", x.Base, x.Offset, x.Len, x.DestRegister)
	case *expr.Lookup:
		return fmt.Sprintf("lookup(inv=%t,set=[%s])", x.Invert, canonSet(p, x.SetID))
	case *expr.Range:
		return fmt.Sprintf("range(op=%d,from=%s,to=%s)", x.Op, hex.EncodeToString(x.FromData), hex.EncodeToString(x.ToData))
	case *expr.Objref:
		return fmt.Sprintf("objref(type=%d,name=%q)", x.Type, x.Name)
	case *expr.Log:
		return fmt.Sprintf("log(key=%d,prefix=%q)", x.Key, string(x.Data))
	case *expr.Reject:
		return fmt.Sprintf("reject(type=%d,code=%d)", x.Type, x.Code)
	case *expr.Exthdr:
		return fmt.Sprintf("exthdr(type=%d,off=%d,len=%d,op=%d,flags=%d,reg=%d)", x.Type, x.Offset, x.Len, x.Op, x.Flags, x.DestRegister)
	case *expr.Verdict:
		return fmt.Sprintf("verdict(%d)", x.Kind)
	default:
		return fmt.Sprintf("unknown(%T)", e)
	}
}

// canonSet renders an anonymous set's elements as a sorted list of hex keys
// (interval-end elements marked), so set CONTENTS (not the volatile set name/ID)
// determine the canonical form.
func canonSet(p *nlPlan, id uint32) string {
	els := p.sets[id]
	toks := make([]string, 0, len(els))
	for _, el := range els {
		tok := hex.EncodeToString(el.Key)
		if el.IntervalEnd {
			tok += "!end"
		}
		toks = append(toks, tok)
	}
	sort.Strings(toks)
	return strings.Join(toks, ",")
}

// setElementsForID exposes an anonymous set's elements to a test (nil if none).
func (p *nlPlan) setElementsForID(id uint32) []nftables.SetElement { return p.sets[id] }
