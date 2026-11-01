package nftables

import (
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// #18746 fixes 2 and 3 (#10751 contracts): TableEnforcing and TableDropsInput
// must not count the #16841 zero-hop rule, and must count every other rule,
// near-misses included.

var zeroHopNames18746 = []string{"meta", "cmp", "payload", "cmp", "fib", "byteorder", "lookup", "immediate"}

// zeroHopDecoded18746 is the zero-hop rule the build emits, in the shape
// GetRules returns it (byteorder dropped).
func zeroHopDecoded18746(t *testing.T) []expr.Any {
	t.Helper()
	want, _ := zeroHopPlanRule18746(t)
	return kernelReadback18746(want)
}

func exactSet18746(string) ([]nftables.SetElement, error) {
	return fibLocalOrAnycastElements(), nil
}

func TestZeroHopMatcherAcceptsExactlyTheBuiltRule18746(t *testing.T) {
	decoded := zeroHopDecoded18746(t)
	ok, err := isZeroHopLimitLocalDropRule(&nftables.Rule{Exprs: decoded}, zeroHopNames18746, exactSet18746)
	if err != nil || !ok {
		t.Fatalf("the rule EmitZeroHopLimitLocalDrop builds is not recognised: %v, %v", ok, err)
	}

	clone := func() []expr.Any { return append([]expr.Any(nil), decoded...) }
	replace := func(i int, e expr.Any) []expr.Any { c := clone(); c[i] = e; return c }
	lookup := decoded[5].(*expr.Lookup)
	for name, tc := range map[string]struct {
		exprs []expr.Any
		names []string
		set   []nftables.SetElement
	}{
		"hop limit 1":             {exprs: replace(3, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}})},
		"payload offset 8":        {exprs: replace(2, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 1})},
		"nfproto ipv4":            {exprs: replace(1, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}})},
		"fib saddr":               {exprs: replace(4, &expr.Fib{Register: 1, ResultADDRTYPE: true, FlagSADDR: true})},
		"inverted lookup":         {exprs: replace(5, &expr.Lookup{SourceRegister: 1, SetName: lookup.SetName, Invert: true})},
		"map lookup":              {exprs: replace(5, &expr.Lookup{SourceRegister: 1, SetName: lookup.SetName, IsDestRegSet: true})},
		"named set":               {exprs: replace(5, &expr.Lookup{SourceRegister: 1, SetName: "operator_set"})},
		"accept verdict":          {exprs: replace(6, &expr.Verdict{Kind: expr.VerdictAccept})},
		"extra counter":           {exprs: append(clone()[:6:6], &expr.Counter{}, decoded[6]), names: []string{"meta", "cmp", "payload", "cmp", "fib", "byteorder", "lookup", "counter", "immediate"}},
		"kernel lacks byteorder":  {names: []string{"meta", "cmp", "payload", "cmp", "fib", "lookup", "immediate"}},
		"hidden kind for fib":     {names: []string{"meta", "cmp", "payload", "cmp", "rt", "byteorder", "lookup", "immediate"}},
		"set holds only local":    {set: []nftables.SetElement{{Key: binaryutil.BigEndian.PutUint32(uint32(unix.RTN_LOCAL))}}},
		"set holds an extra type": {set: append(fibLocalOrAnycastElements(), nftables.SetElement{Key: binaryutil.BigEndian.PutUint32(uint32(unix.RTN_UNICAST))})},
		"set swaps anycast":       {set: []nftables.SetElement{{Key: binaryutil.BigEndian.PutUint32(uint32(unix.RTN_LOCAL))}, {Key: binaryutil.BigEndian.PutUint32(uint32(unix.RTN_UNICAST))}}},
	} {
		exprs := tc.exprs
		if exprs == nil {
			exprs = decoded
		}
		names := tc.names
		if names == nil {
			names = zeroHopNames18746
		}
		set := exactSet18746
		if tc.set != nil {
			s := tc.set
			set = func(string) ([]nftables.SetElement, error) { return s, nil }
		}
		if ok, _ := isZeroHopLimitLocalDropRule(&nftables.Rule{Exprs: exprs}, names, set); ok {
			t.Errorf("near-miss %q was taken for the zero-hop rule; a real rule would go uncounted", name)
		}
	}
}

// The live predicates, against tables the kernel really holds.
func TestTablePredicatesIgnoreOnlyTheZeroHopRule18746(t *testing.T) {
	requirePrivateNetns18721(t)
	in := NewNetlinkInstaller().(*netlinkInstaller)
	t.Cleanup(func() { _ = in.DeleteTable(HostInboundTableName) })
	enforceNearMiss := func(p *nlPlan) {
		// `ip6 hoplimit 1 fib daddr type { local, anycast } drop`: one byte
		// off the zero-hop rule, so it must count as a real DROP.
		a := p.rule()
		a.needNfproto(famV6)
		a.add(&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 7, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}})
		a.fibLocalOrAnycast().emit(verdictDrop()...)
	}
	for _, tc := range []struct {
		name               string
		build              func(p *nlPlan)
		enforcing, dropsIn bool
	}{
		{"only the zero-hop rule", func(p *nlPlan) { EmitZeroHopLimitLocalDrop(p, false) }, false, false},
		{"zero-hop plus a real DROP", func(p *nlPlan) {
			EmitZeroHopLimitLocalDrop(p, false)
			p.rule().daddr(famV4, []string{"192.0.2.1"}, false).emit(verdictDrop()...)
		}, true, true},
		{"zero-hop plus an accept", func(p *nlPlan) {
			EmitZeroHopLimitLocalDrop(p, false)
			p.rule().daddr(famV4, []string{"192.0.2.1"}, false).emit(verdictAccept()...)
		}, true, false},
		{"a near-miss of the zero-hop rule alone", enforceNearMiss, true, true},
		{"no rules at all", func(p *nlPlan) {}, false, false},
	} {
		if _, err := in.replaceTable(HostInboundTableName, hostInboundPriority, tc.build); err != nil {
			t.Fatalf("%s: install: %v", tc.name, err)
		}
		if got, err := in.TableEnforcing(HostInboundTableName); err != nil || got != tc.enforcing {
			t.Errorf("%s: TableEnforcing = %v, %v; want %v", tc.name, got, err, tc.enforcing)
		}
		if got, err := in.TableDropsInput(HostInboundTableName); err != nil || got != tc.dropsIn {
			t.Errorf("%s: TableDropsInput = %v, %v; want %v", tc.name, got, err, tc.dropsIn)
		}
	}
	// The production lo0 path: an empty filter renders only the zero-hop rule.
	if _, err := in.InstallLo0(Lo0FilterSpec{}); err != nil {
		t.Fatalf("install empty lo0 filter: %v", err)
	}
	t.Cleanup(func() { _ = in.DeleteTable(Lo0TableName) })
	if got, err := in.TableEnforcing(Lo0TableName); err != nil || got {
		t.Errorf("an empty lo0 filter (zero-hop rule only) reads enforcing = %v, %v; want false", got, err)
	}
	if !strings.HasPrefix(HostInboundTableName, "xpf_") {
		t.Fatal("fixture: unexpected table name")
	}
}
