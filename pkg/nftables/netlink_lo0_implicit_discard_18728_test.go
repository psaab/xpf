package nftables

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// #18728: the netlink lo0 builder ends each flagged family with the Junos
// implicit final discard: nfproto guard, iifname exemption, named counter,
// drop. The daemon parity test (TestNftNetlinkParity) proves it equals the
// text oracle against a real kernel; these cells pin its structure without
// one.

func implicitRule18728(t *testing.T, p *nlPlan) []expr.Any {
	t.Helper()
	for _, r := range p.rules {
		for _, e := range r {
			if o, ok := e.(*expr.Objref); ok && strings.HasPrefix(o.Name, lo0ImplicitDiscardCounterPrefix) {
				return r
			}
		}
	}
	t.Fatalf("no implicit-discard rule in the plan:\n%s", canonRules(p))
	return nil
}

func TestLo0NetlinkImplicitDiscardRule18728(t *testing.T) {
	p := newBuildPlan(t, "xpf_lo0", lo0FilterPriority)
	buildLo0FilterNetlink(p, Lo0FilterSpec{
		NoIPv6RejectZeroHopLimit: true,
		V4Terms: []Lo0FilterTerm{{
			Name: "ssh", Protocols: []string{"tcp"}, DestinationPorts: []string{"22"}, Action: "accept",
		}},
		ImplicitDiscardV4:            true,
		ImplicitDiscardExemptNetdevs: []string{"lo", "em0"},
	})
	if p.err != nil {
		t.Fatalf("build: %v", p.err)
	}
	if len(p.rules) != 2 {
		t.Fatalf("want the ssh accept then the implicit drop (2 rules), got %d:\n%s", len(p.rules), canonRules(p))
	}
	if !reflect.DeepEqual(p.counters, []string{"xpflo0implicit_inet"}) {
		t.Fatalf("declared counters = %v, want only the implicit one", p.counters)
	}
	r := implicitRule18728(t, p)
	if !reflect.DeepEqual(r, p.rules[1]) {
		t.Fatalf("the implicit drop must be the LAST v4 rule:\n%s", canonRules(p))
	}
	canon := canonRule(p, r)
	var nfproto, exemptLookup, drop bool
	for i, e := range r {
		switch x := e.(type) {
		case *expr.Meta:
			if x.Key == expr.MetaKeyNFPROTO && i+1 < len(r) {
				if c, ok := r[i+1].(*expr.Cmp); ok && c.Op == expr.CmpOpEq && len(c.Data) == 1 && c.Data[0] == unix.NFPROTO_IPV4 {
					nfproto = true
				}
			}
		case *expr.Lookup:
			if x.Invert {
				exemptLookup = true
			}
		case *expr.Verdict:
			drop = x.Kind == expr.VerdictDrop
		}
	}
	if !nfproto || !exemptLookup || !drop {
		t.Fatalf("implicit rule must be `meta nfproto ipv4 iifname != {lo, em0} counter drop`; nfproto=%v exempt=%v drop=%v\n%s",
			nfproto, exemptLookup, drop, canon)
	}
	// canonRule renders set elements as hex of the 16-byte ifname.
	for _, name := range []string{"lo", "em0"} {
		if !strings.Contains(canon, hex.EncodeToString(ifname16(name))) {
			t.Errorf("exemption set lacks %q: %s", name, canon)
		}
	}
}

// Single-name exemption ("lo" on a standalone node) uses the != compare.
func TestLo0NetlinkImplicitDiscardSingleExemption18728(t *testing.T) {
	p := newBuildPlan(t, "xpf_lo0", lo0FilterPriority)
	buildLo0FilterNetlink(p, Lo0FilterSpec{
		NoIPv6RejectZeroHopLimit:     true,
		ImplicitDiscardV6:            true,
		ImplicitDiscardExemptNetdevs: []string{"lo"},
	})
	if p.err != nil {
		t.Fatalf("build: %v", p.err)
	}
	if len(p.rules) != 1 {
		t.Fatalf("an empty v6 filter renders exactly its implicit drop; got %d:\n%s", len(p.rules), canonRules(p))
	}
	r := implicitRule18728(t, p)
	neq := false
	for _, e := range r {
		if c, ok := e.(*expr.Cmp); ok && c.Op == expr.CmpOpNeq && strings.HasPrefix(string(c.Data), "lo\x00") {
			neq = true
		}
	}
	if !neq {
		t.Fatalf("single exemption must render `iifname != \"lo\"`: %s", canonRule(p, r))
	}
	if !reflect.DeepEqual(p.counters, []string{"xpflo0implicit_inet6"}) {
		t.Fatalf("declared counters = %v", p.counters)
	}
}

// An empty exemption list would render an UNSCOPED drop, which takes loopback
// with it; the builder refuses the plan instead.
func TestLo0NetlinkImplicitDiscardRefusesUnscopedDrop18728(t *testing.T) {
	p := newBuildPlan(t, "xpf_lo0", lo0FilterPriority)
	buildLo0FilterNetlink(p, Lo0FilterSpec{NoIPv6RejectZeroHopLimit: true, ImplicitDiscardV4: true})
	if p.err == nil {
		t.Fatalf("an implicit discard with no exemption must fail the plan; rules:\n%s", canonRules(p))
	}
}

// No flag, no rule: a catch-all filter's spec renders only its own terms.
func TestLo0NetlinkNoImplicitDiscardWithoutFlag18728(t *testing.T) {
	p := newBuildPlan(t, "xpf_lo0", lo0FilterPriority)
	buildLo0FilterNetlink(p, Lo0FilterSpec{
		NoIPv6RejectZeroHopLimit:     true,
		V4Terms:                      []Lo0FilterTerm{{Name: "default", Action: "accept"}},
		ImplicitDiscardExemptNetdevs: []string{"lo"},
	})
	if p.err != nil || len(p.rules) != 1 || len(p.counters) != 0 {
		t.Fatalf("catch-all spec: err=%v rules=%d counters=%v\n%s", p.err, len(p.rules), p.counters, canonRules(p))
	}
}

func TestLo0ImplicitDiscardCounterNames18728(t *testing.T) {
	for _, fam := range []string{"inet", "inet6"} {
		name := Lo0ImplicitDiscardCounterName(fam)
		got, ok := ParseLo0ImplicitDiscardCounterName(name)
		if !ok || got != fam {
			t.Fatalf("round trip %q -> %q ok=%v", name, got, ok)
		}
		// Never readable as an operator `then count` counter.
		if c, ok := ParseLo0CounterName(name); ok {
			t.Fatalf("implicit counter %q parsed as operator counter %q", name, c)
		}
	}
	// No operator count name can produce an implicit counter object.
	if _, ok := ParseLo0ImplicitDiscardCounterName(Lo0CounterName("implicit_inet")); ok {
		t.Fatal("an operator counter named implicit_inet must not parse as the implicit counter")
	}
	for _, bad := range []string{"xpflo0implicit_", "xpflo0implicit_inet4", "xpflo0_implicit_inet"} {
		if _, ok := ParseLo0ImplicitDiscardCounterName(bad); ok {
			t.Errorf("%q must not parse as an implicit counter", bad)
		}
	}
}
