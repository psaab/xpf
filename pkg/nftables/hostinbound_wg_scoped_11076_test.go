package nftables

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/nftables/expr"
)

// #11574 (netlink production renderer): WireGuard admission requires the
// transport-zone ingress and unique same-zone destination, never a global accept.
func TestWireGuardAcceptIsZoneScopedNetlink11076(t *testing.T) {
	p := newBuildPlan(t, "xpf_11076", hostInboundPriority)
	buildHostInboundNetlink(p, HostInboundSpec{
		Views: []HostInboundZoneView{
			{Zone: "trust", SystemServices: []string{"ssh"}, V4Addrs: []string{"10.0.1.1"}, V6Addrs: []string{"2001:db8:1::1"}, IngressNetdevs: []string{"trust0"}},
			{Zone: "untrust", SystemServices: []string{"ping"}, V4Addrs: []string{"10.0.2.1"}, IngressNetdevs: []string{"untrust0"}},
		},
		UnzonedV4:     []string{"10.0.99.1"},
		UnzonedV6:     []string{"2001:db8:99::1"},
		WGListenPorts: []uint16{51820},
		WGZonePorts:   map[string][]uint16{"trust": {51820}},
	})
	if p.err != nil {
		t.Fatalf("build error: %v", p.err)
	}
	plan := canonRules(p)

	// Trust's addresses admit UDP/51820 (hex dport ca6c). verdict(1)
	// is NF_ACCEPT, verdict(0) is NF_DROP.
	trustRules := zoneRules(t, p, "10.0.1.1")
	found := false
	for _, line := range trustRules {
		if strings.Contains(line, "ca6c") && strings.HasSuffix(line, "verdict(1)") {
			found = true
		}
	}
	if !found {
		t.Fatalf("trust section missing scoped UDP/51820 accept:\n%s", plan)
	}
	// No bare (daddr-less) UDP/51820 accept anywhere: every 51820 line must
	// also carry a daddr payload (trust's v4 or v6 hex).
	trustV4 := addrHex(t, "10.0.1.1")
	trustV6 := addrHex(t, "2001:db8:1::1")
	for _, r := range p.rules {
		line := canonRule(p, r)
		if strings.Contains(line, "ca6c") && strings.HasSuffix(line, "verdict(1)") &&
			!strings.Contains(line, trustV4) && !strings.Contains(line, trustV6) {
			t.Fatalf("bare WG accept leaked: %s\nplan:\n%s", line, plan)
		}
	}
	// Untrust's address admits nothing on 51820.
	for _, line := range zoneRules(t, p, "10.0.2.1") {
		if strings.Contains(line, "ca6c") && strings.HasSuffix(line, "verdict(1)") {
			t.Fatalf("non-serving zone admits the WG port: %s\nplan:\n%s", line, plan)
		}
	}
	// Ordering: the matching iifname/daddr/port accept precedes the zone's
	// service catch-all drop. Mismatch guards also mention ca6c but end in DROP.
	acceptIdx, dropIdx := -1, -1
	for _, r := range p.rules {
		line := canonRule(p, r)
		if acceptIdx < 0 && strings.Contains(line, trustV4) && strings.Contains(line, "ca6c") && strings.HasSuffix(line, "verdict(1)") {
			acceptIdx = strings.Index(plan, line)
		}
		if dropIdx < 0 && strings.Contains(line, trustV4) && strings.Contains(line, "xpfhi_") &&
			!strings.Contains(line, "ca6c") && strings.HasSuffix(line, "verdict(0)") {
			dropIdx = strings.Index(plan, line)
		}
	}
	if acceptIdx < 0 || dropIdx < 0 || acceptIdx > dropIdx {
		t.Fatalf("scoped accept must precede the zone drop (accept=%d drop=%d):\n%s", acceptIdx, dropIdx, plan)
	}
}

// The fresh trusted reinject accept must not suppress WireGuard owner-zone
// mismatch drops in the netlink renderer. This pins the mirrored production
// path as well as the daemon text builder.
func TestWireGuardMismatchDropCoversTrustedReinjectNetlink12119(t *testing.T) {
	for _, tc := range []struct {
		name     string
		zonePort map[string][]uint16
	}{
		{name: "owned source", zonePort: map[string][]uint16{"trust": {51820}}},
		{name: "source-less", zonePort: map[string][]uint16{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newBuildPlan(t, "xpf_12119", hostInboundPriority)
			buildHostInboundNetlink(p, HostInboundSpec{
				Views: []HostInboundZoneView{
					{Zone: "trust", SystemServices: []string{"ssh"}, V4Addrs: []string{"10.0.1.1"}, IngressNetdevs: []string{"trust0"}},
					{Zone: "untrust", SystemServices: []string{"any-service"}, V4Addrs: []string{"10.0.2.1"}, IngressNetdevs: []string{"untrust0"}},
				},
				WGListenPorts:  []uint16{51820},
				WGZonePorts:    tc.zonePort,
				DataplaneFresh: true,
			})
			if p.err != nil {
				t.Fatalf("build error: %v", p.err)
			}
			plan := canonRules(p)
			sawDrop := false
			lastDropIndex := -1
			reinjectAcceptIndex := -1
			for index, rule := range p.rules {
				line := canonRule(p, rule)
				if strings.Contains(line, "ca6c") && strings.Contains(line, "xpfhi_") &&
					strings.HasSuffix(line, "verdict(0)") {
					sawDrop = true
					lastDropIndex = index
					if hasIifnameRuleValue(rule, HostInboundReinjectIfname) {
						t.Fatalf("WG mismatch drop includes trusted reinject: %s\nplan:\n%s", line, plan)
					}
				}
				if hasIifnameRuleMatch(rule, HostInboundReinjectIfname) &&
					strings.HasSuffix(line, "verdict(1)") {
					reinjectAcceptIndex = index
				}
			}
			if !sawDrop {
				t.Fatalf("fresh dataplane must render a WG mismatch drop:\n%s", plan)
			}
			if reinjectAcceptIndex <= lastDropIndex {
				t.Fatalf("fresh reinject accept must remain after WG mismatch drops: drop=%d accept=%d\n%s", lastDropIndex, reinjectAcceptIndex, plan)
			}
		})
	}
}

func hasIifnameRuleValue(rule []expr.Any, name string) bool {
	return iifnameRuleComparison(rule, name) != nil
}

func hasIifnameRuleMatch(rule []expr.Any, name string) bool {
	cmp := iifnameRuleComparison(rule, name)
	return cmp != nil && cmp.Op == expr.CmpOpEq
}

func iifnameRuleComparison(rule []expr.Any, name string) *expr.Cmp {
	want := ifname16(name)
	for i, e := range rule {
		meta, ok := e.(*expr.Meta)
		if !ok || meta.Key != expr.MetaKeyIIFNAME || i+1 >= len(rule) {
			continue
		}
		cmp, ok := rule[i+1].(*expr.Cmp)
		if ok && cmp.Register == meta.Register && bytes.Equal(cmp.Data, want) {
			return cmp
		}
	}
	return nil
}
