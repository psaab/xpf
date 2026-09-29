package nftables

import (
	"strings"
	"testing"
)

// #11076 (netlink production renderer): WireGuard admission is per-zone
// daddr-scoped, ordered with zone policy — never a global bare accept.
func TestWireGuardAcceptIsZoneScopedNetlink11076(t *testing.T) {
	p := newBuildPlan(t, "xpf_11076", hostInboundPriority)
	buildHostInboundNetlink(p, HostInboundSpec{
		Views: []HostInboundZoneView{
			{Zone: "trust", SystemServices: []string{"ssh"}, V4Addrs: []string{"10.0.1.1"}, V6Addrs: []string{"2001:db8:1::1"}},
			{Zone: "untrust", SystemServices: []string{"ping"}, V4Addrs: []string{"10.0.2.1"}},
		},
		UnzonedV4:   []string{"10.0.99.1"},
		UnzonedV6:   []string{"2001:db8:99::1"},
		WGZonePorts: map[string][]uint16{"trust": {51820}},
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
	// Ordering: trust's scoped accept precedes trust's catch-all drop.
	acceptIdx := strings.Index(plan, "ca6c")
	dropIdx := -1
	for _, r := range p.rules {
		line := canonRule(p, r)
		// The zone catch-all carries the per-zone deny counter (early
		// stale-guard drops share the daddr but have no counter).
		if strings.Contains(line, trustV4) && strings.Contains(line, "xpfhi_") && strings.HasSuffix(line, "verdict(0)") {
			dropIdx = strings.Index(plan, line)
			break
		}
	}
	if acceptIdx < 0 || dropIdx < 0 || acceptIdx > dropIdx {
		t.Fatalf("scoped accept must precede the zone drop (accept=%d drop=%d):\n%s", acceptIdx, dropIdx, plan)
	}
}
