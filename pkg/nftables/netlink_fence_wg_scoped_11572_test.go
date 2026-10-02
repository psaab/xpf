package nftables

import (
	"strings"
	"testing"
)

// TestFenceWGAdmissionIsNotGlobal11572 catches a fence's global UDP-port
// exception before its destination drops and proves only the serving zone is
// admitted in both the cold-boot and coverage-gap tables.
func TestFenceWGAdmissionIsNotGlobal11572(t *testing.T) {
	views := []HostInboundZoneView{
		{Zone: "serving", V4Addrs: []string{"10.0.1.1"}, V6Addrs: []string{"2001:db8:1::1"}},
		{Zone: "unconfigured", V4Addrs: []string{"10.0.2.1"}, V6Addrs: []string{"2001:db8:2::1"}},
	}
	wgZonePorts := map[string][]uint16{"serving": {51820}}
	unzonedV4, unzonedV6 := []string{"10.0.99.1"}, []string{"2001:db8:99::1"}
	uncoveredV4 := []string{"10.0.1.1", "10.0.2.1", unzonedV4[0]}
	uncoveredV6 := []string{"2001:db8:1::1", "2001:db8:2::1", unzonedV6[0]}

	t.Run("cold-boot", func(t *testing.T) {
		p := newBuildPlan(t, HostInboundTableName, hostInboundPriority)
		buildHostInboundFenceNetlink(p, FenceSpec{
			Views: views, UnzonedV4: unzonedV4, UnzonedV6: unzonedV6,
			WGListenPorts: []uint16{51820}, WGZonePorts: wgZonePorts,
		})
		assertFenceWGScope11572(t, p)
	})

	t.Run("coverage-gap", func(t *testing.T) {
		gapViews := []HostInboundZoneView{
			{Zone: "serving", V4Addrs: []string{"10.0.1.1", "10.0.1.2"}, V6Addrs: []string{"2001:db8:1::1"}},
			views[1],
		}
		p := newBuildPlan(t, HostInboundGapTableName, hostInboundGapPriority)
		buildHostInboundGapFenceNetlink(p, GapFenceSpec{
			Views: gapViews, UncoveredV4: uncoveredV4, UncoveredV6: uncoveredV6,
			WGListenPorts: []uint16{51820}, WGZonePorts: wgZonePorts,
		})
		assertFenceWGScope11572(t, p)
		if fenceHasVerdictForAddress11572(t, p, "10.0.1.2", true) ||
			fenceHasVerdictForAddress11572(t, p, "10.0.1.2", false) {
			t.Fatal("gap fence must leave a covered serving-zone address to the retained table")
		}
	})
}

func assertFenceWGScope11572(t *testing.T, p *nlPlan) {
	t.Helper()
	if p.err != nil {
		t.Fatalf("build fence: %v", p.err)
	}
	for _, addr := range []string{"10.0.1.1", "2001:db8:1::1"} {
		acceptAt, dropAt := fenceWGRuleIndexes11572(t, p, addr)
		if acceptAt < 0 || dropAt < 0 || acceptAt >= dropAt {
			t.Errorf("serving-zone WG accept for %s must precede its destination drop; accept=%d drop=%d", addr, acceptAt, dropAt)
		}
	}
	for _, addr := range []string{"10.0.2.1", "2001:db8:2::1", "10.0.99.1", "2001:db8:99::1"} {
		if fenceHasVerdictForAddress11572(t, p, addr, true) {
			t.Errorf("unconfigured or unzoned address %s has a WG dport accept", addr)
		}
		if !fenceHasVerdictForAddress11572(t, p, addr, false) {
			t.Errorf("unconfigured or unzoned address %s is not denied by the fence", addr)
		}
	}
	servingV4, servingV6 := addrHex(t, "10.0.1.1"), addrHex(t, "2001:db8:1::1")
	for _, rule := range p.rules {
		line := canonRule(p, rule)
		if strings.Contains(line, "ca6c") && strings.Contains(line, "verdict(1)") &&
			!strings.Contains(line, servingV4) && !strings.Contains(line, servingV6) {
			t.Fatalf("WireGuard dport accept has no serving-zone destination scope: %s", line)
		}
	}
}

func fenceWGRuleIndexes11572(t *testing.T, p *nlPlan, addr string) (acceptAt, dropAt int) {
	t.Helper()
	acceptAt, dropAt = -1, -1
	wantAddr := addrHex(t, addr)
	for i, rule := range p.rules {
		line := canonRule(p, rule)
		if !strings.Contains(line, wantAddr) {
			continue
		}
		if acceptAt < 0 && strings.Contains(line, "ca6c") && strings.Contains(line, "verdict(1)") {
			acceptAt = i
		}
		if dropAt < 0 && strings.Contains(line, "verdict(0)") && !strings.Contains(line, "payload(base=2,off=2,len=2") {
			dropAt = i
		}
	}
	return acceptAt, dropAt
}

func fenceHasVerdictForAddress11572(t *testing.T, p *nlPlan, addr string, wgAccept bool) bool {
	t.Helper()
	wantAddr := addrHex(t, addr)
	for _, rule := range p.rules {
		line := canonRule(p, rule)
		if !strings.Contains(line, wantAddr) {
			continue
		}
		if wgAccept && strings.Contains(line, "ca6c") && strings.Contains(line, "verdict(1)") {
			return true
		}
		if !wgAccept && strings.Contains(line, "verdict(0)") {
			return true
		}
	}
	return false
}
