package daemon

import (
	"strings"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #15977: gap-fence fixtures passed IPv6 literals in the uncoveredV4
// positional slot, rendering `ip daddr <v6> drop` through the verbatim
// nftAddrSet. Production producers (BuildZoneHostInboundViews /
// BuildUnzonedHostInboundAddrs) split by `strings.Contains(host, ":")` on
// hostIPFromCIDR output, so they cannot mis-family today; this cell pins
// the boundary guarantee at hostInboundUncoveredDropAddrs regardless of
// producer, and pins that the corrected fixtures render family-correct
// gap drops.
//
// RED on revert: drop the hostInboundAddrMatchesFamily filter and the
// wrong-family literals below reappear in the returned lists and in the
// rendered `ip daddr <v6>` / `ip6 daddr <v4>` drops.

func TestHostInboundUncoveredDropAddrsFamilyFiltered15977(t *testing.T) {
	views := []dpuserspace.ZoneHostInboundView{
		{
			Zone:          "zoneb",
			V4Addrs:       []string{"192.0.2.1", "2001:db8:b::1"}, // v6 misfiled as v4
			V6Addrs:       []string{"2001:db8:b::1", "192.0.2.1"}, // v4 misfiled as v6
			IngressDenyV4: []string{"2001:db8:b::9"},
			IngressDenyV6: []string{"198.51.100.9"},
		},
	}
	v4, v6 := hostInboundUncoveredDropAddrs(views,
		[]string{"10.0.0.1", "2001:db8:e::1", "not-an-ip", "::ffff:10.0.0.2"},
		[]string{"2001:db8:e::1", "10.0.0.1", "2001:db8:ee::1"},
		nil)
	if len(v4) != 2 || v4[0] != "10.0.0.1" || v4[1] != "192.0.2.1" {
		t.Errorf("uncoveredV4 = %v, want [10.0.0.1 192.0.2.1] (family-filtered, sorted)", v4)
	}
	if len(v6) != 3 || v6[0] != "2001:db8:b::1" || v6[1] != "2001:db8:e::1" || v6[2] != "2001:db8:ee::1" {
		t.Errorf("uncoveredV6 = %v, want [2001:db8:b::1 2001:db8:e::1 2001:db8:ee::1] (family-filtered, sorted)", v6)
	}

	// The rendered gap payload must carry each address only under its own
	// family keyword (nil views isolate the uncovered-drop rendering).
	payload := buildHostInboundGapFencePayload(nil, v4, v6, nil, nil, nil, nil, nil, nil, nil, dhcpBackstopLists{}, nil, nil)
	if !strings.Contains(payload, "ip daddr { 10.0.0.1, 192.0.2.1 } drop") {
		t.Errorf("gap payload missing family-correct v4 drop:\n%s", payload)
	}
	if !strings.Contains(payload, "ip6 daddr { 2001:db8:b::1, 2001:db8:e::1, 2001:db8:ee::1 } drop") {
		t.Errorf("gap payload missing family-correct v6 drop:\n%s", payload)
	}
	for _, bad := range []string{"ip daddr 2001:", "ip6 daddr 192.", "ip6 daddr 198.", "ip daddr not-an-ip"} {
		if strings.Contains(payload, bad) {
			t.Errorf("gap payload contains wrong-family/malformed drop %q:\n%s", bad, payload)
		}
	}
}

// The two corrected #15931 gap fixtures: the v6 gap address must render
// only as `ip6 daddr`, never as `ip daddr`.
func TestNDGapFixtureFamilyCorrect15977(t *testing.T) {
	for name, tc := range map[string]struct {
		views []dpuserspace.ZoneHostInboundView
		addr  string
	}{
		"except": {
			views: ndCrossZoneViews15931(),
			addr:  "2001:db8:b::9",
		},
		"any-service": {
			views: []dpuserspace.ZoneHostInboundView{
				{Zone: "zonea", SystemServices: []string{"ssh"}, ProtocolsExcept: []string{"ndp"}, V6Addrs: []string{"2001:db8:a::1"}, IngressNetdevs: []string{"ge-a"}},
				{Zone: "zoneany", SystemServices: []string{"any-service"}, V6Addrs: []string{"2001:db8:17::1"}, IngressNetdevs: []string{"ge-any"}},
			},
			addr: "2001:db8:17::9",
		},
	} {
		gap := buildHostInboundGapFencePayload(tc.views, nil, []string{tc.addr}, nil, nil, nil, nil, nil, nil, nil, dhcpBackstopLists{}, nil, nil)
		if !strings.Contains(gap, "ip6 daddr "+tc.addr+" drop") {
			t.Errorf("%s: gap missing `ip6 daddr %s drop`:\n%s", name, tc.addr, gap)
		}
		if strings.Contains(gap, "ip daddr "+tc.addr) {
			t.Errorf("%s: gap renders v6 address under `ip daddr`:\n%s", name, gap)
		}
	}
}
