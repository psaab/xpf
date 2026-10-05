package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #11574: WireGuard admission is scoped to the unique outer-source owner
// ingress and local destination zone; selected-port mismatches are denied
// before broad service accepts.
func wgScopedViews11076() []dpuserspace.ZoneHostInboundView {
	return []dpuserspace.ZoneHostInboundView{
		{Zone: "trust", SystemServices: []string{"ssh"}, V4Addrs: []string{"10.0.1.1"}, V6Addrs: []string{"2001:db8:1::1"}, IngressNetdevs: []string{"trust0"}},
		{Zone: "untrust", SystemServices: []string{"ping"}, V4Addrs: []string{"10.0.2.1"}, IngressNetdevs: []string{"untrust0"}},
	}
}

func TestWireGuardAcceptIsZoneScoped11076(t *testing.T) {
	wgZones := map[string][]uint16{"trust": {51820}}
	payload := buildHostInboundFilterPayload(wgScopedViews11076(), []string{"10.0.99.1"}, []string{"2001:db8:99::1"}, nil, wgZones, true)

	// Trust's outer-source owner admits 51820 only on its ingress and addresses.
	for _, want := range []string{
		`iifname "trust0" ip daddr 10.0.1.1 udp dport 51820 accept`,
		`iifname "trust0" ip6 daddr 2001:db8:1::1 udp dport 51820 accept`,
	} {
		if !strings.Contains(payload, want) {
			t.Fatalf("missing scoped WG accept %q:\n%s", want, payload)
		}
	}
	// No bare accept exists, and the selected port to a non-serving zone is
	// explicitly denied rather than being exposed by another zone's rights.
	for _, line := range strings.Split(payload, "\n") {
		if strings.Contains(line, "udp dport") && strings.Contains(line, "51820") && !strings.Contains(line, "daddr") {
			t.Fatalf("global bare WG rule leaked: %s\n%s", line, payload)
		}
		if strings.Contains(line, "10.0.2.1") && strings.Contains(line, "51820") && strings.HasSuffix(line, " accept") {
			t.Fatalf("non-serving zone admits the WG port: %s\n%s", line, payload)
		}
	}
	// The admitted tuple precedes trust's catch-all drop, which precedes the
	// unzoned deny.
	accept := strings.Index(payload, `iifname "trust0" ip daddr 10.0.1.1 udp dport 51820 accept`)
	drop := strings.Index(payload, hiDrop("ip", "10.0.1.1", "trust"))
	unzoned := strings.Index(payload, "ip daddr 10.0.99.1 counter name")
	if accept < 0 || drop < 0 || unzoned < 0 {
		t.Fatalf("missing accept/drop/unzoned markers:\n%s", payload)
	}
	if !(accept < drop && drop < unzoned) {
		t.Fatalf("wrong order: accept=%d drop=%d unzoned=%d:\n%s", accept, drop, unzoned, payload)
	}
}

// Without a zone admit, selected WG ports are denied rather than accepted.
func TestWireGuardZoneUnservedPortsAreDenied11076(t *testing.T) {
	for name, wgZones := range map[string]map[string][]uint16{
		"nil-map":    nil,
		"empty-map":  {},
		"other-zone": {"elsewhere": {51820}},
	} {
		t.Run(name, func(t *testing.T) {
			payload := buildHostInboundFilterPayload(wgScopedViews11076(), nil, nil, nil, wgZones, true)
			if name != "other-zone" {
				if strings.Contains(payload, "51820") {
					t.Fatalf("%s: no configured WG port should emit no WG rules:\n%s", name, payload)
				}
				return
			}
			if !strings.Contains(payload, "ip daddr 10.0.1.1 udp dport 51820") ||
				strings.Contains(payload, "udp dport 51820 accept") {
				t.Fatalf("unserved selected WG port must be denied at local addresses, not admitted:\n%s", payload)
			}
		})
	}
}

// TestFenceWireGuardAdmitsStayZoneScoped11572 applies #11076's serving-zone
// contract to the two temporary enforcement tables: the cold-boot fence and
// the additive gap fence.
func TestFenceWireGuardAdmitsStayZoneScoped11572(t *testing.T) {
	views := wgScopedViews11076()
	wgZonePorts := map[string][]uint16{"trust": {51820}}
	unzonedV4 := []string{"10.0.99.1"}
	unzonedV6 := []string{"2001:db8:99::1"}
	uncoveredV4 := []string{"10.0.1.1", "10.0.2.1", "10.0.99.1"}
	uncoveredV6 := []string{"2001:db8:1::1", "2001:db8:99::1"}

	for name, payload := range map[string]string{
		"cold-boot": buildHostInboundFencePayload(views, unzonedV4, unzonedV6, []uint16{51820}, wgZonePorts, nil, nil, dhcpBackstopLists{}),
		"gap":       buildHostInboundGapFencePayload(views, uncoveredV4, uncoveredV6, []uint16{51820}, wgZonePorts, nil, nil, nil, nil, nil, dhcpBackstopLists{}, nil, nil),
	} {
		for _, want := range []string{
			"ip daddr 10.0.1.1 udp dport 51820 accept",
			"ip6 daddr 2001:db8:1::1 udp dport 51820 accept",
		} {
			if !strings.Contains(payload, want) {
				t.Errorf("%s fence lacks serving-zone WG accept %q:\n%s", name, want, payload)
			}
		}
		for _, deniedAddr := range []string{"10.0.2.1", unzonedV4[0], unzonedV6[0]} {
			for _, line := range strings.Split(payload, "\n") {
				if strings.Contains(line, deniedAddr) && strings.Contains(line, "udp dport 51820 accept") {
					t.Errorf("%s fence admits WG port 51820 to non-serving address %s: %s", name, deniedAddr, line)
				}
			}
		}
		for _, line := range strings.Split(payload, "\n") {
			if strings.Contains(line, "udp dport 51820 accept") && !strings.Contains(line, "daddr") {
				t.Errorf("%s fence emitted a global WG port accept: %s", name, line)
			}
		}
	}
}

func TestFenceWireGuardAdmissionUsesVRFMembers12034(t *testing.T) {
	views := []dpuserspace.ZoneHostInboundView{
		{
			Zone: "wan", V4Addrs: []string{"192.0.2.1"}, V6Addrs: []string{"2001:db8:1::1"},
			IngressVRFScopes: []config.HostInboundVRFIngressScope{{Master: "vrf-shared", Slaves: []string{"ge-wan"}}},
		},
		{
			Zone: "trust", V4Addrs: []string{"198.51.100.1"}, V6Addrs: []string{"2001:db8:2::1"},
			IngressVRFScopes: []config.HostInboundVRFIngressScope{{Master: "vrf-shared", Slaves: []string{"ge-trust"}}},
		},
	}
	wgZones := map[string][]uint16{"wan": {51820}}
	uncoveredV4 := []string{"192.0.2.1", "198.51.100.1"}
	uncoveredV6 := []string{"2001:db8:1::1", "2001:db8:2::1"}
	for name, payload := range map[string]string{
		"cold-boot": buildHostInboundFencePayload(views, nil, nil, []uint16{51820}, wgZones, nil, nil, dhcpBackstopLists{}),
		"gap":       buildHostInboundGapFencePayload(views, uncoveredV4, uncoveredV6, []uint16{51820}, wgZones, nil, nil, nil, nil, nil, dhcpBackstopLists{}, nil, nil),
	} {
		for _, want := range []string{
			`iifname "vrf-shared" meta sdifname "ge-wan" ip daddr 192.0.2.1 udp dport 51820 accept`,
			`iifname "vrf-shared" meta sdifname "ge-wan" ip6 daddr 2001:db8:1::1 udp dport 51820 accept`,
		} {
			if !strings.Contains(payload, want) {
				t.Errorf("%s fence lacks owner-member WG accept %q:\n%s", name, want, payload)
			}
		}
		for _, wrong := range []string{
			`iifname "vrf-shared" meta sdifname "ge-trust" ip daddr 192.0.2.1 udp dport 51820 accept`,
			`iifname "vrf-shared" meta sdifname "ge-trust" ip6 daddr 2001:db8:1::1 udp dport 51820 accept`,
		} {
			if strings.Contains(payload, wrong) {
				t.Errorf("%s fence admits sibling VRF member WG tuple %q:\n%s", name, wrong, payload)
			}
		}
	}
}

func TestWireGuardSharedVRFViewsMergeOwnerMembers12034(t *testing.T) {
	views := []dpuserspace.ZoneHostInboundView{
		{Zone: "wan", V4Addrs: []string{"192.0.2.1"}, IngressVRFScopes: []config.HostInboundVRFIngressScope{{Master: "vrf-shared", Slaves: []string{"ge-wan-1"}}}},
		{Zone: "wan", V4Addrs: []string{"192.0.2.2"}, IngressVRFScopes: []config.HostInboundVRFIngressScope{{Master: "vrf-shared", Slaves: []string{"ge-wan-2"}}}},
		{Zone: "trust", V4Addrs: []string{"198.51.100.1"}, IngressVRFScopes: []config.HostInboundVRFIngressScope{{Master: "vrf-shared", Slaves: []string{"ge-trust"}}}},
	}
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, map[string][]uint16{"wan": {51820}}, true)
	members := nftIifnameSet([]string{"ge-wan-1", "ge-wan-2"})
	addrs := nftAddrSet([]string{"192.0.2.1", "192.0.2.2"})
	wantAccept := `iifname "vrf-shared" meta sdifname ` + members + ` ip daddr ` + addrs + ` udp dport 51820 accept`
	wantMismatch := `iifname "vrf-shared" meta sdifname != ` + members + ` ip daddr ` + addrs + ` udp dport 51820`
	if !strings.Contains(payload, wantAccept) {
		t.Fatalf("owner-zone WG admit did not merge same-zone VRF members %q:\n%s", wantAccept, payload)
	}
	if !strings.Contains(payload, wantMismatch) {
		t.Fatalf("WG mismatch guard did not exclude sibling VRF members from merged owner scope %q:\n%s", wantMismatch, payload)
	}
}
