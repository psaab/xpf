package daemon

import (
	"strings"
	"testing"

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
