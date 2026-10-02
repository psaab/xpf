package daemon

import (
	"strings"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #11076: WireGuard admission is per-zone daddr-scoped, ordered with zone
// policy — never a global bare accept above it.
func wgScopedViews11076() []dpuserspace.ZoneHostInboundView {
	return []dpuserspace.ZoneHostInboundView{
		{Zone: "trust", SystemServices: []string{"ssh"}, V4Addrs: []string{"10.0.1.1"}, V6Addrs: []string{"2001:db8:1::1"}},
		{Zone: "untrust", SystemServices: []string{"ping"}, V4Addrs: []string{"10.0.2.1"}},
	}
}

func TestWireGuardAcceptIsZoneScoped11076(t *testing.T) {
	wgZones := map[string][]uint16{"trust": {51820}}
	payload := buildHostInboundFilterPayload(wgScopedViews11076(), []string{"10.0.99.1"}, []string{"2001:db8:99::1"}, nil, wgZones, true)

	// The trust section admits 51820 scoped to trust's addresses (v4+v6).
	for _, want := range []string{
		"ip daddr 10.0.1.1 udp dport 51820 accept",
		"ip6 daddr 2001:db8:1::1 udp dport 51820 accept",
	} {
		if !strings.Contains(payload, want) {
			t.Fatalf("missing scoped WG accept %q:\n%s", want, payload)
		}
	}
	// No bare (daddr-less) WG accept anywhere.
	for _, line := range strings.Split(payload, "\n") {
		if strings.Contains(line, "udp dport") && strings.Contains(line, "51820") && !strings.Contains(line, "daddr") {
			t.Fatalf("global bare WG accept leaked: %s\n%s", line, payload)
		}
		// The untrust section must not admit 51820 at all.
		if strings.Contains(line, "10.0.2.1") && strings.Contains(line, "51820") {
			t.Fatalf("non-serving zone admits the WG port: %s\n%s", line, payload)
		}
	}
	// Ordering: the scoped accept precedes trust's catch-all drop, which
	// precedes the unzoned deny.
	accept := strings.Index(payload, "udp dport 51820 accept")
	drop := strings.Index(payload, hiDrop("ip", "10.0.1.1", "trust"))
	// The unzoned DENY rule (not the guards' early address mentions).
	unzoned := strings.Index(payload, "ip daddr 10.0.99.1 counter name")
	if accept < 0 || drop < 0 || unzoned < 0 {
		t.Fatalf("missing accept/drop/unzoned markers:\n%s", payload)
	}
	if !(accept < drop && drop < unzoned) {
		t.Fatalf("wrong order: accept=%d drop=%d unzoned=%d:\n%s", accept, drop, unzoned, payload)
	}
}

// A zone whose WG ports map is empty (and the nil-map case) emits no accept.
func TestWireGuardAcceptAbsentWithoutZonePorts11076(t *testing.T) {
	for name, wgZones := range map[string]map[string][]uint16{
		"nil-map":    nil,
		"empty-map":  {},
		"other-zone": {"elsewhere": {51820}},
	} {
		payload := buildHostInboundFilterPayload(wgScopedViews11076(), nil, nil, nil, wgZones, true)
		if strings.Contains(payload, "51820") {
			t.Fatalf("%s: no zone serves WG yet 51820 is admitted:\n%s", name, payload)
		}
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
		"cold-boot": buildHostInboundFencePayload(views, unzonedV4, unzonedV6, []uint16{51820}, wgZonePorts, nil, nil),
		"gap":       buildHostInboundGapFencePayload(views, uncoveredV4, uncoveredV6, []uint16{51820}, wgZonePorts, nil, nil, nil, nil, nil),
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
