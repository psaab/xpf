package daemon

import (
	"strings"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #12959 (follow-up #12846): the cold-boot, lo0, and coverage-gap fence WG
// admits must reuse the steady-state WireGuard zone mapping, which since #12846
// includes the lifeline-shared addresses withheld into IngressDenyV4/V6. The
// fences kept a V4Addrs/V6Addrs-only copy of that mapping, so fence windows
// emitted no scoped accept naming a lifeline-shared WG endpoint and judged
// cross-zone ownership without the withheld claims.
//
// Views are hand-built (mirroring zones_host_inbound.go output for an
// empty-admit zone sharing an address with the lifeline: the shared value sits
// in IngressDeny*, not in V*Addrs) so the test isolates the fence emitters
// from the lifeline splitter.
func wgFenceIngressDenyViews12959() []dpuserspace.ZoneHostInboundView {
	return []dpuserspace.ZoneHostInboundView{
		{
			Zone:           "untrust",
			V4Addrs:        []string{"198.51.100.1"},
			V6Addrs:        []string{"2001:db8:a::1"},
			IngressDenyV4:  []string{"192.0.2.1"},
			IngressDenyV6:  []string{"2001:db8::1"},
			IngressNetdevs: []string{"ge-0-0-0"},
		},
		{
			Zone:           "trust",
			V4Addrs:        []string{"10.2.2.1"},
			SystemServices: []string{"ssh"},
			IngressNetdevs: []string{"ge-0-0-2"},
		},
	}
}

// The whole-table cold-boot fence and the lo0 cold-boot fence must carry the
// same zone-scoped WG accept as the steady-state chain for an IngressDeny-only
// endpoint: unique owner zone, its own ingress, configured ports. On unfixed
// code the withheld address is absent from the fence accept entirely.
func TestWireGuardIngressDenyFenceAdmits12959(t *testing.T) {
	views := wgFenceIngressDenyViews12959()
	zonePorts := map[string][]uint16{"untrust": {51820, 51821}}
	coldBoot := buildHostInboundFencePayload(views, nil, nil, nil, zonePorts, nil, nil, dhcpBackstopLists{})
	lo0 := buildLo0FencePayload(views, nil, nil, zonePorts)
	for name, payload := range map[string]string{"cold-boot": coldBoot, "lo0": lo0} {
		for _, want := range []string{
			`iifname "ge-0-0-0" ip daddr { 198.51.100.1, 192.0.2.1 } udp dport { 51820, 51821 } accept`,
			`iifname "ge-0-0-0" ip6 daddr { 2001:db8:a::1, 2001:db8::1 } udp dport { 51820, 51821 } accept`,
		} {
			if !strings.Contains(payload, want) {
				t.Fatalf("%s fence (%d bytes) missing scoped WG admission %q\n---\n%s", name, len(payload), want, payload)
			}
		}
		// Fail-closed: no WG accept may ride another zone's ingress and no
		// bare (destination-less) WG accept may leak.
		for _, line := range strings.Split(payload, "\n") {
			if strings.Contains(line, "udp dport") && strings.Contains(line, "accept") {
				if strings.Contains(line, `"ge-0-0-2"`) {
					t.Fatalf("%s fence leaked WG accept onto non-owner ingress: %s", name, line)
				}
				if !strings.Contains(line, "daddr") {
					t.Fatalf("%s fence leaked bare WG accept: %s", name, line)
				}
			}
		}
	}
}

// A zone with an IngressDeny address but no configured WG listener gains no
// fence accept for it (no global port exception), in either fence flavor.
func TestWireGuardIngressDenyFenceNoListenerStaysFailClosed12959(t *testing.T) {
	views := wgFenceIngressDenyViews12959()
	coldBoot := buildHostInboundFencePayload(views, nil, nil, nil, nil, nil, nil, dhcpBackstopLists{})
	lo0 := buildLo0FencePayload(views, nil, nil, nil)
	for name, payload := range map[string]string{"cold-boot": coldBoot, "lo0": lo0} {
		if strings.Contains(payload, "udp dport 5182") {
			t.Fatalf("%s fence without WG listeners must contain no WG accept:\n%s", name, payload)
		}
	}
}

// Gap-fence positive scope: when the uncovered set drops a lifeline-shared
// value that one zone claims through BOTH an empty-admit view (IngressDeny)
// and a admitting override view (V4Addrs) of the same zone, the gap fence must
// keep the zone-scoped WG accept ahead of the bare uncovered drop. The accept
// carries the zone's coalesced ingress across both views.
func TestWireGuardIngressDenyGapFenceSameZoneAdmit12959(t *testing.T) {
	views := []dpuserspace.ZoneHostInboundView{
		{
			Zone:           "edge",
			IngressDenyV4:  []string{"192.0.2.1"},
			IngressNetdevs: []string{"ge-0-0-0"},
		},
		{
			Zone:           "edge",
			SystemServices: []string{"ssh"},
			V4Addrs:        []string{"192.0.2.1"},
			IngressNetdevs: []string{"ge-0-0-1"},
		},
	}
	zonePorts := map[string][]uint16{"edge": {51820}}
	payload := buildHostInboundGapFencePayload(views, []string{"192.0.2.1"}, nil, nil, zonePorts, nil, nil, nil, nil, nil, dhcpBackstopLists{}, nil, nil)
	want := `iifname { "ge-0-0-0", "ge-0-0-1" } ip daddr 192.0.2.1 udp dport 51820 accept`
	acceptAt := strings.Index(payload, want)
	if acceptAt < 0 {
		t.Fatalf("gap fence missing same-zone WG admission %q\n---\n%s", want, payload)
	}
	dropAt := strings.Index(payload, "ip daddr 192.0.2.1 drop")
	if dropAt < 0 || acceptAt > dropAt {
		t.Fatalf("WG accept must precede the bare uncovered drop (accept=%d drop=%d):\n%s", acceptAt, dropAt, payload)
	}
}

// Gap-fence fail-close: a lifeline-shared value claimed by one zone via
// IngressDeny and by a DIFFERENT zone via V4Addrs is ambiguous in the
// steady-state mapping (#12846), so the gap fence must not grant either zone a
// WG accept; the bare uncovered drop stands. On unfixed code the fence's
// owner map ignored the IngressDeny claim and emitted a bogus unique-owner
// accept for the V4Addrs zone.
func TestWireGuardIngressDenyGapFenceAmbiguityStaysFailClosed12959(t *testing.T) {
	views := []dpuserspace.ZoneHostInboundView{
		{
			Zone:           "denyzone",
			IngressDenyV4:  []string{"192.0.2.1"},
			IngressNetdevs: []string{"ge-0-0-0"},
		},
		{
			Zone:           "admzone",
			SystemServices: []string{"ssh"},
			V4Addrs:        []string{"192.0.2.1"},
			IngressNetdevs: []string{"ge-0-0-1"},
		},
	}
	zonePorts := map[string][]uint16{"denyzone": {51820}, "admzone": {51820}}
	payload := buildHostInboundGapFencePayload(views, []string{"192.0.2.1"}, nil, nil, zonePorts, nil, nil, nil, nil, nil, dhcpBackstopLists{}, nil, nil)
	if strings.Contains(payload, "udp dport 51820 accept") {
		t.Fatalf("cross-zone-shared address claimed via IngressDeny must stay fail-closed in the gap fence:\n%s", payload)
	}
	if !strings.Contains(payload, "ip daddr 192.0.2.1 drop") {
		t.Fatalf("gap fence must keep the bare uncovered drop:\n%s", payload)
	}
}
