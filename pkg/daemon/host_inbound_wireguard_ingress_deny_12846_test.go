package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #12846 (D3-12): WireGuard outer-source owner mapping must include the
// lifeline-shared addresses withheld into IngressDenyV4/V6 on empty-admit zones.
// These addresses are included in the global ingress-judgement list and the
// zone ingress policy drops them, but the WG source-owner mapper previously
// ignored IngressDeny and emitted no scoped accept.
//
// Views are hand-built here (not via BuildZoneHostInboundViews) so the test
// isolates the WG mapping/emission from the lifeline splitter: the view
// shape mirrors what zones_host_inbound.go produces for an empty-admit zone
// that shares an address with the lifeline (addr in IngressDeny*, not in
// V*Addrs).
func wgIngressDenyViews12846() []dpuserspace.ZoneHostInboundView {
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

// The owner lookup must resolve a WG source that lives only in IngressDenyV4
// (v4) and only in IngressDenyV6 (v6) to the owning zone. On unfixed code the
// source is unknown, so the port lands in the "" sentinel (fail-closed only)
// and no zone admit is emitted.
func TestWireGuardSourceInIngressDenyResolvesOwner12846(t *testing.T) {
	cfg := lifelineDenyAllConfig12229()
	cfg.Interfaces.Interfaces["wg0"] = &config.InterfaceConfig{
		Name:   "wg0",
		Tunnel: &config.TunnelConfig{Mode: "wireguard", Source: "192.0.2.1", WgListenPort: 51820},
	}
	cfg.Interfaces.Interfaces["wg1"] = &config.InterfaceConfig{
		Name:   "wg1",
		Tunnel: &config.TunnelConfig{Mode: "wireguard", Source: "2001:db8::1", WgListenPort: 51821},
	}

	views := wgIngressDenyViews12846()
	ports := hostInboundWireGuardZonePorts(cfg, views)
	if len(ports["untrust"]) != 2 || ports["untrust"][0] != 51820 || ports["untrust"][1] != 51821 {
		t.Fatalf("WG ports for IngressDeny-owned sources = %v, want untrust:[51820 51821]", ports)
	}
	if len(ports[""]) != 0 {
		t.Fatalf("known-owner sources must not fall into the fail-closed sentinel: %v", ports)
	}
	if len(ports["trust"]) != 0 {
		t.Fatalf("trust has no WG listener and must gain no WG ports: %v", ports)
	}
}

// The zone-address derivation must carry the IngressDeny addresses so the
// ingress-scoped accept (and its mismatch guard) names the actual outer
// destination. On unfixed code the shared addresses are absent entirely.
func TestWireGuardIngressDenyAddressesAccepted12846(t *testing.T) {
	views := wgIngressDenyViews12846()
	zonePorts := map[string][]uint16{"untrust": {51820, 51821}}
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, zonePorts, true)

	for _, want := range []string{
		`iifname "ge-0-0-0" ip daddr { 198.51.100.1, 192.0.2.1 } udp dport { 51820, 51821 } accept`,
		`iifname "ge-0-0-0" ip6 daddr { 2001:db8:a::1, 2001:db8::1 } udp dport { 51820, 51821 } accept`,
	} {
		if !strings.Contains(payload, want) {
			t.Fatalf("payload (%d bytes) missing scoped WG admission %q\n---\n%s", len(payload), want, payload)
		}
	}
	// Accept must precede the same zone's ingress catch-all drop for that
	// destination (the drop the issue reports killing the handshake).
	acceptAt := strings.Index(payload, `iifname "ge-0-0-0" ip daddr { 198.51.100.1, 192.0.2.1 } udp dport { 51820, 51821 } accept`)
	dropAt := -1
	for _, line := range strings.Split(payload, "\n") {
		if strings.Contains(line, `iifname "ge-0-0-0" ip daddr`) &&
			strings.Contains(line, "192.0.2.1") && strings.Contains(line, "counter name") &&
			strings.HasSuffix(line, "drop") {
			dropAt = strings.Index(payload, line)
			break
		}
	}
	if acceptAt < 0 || dropAt < 0 || acceptAt > dropAt {
		t.Fatalf("WG accept must precede the zone ingress drop (accept=%d drop=%d):\n%s", acceptAt, dropAt, payload)
	}
	// No bare (destination-less) WG accept may leak.
	for _, line := range strings.Split(payload, "\n") {
		if strings.Contains(line, "udp dport") && (strings.Contains(line, "51820") || strings.Contains(line, "51821")) &&
			strings.Contains(line, "accept") && !strings.Contains(line, "daddr") {
			t.Fatalf("bare WG accept leaked: %s\n---\n%s", line, payload)
		}
	}
}

// Fail-closed invariants that must survive the fix:
//   - a zone with an IngressDeny address but NO configured WG listener gains
//     no WG accept for it (no global port exception);
//   - the WG accept never appears on another zone's ingress;
//   - the shared address keeps its counted ingress drop for non-WG traffic.
func TestWireGuardIngressDenyStaysFailClosed12846(t *testing.T) {
	views := wgIngressDenyViews12846()

	// No WG configured anywhere.
	noWG := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)
	if strings.Contains(noWG, "udp dport 5182") {
		t.Fatalf("no-WG payload must contain no WG accept:\n%s", noWG)
	}

	// WG configured only for trust's (non-shared) address: untrust's shared
	// address must not be admitted, and trust's admit must not ride untrust
	// ingress.
	trustOnly := map[string][]uint16{"trust": {51820}}
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, trustOnly, true)
	if strings.Contains(payload, "192.0.2.1 udp dport 51820 accept") {
		t.Fatalf("non-WG zone's IngressDeny address must not gain a WG accept:\n%s", payload)
	}
	if strings.Contains(payload, `iifname "ge-0-0-0" ip daddr 192.0.2.1 udp dport`) &&
		strings.Contains(payload, "accept") {
		// scoped check below handles the precise line
	}
	for _, line := range strings.Split(payload, "\n") {
		if strings.Contains(line, `iifname "ge-0-0-0"`) && strings.Contains(line, "192.0.2.1") &&
			strings.Contains(line, "udp dport") && strings.Contains(line, "accept") {
			t.Fatalf("WG accept leaked onto untrust ingress for shared address: %s\n---\n%s", line, payload)
		}
	}
	// The counted ingress deny for the shared address remains (other daemons'
	// traffic / non-WG ports still judged by the empty-admit zone).
	if !strings.Contains(payload, "192.0.2.1") || !strings.Contains(payload, "drop") {
		t.Fatalf("shared address ingress deny must remain:\n%s", payload)
	}
}
