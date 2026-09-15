package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// host_inbound_all_scoping_3226_test.go is the KERNEL-MIRROR half of the #3226
// verdict guard (the AF_XDP/classifier half lives in
// pkg/dataplane/userspace/host_inbound_all_scoping_3226_test.go and the Rust
// `admits()` half in userspace-dp/src/afxdp/forwarding/host_inbound.rs).
//
// Before #3226 `system-services all` took the hostInboundAllowsAll branch in
// emitHostInboundZone: a bare `<fam> daddr <addrs> accept` and — because
// hostInboundEmitsDrop was false — NO catch-all drop and not even a declared
// deny counter. Every IP protocol and port reached the host stack. This asserts
// the nft payload now carries the Junos-scoped shape instead.

// allScopingTestConfig puts `system-services all` on a NON-lifeline zone with a
// static v4+v6 address, so the zone genuinely contributes host-inbound
// addresses (a lifeline-only zone emits no rules at all — which is why every
// shipped HA config's `control` zone is unaffected by #3226).
func allScopingTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.2.1/24", "2001:db8:2::1/64"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"edge": {
			Name:               "edge",
			Interfaces:         []string{"ge-0/0/1.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"all"}},
		},
	}
	return cfg
}

func allScopingPayload(t *testing.T, cfg *config.Config) string {
	t.Helper()
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	if len(views) == 0 {
		t.Fatalf("expected at least one host-inbound view — the zone must contribute addresses for this test to mean anything")
	}
	return buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)
}

// TestHostInboundNftSystemServicesAllIsScopedNotBlanket is the #3226
// RED-on-revert proof on the kernel path: a `system-services all` zone must
// render per-service accepts PLUS the catch-all drop, and must NOT render the
// blanket `<fam> daddr <addrs> accept`.
//
// FAIL-ON-REVERT: restore `all` to config.HostInboundFullAdmitService and
// hostInboundAllowsAll takes the blanket branch again — the drop assertions and
// the no-blanket-accept assertion all go RED.
func TestHostInboundNftSystemServicesAllIsScopedNotBlanket(t *testing.T) {
	payload := allScopingPayload(t, allScopingTestConfig())

	// The catch-all deny must exist for BOTH families — the pre-#3226 blanket
	// branch emitted none at all.
	for _, want := range []string{
		hiDrop("ip", "10.0.2.1", "edge"),
		hiDrop("ip6", "2001:db8:2::1", "edge"),
	} {
		if !strings.Contains(payload, want) {
			t.Errorf("payload missing catch-all host-inbound drop %q — `system-services all` must fall through to the per-match path with a default deny (#3226).\n%s", want, payload)
		}
	}

	// The named system-services must be accepted (positive control that `all`
	// genuinely EXPANDS rather than simply closing the zone).
	for _, want := range []string{
		"ip daddr 10.0.2.1 tcp dport 22 accept",           // ssh
		"ip daddr 10.0.2.1 tcp dport 443 accept",          // https
		"ip daddr 10.0.2.1 udp dport 161 accept",          // snmp
		"ip daddr 10.0.2.1 icmp type echo-request accept", // ping
		"ip6 daddr 2001:db8:2::1 tcp dport 22 accept",
		"ip6 daddr 2001:db8:2::1 icmpv6 type echo-request accept",
	} {
		if !strings.Contains(payload, want) {
			t.Errorf("payload missing %q — `system-services all` must expand to the named system-service union (#3226).\n%s", want, payload)
		}
	}

	// The blanket admit must be GONE. This is the exact rule the pre-#3226
	// hostInboundAllowsAll branch emitted.
	for _, blanket := range []string{
		"ip daddr 10.0.2.1 accept",
		"ip6 daddr 2001:db8:2::1 accept",
	} {
		for _, line := range strings.Split(payload, "\n") {
			if strings.TrimSpace(line) == blanket {
				t.Errorf("payload still emits the packet-wide blanket admit %q — `system-services all` must no longer be a full admit (#3226).\n%s", blanket, payload)
			}
		}
	}

	// No raw-IP-protocol admit may be synthesised by the expansion: Junos's
	// system-service list carries none, so `all` must not open ospf(89),
	// gre(47), vrrp(112) or pim(103).
	for _, forbidden := range []string{
		"meta l4proto 89", "meta l4proto 47", "meta l4proto 112", "meta l4proto 103",
	} {
		if strings.Contains(payload, forbidden) {
			t.Errorf("payload contains %q — `system-services all` must not admit a raw IP protocol (#3226).\n%s", forbidden, payload)
		}
	}
}

// TestHostInboundNftSystemServicesAllRendersIdentResetVerdict is the fail-OPEN
// guard on the expansion's VERDICT plumbing. `all` expands to a set containing
// `ident-reset`, whose Junos semantics are to RESET inbound ident (TCP/113), not
// to admit it (#3310). hostInboundMatchSet therefore has to take the verdict
// from the EXPANDED token, not the authored one — keying it on the authored
// token renders `tcp dport 113 accept` (hostInboundServiceAction("all") is a
// plain accept) and silently ADMITS ident probes that the per-token form resets.
//
// FAIL-ON-REVERT: drop the HostInboundServiceTokenExpansion walk from
// hostInboundMatchSet (and the netlink mirror) and the accept row below fires.
func TestHostInboundNftSystemServicesAllRendersIdentResetVerdict(t *testing.T) {
	payload := allScopingPayload(t, allScopingTestConfig())

	want := "ip daddr 10.0.2.1 tcp dport 113 " + hostInboundReject
	if !strings.Contains(payload, want) {
		t.Errorf("payload missing %q — `all` expands to include ident-reset, which RESETS TCP/113 (#3310/#3226).\n%s", want, payload)
	}
	if bad := "ip daddr 10.0.2.1 tcp dport 113 " + hostInboundAccept; strings.Contains(payload, bad) {
		t.Errorf("payload contains %q — the expanded ident-reset must RESET, never admit, TCP/113 (#3226 verdict plumbing).\n%s", bad, payload)
	}
}

// TestHostInboundNftAnyServiceStillBlanket is the over-reach guard: the
// `any-service` escape hatch keeps the pre-#3226 blanket shape (bare accept, no
// deny). If the narrowing were mistakenly applied to `any-service` too, this
// goes RED.
func TestHostInboundNftAnyServiceStillBlanket(t *testing.T) {
	cfg := allScopingTestConfig()
	cfg.Security.Zones["edge"].HostInboundTraffic.SystemServices = []string{"any-service"}
	payload := allScopingPayload(t, cfg)

	for _, want := range []string{"ip daddr 10.0.2.1 accept", "ip6 daddr 2001:db8:2::1 accept"} {
		found := false
		for _, line := range strings.Split(payload, "\n") {
			if strings.TrimSpace(line) == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("payload missing blanket admit %q — `any-service` remains the documented packet-wide escape hatch (#3226).\n%s", want, payload)
		}
	}
	if strings.Contains(payload, hiDrop("ip", "10.0.2.1", "edge")) {
		t.Errorf("payload emits a catch-all drop for an `any-service` zone — the operator opened everything.\n%s", payload)
	}
}
