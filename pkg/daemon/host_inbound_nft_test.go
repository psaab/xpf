package daemon

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// hiDrop builds the canonical host-inbound catch-all DROP rule line for a
// zone/family — the named-counter form (#3361). The drop now carries
// `counter name "<n>"` so the kernel host-inbound denies are scrapeable; removing
// the counter attachment (reverting #3361) makes every assertion built from this
// helper RED.
func hiDrop(family, addrs, zone string) string {
	return family + " daddr " + addrs + " counter name \"" +
		xnft.HostInboundDenyCounterName(zone, family) + "\" drop"
}

// hostInboundTestConfig builds a config exercising the #3070 kernel-nftables
// host-inbound enforcement path end to end (config -> BuildZoneHostInboundViews
// -> buildHostInboundFilterPayload):
//   - wan: host-inbound { ssh; ping; } on reth0.50 (v4+v6 static addrs) — the
//     enforced zone.
//   - lan: NO host-inbound stanza on reth1.0 — must produce NO deny.
//   - control: host-inbound { all; } on em0 — em0 is a cluster-control lifeline,
//     its address must never be denied (and `all` would open it anyway).
//   - mgmt: host-inbound { ssh; } on fxp0 — fxp0 is the management lifeline
//     (DHCP, no static addr); must never be denied.
func hostInboundTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			50: {Number: 50, VlanID: 50, Addresses: []string{"172.16.50.8/24", "2001:db8:50::8/64"}},
		}},
		"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.61.1/24"}},
		}},
		"em0": {Name: "em0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.99.0.1/24"}},
		}},
		"fxp0": {Name: "fxp0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {
			Name:               "wan",
			Interfaces:         []string{"reth0.50"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh", "ping"}},
		},
		"lan": {
			Name:       "lan",
			Interfaces: []string{"reth1.0"},
			// no HostInboundTraffic stanza
		},
		"control": {
			Name:               "control",
			Interfaces:         []string{"em0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"all"}},
		},
		"mgmt": {
			Name:               "mgmt",
			Interfaces:         []string{"fxp0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}
	return cfg
}

// TestHostInboundFilterAcceptsListedDeniesRest is the #3070 fail-on-revert
// proof: for a host-inbound-configured zone the generated `chain input`
// ACCEPTS each listed service to the zone's addresses and DROPs everything
// else to those addresses. Reverting the host-inbound nft emission (so no
// accept/drop are produced) turns this RED.
func TestHostInboundFilterAcceptsListedDeniesRest(t *testing.T) {
	cfg := hostInboundTestConfig()
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil)

	mustContain := []string{
		"table inet xpf_hostinbound",
		"ct state established,related accept",
		// wan allows ssh -> accept tcp/22 to the reth IP, both families gated.
		"ip daddr 172.16.50.8 tcp dport 22 accept",
		// wan allows ping -> accept icmp/icmpv6 echo-request.
		"ip daddr 172.16.50.8 icmp type echo-request accept",
		"ip6 daddr 2001:db8:50::8 icmpv6 type echo-request accept",
		// catch-all deny for the rest, per family — now carrying a named counter.
		hiDrop("ip", "172.16.50.8", "wan"),
		hiDrop("ip6", "2001:db8:50::8", "wan"),
		// the named counter objects must be declared (UNQUOTED, #3578) in the
		// table body.
		"counter " + xnft.HostInboundDenyCounterName("wan", "ip") + " {",
		"counter " + xnft.HostInboundDenyCounterName("wan", "ip6") + " {",
	}
	for _, want := range mustContain {
		if !strings.Contains(payload, want) {
			t.Errorf("payload missing %q\n---\n%s", want, payload)
		}
	}

	// An unlisted service (telnet tcp/23) must NOT be accepted — it falls to the
	// catch-all drop.
	if strings.Contains(payload, "tcp dport 23") {
		t.Errorf("payload unexpectedly accepts telnet (tcp/23):\n%s", payload)
	}

	// Ordering: each accept for the wan v4 addr must precede that addr's drop.
	if idxDrop := strings.Index(payload, hiDrop("ip", "172.16.50.8", "wan")); idxDrop >= 0 {
		if idxAccept := strings.Index(payload, "ip daddr 172.16.50.8 tcp dport 22 accept"); idxAccept < 0 || idxAccept > idxDrop {
			t.Errorf("wan v4 ssh accept must precede the v4 catch-all drop:\n%s", payload)
		}
	}
}

// TestHostInboundFilterDropRulesCounted is the #3361 fail-on-revert proof: each
// per-zone/family catch-all host-inbound DROP rule carries a NAMED nft counter,
// and that counter object is DECLARED in the table body. The kernel
// `inet xpf_hostinbound` chain is the PRIMARY host-inbound enforcement path
// (host-bound traffic is shunted to the kernel before userspace-dp sees it), so
// without these counters operator-configured host-inbound denies are invisible
// (host_inbound_denies = 0 forever — a forensics/alerting blind spot distinct
// from the #3326 userspace path). Dropping the `counter name "..."` from the drop
// rule, or the `counter "..." { }` declaration, turns this RED.
func TestHostInboundFilterDropRulesCounted(t *testing.T) {
	cfg := hostInboundTestConfig()
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil)

	for _, fam := range []struct{ family, addr string }{
		{"ip", "172.16.50.8"},
		{"ip6", "2001:db8:50::8"},
	} {
		cn := xnft.HostInboundDenyCounterName("wan", fam.family)

		// The named counter object must be DECLARED (UNQUOTED, #3578) in the
		// table body.
		decl := "counter " + cn + " {"
		if !strings.Contains(payload, decl) {
			t.Errorf("missing named counter declaration %q\n---\n%s", decl, payload)
		}
		// The declaration must appear BEFORE the chain references it (nft rejects
		// a reference to an undeclared counter on an atomic load).
		idxDecl := strings.Index(payload, decl)
		idxChain := strings.Index(payload, "chain input {")
		if idxDecl < 0 || idxChain < 0 || idxDecl > idxChain {
			t.Errorf("counter %q must be declared before `chain input`:\n%s", cn, payload)
		}
		// The catch-all DROP must reference that named counter.
		wantDrop := hiDrop(fam.family, fam.addr, "wan")
		if !strings.Contains(payload, wantDrop) {
			t.Errorf("catch-all drop missing named counter, want %q\n---\n%s", wantDrop, payload)
		}
	}

	// A fully-open zone (`system-services all`, no drop) must NOT declare a deny
	// counter — only zones that emit a drop get one. control/em0 is a lifeline so
	// it never scopes. #3405: lan declared NO stanza but is now default-deny, so
	// it DOES emit a catch-all drop scoped to its address (10.0.61.1) and thus a
	// deny counter. Fail-on-revert: restore the no-stanza=admit-all posture and
	// this counter disappears (lan reverts to a permit-all exposure).
	if !strings.Contains(payload, xnft.HostInboundDenyCounterName("lan", "ip")) {
		t.Errorf("lan (no stanza, #3405 default-deny) must get a deny counter:\n%s", payload)
	}

	// The atomic replace idiom must delete the table before recreating it, so the
	// per-commit redeclaration of the named counters cannot collide (flush would
	// leave the objects behind). Reverting to a plain `flush table` turns this RED.
	if !strings.Contains(payload, "delete table inet xpf_hostinbound") {
		t.Errorf("payload must delete+recreate the table (not flush) so counter "+
			"objects do not collide on the next commit:\n%s", payload)
	}
}

// TestHostInboundFilterExemptsIPsecAndV6Errors verifies the global exemptions
// that must agree with the userspace stage_ipsec_passthrough_check: raw ESP/AH
// (proto 50/51) and v6 ND/error/PMTUD control are accepted BEFORE any per-zone
// drop, so an IPsec-terminating zone configured `host-inbound { ike; }` keeps
// its tunnel data plane and v6 error delivery is never gapped. The ESP/AH
// accept is fail-on-revert: removing it turns this RED.
func TestHostInboundFilterExemptsIPsecAndV6Errors(t *testing.T) {
	cfg := hostInboundTestConfig()
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil)

	espAH := "meta l4proto { 50, 51 } accept"
	if !strings.Contains(payload, espAH) {
		t.Errorf("payload missing raw ESP/AH exemption %q\n---\n%s", espAH, payload)
	}
	// #4759: the single ICMPv6 accept was SPLIT into error (1-4) and ND (133-137)
	// so each type-class counts separately, and each accept now carries a named
	// nft counter. The split is verdict-preserving — the union {1,2,3,4} ∪
	// {133,134,135,136,137} is the exact pre-#4759 accepted set, and `counter name
	// "<n>" accept` counts then accepts (identical terminal verdict to a bare
	// accept). Assert BOTH split rules carry their counter AND still end in
	// `accept` (fail-on-revert: dropping a class, dropping the counter, or
	// changing the verdict turns this RED).
	if !strings.Contains(payload, "icmpv6 type { 1, 2, 3, 4 } counter name \"xpfhia_icmp6_error\" accept") {
		t.Errorf("payload missing icmpv6 error/PMTUD (1-4) counted accept:\n%s", payload)
	}
	if !strings.Contains(payload, "icmpv6 type { 133, 134, 135, 136, 137 } counter name \"xpfhia_icmp6_nd\" accept") {
		t.Errorf("payload missing icmpv6 ND (133-137) counted accept:\n%s", payload)
	}
	// #3171: the ICMPv4 error/PMTUD set must agree with the userspace
	// host-inbound exemption (is_icmp_host_inbound_error) so the kernel chain and
	// the XSK LocalDelivery classifier admit the same ICMP errors on a ping-less
	// zone. Fail-on-revert: narrowing this back to bare destination-unreachable
	// (or dropping the counter / changing the verdict) turns this RED.
	if !strings.Contains(payload, "icmp type { destination-unreachable, time-exceeded, parameter-problem } counter name \"xpfhia_icmp4_error\" accept") {
		t.Errorf("payload missing icmpv4 error/PMTUD (dest-unreachable/time-exceeded/parameter-problem) counted accept:\n%s", payload)
	}
	// #4759: every accept counter object referenced above must also be DECLARED in
	// the table body (nft rejects a reference to an undeclared counter). The three
	// declarations are UNCONDITIONAL (the accept rules are always present).
	for _, decl := range []string{
		"counter xpfhia_icmp6_nd {",
		"counter xpfhia_icmp6_error {",
		"counter xpfhia_icmp4_error {",
	} {
		if !strings.Contains(payload, decl) {
			t.Errorf("payload missing accept-counter declaration %q:\n%s", decl, payload)
		}
	}

	// The ESP/AH exemption MUST precede every per-zone scoped drop, otherwise a
	// zone's `daddr <wan-ip> drop` would catch outer ESP before XFRM decrypts.
	idxESP := strings.Index(payload, espAH)
	if idxESP < 0 {
		t.Fatalf("ESP/AH accept not found")
	}
	for _, drop := range []string{
		hiDrop("ip", "172.16.50.8", "wan"),
		hiDrop("ip6", "2001:db8:50::8", "wan"),
	} {
		if idxDrop := strings.Index(payload, drop); idxDrop >= 0 && idxESP > idxDrop {
			t.Errorf("ESP/AH exemption must precede the per-zone drop %q", drop)
		}
	}
}

// TestHostInboundFilterNoStanzaDefaultDeny verifies #3405 (Junos/vSRX
// default-deny parity): a zone with NO host-inbound-traffic stanza (lan) is now
// enforced exactly like an empty stanza — its firewall-local address gets a
// catch-all DROP and NO service/protocol accept. Before #3405 a no-stanza zone
// emitted no deny (admit-all), a permit-all management-plane exposure.
// Fail-on-revert: restore the stanza-required `configured` predicate and lan's
// address vanishes from the payload (no drop), turning the assertions RED.
func TestHostInboundFilterNoStanzaDefaultDeny(t *testing.T) {
	cfg := hostInboundTestConfig()
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil)

	// lan's reth1 address must now be scoped by a catch-all drop.
	wantDrop := hiDrop("ip", "10.0.61.1", "lan")
	if !strings.Contains(payload, wantDrop) {
		t.Errorf("lan (no stanza, #3405) must emit a default-deny catch-all drop %q:\n%s", wantDrop, payload)
	}
	// And lan must NOT accept any service: the operator opened nothing.
	//
	// #9637 narrowed what "lan" means here. Before it, every rule was
	// destination-only, so "no accept names lan's address" was the whole
	// property. Since #9637 another zone's ingress-zone rules name every judged
	// address, lan's included, because a packet arriving on THAT zone is judged
	// by that zone (wan admits ssh, so wan-ingress ssh to 10.0.61.1 is
	// accepted). The #3405 decision is about traffic arriving on lan's own
	// interfaces, and it still holds: neither lan's ingress-zone rules nor its
	// destination-only rules may accept anything.
	lanIngress := ""
	for _, v := range views {
		if v.Zone == "lan" && len(v.IngressNetdevs) > 0 {
			lanIngress = "iifname " + nftIifnameSet(v.IngressNetdevs) + " "
		}
	}
	if lanIngress == "" {
		t.Fatal("lan's view must carry its ingress netdevs (#9637); without them this cell cannot see lan's ingress-zone rules")
	}
	sawLanIngressDrop := false
	for _, line := range strings.Split(payload, "\n") {
		s := strings.TrimSpace(line)
		if strings.HasPrefix(s, "iifname ") && !strings.HasPrefix(s, lanIngress) {
			continue // another zone's ingress judges its own arrivals
		}
		if strings.HasPrefix(s, lanIngress) && strings.HasSuffix(s, " drop") {
			sawLanIngressDrop = true
		}
		if strings.Contains(s, "10.0.61.1") && strings.Contains(s, "accept") {
			t.Errorf("lan (no stanza) must not accept any service, got: %q", line)
		}
	}
	if !sawLanIngressDrop {
		t.Errorf("lan (no stanza) must default-deny what arrives on its own netdevs (#9637 ingress-zone drop):\n%s", payload)
	}
}

// TestHostInboundFilterLifelineNeverDenied verifies the management (fxp0) and
// cluster-control (em0) lifeline interfaces never get a host-inbound deny, even
// when their zone declares a host-inbound stanza.
func TestHostInboundFilterLifelineNeverDenied(t *testing.T) {
	cfg := hostInboundTestConfig()
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil)

	// em0's address (cluster control plane) must never be denied/scoped, even
	// though the control zone declares a host-inbound stanza.
	if strings.Contains(payload, "10.99.0.1") {
		t.Errorf("control/em0 lifeline address must never appear in host-inbound payload:\n%s", payload)
	}
	// fxp0 (management) has no static address and is a lifeline — it must not
	// be scoped either (there is no address to scope, and it is excluded).
	if strings.Contains(payload, "fxp0") {
		t.Errorf("management fxp0 must never appear in host-inbound payload:\n%s", payload)
	}
}

// TestHostInboundFilterAllOpensZoneNoDeny verifies `system-services { all }`
// fully opens a zone (accept all to its addresses, no deny). Uses a config
// whose `all` zone is NOT a lifeline so it actually emits a rule.
func TestHostInboundFilterAnyServiceOpensZoneNoDeny(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.1.1.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {
			Name:               "trust",
			Interfaces:         []string{"reth0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"any-service"}},
		},
	}
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil)
	if !strings.Contains(payload, "ip daddr 10.1.1.1 accept") {
		t.Errorf("`any-service` zone must accept everything to its addr:\n%s", payload)
	}
	if strings.Contains(payload, "ip daddr 10.1.1.1 drop") {
		t.Errorf("`any-service` zone must NOT emit a deny:\n%s", payload)
	}
}

// TestHostInboundFilterProtocolsAllScopedToRouting is the #3199 fail-on-revert
// proof for the kernel nft mirror: `host-inbound-traffic protocols all` admits
// the routing-protocol set (ospf/bgp/vrrp/...) but DOES NOT open
// system-services (SSH/HTTPS/SNMP), and still emits a catch-all drop for the
// rest. Restoring the old behaviour — hostInboundAllowsAll returning true for
// `protocols all` (a bare `<fam> daddr <addrs> accept` with no deny) — turns
// the "does not accept ssh" / "emits a drop" assertions RED.
func TestHostInboundFilterProtocolsAllScopedToRouting(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.2.2.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"routing": {
			Name:               "routing",
			Interfaces:         []string{"reth0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{Protocols: []string{"all"}},
		},
	}
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil)

	// Routing protocols must be accepted: ospf (proto 89), bgp (tcp/179),
	// vrrp (proto 112).
	mustAccept := []string{
		"ip daddr 10.2.2.1 meta l4proto 89 accept",
		"ip daddr 10.2.2.1 tcp dport 179 accept",
		"ip daddr 10.2.2.1 meta l4proto 112 accept",
	}
	for _, want := range mustAccept {
		if !strings.Contains(payload, want) {
			t.Errorf("protocols all must accept routing %q\n---\n%s", want, payload)
		}
	}

	// System-services must NOT be opened: no bare accept, no ssh/https accept.
	if strings.Contains(payload, "ip daddr 10.2.2.1 accept") {
		t.Errorf("protocols all must NOT emit a bare full-accept (opens all services):\n%s", payload)
	}
	if strings.Contains(payload, "tcp dport 22") {
		t.Errorf("protocols all must NOT accept ssh (tcp/22):\n%s", payload)
	}
	if strings.Contains(payload, "tcp dport 443") {
		t.Errorf("protocols all must NOT accept https (tcp/443):\n%s", payload)
	}
	if strings.Contains(payload, "udp dport 161") {
		t.Errorf("protocols all must NOT accept snmp (udp/161):\n%s", payload)
	}

	// A catch-all drop for everything else must be present (default-deny to
	// the host for non-routing traffic).
	if !strings.Contains(payload, hiDrop("ip", "10.2.2.1", "routing")) {
		t.Errorf("protocols all must still emit the v4 catch-all drop:\n%s", payload)
	}
}

// TestHostInboundFilterExplicitSshStillAdmitted is the #3199 regression guard:
// an explicit `system-services ssh` zone still accepts ssh (the protocols-all
// scoping change must not affect explicit service lists).
func TestHostInboundFilterExplicitSshStillAdmitted(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.3.3.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"mgmt": {
			Name:               "mgmt",
			Interfaces:         []string{"reth0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil)

	if !strings.Contains(payload, "ip daddr 10.3.3.1 tcp dport 22 accept") {
		t.Errorf("system-services ssh must accept tcp/22:\n%s", payload)
	}
	if !strings.Contains(payload, hiDrop("ip", "10.3.3.1", "mgmt")) {
		t.Errorf("system-services ssh zone must emit a catch-all drop:\n%s", payload)
	}
}

// TestHostInboundFilterFamilyAware is the #3225 fail-on-revert proof for the
// kernel nft mirror: family-specific host-inbound tokens must emit ONLY under
// their own family. A v4-only service/protocol (dhcp udp/67-68, rip udp/520,
// ospf proto 89) appears under `ip daddr <v4>` but NEVER under `ip6 daddr <v6>`;
// a v6-only one (dhcpv6 udp/546-547, ripng udp/521, ospf3 proto 89) appears
// under `ip6` but NEVER under `ip`. Dual-family services (ssh) appear under
// both. Removing the family gate in hostInboundServiceMatches /
// hostInboundProtocolMatches (so a token emits under both families) turns the
// "wrong family must NOT appear" assertions RED.
func TestHostInboundFilterFamilyAware(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.5.5.1/24", "2001:db8:5::1/64"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"edge": {
			Name:       "edge",
			Interfaces: []string{"reth0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{
				SystemServices: []string{"dhcp", "dhcpv6", "ssh"},
				Protocols:      []string{"rip", "ripng", "ospf", "ospf3"},
			},
		},
	}
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil)

	// v4-only tokens accepted under ip, dual-family ssh under both.
	mustContain := []string{
		"ip daddr 10.5.5.1 udp dport { 67, 68 } accept",         // dhcp (v4)
		"ip daddr 10.5.5.1 udp dport 520 accept",                // rip (v4)
		"ip daddr 10.5.5.1 meta l4proto 89 accept",              // ospf (v4, OSPFv2)
		"ip6 daddr 2001:db8:5::1 udp dport { 546, 547 } accept", // dhcpv6 (v6)
		"ip6 daddr 2001:db8:5::1 udp dport 521 accept",          // ripng (v6)
		"ip6 daddr 2001:db8:5::1 meta l4proto 89 accept",        // ospf3 (v6, OSPFv3)
		"ip daddr 10.5.5.1 tcp dport 22 accept",                 // ssh (dual)
		"ip6 daddr 2001:db8:5::1 tcp dport 22 accept",           // ssh (dual)
	}
	for _, want := range mustContain {
		if !strings.Contains(payload, want) {
			t.Errorf("payload missing %q\n---\n%s", want, payload)
		}
	}

	// WRONG-FAMILY emissions must be ABSENT: v4-only tokens must not appear
	// under ip6, and v6-only tokens must not appear under ip.
	mustNotContain := []string{
		"ip6 daddr 2001:db8:5::1 udp dport { 67, 68 } accept", // dhcp on v6
		"ip6 daddr 2001:db8:5::1 udp dport 520 accept",        // rip on v6
		"ip daddr 10.5.5.1 udp dport { 546, 547 } accept",     // dhcpv6 on v4
		"ip daddr 10.5.5.1 udp dport 521 accept",              // ripng on v4
	}
	for _, bad := range mustNotContain {
		if strings.Contains(payload, bad) {
			t.Errorf("payload emits wrong-family match %q (family-blind admit)\n---\n%s", bad, payload)
		}
	}
}

// TestHostInboundFilterConfiguredControlInterfaceLifeline is the #3277
// fail-on-revert proof through the full payload path: a chassis cluster whose
// `control-interface` is the operator-renamed fxp1 (NOT the default em0) must
// have fxp1's address excluded from host-inbound deny scoping, exactly like the
// default em0. Reverting the lifeline set to the hardcoded fxp0/em0/fab* list
// leaves fxp1 SUBJECT to deny scoping -> its address appears in the payload ->
// this goes RED (the latent HA split-brain the issue describes).
func TestHostInboundFilterConfiguredControlInterfaceLifeline(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{ControlInterface: "fxp1"}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"172.16.50.8/24"}},
		}},
		// Control link rides the non-default-named fxp1 with a static address.
		"fxp1": {Name: "fxp1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.99.0.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		// An enforced zone so the table is actually emitted.
		"wan": {
			Name:               "wan",
			Interfaces:         []string{"reth0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
		// The control zone scopes `all` but, more importantly, fxp1 must never be
		// subjected to a deny regardless of its zone's stanza.
		"control": {
			Name:               "control",
			Interfaces:         []string{"fxp1.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil)

	// fxp1's control-link address must NEVER appear (accept or drop): it is the
	// configured cluster control-interface and so a lifeline (#3277).
	if strings.Contains(payload, "10.99.0.1") {
		t.Errorf("configured control-interface fxp1 address must never appear in host-inbound payload:\n%s", payload)
	}
	// Sanity: the enforced wan zone still scopes its own address.
	if !strings.Contains(payload, hiDrop("ip", "172.16.50.8", "wan")) {
		t.Errorf("wan zone must still emit a scoped deny:\n%s", payload)
	}
}

// TestHostInboundFilterApplyFailureSurfaced is the #3333 fail-on-revert proof
// for the APPLY path: when the netlink install fails, applyHostInboundFilter must
// return the error (so applyConfigLocked fails the commit closed) rather than
// swallow it at WARN. With the pre-fix warn-only code the function returned
// nothing and this goes RED. #6387 PR-3: the install goes through the netlink
// nftInstaller seam, stubbed here to inject a failure without a real kernel.
func TestHostInboundFilterApplyFailureSurfaced(t *testing.T) {
	cfg := hostInboundTestConfig()

	injected := errors.New("nftables: rule load failed")
	var called bool
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(spec xnft.HostInboundSpec) error {
			called = true
			// Sanity: an enforceable view exists, so the spec carries the enforced
			// zone addresses — a failure here is a real deny-not-installed event.
			if len(spec.Views) == 0 {
				t.Errorf("host-inbound install seam got a spec with no zone views: %+v", spec)
			}
			return injected
		},
	}
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	err := d.applyHostInboundFilter(cfg)
	if !called {
		t.Fatal("expected the netlink install seam to be invoked for an enforceable config")
	}
	if err == nil {
		t.Fatal("apply failure must be surfaced as an error (fail-closed), got nil")
	}
	if !errors.Is(err, injected) {
		t.Errorf("returned error must wrap the netlink failure, got %v", err)
	}
}

// TestHostInboundFilterDeleteFailureSurfaced is the #3333 fail-on-revert proof
// for the TEARDOWN path: when no zone is enforceable, the stale table is removed
// via the idempotent add-then-delete payload; a genuine teardown failure (stale
// deny left in the kernel) must surface as an error. The add+delete is
// idempotent for the benign absent-table case, so any error from the seam is a
// real failure. Pre-fix the delete error was discarded entirely (`_, _ =`), so
// this goes RED.
func TestHostInboundFilterDeleteFailureSurfaced(t *testing.T) {
	// A config with no enforceable host-inbound view drives the teardown branch.
	// #3405 makes every zone host-inbound-enforcing (default-deny), so "no
	// enforceable view" now means a zone with no firewall-local ADDRESS to scope
	// a deny (rather than the pre-#3405 "no stanza"): the interface carries no
	// address, so BuildZoneHostInboundViews yields an empty (address-less) view.
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"reth0.0"}},
	}
	if hostInboundHasEnforceableView(dpuserspace.BuildZoneHostInboundViews(cfg)) {
		t.Fatal("test config must have no enforceable host-inbound view")
	}

	injected := errors.New("nftables: device or resource busy")
	var gotName string
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		del: func(name string) error {
			gotName = name
			return injected
		},
	}
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	err := d.applyHostInboundFilter(cfg)
	if gotName != xnft.HostInboundTableName {
		t.Errorf("teardown must target inet xpf_hostinbound, got %s", gotName)
	}
	if err == nil {
		t.Fatal("teardown failure must be surfaced as an error (fail-closed), got nil")
	}
	if !errors.Is(err, injected) {
		t.Errorf("returned error must wrap the netlink teardown failure, got %v", err)
	}
}

// TestNftDeleteTableIdempotentAddDelete pins the #3333 MAJOR-2 teardown shape:
// the default nftDeleteTable must NOT depend on the recent `nft destroy` verb
// (the project pins no minimum nftables version), and must instead emit an
// idempotent add-then-delete payload through the atomic nftApplyPayload runner.
// Reverting to `nft destroy` (or dropping the `add`) turns this RED.
func TestNftDeleteTableIdempotentAddDelete(t *testing.T) {
	var got string
	orig := nftApplyPayload
	nftApplyPayload = func(payload string) ([]byte, error) { got = payload; return nil, nil }
	defer func() { nftApplyPayload = orig }()

	if _, err := nftDeleteTable("inet", "xpf_hostinbound"); err != nil {
		t.Fatalf("nftDeleteTable: %v", err)
	}
	if strings.Contains(got, "destroy") {
		t.Errorf("teardown must not use the unpinned `nft destroy` verb:\n%s", got)
	}
	for _, want := range []string{
		"add table inet xpf_hostinbound",
		"delete table inet xpf_hostinbound",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("teardown payload missing %q:\n%s", want, got)
		}
	}
	// `add` must precede `delete` so the delete always has a target.
	if strings.Index(got, "add table") > strings.Index(got, "delete table") {
		t.Errorf("add must precede delete in the teardown payload:\n%s", got)
	}
}

// TestHostInboundFilterApplySuccessNoError verifies the happy paths return nil:
// a successful apply (enforceable view) and a successful/benign teardown (no
// enforceable view) must NOT report a commit failure.
func TestHostInboundFilterApplySuccessNoError(t *testing.T) {
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{} // every op succeeds
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
		t.Errorf("successful apply must return nil, got %v", err)
	}

	empty := &config.Config{}
	if err := d.applyHostInboundFilter(empty); err != nil {
		t.Errorf("benign teardown (no enforceable view) must return nil, got %v", err)
	}
}

// identResetTestConfig builds a config whose wan zone declares
// `system-services { ssh; ping; ident-reset; }` on reth0.50 (v4+v6 static
// addresses). reth0.50 is a dataplane interface (not a lifeline), so its
// addresses are scoped by host-inbound enforcement.
func identResetTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			50: {Number: 50, VlanID: 50, Addresses: []string{"172.16.50.8/24", "2001:db8:50::8/64"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {
			Name:               "wan",
			Interfaces:         []string{"reth0.50"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh", "ping", "ident-reset"}},
		},
	}
	return cfg
}

// TestHostInboundFilterIdentResetEmitsReset is the #3310 fail-on-revert proof:
// `system-services ident-reset` must emit a `tcp dport 113 reject with tcp
// reset` rule (both families), NOT an `accept` for TCP/113. On Junos ident-reset
// actively RESETS inbound ident (auth/113) probes; it must never open 113 to the
// host stack. Reverting hostInboundServiceAction("ident-reset") to a plain admit
// (or the matcher to insert 113 into the accept loop) re-opens 113 and turns
// this RED.
func TestHostInboundFilterIdentResetEmitsReset(t *testing.T) {
	cfg := identResetTestConfig()
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil)

	// The ident-reset rule must be a reject-with-tcp-reset on TCP/113, per family.
	mustContain := []string{
		"ip daddr 172.16.50.8 tcp dport 113 reject with tcp reset",
		"ip6 daddr 2001:db8:50::8 tcp dport 113 reject with tcp reset",
		// Control: the other declared services on the SAME zone still admit
		// normally (no over-removal). ssh -> tcp/22, ping -> echo-request.
		"ip daddr 172.16.50.8 tcp dport 22 accept",
		"ip daddr 172.16.50.8 icmp type echo-request accept",
		"ip6 daddr 2001:db8:50::8 tcp dport 22 accept",
		// catch-all deny for the rest must still be present.
		hiDrop("ip", "172.16.50.8", "wan"),
		hiDrop("ip6", "2001:db8:50::8", "wan"),
	}
	for _, want := range mustContain {
		if !strings.Contains(payload, want) {
			t.Errorf("payload missing %q\n---\n%s", want, payload)
		}
	}

	// TCP/113 must NEVER be accepted — the exposure this issue fixes.
	if strings.Contains(payload, "tcp dport 113 accept") {
		t.Errorf("ident-reset must NOT open TCP/113 with an accept (the #3310 exposure):\n%s", payload)
	}

	// The reject rule must precede the catch-all drop for each family (a fresh
	// ident SYN has no `established` state, so it reaches the reject).
	for _, fam := range []struct{ family, addr string }{
		{"ip", "172.16.50.8"},
		{"ip6", "2001:db8:50::8"},
	} {
		reject := fam.family + " daddr " + fam.addr + " tcp dport 113 reject with tcp reset"
		drop := hiDrop(fam.family, fam.addr, "wan")
		idxReject := strings.Index(payload, reject)
		idxDrop := strings.Index(payload, drop)
		if idxReject < 0 || idxDrop < 0 || idxReject > idxDrop {
			t.Errorf("%s ident-reset reject must precede the catch-all drop:\n%s", fam.family, payload)
		}
	}
}

// TestHostInboundFilterAllSuppressesIdentReset verifies the `all` /
// `any-service` precedence: a zone that lists BOTH `all` and `ident-reset`
// fully opens (bare accept, no per-token rule), so it emits NO ident-reset
// reject and NO catch-all drop — matching the Rust classifier, where
// `all_services` short-circuits `admits` to true. This pins the precedence the
// plan §5b/§6 calls out: `all` wins over ident-reset.
func TestHostInboundFilterAnyServiceSuppressesIdentReset(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.1.1.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {
			Name:               "trust",
			Interfaces:         []string{"reth0.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"any-service", "ident-reset"}},
		},
	}
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil)

	if !strings.Contains(payload, "ip daddr 10.1.1.1 accept") {
		t.Errorf("`any-service` zone must accept everything to its addr:\n%s", payload)
	}
	if strings.Contains(payload, "reject with tcp reset") {
		t.Errorf("`any-service` precedence must suppress the ident-reset reject rule:\n%s", payload)
	}
	if strings.Contains(payload, "tcp dport 113") {
		t.Errorf("`any-service` zone must not emit any per-token 113 rule:\n%s", payload)
	}
}

// findNft locates the nft binary in PATH or the common sbin dirs (go test does
// not always carry /sbin in PATH, but the appliance runs nft from /usr/sbin).
func findNft() string {
	if p, err := exec.LookPath("nft"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/sbin/nft", "/sbin/nft"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// TestHostInboundFilterIdentResetPayloadParses is the #3310 merge gate (plan
// §7 / Q7) AND the #3578 fail-on-revert proof for the named-counter DECLARATION
// syntax: the EXACT host-inbound payload buildHostInboundFilterPayload emits —
// the #3310 `reject` rule plus the #3361 named-counter declarations — must parse
// on the appliance nft binary. Mirrors the lo0 precedent
// (TestLo0FilterPayloadNftParses).
//
// #3578: nft v1.1.6 accepts a quoted name in a counter REFERENCE
// (`counter name "<n>" drop`) but REJECTS it in a counter DECLARATION
// (`counter "<n>" {}` -> "syntax error, unexpected quoted string"). The payload
// must therefore declare counters UNQUOTED (`counter <n> {}`) with an identifier
// sanitized to the bare-safe nft set. This test runs the RAW payload through
// `nft -c -f -` (no normalization): reverting the unquoted declaration (or
// dropping the identifier sanitization) re-introduces a `syntax error` and turns
// this RED. A netlink/permission failure (no CAP_NET_ADMIN) occurs only AFTER
// syntax parsing succeeds and is a pass; nft absent skips.
func TestHostInboundFilterIdentResetPayloadParses(t *testing.T) {
	nftPath := findNft()
	if nftPath == "" {
		t.Skip("nft not found; covered by TestHostInboundFilterIdentResetEmitsReset")
	}
	// Extend the ident-reset scenario with zones whose names carry bare-safe nft
	// identifier bytes that sanitizeNftIdent PRESERVES — a hyphen ("wan-zone")
	// and a dot ("vlan.50") — so the LIVE `nft -c` parse exercises a bare
	// `counter xpfhi_..._wan-zone {` / `..._vlan.50 {` declaration. This pins at
	// CI that nft v1.1.6 accepts those bytes UNQUOTED (#3578): an accidental
	// narrowing of the sanitize charset that mangled '-'/'.' to '_' is caught by
	// the "survived sanitization" assertions below, and a true nft rejection of
	// bare '-'/'.' would surface as a `syntax error` and fail the parse. Both
	// names commit (only '/' is rejected for zone names).
	cfg := identResetTestConfig()
	cfg.Interfaces.Interfaces["reth1"] = &config.InterfaceConfig{Name: "reth1", Units: map[int]*config.InterfaceUnit{
		60: {Number: 60, VlanID: 60, Addresses: []string{"172.16.60.8/24"}},
		70: {Number: 70, VlanID: 70, Addresses: []string{"172.16.70.8/24"}},
	}}
	cfg.Security.Zones["wan-zone"] = &config.ZoneConfig{
		Name:               "wan-zone",
		Interfaces:         []string{"reth1.60"},
		HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
	}
	cfg.Security.Zones["vlan.50"] = &config.ZoneConfig{
		Name:               "vlan.50",
		Interfaces:         []string{"reth1.70"},
		HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
	}
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil)

	// Sanity: the raw payload must still carry the #3310 reject rule and the
	// #3361 named-counter declaration — otherwise the parse check is vacuous.
	if !strings.Contains(payload, "tcp dport 113 reject with tcp reset") {
		t.Fatalf("payload lost the ident-reset reject rule:\n%s", payload)
	}
	if !strings.Contains(payload, "counter "+xnft.HostInboundDenyCounterName("wan", "ip")+" {") {
		t.Fatalf("payload lost the #3361 named-counter declaration:\n%s", payload)
	}
	// The hyphen/dot zone counters must be declared BARE with the byte intact
	// (sanitizeNftIdent is the identity for '-'/'.'); this is what the live nft
	// parse below then exercises.
	for _, want := range []string{
		"counter xpfhi_ip_8_wan-zone {", // hyphen preserved, bare declaration
		"counter xpfhi_ip_7_vlan.50 {",  // dot preserved, bare declaration
	} {
		if !strings.Contains(payload, want) {
			t.Fatalf("payload missing bare hyphen/dot counter declaration %q:\n%s", want, payload)
		}
	}

	cmd := exec.Command(nftPath, "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(payload)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return // parsed and (as root) check-applied cleanly
	}
	combined := string(out)
	if strings.Contains(combined, "syntax error") {
		t.Fatalf("nft -c rejected the host-inbound payload with a syntax error:\n%s\npayload:\n%s", combined, payload)
	}
	t.Logf("nft -c parsed the payload; non-syntax error (expected without CAP_NET_ADMIN): %v\n%s", err, combined)
}

// TestHostInboundFilterCounterDeclarationUnquoted is the #3578 unit-level
// fail-on-revert proof (independent of whether nft is installed): every counter
// DECLARATION the payload emits is UNQUOTED, no QUOTED declaration appears, and
// the declared identifier is byte-identical to the identifier the catch-all DROP
// references (so nft never sees a reference to an undeclared counter). Reverting
// the declaration to the quoted `counter "<n>" {}` form turns the "no quoted
// declaration" assertion RED.
func TestHostInboundFilterCounterDeclarationUnquoted(t *testing.T) {
	cfg := hostInboundTestConfig()
	views := buildAndCheckViews(t, cfg)
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil)

	// No QUOTED counter declaration may appear (a reference is `counter name
	// "<n>"`, never `counter "<n>" {`).
	if strings.Contains(payload, "counter \"") {
		for _, line := range strings.Split(payload, "\n") {
			if strings.Contains(line, "counter \"") {
				t.Errorf("payload carries a quoted counter declaration (nft v1.1.6 rejects it): %q", line)
			}
		}
	}

	for _, fam := range []string{"ip", "ip6"} {
		cn := xnft.HostInboundDenyCounterName("wan", fam)
		// The declaration is the unquoted bare-identifier form.
		if !strings.Contains(payload, "counter "+cn+" {") {
			t.Errorf("missing unquoted declaration for (wan,%s): want %q\n%s", fam, "counter "+cn+" {", payload)
		}
		// The DROP references the SAME identifier (so the counter is defined).
		if !strings.Contains(payload, "counter name \""+cn+"\" drop") {
			t.Errorf("catch-all drop must reference the declared counter %q\n%s", cn, payload)
		}
	}
}

// buildAndCheckViews resolves the per-zone views and asserts the table would be
// applied (at least one enforceable zone).
func buildAndCheckViews(t *testing.T, cfg *config.Config) []dpuserspace.ZoneHostInboundView {
	t.Helper()
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	if !hostInboundHasEnforceableView(views) {
		t.Fatalf("expected at least one enforceable host-inbound view")
	}
	return views
}
