package config

import (
	"strings"
	"testing"
)

// #5837 (Track-1 mitigation): a destination-NAT / static-NAT rule whose PUBLIC
// (matched / external) destination address equals a configured interface address
// is INERT on the first packet — the userspace AF_XDP shim classifies a
// firewall-local destination as kernel-local and shunts it to the host BEFORE
// consulting DNAT/static-NAT (is_local_destination runs before pre_routing_dnat).
// The commit compiler now emits a WARN-only advisory naming the rule + the
// colliding interface address on BOTH compile paths. See
// compiler_validate_warn_nat_iface_addr.go and
// docs/research/5837-xdp-dnat-before-local/plan.md §0a.
//
// All tests use the production ParseSetCommand + SetPath path (buildTree),
// never NewParser (the flat-set gotcha in CLAUDE.md).

// nat5837Warnings returns every cfg.Warnings entry that names the #5837
// interface-address NAT-bypass advisory.
func nat5837Warnings(cfg *Config) []string {
	var out []string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#5837") {
			out = append(out, w)
		}
	}
	return out
}

// ifaceWithAddr configures ge-0/0/2.0 with the WAN interface address and puts it
// in the untrust zone, so the NAT rule-sets' `from zone untrust` resolves.
func ifaceWithAddr(addr string) []string {
	return []string{
		"set interfaces ge-0/0/2 unit 0 family inet address " + addr,
		"set security zones security-zone untrust interfaces ge-0/0/2.0",
	}
}

// A destination-NAT rule that matches the firewall's own WAN interface address
// must produce exactly one #5837 advisory naming the rule-set/rule + interface.
func TestDNATInterfaceAddressCollisionWarns(t *testing.T) {
	lines := append(ifaceWithAddr("172.16.50.8/24"),
		"set security nat destination pool P1 address 10.0.30.100",
		"set security nat destination rule-set RD from zone untrust",
		"set security nat destination rule-set RD rule R1 match destination-address 172.16.50.8/32",
		"set security nat destination rule-set RD rule R1 then destination-nat pool P1",
	)
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("config must compile (WARN-only), got: %v", err)
	}
	ws := nat5837Warnings(cfg)
	if len(ws) != 1 {
		t.Fatalf("expected exactly one #5837 DNAT advisory, got %d: %v", len(ws), ws)
	}
	w := ws[0]
	for _, want := range []string{
		"security nat destination rule-set \"RD\" rule \"R1\"",
		"172.16.50.8",
		"ge-0/0/2.0",
		"INERT on the first packet",
		// The advisory must state the DISPOSITION truthfully. Track-2 (the
		// dedicated-intent-map dataplane fix) was #6051 and is plan-killed, so
		// this warning is the terminal mitigation. It previously promised a
		// "deferred (Track-2)" fix; an operator reading that would wait for
		// something that is not coming instead of applying the workaround the
		// same sentence offers.
		"the dataplane fix is not planned (#6051)",
		"Use a non-interface public address",
	} {
		if !strings.Contains(w, want) {
			t.Fatalf("advisory missing %q, got: %s", want, w)
		}
	}
}

// The same collision must also warn on the tolerant load / peer-sync path
// (the advisory is emitted from ValidateConfig, which runs on every compile).
func TestDNATInterfaceAddressCollisionWarnsLenient(t *testing.T) {
	lines := append(ifaceWithAddr("172.16.50.8/24"),
		"set security nat destination pool P1 address 10.0.30.100",
		"set security nat destination rule-set RD from zone untrust",
		"set security nat destination rule-set RD rule R1 match destination-address 172.16.50.8",
		"set security nat destination rule-set RD rule R1 then destination-nat pool P1",
	)
	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("lenient compile must succeed, got: %v", err)
	}
	if got := len(nat5837Warnings(cfg)); got != 1 {
		t.Fatalf("expected one #5837 advisory on the lenient path, got %d", got)
	}
}

// A static-NAT rule whose external (public) match address is a firewall
// interface address must produce a #5837 advisory.
func TestStaticNATInterfaceAddressCollisionWarns(t *testing.T) {
	lines := append(ifaceWithAddr("172.16.50.8/24"),
		"set security nat static rule-set RS from zone untrust",
		"set security nat static rule-set RS rule R1 match destination-address 172.16.50.8/32",
		"set security nat static rule-set RS rule R1 then static-nat prefix 10.0.30.100/32",
	)
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("config must compile (WARN-only), got: %v", err)
	}
	ws := nat5837Warnings(cfg)
	if len(ws) != 1 {
		t.Fatalf("expected exactly one #5837 static-NAT advisory, got %d: %v", len(ws), ws)
	}
	for _, want := range []string{
		"security nat static rule-set \"RS\" rule \"R1\"",
		"172.16.50.8",
		"ge-0/0/2.0",
		// Same disposition claim as the DNAT advisory (see above): #6051 is
		// plan-killed, so the sentence must not promise a deferred fix.
		"the dataplane fix is not planned (#6051)",
		"Use a non-interface external address",
	} {
		if !strings.Contains(ws[0], want) {
			t.Fatalf("advisory missing %q, got: %s", want, ws[0])
		}
	}
}

// A VRRP virtual address (VIP) is firewall-local too: a DNAT match on the VIP
// must warn, naming the VIP-bearing interface.
func TestDNATVRRPVIPCollisionWarns(t *testing.T) {
	lines := []string{
		"set interfaces reth0 unit 0 family inet address 172.16.50.2/24",
		"set interfaces reth0 unit 0 family inet address 172.16.50.2/24 vrrp-group 1 virtual-address 172.16.50.1",
		"set security zones security-zone untrust interfaces reth0.0",
		"set security nat destination pool P1 address 10.0.30.100",
		"set security nat destination rule-set RD from zone untrust",
		"set security nat destination rule-set RD rule R1 match destination-address 172.16.50.1",
		"set security nat destination rule-set RD rule R1 then destination-nat pool P1",
	}
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("config must compile, got: %v", err)
	}
	ws := nat5837Warnings(cfg)
	if len(ws) != 1 {
		t.Fatalf("expected one #5837 advisory for a VIP collision, got %d: %v", len(ws), ws)
	}
	if !strings.Contains(ws[0], "172.16.50.1") || !strings.Contains(ws[0], "VRRP VIP") {
		t.Fatalf("VIP advisory should name the VIP + mark it a VRRP VIP, got: %s", ws[0])
	}
}

// NO-false-warn control: a DNAT rule whose public match address is NOT any
// interface address must produce no #5837 advisory. Also covers the pool
// address deliberately being an interface address (10.0.30.100 is NOT here) —
// the check keys on the matched/public address, not the translated-to pool.
func TestDNATNonInterfaceAddressNoWarn(t *testing.T) {
	lines := append(ifaceWithAddr("172.16.50.8/24"),
		"set security nat destination pool P1 address 10.0.30.100",
		"set security nat destination rule-set RD from zone untrust",
		"set security nat destination rule-set RD rule R1 match destination-address 203.0.113.5/32",
		"set security nat destination rule-set RD rule R1 then destination-nat pool P1",
	)
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("config must compile, got: %v", err)
	}
	if ws := nat5837Warnings(cfg); len(ws) != 0 {
		t.Fatalf("a non-interface public address must not warn, got: %v", ws)
	}
}

// Control: a DNAT whose POOL (translated-to) address is an interface address but
// whose MATCH (public) address is not must NOT warn — the #5837 bypass is about
// the ingress destination the shim classifies as local, not the pool target.
func TestDNATPoolAddressIsInterfaceNoWarn(t *testing.T) {
	lines := append(ifaceWithAddr("172.16.50.8/24"),
		"set security nat destination pool P1 address 172.16.50.8", // pool == iface addr
		"set security nat destination rule-set RD from zone untrust",
		"set security nat destination rule-set RD rule R1 match destination-address 203.0.113.5/32",
		"set security nat destination rule-set RD rule R1 then destination-nat pool P1",
	)
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("config must compile, got: %v", err)
	}
	if ws := nat5837Warnings(cfg); len(ws) != 0 {
		t.Fatalf("pool-address collision is not the #5837 bypass; must not warn, got: %v", ws)
	}
}

// #5837 rev6052 (fold): interface-mode source-NAT to a zone routes THAT zone's
// interface addresses out of the kernel-local set and into interface_nat (the
// dataplane's nat_translated_local_exclusions, userspace-dp/src/afxdp/rst.rs).
// is_local_destination then returns FALSE for such an address — it short-circuits
// on USERSPACE_INTERFACE_NAT membership BEFORE the local_v4/v6 check — so the
// first SYN reaches the helper and inbound DNAT applies. The translation is NOT
// inert, so the advisory must be SUPPRESSED. This is the canonical masquerade +
// WAN-port-forward config (interface SNAT trust->untrust + DNAT from untrust
// matching the untrust interface's own WAN-IP). Reverting the exclusion
// (interfaceModeSNATExcludedAddresses / the `if excluded[host]` guard) makes this
// warn again — RED.
func TestDNATInterfaceAddressExcludedByInterfaceSNAT_5837(t *testing.T) {
	lines := []string{
		// trust (LAN) interface + zone
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
		// untrust (WAN) interface + zone — its own address is the WAN-IP
		"set interfaces ge-0/0/2 unit 0 family inet address 172.16.50.8/24",
		"set security zones security-zone untrust interfaces ge-0/0/2.0",
		// interface-mode source-NAT trust -> untrust (canonical masquerade)
		"set security nat source rule-set S from zone trust",
		"set security nat source rule-set S to zone untrust",
		"set security nat source rule-set S rule R match source-address 10.0.61.0/24",
		"set security nat source rule-set S rule R then source-nat interface",
		// WAN port-forward: DNAT from untrust matching the untrust WAN-IP
		"set security nat destination pool P1 address 10.0.30.100",
		"set security nat destination rule-set RD from zone untrust",
		"set security nat destination rule-set RD rule R1 match destination-address 172.16.50.8/32",
		"set security nat destination rule-set RD rule R1 then destination-nat pool P1",
	}
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("config must compile, got: %v", err)
	}
	if ws := nat5837Warnings(cfg); len(ws) != 0 {
		t.Fatalf("interface-mode SNAT routes the WAN-IP into interface_nat; the "+
			"DNAT is NOT inert and must not warn (rev6052 false-warn), got: %v", ws)
	}
}

// Keep-green control: interface-mode source-NAT exists but its to-zone is NOT
// the zone that owns the matched WAN-IP, so that address stays kernel-local (it
// is not routed into interface_nat) and the DNAT is still inert — it must STILL
// warn. Proves the exclusion is to-zone scoped (mirrors the rst.rs predicate),
// not a blanket "any interface-mode SNAT suppresses every advisory".
func TestDNATInterfaceAddressStillWarnsWhenSNATToOtherZone_5837(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.61.1/24",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
		"set interfaces ge-0/0/2 unit 0 family inet address 172.16.50.8/24",
		"set security zones security-zone untrust interfaces ge-0/0/2.0",
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.30.10/24",
		"set security zones security-zone dmz interfaces ge-0/0/3.0",
		// interface-mode SNAT trust -> DMZ (NOT untrust)
		"set security nat source rule-set S from zone trust",
		"set security nat source rule-set S to zone dmz",
		"set security nat source rule-set S rule R match source-address 10.0.61.0/24",
		"set security nat source rule-set S rule R then source-nat interface",
		// DNAT from untrust matching the untrust WAN-IP — untrust is NOT the SNAT to-zone
		"set security nat destination pool P1 address 10.0.30.100",
		"set security nat destination rule-set RD from zone untrust",
		"set security nat destination rule-set RD rule R1 match destination-address 172.16.50.8/32",
		"set security nat destination rule-set RD rule R1 then destination-nat pool P1",
	}
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("config must compile, got: %v", err)
	}
	ws := nat5837Warnings(cfg)
	if len(ws) != 1 {
		t.Fatalf("SNAT to a different zone must not exclude the untrust WAN-IP; "+
			"expected exactly 1 advisory, got %d: %v", len(ws), ws)
	}
	if !strings.Contains(ws[0], "172.16.50.8") {
		t.Fatalf("advisory should name the WAN-IP, got: %s", ws[0])
	}
}
