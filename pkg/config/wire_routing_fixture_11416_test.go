package config

import (
	"strings"
	"testing"
)

// #11416: the wire-routing-separation populated-RI fixture must compile
// under the strict validators. The 2026-10-16 live attempt VOIDed because
// cli_commit_populated added the RI's GRE member (gr-0/0/1.0, member of
// routing-instance wire-10136) to the existing `wan` zone, which also
// carries MAIN-context reth0.50/.80 — validateFabricZoneRoutingInstance-
// AmbiguityStrict (#11061) rejects a zone spanning two routing contexts.
// The fixture now uses a dedicated wire-vrf zone with its own
// lan->wire-vrf permit and interface-SNAT pair (mirroring lan->sfmix).
//
// Fail-on-revert: putting gr-0/0/1.0 back into `wan` (the old fixture
// shape, TestWireRoutingFixture11416CrossContextWanRejected) makes the
// strict compile fail with the exact production error; the dedicated-zone
// shape must compile clean.

func wireRoutingFixture11416Lines(zone string) []string {
	return []string{
		"set interfaces reth0 vlan-tagging",
		"set interfaces reth0 unit 50 vlan-id 50",
		"set interfaces reth0 unit 50 family inet address 172.16.50.8/24",
		"set interfaces reth0 unit 80 vlan-id 80",
		"set interfaces reth0 unit 80 family inet address 172.16.80.8/24",
		"set interfaces reth1 unit 0 family inet filter input sfmix-pbr",
		"set interfaces gr-0/0/1 tunnel source 172.16.80.8",
		"set interfaces gr-0/0/1 tunnel destination 172.16.80.201",
		"set interfaces gr-0/0/1 unit 0 family inet address 198.18.117.1/32",
		"set security zones security-zone wan interfaces reth0.50",
		"set security zones security-zone wan interfaces reth0.80",
		"set security zones security-zone lan interfaces reth1",
		"set security zones security-zone " + zone + " interfaces gr-0/0/1.0",
		"set security policies from-zone lan to-zone " + zone + " policy wire-vrf-allow match source-address any",
		"set security policies from-zone lan to-zone " + zone + " policy wire-vrf-allow match destination-address any",
		"set security policies from-zone lan to-zone " + zone + " policy wire-vrf-allow match application any",
		"set security policies from-zone lan to-zone " + zone + " policy wire-vrf-allow then permit",
		"set security nat source rule-set lan-to-wire-vrf from zone lan",
		"set security nat source rule-set lan-to-wire-vrf to zone " + zone,
		"set security nat source rule-set lan-to-wire-vrf rule snat match source-address 0.0.0.0/0",
		"set security nat source rule-set lan-to-wire-vrf rule snat then source-nat interface",
		"set firewall family inet filter sfmix-pbr term wire-10136 from source-address 10.0.61.102/32",
		"set firewall family inet filter sfmix-pbr term wire-10136 from destination-address 172.16.80.201/32",
		"set firewall family inet filter sfmix-pbr term wire-10136 from protocol udp",
		"set firewall family inet filter sfmix-pbr term wire-10136 from destination-port 40000",
		"set firewall family inet filter sfmix-pbr term wire-10136 then routing-instance wire-10136",
		"set firewall family inet filter sfmix-pbr term default then accept",
		"set routing-instances wire-10136 instance-type vrf",
		"set routing-instances wire-10136 interface gr-0/0/1.0",
		"set routing-instances wire-10136 routing-options static route 172.16.80.201/32 next-hop gr-0/0/1.0",
	}
}

func TestWireRoutingFixture11416DedicatedZoneCompilesStrictly(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, wireRoutingFixture11416Lines("wire-vrf")))
	if err != nil {
		t.Fatalf("dedicated-zone populated fixture must compile strictly: %v", err)
	}
	if cfg == nil || cfg.Security.Zones["wire-vrf"] == nil {
		t.Fatalf("compiled fixture lost the wire-vrf zone: %+v", cfg)
	}
	if got := cfg.Security.Zones["wire-vrf"].Interfaces; len(got) != 1 || got[0] != "gr-0/0/1.0" {
		t.Fatalf("wire-vrf zone interfaces = %v, want [gr-0/0/1.0]", got)
	}
	// The wan zone must stay MAIN-only (the cross-context shape is the bug).
	if got := cfg.Security.Zones["wan"].Interfaces; len(got) != 2 {
		t.Fatalf("wan zone interfaces = %v, want reth0.50+reth0.80 only", got)
	}
}

func TestWireRoutingFixture11416CrossContextWanRejected(t *testing.T) {
	_, err := CompileConfig(buildTree(t, wireRoutingFixture11416Lines("wan")))
	if err == nil {
		t.Fatal("old wan-zone fixture shape compiled; the #11061 validator no longer guards it")
	}
	if !strings.Contains(err.Error(), "spans multiple routing contexts") ||
		!strings.Contains(err.Error(), `"wan"`) {
		t.Fatalf("rejection must name the cross-context wan zone (the live 2026-10-16 error), got: %v", err)
	}
}
