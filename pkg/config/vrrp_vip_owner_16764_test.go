package config

import (
	"strings"
	"testing"
)

// #16764 (R3-A25-01): a virtual-address equal to an address of its own unit
// is the RFC 5798 address-owner shape. pkg/vrrp excludes VIPs from the
// advert source and deletes every VIP on BACKUP/stop, so the owner would
// advertise nothing while reporting MASTER and would strip its own unit
// address at every start and stop. The strict compile now rejects it.
//
// FAIL-ON-REVERT: drop the validateVRRPVIPOwnerStrict dispatch in
// compiler_uniformgates_cluster_zone.go and every strict-reject test below
// goes green on the BAD (owner) config.

func ownerLines16764(iface, unitAddr, vip string, priority string) []string {
	base := "set interfaces " + iface + " unit 0 family inet address " + unitAddr + " vrrp-group 1"
	lines := []string{base + " virtual-address " + vip}
	if priority != "" {
		lines = append(lines, base+" priority "+priority)
	}
	return lines
}

// TestVIPOwnerEqualsUnitAddressFailsCommit16764 is the issue's subject row:
// VIP == the unit's only address, priority 255.
func TestVIPOwnerEqualsUnitAddressFailsCommit16764(t *testing.T) {
	_, err := CompileConfig(buildTree(t, ownerLines16764("ge-0/0/0", "10.0.1.1/24", "10.0.1.1/24", "255")))
	if err == nil {
		t.Fatal("expected commit to reject virtual-address equal to the unit address (address owner)")
	}
	for _, want := range []string{"ge-0/0/0", "unit 0", "vrrp-group 1", "10.0.1.1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err.Error(), want)
		}
	}
}

// TestVIPOwnerAnyPriorityFailsCommit16764: the defect mechanism does not
// depend on priority 255 — any priority with VIP == unit address loses its
// advert source when it is the only address and loses the address on
// BACKUP/stop — so the gate is not scoped to 255.
func TestVIPOwnerAnyPriorityFailsCommit16764(t *testing.T) {
	for _, prio := range []string{"", "100", "200"} {
		_, err := CompileConfig(buildTree(t, ownerLines16764("ge-0/0/0", "10.0.1.1/24", "10.0.1.1/24", prio)))
		if err == nil {
			t.Fatalf("priority %q: expected commit to reject VIP == unit address", prio)
		}
	}
}

// TestVIPOwnerSecondAddressFailsCommit16764: equality with ANY address of
// the unit counts, not only the address the group is nested under.
func TestVIPOwnerSecondAddressFailsCommit16764(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.2/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24 vrrp-group 1 virtual-address 10.0.1.2/24",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24 vrrp-group 1 priority 255",
	}
	if _, err := CompileConfig(buildTree(t, lines)); err == nil {
		t.Fatal("expected commit to reject VIP equal to another address of the same unit")
	}
}

// TestVIPOwnerBareSpellingFailsCommit16764: a bare VIP spelling is
// normalized to the enclosing unit prefix before the gate runs, so it
// cannot slip past as a distinct literal.
func TestVIPOwnerBareSpellingFailsCommit16764(t *testing.T) {
	if _, err := CompileConfig(buildTree(t, ownerLines16764("ge-0/0/0", "10.0.1.1/24", "10.0.1.1", "255"))); err == nil {
		t.Fatal("expected commit to reject bare VIP equal to the unit address")
	}
}

// TestVIPOwnerIPv6FailsCommit16764: the IPv6 leg loses its global unit
// address the same way (its advert source is the link-local, so it would
// still advertise — the address stripping alone is the defect there).
func TestVIPOwnerIPv6FailsCommit16764(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64 vrrp-inet6-group 1 virtual-inet6-address 2001:db8::1/64",
		"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64 vrrp-inet6-group 1 priority 255",
	}
	if _, err := CompileConfig(buildTree(t, lines)); err == nil {
		t.Fatal("expected commit to reject IPv6 virtual-address equal to the unit address")
	}
}

// TestVIPOwnerHierarchicalFailsCommit16764: the braced spelling reaches the
// same compiled VRRPGroup and must reject identically.
func TestVIPOwnerHierarchicalFailsCommit16764(t *testing.T) {
	text := `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24 { vrrp-group 1 { virtual-address 10.0.1.1/24; priority 255; } } } } } }`
	if _, err := CompileConfig(parseHierText(t, text)); err == nil {
		t.Fatal("expected hierarchical commit to reject VIP equal to the unit address")
	}
}

// TestVIPDistinctFromUnitAddressCommits16764 is the issue's control row:
// VIP 10.0.1.254 on unit address 10.0.1.1, priority 255, commits cleanly
// with no warning.
func TestVIPDistinctFromUnitAddressCommits16764(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, ownerLines16764("ge-0/0/0", "10.0.1.1/24", "10.0.1.254/24", "255")))
	if err != nil {
		t.Fatalf("distinct VIP (control row) must commit: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "10.0.1.254") {
			t.Fatalf("control row must not warn about its VIP; warnings=%v", cfg.Warnings)
		}
	}
}

// TestVIPOwnerDifferentUnitCommits16764: a VIP equal to an address of a
// DIFFERENT unit is a different kernel device / L2 domain and stays legal.
func TestVIPOwnerDifferentUnitCommits16764(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.2.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.2/24 vrrp-group 1 virtual-address 10.0.2.1/24",
	}
	if _, err := CompileConfig(buildTree(t, lines)); err != nil {
		t.Fatalf("VIP equal to another unit's address must commit: %v", err)
	}
}

// TestVIPOwnerLenientWarns16764 pins the #1960 downgrade: the tolerant
// load / peer-sync path compiles the owner shape but warns naming it, so a
// persisted config an older binary accepted still boots.
func TestVIPOwnerLenientWarns16764(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, ownerLines16764("ge-0/0/0", "10.0.1.1/24", "10.0.1.1/24", "255")))
	if err != nil {
		t.Fatalf("lenient compile must not reject the owner shape (no-brick): %v", err)
	}
	if !warningsContain(cfg.Warnings, "10.0.1.1") {
		t.Fatalf("lenient compile should warn naming the owner VIP; warnings=%v", cfg.Warnings)
	}
	if !lenientCompileOpts().lenientVRRPVIPOwner {
		t.Fatal("lenientVRRPVIPOwner is NOT registered in lenientCompileOpts() — a persisted or peer-synced owner config would fail to boot (#1960)")
	}
}

// TestRethUnitAddressesNotOwnerRejected16764: RETH-derived instances carry
// the unit addresses as their VIPs by construction; with no explicit
// vrrp-group there is nothing for this gate to reject.
func TestRethUnitAddressesNotOwnerRejected16764(t *testing.T) {
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.99.0.2",
		"set chassis cluster authentication-key test-cluster-psk-16764",
		"set chassis cluster reth-count 1",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 10.0.0.100/24",
	}
	if _, err := CompileConfig(buildTree(t, lines)); err != nil {
		t.Fatalf("plain RETH unit address (no explicit vrrp-group) must commit: %v", err)
	}
}
