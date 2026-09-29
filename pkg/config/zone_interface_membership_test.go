package config

import (
	"strings"
	"testing"
)

// TestZoneInterfaceMultiZoneFailsCommit is the fail-on-revert guard for #3072:
// assigning the same interface to two security zones MUST be hard-rejected at
// commit. Without validateZoneInterfaceMembershipStrict (or its dispatch in
// compiler.go) this config compiles cleanly and the userspace interface->zone
// map silently resolves ge-0/0/0.0 to whichever zone name sorts first
// ("aaa" < "trust"), evaluating traffic against the wrong zone's policy — the
// regression this subtest guards. The error must name the interface and BOTH
// conflicting zones.
func TestZoneInterfaceMultiZoneFailsCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone aaa interfaces ge-0/0/0.0",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject an interface assigned to two security zones, got nil error")
	}
	for _, want := range []string{"ge-0/0/0.0", "aaa", "trust"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name %q", err.Error(), want)
		}
	}
}

func TestZoneInterfaceConflictDiagnosticDeterministic(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/0 unit 2 family inet address 10.0.0.2/24",
		"set interfaces ge-0/0/0 unit 10 family inet address 10.0.0.10/24",
		"set security zones security-zone aaa interfaces ge-0/0/0.2",
		"set security zones security-zone bbb interfaces ge-0/0/0.10",
		"set security zones security-zone trust interfaces ge-0/0/0",
	}
	var want string
	for i := range 20 {
		_, err := CompileConfig(buildTree(t, lines))
		if err == nil {
			t.Fatal("expected strict compile to reject conflicting unit membership")
		}
		got := err.Error()
		for _, part := range []string{"bbb", "trust"} {
			if !strings.Contains(got, part) {
				t.Fatalf("strict diagnostic %q does not identify first conflict zone %q", got, part)
			}
		}
		if strings.Contains(got, "aaa") {
			t.Fatalf("strict diagnostic %q selected the later unit conflict instead of the .10 conflict", got)
		}
		if i == 0 {
			want = got
		} else if got != want {
			t.Fatalf("strict diagnostic changed between compiles:\nfirst: %q\nagain: %q", want, got)
		}
	}
}

// TestZoneInterfaceMultiZoneLenientDowngradesToWarning asserts the tolerant
// load / peer-sync path warns instead of failing the compile, so an already-
// persisted or peer-synced config still boots (#3072 / #1960 no-brick). The
// contested logical interface key is omitted from the runtime map, making the
// ambiguous interface unzoned and fail-closed rather than selecting a zone by
// sorted-name order.
func TestZoneInterfaceMultiZoneLenientDowngradesToWarning(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone aaa interfaces ge-0/0/0.0",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not fail on a multi-zone interface config: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "zone interface membership (downgraded to warning on tolerant path)") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a downgraded zone-interface-membership warning, got warnings: %v", cfg.Warnings)
	}
	zoneMap := InterfaceZoneMap(cfg)
	if got := zoneMap["ge-0/0/0.0"]; got != "" {
		t.Fatalf("ambiguous interface resolved to zone %q, want no zone (fail closed)", got)
	}
	if _, quarantined := QuarantinedZoneInterfaceKeys(cfg)["ge-0/0/0.0"]; !quarantined {
		t.Fatal("contested logical interface key was not quarantined")
	}
	if got := buildZoneInterfaceMapLocal(cfg)["ge-0/0/0.0"]; got != "" {
		t.Fatalf("local host-inbound map resolved contested interface to %q", got)
	}
	for _, name := range []string{"aaa", "trust"} {
		cfg.Security.Zones[name].InterfaceHostInbound = map[string]*HostInboundTraffic{
			"ge-0/0/0.0": {Protocols: []string{"ospf"}},
		}
	}
	if got := ResolveInterfaceHostInbound(cfg); got["ge-0/0/0.0"] != nil {
		t.Fatalf("host-inbound override leaked onto contested interface: %+v", got)
	}
}

// TestZoneInterfaceBareVsUnitMultiZoneFailsCommit asserts the base/unit alias
// overlap the userspace expansion creates is also rejected (#3072): a bare
// physical interface (ge-0/0/0, which claims all its configured units) in one
// zone and a specific unit of it (ge-0/0/0.0) in another zone is the same
// logical interface in two zones.
func TestZoneInterfaceBareVsUnitMultiZoneFailsCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone aaa interfaces ge-0/0/0",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject a bare interface and one of its units assigned to two zones, got nil error")
	}
	for _, want := range []string{"aaa", "trust"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not name %q", err.Error(), want)
		}
	}
}

// TestZoneInterfaceSameZoneRepeatNotFlagged asserts listing the same interface
// twice WITHIN one zone (an idempotent `set`, or a bare/unit pair in the same
// zone) is NOT a conflict — only cross-zone duplication is (#3072
// anti-over-reject).
func TestZoneInterfaceSameZoneRepeatNotFlagged(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected an interface listed twice in the SAME zone: %v", err)
	}
}

// TestZoneInterfaceDistinctUnitsAcrossZonesNotFlagged asserts two DIFFERENT
// units of one physical interface in two zones (a valid VLAN sub-interface
// split, ge-0/0/0.0 in trust and ge-0/0/0.1 in untrust) is NOT rejected (#3072
// anti-over-reject). The userspace map's coarse bare-base fallback for untagged
// lookups is a first-writer-wins artifact, not a second operator assignment.
func TestZoneInterfaceDistinctUnitsAcrossZonesNotFlagged(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/0 unit 1 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone untrust interfaces ge-0/0/0.1",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected a valid two-unit VLAN split across zones: %v", err)
	}
}

// TestZoneInterfaceOrdinaryConfigUnaffected asserts a normal one-interface-per-
// zone config commits cleanly — the gate does not perturb the common case
// (#3072).
func TestZoneInterfaceOrdinaryConfigUnaffected(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/2 unit 0 family inet address 10.0.2.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone untrust interfaces ge-0/0/1.0",
		"set security zones security-zone dmz interfaces ge-0/0/2.0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected an ordinary one-interface-per-zone config: %v", err)
	}
}
