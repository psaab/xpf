package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// #13936 (deep-review H08-02): a unit carrying `family inet6` whose
// effective MTU is below the RFC 8200 §5 IPv6 minimum of 1280 must be
// rejected at commit. The compiled unit.MTU is the min-fold of BOTH
// family mtu statements (#10050), and the value is written to the link
// (networkd MTUBytes / dataplane LinkSetMTU); the kernel then removes
// the unit's IPv6 addresses. Before this gate every shape below
// committed clean with no warning.

// The direct spelling: `family inet6 mtu` below 1280 on the unit itself.
func TestIPv6UnitMTUBelowMinimumRejected13936(t *testing.T) {
	_, err := CompileConfig(flatTreeFromSets(t,
		"set interfaces ge-0-0-0 unit 0 family inet6 address 2001:db8::1/64",
		"set interfaces ge-0-0-0 unit 0 family inet6 mtu 1000",
	))
	if err == nil {
		t.Fatal("strict commit ACCEPTED an IPv6-bearing unit with effective MTU 1000 (< 1280)")
	}
	for _, want := range []string{"ge-0-0-0", "unit 0", "1000", "1280", "#13936"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err.Error(), want)
		}
	}
}

// The min-fold spelling named by the issue: the unit carries inet6, and
// a `family inet mtu` below 1280 folds into the shared unit.MTU.
func TestIPv6UnitMTUInetFoldRejected13936(t *testing.T) {
	for _, sets := range [][]string{
		{ // inet6 first
			"set interfaces ge-0-0-0 unit 0 family inet6 address 2001:db8::1/64",
			"set interfaces ge-0-0-0 unit 0 family inet address 10.0.0.1/24",
			"set interfaces ge-0-0-0 unit 0 family inet mtu 1000",
		},
		{ // inet first — the fold is order-independent (#10050)
			"set interfaces ge-0-0-0 unit 0 family inet address 10.0.0.1/24",
			"set interfaces ge-0-0-0 unit 0 family inet mtu 1000",
			"set interfaces ge-0-0-0 unit 0 family inet6 address 2001:db8::1/64",
		},
	} {
		_, err := CompileConfig(flatTreeFromSets(t, sets...))
		if err == nil {
			t.Fatalf("strict commit ACCEPTED an IPv6-bearing unit whose inet mtu folds to 1000 (< 1280): %v", sets)
		}
		if !strings.Contains(err.Error(), "#13936") {
			t.Errorf("error %q does not cite #13936", err.Error())
		}
	}
}

// The interface-level spelling: no family mtu at all, but the
// interface-level `mtu` the untagged unit inherits is below 1280.
func TestIPv6UnitMTUInterfaceLevelRejected13936(t *testing.T) {
	assertCommitRejects(t, flatTreeFromSets(t,
		"set interfaces ge-0-0-0 mtu 1000",
		"set interfaces ge-0-0-0 unit 0 family inet6 address 2001:db8::1/64",
	), "#13936")
}

// The tagged spelling: the unit's own MTU lands on the VLAN child.
func TestIPv6TaggedUnitMTUBelowMinimumRejected13936(t *testing.T) {
	assertCommitRejects(t, flatTreeFromSets(t,
		"set interfaces ge-0-0-2 vlan-tagging",
		"set interfaces ge-0-0-2 mtu 1500",
		"set interfaces ge-0-0-2 unit 50 vlan-id 50",
		"set interfaces ge-0-0-2 unit 50 family inet6 address 2001:db8:50::1/64",
		"set interfaces ge-0-0-2 unit 50 family inet6 mtu 1279",
	), "#13936")
}

// IPv6 presence via DHCPv6 (no static address) still makes the unit
// IPv6-bearing: the kernel removes the DHCPv6-learned addresses too.
func TestIPv6UnitMTUDHCPv6Rejected13936(t *testing.T) {
	assertCommitRejects(t, flatTreeFromSets(t,
		"set interfaces ge-0-0-0 unit 0 family inet6 dhcpv6",
		"set interfaces ge-0-0-0 unit 0 family inet6 mtu 1000",
	), "#13936")
}

// Hierarchical spelling reaches the same gate.
func TestIPv6UnitMTUHierarchicalRejected13936(t *testing.T) {
	assertCommitRejects(t, hierTree(t, `interfaces {
    ge-0-0-0 {
        unit 0 {
            family inet6 {
                address 2001:db8::1/64;
                mtu 1000;
            }
        }
    }
}`), "#13936")
}

// Unit 0 and unit 1 share the physical link. The planner writes the lowest
// referenced untagged unit MTU (1000) to that link, so an IPv6-bearing sibling
// with no family MTU still has an effective link MTU below 1280.
func TestIPv6UnitMTULowReferencedSiblingRejected13936(t *testing.T) {
	assertCommitRejects(t, flatTreeFromSets(t,
		"set interfaces ge-0-0-0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0-0-0 unit 0 family inet mtu 1000",
		"set interfaces ge-0-0-0 unit 1 family inet6 address 2001:db8:1::1/64",
		"set security zones security-zone trust interfaces ge-0-0-0.0",
		"set security zones security-zone trust interfaces ge-0-0-0.1",
	), "interfaces ge-0-0-0 unit 1: effective mtu 1000")
}

// Controls: the boundary and every non-IPv6 / no-committed-MTU shape
// still commit.
func TestIPv6UnitMTUControlsAccepted13936(t *testing.T) {
	cases := map[string][]string{
		// Boundary: exactly 1280 is the RFC 8200 §5 minimum.
		"inet6 mtu exactly 1280": {
			"set interfaces ge-0-0-0 unit 0 family inet6 address 2001:db8::1/64",
			"set interfaces ge-0-0-0 unit 0 family inet6 mtu 1280",
		},
		"inet6 mtu above minimum": {
			"set interfaces ge-0-0-0 unit 0 family inet6 address 2001:db8::1/64",
			"set interfaces ge-0-0-0 unit 0 family inet6 mtu 1500",
		},
		// IPv4-only unit: a sub-1280 MTU is legitimate (IPv4 has no
		// 1280 floor) and must not newly refuse.
		"ipv4-only unit below 1280": {
			"set interfaces ge-0-0-0 unit 0 family inet address 10.0.0.1/24",
			"set interfaces ge-0-0-0 unit 0 family inet mtu 1000",
		},
		// IPv4-only interface below 1280.
		"ipv4-only interface below 1280": {
			"set interfaces ge-0-0-0 mtu 1000",
			"set interfaces ge-0-0-0 unit 0 family inet address 10.0.0.1/24",
		},
		// No MTU statement anywhere: the commit cannot see the running
		// MTU — same no-check case as #9837.
		"ipv6 unit with no mtu statement": {
			"set interfaces ge-0-0-0 unit 0 family inet6 address 2001:db8::1/64",
		},
		// A unit-level mtu at/above 1280 overrides a below-minimum
		// interface level: the unit override is what the planner
		// writes for the untagged unit.
		"unit mtu overrides low interface mtu": {
			"set interfaces ge-0-0-0 mtu 1000",
			"set interfaces ge-0-0-0 unit 0 family inet6 address 2001:db8::1/64",
			"set interfaces ge-0-0-0 unit 0 family inet6 mtu 1500",
			"set security zones security-zone trust interfaces ge-0-0-0.0",
		},
	}
	for name, sets := range cases {
		t.Run(name, func(t *testing.T) {
			assertCommitAccepts(t, flatTreeFromSets(t, sets...))
		})
	}
}

// The tolerant load / peer-sync path downgrades to a warning (#1960
// no-brick), mirroring the #9837 sibling gate.
func TestIPv6UnitMTULenientWarns13936(t *testing.T) {
	cfg, err := CompileConfigLenient(flatTreeFromSets(t,
		"set interfaces ge-0-0-0 unit 0 family inet6 address 2001:db8::1/64",
		"set interfaces ge-0-0-0 unit 0 family inet6 mtu 1000",
	))
	if err != nil {
		t.Fatalf("lenient compile must not hard-fail: %v", err)
	}
	joined := strings.Join(cfg.Warnings, "\n")
	for _, want := range []string{"1000", "1280", "#13936"} {
		if !strings.Contains(joined, want) {
			t.Errorf("lenient warnings %q do not name %q", joined, want)
		}
	}
}

// First-error stability: sorted visit order names the lowest interface
// and unit regardless of map iteration.
func TestIPv6UnitMTUFirstErrorStable13936(t *testing.T) {
	_, err := CompileConfig(flatTreeFromSets(t,
		"set interfaces ge-0-0-3 unit 0 family inet6 address 2001:db8:3::1/64",
		"set interfaces ge-0-0-3 unit 0 family inet6 mtu 900",
		"set interfaces ge-0-0-1 unit 0 family inet6 address 2001:db8:1::1/64",
		"set interfaces ge-0-0-1 unit 0 family inet6 mtu 1000",
	))
	if err == nil {
		t.Fatal("strict commit ACCEPTED IPv6-bearing units below 1280")
	}
	if !strings.Contains(err.Error(), "ge-0-0-1") || !strings.Contains(err.Error(), "1000") {
		t.Errorf("first error %q does not name the sorted-first offender ge-0-0-1/1000", err.Error())
	}
}

// Compiler-only family-presence evidence must not change the snapshot wire
// contract. Persisted IPv6 identity remains discoverable from addresses and
// DHCPv6 state after reload.
func TestIPv6FamilyEvidenceIsNotOnSnapshotWire13936(t *testing.T) {
	encoded, err := json.Marshal(InterfaceUnit{FamilyInet6: true})
	if err != nil {
		t.Fatalf("marshal interface unit: %v", err)
	}
	if strings.Contains(string(encoded), "FamilyInet6") {
		t.Fatalf("compiler-only inet6-family evidence leaked onto config snapshot wire: %s", encoded)
	}
}
