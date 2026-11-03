package config

import (
	"strings"
	"testing"
)

// #4826: the RETH-derived VRRP GroupID (100+rgID, CollectRethInstances in
// pkg/vrrp/vrrp.go) had no commit-time bound, unlike the explicit
// `vrrp-group <id>` path (#4573, validateVRRPGroupIDStrict). The chassis
// redundancy-group validators have independent heartbeat and dataplane-array
// bounds, neither of which is the VRRP bound. A fixture that declares the same
// overflowing id as a chassis RG is therefore rejected before the VRID gate.
// The integration fixture below declares only in-range chassis RG 1 so the
// reth's overflowing id reaches validateRethVRRPGroupIDStrict, which rejects
// it when the derived VRID (100+id) would overflow the RFC 5798 byte range.
//
// FAIL-ON-REVERT: drop the validateRethVRRPGroupIDStrict dispatch in
// compiler_uniformgates_cluster_zone.go (or the range check inside the
// validator) and the out-of-range subtests below reach the later undefined-RG
// gate, whose error does not have the required VRID out-of-range signature.

// rethRedundancyGroupSetLines returns the flat-set lines for a minimal
// chassis-cluster config with a single reth interface in the given
// redundancy-group id. `no-private-rg-election` is required to actually
// activate reth-derived VRRP instance synthesis — private-rg-election
// (election over the control link only, no RETH VRRP) is the compiler
// default for any `chassis cluster` stanza (compiler_system.go), and
// CollectRethInstances early-returns nil while it is set, same as
// no-reth-vrrp. Only chassis RG 1 is declared, independently of the reth's
// target id: an overflowing declaration would trip the chassis 0..15 array
// bound first, while an undefined reth target is checked only after the VRID
// gate under test.
func rethRedundancyGroupSetLines(id string) []string {
	return []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.99.0.2",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster reth-count 1",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces reth0 redundant-ether-options redundancy-group " + id,
	}
}

// rethVRRPValidatorConfig builds the typed input for boundary and mode cells
// whose ids cannot be declared as chassis RGs without tripping an earlier gate.
func rethVRRPValidatorConfig(id int, cluster *ClusterConfig) *Config {
	return &Config{
		Chassis: ChassisConfig{Cluster: cluster},
		Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
			"reth0": {Name: "reth0", RedundancyGroup: id},
		}},
	}
}

func TestRethRedundancyGroupIDOverflowsVRIDFailsCommit(t *testing.T) {
	// 156 is the first id whose derived VRID (100+156=256) overflows the
	// single wire byte; 255 is the chassis validator's own ceiling.
	for _, id := range []string{"156", "200", "255"} {
		t.Run("id="+id, func(t *testing.T) {
			tree := buildTree(t, rethRedundancyGroupSetLines(id))
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("expected commit to reject reth redundancy-group %s "+
					"(derived VRID 100+%s overflows the RFC 5798 byte range), "+
					"got nil error", id, id)
			} else if !stringContainsAll(err.Error(),
				"redundancy-group "+id+" is out of range 1..155",
				"VRRP GroupID") {
				t.Fatalf("error %q does not pin the VRID overflow for "+
					"redundancy-group id %s", err.Error(), id)
			}

			// Tolerant path (load / peer-sync) must NOT brick — it downgrades
			// to a warning so an already-persisted config still boots (#1960).
			lcfg, lerr := CompileConfigLenient(tree)
			if lerr != nil {
				t.Fatalf("lenient compile must not reject an out-of-range "+
					"reth redundancy-group id (no-brick), got %v", lerr)
			}
			if !warningsContain(lcfg.Warnings, "redundancy-group") {
				t.Fatalf("lenient compile should have warned about the "+
					"reth redundancy-group id; warnings=%v", lcfg.Warnings)
			}
		})
	}
}

func TestRethRedundancyGroupIDInRangeCommits(t *testing.T) {
	// 1 and 155 are the boundaries: 100+155=255 still fits the VRID byte.
	// Keep id=1 as a full compile integration cell. Ids 100 and 155 cannot be
	// declared as chassis RGs without tripping the earlier 0..15 array gate,
	// so their in-range VRID behavior is pinned directly at the validator.
	t.Run("id=1", func(t *testing.T) {
		tree := buildTree(t, rethRedundancyGroupSetLines("1"))
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("in-range reth redundancy-group 1 must commit "+
				"cleanly, got %v", err)
		}
		if warningsContain(cfg.Warnings, "redundancy-group") {
			t.Fatalf("in-range reth redundancy-group 1 should not warn; "+
				"warnings=%v", cfg.Warnings)
		}
	})
	for _, tc := range []struct {
		name string
		id   int
	}{
		{name: "id=100", id: 100},
		{name: "id=155", id: 155},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := rethVRRPValidatorConfig(tc.id, &ClusterConfig{})
			if err := validateRethVRRPGroupIDStrict(cfg); err != nil {
				t.Fatalf("in-range reth redundancy-group %d must pass "+
					"VRID validation, got %v", tc.id, err)
			}
		})
	}
}

// TestRethRedundancyGroupIDOverflowSkippedWhenRGElectionPrivate pins that
// the gate mirrors CollectRethInstances' own early return: private RG
// election (the compiler default for any `chassis cluster` stanza — no
// synthesized RETH VRRP instance at all, election happens over the control
// link only) means an overflowing redundancy-group id has no runtime
// consequence and must not be rejected. This is a direct validator cell:
// declaring chassis RG 200 would trip the earlier chassis array bound.
func TestRethRedundancyGroupIDOverflowSkippedWhenRGElectionPrivate(t *testing.T) {
	cfg := rethVRRPValidatorConfig(200, &ClusterConfig{PrivateRGElection: true})
	if err := validateRethVRRPGroupIDStrict(cfg); err != nil {
		t.Fatalf("default private-rg-election must not reject an "+
			"overflowing redundancy-group id (no synthesized VRRP "+
			"instance), got %v", err)
	}
}

// TestRethRedundancyGroupIDOverflowSkippedUnderNoRethVRRP is the legacy-VRRP
// sibling: with no-private-rg-election active (so reth VRRP would otherwise
// synthesize), explicit no-reth-vrrp still suppresses instance creation
// entirely and the overflowing id must not be rejected. This is a direct
// validator cell for the same chassis-array-bound reason as its private-RG
// sibling.
func TestRethRedundancyGroupIDOverflowSkippedUnderNoRethVRRP(t *testing.T) {
	cfg := rethVRRPValidatorConfig(200, &ClusterConfig{NoRethVRRP: true})
	if err := validateRethVRRPGroupIDStrict(cfg); err != nil {
		t.Fatalf("no-reth-vrrp must not reject an overflowing "+
			"redundancy-group id (no synthesized VRRP instance), got %v", err)
	}
}

// stringContainsAll reports whether s contains every substring in subs.
func stringContainsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
