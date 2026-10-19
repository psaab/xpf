package config

import "testing"

// #6781: `redundant-ether-options redundancy-group <N>` on an interface that is
// neither structurally nor nominally a redundant-ethernet interface committed
// cleanly and then meant three different things — networkd replaced the
// operator's address with a link-local /32, the VRRP-backed owner claimed the
// real address as a MASTER-only VIP, and the direct owner skipped it, so under
// `no-reth-vrrp` the address was stripped and installed by nobody on BOTH nodes.
//
// FAIL-ON-REVERT: drop the validateRethRedundancyGroupStrict dispatch in
// compiler_uniformgates_routing_rib_rpm.go (or the comparison inside the
// validator) and the reject subtests go green on the BAD config.

func rethRGGateLines(extra ...string) []string {
	return append([]string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6781",
		"set chassis cluster reth-count 2",
		// #15199: RG1 must be a configured data group for the
		// legitimate-reth controls to commit.
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
	}, extra...)
}

func TestRedundancyGroupOnNonRethFailsCommit(t *testing.T) {
	tree := buildTree(t, rethRGGateLines(
		"set interfaces ge-0/0/5 redundant-ether-options redundancy-group 1",
		"set interfaces ge-0/0/5 unit 0 family inet address 10.0.99.1/24",
	))

	cfg, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject redundancy-group on ge-0/0/5 (no "+
			"port names it as a redundant-parent, and it is not named reth*); "+
			"got nil error (warnings=%v)", cfg.Warnings)
	}
	if !stringContainsAll(err.Error(), "ge-0/0/5", "redundant-parent") {
		t.Fatalf("error %q does not name the interface and what it is missing",
			err.Error())
	}

	// Tolerant path must NOT brick (#1960) — and must warn.
	lcfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("lenient compile must not reject (no-brick), got %v", lerr)
	}
	if !warningsContain(lcfg.Warnings, "redundancy-group") {
		t.Fatalf("lenient compile should warn; warnings=%v", lcfg.Warnings)
	}
	// And the leniently-loaded config must leave the interface a PLAIN L3
	// interface — not a half-applied RG owner. This is the property that keeps
	// its address from being replaced by a link-local /32 downstream.
	if _, owns := lcfg.RethRGOwner("ge-0/0/5"); owns {
		t.Errorf("a leniently-loaded ge-0/0/5 must not own a redundancy group; "+
			"owners=%v", lcfg.RethRGOwners())
	}
}

// TestRedundancyGroupOnRealRethCommits is the TIGHTENING control: the gate must
// not over-reject. Both legitimate shapes commit cleanly and own their group.
func TestRedundancyGroupOnRealRethCommits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		owner string
		lines []string
	}{
		{
			name:  "conventional-reth-with-members",
			owner: "reth0",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent reth0",
				"set interfaces reth0 redundant-ether-options redundancy-group 1",
				"set interfaces reth0 unit 0 family inet address 10.0.61.1/24",
			},
		},
		{
			// Structurally a reth, not spelled reth*. Rejecting this for its
			// NAME would turn a working config into a failed commit.
			name:  "structural-pair-not-named-reth",
			owner: "bond0",
			lines: []string{
				"set interfaces ge-0/0/1 gigether-options redundant-parent bond0",
				"set interfaces bond0 redundant-ether-options redundancy-group 1",
				"set interfaces bond0 unit 0 family inet address 10.0.61.1/24",
			},
		},
		{
			// Declared but not yet wired. Deliberately NOT rejected: both
			// ownership modes accepted it before #6781, and narrowing that is
			// out of scope.
			name:  "reth-named-without-members",
			owner: "reth0",
			lines: []string{
				"set interfaces reth0 redundant-ether-options redundancy-group 1",
				"set interfaces reth0 unit 0 family inet address 10.0.61.1/24",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(buildTree(t, rethRGGateLines(tc.lines...)))
			if err != nil {
				t.Fatalf("%s must commit cleanly, got %v", tc.name, err)
			}
			if warningsContain(cfg.Warnings, "redundant-parent") {
				t.Errorf("%s must not warn; warnings=%v", tc.name, cfg.Warnings)
			}
			if _, owns := cfg.RethRGOwner(tc.owner); !owns {
				t.Errorf("%s must own its redundancy group; owners=%v",
					tc.owner, cfg.RethRGOwners())
			}
		})
	}
}

// TestRethRGOwnersExcludesDefaultZeroInterfaces pins the guard the replaced
// name filter was really providing: an RG-0 query must not sweep in every
// interface whose redundancy-group is merely UNSET (fabric, control, mgmt all
// default to 0). The structural/nominal test subsumes it.
func TestRethRGOwnersExcludesDefaultZeroInterfaces(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, rethRGGateLines(
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 10.0.61.1/24",
		"set interfaces ge-0/0/9 unit 0 family inet address 10.0.77.1/24",
	)))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	owners := cfg.RethRGOwners()
	if _, ok := owners["ge-0/0/9"]; ok {
		t.Errorf("an interface with an UNSET redundancy-group must not own "+
			"group 0; owners=%v", owners)
	}
	if _, ok := owners["reth0"]; !ok {
		t.Errorf("reth0 must still own its group; owners=%v", owners)
	}
}
