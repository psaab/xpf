package config

import "testing"

// #17170: "does this cluster run RETH VRRP?" was open-coded 11 times as
// `NoRethVRRP || PrivateRGElection` with differing nil semantics, and the
// one named wrapper (Daemon.isNoRethVRRP) was documented as if the compiler
// default were legacy VRRP — the opposite of the truth (private-RG election
// is the compiler default). RethOwnershipMode/UsesRethVRRP on ClusterConfig
// are the single derived reading; this table pins all four bool
// combinations plus nil so a precedence or nil-semantics regression fails
// here instead of diverging across callers again.
//
// FAIL-ON-REVERT: on pre-fix code this test does not compile (the methods
// do not exist); reverting the precedence so NoRethVRRP wins, or treating a
// nil config as legacy VRRP, fails the both-set and nil rows.
func TestClusterConfigRethOwnershipMode17170(t *testing.T) {
	tests := []struct {
		name       string
		cc         *ClusterConfig
		wantMode   RethOwnershipMode
		wantUsesVR bool
	}{
		{"nil cluster config", nil, RethOwnershipUnknown, false},
		{"legacy neither flag", &ClusterConfig{}, RethVRRP, true},
		{"no-reth-vrrp only", &ClusterConfig{NoRethVRRP: true}, RethDirectNoVRRP, false},
		{"private-rg-election only", &ClusterConfig{PrivateRGElection: true}, RethPrivateRG, false},
		{"both set private rg wins", &ClusterConfig{NoRethVRRP: true, PrivateRGElection: true}, RethPrivateRG, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cc.RethOwnershipMode(); got != tc.wantMode {
				t.Errorf("RethOwnershipMode() = %v, want %v", got, tc.wantMode)
			}
			if got := tc.cc.UsesRethVRRP(); got != tc.wantUsesVR {
				t.Errorf("UsesRethVRRP() = %v, want %v", got, tc.wantUsesVR)
			}
		})
	}
}

// The compiler default (no mode flag) must classify as private-RG election:
// a plain cluster stanza suppresses RETH VRRP. This is the control cell the
// old isNoRethVRRP doc got backwards. Compile shape mirrors
// TestChassisClusterNoRethVRRPDefault (authentication-key is required).
func TestClusterConfigRethOwnershipModeCompilerDefault17170(t *testing.T) {
	compile := func(input string) *ClusterConfig {
		tree, errs := NewParser(input).Parse()
		if len(errs) > 0 {
			t.Fatal(errs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Chassis.Cluster == nil {
			t.Fatal("compiled config has no cluster config")
		}
		return cfg.Chassis.Cluster
	}

	cc := compile("chassis {\n    cluster {\n        authentication-key test-cluster-psk-6611;\n        cluster-id 1;\n    }\n}")
	if cc.NoRethVRRP {
		t.Fatal("compiler default must leave NoRethVRRP false")
	}
	if got := cc.RethOwnershipMode(); got != RethPrivateRG {
		t.Errorf("compiler default RethOwnershipMode() = %v, want RethPrivateRG", got)
	}
	if cc.UsesRethVRRP() {
		t.Error("compiler default must not use RETH VRRP")
	}

	lcc := compile("chassis {\n    cluster {\n        authentication-key test-cluster-psk-6611;\n        cluster-id 1;\n        no-private-rg-election;\n    }\n}")
	if got := lcc.RethOwnershipMode(); got != RethVRRP {
		t.Errorf("no-private-rg-election RethOwnershipMode() = %v, want RethVRRP", got)
	}
	if !lcc.UsesRethVRRP() {
		t.Error("no-private-rg-election must use RETH VRRP")
	}
}
