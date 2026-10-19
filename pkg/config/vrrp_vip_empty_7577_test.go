package config

import (
	"strings"
	"testing"
)

// #7577: an explicit `vrrp-group` with no advertisable virtual address claims
// its group and advertises nothing. sendAdvert emits a per-family advert only
// when that family's slice is non-empty, so Marshal is never reached and its
// MinAdvertAddrCount floor never fires — while becomeMaster returns true
// regardless and seats the instance in the election.

func vrrpEmptyCfg7577(vips []string) *Config {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"reth0": {
			Units: map[int]*InterfaceUnit{
				0: {
					Number:    0,
					Addresses: []string{"10.0.0.2/24"},
					VRRPGroups: map[string]*VRRPGroup{
						"7": {ID: 7, VirtualAddresses: vips},
					},
				},
			},
		},
	}
	return cfg
}

func TestEmptyVRRPVirtualAddressIsRejectedAtCommit7577(t *testing.T) {
	for _, tc := range []struct {
		name string
		vips []string
		want string // a distinguishing fragment of the expected message
	}{
		// The two causes are reported separately: the remedies differ (add the
		// statement vs fix the literal), and one message would send half the
		// operators looking for the wrong thing.
		{"absent", nil, "has no virtual-address"},
		{"empty slice", []string{}, "has no virtual-address"},
		{"present but unparseable", []string{"not-an-ip", "10.0.0.999"},
			"none of them parses"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateVRRPVIPEmptyStrict(vrrpEmptyCfg7577(tc.vips))
			if err == nil {
				t.Fatalf("accepted a vrrp-group with vips=%q — it would claim "+
					"the group and advertise nothing", tc.vips)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("message does not distinguish the cause:\n got: %v\nwant fragment: %q",
					err, tc.want)
			}
			if !strings.Contains(err.Error(), "vrrp-group 7") {
				t.Errorf("message does not name the offending group: %v", err)
			}
		})
	}
}

// The negative control. Without it every assertion above is satisfied by a
// validator that rejects unconditionally.
func TestParseableVRRPVirtualAddressIsAccepted7577(t *testing.T) {
	for _, tc := range []struct {
		name string
		vips []string
	}{
		{"one ipv4 cidr", []string{"10.0.0.1/24"}},
		{"one ipv4 bare", []string{"10.0.0.1"}},
		{"one ipv6", []string{"2001:db8::1/64"}},
		// The MIDDLE row: a set that is partly unparseable still advertises,
		// because the send path skips the bad entries and emits the good one.
		// Rejecting this would be a false reject on a config that works.
		{"one good among bad", []string{"garbage", "10.0.0.1/24", "also-bad"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateVRRPVIPEmptyStrict(vrrpEmptyCfg7577(tc.vips)); err != nil {
				t.Errorf("rejected an advertisable set %q: %v", tc.vips, err)
			}
		})
	}
}

// SCOPE GUARD. RETH-derived instances must NOT be checked: CollectRethInstances
// already skips a RETH with no VIPs, so no instance is synthesized and there is
// nothing to claim a group. Extending the gate to RETH units would reject
// configuration that is correct today and produces no VRRP instance at all.
//
// This is the test that fails if someone "improves" the validator by reusing
// validateVRRPVIPCountStrict's full walk, which visits RETH units too.
func TestRethUnitWithNoAddressesIsNotRejected7577(t *testing.T) {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"reth1": {
			RedundancyGroup: 1,
			Units: map[int]*InterfaceUnit{
				// No Addresses and no VRRPGroups: CollectRethInstances skips it.
				0: {Number: 0},
			},
		},
	}
	if err := validateVRRPVIPEmptyStrict(cfg); err != nil {
		t.Errorf("rejected a RETH unit with no addresses: %v\n"+
			"CollectRethInstances skips such a RETH, so no VRRP instance is "+
			"created — this config is correct and produces no silent master", err)
	}
}

// A unit with no vrrp-group at all is not a finding either.
func TestUnitWithNoVRRPGroupIsNotRejected7577(t *testing.T) {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0-0-0": {Units: map[int]*InterfaceUnit{0: {Number: 0, Addresses: []string{"10.0.0.2/24"}}}},
	}
	if err := validateVRRPVIPEmptyStrict(cfg); err != nil {
		t.Errorf("rejected a unit carrying no vrrp-group: %v", err)
	}
}

// BIND THE WIRING. validateVRRPVIPEmptyStrict can be entirely correct and never
// run if the call in compiler_uniformgates_cluster_zone.go is dropped — every
// test above stays green through exactly that deletion, certifying a gate the
// operator never hits. This exercises the real compiler entry points.
func TestEmptyVRRPVirtualAddressFailsCommitButNotLenientLoad7577(t *testing.T) {
	// A `vrrp-group` authored with a priority and no virtual-address: the
	// reachable production shape, per #7577 (CollectRethInstances already skips
	// a VIP-less RETH, so an explicit group is the only way to reach it).
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.9.0.1/16 vrrp-group 1 priority 150",
	})

	cfg, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject a vrrp-group with no "+
			"virtual-address: it claims the group and advertises nothing, "+
			"seating a silent non-advertising MASTER; got nil (warnings=%v)",
			cfg.Warnings)
	}
	if !stringContainsAll(err.Error(), "virtual-address", "vrrp-group 1") {
		t.Fatalf("error %q does not name the empty group", err.Error())
	}

	// Tolerant path must NOT brick — #1960 no-brick. Note the asymmetry with
	// #6779 recorded in the validator's doc comment: there is no pkg/vrrp
	// runtime guard behind this downgrade, so a leniently-loaded empty group
	// keeps today's behaviour. That is intended — an empty set claims no
	// addresses, so it cannot produce a duplicate-address collision.
	lcfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("lenient compile must not reject an empty VRRP virtual-address "+
			"set (no-brick), got %v", lerr)
	}
	if !warningsContain(lcfg.Warnings, "virtual-address") {
		t.Fatalf("lenient compile should have warned about the empty VIP set; "+
			"warnings=%v", lcfg.Warnings)
	}
}

// The tightening control for the wiring test: the same shape WITH a
// virtual-address must commit cleanly and warn about nothing. A gate wired to
// reject unconditionally reds here; a gate not wired at all reds above.
func TestVRRPGroupWithVirtualAddressCommitsCleanly7577(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.9.0.1/16 vrrp-group 1 priority 150",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.9.0.1/16 vrrp-group 1 virtual-address 10.9.0.100/16",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("rejected a vrrp-group carrying a virtual-address: %v", err)
	}
	if warningsContain(cfg.Warnings, "empty virtual-address") {
		t.Errorf("warned about an empty VIP set on a group that has one; warnings=%v",
			cfg.Warnings)
	}
}
