package config

import (
	"strings"
	"testing"
)

// #14194: the RETH-member set was keyed on the RAW declared interface name
// (`ge-0/0/3`) while the device-map entry was looked up by its RAW spelling
// too. `LinuxIfName` folds slash -> dash, so `ge-0/0/3` and `ge-0-0-3` are
// one interface (#6546 already canonicalises the duplicate-name check that
// way). A slash RETH member paired with a dash device-map entry therefore
// missed the R-6 lookup in validateDeviceMapStrict: `key mac` (and a
// MAC-only entry with no pci) was admitted strict even though the member's
// MAC alternates physical<->virtual. The resolver repeated the raw lookup,
// so its PCI-only defense was skipped too.
//
// FAIL-ON-REVERT: key rethMembers on ifc.Name again (or look up
// rethMembers[e.LogicalName] without canonicalising) and the dash cases
// below commit clean / bind by MAC.

func TestDeviceMapRETHDashAliasRejectsKeyMAC14194(t *testing.T) {
	for _, c := range []struct {
		name  string
		lines []string
	}{
		{
			name: "slash member dash entry key mac",
			lines: []string{
				"set interfaces reth0 redundant-ether-options redundancy-group 1",
				"set interfaces ge-0/0/3 gigether-options redundant-parent reth0",
				"set chassis device-map interface ge-0-0-3 mac 00:11:22:33:44:55 key mac",
			},
		},
		{
			name: "slash member dash entry key mac-then-pci",
			lines: []string{
				"set interfaces reth0 redundant-ether-options redundancy-group 1",
				"set interfaces ge-0/0/3 gigether-options redundant-parent reth0",
				"set chassis device-map interface ge-0-0-3 pci 0000:09:00.0 mac 00:11:22:33:44:55 key mac-then-pci",
			},
		},
		{
			name: "dash member slash entry key mac",
			lines: []string{
				"set interfaces reth0 redundant-ether-options redundancy-group 1",
				"set interfaces ge-0-0-3 gigether-options redundant-parent reth0",
				"set chassis device-map interface ge-0/0/3 mac 00:11:22:33:44:55 key mac",
			},
		},
		{
			// MAC-only entry (no pci) on a RETH member: EffectiveKeyOrder
			// defaults to pci-then-mac, so the key-order arm alone would
			// not fire — the `PCIAddr == ""` arm must also see the alias.
			name: "slash member dash entry mac only no pci",
			lines: []string{
				"set interfaces reth0 redundant-ether-options redundancy-group 1",
				"set interfaces ge-0/0/3 gigether-options redundant-parent reth0",
				"set chassis device-map interface ge-0-0-3 mac 00:11:22:33:44:55",
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, c.lines))
			if err == nil {
				t.Fatalf("strict commit ACCEPTED a MAC-keyed device-map entry for a RETH member under a dash alias; want R-6 rejection")
			}
			if !strings.Contains(err.Error(), "RETH member") {
				t.Fatalf("want RETH member rejection, got %v", err)
			}
		})
	}
}

// TestDeviceMapRETHDashAliasPCIKeyedStillCommits14194 is the negative
// control: a correctly PCI-keyed dash entry for a slash RETH member must
// still commit — the fix must match the alias, not reject dash spellings.
func TestDeviceMapRETHDashAliasPCIKeyedStillCommits14194(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces ge-0/0/3 gigether-options redundant-parent reth0",
		"set chassis device-map interface ge-0-0-3 pci 0000:09:00.0 mac 00:11:22:33:44:55 key pci-then-mac",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("PCI-keyed dash entry for slash RETH member should commit: %v", err)
	}
	if len(cfg.Chassis.DeviceMap.Entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(cfg.Chassis.DeviceMap.Entries))
	}
}

// TestDeviceMapNonRETHDashMACStillCommits14194: a dash MAC entry for a
// NON-RETH interface must still commit — canonicalising the RETH lookup
// must not turn every dash name into a RETH member.
func TestDeviceMapNonRETHDashMACStillCommits14194(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/4 unit 0 family inet address 192.0.2.1/24",
		"set chassis device-map interface ge-0-0-4 mac 00:11:22:33:44:55 key mac",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("non-RETH dash MAC entry should commit: %v", err)
	}
}

// TestDeviceMapWrongNodeDashControl14194 is the decisive slot control from
// the issue: the existing InterfaceSlot check (which already parses the
// dash spelling, #8829) must reject a wrong-node dash entry. This must
// keep passing — the RETH alias fix must not disturb the slot gate.
func TestDeviceMapWrongNodeDashControl14194(t *testing.T) {
	for _, iface := range []string{"ge-7-0-3", "ge-7/0/3"} {
		tree := buildTree(t, []string{
			"set chassis cluster cluster-id 1",
			"set chassis cluster authentication-key test-cluster-psk-14194",
			"set chassis cluster node 0",
			"set chassis device-map interface " + iface + " pci 0000:09:00.0",
		})
		if _, err := CompileConfig(tree); err == nil {
			t.Errorf("strict commit ACCEPTED wrong-node entry %q on node 0; want slot rejection", iface)
		}
	}
	// Local dash control must commit.
	tree := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-14194",
		"set chassis cluster node 0",
		"set chassis device-map interface ge-0-0-3 pci 0000:09:00.0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Errorf("local dash entry ge-0-0-3 on node 0 should commit: %v", err)
	}
}

// TestValidateDeviceMapStrictRETHAliasDirect14194 exercises the validator
// directly (no parser) so both spellings of the MEMBER and both spellings
// of the ENTRY are covered symmetrically.
func TestValidateDeviceMapStrictRETHAliasDirect14194(t *testing.T) {
	mk := func(member, entry string) *Config {
		return &Config{
			Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
				member: {Name: member, RedundantParent: "reth0"},
			}},
			Chassis: ChassisConfig{DeviceMap: &DeviceMapConfig{Entries: []DeviceMapEntry{
				{LogicalName: entry, MAC: "00:11:22:33:44:55", KeyOrder: DeviceMapKeyMAC},
			}}},
		}
	}
	for _, member := range []string{"ge-0/0/3", "ge-0-0-3"} {
		for _, entry := range []string{"ge-0/0/3", "ge-0-0-3"} {
			if err := validateDeviceMapStrict(mk(member, entry)); err == nil {
				t.Errorf("member %q entry %q: want RETH key-mac rejection, got nil", member, entry)
			}
		}
	}
	// Non-member entry with same MAC key must pass the RETH arm.
	cfg := mk("ge-0/0/3", "ge-0/0/4")
	// ge-0/0/4 is not the member; but mk keys the map by member name only,
	// so this config's member is ge-0/0/3 and entry ge-0/0/4 is unrelated.
	if err := validateDeviceMapStrict(cfg); err != nil {
		t.Errorf("non-RETH entry should not be RETH-rejected: %v", err)
	}
}
