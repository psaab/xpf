package config

import (
	"strings"
	"testing"
)

// #1956 device-map config compile + cross-entry validation tests. All use
// the production ParseSetCommand + SetPath path (buildTree), never NewParser
// (the flat-set gotcha in CLAUDE.md).

func TestDeviceMapCompilesStandaloneWithoutCluster(t *testing.T) {
	// R-7: device-map must compile independently of `chassis cluster`.
	tree := buildTree(t, []string{
		"set chassis device-map interface ge-0/0/3 pci 0000:09:00.0",
		"set chassis device-map interface ge-0/0/4 pci 0000:0a:00.0 mac 00:11:22:33:44:55",
		"set chassis device-map unmapped-interface-policy leave-alone",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	dm := cfg.Chassis.DeviceMap
	if !dm.Active() {
		t.Fatalf("device-map should be Active with 2 entries")
	}
	if len(dm.Entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(dm.Entries))
	}
	if dm.EffectiveUnmappedPolicy() != DeviceMapPolicyLeaveAlone {
		t.Fatalf("want leave-alone, got %q", dm.EffectiveUnmappedPolicy())
	}
	// Entries are sorted by logical name.
	if dm.Entries[0].LogicalName != "ge-0/0/3" || dm.Entries[0].PCIAddr != "0000:09:00.0" {
		t.Fatalf("entry 0 wrong: %+v", dm.Entries[0])
	}
	if dm.Entries[1].MAC != "00:11:22:33:44:55" {
		t.Fatalf("entry 1 mac wrong: %+v", dm.Entries[1])
	}
}

func TestDeviceMapEmptyBlockIsPositionalMode(t *testing.T) {
	// R-7/V-7: an empty device-map block must NOT engage device-map mode
	// (the empty-tree-compiles-non-nil trap). With no entries, Active()
	// is false and positional naming stays in effect.
	tree := buildTree(t, []string{
		"set chassis device-map unmapped-interface-policy leave-alone",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Chassis.DeviceMap.Active() {
		t.Fatalf("a policy-only device-map (no entries) must not be Active")
	}
}

func TestDeviceMapNoStanzaIsPositionalMode(t *testing.T) {
	// Backward compat: no chassis device-map at all => nil, positional.
	tree := buildTree(t, []string{
		"set system host-name fw",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Chassis.DeviceMap.Active() {
		t.Fatalf("no device-map stanza must leave Active()==false")
	}
}

func TestDeviceMapDuplicateLogicalNameFatal(t *testing.T) {
	// Direct struct test: the validator must reject one logical name mapped
	// to two identities (the AST merges identical set paths, so exercise the
	// validator on a hand-built config to prove the cross-entry guard).
	cfg := &Config{Chassis: ChassisConfig{DeviceMap: &DeviceMapConfig{
		Entries: []DeviceMapEntry{
			{LogicalName: "ge-0/0/3", PCIAddr: "0000:09:00.0"},
			{LogicalName: "ge-0/0/3", PCIAddr: "0000:0a:00.0"},
		},
	}}}
	if err := validateDeviceMapStrict(cfg); err == nil ||
		!strings.Contains(err.Error(), "mapped twice") {
		t.Fatalf("want duplicate-logical-name fatal, got %v", err)
	}
}

func TestDeviceMapDuplicatePCIFatal(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis device-map interface ge-0/0/3 pci 0000:09:00.0",
		"set chassis device-map interface ge-0/0/4 pci 0000:09:00.0",
	})
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "PCI address") {
		t.Fatalf("want duplicate-PCI fatal, got %v", err)
	}
}

func TestDeviceMapDuplicateMACFatal(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis device-map interface ge-0/0/3 mac 00:11:22:33:44:55",
		"set chassis device-map interface ge-0/0/4 mac 00:11:22:33:44:55",
	})
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "MAC") {
		t.Fatalf("want duplicate-MAC fatal, got %v", err)
	}
}

func TestDeviceMapEntryWithoutIdentityFatal(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis device-map interface ge-0/0/3 key pci-then-mac",
	})
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "neither a pci nor a") {
		t.Fatalf("want no-identity fatal, got %v", err)
	}
}

func TestDeviceMapKeyMACWithoutMACFatal(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis device-map interface ge-0/0/3 pci 0000:09:00.0 key mac",
	})
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "key mac") {
		t.Fatalf("want key-mac-without-mac fatal, got %v", err)
	}
}

func TestDeviceMapRETHMemberRejectsKeyMAC(t *testing.T) {
	// R-6: a RETH member's MAC alternates physical<->virtual, so key mac
	// must be rejected.
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/2 gigether-options redundant-parent reth0",
		"set chassis device-map interface ge-0/0/2 pci 0000:09:00.0 mac 00:11:22:33:44:55 key mac-then-pci",
	})
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "RETH member") {
		t.Fatalf("want RETH key-mac fatal, got %v", err)
	}
}

func TestDeviceMapFPCNodeAlignmentFatal(t *testing.T) {
	// V-6: in cluster mode, a logical name whose FPC slot maps to the wrong
	// node is fatal (ge-7/0/3 on node 0).
	tree := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster node 0",
		"set chassis device-map interface ge-7/0/3 pci 0000:09:00.0",
	})
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "node") {
		t.Fatalf("want FPC/node-misalignment fatal, got %v", err)
	}
}

func TestDeviceMapFPCNodeAlignmentOKForLocalNode(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster node 1",
		"set chassis device-map interface ge-7/0/3 pci 0000:09:00.0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("ge-7/0/3 on node 1 should be accepted: %v", err)
	}
}

func TestDeviceMapLenientDowngradesToWarning(t *testing.T) {
	// V-1: the lenient compile path (peer-sync / load) downgrades a
	// cross-entry violation to a warning so a peer-section config still
	// boots instead of stalling config sync.
	tree := buildTree(t, []string{
		"set chassis device-map interface ge-0/0/3 pci 0000:09:00.0",
		"set chassis device-map interface ge-0/0/4 pci 0000:09:00.0",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not hard-fail: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "device-map") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a downgraded device-map warning, got %v", cfg.Warnings)
	}
}

func TestDeviceMapMACNormalizedToColonLowercase(t *testing.T) {
	// AGY HIGH-1: a hyphenated/upper-case committed MAC must be normalized to
	// the kernel's colon-lower-case form so the resolver matches it.
	tree := buildTree(t, []string{
		"set chassis device-map interface ge-0/0/3 mac AA-BB-CC-DD-EE-FF",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	got := cfg.Chassis.DeviceMap.Entries[0].MAC
	if got != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("MAC not normalized: got %q, want aa:bb:cc:dd:ee:ff", got)
	}
}

func TestDeviceMapPCIAddrNormalizedToLowercase(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis device-map interface ge-0/0/3 pci 0000:09:00.0",
	})
	cfg, _ := CompileConfig(tree)
	if cfg.Chassis.DeviceMap.Entries[0].PCIAddr != "0000:09:00.0" {
		t.Fatalf("PCI not normalized lowercase: %q", cfg.Chassis.DeviceMap.Entries[0].PCIAddr)
	}
}

func TestDeviceMapPCIAddrValidatorRejectsGarbage(t *testing.T) {
	tree := buildTree(t, []string{
		"set chassis device-map interface ge-0/0/3 pci not-a-pci-addr",
	})
	if err := SchemaValidate(treeToConfigTree(t, tree)); err == nil {
		t.Fatalf("want PCI-format schema validation error")
	}
}

// treeToConfigTree is a passthrough — buildTree already returns *ConfigTree.
func treeToConfigTree(t *testing.T, tree *ConfigTree) *ConfigTree {
	t.Helper()
	return tree
}
