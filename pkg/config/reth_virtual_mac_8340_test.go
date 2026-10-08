package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// #8340 (muse-spark-review-004 K18 / K105): the RETH virtual MAC's byte width,
// asserted as an AGREEMENT with the commit gates rather than restated as a
// comment, plus a census that the construction exists exactly once.
//
// Cluster ID and RG occupy one octet each. RETH index and node ID are packed
// into the last octet as `2*rethIndex+nodeID`, using the configured 0..127
// RETH-index range and the two-node 0..1 node-ID range.

// TestRethVirtualMACWidthAgreesWithCommitBounds_8340 is the agreement.
func TestRethVirtualMACWidthAgreesWithCommitBounds_8340(t *testing.T) {
	// Each MAC field is one octet. A commit-time ceiling above 255 would put an
	// id on the wire that the MAC cannot represent.
	if MaxHeartbeatRedundancyGroupID > 255 {
		t.Errorf("#8340: the redundancy-group id ceiling is %d, but the RETH virtual MAC "+
			"carries it in ONE octet. Two groups above 255 would share an L2 identity, which "+
			"is the per-RG identity RethVirtualMAC exists to provide.",
			MaxHeartbeatRedundancyGroupID)
	}
	if MaxRedundancyGroups-1 > 255 {
		t.Errorf("#8340: the dataplane RG-slot ceiling admits id %d, wider than the MAC's octet",
			MaxRedundancyGroups-1)
	}

	// The cluster-id leaf's own description claims it IS one byte of this MAC.
	// Assert the validator agrees, rather than trusting the sentence.
	node := setSchema.children["chassis"].children["cluster"].children["cluster-id"]
	if node == nil || node.validator == nil {
		t.Fatal("PREMISE: the cluster-id leaf must carry a validator, or this agreement is " +
			"unanchored and the assertions below pass vacuously")
	}
	if err := node.validator("255", nil); err != nil {
		t.Errorf("#8340: cluster-id 255 must COMMIT — it is the widest value the MAC octet "+
			"holds, and rejecting it would mean the schema and the MAC disagree in the other "+
			"direction: %v", err)
	}
	if err := node.validator("256", nil); err == nil {
		t.Error("#8340: cluster-id 256 must be REJECTED at commit. The RETH virtual MAC " +
			"carries the cluster id in one octet, so 256 aliases onto 0 — a different " +
			"cluster's MAC on the same L2 segment.")
	}
}

// TestRethVirtualMACIsConstructedOnce_8340 is the census. K105 is the second
// construction: `pkg/dataplane/compiler_iface.go` built the same MAC inline to
// SEARCH for a RETH member whose `.link` rename was lost. A search key and the
// thing it searches for, written twice — a format drift in one would make the
// recovery find nothing and drop the member silently.
//
// They could not be merged before because `pkg/cluster` imports `pkg/dataplane`;
// the constructor now lives in `pkg/config`, the leaf both already depend on.
func TestRethVirtualMACIsConstructedOnce_8340(t *testing.T) {
	// The literal, in either spelling Go source uses for it.
	lit := regexp.MustCompile(`0x02,\s*0xbf,\s*0x72`)
	var hits []string
	roots := []string{
		filepath.Join("..", "config"),
		filepath.Join("..", "cluster"),
		filepath.Join("..", "dataplane"),
		filepath.Join("..", "daemon"),
	}
	var scanned int
	for _, root := range roots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
				strings.HasSuffix(path, "_test.go") {
				return nil
			}
			scanned++
			src, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			if lit.Match(src) {
				hits = append(hits, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	// POSITIVE CONTROL, first. A census that scanned nothing finds nothing and
	// passes forever — and it is the thing you would consult to discover that.
	if scanned < 100 {
		t.Fatalf("the census scanned only %d non-test Go files across %v; the walk is not "+
			"reaching the packages it claims to cover, so its result is not evidence",
			scanned, roots)
	}
	if len(hits) == 0 {
		t.Fatalf("the census found NO construction of the 02:bf:72 RETH MAC prefix in %d "+
			"files. Either the format changed — in which case this test's subject moved — or "+
			"the pattern has rotted and it is asserting nothing", scanned)
	}

	want := filepath.Join("..", "config", "reth_virtual_mac_8340.go")
	if len(hits) != 1 || hits[0] != want {
		t.Errorf("#8340 (K105): the RETH virtual MAC must be constructed in exactly ONE place "+
			"(%s). Found %d: %v.\nA second copy is a search key written twice: the daemon "+
			"programs one and the dataplane's recovery path searches for the other, so a "+
			"format drift in either makes the search find nothing and the RETH member is "+
			"dropped from the config with no diagnostic.", want, len(hits), hits)
	}
}

// TestRethVirtualMACBytes_8340 pins the format itself, so the census above
// cannot be satisfied by a single construction that builds the WRONG MAC.
func TestRethVirtualMACBytes_8340(t *testing.T) {
	mac := RethVirtualMAC(7, 3, 0, 1)
	want := []byte{0x02, 0xbf, 0x72, 7, 3, 1}
	if len(mac) != len(want) {
		t.Fatalf("RethVirtualMAC length = %d, want %d", len(mac), len(want))
	}
	for i := range want {
		if mac[i] != want[i] {
			t.Fatalf("RethVirtualMAC(7,3,0,1) = %v, want %v", mac, want)
		}
	}
}

func TestRethVirtualMACIndexUniqueness_12157(t *testing.T) {
	seen := make(map[string]struct{}, MaxRethCount*2)
	for rethIndex := range MaxRethCount {
		for nodeID := range 2 {
			mac := RethVirtualMAC(7, 3, rethIndex, nodeID).String()
			if _, exists := seen[mac]; exists {
				t.Fatalf("duplicate RETH virtual MAC at index %d, node %d: %s", rethIndex, nodeID, mac)
			}
			seen[mac] = struct{}{}
		}
	}
}

func TestRethIndex_12157(t *testing.T) {
	for name, want := range map[string]int{"reth0": 0, "reth1": 1, "reth127": 127} {
		got, ok := RethIndex(name)
		if !ok || got != want {
			t.Errorf("RethIndex(%q) = (%d, %v), want (%d, true)", name, got, ok, want)
		}
	}
	for _, name := range []string{"", "reth", "reth-1", "reth128", "reth01", "reth1.0", "ge-0/0/1"} {
		if got, ok := RethIndex(name); ok {
			t.Errorf("RethIndex(%q) = (%d, true), want invalid", name, got)
		}
	}
}

func TestRethMACIndexesCoverStructuralOwnerNames_12157(t *testing.T) {
	build := func(ownerOrder []string) *Config {
		interfaces := map[string]*InterfaceConfig{
			"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth0"},
			"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "bond0"},
			"reth0":    {Name: "reth0", RedundancyGroup: 1},
			"bond0":    {Name: "bond0", RedundancyGroup: 1},
		}
		ordered := make(map[string]*InterfaceConfig, len(interfaces))
		for _, name := range ownerOrder {
			ordered[name] = interfaces[name]
		}
		for name, ifc := range interfaces {
			if _, exists := ordered[name]; !exists {
				ordered[name] = ifc
			}
		}
		return &Config{Interfaces: InterfacesConfig{Interfaces: ordered}}
	}

	want := map[string]int{"reth0": 0, "bond0": 1}
	for _, order := range [][]string{{"reth0", "bond0"}, {"bond0", "reth0"}} {
		got := build(order).RethMACIndexes()
		if len(got) != len(want) {
			t.Fatalf("RethMACIndexes = %v, want %v", got, want)
		}
		for name, index := range want {
			if got[name] != index {
				t.Errorf("RethMACIndexes[%q] = %d, want %d (all: %v)", name, got[name], index, got)
			}
		}
	}
}

func TestStrictRethOwnerLimitMatchesVirtualMACCapacity_12157(t *testing.T) {
	interfaces := make(map[string]*InterfaceConfig, (MaxRethCount+1)*2)
	for i := range MaxRethCount + 1 {
		owner := fmt.Sprintf("owner%d", i)
		member := fmt.Sprintf("ge-0/0/%d", i)
		interfaces[owner] = &InterfaceConfig{Name: owner, RedundancyGroup: 1}
		interfaces[member] = &InterfaceConfig{Name: member, RedundantParent: owner}
	}
	cfg := &Config{Interfaces: InterfacesConfig{Interfaces: interfaces}}
	if err := validateRethRedundancyGroupStrict(cfg); err == nil {
		t.Fatal("strict validation accepted more RETH owners than the virtual-MAC index can represent")
	}
}
