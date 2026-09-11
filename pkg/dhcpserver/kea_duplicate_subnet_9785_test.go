package dhcpserver

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

type keaSubnetView9785 struct {
	ID     int    `json:"id"`
	Subnet string `json:"subnet"`
	Pools  []struct {
		Pool string `json:"pool"`
	} `json:"pools"`
}

// renderedSubnets9785 reads the subnet4 or subnet6 list from a generated Kea
// config.
func renderedSubnets9785(t *testing.T, path, family string) []keaSubnetView9785 {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var outer map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &outer); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	var subs []keaSubnetView9785
	if err := json.Unmarshal(outer["Dhcp"+family]["subnet"+family], &subs); err != nil {
		t.Fatalf("%s subnet%s: %v", path, family, err)
	}
	return subs
}

// recordWarnings9785 swaps the manager's warn seam for a recorder.
func recordWarnings9785(m *Manager) *[]string {
	warned := &[]string{}
	m.SetWarnForTesting(func(msg string, args ...any) {
		s := msg
		for _, a := range args {
			s += fmt.Sprintf(" %v", a)
		}
		*warned = append(*warned, s)
	})
	return warned
}

// splitWarnings9785 separates the #1778 ambiguity warnings from the #9785
// duplicate-subnet skip warnings.
func splitWarnings9785(warned []string) (ambiguous, skipped []string) {
	for _, w := range warned {
		switch {
		case strings.Contains(w, "ambiguous Kea subnet selection"):
			ambiguous = append(ambiguous, w)
		case strings.Contains(w, "subnet duplicates one already rendered"):
			skipped = append(skipped, w)
		}
	}
	return ambiguous, skipped
}

func dupSubnetV4Config9785(withDuplicate bool) *config.DHCPServerConfig {
	groups := map[string]*config.DHCPServerGroup{
		"lan-pool": {Name: "lan-pool", Interfaces: []string{"reth1.0"}, Pools: []*config.DHCPPool{
			{Name: "lan-range", Subnet: "10.0.61.0/24", RangeLow: "10.0.61.100", RangeHigh: "10.0.61.199"},
		}},
		"wan-pool": {Name: "wan-pool", Interfaces: []string{"reth2.0"}, Pools: []*config.DHCPPool{
			{Name: "wan-range", Subnet: "10.0.62.0/24", RangeLow: "10.0.62.100", RangeHigh: "10.0.62.199"},
		}},
	}
	if withDuplicate {
		// The #9785 fixture: a second group for the lab LAN subnet on the
		// same interface. g9729 sorts before lan-pool, so the stable order
		// keeps it and skips lan-range.
		groups["g9729"] = &config.DHCPServerGroup{Name: "g9729", Interfaces: []string{"reth1.0"}, Pools: []*config.DHCPPool{
			{Name: "p9729", Subnet: "10.0.61.0/24", RangeLow: "10.0.61.150", RangeHigh: "10.0.61.199"},
		}}
	}
	return &config.DHCPServerConfig{DHCPLocalServer: &config.DHCPLocalServerConfig{Groups: groups}}
}

// TestKea4DuplicatePoolSubnetRendersOnce9785 binds the v4 render belt. Kea
// refuses a second subnet4 with a prefix it already holds and then loads
// nothing, so a duplicate that reached the renderer through the tolerant path
// must be emitted once, with the other subnets and their ids untouched.
func TestKea4DuplicatePoolSubnetRendersOnce9785(t *testing.T) {
	m, _ := testManager(t, map[string]bool{}, "")
	warned := recordWarnings9785(m)
	if err := m.generateKea4Config(dupSubnetV4Config9785(false)); err != nil {
		t.Fatalf("CONTROL BROKE: generateKea4Config without a duplicate: %v", err)
	}
	base := renderedSubnets9785(t, m.confPath4, "4")
	if len(base) != 2 || len(*warned) != 0 {
		t.Fatalf("CONTROL BROKE: want one subnet4 per prefix and no warning, got %+v warned=%v", base, *warned)
	}

	if err := m.generateKea4Config(dupSubnetV4Config9785(true)); err != nil {
		t.Fatalf("generateKea4Config with a duplicate: %v", err)
	}
	got := renderedSubnets9785(t, m.confPath4, "4")
	seen := map[string]keaSubnetView9785{}
	for _, s := range got {
		if _, dup := seen[s.Subnet]; dup {
			t.Fatalf("subnet4 %s rendered twice, which Kea refuses: %+v", s.Subnet, got)
		}
		seen[s.Subnet] = s
	}
	if len(got) != 2 {
		t.Fatalf("want 2 subnet4 entries, got %+v", got)
	}
	if kept := seen["10.0.61.0/24"]; len(kept.Pools) != 1 || kept.Pools[0].Pool != "10.0.61.150 - 10.0.61.199" {
		t.Errorf("want the first pool in stable order (g9729) kept, got %+v", kept.Pools)
	}
	for _, b := range base {
		if seen[b.Subnet].ID != b.ID {
			t.Errorf("subnet %s id %d became %d beside the skipped duplicate", b.Subnet, b.ID, seen[b.Subnet].ID)
		}
	}
	_, skipped := splitWarnings9785(*warned)
	if len(skipped) != 1 || !strings.Contains(skipped[0], "lan-pool") || !strings.Contains(skipped[0], "g9729") {
		t.Errorf("want one skip warning naming the skipped and the kept pool, got %v", *warned)
	}
}

// TestKea6DuplicatePoolSubnetRendersOnce9785 is the same belt for subnet6.
func TestKea6DuplicatePoolSubnetRendersOnce9785(t *testing.T) {
	cfg := &config.DHCPServerConfig{DHCPv6LocalServer: &config.DHCPLocalServerConfig{Groups: map[string]*config.DHCPServerGroup{
		"a6": {Name: "a6", Interfaces: []string{"ge-0-0-1"}, Pools: []*config.DHCPPool{
			{Name: "p", Subnet: "2001:db8:61::/64", RangeLow: "2001:db8:61::10", RangeHigh: "2001:db8:61::20"},
		}},
		"b6": {Name: "b6", Interfaces: []string{"ge-0-0-1"}, Pools: []*config.DHCPPool{
			{Name: "p", Subnet: "2001:db8:61::/64", RangeLow: "2001:db8:61::30", RangeHigh: "2001:db8:61::40"},
		}},
	}}}
	m, _ := testManager(t, map[string]bool{}, "")
	warned := recordWarnings9785(m)
	if err := m.generateKea6Config(cfg); err != nil {
		t.Fatalf("generateKea6Config: %v", err)
	}
	got := renderedSubnets9785(t, m.confPath6, "6")
	if len(got) != 1 || got[0].Subnet != "2001:db8:61::/64" {
		t.Fatalf("want 2001:db8:61::/64 rendered once, got %+v", got)
	}
	if len(got[0].Pools) != 1 || got[0].Pools[0].Pool != "2001:db8:61::10 - 2001:db8:61::20" {
		t.Errorf("want a6's pool kept (first in stable order), got %+v", got[0].Pools)
	}
	if _, skipped := splitWarnings9785(*warned); len(skipped) != 1 {
		t.Errorf("want one skip warning, got %v", *warned)
	}
}

// TestClaimPoolSubnetKeysTheMaskedPrefix9785 pins the belt's key to the one
// the commit gate uses: a host-bit spelling of a claimed network duplicates
// it, a nested prefix of another length does not, and a subnet that does not
// parse claims nothing.
func TestClaimPoolSubnetKeysTheMaskedPrefix9785(t *testing.T) {
	seen := map[netip.Prefix]string{}
	pool := func(name, subnet string) *config.DHCPPool { return &config.DHCPPool{Name: name, Subnet: subnet} }
	if _, dup := claimPoolSubnet(seen, "g", pool("first", "10.0.61.0/24")); dup {
		t.Fatal("the first claim cannot be a duplicate")
	}
	if kept, dup := claimPoolSubnet(seen, "h", pool("hostbits", "10.0.61.1/24")); !dup || kept != "group g pool first" {
		t.Errorf("10.0.61.1/24 after 10.0.61.0/24: want a duplicate of group g pool first, got %q %v", kept, dup)
	}
	if _, dup := claimPoolSubnet(seen, "h", pool("nested", "10.0.61.0/25")); dup {
		t.Error("10.0.61.0/25 is a different prefix and must render")
	}
	for i := 0; i < 2; i++ {
		if _, dup := claimPoolSubnet(seen, "h", pool("bad", "not-a-prefix")); dup {
			t.Error("an unparsable subnet must neither duplicate nor claim")
		}
	}
}
