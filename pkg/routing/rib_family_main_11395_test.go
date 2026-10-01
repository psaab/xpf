package routing

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sys/unix"
)

// #11395: Junos RIBs are distinct despite sharing Linux table 254. A v4
// interface-routes rib-group importing only inet6.0 must not leak v4
// connected prefixes; the pre-fix ribGroupLeaksIntoMain returned true on
// ANY main-resolving import regardless of family.
func TestRibGroupV6OnlyImportLeaksNoV4Rules11395(t *testing.T) {
	ops := newFakeRuleOps()
	rg := &ribGroupManager{ops: ops}

	ribGroups := map[string]*config.RibGroup{
		"v6-main-only": {Name: "v6-main-only", ImportRibs: []string{"inet6.0"}},
	}
	instances := []*config.RoutingInstanceConfig{
		{Name: "dmz-vr", TableID: 101, InterfaceRoutesRibGroup: "v6-main-only"},
	}
	connected := map[string][]string{
		"dmz-vr": {"10.0.30.0/24", "2001:db8:30::/64"},
	}

	if err := rg.Apply(ribGroups, instances, connected); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := ops.count(unix.AF_INET); got != 0 {
		t.Errorf("v6-only main import installed %d IPv4 leak rules, want zero: %v",
			got, ops.rules[unix.AF_INET])
	}
	if ops.hasTable(unix.AF_INET, 101) {
		t.Errorf("v6-only main import leaked v4 connected prefix into table 101: %v",
			ops.rules[unix.AF_INET])
	}
}

// #11395 mirror: a v6 slot importing only inet.0 must not leak v6 prefixes.
func TestRibGroupV4OnlyImportLeaksNoV6Rules11395(t *testing.T) {
	ops := newFakeRuleOps()
	rg := &ribGroupManager{ops: ops}

	ribGroups := map[string]*config.RibGroup{
		"v4-main-only": {Name: "v4-main-only", ImportRibs: []string{"inet.0"}},
	}
	instances := []*config.RoutingInstanceConfig{
		{Name: "dmz-vr", TableID: 101, InterfaceRoutesRibGroupV6: "v4-main-only"},
	}
	connected := map[string][]string{
		"dmz-vr": {"10.0.30.0/24", "2001:db8:30::/64"},
	}

	if err := rg.Apply(ribGroups, instances, connected); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := ops.count(unix.AF_INET6); got != 0 {
		t.Errorf("v4-only main import installed %d IPv6 leak rules, want zero: %v",
			got, ops.rules[unix.AF_INET6])
	}
}

// #11395 control: a mixed import still leaks each family through its own slot.
func TestRibGroupMixedImportLeaksBothFamilies11395(t *testing.T) {
	ops := newFakeRuleOps()
	rg := &ribGroupManager{ops: ops}

	ribGroups := map[string]*config.RibGroup{
		"dual-main": {Name: "dual-main", ImportRibs: []string{"inet.0", "inet6.0"}},
	}
	instances := []*config.RoutingInstanceConfig{
		{Name: "dmz-vr", TableID: 101,
			InterfaceRoutesRibGroup:   "dual-main",
			InterfaceRoutesRibGroupV6: "dual-main"},
	}
	connected := map[string][]string{
		"dmz-vr": {"10.0.30.0/24", "2001:db8:30::/64"},
	}

	if err := rg.Apply(ribGroups, instances, connected); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, ok := ops.findDstRule(unix.AF_INET, 101, "10.0.30.0/24"); !ok {
		t.Errorf("mixed main import must still leak the v4 prefix, rules=%v",
			ops.rules[unix.AF_INET])
	}
	if _, ok := ops.findDstRule(unix.AF_INET6, 101, "2001:db8:30::/64"); !ok {
		t.Errorf("mixed main import must still leak the v6 prefix, rules=%v",
			ops.rules[unix.AF_INET6])
	}
}
