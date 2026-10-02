package routing

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func bestLeakRule11396(ops *fakeRuleOps, destination, ingress string) (netlink.Rule, bool) {
	ip := net.ParseIP(destination)
	if ip == nil {
		return netlink.Rule{}, false
	}
	var best *netlink.Rule
	for i := range ops.rules[unix.AF_INET] {
		rule := &ops.rules[unix.AF_INET][i]
		if rule.Dst == nil || !rule.Dst.Contains(ip) {
			continue
		}
		if rule.IifName != "" && rule.IifName != ingress {
			continue
		}
		if rule.OifName != "" {
			continue
		}
		if best == nil || rule.Priority < best.Priority {
			best = rule
		}
	}
	if best == nil {
		return netlink.Rule{}, false
	}
	return *best, true
}

func TestRibGroupOverlapPrefersLongestPrefix11396(t *testing.T) {
	for _, order := range []struct {
		name      string
		instances []*config.RoutingInstanceConfig
	}{
		{
			name: "vr-a-declared-first",
			instances: []*config.RoutingInstanceConfig{
				{Name: "vr-a", TableID: 501, InterfaceRoutesRibGroup: "leak"},
				{Name: "vr-b", TableID: 502, InterfaceRoutesRibGroup: "leak"},
			},
		},
		{
			name: "vr-b-declared-first",
			instances: []*config.RoutingInstanceConfig{
				{Name: "vr-b", TableID: 502, InterfaceRoutesRibGroup: "leak"},
				{Name: "vr-a", TableID: 501, InterfaceRoutesRibGroup: "leak"},
			},
		},
	} {
		t.Run(order.name, func(t *testing.T) {
			ops := newFakeRuleOps()
			rg := &ribGroupManager{ops: ops}
			ribGroups := map[string]*config.RibGroup{
				"leak": {Name: "leak", ImportRibs: []string{"inet.0"}},
			}
			connected := map[string][]string{
				"vr-a": {"10.0.0.0/8"},
				"vr-b": {"10.1.2.0/24"},
			}
			if err := rg.Apply(ribGroups, order.instances, connected); err != nil {
				t.Fatalf("rib-group Apply: %v", err)
			}

			winner, ok := bestLeakRule11396(ops, "10.1.2.5", "ge-0-0-0")
			if !ok {
				t.Fatalf("no leaked rule matches the probe: %v", ops.rules[unix.AF_INET])
			}
			if winner.Table != 502 || winner.Dst.String() != "10.1.2.0/24" {
				t.Fatalf("lookup selected table %d via %s at priority %d; want VR-B table 502 via 10.1.2.0/24, rules=%v",
					winner.Table, winner.Dst, winner.Priority, ops.rules[unix.AF_INET])
			}
		})
	}
}

func TestMixedLeakKindsPreferLongestPrefix11396(t *testing.T) {
	for _, order := range []struct {
		name      string
		instances []*config.RoutingInstanceConfig
	}{
		{
			name: "vr-a-declared-first",
			instances: []*config.RoutingInstanceConfig{
				{Name: "vr-a", TableID: 501},
				{Name: "vr-b", TableID: 502},
			},
		},
		{
			name: "vr-b-declared-first",
			instances: []*config.RoutingInstanceConfig{
				{Name: "vr-b", TableID: 502},
				{Name: "vr-a", TableID: 501},
			},
		},
	} {
		for _, narrowKind := range []string{"next-table", "rib-group"} {
			t.Run(order.name+"/narrow-"+narrowKind, func(t *testing.T) {
				instances := make([]*config.RoutingInstanceConfig, 0, len(order.instances))
				for _, inst := range order.instances {
					instances = append(instances, &config.RoutingInstanceConfig{Name: inst.Name, TableID: inst.TableID})
				}
				ops := newFakeRuleOps()
				var routes []*config.StaticRoute
				connected := map[string][]string{}
				ribGroups := map[string]*config.RibGroup{}
				if narrowKind == "next-table" {
					routes = []*config.StaticRoute{{Destination: "10.1.2.0/24", NextTable: "vr-b"}}
					ribGroups["leak"] = &config.RibGroup{Name: "leak", ImportRibs: []string{"inet.0"}}
					for _, inst := range instances {
						if inst.Name == "vr-a" {
							inst.InterfaceRoutesRibGroup = "leak"
						}
					}
					connected["vr-a"] = []string{"10.0.0.0/8"}
				} else {
					routes = []*config.StaticRoute{{Destination: "10.0.0.0/8", NextTable: "vr-a"}}
					ribGroups["leak"] = &config.RibGroup{Name: "leak", ImportRibs: []string{"inet.0"}}
					for _, inst := range instances {
						if inst.Name == "vr-b" {
							inst.InterfaceRoutesRibGroup = "leak"
						}
					}
					connected["vr-b"] = []string{"10.1.2.0/24"}
				}

				nt := &nextTableManager{ops: ops}
				if err := nt.Apply(routes, instances, testNextTableIifs); err != nil {
					t.Fatalf("next-table Apply: %v", err)
				}
				rg := &ribGroupManager{ops: ops}
				if err := rg.Apply(ribGroups, instances, connected); err != nil {
					t.Fatalf("rib-group Apply: %v", err)
				}

				winner, ok := bestLeakRule11396(ops, "10.1.2.5", testNextTableIifs[0])
				if !ok || winner.Table != 502 {
					t.Fatalf("narrow %s lookup = %+v, matched=%v; want VR-B table 502, rules=%v",
						narrowKind, winner, ok, ops.rules[unix.AF_INET])
				}
			})
		}
	}
}

func TestSharedLeakClearPreservesOtherRuleKind11396(t *testing.T) {
	for _, manager := range []string{"next-table", "rib-group"} {
		t.Run(manager, func(t *testing.T) {
			ops := newFakeRuleOps()
			for _, test := range []struct {
				family      int
				destination string
				bits        int
			}{
				{unix.AF_INET, "10.1.2.0/24", 32},
				{unix.AF_INET6, "2001:db8:1::/64", 128},
			} {
				_, dst, err := net.ParseCIDR(test.destination)
				if err != nil {
					t.Fatal(err)
				}
				prefixLength, _ := dst.Mask.Size()
				ribGroupRule := netlink.NewRule()
				ribGroupRule.Family = test.family
				ribGroupRule.Dst = dst
				ribGroupRule.Table = 501
				ribGroupRule.Priority = config.RouteLeakRulePriority(prefixLength, test.bits, config.RouteLeakRibGroup)
				nextTableRule := netlink.NewRule()
				nextTableRule.Family = test.family
				nextTableRule.Dst = dst
				nextTableRule.Table = 502
				nextTableRule.IifName = testNextTableIifs[0]
				nextTableRule.Priority = config.RouteLeakRulePriority(prefixLength, test.bits, config.RouteLeakNextTable)
				ops.rules[test.family] = append(ops.rules[test.family], *ribGroupRule, *nextTableRule)
			}

			if manager == "next-table" {
				if err := (&nextTableManager{ops: ops}).Apply(nil, nil, testNextTableIifs); err != nil {
					t.Fatalf("next-table Apply: %v", err)
				}
			} else {
				if err := (&ribGroupManager{ops: ops}).Apply(nil, nil, nil); err != nil {
					t.Fatalf("rib-group Apply: %v", err)
				}
			}

			for _, test := range []struct {
				family      int
				destination string
			}{
				{unix.AF_INET, "10.1.2.0/24"},
				{unix.AF_INET6, "2001:db8:1::/64"},
			} {
				var sawRibGroup, sawNextTable bool
				for _, rule := range ops.rules[test.family] {
					if rule.Dst == nil || rule.Dst.String() != test.destination {
						continue
					}
					sawRibGroup = sawRibGroup || rule.IifName == ""
					sawNextTable = sawNextTable || rule.IifName == testNextTableIifs[0]
				}
				if manager == "next-table" && (sawNextTable || !sawRibGroup) {
					t.Errorf("%s clear should remove only next-table rule for %s; rib=%v next=%v",
						manager, test.destination, sawRibGroup, sawNextTable)
				}
				if manager == "rib-group" && (!sawNextTable || sawRibGroup) {
					t.Errorf("%s clear should remove only rib-group rule for %s; rib=%v next=%v",
						manager, test.destination, sawRibGroup, sawNextTable)
				}
			}
		})
	}
}
