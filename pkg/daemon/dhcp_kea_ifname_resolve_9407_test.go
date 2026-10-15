package daemon

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9407. The Kea interface derivation was LinuxIfName(ResolveReth(ref)) — the
// slash rewrite plus the RETH member map, and nothing else. That is TWO arms
// short of Config.ResolveKernelIfName, and both gaps produce a name Kea cannot
// bind:
//
//	reth1.0             -> "ge-0-0-1.0"    dangling unit suffix; not a device
//	reth1.80 (vlan 180) -> "ge-0-0-1.80"   the UNIT number, not the VLAN device
//
// Only the CLUSTER path papered over the first (stripUntaggedUnitSuffix,
// #4647), so the STANDALONE builder named a phantom device on identical
// config. Nothing covered the second on either topology.

func keaCfg9407(t *testing.T) *config.Config {
	t.Helper()
	text := `
chassis {
    cluster {
        node 0;
        reth-count 2;
        redundancy-group 1 { node 0 priority 200; node 1 priority 100; }
    }
}
interfaces {
    ge-0/0/1 {
        gigether-options { redundant-parent reth1; }
    }
    reth1 {
        redundant-ether-options { redundancy-group 1; }
        unit 0 { family inet { address 10.0.61.1/24; } }
        unit 80 { vlan-id 180; family inet { address 10.0.80.1/24; } }
    }
}
`
	tree, perrs := config.NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("fixture must compile: %v", err)
	}
	cfg.System.DHCPServer.DHCPLocalServer = &config.DHCPLocalServerConfig{
		Groups: map[string]*config.DHCPServerGroup{
			"untagged": {Name: "untagged", Interfaces: []string{"reth1.0"}},
			"tagged":   {Name: "tagged", Interfaces: []string{"reth1.80"}},
		},
	}
	cfg.System.DHCPServer.DHCPv6LocalServer = &config.DHCPLocalServerConfig{
		Groups: map[string]*config.DHCPServerGroup{
			"untagged6": {Name: "untagged6", Interfaces: []string{"reth1.0"}},
		},
	}
	return cfg
}

// TestKeaInterfaceDerivationNamesRealDevices9407 pins both missing arms.
func TestKeaInterfaceDerivationNamesRealDevices9407(t *testing.T) {
	cfg := keaCfg9407(t)
	out := resolveDHCPRethInterfaces(cfg.System.DHCPServer, cfg)

	for _, tc := range []struct {
		family, group, want, why string
		local                    *config.DHCPLocalServerConfig
	}{
		{"v4", "untagged", "ge-0-0-1", "unit 0 collapses; `ge-0-0-1.0` is not a device", out.DHCPLocalServer},
		{"v4", "tagged", "ge-0-0-1.180", "the device is the VLAN ID (180), not the unit number (80)", out.DHCPLocalServer},
		{"v6", "untagged6", "ge-0-0-1", "the v6 family shares the derivation", out.DHCPv6LocalServer},
	} {
		g := tc.local.Groups[tc.group]
		if g == nil {
			t.Fatalf("%s group %s missing", tc.family, tc.group)
		}
		if got := g.Interfaces[0]; got != tc.want {
			t.Errorf("%s group %s -> %q, want %q (%s)", tc.family, tc.group, got, tc.want, tc.why)
		}
	}

	// #9141 stays closed: the derivation returns a copy.
	if got := cfg.System.DHCPServer.DHCPLocalServer.Groups["tagged"].Interfaces[0]; got != "reth1.80" {
		t.Fatalf("the shared active config was mutated to %q", got)
	}
}

// TestStandaloneAndClusterAgreeOnKeaDevice9407: the issue's headline symptom is
// "identical config, different behaviour by topology" — the cluster path had a
// strip the standalone path did not. Both builders must now name the same
// device for the same config.
func TestStandaloneAndClusterAgreeOnKeaDevice9407(t *testing.T) {
	cfg := keaCfg9407(t)
	standalone := desiredStandaloneDHCPConfig(cfg)

	// Master both RGs so the cluster filter keeps everything and the comparison
	// is about NAMES, not about mastership narrowing.
	d := masteringRG9407(1)
	cluster := d.desiredClusterDHCPConfigWithMasters(cfg, d.snapshotRethMasterState())
	if cluster == nil {
		t.Fatal("cluster desired config is nil while RG 1 is mastered")
	}

	for _, group := range []string{"untagged", "tagged"} {
		s := standalone.DHCPLocalServer.Groups[group]
		c := cluster.DHCPLocalServer.Groups[group]
		if s == nil || c == nil {
			t.Fatalf("group %s: standalone=%v cluster=%v", group, s, c)
		}
		if !reflect.DeepEqual(s.Interfaces, c.Interfaces) {
			t.Errorf("group %s names %v standalone but %v in cluster — identical "+
				"config must not produce a different device by topology (#9407)",
				group, s.Interfaces, c.Interfaces)
		}
	}
}

// TestTaggedRethGroupIsRGScoped9407 is the consequence the source report did
// not name, and it is worse than a misnamed device.
//
// filterDHCPConfigForMasterRGs compares the group's resolved interface against
// rethInterfacesMatchingRG, which ALREADY derives `<member>.<vlan-id>`. With
// the group resolved to `<member>.<unit>` the two never matched, so the filter
// fell through to its "not RG-scoped implies node-local, always keep" arm and
// kept a redundancy-group-owned tagged segment on a node that masters NOTHING.
// Measured before the fix, with no RG mastered: the group survived as
// `ge-0-0-1.80`.
func TestTaggedRethGroupIsRGScoped9407(t *testing.T) {
	cfg := keaCfg9407(t)

	// No RG mastered: an RG-scoped group must be dropped.
	backup := (&Daemon{}).filterDHCPConfigForMasterRGsWithMasters(cfg, map[int]bool{})
	if backup != nil && backup.DHCPLocalServer != nil {
		if g := backup.DHCPLocalServer.Groups["tagged"]; g != nil {
			t.Errorf("the tagged RETH group survived on a node mastering no RG, as %v. "+
				"It is redundancy-group-scoped; keeping it means BOTH cluster nodes "+
				"serve DHCP on one redundant segment (#9407).", g.Interfaces)
		}
	}

	// Positive control in the same shape: mastering the RG keeps it, so the
	// drop above is mastership narrowing and not the group vanishing outright.
	master := masteringRG9407(1).desiredClusterDHCPConfigWithMasters(cfg, masteringRG9407(1).snapshotRethMasterState())
	if master == nil || master.DHCPLocalServer == nil ||
		master.DHCPLocalServer.Groups["tagged"] == nil {
		t.Fatalf("the tagged group vanished while RG 1 is MASTER: %+v", master)
	}
	if got := master.DHCPLocalServer.Groups["tagged"].Interfaces; len(got) != 1 || got[0] != "ge-0-0-1.180" {
		t.Fatalf("mastered tagged group names %v, want [ge-0-0-1.180]", got)
	}
}

// masteringRG9407 builds a Daemon whose state machine reports the given
// redundancy group as MASTER, so the cluster filter keeps its groups.
func masteringRG9407(rgID int) *Daemon {
	sm := newRGStateMachine()
	sm.SetCluster(true)
	return &Daemon{rgStates: map[int]*rgStateMachine{rgID: sm}}
}

// TestKeaAndRGSetsDeriveNamesIdentically9407 is the #8994-style agreement cell
// for the pair that actually has to agree.
//
// filterDHCPConfigForMasterRGs compares the Kea group's resolved interface
// against the set rethInterfacesMatchingRG builds. Those are TWO derivations of
// one kernel name, and #9407 is what happens when they drift: the RG side
// already used the `.<vlan-id>` arm while the Kea side used the unit number, so
// the compare silently missed and the filter's node-local fallback kept an
// RG-scoped group.
//
// Comparing outcomes (as the cells above do) catches today's drift; comparing
// the DERIVATIONS over a corpus catches tomorrow's, including on shapes no
// outcome cell enumerates.
func TestKeaAndRGSetsDeriveNamesIdentically9407(t *testing.T) {
	cfg := keaCfg9407(t)

	rgSide := make(map[string]bool)
	for _, n := range rethInterfacesMatchingRG(cfg, func(int) bool { return true }) {
		rgSide[n] = true
	}
	if len(rgSide) == 0 {
		t.Fatal("the RG-derived set is empty, so this cell compared nothing")
	}

	// Every unit of every RG-owned interface, named the way the Kea derivation
	// names it, must be a member of the RG-derived set.
	compared := 0
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		if owns, ok := cfg.RethRGOwners()[name]; !ok || owns == 0 {
			continue
		}
		for unitNum := range ifc.Units {
			ref := name + "." + itoa(unitNum)
			viaKea := resolveDHCPRethInterfaces(config.DHCPServerConfig{
				DHCPLocalServer: &config.DHCPLocalServerConfig{
					Groups: map[string]*config.DHCPServerGroup{
						"g": {Name: "g", Interfaces: []string{ref}},
					},
				},
			}, cfg).DHCPLocalServer.Groups["g"].Interfaces[0]
			compared++
			if !rgSide[viaKea] {
				t.Errorf("%s: the Kea derivation names %q, which is not in the "+
					"RG-derived set %v. These two names are compared directly by "+
					"filterDHCPConfigForMasterRGs; when they disagree the group is "+
					"read as node-local and served on a node that masters nothing "+
					"(#9407).", ref, viaKea, keysOf9407(rgSide))
			}
		}
	}
	if compared == 0 {
		t.Fatal("no RG-owned unit was compared — the fixture does not exercise this")
	}
}

func keysOf9407(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
