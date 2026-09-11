package config

import (
	"strings"
	"testing"
)

// #9622: a routing instance may not take a name the daemon reserves for its own
// VRF. Before this gate, `routing-instances mgmt` committed clean and every
// apply planned two vrf-mgmt specs with different tables.

func setTree9622(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		p, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("parse %q: %v", cmd, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", cmd, err)
		}
	}
	return tree
}

var riBase9622 = []string{
	"set interfaces ge-0/0/1 unit 0 family inet address 10.1.1.1/24",
}

func TestReservedRoutingInstanceNameIsRejectedStrict_9622(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmds []string
	}{
		{"top-level", []string{
			"set routing-instances mgmt instance-type virtual-router",
			"set routing-instances mgmt interface ge-0/0/1.0",
		}},
		{"applied group", []string{
			"set groups g1 routing-instances mgmt instance-type virtual-router",
			"set groups g1 routing-instances mgmt interface ge-0/0/1.0",
			"set apply-groups g1",
		}},
		{"node group via ${node}", []string{
			"set groups node0 routing-instances mgmt instance-type virtual-router",
			"set groups node1 routing-instances blue instance-type virtual-router",
			`set apply-groups "${node}"`,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := setTree9622(t, append(append([]string{}, riBase9622...), tc.cmds...)...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("#9622: a routing instance named %q committed clean on the strict path; the daemon "+
					"creates that VRF itself, and an operator instance of the same name merges with it", ManagementVRFInstanceName)
			}
			if !strings.Contains(err.Error(), "reserved for") || !strings.Contains(err.Error(), "management VRF") {
				t.Errorf("#9622: the rejection must say the name is reserved for the management VRF: %v", err)
			}
		})
	}
}

func TestReservedRoutingInstanceNameIsQuarantinedLenient_9622(t *testing.T) {
	tree := setTree9622(t, append(append([]string{}, riBase9622...),
		"set routing-instances mgmt instance-type virtual-router",
		"set routing-instances mgmt interface ge-0/0/1.0",
		"set routing-instances blue instance-type virtual-router",
	)...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("#9622: the tolerant path must still boot a persisted config with a reserved instance name: %v", err)
	}
	var names []string
	for _, ri := range cfg.RoutingInstances {
		names = append(names, ri.Name)
	}
	for _, n := range names {
		if n == ManagementVRFInstanceName {
			t.Errorf("#9622: the lenient compile kept routing instance %q; it must be QUARANTINED so the daemon never plans a second vrf-mgmt (instances: %v)", n, names)
		}
	}
	if len(names) != 1 || names[0] != "blue" {
		t.Errorf("#9622 control: the unreserved sibling must survive untouched, got %v", names)
	}
	quarantineWarned := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "QUARANTINED") && strings.Contains(w, "reserved") {
			quarantineWarned = true
		}
	}
	if !quarantineWarned {
		t.Errorf("#9622: the quarantine must be reported in cfg.Warnings, got %v", cfg.Warnings)
	}
}

// Controls: names that only LOOK like the reserved one are ordinary instances.
// Instance names are case-sensitive, and the VRF device is "vrf-"+name, so
// neither "MGMT" nor "vrf-mgmt" (device "vrf-vrf-mgmt") collides.
func TestNearReservedRoutingInstanceNamesStillCommit_9622(t *testing.T) {
	for _, name := range []string{"mgmt1", "vrf-mgmt", "MGMT", "oob-mgmt"} {
		tree := setTree9622(t, append(append([]string{}, riBase9622...),
			"set routing-instances "+name+" instance-type virtual-router",
			"set routing-instances "+name+" interface ge-0/0/1.0",
		)...)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Errorf("#9622 control: routing instance %q must commit clean: %v", name, err)
			continue
		}
		if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].Name != name {
			t.Errorf("#9622 control: routing instance %q did not compile as an ordinary instance", name)
		}
	}
}
