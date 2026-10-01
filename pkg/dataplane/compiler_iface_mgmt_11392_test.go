package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestTolerantManagementRIMemberDoesNotEnterIfaceTableIDMap11392(t *testing.T) {
	lines := []string{
		"set interfaces fxp0 unit 0 family inet address 192.0.2.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 198.51.100.1/24",
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue interface fxp0.0",
		"set routing-instances blue interface ge-0/0/1.0",
	}
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("parse set command %q: %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("set config path %q: %v", line, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile tolerant management-member fixture: %v", err)
	}

	tableIDs := buildIfaceTableIDMap(cfg)
	if _, found := tableIDs["fxp0.0"]; found {
		t.Fatalf("management interface received tenant table ID %d", tableIDs["fxp0.0"])
	}
	if got, want := tableIDs["ge-0/0/1.0"], uint32(config.StableRoutingInstanceTableID("blue")); got != want {
		t.Errorf("ordinary interface table ID = %d, want %d", got, want)
	}
}

func TestIfaceTableIDMapIncludesRetainedPrimaryClaim11392(t *testing.T) {
	cfg := &config.Config{
		RoutingInstances: []*config.RoutingInstanceConfig{{
			Name: "blue", InstanceType: "virtual-router", TableID: 123,
		}},
		QuarantinedRIMemberPrimaryClaims: []config.RoutingInstanceMemberPrimaryClaim{{
			Instance: "blue", InterfaceKey: "ge-0/0/0", LinuxName: "ge-0-0-0",
		}},
	}
	if got := buildIfaceTableIDMap(cfg)["ge-0/0/0"]; got != 123 {
		t.Fatalf("retained primary interface table ID = %d, want 123", got)
	}
}
