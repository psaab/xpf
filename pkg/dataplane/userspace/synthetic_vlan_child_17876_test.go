package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestBuildInterfaceSnapshotsKeepsKernelRethVlanChild_17876(t *testing.T) {
	previous := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = previous })
	const parentIfindex = 10
	const childIfindex = 12
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		switch linuxName {
		case "ge-0-0-2":
			return parentIfindex, 1500, "02:00:00:00:00:10", nil
		case "ge-0-0-2.80":
			return childIfindex, 1500, "02:00:00:00:00:12", nil
		default:
			return 0, 0, "", nil
		}
	}

	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth0"},
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			80: {Number: 80, VlanID: 80},
		}},
	}}}
	rows := BuildInterfaceSnapshots(cfg)
	var child *InterfaceSnapshot
	for i := range rows {
		if rows[i].Name == "reth0.80" {
			child = &rows[i]
			break
		}
	}
	if child == nil {
		t.Fatal("snapshot builder omitted reth0.80")
	}
	if child.LogicalOnly || child.Ifindex != childIfindex || child.ParentIfindex != parentIfindex {
		t.Fatalf("builder child row = %+v, want non-logical ifindex %d with parent %d", child, childIfindex, parentIfindex)
	}
}
