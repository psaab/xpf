package userspace

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

func TestKernelLinkUp11404(t *testing.T) {
	for _, tc := range []struct {
		name string
		link netlink.Link
		want bool
	}{
		{name: "admin down", link: &netlink.Device{LinkAttrs: netlink.LinkAttrs{OperState: netlink.OperUp}}},
		{name: "oper down", link: &netlink.Device{LinkAttrs: netlink.LinkAttrs{Flags: net.FlagUp, OperState: netlink.OperDown}}},
		{name: "lower layer down", link: &netlink.Device{LinkAttrs: netlink.LinkAttrs{Flags: net.FlagUp, OperState: netlink.OperLowerLayerDown}}},
		{name: "not present", link: &netlink.Device{LinkAttrs: netlink.LinkAttrs{Flags: net.FlagUp, OperState: netlink.OperNotPresent}}},
		{name: "up", link: &netlink.Device{LinkAttrs: netlink.LinkAttrs{Flags: net.FlagUp, OperState: netlink.OperUp}}, want: true},
		{name: "unknown", link: &netlink.Device{LinkAttrs: netlink.LinkAttrs{Flags: net.FlagUp, OperState: netlink.OperUnknown}}, want: true},
		{name: "dormant", link: &netlink.Device{LinkAttrs: netlink.LinkAttrs{Flags: net.FlagUp, OperState: netlink.OperDormant}}, want: true},
		{name: "testing", link: &netlink.Device{LinkAttrs: netlink.LinkAttrs{Flags: net.FlagUp, OperState: netlink.OperTesting}}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := kernelLinkUp(tc.link); got != tc.want {
				t.Fatalf("kernelLinkUp = %t, want %t", got, tc.want)
			}
		})
	}

	previous := linkByNameFn
	t.Cleanup(func() { linkByNameFn = previous })
	linkByNameFn = func(string) (netlink.Link, error) { return nil, nil }
	if linuxLinkUp("") || linuxLinkUp("missing") {
		t.Fatal("empty or unresolved link reported up")
	}
}

func TestInterfaceSnapshotLinkUpWire11404(t *testing.T) {
	down := false
	wire, err := json.Marshal(InterfaceSnapshot{LinkUp: &down})
	if err != nil {
		t.Fatalf("marshal down interface: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatalf("unmarshal down interface: %v", err)
	}
	if got := string(fields["link_up"]); got != "false" {
		t.Fatalf("link_up = %s, want explicit false", got)
	}

	wire, err = json.Marshal(InterfaceSnapshot{})
	if err != nil {
		t.Fatalf("marshal legacy interface: %v", err)
	}
	fields = nil
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatalf("unmarshal legacy interface: %v", err)
	}
	if _, present := fields["link_up"]; present {
		t.Fatalf("nil LinkUp should be absent for a legacy/unknown row: %s", wire)
	}
}

func TestLogicalOnlyRethVLANUsesParentLinkUp11404(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/0": {
				Name:            "ge-0/0/0",
				RedundantParent: "reth0",
			},
			"reth0": {
				Name: "reth0",
				Units: map[int]*config.InterfaceUnit{
					50: {Number: 50, VlanID: 50},
				},
			},
		}},
	}

	previousBuild := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = previousBuild })
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		if linuxName == "ge-0-0-0" {
			return 17, 1500, "", nil
		}
		return 0, 0, "", nil
	}
	previousLookup := linkByNameFn
	t.Cleanup(func() { linkByNameFn = previousLookup })
	linkByNameFn = func(linuxName string) (netlink.Link, error) {
		var state netlink.LinkOperState = netlink.OperUp
		if linuxName == "ge-0-0-0.50" {
			state = netlink.OperDown
		}
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Flags: net.FlagUp, OperState: state}}, nil
	}

	rows := buildInterfaceSnapshotsFrom(cfg, nil)
	for _, row := range rows {
		if row.LinkUp == nil {
			t.Errorf("generated row %q has no LinkUp value", row.Name)
		}
	}
	var unit *InterfaceSnapshot
	for i := range rows {
		if rows[i].Name == "reth0.50" {
			unit = &rows[i]
			break
		}
	}
	if unit == nil || !unit.LogicalOnly {
		t.Fatalf("logical-only RETH VLAN row missing: %+v", rows)
	}
	if unit.LinkUp == nil || !*unit.LinkUp {
		t.Fatalf("LinkUp = %v, want true from the live parent despite the down/missing VLAN child", unit.LinkUp)
	}
}

func TestRevalidateLogicalOnlyRethVLANRefreshesParentLinkUp11404(t *testing.T) {
	previousBuild := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = previousBuild })
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		if linuxName == "ge-0-0-0" {
			return 44, 1500, "", nil
		}
		return 0, 0, "", nil
	}
	previousLookup := linkByNameFn
	t.Cleanup(func() { linkByNameFn = previousLookup })
	linkByNameFn = func(linuxName string) (netlink.Link, error) {
		var state netlink.LinkOperState = netlink.OperUp
		if linuxName == "ge-0-0-0.50" {
			state = netlink.OperDown
		}
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Flags: net.FlagUp, OperState: state}}, nil
	}

	down := false
	snap := &ConfigSnapshot{Interfaces: []InterfaceSnapshot{{
		Name: "reth0.50", LinuxName: "ge-0-0-0.50", ParentLinuxName: "ge-0-0-0",
		Ifindex: 70001, ParentIfindex: 17, LogicalOnly: true, LinkUp: &down,
	}}}
	refreshed, dropped := revalidateSnapshotIfindexes(snap)
	if dropped != 0 || len(snap.Interfaces) != 1 {
		t.Fatalf("logical-only row dropped: refreshed=%d dropped=%d rows=%+v", refreshed, dropped, snap.Interfaces)
	}
	row := snap.Interfaces[0]
	if row.Ifindex != 70001 || row.ParentIfindex != 44 {
		t.Fatalf("revalidation changed synthetic/parent ifindexes unexpectedly: %+v", row)
	}
	if row.LinkUp == nil || !*row.LinkUp {
		t.Fatalf("LinkUp = %v, want refreshed true parent state", row.LinkUp)
	}
}
