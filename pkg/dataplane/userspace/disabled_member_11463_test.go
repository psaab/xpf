package userspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #11463: a disabled routing-instance member still carried its configured
// address into InterfaceSnapshot, where buildRouteSnapshots accepted every
// positive-ifindex row and emitted the connected prefix. The helper then
// rebuilt that prefix as a connected route and registered its address locally.
//
// RED-before: this apply-shaped snapshot contains 10.9.0.0/24 in the helper
// FIB even though its interface is administratively disabled.
func TestDisabledMemberAddressDoesNotReachUserspaceFIB11463(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/2": {
				Name:    "ge-0/0/2",
				Disable: true,
				Units: map[int]*config.InterfaceUnit{
					0: {Number: 0, Addresses: []string{"10.9.0.1/24"}},
				},
			},
		}},
		RoutingInstances: []*config.RoutingInstanceConfig{{
			Name:       "parked-vr",
			TableID:    101,
			Interfaces: []string{"ge-0/0/2"},
		}},
	}

	oldBuildLinkSnapshot := buildLinkSnapshot
	buildLinkSnapshot = func(string) (int, int, string, []InterfaceAddressSnapshot) {
		return 27, 1500, "02:00:00:00:00:27", []InterfaceAddressSnapshot{{
			Family:  "inet",
			Address: "198.51.100.9/24",
		}}
	}
	t.Cleanup(func() { buildLinkSnapshot = oldBuildLinkSnapshot })
	oldRuleListFn := ruleListFn
	ruleListFn = func(int) ([]netlink.Rule, error) { return nil, nil }
	t.Cleanup(func() { ruleListFn = oldRuleListFn })

	interfaces := buildInterfaceSnapshotsFrom(cfg, map[string]bool{})
	var unit *InterfaceSnapshot
	for i := range interfaces {
		if interfaces[i].Name == "ge-0/0/2.0" {
			unit = &interfaces[i]
			break
		}
	}
	if unit == nil {
		t.Fatal("disabled member unit missing from interface snapshot")
	}
	if len(unit.Addresses) != 0 {
		t.Fatalf("disabled member snapshot retained configured or live addresses: %+v", unit.Addresses)
	}
	var base *InterfaceSnapshot
	for i := range interfaces {
		if interfaces[i].Name == "ge-0/0/2" {
			base = &interfaces[i]
			break
		}
	}
	if base == nil {
		t.Fatal("disabled member base missing from interface snapshot")
	}
	if len(base.Addresses) != 0 {
		t.Fatalf("disabled member base snapshot retained live addresses: %+v", base.Addresses)
	}
	if !unit.AdminDisabled {
		t.Fatal("disabled member state missing from InterfaceSnapshot")
	}
	wire, err := json.Marshal(unit)
	if err != nil {
		t.Fatalf("marshal disabled interface: %v", err)
	}
	var decoded InterfaceSnapshot
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("unmarshal disabled interface: %v", err)
	}
	if !decoded.AdminDisabled {
		t.Fatalf("wire snapshot lost admin_disabled: %s", wire)
	}

	// A wire-state change is acceptable only when the Rust consumer and Go FIB
	// both honor it. This connected-route assertion is the Go half.
	routes, _, err := buildRouteSnapshots(cfg, interfaces, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	for _, route := range routes {
		if route.Destination == "10.9.0.0/24" || route.Destination == "198.51.100.0/24" {
			t.Fatalf("disabled member address leaked into userspace route snapshot: %+v (routes=%v)", route, routes)
		}
	}
	localAddresses := buildLocalAddressEntries(&ConfigSnapshot{Interfaces: interfaces})
	if len(localAddresses) != 0 {
		t.Fatalf("disabled member addresses leaked into local FIB entries: %+v", localAddresses)
	}

	disabledV4 := pickInterfaceSnapshotV4(*unit)
	if disabledV4 != nil {
		t.Fatalf("disabled member selected as an interface primary: %v", disabledV4)
	}

	v4, v6 := connectedPrefixesForInterface(*unit)
	if len(v4) != 0 || len(v6) != 0 {
		t.Fatalf("disabled unit connected prefixes = (%v, %v), want none", v4, v6)
	}

	// Control: an otherwise identical enabled member must still contribute its
	// connected prefix, preventing a blanket address suppression from passing.
	cfg.Interfaces.Interfaces["ge-0/0/2"].Disable = false
	active := buildInterfaceSnapshotsFrom(cfg, map[string]bool{})
	activeRoutes, _, err := buildRouteSnapshots(cfg, active, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots enabled control: %v", err)
	}
	found := false
	for _, route := range activeRoutes {
		if route.Table == "parked-vr.inet.0" && route.Destination == "10.9.0.0/24" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("enabled-member control lost its connected route: %v", activeRoutes)
	}
	activeLocalAddresses := buildLocalAddressEntries(&ConfigSnapshot{Interfaces: active})
	if len(activeLocalAddresses) != 2 {
		t.Fatalf("enabled-member control local FIB entries = %+v, want both live and configured addresses", activeLocalAddresses)
	}

	var activeUnit *InterfaceSnapshot
	for i := range active {
		if active[i].Name == "ge-0/0/2.0" {
			activeUnit = &active[i]
			break
		}
	}
	if activeUnit == nil {
		t.Fatal("enabled-member control unit missing from interface snapshot")
	}
	if primary := pickInterfaceSnapshotV4(*activeUnit); primary == nil || primary.String() != "10.9.0.1" {
		t.Fatalf("enabled-member control primary = %v, want 10.9.0.1", primary)
	}
}

func TestAdminDisabledWireKeyLockstep11463(t *testing.T) {
	goKey := jsonKeyOf(t, reflect.TypeOf(InterfaceSnapshot{}), "AdminDisabled")
	path := filepath.Join("..", "..", "..", "userspace-dp", "src", "protocol", "snapshot.rs")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	rustKey := rustSerdeRenameOf(t, rustStructBody(t, string(src), "InterfaceSnapshot"), "admin_disabled")
	if goKey != rustKey {
		t.Fatalf("admin-disabled wire key skew: Go emits %q, Rust reads %q", goKey, rustKey)
	}
}
