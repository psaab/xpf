package daemon

import (
	"bytes"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/vishvananda/netlink"
)

// #16806: mgmtVRFControlFabricInterfaces mapped the authored
// control/fabric ref with LinuxIfName ("/" -> "-" only), so
// "em0.0" never matched the mgmt set {em0, ...} and the #11362
// fence had no links — with the classless trust override set the
// route into the control prefix was installed in table 999.
// Acceptance: the probe's em0.0 arm returns [em0] and a #11362
// cell with the override + unit spelling suppresses the route.
func TestMgmtVRFControlFabricInterfacesUnitSpelling16806(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key xpf-test-cluster-authentication-key-16806",
		"set chassis cluster control-interface em0.0",
		"set chassis cluster peer-address 10.77.0.2",
		"set chassis cluster fabric-interface fab0.0",
		"set chassis cluster fabric-peer-address 10.78.0.2",
		"set chassis cluster fabric1-interface fab1.0",
		"set chassis cluster fabric1-peer-address 10.79.0.2",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24",
		"set interfaces em0 unit 0 family inet address 10.77.0.1/24",
		"set interfaces fab0 unit 0 family inet address 10.78.0.1/24",
		"set interfaces fab1 unit 0 family inet address 10.79.0.1/24",
	})
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		t.Fatal("fixture must compile a cluster with control and fabric links")
	}
	// Compiler must preserve unit spelling (not normalize away).
	if cfg.Chassis.Cluster.ControlInterface != "em0.0" {
		t.Fatalf("ControlInterface = %q, want unit spelling preserved (em0.0)", cfg.Chassis.Cluster.ControlInterface)
	}
	mgmtSet := map[string]bool{"fxp0": true, "em0": true, "fab0": true, "fab1": true}
	got := mgmtVRFControlFabricInterfaces(cfg, mgmtSet)
	want := []string{"em0", "fab0", "fab1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mgmtVRFControlFabricInterfaces(unit-spelled) = %v, want %v", got, want)
	}
	// Bare-spelling control: same result.
	store2 := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key xpf-test-cluster-authentication-key-16806",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.77.0.2",
		"set chassis cluster fabric-interface fab0",
		"set chassis cluster fabric-peer-address 10.78.0.2",
		"set chassis cluster fabric1-interface fab1",
		"set chassis cluster fabric1-peer-address 10.79.0.2",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24",
		"set interfaces em0 unit 0 family inet address 10.77.0.1/24",
		"set interfaces fab0 unit 0 family inet address 10.78.0.1/24",
		"set interfaces fab1 unit 0 family inet address 10.79.0.1/24",
	})
	if got := mgmtVRFControlFabricInterfaces(store2.ActiveConfig(), mgmtSet); !reflect.DeepEqual(got, want) {
		t.Fatalf("mgmtVRFControlFabricInterfaces(bare) = %v, want %v", got, want)
	}
}

func TestMgmtVRFClasslessUnitSpellingControlFencedWithOverride16806(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key xpf-test-cluster-authentication-key-16806",
		"set chassis cluster control-interface em0.0",
		"set chassis cluster peer-address 10.77.0.2",
		"set chassis cluster fabric-interface fab0.0",
		"set chassis cluster fabric-peer-address 10.78.0.2",
		"set chassis cluster fabric1-interface fab1.0",
		"set chassis cluster fabric1-peer-address 10.79.0.2",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24",
		"set interfaces em0 unit 0 family inet address 10.77.0.1/24",
		"set interfaces fab0 unit 0 family inet address 10.78.0.1/24",
		"set interfaces fab1 unit 0 family inet address 10.79.0.1/24",
	})
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		t.Fatal("fixture must compile a cluster")
	}
	mgmtSet := managementVRFIfaceSet(cfg)
	for _, name := range []string{"fxp0", "em0", "fab0", "fab1"} {
		if !mgmtSet[name] {
			t.Fatalf("fixture interface %s must be managed by vrf-mgmt: %v", name, mgmtSet)
		}
	}
	fake := &fakeMgmtProgrammer{
		links: map[string]int{"fxp0": 7, "em0": 8, "fab0": 9, "fab1": 10},
		v4: []netlink.Route{
			connectedRoute11362(t, "192.0.2.0/24", 7),
			connectedRoute11362(t, "10.77.0.0/24", 8),
			connectedRoute11362(t, "10.78.0.0/24", 9),
			connectedRoute11362(t, "10.79.0.0/24", 10),
		},
	}
	lease := classlessLease9943("10.77.0.42/32", "10.78.0.42/32", "10.79.0.42/32", "192.0.2.42/32")
	d := &Daemon{store: store}
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	// #11362 fence must NOT yield to the trust override, even with
	// unit-spelled control/fabric refs.
	t.Setenv(dhcpClasslessTrustOverrideEnv, "1")
	if err := d.applyMgmtVRFRoutesTo(fake, []*dhcp.Lease{lease}, mgmtSet); err != nil {
		t.Fatalf("applyMgmtVRFRoutesTo: %v", err)
	}
	got := replacedDestinations9943(fake.replaced)
	for _, dst := range []string{"10.77.0.42/32", "10.78.0.42/32", "10.79.0.42/32"} {
		if got[dst] != 0 {
			t.Errorf("unit-spelled control/fabric classless route %s reached RouteReplace despite #11362 fence: %v (logs: %s)", dst, got, logs.String())
		}
	}
	if got["192.0.2.42/32"] != 1 {
		t.Errorf("trust-override ordinary connected route must install exactly once: %v", got)
	}
	for _, want := range []string{
		"inside a cluster control/fabric connected prefix",
		"control_interface=em0",
		"connected_prefix=10.77.0.0/24",
	} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("suppression alarm missing %q: %s", want, logs.String())
		}
	}
}
