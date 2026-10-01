package daemon

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func connectedRoute11362(t *testing.T, prefix string, linkIndex int) netlink.Route {
	t.Helper()
	route := operatorRouteWithProtocol9943(t, prefix, unix.RTPROT_KERNEL)
	route.LinkIndex = linkIndex
	route.Scope = netlink.SCOPE_LINK
	return route
}

func TestMgmtVRFClasslessControlFabricConnectedPrefixesFenced11362(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key xpf-test-cluster-authentication-key-11362",
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
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		t.Fatal("fixture must compile a cluster with control and fabric links")
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
			connectedRoute11362(t, "192.0.2.0/24", 7),  // DHCP interface's own connected prefix.
			connectedRoute11362(t, "10.77.0.0/24", 8),  // cluster control link.
			connectedRoute11362(t, "10.78.0.0/24", 9),  // primary fabric.
			connectedRoute11362(t, "10.79.0.0/24", 10), // secondary fabric.
		},
	}
	lease := classlessLease9943(
		"10.77.0.42/32", "10.78.0.42/32", "10.79.0.42/32",
		"192.0.2.42/32", "10.0.0.0/8", "172.16.0.0/16",
	)
	d := &Daemon{store: store}
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	// The ordinary classless trust escape hatch must not restore a route that
	// could steal traffic from a cluster control/fabric connected prefix.
	t.Setenv(dhcpClasslessTrustOverrideEnv, "1")
	if err := d.applyMgmtVRFRoutesTo(fake, []*dhcp.Lease{lease}, mgmtSet); err != nil {
		t.Fatalf("applyMgmtVRFRoutesTo: %v", err)
	}
	got := replacedDestinations9943(fake.replaced)
	for _, dst := range []string{"10.77.0.42/32", "10.78.0.42/32", "10.79.0.42/32"} {
		if got[dst] != 0 {
			t.Errorf("option-121 route %s inside a control/fabric connected prefix reached RouteReplace: %v", dst, got)
		}
	}
	for _, dst := range []string{"192.0.2.42/32", "10.0.0.0/8", "172.16.0.0/16"} {
		if got[dst] != 1 {
			t.Errorf("safe option-121 route %s must install exactly once: %v", dst, got)
		}
	}
	for _, want := range []string{
		"inside a cluster control/fabric connected prefix",
		"control_interface=em0",
		"connected_prefix=10.77.0.0/24",
		"control_interface=fab0",
		"connected_prefix=10.78.0.0/24",
		"control_interface=fab1",
		"connected_prefix=10.79.0.0/24",
	} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("suppression alarm missing %q: %s", want, logs.String())
		}
	}
	logs.Reset()
	missingControlLink := &fakeMgmtProgrammer{
		links: map[string]int{"fxp0": 7, "fab0": 9, "fab1": 10},
		v4:    append([]netlink.Route(nil), fake.v4...),
	}
	if err := d.applyMgmtVRFRoutesTo(missingControlLink, []*dhcp.Lease{lease}, mgmtSet); err == nil {
		t.Fatal("classless apply must fail closed when a configured control link cannot be resolved")
	}
	if got := replacedDestinations9943(missingControlLink.replaced); len(got) != 0 {
		t.Errorf("trust override bypassed incomplete control-link inventory: %v", got)
	}
	if !strings.Contains(logs.String(), "cannot be resolved (#11362)") {
		t.Errorf("missing control-link inventory did not alarm: %s", logs.String())
	}
}
