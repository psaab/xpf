package daemon

import (
	"bytes"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/vishvananda/netlink"
)

// #13546: applyMgmtVRFRoutesTo read ActiveConfig() twice — once for the
// static-route and configured-connected-prefix decisions at the head of the
// pass, and again for the cluster control/fabric interface inventory that
// gates classless routes. A commit landing between those reads must not mix
// config generations in the route-security decision.

type swappingMgmtProgrammer13546 struct {
	fakeMgmtProgrammer
	store   *configstore.Store
	t       *testing.T
	flipped bool
}

func (p *swappingMgmtProgrammer13546) RouteListFiltered(
	family int, filter *netlink.Route, mask uint64,
) ([]netlink.Route, error) {
	// The first list is the static-route reconciler's inventory. Flip active
	// config after applyMgmtVRFRoutesTo captured generation A, but before its
	// later control/fabric inventory read.
	if !p.flipped {
		p.flipped = true
		p.store.ExitConfigure()
		if err := p.store.EnterConfigure(); err != nil {
			p.t.Fatalf("EnterConfigure: %v", err)
		}
		if err := p.store.DeleteFromInput("chassis cluster"); err != nil {
			p.t.Fatalf("delete cluster: %v", err)
		}
		if _, err := p.store.Commit(); err != nil {
			p.t.Fatalf("Commit(generation B): %v", err)
		}
	}
	return p.fakeMgmtProgrammer.RouteListFiltered(family, filter, mask)
}

func mgmtVRFClusterLines13546() []string {
	return []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key xpf-test-cluster-authentication-key-13546",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.77.0.2",
		"set chassis cluster fabric-interface fab0",
		"set chassis cluster fabric-peer-address 10.78.0.2",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces fxp0 unit 0 family inet address 192.0.2.2/24",
		"set interfaces em0 unit 0 family inet address 10.77.0.1/24",
		"set interfaces fab0 unit 0 family inet address 10.78.0.1/24",
	}
}

func TestMgmtVRFReconcileSingleConfigGeneration13546(t *testing.T) {
	store := testStoreWithSetConfig(t, mgmtVRFClusterLines13546())
	before := store.ActiveConfig()
	if before == nil || before.Chassis.Cluster == nil {
		t.Fatal("fixture must compile a clustered generation A")
	}

	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	t.Setenv(dhcpClasslessTrustOverrideEnv, "1")

	fake := &swappingMgmtProgrammer13546{
		fakeMgmtProgrammer: fakeMgmtProgrammer{
			links: map[string]int{"fxp0": 7, "em0": 8, "fab0": 9},
			v4: []netlink.Route{
				connectedRoute11362(t, "192.0.2.0/24", 7), // DHCP interface
				connectedRoute11362(t, "10.77.0.0/24", 8), // control link
				connectedRoute11362(t, "10.78.0.0/24", 9), // fabric link
			},
		},
		store: store,
		t:     t,
	}
	lease := classlessLease9943("10.77.0.42/32", "198.51.100.42/32")
	lease.Address = netip.MustParsePrefix("192.0.2.2/24")
	d := &Daemon{store: store}
	mgmtSet := map[string]bool{"fxp0": true, "em0": true, "fab0": true}
	if err := d.applyMgmtVRFRoutesTo(fake, []*dhcp.Lease{lease}, mgmtSet); err != nil {
		t.Fatalf("applyMgmtVRFRoutesTo: %v", err)
	}
	if !fake.flipped {
		t.Fatal("harness never flipped the config generation mid-pass; test is vacuous")
	}
	if after := store.ActiveConfig(); after == before || after.Chassis.Cluster != nil {
		t.Fatal("config did not flip from clustered generation A to standalone generation B")
	}
	got := replacedDestinations9943(fake.replaced)
	// A coherent pass uses A for both reads, so em0 remains a configured
	// control interface and the classless route into its prefix is fenced.
	if got["10.77.0.42/32"] != 0 {
		t.Errorf("classless route into cluster control prefix installed (%v); reconcile mixed generations (logs: %s)", got, logs.String())
	}
	if got["198.51.100.42/32"] != 1 {
		t.Errorf("benign classless route = %v, want installed exactly once", got)
	}
}
