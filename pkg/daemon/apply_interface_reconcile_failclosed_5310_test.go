package daemon

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/psaab/xpf/pkg/vrrp"
	"github.com/vishvananda/netlink"
)

// #5310: applyInterfaceReconcile was VOID — every sub-stage failure
// (xfrmManager.Apply, ApplyBonds, ApplyTunnels, ClearRethInterfaces) was
// logged at WARN and swallowed, and the apply-error join at the tail of
// applyConfigLocked EXCLUDED the whole interface-reconcile stage. A commit that
// added a route-based IPsec VPN whose xfrmi LinkAdd failed therefore reported
// SUCCESS while the interface — and the route-based IPs bound to it — carried
// no traffic (fail-open false convergence). The fix makes applyInterfaceReconcile
// RETURN an aggregated error and threads it (ifaceErr) into the tail commit-error
// join. These tests pin the daemon-boundary half of that chain (the
// routing-package half is pkg/routing/xfrm_apply_failclosed_5310_test.go).

// reconcileFakeLinkOps is a minimal in-memory linkOps double for driving a
// routing.Manager (via routing.NewManagerWithLinkOpsForTest) through the
// interface-reconcile stage without a real netlink handle. Failure injection is
// keyed by link name.
type reconcileFakeLinkOps struct {
	links   map[string]netlink.Link
	addFail map[string]error // name -> LinkAdd (create) failure
	upFail  map[string]error // name -> LinkSetUp (bring-up) failure
}

func newReconcileFakeLinkOps() *reconcileFakeLinkOps {
	return &reconcileFakeLinkOps{
		links:   map[string]netlink.Link{},
		addFail: map[string]error{},
		upFail:  map[string]error{},
	}
}

func (f *reconcileFakeLinkOps) LinkByName(name string) (netlink.Link, error) {
	if l, ok := f.links[name]; ok {
		return l, nil
	}
	// Return the SAME type real *netlink.Handle.LinkByName returns on absence
	// (netlink.LinkNotFoundError), so routing's isLinkNotFound (pkg/routing/
	// vrf.go — errors.As against netlink.LinkNotFoundError) recognizes it and
	// the create path falls through to LinkAdd. A plain errors.New("link not
	// found") is NOT recognized after #5499 tightened Apply to distinguish a
	// genuine absence from a transient lookup error, so it was misclassified as
	// transient and the injected LinkAdd failure never reached (#5504). The
	// embedded error field is unexported, so this can only be the zero value;
	// that is safe here because no path formats/prints a recognized not-found
	// error (isLinkNotFound uses errors.As, which never calls Error()).
	return nil, netlink.LinkNotFoundError{}
}

func (f *reconcileFakeLinkOps) LinkAdd(l netlink.Link) error {
	name := l.Attrs().Name
	if err, ok := f.addFail[name]; ok {
		return err
	}
	f.links[name] = l
	return nil
}

func (f *reconcileFakeLinkOps) LinkDel(l netlink.Link) error {
	delete(f.links, l.Attrs().Name)
	return nil
}

func (f *reconcileFakeLinkOps) LinkSetUp(l netlink.Link) error {
	if err, ok := f.upFail[l.Attrs().Name]; ok {
		return err
	}
	return nil
}

func (f *reconcileFakeLinkOps) LinkSetDown(netlink.Link) error                 { return nil }
func (f *reconcileFakeLinkOps) LinkSetMaster(netlink.Link, netlink.Link) error { return nil }
func (f *reconcileFakeLinkOps) LinkSetNoMaster(netlink.Link) error             { return nil }
func (f *reconcileFakeLinkOps) LinkSetMTU(netlink.Link, int) error             { return nil }
func (f *reconcileFakeLinkOps) LinkList() ([]netlink.Link, error)              { return nil, nil }
func (f *reconcileFakeLinkOps) AddrAdd(netlink.Link, *netlink.Addr) error      { return nil }
func (f *reconcileFakeLinkOps) AddrDel(netlink.Link, *netlink.Addr) error      { return nil }
func (f *reconcileFakeLinkOps) AddrList(netlink.Link, int) ([]netlink.Addr, error) {
	return nil, nil
}

func xfrmVPNConfig(bindIface string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"v1": {Name: "v1", BindInterface: bindIface},
	}
	return cfg
}

// TestApplyInterfaceReconcileFailsClosedOnXfrmCreateFailure drives the REAL
// applyInterfaceReconcile against a routing.Manager whose xfrmi LinkAdd fails,
// and asserts it RETURNS the aggregated error (fail-closed).
//
// FAIL-ON-REVERT: revert applyInterfaceReconcile to its void, log-and-swallow
// form and this test stops compiling (no error to assign) / the assertion goes
// RED — the silent fail-open #5310 describes.
func TestApplyInterfaceReconcileFailsClosedOnXfrmCreateFailure(t *testing.T) {
	ops := newReconcileFakeLinkOps()
	ifName, _ := config.XFRMIfNameAndID("st0.1")
	injected := errors.New("injected: xfrmi LinkAdd EPERM")
	ops.addFail[ifName] = injected

	d := &Daemon{routing: routing.NewManagerWithLinkOpsForTest(ops)}
	err := d.applyInterfaceReconcile(xfrmVPNConfig("st0.1"))
	if err == nil {
		t.Fatal("applyInterfaceReconcile must return the xfrmi create failure " +
			"(fail-closed); got nil (the swallowed-error false-convergence #5310 describes)")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned error must wrap the injected xfrmi failure, got %v", err)
	}
}

// TestApplyInterfaceReconcileSurfacesBondFailure proves the bond sub-stage is
// also aggregated (not just xfrmi): a genuine fabric-bond LinkAdd failure makes
// applyInterfaceReconcile return non-nil. Before #5310 the ApplyBonds error was
// logged and swallowed at the daemon boundary even though bond.Apply already
// returned it (#4823).
//
// FAIL-ON-REVERT: revert applyInterfaceReconcile to void / drop the ApplyBonds
// aggregation and this goes RED.
func TestApplyInterfaceReconcileSurfacesBondFailure(t *testing.T) {
	ops := newReconcileFakeLinkOps()
	injected := errors.New("injected: bond LinkAdd EPERM")
	ops.addFail["ae0"] = injected

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ae0": {Name: "ae0", FabricMembers: []string{"ge-0-0-1"}, BondMode: "active-backup"},
	}

	d := &Daemon{routing: routing.NewManagerWithLinkOpsForTest(ops)}
	err := d.applyInterfaceReconcile(cfg)
	if err == nil {
		t.Fatal("applyInterfaceReconcile must surface the bond create failure " +
			"(fail-closed); got nil")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned error must wrap the injected bond failure, got %v", err)
	}
}

// TestApplyInterfaceReconcileSurfacesTunnelFailure proves the tunnel sub-stage
// is aggregated too (#5355): a genuine GRE/anchor tunnel LinkAdd failure makes
// applyInterfaceReconcile return non-nil. Before #5355 tunnelManager.Apply
// logged every per-tunnel create/up/delete failure and returned nil
// UNCONDITIONALLY, so even though the #5354 tail-join already threaded
// ApplyTunnels, there was never an error to surface — the commit reported
// success while the tunnel interface was absent (fail-open false convergence).
//
// FAIL-ON-REVERT: restore tunnelManager.Apply's unconditional `return nil` and
// this goes RED (applyInterfaceReconcile returns nil despite the tunnel create
// having failed).
func TestApplyInterfaceReconcileSurfacesTunnelFailure(t *testing.T) {
	ops := newReconcileFakeLinkOps()
	injected := errors.New("injected: tunnel LinkAdd EPERM")
	ops.addFail["gr-0-0-0"] = injected

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"gr-0/0/0": {
			Name: "gr-0/0/0",
			Tunnel: &config.TunnelConfig{
				Name:        "gr-0-0-0",
				Source:      "10.0.0.1",
				Destination: "10.0.0.2",
			},
		},
	}

	d := &Daemon{routing: routing.NewManagerWithLinkOpsForTest(ops)}
	err := d.applyInterfaceReconcile(cfg)
	if err == nil {
		t.Fatal("applyInterfaceReconcile must surface the tunnel create failure " +
			"(fail-closed #5355); got nil")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned error must wrap the injected tunnel failure, got %v", err)
	}
}

// TestApplyInterfaceReconcileToleratesIdempotent proves a benign reconcile does
// NOT fail the commit: the xfrmi already exists with the matching if_id (adopt
// path) and every other sub-stage is a no-op, so applyInterfaceReconcile returns
// nil. GREEN both before and after the fix — the fix must not turn a tolerated
// already-exists condition into a commit failure.
func TestApplyInterfaceReconcileToleratesIdempotent(t *testing.T) {
	ops := newReconcileFakeLinkOps()
	ifName, ifID := config.XFRMIfNameAndID("st0.1")
	ops.links[ifName] = &netlink.Xfrmi{
		LinkAttrs: netlink.LinkAttrs{Name: ifName, Index: 5},
		Ifid:      ifID,
	}

	d := &Daemon{routing: routing.NewManagerWithLinkOpsForTest(ops)}
	if err := d.applyInterfaceReconcile(xfrmVPNConfig("st0.1")); err != nil {
		t.Fatalf("idempotent adopt of an already-exists xfrmi must not fail the "+
			"interface reconcile, got %v", err)
	}
}

// TestApplyTailReconcilesSurfacesInterfaceReconcileError is the commit-level
// wiring proof: it drives the REAL applyTailReconciles with an injected
// interface-reconcile error (ifaceErr) and asserts the returned commit error
// includes it. This pins the production wiring — the
// errors.Join(networkdErr, dhcpServerErr, hostInboundErr, lo0Err, ipsecErr,
// ifaceErr) at the tail — that the direct applyInterfaceReconcile test does not
// cover.
//
// FAIL-ON-REVERT: drop ifaceErr from that join and this test goes RED (the apply
// completes and returns nil despite the interface reconcile having failed — the
// exact fail-open the issue describes). The nft seams are stubbed to succeed so
// the injected ifaceErr is the ONLY operand that can surface.
func TestApplyTailReconcilesSurfacesInterfaceReconcileError(t *testing.T) {
	installFakeNetworkctl(t)

	origApply, origDelete := nftApplyPayload, nftDeleteTable
	nftApplyPayload = func(string) ([]byte, error) { return nil, nil }
	nftDeleteTable = func(string, string) ([]byte, error) { return nil, nil }
	defer func() { nftApplyPayload, nftDeleteTable = origApply, origDelete }()

	d := &Daemon{
		networkd: networkd.NewInDir(t.TempDir()),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(&runtimeOnlyApplyTestDP{}) // #2114: publish through the cell

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"reth0.0"}},
	}

	injected := errors.New("injected: interface reconcile (xfrmi create) failed")
	err := d.applyTailReconciles(cfg, nil, nil, nil, nil, injected, nil, nil, nil, nil, nil, nil)
	if err == nil {
		t.Fatal("applyTailReconciles must surface the interface-reconcile failure " +
			"(fail-closed); got nil")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned commit error must include the interface-reconcile failure "+
			"via the tail errors.Join wiring, got %v", err)
	}
}
