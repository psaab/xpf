package daemon

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"
)

type mgmtVRFBindRecorder11448 struct {
	*reconcileFakeLinkOps
	binds []string
}

func (r *mgmtVRFBindRecorder11448) LinkSetMaster(link, master netlink.Link) error {
	r.binds = append(r.binds, link.Attrs().Name+"->"+master.Attrs().Name)
	link.Attrs().MasterIndex = master.Attrs().Index
	return nil
}

func newMgmtVRFReassertDaemon11448(t *testing.T, masters map[string]int) (*Daemon, *mgmtVRFBindRecorder11448) {
	t.Helper()
	ops := &mgmtVRFBindRecorder11448{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
	ops.links[config.ManagementVRFDeviceName] = &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{
		Name: config.ManagementVRFDeviceName, Index: 77,
	}}
	for i, name := range []string{"em0", "fxp0"} {
		ops.links[name] = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
			Name: name, Index: i + 10, Flags: net.FlagUp, MasterIndex: masters[name],
		}}
	}
	d := &Daemon{
		applySem:     semaphore.NewWeighted(1),
		routing:      routing.NewManagerWithLinkOpsForTest(ops),
		linkByNameFn: ops.LinkByName,
	}
	d.publishMgmtVRFIfaces(map[string]bool{"em0": true, "fxp0": true})
	return d, ops
}

func TestMgmtVRFReassertRepairsUnboundManagementInterfaces11448(t *testing.T) {
	d, ops := newMgmtVRFReassertDaemon11448(t, map[string]int{"em0": 0, "fxp0": 45})
	var routeRefreshes int
	previousRouteReconcile := mgmtVRFRouteReconcileFn
	mgmtVRFRouteReconcileFn = func(*Daemon) error {
		routeRefreshes++
		return nil
	}
	t.Cleanup(func() { mgmtVRFRouteReconcileFn = previousRouteReconcile })
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	d.reassertMgmtVRFOnce(context.Background())

	if len(ops.binds) != 2 || ops.binds[0] == ops.binds[1] {
		t.Fatalf("drifted management links were not each rebound exactly once: %v", ops.binds)
	}
	for _, name := range []string{"em0", "fxp0"} {
		if got := ops.links[name].Attrs().MasterIndex; got != ops.links[config.ManagementVRFDeviceName].Attrs().Index {
			t.Errorf("%s master index = %d, want vrf-mgmt index %d", name, got, ops.links[config.ManagementVRFDeviceName].Attrs().Index)
		}
	}
	if routeRefreshes != 1 {
		t.Errorf("management VRF routes refreshed %d times after binding drift, want once", routeRefreshes)
	}
	if !strings.Contains(logs.String(), "management interface outside the management VRF — re-binding") {
		t.Errorf("drift did not emit the required WARN: %s", logs.String())
	}
}

func TestMgmtVRFReassertLeavesHealthyManagementInterfacesAlone11448(t *testing.T) {
	d, ops := newMgmtVRFReassertDaemon11448(t, map[string]int{"em0": 77, "fxp0": 77})
	var routeRefreshes int
	previousRouteReconcile := mgmtVRFRouteReconcileFn
	mgmtVRFRouteReconcileFn = func(*Daemon) error {
		routeRefreshes++
		return nil
	}
	t.Cleanup(func() { mgmtVRFRouteReconcileFn = previousRouteReconcile })

	d.reassertMgmtVRFOnce(context.Background())

	if len(ops.binds) != 0 {
		t.Errorf("healthy management-VRF members drew netlink binds: %v", ops.binds)
	}
	if routeRefreshes != 0 {
		t.Errorf("healthy management-VRF members refreshed routes %d times, want no writes", routeRefreshes)
	}
}

// #18613: a dual-fabric epoch keeps its constructor-captured fab1 bind, but
// periodic reassert warns once when the active config resolves a different
// local address. The warning is diagnostic only: it does not replace the
// SessionSync, and a successor epoch gets its own warning allowance.
func TestFab1LocalAddressMismatchWarnsOncePerEpoch18613(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-fab1-address-18613",
		"set chassis cluster fabric-interface lo",
		"set chassis cluster fabric-peer-address 127.0.0.2",
		"set chassis cluster fabric1-interface lo",
		"set chassis cluster fabric1-peer-address 2001:db8::3",
	})
	currentHost := "2001:db8::1"
	previousAddrs := clusterInterfaceAddrsByName
	clusterInterfaceAddrsByName = func(_ *config.Config, ifname string) ([]net.Addr, error) {
		if ifname != "lo" {
			return nil, errors.New("unexpected interface " + ifname)
		}
		ip := net.ParseIP(currentHost)
		bits, prefix := 128, 64
		if ip.To4() != nil {
			bits, prefix = 32, 24
		}
		return []net.Addr{&net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(prefix, bits),
		}}, nil
	}
	t.Cleanup(func() { clusterInterfaceAddrsByName = previousAddrs })

	d := &Daemon{
		store:    store,
		applySem: semaphore.NewWeighted(1),
	}
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	publishEpoch := func(localHost string) (*cluster.SessionSync, uint64) {
		t.Helper()
		_, gen, cancel := d.beginClusterCommsEpoch(context.Background())
		t.Cleanup(cancel)
		ss := cluster.NewDualSessionSync(
			"127.0.0.1:4785", "127.0.0.2:4785",
			net.JoinHostPort(localHost, "4785"), net.JoinHostPort("2001:db8::3", "4785"), nil)
		if !d.publishSessionSyncIfCurrent(gen, ss) {
			t.Fatalf("could not publish SessionSync for epoch %d", gen)
		}
		d.publishFab1LocalHostIfCurrent(gen, net.JoinHostPort(localHost, "4785"))
		return ss, gen
	}

	ss1, gen1 := publishEpoch("2001:0db8:0:0:0:0:0:1")
	// Equivalent IPv6 spellings must not trigger the mismatch warning.
	d.reassertMgmtVRFOnce(context.Background())
	if got := strings.Count(logs.String(), "fab1 local address differs"); got != 0 {
		t.Fatalf("equivalent host spellings emitted %d mismatch warnings: %s", got, logs.String())
	}
	if got := d.getSessionSync(); got != ss1 {
		t.Fatalf("equal-address reassert replaced SessionSync in epoch %d: got %p, want %p", gen1, got, ss1)
	}
	currentHost = "2001:db8::2"
	for range 3 {
		d.reassertMgmtVRFOnce(context.Background())
		if got := d.getSessionSync(); got != ss1 {
			t.Fatalf("fab1 mismatch replaced SessionSync in epoch %d: got %p, want %p", gen1, got, ss1)
		}
	}
	const warning = "cluster: fab1 local address differs from the active session-sync epoch"
	if got := strings.Count(logs.String(), warning); got != 1 {
		t.Fatalf("epoch %d emitted %d fab1 mismatch warnings across repeated reasserts, want one: %s",
			gen1, got, logs.String())
	}

	// A replacement epoch captures the then-current host. A further address
	// move gets one new warning without changing that epoch's SessionSync.
	currentHost = "2001:db8::3"
	ss2, gen2 := publishEpoch("2001:db8::2")
	if gen2 == gen1 {
		t.Fatalf("new epoch retained generation %d", gen1)
	}
	for range 3 {
		d.reassertMgmtVRFOnce(context.Background())
		if got := d.getSessionSync(); got != ss2 {
			t.Fatalf("fab1 mismatch replaced SessionSync in epoch %d: got %p, want %p", gen2, got, ss2)
		}
	}
	if got := strings.Count(logs.String(), warning); got != 2 {
		t.Fatalf("two mismatched epochs emitted %d fab1 mismatch warnings, want one per epoch: %s",
			got, logs.String())
	}
}

// #18613 race arm (GLM delta): the resolve runs unlocked; an epoch
// replacement DURING it must not let the stale result warn against
// (or spend the allowance of) the successor epoch. The injected
// resolver hook swaps the epoch mid-resolution.
func TestFab1MismatchStaleResolveDoesNotWarnAgainstSuccessor18613(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-fab1-address-18613",
		"set chassis cluster fabric-interface lo",
		"set chassis cluster fabric-peer-address 127.0.0.2",
		"set chassis cluster fabric1-interface lo",
		"set chassis cluster fabric1-peer-address 2001:db8::3",
	})
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1)}
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	publish := func(localHost string) uint64 {
		_, gen, cancel := d.beginClusterCommsEpoch(context.Background())
		t.Cleanup(cancel)
		ss := cluster.NewDualSessionSync(
			"127.0.0.1:4785", "127.0.0.2:4785",
			net.JoinHostPort(localHost, "4785"), net.JoinHostPort("2001:db8::3", "4785"), nil)
		if !d.publishSessionSyncIfCurrent(gen, ss) {
			t.Fatalf("publish epoch %d", gen)
		}
		d.publishFab1LocalHostIfCurrent(gen, net.JoinHostPort(localHost, "4785"))
		return gen
	}
	gen1 := publish("2001:db8::1")

	swapped := false
	previousAddrs := clusterInterfaceAddrsByName
	clusterInterfaceAddrsByName = func(_ *config.Config, _ string) ([]net.Addr, error) {
		if !swapped {
			swapped = true
			publish("2001:db8::2") // successor epoch replaces gen1 mid-resolve
		}
		ip := net.ParseIP("2001:db8::9")
		return []net.Addr{&net.IPNet{IP: ip, Mask: net.CIDRMask(64, 128)}}, nil
	}
	t.Cleanup(func() { clusterInterfaceAddrsByName = previousAddrs })

	d.warnFab1LocalAddressMismatch(store.ActiveConfig())
	if strings.Contains(logs.String(), "cluster: fab1 local address differs") {
		t.Fatalf("stale resolve warned against the successor epoch: %s", logs.String())
	}
	// No allowance spent on the SUCCESSOR epoch either: publish reset
	// its latch to 0, and the stale path must leave it there (gen1 is
	// superseded; a direct gen compare would be racy to assert).
	d.fabricMu.RLock()
	warned := d.fab1LocalWarnedGen
	latchedEpoch := d.fab1LocalGen
	d.fabricMu.RUnlock()
	if warned != 0 {
		t.Fatalf("stale resolve spent the successor epoch's allowance (warnedGen=%d, epoch=%d)", warned, latchedEpoch)
	}
	_ = gen1
}

func TestFab1MismatchSkipsResolveWithoutDualEpochHost18613(t *testing.T) {
	cfg := &config.Config{Chassis: config.ChassisConfig{Cluster: &config.ClusterConfig{
		FabricInterface: "fab0", FabricPeerAddress: "10.99.0.2",
		Fabric1Interface: "fab1", Fabric1PeerAddress: "10.99.1.2",
	}}}
	previousAddrs := clusterInterfaceAddrsByName
	resolutions := 0
	missing := true
	clusterInterfaceAddrsByName = func(*config.Config, string) ([]net.Addr, error) {
		resolutions++
		if missing {
			return nil, errors.New("injected missing fab1")
		}
		return []net.Addr{&net.IPNet{
			IP: net.ParseIP("10.99.1.3"), Mask: net.CIDRMask(24, 32),
		}}, nil
	}
	t.Cleanup(func() { clusterInterfaceAddrsByName = previousAddrs })
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	d := &Daemon{}
	d.warnFab1LocalAddressMismatch(cfg) // no SessionSync
	if resolutions != 0 {
		t.Fatalf("resolver ran %d times without a published SessionSync, want zero", resolutions)
	}

	d.clusterCommsMu.Lock()
	d.clusterCommsGen = 7
	d.sessionSync = cluster.NewSessionSync("10.99.0.1:4785", "10.99.0.2:4785", nil)
	d.clusterCommsMu.Unlock()
	d.warnFab1LocalAddressMismatch(cfg) // single-fabric epoch
	if resolutions != 0 {
		t.Fatalf("resolver ran %d times for a single-fabric epoch, want zero", resolutions)
	}

	d.clusterCommsMu.Lock()
	d.sessionSync = cluster.NewDualSessionSync(
		"10.99.0.1:4785", "10.99.0.2:4785",
		"10.99.1.1:4785", "10.99.1.2:4785", nil)
	d.clusterCommsMu.Unlock()
	d.warnFab1LocalAddressMismatch(cfg) // dual session, but no recorded epoch host
	if resolutions != 0 {
		t.Fatalf("resolver ran %d times without a recorded epoch host, want zero", resolutions)
	}

	d.fabricMu.Lock()
	d.fab1LocalHost, d.fab1LocalGen = "10.99.1.1", 7
	d.fabricMu.Unlock()
	d.warnFab1LocalAddressMismatch(cfg) // empty resolution is not an address mismatch
	if resolutions != 1 {
		t.Fatalf("resolver ran %d times with a current dual epoch host, want one", resolutions)
	}
	if strings.Contains(logs.String(), "cluster: fab1 local address differs") {
		t.Fatalf("empty resolution emitted a fab1 address-mismatch warning: %s", logs.String())
	}
	d.fabricMu.RLock()
	warnedGen := d.fab1LocalWarnedGen
	d.fabricMu.RUnlock()
	if warnedGen == 7 {
		t.Fatal("empty resolution consumed the epoch's mismatch-warning allowance")
	}

	// Sol #18613: while eligible-but-unresolvable, repeated ticks must
	// not storm ANY warning. The resolver's own generic WARN
	// ("using fallback") firing per tick is the storm shape; count
	// every WARN record across repeated empty/failed resolutions.
	warnBefore := strings.Count(logs.String(), "level=WARN")
	for range 3 {
		d.warnFab1LocalAddressMismatch(cfg)
	}
	if got := strings.Count(logs.String(), "level=WARN"); got != warnBefore {
		t.Fatalf("eligible-but-unresolvable ticks emitted %d new WARN records, want 0 (warn storm): %s", got-warnBefore, logs.String())
	}
	if resolutions != 4 {
		t.Fatalf("resolver ran %d times after repeated unresolvable ticks, want 4 total", resolutions)
	}

	missing = false
	d.warnFab1LocalAddressMismatch(cfg) // recovery to a different address is still checked
	if resolutions != 5 {
		t.Fatalf("resolver ran %d times after fab1 became addressable, want five total", resolutions)
	}
	if got := strings.Count(logs.String(), "cluster: fab1 local address differs"); got != 1 {
		t.Fatalf("resolved mismatch warnings = %d, want one: %s", got, logs.String())
	}
}

func TestMgmtVRFReassertLatchesRouteRefreshDebt11448(t *testing.T) {
	d, _ := newMgmtVRFReassertDaemon11448(t, map[string]int{"em0": 0, "fxp0": 77})
	routeErr := errors.New("injected management route refresh failure")
	previousRouteReconcile := mgmtVRFRouteReconcileFn
	mgmtVRFRouteReconcileFn = func(*Daemon) error { return routeErr }
	t.Cleanup(func() { mgmtVRFRouteReconcileFn = previousRouteReconcile })

	d.reassertMgmtVRFOnce(context.Background())

	if owed, failures, last := d.RoutingReconcileDebt(); !owed ||
		failures != 1 || last != routeErr.Error() {
		t.Fatalf("route refresh failure must enter management-route debt: owed=%v failures=%d last=%q",
			owed, failures, last)
	}
}

func TestMgmtVRFReassertLoopConvergesAfterUnbind11448(t *testing.T) {
	previousInterval := mgmtVRFReassertInterval
	mgmtVRFReassertInterval = 10 * time.Millisecond
	t.Cleanup(func() { mgmtVRFReassertInterval = previousInterval })

	d, ops := newMgmtVRFReassertDaemon11448(t, map[string]int{"em0": 0, "fxp0": 0})
	routeRefreshed := make(chan struct{}, 1)
	previousRouteReconcile := mgmtVRFRouteReconcileFn
	mgmtVRFRouteReconcileFn = func(*Daemon) error {
		select {
		case routeRefreshed <- struct{}{}:
		default:
		}
		return nil
	}
	t.Cleanup(func() { mgmtVRFRouteReconcileFn = previousRouteReconcile })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		d.mgmtVRFReassertLoop(ctx)
		close(done)
	}()

	select {
	case <-routeRefreshed:
	case <-time.After(time.Second):
		cancel()
		if !waitForMgmtVRFLoopExit11448(t, done) {
			return
		}
		t.Fatal("periodic management-VRF reassert did not refresh routes after drift")
	}
	cancel()
	if !waitForMgmtVRFLoopExit11448(t, done) {
		return
	}

	if len(ops.binds) != 2 {
		t.Fatalf("periodic reassert bound %d interfaces, want em0 and fxp0: %v", len(ops.binds), ops.binds)
	}
	for _, name := range []string{"em0", "fxp0"} {
		if got := ops.links[name].Attrs().MasterIndex; got != 77 {
			t.Errorf("%s master index after periodic reassert = %d, want vrf-mgmt index 77", name, got)
		}
	}
}

func waitForMgmtVRFLoopExit11448(t *testing.T, done <-chan struct{}) bool {
	t.Helper()
	select {
	case <-done:
		return true
	case <-time.After(time.Second):
		t.Error("management-VRF reassert loop did not stop after cancellation")
		return false
	}
}

func TestMgmtVRFReassertUsesOnlyPublishedManagementSet11448(t *testing.T) {
	d, ops := newMgmtVRFReassertDaemon11448(t, map[string]int{"em0": 0, "fxp0": 0})
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true})

	d.reassertMgmtVRFOnce(context.Background())

	if len(ops.binds) != 1 || ops.binds[0] != "fxp0->vrf-mgmt" {
		t.Errorf("reassert bound links outside the published management set: %v", ops.binds)
	}
}

func TestMgmtVRFReassertHonorsCancellation11448(t *testing.T) {
	d, ops := newMgmtVRFReassertDaemon11448(t, map[string]int{"em0": 0, "fxp0": 0})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	d.reassertMgmtVRFOnce(ctx)

	if len(ops.binds) != 0 {
		t.Errorf("cancelled reassert pass bound links: %v", ops.binds)
	}
}

// This is the management-VRF counterpart to the #9813 kernel acceptance cell:
// the real netlink manager repairs a device after an out-of-band nomaster.
func TestMgmtVRFReassertRepairsOutOfBandUnbindInKernel11448(t *testing.T) {
	enterPrivateNetns9813(t)

	vrf := &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: config.ManagementVRFDeviceName},
		Table:     config.ManagementVRFTableID,
	}
	if err := netlink.LinkAdd(vrf); err != nil {
		t.Fatalf("cannot create management VRF in this netns (is the vrf module loaded?): %v", err)
	}
	if err := netlink.LinkSetUp(vrf); err != nil {
		t.Fatalf("bring management VRF up: %v", err)
	}
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fxp0"}}); err != nil {
		t.Fatalf("cannot create dummy fxp0 in this netns: %v", err)
	}
	rt, err := routing.New()
	if err != nil {
		t.Fatalf("routing.New: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	d := &Daemon{
		applySem:     semaphore.NewWeighted(1),
		routing:      rt,
		linkByNameFn: netlink.LinkByName,
	}
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true})
	if err := rt.BindInterfaceToVRF("fxp0", config.ManagementVRFInstanceName); err != nil {
		t.Fatalf("initial management-VRF bind: %v", err)
	}
	fxp0, err := netlink.LinkByName("fxp0")
	if err != nil {
		t.Fatalf("lookup fxp0 before out-of-band unbind: %v", err)
	}
	if err := netlink.LinkSetNoMaster(fxp0); err != nil {
		t.Fatalf("out-of-band fxp0 nomaster: %v", err)
	}

	d.reassertMgmtVRFOnce(context.Background())

	fxp0, err = netlink.LinkByName("fxp0")
	if err != nil {
		t.Fatalf("lookup fxp0 after reassert: %v", err)
	}
	vrfLink, err := netlink.LinkByName(config.ManagementVRFDeviceName)
	if err != nil {
		t.Fatalf("lookup vrf-mgmt after reassert: %v", err)
	}
	if got := fxp0.Attrs().MasterIndex; got != vrfLink.Attrs().Index {
		t.Fatalf("fxp0 master index after out-of-band unbind and reassert = %d, want vrf-mgmt index %d",
			got, vrfLink.Attrs().Index)
	}
}
