package daemon

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/grpcapi"
	"github.com/vishvananda/netlink"
)

func newVRFBindingRetryDaemon12168(t *testing.T, lines []string, withGRPC bool) *Daemon {
	t.Helper()
	store := testStoreWithSetConfig(t, lines)
	ctx, cancel := context.WithCancel(context.Background())
	manager := cluster.NewManager(0, 1)
	d := &Daemon{store: store, cluster: manager, daemonCtx: ctx}
	if withGRPC {
		d.grpcSrv = grpcapi.NewServer("", grpcapi.Config{Store: store, Cluster: manager})
	}
	vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: config.ManagementVRFDeviceName, Index: 77}}
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "lo", Index: 1}}
	d.linkByNameFn = func(name string) (netlink.Link, error) {
		switch name {
		case config.ManagementVRFDeviceName:
			return vrf, nil
		case "lo":
			return link, nil
		default:
			return nil, errors.New("unknown test link")
		}
	}
	d.publishMgmtVRFIfaces(map[string]bool{"lo": true})
	t.Cleanup(func() {
		d.stopClusterComms()
		manager.Stop()
		cancel()
	})
	return d
}

func waitVRFLinkLookups12168(t *testing.T, got *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if got.Load() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("transport resolver made %d loopback lookups, want at least %d", got.Load(), want)
}

// Snapshot MasterIndex before publishing the lookup count. A test can then
// change membership without racing either the returned link or its reader.
func trackVRFBindingLink12168(d *Daemon, master *atomic.Int32) *atomic.Int32 {
	lookups := new(atomic.Int32)
	d.linkByNameFn = func(name string) (netlink.Link, error) {
		switch name {
		case "lo":
			index := int(master.Load())
			lookups.Add(1)
			return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
				Name: "lo", Index: 1, MasterIndex: index,
			}}, nil
		case config.ManagementVRFDeviceName:
			return &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{
				Name: config.ManagementVRFDeviceName, Index: 77,
			}}, nil
		default:
			return nil, errors.New("unknown test link")
		}
	}
	return lookups
}

func waitVRFCommsConstructor12168(t *testing.T, d *Daemon) {
	t.Helper()
	d.clusterCommsMu.Lock()
	epoch := d.clusterCommsEpoch
	d.clusterCommsMu.Unlock()
	if epoch == nil {
		t.Fatal("no cluster communications epoch is active")
	}
	done := make(chan struct{})
	go func() {
		epoch.constructorWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("session-sync constructor did not finish")
	}
}

func waitFabricListenerUp12168(t *testing.T, d *Daemon, addr string) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if d.grpcSrv.FabricListenerUp(addr) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("fabric gRPC listener %q did not start", addr)
}

func waitVRFBindingChanged12168(t *testing.T, d *Daemon) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if d.activeTransport().BindingChanged {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("off-key bind did not mark activeTransport().BindingChanged: %+v", d.activeTransport())
}

var vrfBindingFabricConfig12168 = []string{
	"set chassis cluster cluster-id 1",
	"set chassis cluster node 0",
	"set chassis cluster authentication-key binding-retry-test-12168",
	"set chassis cluster fabric-interface lo",
	"set chassis cluster fabric-peer-address 127.0.0.2",
}

var vrfBindingControlConfig12168 = []string{
	"set chassis cluster cluster-id 1",
	"set chassis cluster node 0",
	"set chassis cluster authentication-key binding-retry-test-12168",
	"set chassis cluster control-interface lo",
	"set chassis cluster peer-address 127.0.0.2",
}

// This exercises the real session-sync retry loop without namespaces. The
// occupied listener forces another Start attempt; each attempt must re-resolve
// the binding rather than reuse the value computed before the loop.
func TestSessionSyncResolvesVRFBindingPerAttempt12168(t *testing.T) {
	occupier, err := net.Listen("tcp4", "127.0.0.1:4785")
	if err != nil {
		t.Fatalf("reserve session-sync listener: %v", err)
	}
	t.Cleanup(func() { _ = occupier.Close() })
	grpcProbe, err := net.Listen("tcp4", "127.0.0.1:50051")
	if err != nil {
		t.Fatalf("check fabric gRPC listener availability: %v", err)
	}
	_ = grpcProbe.Close()

	d := newVRFBindingRetryDaemon12168(t, vrfBindingFabricConfig12168, true)
	var linkLookups atomic.Int32
	d.linkByNameFn = func(name string) (netlink.Link, error) {
		if name == "lo" {
			linkLookups.Add(1)
			return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "lo", Index: 1}}, nil
		}
		if name == config.ManagementVRFDeviceName {
			return &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: config.ManagementVRFDeviceName, Index: 77}}, nil
		}
		return nil, errors.New("unknown test link")
	}
	d.startClusterComms(d.daemonCtx)

	// One lookup computes the epoch key, one opens session sync, and one is
	// the live gRPC listener. A session retry adds another lookup; a frozen
	// session device (M7) leaves the count at three.
	waitVRFLinkLookups12168(t, &linkLookups, 4)
}

// The fabric gRPC supervisor must refresh the device on each bind retry.
// Publish the server before starting comms, then join session-sync startup
// before waiting for repeated gRPC resolver calls. The production late
// grpcSrv assignment in daemon_run_servers.go:301 still races the poller read
// in daemon_ha_comms_wiring.go:229; that pre-existing race is not fixed here,
// and this test does not reproduce it to pin the M8 resolver.
func TestFabricGRPCResolvesVRFBindingPerAttempt12168(t *testing.T) {
	occupier, err := net.Listen("tcp4", "127.0.0.1:50051")
	if err != nil {
		t.Fatalf("reserve fabric gRPC listener: %v", err)
	}
	t.Cleanup(func() { _ = occupier.Close() })
	sessionProbe, err := net.Listen("tcp4", "127.0.0.1:4785")
	if err != nil {
		t.Fatalf("check session-sync listener availability: %v", err)
	}
	_ = sessionProbe.Close()

	d := newVRFBindingRetryDaemon12168(t, vrfBindingFabricConfig12168, true)
	var master atomic.Int32
	linkLookups := trackVRFBindingLink12168(d, &master)
	d.startClusterComms(d.daemonCtx)
	waitVRFCommsConstructor12168(t, d)
	waitVRFLinkLookups12168(t, linkLookups, 3) // key, session sync and gRPC
	if key := d.activeTransport(); key.VRFDevice != "" || key.BindingChanged {
		t.Fatalf("premise: initial main-table binds changed the key: %+v", key)
	}
	baseline := linkLookups.Load()

	master.Store(77) // the retry sees the new kernel master after key publish
	deadline := time.Now().Add(1800 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := linkLookups.Load(); got >= baseline+2 && d.activeTransport().BindingChanged {
			t.Logf("gRPC bind retries refreshed VRF resolver %d times and marked the epoch",
				got-baseline)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("gRPC retries made %d VRF lookups after the initial bind, binding_changed=%v; want >=2 and true",
		linkLookups.Load()-baseline, d.activeTransport().BindingChanged)
}

// startClusterComms must install the manager's live resolver even when no
// heartbeat is configured in the active config. The direct heartbeat stands
// in for a transport that became live after startup; restarting it must consult
// the daemon resolver instead of retaining its startup device.
func TestStartClusterCommsInstallsHeartbeatVRFResolver12168(t *testing.T) {
	d := newVRFBindingRetryDaemon12168(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key binding-retry-test-12168",
	}, false)
	d.startClusterComms(d.daemonCtx)
	if err := d.cluster.StartHeartbeat("127.0.0.1", "127.0.0.1", "", "em0"); err != nil {
		t.Fatalf("start control heartbeat: %v", err)
	}

	var lookups atomic.Int32
	d.publishMgmtVRFIfaces(map[string]bool{"em0": true})
	d.linkByNameFn = func(string) (netlink.Link, error) {
		lookups.Add(1)
		return nil, errors.New("test link unavailable")
	}
	if !d.cluster.RestartHeartbeat() {
		t.Fatal("heartbeat restart failed with an empty-device fallback")
	}
	if got := lookups.Load(); got == 0 {
		t.Fatal("heartbeat restart did not use the resolver installed by startClusterComms (M9)")
	}
}

func TestClusterTransportBindingMismatchStaysSticky12168(t *testing.T) {
	d := &Daemon{clusterCommsGen: 9, activeClusterTransport: clusterTransportKey{
		VRFDevice: config.ManagementVRFDeviceName,
	}}
	d.noteClusterTransportBinding(9, "")
	if !d.activeTransport().BindingChanged {
		t.Fatal("off-key bind did not mark the epoch binding changed")
	}
	d.noteClusterTransportBinding(9, config.ManagementVRFDeviceName)
	if !d.activeTransport().BindingChanged {
		t.Fatal("later matching bind cleared the epoch's earlier off-key bind")
	}
	d.noteClusterTransportBinding(8, "")
	if !d.activeTransport().BindingChanged {
		t.Fatal("stale epoch changed the current binding state")
	}
}

func TestHeartbeatRetryMarksOffKeyBinding12168(t *testing.T) {
	d := newVRFBindingRetryDaemon12168(t, vrfBindingControlConfig12168, false)
	var master atomic.Int32
	master.Store(77)
	trackVRFBindingLink12168(d, &master)
	parent, cancel := context.WithTimeout(d.daemonCtx, time.Second)
	defer cancel()
	ctx, gen, _ := d.beginClusterCommsEpoch(parent)
	key := d.clusterTransportForConfig(d.store.ActiveConfig())
	if key.VRFDevice != config.ManagementVRFDeviceName || gen == 0 ||
		!d.setActiveTransportIfCurrent(gen, key) {
		t.Fatalf("premise: failed to publish bound key %+v for live epoch %d", key, gen)
	}

	master.Store(0) // strip the link after key computation, before heartbeat bind
	d.startHeartbeatWithRetryForEpoch(ctx, "lo", "127.0.0.2", gen)
	if !d.activeTransport().BindingChanged {
		t.Fatal("heartbeat retry did not mark activeTransport().BindingChanged")
	}
}

func TestSessionSyncRetryMarksOffKeyBinding12168(t *testing.T) {
	occupier, err := net.Listen("tcp4", "127.0.0.1:4785")
	if err != nil {
		t.Fatalf("reserve session-sync listener: %v", err)
	}
	t.Cleanup(func() { _ = occupier.Close() })
	grpcProbe, err := net.Listen("tcp4", "127.0.0.1:50051")
	if err != nil {
		t.Fatalf("check fabric gRPC listener availability: %v", err)
	}
	_ = grpcProbe.Close()
	// The gRPC listener is started before flipping the fake master so it
	// cannot mark the key on a later retry.
	d := newVRFBindingRetryDaemon12168(t, vrfBindingFabricConfig12168, true)
	var master atomic.Int32
	lookups := trackVRFBindingLink12168(d, &master)
	d.startClusterComms(d.daemonCtx)
	waitVRFLinkLookups12168(t, lookups, 3) // key, session sync and gRPC
	waitFabricListenerUp12168(t, d, "127.0.0.1:50051")
	if key := d.activeTransport(); key.VRFDevice != "" || key.BindingChanged {
		t.Fatalf("premise: initial main-table binds changed the key: %+v", key)
	}

	// Session sync is still retrying the occupied port. The gRPC listener is
	// already up and the fabric config has no heartbeat, so only session sync
	// can observe this new MasterIndex.
	master.Store(77)
	waitVRFBindingChanged12168(t, d)
}

func TestHeartbeatRestartMarksOffKeyBinding12168(t *testing.T) {
	d := newVRFBindingRetryDaemon12168(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key binding-restart-test-12168",
	}, false)
	var master atomic.Int32
	master.Store(77)
	trackVRFBindingLink12168(d, &master)
	// Install the real RestartHeartbeat closure without starting any sibling
	// transport. Publish the key for the directly started heartbeat below.
	d.startClusterComms(d.daemonCtx)
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		ControlInterface: "lo", PeerAddress: "127.0.0.2",
	}
	key := d.clusterTransportForConfig(cfg)
	gen := warmVRFCommsGeneration12168(d)
	if key.VRFDevice != config.ManagementVRFDeviceName || gen == 0 ||
		!d.setActiveTransportIfCurrent(gen, key) {
		t.Fatalf("premise: failed to publish bound key %+v for live epoch %d", key, gen)
	}
	if err := d.cluster.StartHeartbeat("127.0.0.1", "127.0.0.2", "", "lo"); err != nil {
		t.Fatalf("start control heartbeat: %v", err)
	}
	if d.activeTransport().BindingChanged {
		t.Fatal("premise: direct heartbeat start unexpectedly marked the key")
	}

	master.Store(0)
	if !d.cluster.RestartHeartbeat() {
		t.Fatal("heartbeat restart failed with the stripped main-table binding")
	}
	if !d.activeTransport().BindingChanged {
		t.Fatal("RestartHeartbeat closure did not mark activeTransport().BindingChanged")
	}
}
