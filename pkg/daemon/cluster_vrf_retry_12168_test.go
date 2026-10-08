package daemon

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
)

// Keep apply-tail's DNS reconciliation inside the test tempdir; the real
// kernel acceptance test isolates networking, not the host filesystem.
func useTemporaryDNSReconciler12168(t *testing.T) {
	t.Helper()
	rec, _ := newTestReconciler(t, t.TempDir())
	prev := newDNSReconcilerFn
	newDNSReconcilerFn = func() *dnsReconciler { return rec }
	t.Cleanup(func() { newDNSReconcilerFn = prev })
}

// TestVRFMembershipConvergenceRestartsClusterComms12168 reproduces a failed
// boot apply that starts cluster comms before management-VRF membership is
// published, followed by an apply that publishes the membership. Step 20 must
// select a restart from that membership transition, not leave the original
// unbound epoch active.
func TestVRFMembershipConvergenceRestartsClusterComms12168(t *testing.T) {
	useTemporaryDNSReconciler12168(t)

	installFakeNetworkctl(t)

	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		ClusterID:        1,
		NodeID:           0,
		ControlInterface: "em0",
		PeerAddress:      "192.0.2.2",
	}
	d := &Daemon{
		store:     newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		networkd:  networkd.NewInDir(t.TempDir()),
		vrrpMgr:   vrrp.NewManager(),
		cluster:   cluster.NewManager(0, 1),
		daemonCtx: context.Background(),
		opts:      Options{NoDataplane: true},
	}
	t.Cleanup(d.cluster.StopHeartbeat)
	d.activeClusterTransport = clusterTransportFromConfig(cfg)
	if d.activeClusterTransport == (clusterTransportKey{}) {
		t.Fatal("fixture requires an active, non-zero cluster transport")
	}
	d.publishMgmtVRFIfaces(nil) // failed boot apply did not publish membership

	starts := 0
	d.startClusterCommsFn = func(context.Context) { starts++ }
	generation := func() uint64 {
		d.clusterCommsMu.Lock()
		defer d.clusterCommsMu.Unlock()
		return d.clusterCommsGen
	}
	before := generation()

	// The later successful apply publishes the interface after binding it to
	// vrf-mgmt. No real network interface or cluster socket is needed to observe
	// step 20's restart decision; this fixture asserts the production call site.
	d.publishMgmtVRFIfaces(map[string]bool{"em0": true})
	_ = d.applyTailReconciles(cfg, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	if starts != 1 {
		t.Fatalf("VRF membership convergence started comms %d times, want 1 restart", starts)
	}
	if got := d.resolveClusterVRFDevice("em0"); got != config.ManagementVRFDeviceName {
		t.Fatalf("converged heartbeat VRF device = %q, want %q", got, config.ManagementVRFDeviceName)
	}
	if after := generation(); after == before {
		t.Fatalf("VRF membership convergence did not advance comms generation: %d", after)
	}
}

func TestClusterTransportKeyTracksVRFConvergence12168(t *testing.T) {
	d := &Daemon{}
	controlCfg := &config.Config{}
	controlCfg.Chassis.Cluster = &config.ClusterConfig{
		ControlInterface: "em0",
		PeerAddress:      "192.0.2.2",
	}

	d.publishMgmtVRFIfaces(nil)
	controlUnpublished := d.clusterTransportForConfig(controlCfg)
	if controlUnpublished.VRFDevice != "" {
		t.Fatalf("unpublished control membership resolved VRF %q", controlUnpublished.VRFDevice)
	}
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true})
	if got := d.clusterTransportForConfig(controlCfg); got != controlUnpublished {
		t.Fatalf("unrelated management member changed transport key: before=%+v after=%+v",
			controlUnpublished, got)
	}
	d.publishMgmtVRFIfaces(map[string]bool{"em0": true})
	controlBound := d.clusterTransportForConfig(controlCfg)
	if controlBound == controlUnpublished || controlBound.VRFDevice != config.ManagementVRFDeviceName {
		t.Fatalf("control membership produced key %+v, want VRF %q",
			controlBound, config.ManagementVRFDeviceName)
	}

	fabricCfg := &config.Config{}
	fabricCfg.Chassis.Cluster = &config.ClusterConfig{
		FabricInterface:    "fab0",
		FabricPeerAddress:  "192.0.2.3",
		Fabric1Interface:   "fab1",
		Fabric1PeerAddress: "192.0.2.4",
	}
	d.publishMgmtVRFIfaces(nil)
	fabricUnpublished := d.clusterTransportForConfig(fabricCfg)
	if fabricUnpublished.VRFDevice != "" {
		t.Fatalf("unpublished fabric membership resolved VRF %q", fabricUnpublished.VRFDevice)
	}
	d.publishMgmtVRFIfaces(map[string]bool{"fab0": true})
	primaryOnly := d.clusterTransportForConfig(fabricCfg)
	if primaryOnly != fabricUnpublished {
		t.Fatalf("dual-fabric key selected VRF with only one member: before=%+v after=%+v",
			fabricUnpublished, primaryOnly)
	}
	d.publishMgmtVRFIfaces(map[string]bool{"fab0": true, "fab1": true})
	fabricBound := d.clusterTransportForConfig(fabricCfg)
	if fabricBound == fabricUnpublished || fabricBound.VRFDevice != config.ManagementVRFDeviceName {
		t.Fatalf("dual-fabric membership produced key %+v, want VRF %q",
			fabricBound, config.ManagementVRFDeviceName)
	}
}
