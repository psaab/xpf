package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
	"github.com/vishvananda/netlink"
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
// published. Publishing desired membership after a failed kernel bind must not
// restart working comms; the later kernel-master transition must still select
// one restart even though the published set did not change.
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
	vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: config.ManagementVRFDeviceName, Index: 77}}
	control := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "em0", Index: 10}}
	d.linkByNameFn = func(name string) (netlink.Link, error) {
		switch name {
		case "em0":
			return control, nil
		case config.ManagementVRFDeviceName:
			return vrf, nil
		default:
			return nil, errors.New("unknown fixture link")
		}
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

	// Desired membership can publish before the authoritative post-networkd
	// bind succeeds. That is not kernel evidence and must leave comms intact.
	d.publishMgmtVRFIfaces(map[string]bool{"em0": true})
	_ = d.applyTailReconciles(cfg, applyPhaseErrors{})
	if starts != 0 || generation() != before {
		t.Fatalf("desired-only membership restarted comms: starts=%d generation=%d->%d",
			starts, before, generation())
	}
	if got := d.activeTransport().VRFDevice; got != "" {
		t.Fatalf("desired-only membership published active VRF %q", got)
	}

	// Genuine kernel convergence, without changing the published set, is the
	// transition that must restart the unbound comms epoch.
	control.Attrs().MasterIndex = vrf.Attrs().Index
	_ = d.applyTailReconciles(cfg, applyPhaseErrors{})
	if starts != 1 {
		t.Fatalf("kernel membership convergence started comms %d times, want 1 restart", starts)
	}
	if got := d.clusterTransportForConfig(cfg).VRFDevice; got != config.ManagementVRFDeviceName {
		t.Fatalf("converged transport VRF device = %q, want %q", got, config.ManagementVRFDeviceName)
	}
	if after := generation(); after == before {
		t.Fatalf("VRF membership convergence did not advance comms generation: %d", after)
	}
}

func TestClusterTransportKeyTracksVRFConvergence12168(t *testing.T) {
	d := &Daemon{}
	control := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "em0", Index: 10}}
	fab0 := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fab0", Index: 11}}
	fab1 := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "fab1", Index: 12}}
	vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: config.ManagementVRFDeviceName, Index: 77}}
	missingFab1 := false
	d.linkByNameFn = func(name string) (netlink.Link, error) {
		switch name {
		case "em0":
			return control, nil
		case "fab0":
			return fab0, nil
		case "fab1":
			if missingFab1 {
				return nil, errors.New("fab1 missing")
			}
			return fab1, nil
		case config.ManagementVRFDeviceName:
			return vrf, nil
		default:
			return nil, errors.New("unknown fixture link")
		}
	}
	// Desired membership alone cannot make a main-table transport look bound.

	controlCfg := &config.Config{}
	controlCfg.Chassis.Cluster = &config.ClusterConfig{
		ControlInterface: "em0",
		PeerAddress:      "192.0.2.2",
	}

	d.publishMgmtVRFIfaces(nil)
	controlUnbound := d.clusterTransportForConfig(controlCfg)
	if controlUnbound.VRFDevice != "" {
		t.Fatalf("unbound control interface resolved VRF %q", controlUnbound.VRFDevice)
	}
	d.publishMgmtVRFIfaces(map[string]bool{"em0": true})
	if got := d.clusterTransportForConfig(controlCfg); got != controlUnbound {
		t.Fatalf("desired-only control membership changed transport key: before=%+v after=%+v",
			controlUnbound, got)
	}
	control.Attrs().MasterIndex = vrf.Attrs().Index
	controlBound := d.clusterTransportForConfig(controlCfg)
	if controlBound == controlUnbound || controlBound.VRFDevice != config.ManagementVRFDeviceName {
		t.Fatalf("published kernel control membership produced key %+v, want VRF %q",
			controlBound, config.ManagementVRFDeviceName)
	}

	fabricCfg := &config.Config{}
	fabricCfg.Chassis.Cluster = &config.ClusterConfig{
		FabricInterface:    "fab0",
		FabricPeerAddress:  "192.0.2.3",
		Fabric1Interface:   "fab1",
		Fabric1PeerAddress: "192.0.2.4",
	}
	d.publishMgmtVRFIfaces(map[string]bool{"fab0": true, "fab1": true})
	fabricUnbound := d.clusterTransportForConfig(fabricCfg)
	if fabricUnbound.VRFDevice != "" {
		t.Fatalf("unbound primary fabric interface resolved VRF %q", fabricUnbound.VRFDevice)
	}
	fab0.Attrs().MasterIndex = vrf.Attrs().Index
	fabricPrimaryBound := d.clusterTransportForConfig(fabricCfg)
	if fabricPrimaryBound == fabricUnbound || fabricPrimaryBound.VRFDevice != config.ManagementVRFDeviceName {
		t.Fatalf("healthy primary with unbound secondary did not select VRF: before=%+v after=%+v",
			fabricUnbound, fabricPrimaryBound)
	}
	missingFab1 = true
	if got := d.clusterTransportForConfig(fabricCfg); got != fabricPrimaryBound {
		t.Fatalf("missing secondary changed primary-only transport key: before=%+v after=%+v",
			fabricPrimaryBound, got)
	}
	missingFab1 = false
	if got := d.clusterTransportForConfig(fabricCfg); got != fabricPrimaryBound {
		t.Fatalf("secondary outside VRF changed primary-only transport key: before=%+v after=%+v",
			fabricPrimaryBound, got)
	}
	fab1.Attrs().MasterIndex = vrf.Attrs().Index
	if got := d.clusterTransportForConfig(fabricCfg); got != fabricPrimaryBound {
		t.Fatalf("secondary VRF convergence changed primary-only transport key: before=%+v after=%+v",
			fabricPrimaryBound, got)
	}
}

func TestDaemonPeerDialResolverTracksCurrentTransportBinding12168(t *testing.T) {
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key xpf-peer-resolver-key-12168",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 192.0.2.2",
		"set interfaces em0 unit 0 family inet address 192.0.2.1/24",
	})
	control := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "em0", Index: 10}}
	vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: config.ManagementVRFDeviceName, Index: 77}}
	d := &Daemon{
		store: store,
		linkByNameFn: func(name string) (netlink.Link, error) {
			switch name {
			case "em0":
				return control, nil
			case config.ManagementVRFDeviceName:
				return vrf, nil
			default:
				return nil, errors.New("unknown fixture link")
			}
		},
	}
	d.publishMgmtVRFIfaces(nil)
	if got := d.clusterPeerVRFDevice(); got != "" {
		t.Fatalf("unpublished kernel VRF binding resolved %q", got)
	}
	d.publishMgmtVRFIfaces(map[string]bool{"em0": true})
	if got := d.clusterPeerVRFDevice(); got != "" {
		t.Fatalf("published but unbound transport resolved %q", got)
	}
	control.Attrs().MasterIndex = vrf.Attrs().Index
	if got := d.clusterPeerVRFDevice(); got != config.ManagementVRFDeviceName {
		t.Fatalf("converged active transport resolved %q, want vrf-mgmt", got)
	}
	d.publishMgmtVRFIfaces(nil)
	if got := d.clusterPeerVRFDevice(); got != "" {
		t.Fatalf("withdrawn membership retained peer dial binding %q", got)
	}
}
