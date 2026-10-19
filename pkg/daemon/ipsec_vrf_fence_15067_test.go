package daemon

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"

	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #15067 A35-02: a VRF-enslaved xfrmi must be a supported multi-homing
// topology. classifyIpsecTopologyLinks must not mark it UNSAFE merely
// because its master is a VRF (the divert + fence already scope it by
// iifname=master + sdifname=tunnel, #14974), otherwise the permit never
// OPENs, the fence overlay (which only retires on OPEN) never retires,
// and the slave-scoped DROP stays at the head of host-inbound forever.

func vrfTopologyLinks15067() (vrf *netlink.Vrf, xfrmi *netlink.Xfrmi, outlet *netlink.Tuntap) {
	vrf = &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-blue", Index: 22}}
	xfrmi = &netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: "st0.0", Index: 11, MasterIndex: 22}}
	outlet = &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: armedTransitReinjectIfname, Index: 33}}
	return vrf, xfrmi, outlet
}

func stubTopology15067(t *testing.T, links []netlink.Link, byIndex map[int]netlink.Link) {
	t.Helper()
	oldList, oldByIndex := ipsecTopologyLinkList, ipsecFenceLinkByIndex
	t.Cleanup(func() { ipsecTopologyLinkList, ipsecFenceLinkByIndex = oldList, oldByIndex })
	ipsecTopologyLinkList = func() ([]netlink.Link, error) { return links, nil }
	ipsecFenceLinkByIndex = func(index int) (netlink.Link, error) {
		if l, ok := byIndex[index]; ok {
			return l, nil
		}
		return nil, nil
	}
}

func TestIpsecTopologyCensusVRFEnslavedSafe15067(t *testing.T) {
	vrf, xfrmi, outlet := vrfTopologyLinks15067()
	stubTopology15067(t, []netlink.Link{xfrmi, vrf, outlet}, map[int]netlink.Link{22: vrf})
	s := newIpsecSupervisor()
	d := &Daemon{ipsecS4: s}
	d.ipsecTopologySubscribed.Store(true)
	d.pollIpsecTopology()
	snap := s.watch.Load()
	if snap == nil {
		t.Fatal("census published no snapshot")
	}
	if snap.Ready != ipsecReadySafe {
		t.Fatalf("census ready = %v, want SAFE for VRF-enslaved xfrmi (A35-02: VRF master must not be UNSAFE)", snap.Ready)
	}
	var got *ipsecTopologyTuple
	for i := range snap.Tuples {
		if snap.Tuples[i].Kind == "xfrmi" {
			got = &snap.Tuples[i]
		}
	}
	if got == nil || got.Name != "st0.0" || got.MasterIndex != 22 {
		t.Fatalf("census tuples = %+v, want xfrmi st0.0 master 22", snap.Tuples)
	}
	permit := s.loadPermit()
	if permit == nil {
		t.Fatal("no permit after census")
	}
	if !s.tryOpenPermit(permit, snap.closeKey(), snap.Generation) {
		t.Fatalf("permit did not OPEN on SAFE VRF census: %+v", permit)
	}
	if got := s.loadPermit(); got == nil || got.state != ipsecPermitOpen {
		t.Fatalf("permit state = %v, want OPEN", got.state)
	}
}

func TestIpsecTopologyCensusBridgeEnslavedUnsafe15067(t *testing.T) {
	br := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "br0", Index: 22}}
	xfrmi := &netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: "st0.0", Index: 11, MasterIndex: 22}}
	outlet := &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: armedTransitReinjectIfname, Index: 33}}
	stubTopology15067(t, []netlink.Link{xfrmi, br, outlet}, map[int]netlink.Link{22: br})
	s := newIpsecSupervisor()
	d := &Daemon{ipsecS4: s}
	d.ipsecTopologySubscribed.Store(true)
	d.pollIpsecTopology()
	snap := s.watch.Load()
	if snap == nil || snap.Ready != ipsecReadyUnsafe {
		t.Fatalf("census ready = %v, want UNSAFE for bridge-enslaved xfrmi (unsupported master stays fail-closed)", snapshotReady(snap))
	}
}

func TestIpsecTopologyCensusNonVRFMasterUnsafe15067(t *testing.T) {
	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "dummy0", Index: 22}}
	xfrmi := &netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: "st0.0", Index: 11, MasterIndex: 22}}
	outlet := &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: armedTransitReinjectIfname, Index: 33}}
	stubTopology15067(t, []netlink.Link{xfrmi, dummy, outlet}, map[int]netlink.Link{22: dummy})
	s := newIpsecSupervisor()
	d := &Daemon{ipsecS4: s}
	d.ipsecTopologySubscribed.Store(true)
	d.pollIpsecTopology()
	snap := s.watch.Load()
	if snap == nil || snap.Ready != ipsecReadyUnsafe {
		t.Fatalf("census ready = %v, want UNSAFE for non-VRF/non-bridge master", snapshotReady(snap))
	}
}

func TestIpsecHostFenceRetiresAfterVRFOpen15067(t *testing.T) {
	vrf, xfrmi, outlet := vrfTopologyLinks15067()
	stubTopology15067(t, []netlink.Link{xfrmi, vrf, outlet}, map[int]netlink.Link{22: vrf})

	origInstaller := nftInstaller
	origDelete := conntrackDeleteFilters
	origOverlayDelete := hostInputFenceConntrackDeleteFilters
	origCensus := hostInputFenceAllLocalAddrs
	t.Cleanup(func() {
		nftInstaller = origInstaller
		conntrackDeleteFilters = origDelete
		hostInputFenceConntrackDeleteFilters = origOverlayDelete
		hostInputFenceAllLocalAddrs = origCensus
	})
	hostInputFenceAllLocalAddrs = func() ([]string, error) { return nil, nil }
	conntrackDeleteFilters = func(netlink.InetFamily, ...netlink.CustomConntrackFilter) (uint, error) { return 0, nil }
	hostInputFenceConntrackDeleteFilters = func(netlink.InetFamily, ...netlink.CustomConntrackFilter) (uint, error) { return 0, nil }
	var lastSpec xnft.HostInboundSpec
	var installs int
	nftInstaller = &fakeNftInstaller{
		hostInbound:     func(spec xnft.HostInboundSpec) error { lastSpec = spec; installs++; return nil },
		overlayReadback: func(xnft.HostInputFenceOverlay) error { return nil },
	}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride("system { host-name s4-vrf; }"); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	s := newIpsecSupervisor()
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1), ipsecS4: s}
	d.ipsecTopologySubscribed.Store(true)
	// Divert active gate.
	d.ipsecCaptureMu.Lock()
	d.ipsecCapture = &ipsecCaptureRuntime{}
	d.ipsecCaptureMu.Unlock()

	d.pollIpsecTopology()
	snap := s.watch.Load()
	if snap == nil || snap.Ready != ipsecReadySafe {
		t.Fatalf("census ready = %v, want SAFE", snapshotReady(snap))
	}
	permit := s.loadPermit()
	if permit == nil || permit.state != ipsecPermitClosing {
		t.Fatalf("permit = %+v, want CLOSING before fence", permit)
	}
	d.reconcileIpsecHostInputFence(context.Background())
	if got := s.loadPermit(); got == nil || got.state != ipsecPermitOpen {
		t.Fatalf("permit after fence ack = %+v, want OPEN (fence must be able to retire)", got)
	}
	active := d.activeHostInputFenceOverlay()
	if active != nil {
		// Overlay may still be published until the OPEN retire pass; run again.
		d.reconcileIpsecHostInputFence(context.Background())
		active = d.activeHostInputFenceOverlay()
	}
	if active != nil {
		t.Fatalf("fence overlay never retired after OPEN: %+v installs=%d", active, installs)
	}
	// The retired (ordinary) host-inbound must not carry a fence drop.
	if lastSpec.Overlay != nil && len(lastSpec.Overlay.MasterSlavePairs) == 0 && len(lastSpec.Overlay.MasterSet) == 0 && lastSpec.Overlay.State != "RETIRING" {
		t.Fatalf("final spec still fences: %+v", lastSpec.Overlay)
	}
	if lastSpec.Overlay != nil && lastSpec.Overlay.State == "CLOSING" {
		t.Fatalf("final overlay still CLOSING: %+v", lastSpec.Overlay)
	}
}
