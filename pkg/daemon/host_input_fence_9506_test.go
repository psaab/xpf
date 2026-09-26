package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"
)

func TestHostInputFenceConntrackFilterFullRevocation9506(t *testing.T) {
	filter := buildHostInputFenceConntrackFilter([]string{"192.0.2.10", "2001:db8::10"})
	if filter == nil {
		t.Fatal("expected a filter for both address families")
	}
	for _, tc := range []struct {
		name string
		flow *netlink.ConntrackFlow
		want bool
	}{
		{name: "tcp permitted service is still revoked", flow: ctFlow(6, "192.0.2.10", 22), want: true},
		{name: "udp permitted service is still revoked", flow: ctFlow(17, "192.0.2.10", 53), want: true},
		{name: "esp is revoked too", flow: ctFlow(50, "192.0.2.10", 0), want: true},
		{name: "ipv6 destination is revoked", flow: ctFlow(6, "2001:db8::10", 443), want: true},
		{name: "other destination survives", flow: ctFlow(6, "192.0.2.11", 22), want: false},
		{name: "nil flow survives", flow: nil, want: false},
	} {
		if got := filter.MatchConntrackFlow(tc.flow); got != tc.want {
			t.Errorf("%s: MatchConntrackFlow=%v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestHostInputFenceOverlayInstallAndReadback9506(t *testing.T) {
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
	overlayFlushes := 0
	hostInputFenceConntrackDeleteFilters = func(netlink.InetFamily, ...netlink.CustomConntrackFilter) (uint, error) {
		overlayFlushes++
		return 0, nil
	}
	var got xnft.HostInboundSpec
	var verified xnft.HostInputFenceOverlay
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(spec xnft.HostInboundSpec) error {
			got = spec
			return nil
		},
		overlayReadback: func(overlay xnft.HostInputFenceOverlay) error {
			verified = overlay
			return nil
		},
	}
	overlay := &xnft.HostInputFenceOverlay{
		MasterSet:       []string{"st1", "st0", "st1"},
		Generation:      4,
		PermitEpoch:     8,
		CloseRequestSeq: 12,
		CloseRequestKey: "UNSAFE/4",
		WatchGeneration: 4,
		State:           "CLOSING",
	}
	d := &Daemon{}
	d.setHostInputFenceOverlay(overlay)
	if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
		t.Fatalf("apply with overlay: %v", err)
	}
	flushesAfterFirst := overlayFlushes
	if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
		t.Fatalf("reapply with unchanged overlay: %v", err)
	}
	if overlayFlushes != flushesAfterFirst {
		t.Fatalf("unchanged overlay reapply flushed conntrack %d additional times", overlayFlushes-flushesAfterFirst)
	}
	if got.Overlay == nil {
		t.Fatal("host-inbound spec omitted active overlay")
	}
	want := xnft.CanonicalHostInputFenceOverlay(*overlay)
	if !sameHostInputFenceOverlay(got.Overlay, &want) || !sameHostInputFenceOverlay(&verified, &want) {
		t.Fatalf("overlay mismatch: installed=%+v verified=%+v want=%+v", got.Overlay, verified, want)
	}
}

func TestHostInputFenceLiveReadbackAndRestore9506(t *testing.T) {
	enterPrivateNetns9813(t)
	installer := xnft.NewNetlinkInstaller()
	overlay := xnft.HostInputFenceOverlay{
		MasterSet:       []string{"st0"},
		Generation:      7,
		PermitEpoch:     11,
		CloseRequestSeq: 13,
		CloseRequestKey: "3/7/[xfrmi:st0]",
		WatchGeneration: 7,
		State:           "CLOSING",
	}
	t.Cleanup(func() {
		_ = installer.DeleteTable(xnft.HostInboundTableName)
		_ = installer.DeleteTable(xnft.HostInboundGapTableName)
	})
	if err := installer.InstallHostInbound(xnft.HostInboundSpec{Overlay: &overlay}); err != nil {
		t.Fatalf("install live host-input DROP: %v", err)
	}
	if err := installer.VerifyHostInboundOverlay(overlay); err != nil {
		t.Fatalf("exact live overlay readback: %v", err)
	}
	wrongAuthority := overlay
	wrongAuthority.PermitEpoch++
	if err := installer.VerifyHostInboundOverlay(wrongAuthority); err == nil {
		t.Fatal("live overlay readback accepted a different permit epoch")
	}

	if err := installer.InstallHostInbound(xnft.HostInboundSpec{}); err != nil {
		t.Fatalf("restore ordinary host-input table: %v", err)
	}
	if err := installer.VerifyHostInboundOverlay(overlay); err == nil {
		t.Fatal("restored host-input table retained the prior fence marker")
	}
	if err := installer.DeleteTable(xnft.HostInboundTableName); err != nil {
		t.Fatalf("clear restored host-input table: %v", err)
	}
	if err := installer.VerifyHostInboundOverlay(overlay); err == nil {
		t.Fatal("clean restore left the prior fence marker readable")
	}
}

func TestHostInputFenceOverlayReadbackFailureIsNotPublished9506(t *testing.T) {
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
	injected := errors.New("overlay readback mismatch")
	nftInstaller = &fakeNftInstaller{overlayReadback: func(xnft.HostInputFenceOverlay) error { return injected }}
	d := &Daemon{}
	d.setHostInputFenceOverlay(&xnft.HostInputFenceOverlay{MasterSet: []string{"st0"}, Generation: 1, PermitEpoch: 1, State: "CLOSING"})
	err := d.applyHostInboundFilter(hostInboundTestConfig())
	if !errors.Is(err, injected) {
		t.Fatalf("readback error = %v, want wrapped injected error", err)
	}
	if d.hostInboundEnforced.Load() {
		t.Fatal("readback failure published host-inbound enforcement success")
	}
}

func TestHostInputFenceReconcileColdStartFailureRetainsFence9506(t *testing.T) {
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
	injected := errors.New("cold-start overlay readback mismatch")
	nftInstaller = &fakeNftInstaller{overlayReadback: func(xnft.HostInputFenceOverlay) error { return injected }}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride("system { host-name s4-cold-start; }"); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	d := &Daemon{
		store:    store,
		applySem: semaphore.NewWeighted(1),
		ipsecS4:  newIpsecSupervisor(),
	}
	key := testKey(ipsecReadyUnsafe, 4, ipsecTopologyTuple{Kind: "xfrmi", Ifindex: 11, Name: "st0"})
	permit := testClosingRecord(8, 12, key, 4)
	d.ipsecS4.permit.Store(permit)
	d.ipsecS4.watch.Store(&TransitWatchSnapshot{Generation: 4, Ready: ipsecReadyUnsafe, Tuples: key.Tuples})
	d.reconcileIpsecHostInputFence(context.Background())
	active := d.activeHostInputFenceOverlay()
	if active == nil || len(active.MasterSet) != 1 || active.MasterSet[0] != "st0" {
		t.Fatalf("cold-start readback failure cleared conservative fence: %+v", active)
	}
	if d.hostInboundEnforced.Load() {
		t.Fatal("cold-start readback failure reported ordinary host-inbound success")
	}
}

func TestHostInputFenceRetireAckThenClear9506(t *testing.T) {
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
	var events []string
	hostInputFenceConntrackDeleteFilters = func(netlink.InetFamily, ...netlink.CustomConntrackFilter) (uint, error) {
		events = append(events, "ct")
		return 0, nil
	}
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(spec xnft.HostInboundSpec) error {
			if spec.Overlay == nil {
				t.Fatal("retire candidate omitted empty overlay marker")
			}
			events = append(events, "install:"+spec.Overlay.State)
			return nil
		},
		overlayReadback: func(xnft.HostInputFenceOverlay) error {
			events = append(events, "verify")
			return nil
		},
	}
	old := &xnft.HostInputFenceOverlay{
		MasterSet:       []string{"st0"},
		Generation:      4,
		PermitEpoch:     8,
		CloseRequestSeq: 12,
		CloseRequestKey: "UNSAFE/4",
		WatchGeneration: 4,
		State:           "CLOSING",
	}
	d := &Daemon{}
	d.setHostInputFenceOverlay(old)
	req := hostInputFenceConntrackRequestForOverlay(*old, []string{"192.0.2.10"})
	d.hostInputFenceConntrackActive.Store(&req)
	if err := d.retireHostInputFenceOverlay(hostInboundTestConfig(), nil); err != nil {
		t.Fatalf("retire overlay: %v", err)
	}
	if d.activeHostInputFenceOverlay() != nil || d.hostInputFenceConntrackActive.Load() != nil {
		t.Fatal("retire returned before clearing the acknowledged overlay state")
	}
	if len(events) < 5 || events[0] != "ct" || events[1] != "ct" ||
		events[2] != "ct" || events[3] != "ct" || events[4] != "install:RETIRING" {
		t.Fatalf("retire ordering = %v, want old-set conntrack ACK before empty install", events)
	}
}
func TestHostInputFenceRetireAbortsAfterPermitRevoke9506(t *testing.T) {
	origInstaller := nftInstaller
	origDelete := hostInputFenceConntrackDeleteFilters
	origCensus := hostInputFenceAllLocalAddrs
	t.Cleanup(func() {
		nftInstaller = origInstaller
		hostInputFenceConntrackDeleteFilters = origDelete
		hostInputFenceAllLocalAddrs = origCensus
	})
	hostInputFenceAllLocalAddrs = func() ([]string, error) { return nil, nil }
	s := newIpsecSupervisor()
	expected := testOpenRecord(8, 12, testKey(ipsecReadySafe, 4), 4)
	s.permit.Store(expected)
	hostInputFenceConntrackDeleteFilters = func(netlink.InetFamily, ...netlink.CustomConntrackFilter) (uint, error) {
		s.permit.Store(testClosingRecord(8, 13, testKey(ipsecReadyUnknown, 4), 4))
		return 0, nil
	}
	installs := 0
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error {
			installs++
			return nil
		},
		overlayReadback: func(xnft.HostInputFenceOverlay) error { return nil },
	}
	old := &xnft.HostInputFenceOverlay{
		MasterSet:       []string{"st0"},
		Generation:      4,
		PermitEpoch:     8,
		CloseRequestSeq: 12,
		CloseRequestKey: "SAFE/4",
		WatchGeneration: 4,
		State:           "OPEN",
	}
	d := &Daemon{ipsecS4: s}
	d.setHostInputFenceOverlay(old)
	req := hostInputFenceConntrackRequestForOverlay(*old, []string{"192.0.2.10"})
	d.hostInputFenceConntrackActive.Store(&req)
	if err := d.retireHostInputFenceOverlay(hostInboundTestConfig(), expected); err == nil {
		t.Fatal("retire succeeded after permit changed to CLOSING")
	}
	if installs != 0 {
		t.Fatalf("retire installed empty overlay after revoke: %d installs", installs)
	}
	if d.activeHostInputFenceOverlay() == nil {
		t.Fatal("retire dropped conservative overlay after authority mismatch")
	}
}
