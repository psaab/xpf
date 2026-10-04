package userspace

import (
	"errors"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func interfaceLinkRefreshConfig11530() *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/0": {},
		}},
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"trust": {Name: "trust", Interfaces: []string{"ge-0/0/0"}},
		}},
	}
}

func interfaceLinkRefreshManager11530(t *testing.T, cfg *config.Config, linuxName string, initialIndex, initialMTU int) (*Manager, func() int, func(int, int)) {
	t.Helper()
	oldBuild := buildLinkSnapshot
	currentIndex, currentMTU := initialIndex, initialMTU
	buildLinkSnapshot = func(name string) (int, int, string, []InterfaceAddressSnapshot) {
		if name != linuxName || currentIndex == 0 {
			return 0, 0, "", nil
		}
		return currentIndex, currentMTU, "02:00:00:00:11:30", nil
	}
	t.Cleanup(func() { buildLinkSnapshot = oldBuild })

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.generation = 7
	m.lastSnapshot = mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 7, 0)
	m.publishedSnapshot = 7
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	if hash, ok := snapshotContentHash(m.lastSnapshot); ok {
		m.lastSnapshotHash = hash
	} else {
		t.Fatal("fixture snapshot did not hash")
	}
	requests := 0
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" && req.Snapshot != nil {
			requests++
			if status != nil {
				*status = ProcessStatus{
					ConfigSnapshotProtocolVersion: ProtocolVersion,
					LastSnapshotGeneration:        req.Snapshot.Generation,
					LastFIBGeneration:             req.Snapshot.FIBGeneration,
				}
			}
		}
		return nil
	}
	return m, func() int { return requests }, func(index, mtu int) {
		currentIndex, currentMTU = index, mtu
	}
}

func TestInterfaceLinkRefreshRebuildsDroppedRowsFromDesiredConfig11530(t *testing.T) {
	cfg := interfaceLinkRefreshConfig11530()
	index, mtu := 17, 1500
	m, requestCount, setLink := interfaceLinkRefreshManager11530(t, cfg, "ge-0-0-0", index, mtu)

	if !m.InterfaceLinkNameRelevant("ge-0-0-0") {
		t.Fatal("configured Linux interface name is not recognized as a snapshot row")
	}
	if m.InterfaceLinkNameRelevant("unrelated11530") {
		t.Fatal("unconfigured Linux interface name was marked relevant")
	}
	published, err := m.RefreshInterfaceRowsForLink(cfg, "unrelated11530")
	if err != nil || published || requestCount() != 0 {
		t.Fatalf("unrelated link refresh = (%t, %v), requests=%d; want no publish or request",
			published, err, requestCount())
	}

	index, mtu = 29, 9000
	setLink(index, mtu)
	published, err = m.RefreshInterfaceRowsForLink(cfg, "ge-0-0-0")
	if err != nil || !published {
		t.Fatalf("refresh after link recreation = (%t, %v), want a publish", published, err)
	}
	if got := m.lastSnapshot.Interfaces; len(got) != 1 || got[0].Ifindex != index || got[0].MTU != mtu {
		t.Fatalf("recreated interface row = %+v, want ifindex=%d MTU=%d", got, index, mtu)
	}
	if m.lastSnapshot.Generation <= 7 {
		t.Fatalf("recreated row snapshot generation = %d, want > 7", m.lastSnapshot.Generation)
	}
	if got := m.lastSnapshot.Interfaces[0]; got.Zone != "trust" || got.EgressZone != "trust" {
		t.Fatalf("recreated interface zones = %q/%q, want trust/trust", got.Zone, got.EgressZone)
	}
	if got := requestCount(); got != 1 {
		t.Fatalf("apply_snapshot requests after changed row = %d, want 1", got)
	}

	// Repeated RTNL notifications after the state has converged do not republish.
	for i := range 8 {
		published, err = m.RefreshInterfaceRowsForLink(cfg, "ge-0-0-0")
		if err != nil || published {
			t.Fatalf("unchanged refresh %d = (%t, %v), want no publish", i, published, err)
		}
	}
	if got := requestCount(); got != 1 {
		t.Fatalf("repeated unchanged link notifications sent %d snapshots, want 1", got)
	}

	// DELLINK drops the row; the manager retains Config as the desired source.
	firstGeneration := m.lastSnapshot.Generation
	index = 0
	setLink(index, mtu)
	published, err = m.RefreshInterfaceRowsForLink(cfg, "ge-0-0-0")
	if err != nil || !published {
		t.Fatalf("refresh after delete = (%t, %v), want a publish", published, err)
	}
	if m.lastSnapshot.Generation <= firstGeneration {
		t.Fatalf("delete snapshot generation = %d, want > %d", m.lastSnapshot.Generation, firstGeneration)
	}
	if !m.InterfaceLinkNameRelevant("ge-0-0-0") {
		t.Fatal("deleted row lost its desired-config link relevance")
	}
	if got := m.InterfaceLinkRefreshTriggerName(); got != "ge-0-0-0" {
		t.Fatalf("resync trigger after row deletion = %q, want configured interface ge-0-0-0", got)
	}
	if len(m.lastSnapshot.Interfaces) != 0 {
		t.Fatalf("deleted interface remained in retained snapshot: %+v", m.lastSnapshot.Interfaces)
	}

	// Recreate with the same configured name. A clone of lastSnapshot would be
	// empty forever; rebuilding rows from Config restores the fresh kernel row.
	index, mtu = 29, 1600
	setLink(index, mtu)
	published, err = m.RefreshInterfaceRowsForLink(cfg, "ge-0-0-0")
	if err != nil || !published {
		t.Fatalf("refresh after recreate = (%t, %v), want a publish", published, err)
	}
	if got := m.lastSnapshot.Interfaces; len(got) != 1 || got[0].Ifindex != index || got[0].MTU != mtu {
		t.Fatalf("restored interface row = %+v, want ifindex=%d MTU=%d", got, index, mtu)
	}
	if m.lastSnapshot.Interfaces[0].Zone != "trust" || m.lastSnapshot.Interfaces[0].EgressZone != "trust" {
		t.Fatalf("restored interface zone stamp = %+v, want trust/trust", m.lastSnapshot.Interfaces[0])
	}
	if got := requestCount(); got != 3 {
		t.Fatalf("apply_snapshot requests after delete/recreate = %d, want 3", got)
	}

	// A delayed callback carrying a superseded config cannot roll the manager
	// back even if that older config names the same Linux device.
	stale := &config.Config{Interfaces: cfg.Interfaces}
	before := *m.lastSnapshot
	published, err = m.RefreshInterfaceRowsForLink(stale, "ge-0-0-0")
	if err != nil || published {
		t.Fatalf("stale config refresh = (%t, %v), want fenced no-op", published, err)
	}
	if !reflect.DeepEqual(before.Interfaces, m.lastSnapshot.Interfaces) || requestCount() != 3 {
		t.Fatal("stale config refresh changed retained rows or published a snapshot")
	}
}

func TestInterfaceLinkRefreshTracksBindOnlyTunnelNetdev11530(t *testing.T) {
	cfg, unitRef, linuxName := shapeBConfig7949(t, "st0.0", "st0", 0)
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{}
	delete(cfg.Security.Zones, "trust")

	index, mtu := 17, 1400
	m, requestCount, setLink := interfaceLinkRefreshManager11530(t, cfg, linuxName, index, mtu)
	row, ok := rowByName7949(m.lastSnapshot.Interfaces, unitRef)
	if !ok || row.LinuxName != linuxName || row.Ifindex != index || row.Zone != "vpn" ||
		row.EgressZone != "vpn" {
		t.Fatalf("tunnel-only initial row = %+v, present=%t; want netdev=%s ifindex=%d vpn/vpn",
			row, ok, linuxName, index)
	}
	if !m.InterfaceLinkNameRelevant(linuxName) {
		t.Fatalf("zoned bind-only tunnel netdev %q was not marked row-relevant", linuxName)
	}
	if m.InterfaceLinkNameRelevant(linuxName + "0") {
		t.Fatalf("unconfigured same-prefix tunnel device %q was marked row-relevant", linuxName+"0")
	}
	if got := m.InterfaceLinkRefreshTriggerName(); got != linuxName {
		t.Fatalf("tunnel-only resync trigger = %q, want %q", got, linuxName)
	}

	index = 0
	setLink(index, mtu)
	published, err := m.RefreshInterfaceRowsForLink(cfg, linuxName)
	if err != nil || !published || len(m.lastSnapshot.Interfaces) != 0 {
		t.Fatalf("tunnel DELLINK refresh = (%t, %v), rows=%+v; want published empty snapshot",
			published, err, m.lastSnapshot.Interfaces)
	}
	if !m.InterfaceLinkNameRelevant(linuxName) || m.InterfaceLinkRefreshTriggerName() != linuxName {
		t.Fatal("tunnel row deletion lost relevance or its resubscription trigger")
	}

	// Reuse the same interface name and ifindex, but refresh the live MTU.
	index, mtu = 17, 1600
	setLink(index, mtu)
	published, err = m.RefreshInterfaceRowsForLink(cfg, linuxName)
	if err != nil || !published {
		t.Fatalf("tunnel NEWLINK refresh = (%t, %v), want publish", published, err)
	}
	row, ok = rowByName7949(m.lastSnapshot.Interfaces, unitRef)
	if !ok || row.LinuxName != linuxName || row.Ifindex != index || row.MTU != mtu ||
		row.Zone != "vpn" || row.EgressZone != "vpn" {
		t.Fatalf("recreated tunnel row = %+v, present=%t; want netdev=%s ifindex=%d MTU=%d vpn/vpn",
			row, ok, linuxName, index, mtu)
	}
	if requestCount() != 2 {
		t.Fatalf("apply_snapshot requests after tunnel delete/recreate = %d, want 2", requestCount())
	}

	stale := *cfg
	before := append([]InterfaceSnapshot(nil), m.lastSnapshot.Interfaces...)
	published, err = m.RefreshInterfaceRowsForLink(&stale, linuxName)
	if err != nil || published || !reflect.DeepEqual(before, m.lastSnapshot.Interfaces) || requestCount() != 2 {
		t.Fatalf("stale tunnel refresh = (%t, %v), retained rows changed or snapshot published", published, err)
	}
}

func TestInterfaceLinkRefreshPreservesMarkersUntilRetrySucceeds11530(t *testing.T) {
	cfg := interfaceLinkRefreshConfig11530()
	m, requestCount, setLink := interfaceLinkRefreshManager11530(t, cfg, "ge-0-0-0", 17, 1500)
	m.appliedSnapshot = appliedSnapshot{Config: cfg, Generation: m.lastSnapshot.Generation}

	oldSnapshot := m.lastSnapshot
	oldGeneration := m.generation
	oldPublished := m.publishedSnapshot
	oldPlanKey := m.publishedPlanKey
	oldHash := m.lastSnapshotHash
	oldApplied := m.appliedSnapshot
	acceptApply := m.controlRequestHook
	reject := errors.New("transient snapshot rejection")
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" {
			return reject
		}
		return acceptApply(req, status)
	}

	setLink(17, 9000)
	published, err := m.RefreshInterfaceRowsForLink(cfg, "ge-0-0-0")
	if published || !errors.Is(err, reject) {
		t.Fatalf("rejected link publish = (%t, %v), want rejected error without publication", published, err)
	}
	if m.lastSnapshot != oldSnapshot || m.generation != oldGeneration ||
		m.publishedSnapshot != oldPublished || m.publishedPlanKey != oldPlanKey ||
		m.lastSnapshotHash != oldHash || m.appliedSnapshot != oldApplied {
		t.Fatal("rejected link publish advanced retained/published markers")
	}

	// The same desired link state remains owed; a successful retry must publish
	// it and advance the helper-confirmed markers together.
	m.controlRequestHook = acceptApply
	published, err = m.RefreshInterfaceRowsForLink(cfg, "ge-0-0-0")
	if err != nil || !published {
		t.Fatalf("link refresh retry = (%t, %v), want successful publication", published, err)
	}
	if got := m.lastSnapshot.Interfaces; len(got) != 1 || got[0].Ifindex != 17 || got[0].MTU != 9000 {
		t.Fatalf("retried interface row = %+v, want ifindex 17 MTU 9000", got)
	}
	if m.publishedSnapshot != m.lastSnapshot.Generation ||
		m.appliedSnapshot.Config != cfg || m.appliedSnapshot.Generation != m.lastSnapshot.Generation {
		t.Fatalf("retry did not converge published markers: published=%d retained=%d applied=%+v",
			m.publishedSnapshot, m.lastSnapshot.Generation, m.appliedSnapshot)
	}
	if requestCount() != 1 {
		t.Fatalf("successful apply requests after rejected attempt = %d, want 1", requestCount())
	}
}

func TestInterfaceLinkRefreshUsesRealKernelLinkChurn11530(t *testing.T) {
	runtime.LockOSThread()
	original, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Skipf("cannot read current network namespace: %v", err)
	}
	private, err := netns.New()
	if err != nil {
		original.Close()
		runtime.UnlockOSThread()
		t.Skipf("cannot create private network namespace: %v", err)
	}
	t.Cleanup(func() {
		_ = netns.Set(original)
		_ = private.Close()
		_ = original.Close()
		runtime.UnlockOSThread()
	})

	const name = "x11530"
	create := func(mtu int) netlink.Link {
		t.Helper()
		link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, MTU: mtu}}
		if err := netlink.LinkAdd(link); err != nil {
			t.Skipf("cannot create dummy link in private netns: %v", err)
		}
		got, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatalf("lookup created link: %v", err)
		}
		if err := netlink.LinkSetUp(got); err != nil {
			t.Fatalf("bring created link up: %v", err)
		}
		return got
	}
	link := create(1400)

	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{name: {}}},
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"trust": {Name: "trust", Interfaces: []string{name}},
		}},
	}
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.lastSnapshot = mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 10, 0)
	m.generation = 10
	m.publishedSnapshot = 10
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	if len(m.lastSnapshot.Interfaces) != 1 {
		t.Fatalf("initial snapshot rows = %+v, want one row", m.lastSnapshot.Interfaces)
	}
	var applied *ConfigSnapshot
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" && req.Snapshot != nil {
			copy := *req.Snapshot
			copy.Interfaces = append([]InterfaceSnapshot(nil), req.Snapshot.Interfaces...)
			applied = &copy
			if status != nil {
				*status = ProcessStatus{
					ConfigSnapshotProtocolVersion: ProtocolVersion,
					LastSnapshotGeneration:        req.Snapshot.Generation,
					LastFIBGeneration:             req.Snapshot.FIBGeneration,
				}
			}
		}
		return nil
	}

	if err := netlink.LinkDel(link); err != nil {
		t.Fatalf("delete link: %v", err)
	}
	published, err := m.RefreshInterfaceRowsForLink(cfg, name)
	if err != nil || !published {
		t.Fatalf("publish deletion row change = (%t, %v), want publish", published, err)
	}
	deletedGeneration := m.lastSnapshot.Generation
	if applied == nil || len(applied.Interfaces) != 0 || applied.Generation <= 10 || deletedGeneration <= 10 {
		t.Fatalf("deleted link snapshot = %+v, want no interface rows at a fresh generation", applied)
	}
	beforeRecreate := deletedGeneration
	link = create(1600)
	published, err = m.RefreshInterfaceRowsForLink(cfg, name)
	if err != nil || !published {
		t.Fatalf("publish recreated link = (%t, %v), want publish", published, err)
	}
	if applied == nil || len(applied.Interfaces) != 1 {
		t.Fatalf("recreated link snapshot rows = %+v, want one row", applied)
	}
	row := applied.Interfaces[0]
	attrs := link.Attrs()
	if row.Ifindex != attrs.Index || row.MTU != attrs.MTU {
		t.Fatalf("recreated row = %+v, current kernel link index/MTU = %d/%d", row, attrs.Index, attrs.MTU)
	}
	if row.Zone != "trust" || row.EgressZone != "trust" {
		t.Fatalf("recreated row zones = %q/%q, want trust/trust", row.Zone, row.EgressZone)
	}
	if len(m.lastSnapshot.Interfaces) != 1 || m.lastSnapshot.Interfaces[0].Ifindex != attrs.Index {
		t.Fatalf("retained desired row was not restored from config: %+v", m.lastSnapshot.Interfaces)
	}
	if applied.Generation <= beforeRecreate || m.lastSnapshot.Generation != applied.Generation {
		t.Fatalf("recreated snapshot generation = %d (retained %d), want > delete generation %d", applied.Generation, m.lastSnapshot.Generation, beforeRecreate)
	}
}
