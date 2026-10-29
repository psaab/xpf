package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/vishvananda/netlink"

	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #16671: on a fail-closed boot of a COMMITTED firewall, fxp0 lives in
// vrf-mgmt so the main-table default route is the WAN. Route detection
// must never (a) overwrite the persisted lifeline record, (b) admit the
// WAN into the bootstrap input guard via a poisoned record, or (c)
// withhold the WAN addresses from the live-address fences. The
// never-committed foreign-host cell (no record, default-route NIC is the
// only recovery hint) must stay green.
//
// FAIL-ON-REVERT: dropping the EverCommitted gate in
// setupBootstrapLifeline reds the committed cells (record overwritten);
// restoring `protected[lifeline]=true` from route detection in
// installFailClosedBootHostFences reds the fence cell (WAN fenced=[]).

func committedStore16671(t *testing.T, dir string) *configstore.Store {
	t.Helper()
	s := newConfigStore(t, filepath.Join(dir, "xpf.conf"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.LoadOverride("system { host-name committed-16671; }"); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	s.ExitConfigure()
	if !s.EverCommitted() {
		t.Fatal("premise: store must be ever-committed")
	}
	return s
}

// TestBootstrapCommittedDoesNotOverwriteLifeline16671 drives the real
// setupBootstrapLifeline on a committed store whose default route is on
// a WAN-like NIC (eno3, enumeration index 1). The pre-existing record
// must survive byte-for-byte, nothing may be renamed, and no .network
// may be written.
func TestBootstrapCommittedDoesNotOverwriteLifeline16671(t *testing.T) {
	dir := t.TempDir()
	netDir := filepath.Join(dir, "network")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	oldLinkDir, oldDetect := linkDir, detectLifelineInterfaceFn
	oldEnum, oldRename, oldReload := enumeratePCINICsFn, renameInterfaceFn, networkctlReloadFn
	oldNetworkd, oldRecord := networkdActiveFn, lifelineRecordFileForTest
	oldRecordName := lifelineRecordNameFn
	t.Cleanup(func() {
		linkDir, detectLifelineInterfaceFn = oldLinkDir, oldDetect
		enumeratePCINICsFn, renameInterfaceFn, networkctlReloadFn = oldEnum, oldRename, oldReload
		networkdActiveFn, lifelineRecordFileForTest = oldNetworkd, oldRecord
		lifelineRecordNameFn = oldRecordName
	})
	linkDir = netDir
	recordPath := filepath.Join(dir, "lifeline-interface")
	lifelineRecordFileForTest = recordPath
	// Verified record: eno2 / pci .1 is the real management NIC.
	if err := writeLifelineRecordAt(recordPath, lifelineRecord{PCIAddr: "0000:67:00.1", MAC: "02:00:00:00:00:01"}); err != nil {
		t.Fatalf("seed record: %v", err)
	}
	before, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	networkdActiveFn = func() error { return nil }
	// Default route on the WAN (eno3), NOT on management.
	detectLifelineInterfaceFn = func() (string, bool, error) { return "eno3", true, nil }
	enumeratePCINICsFn = func() ([]pciNIC, error) {
		return []pciNIC{
			{sortKey: 0, busAddr: "0000:67:00.1", name: "eno2"},
			{sortKey: 1, busAddr: "0000:67:00.2", name: "eno3"},
		}, nil
	}
	renamed, reloaded := false, false
	renameInterfaceFn = func(_, _ string) error { renamed = true; return nil }
	networkctlReloadFn = func() error { reloaded = true; return nil }
	// Guard resolver reads the record through this seam in production
	// wiring; keep it pointed at the seeded record's name.
	lifelineRecordNameFn = func() (string, bool) { return "eno2", true }

	daemon := &Daemon{store: committedStore16671(t, dir)}
	daemon.setupBootstrapLifeline()
	protected := daemon.resolveProtectedInterfaces()
	if !protected["eno2"] || protected["eno3"] {
		t.Errorf("sane committed record must protect eno2 and leave WAN eno3 unprotected: %v", protected)
	}

	after, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("record vanished on committed boot: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("committed boot overwrote the verified lifeline record:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if renamed {
		t.Error("committed boot renamed an interface from route detection; the WAN must never be renamed to fxp0")
	}
	if reloaded {
		t.Error("committed boot reloaded networkd from route detection")
	}
	if _, err := os.Stat(filepath.Join(netDir, linkPrefix+"fxp0.network")); err == nil {
		t.Error("committed boot wrote a bootstrap fxp0 .network from route detection")
	}

	// Guard: with the verified record intact, the WAN must stay excluded.
	got := resolveEarlyInputGuardLifelines(nil)
	set := map[string]bool{}
	for _, n := range got {
		set[n] = true
	}
	if set["eno3"] {
		t.Errorf("guard lifelines %v admit the WAN eno3 on a committed box", got)
	}
	if !set["eno2"] {
		t.Errorf("guard lifelines %v omit the verified record NIC eno2", got)
	}
}

// TestBootstrapNeverCommittedStillRecordsRouteLifeline16671 is the
// tightness control: a never-committed box with no record still learns
// its lifeline from the default route (the accepted foreign-host /
// day-0 recovery posture). Without it, a fix that refuses every
// committed-or-not record write would pass the witness cells while
// disabling bootstrap recovery entirely.
func TestBootstrapNeverCommittedStillRecordsRouteLifeline16671(t *testing.T) {
	st := staticLifelineSeams(t)
	lifelineLinkByName = func(string) (netlink.Link, error) { return okLink(), nil }
	lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
		return []netlink.Addr{staticAddr("192.0.2.10/24")}, nil
	}
	lifelineRouteList = func(_ netlink.Link, family int) ([]netlink.Route, error) { return nil, nil }

	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	if d.store.EverCommitted() {
		t.Fatal("premise: store must be never-committed")
	}
	d.setupBootstrapLifeline()
	if _, err := os.Stat(filepath.Join(st.linkDir, linkPrefix+"fxp0.network")); err != nil {
		t.Fatalf("never-committed lifeline must still write the bootstrap .network: %v", err)
	}
}

// TestCommittedBootClearsWANPoisonedLifelineAndFencesWAN17730 reproduces
// an upgrade from the old #16671 implementation: a committed boot previously
// overwrote the stable management record with the main-table WAN NIC. The
// committed bootstrap path must clear that unverified identity before the
// fail-closed fence resolves its protected set, then fence both WAN families.
func TestCommittedBootClearsWANPoisonedLifelineAndFencesWAN17730(t *testing.T) {
	dir := t.TempDir()
	recordPath := filepath.Join(dir, "lifeline-interface")
	oldRecord, oldRecordName := lifelineRecordFileForTest, lifelineRecordNameFn
	lifelineRecordFileForTest = recordPath
	lifelineRecordNameFn = func() (string, bool) { return "eno3", true }
	t.Cleanup(func() {
		lifelineRecordFileForTest, lifelineRecordNameFn = oldRecord, oldRecordName
	})
	if err := writeLifelineRecordAt(recordPath, lifelineRecord{
		PCIAddr: "0000:67:00.2", MAC: "02:00:00:00:00:02",
	}); err != nil {
		t.Fatalf("seed WAN-poisoned record: %v", err)
	}

	committed := committedStore16671(t, dir)
	oldNetworkd := networkdActiveFn
	networkdActiveFn = func() error { return nil }
	t.Cleanup(func() { networkdActiveFn = oldNetworkd })
	withFailClosedBootDetect(t, func() (string, bool, error) { return "eno3", true, nil })
	setupFake := &fakeNftInstaller{}
	withFailClosedBootNft(t, setupFake)
	d := &Daemon{store: committed}
	protected := d.resolveProtectedInterfaces()
	if protected["eno3"] {
		t.Fatalf("resolveProtectedInterfaces trusted WAN-poisoned record: %v", protected)
	}
	if !protected["fxp0"] {
		t.Fatalf("resolveProtectedInterfaces omitted default management fxp0: %v", protected)
	}
	if _, ok := readLifelineRecordAt(recordPath); ok {
		t.Fatal("resolveProtectedInterfaces did not clear the WAN-poisoned record")
	}
	if err := writeLifelineRecordAt(recordPath, lifelineRecord{
		PCIAddr: "0000:67:00.2", MAC: "02:00:00:00:00:02",
	}); err != nil {
		t.Fatalf("re-seed WAN-poisoned record for setup path: %v", err)
	}

	d.setupBootstrapLifeline()
	if len(setupFake.earlyInputBarrierLifelineSpecs) != 1 {
		t.Fatalf("committed bootstrap must install one lifeline guard, got %v", setupFake.earlyInputBarrierLifelineSpecs)
	}
	for _, name := range setupFake.earlyInputBarrierLifelineSpecs[0] {
		if name == "eno3" {
			t.Fatalf("committed bootstrap guard admits WAN eno3 from a poisoned record: %v",
				setupFake.earlyInputBarrierLifelineSpecs[0])
		}
	}

	if _, ok := readLifelineRecordAt(recordPath); ok {
		t.Fatal("committed boot retained a lifeline record that resolves to the WAN; poisoned record is not verified management")
	}

	fxp0 := failClosedBootTestLink("fxp0", false)
	wan := failClosedBootTestLink("eno3", false)
	lo := failClosedBootTestLink("lo", true)
	withFailClosedBootLinkList(t, func() ([]netlink.Link, error) {
		return []netlink.Link{fxp0, wan, lo}, nil
	})
	addrs := map[string][]netlink.Addr{
		"fxp0": {failClosedBootTestAddr(t, "10.0.0.1/24")},
		"eno3": {failClosedBootTestAddr(t, "192.0.2.10/24"), failClosedBootTestAddr(t, "2001:db8::10/64")},
		"lo":   {failClosedBootTestAddr(t, "127.0.0.1/8")},
	}
	withFailClosedBootAddrList(t, func(link netlink.Link, _ int) ([]netlink.Addr, error) {
		return addrs[link.Attrs().Name], nil
	})
	fake := &fakeNftInstaller{}
	withFailClosedBootNft(t, fake)
	var hostSpecs []xnft.FenceSpec
	fake.coldBootFence = func(s xnft.FenceSpec) error { hostSpecs = append(hostSpecs, s); return nil }
	fake.lo0ColdBootFence = func(xnft.FenceSpec) error { return nil }
	// Re-poison immediately before fence installation so this caller's
	// protected-set resolution must reject the record itself.
	if err := writeLifelineRecordAt(recordPath, lifelineRecord{
		PCIAddr: "0000:67:00.2", MAC: "02:00:00:00:00:02",
	}); err != nil {
		t.Fatalf("re-seed WAN-poisoned record for fence path: %v", err)
	}

	d.installFailClosedBootHostFences(true)
	if _, ok := readLifelineRecordAt(recordPath); ok {
		t.Fatal("fail-closed fence resolver retained the WAN-poisoned record")
	}

	if len(hostSpecs) != 1 {
		t.Fatalf("fail-closed fence must install exactly one host fence, got %d", len(hostSpecs))
	}
	v4 := fenceViewAddrs(hostSpecs[0], false)
	v6 := fenceViewAddrs(hostSpecs[0], true)
	if !sliceContains(v4, "192.0.2.10") {
		t.Errorf("WAN v4 192.0.2.10 must be fenced after clearing the poisoned record; fenced v4: %v", v4)
	}
	if !sliceContains(v6, "2001:db8::10") {
		t.Errorf("WAN v6 2001:db8::10 must be fenced after clearing the poisoned record; fenced v6: %v", v6)
	}
	if sliceContains(v4, "10.0.0.1") {
		t.Errorf("management 10.0.0.1 must NOT be fenced; fenced v4: %v", v4)
	}
}

// TestFailClosedFenceFencesWANWhenRouteIsWAN16671 is the fence witness:
// links fxp0 (mgmt, 10.0.0.1) + ge-0-0-0 (WAN, 192.0.2.10/2001:db8::10),
// default route on ge-0-0-0. Pre-fix the route NIC joined `protected`,
// so fenced=[]; post-fix the WAN addresses must be fenced and the mgmt
// address must not be.
func TestFailClosedFenceFencesWANWhenRouteIsWAN16671(t *testing.T) {
	withFailClosedBootLifelineFile(t)
	withFailClosedBootDetect(t, func() (string, bool, error) { return "ge-0-0-0", true, nil })
	fxp0 := failClosedBootTestLink("fxp0", false)
	wan := failClosedBootTestLink("ge-0-0-0", false)
	lo := failClosedBootTestLink("lo", true)
	withFailClosedBootLinkList(t, func() ([]netlink.Link, error) {
		return []netlink.Link{fxp0, wan, lo}, nil
	})
	addrs := map[string][]netlink.Addr{
		"fxp0":     {failClosedBootTestAddr(t, "10.0.0.1/24")},
		"ge-0-0-0": {failClosedBootTestAddr(t, "192.0.2.10/24"), failClosedBootTestAddr(t, "2001:db8::10/64")},
		"lo":       {failClosedBootTestAddr(t, "127.0.0.1/8")},
	}
	withFailClosedBootAddrList(t, func(link netlink.Link, _ int) ([]netlink.Addr, error) {
		return addrs[link.Attrs().Name], nil
	})
	fake := &fakeNftInstaller{}
	withFailClosedBootNft(t, fake)
	var hostSpecs []xnft.FenceSpec
	fake.coldBootFence = func(s xnft.FenceSpec) error { hostSpecs = append(hostSpecs, s); return nil }
	fake.lo0ColdBootFence = func(xnft.FenceSpec) error { return nil }

	d := &Daemon{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	// Mark committed: the fence must fence the WAN even (especially) on
	// a committed fail-closed boot.
	if err := d.store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := d.store.LoadOverride("system { host-name committed-16671; }"); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := d.store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	d.store.ExitConfigure()

	d.installFailClosedBootHostFences(true)

	if len(hostSpecs) != 1 {
		t.Fatalf("fail-closed fence must install exactly one host fence, got %d (WAN withheld?)", len(hostSpecs))
	}
	v4 := fenceViewAddrs(hostSpecs[0], false)
	v6 := fenceViewAddrs(hostSpecs[0], true)
	if !sliceContains(v4, "192.0.2.10") {
		t.Errorf("WAN v4 192.0.2.10 must be fenced on a committed fail-closed boot; fenced v4: %v", v4)
	}
	if !sliceContains(v6, "2001:db8::10") {
		t.Errorf("WAN v6 2001:db8::10 must be fenced; fenced v6: %v", v6)
	}
	if sliceContains(v4, "10.0.0.1") {
		t.Errorf("management 10.0.0.1 must NOT be fenced; fenced v4: %v", v4)
	}
}
