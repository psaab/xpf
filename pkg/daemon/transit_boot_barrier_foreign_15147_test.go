package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #15147: on a foreign, never-committed host the pre-networkd boot unit
// (xpf-transit-closed.service) installs the transit barrier unconditionally,
// but the #10733 daemon gate never actuates there — so nothing ever removed
// the barrier and all routed and bridged forwarding stayed dropped for the
// whole uptime. The daemon must release a boot-installed barrier during
// bring-up when it does not own the transit gate, and must keep it when
// durable ownership exists (appliance marker, committed store, the #14620
// ownership record, or FIRST-rollback teardown debt).

func seedForeignStore15147(t *testing.T) (*configstore.Store, string) {
	t.Helper()
	conf := filepath.Join(t.TempDir(), "xpf.conf")
	store, err := configstore.New(conf)
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	if store.EverCommitted() {
		t.Fatal("fixture is not a never-committed foreign host")
	}
	return store, conf
}

func seedCommittedStore15147(t *testing.T) *configstore.Store {
	t.Helper()
	conf := filepath.Join(t.TempDir(), "xpf.conf")
	store, err := configstore.New(conf)
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.SetFromInput("system host-name committed-15147"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if !store.EverCommitted() {
		t.Fatal("committed fixture did not record a commit")
	}
	// Reopen so ownership rests on durable on-disk state alone, the way a
	// fresh daemon lifetime (and the boot barrier's probe) sees it.
	reopened, err := configstore.New(conf)
	if err != nil {
		t.Fatalf("configstore.New (reopen): %v", err)
	}
	if err := reopened.Load(); err != nil {
		t.Fatalf("reopen Load: %v", err)
	}
	if !reopened.EverCommitted() {
		t.Fatal("reopened committed fixture lost its committed marker")
	}
	return reopened
}

// The decisive #15147 cell: a boot-installed barrier (pre-seeded install
// call, modelling the unit's ExecStart) on an unmarked, never-committed
// host must be removed at bring-up while the host's forwarding sysctls stay
// untouched. Reverting removeUnownedBootTransitBarrier15147 (or gating it
// on shouldManageTransitGate alone without the durable probe) leaves the
// barrier standing and this test red.
func TestForeignHostRemovesBootInstalledBarrier15147(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "1")
	withApplianceMarker10733(t, false)
	withTransitOwnershipRecord14620(t)
	fence := withBarrierRecorder(t)
	// Pre-seed the boot-installed barrier, as xpf-transit-closed.service did.
	fence.barrierCalls = append(fence.barrierCalls, "install")

	store, _ := seedForeignStore15147(t)
	d := &Daemon{store: store}
	d.bootstrapMode.Store(true)
	d.removeUnownedBootTransitBarrier15147()
	d.applyBootTransitPolicy()

	if got := lastBarrierCall(fence); got != "remove" {
		t.Fatalf("boot-installed barrier on a foreign never-committed host: last barrier call = %q, want remove (calls: %v)", got, fence.barrierCalls)
	}
	assertTransitForwarding(t, v4, v6, "1", "after foreign-host bring-up removed the boot barrier")
}

// Control: with the appliance marker present the host is owned — the boot
// barrier is xpf's fence to keep/reinstall, never foreign state to release.
func TestApplianceHostKeepsBootBarrier15147(t *testing.T) {
	withTempTransitForwardSysctls(t, "1")
	withApplianceMarker10733(t, true)
	withTransitOwnershipRecord14620(t)
	fence := withBarrierRecorder(t)
	fence.barrierCalls = append(fence.barrierCalls, "install")

	store, _ := seedForeignStore15147(t)
	d := &Daemon{store: store}
	d.removeUnownedBootTransitBarrier15147()

	if got := lastBarrierCall(fence); got == "remove" {
		t.Fatalf("appliance host barrier was removed as unowned (calls: %v)", fence.barrierCalls)
	}
}

// Control: a committed store (no marker) owns the gate; the barrier stays.
func TestCommittedHostKeepsBootBarrier15147(t *testing.T) {
	withTempTransitForwardSysctls(t, "1")
	withApplianceMarker10733(t, false)
	withTransitOwnershipRecord14620(t)
	fence := withBarrierRecorder(t)
	fence.barrierCalls = append(fence.barrierCalls, "install")

	d := &Daemon{store: seedCommittedStore15147(t)}
	d.removeUnownedBootTransitBarrier15147()

	if got := lastBarrierCall(fence); got == "remove" {
		t.Fatalf("committed host barrier was removed as unowned (calls: %v)", fence.barrierCalls)
	}
}

// Control: the durable #14620 ownership record alone (daemon never latched
// in this lifetime, in-memory store reads never-committed) proves prior
// ownership — the barrier must stay so postrm's restore contract and the
// fail-closed gate are not undermined by a premature release.
func TestOwnershipRecordKeepsBootBarrier15147(t *testing.T) {
	withTempTransitForwardSysctls(t, "1")
	withApplianceMarker10733(t, false)
	rec := withTransitOwnershipRecord14620(t)
	if err := os.WriteFile(rec, []byte("ipv4=1\nipv6=1\n"), 0o644); err != nil {
		t.Fatalf("seed ownership record: %v", err)
	}
	fence := withBarrierRecorder(t)
	fence.barrierCalls = append(fence.barrierCalls, "install")

	store, _ := seedForeignStore15147(t)
	if configstore.TransitGateOwnedOnDisk(store.ConfigPath()) != true {
		t.Fatal("probe did not see the seeded ownership record")
	}
	d := &Daemon{store: store}
	d.removeUnownedBootTransitBarrier15147()

	if got := lastBarrierCall(fence); got == "remove" {
		t.Fatalf("ownership-recorded host barrier was removed as unowned (calls: %v)", fence.barrierCalls)
	}
}

// The read-only probe itself: it must not create the .configdb directory on
// a host where the daemon has never run (the boot command's no-mutation
// contract — New/NewDB would create+chmod it). A foreign host whose config
// root was never created reads unowned with zero filesystem side effects.
func TestTransitGateProbeIsReadOnly15147(t *testing.T) {
	withTransitOwnershipRecord14620(t)
	dir := t.TempDir()
	conf := filepath.Join(dir, "xpf.conf")
	if configstore.TransitGateOwnedOnDisk(conf) {
		t.Fatal("never-created config root read as transit-gate owned")
	}
	if _, err := os.Stat(filepath.Join(dir, ".configdb")); !os.IsNotExist(err) {
		t.Fatalf("read-only probe created .configdb (stat err=%v)", err)
	}
}
