package daemon

import (
	"path/filepath"
	"testing"
)

func TestProbePinStartupCleanupRequiresHostOwnership10765(t *testing.T) {
	t.Run("uncommitted foreign host preserves probe bands", func(t *testing.T) {
		withApplianceMarker10733(t, false)
		store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
		if store.EverCommitted() {
			t.Fatal("fresh store unexpectedly reports a committed config")
		}

		d := &Daemon{store: store}
		if err := d.clearStaleProbePinsAtStartup(); err != nil {
			t.Fatalf("clearStaleProbePinsAtStartup: %v", err)
		}
		if d.transitGateOwned.Load() {
			t.Fatal("uncommitted foreign host became owned during probe-pin cleanup")
		}
	})

	t.Run("appliance marker establishes ownership", func(t *testing.T) {
		withApplianceMarker10733(t, true)
		d := &Daemon{}
		if !d.shouldManageTransitGate() {
			t.Fatal("appliance marker did not establish host routing ownership")
		}
	})

	t.Run("committed config establishes ownership", func(t *testing.T) {
		withApplianceMarker10733(t, false)
		store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
		if err := store.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		if err := store.SetFromInput("system host-name committed-host"); err != nil {
			t.Fatalf("SetFromInput: %v", err)
		}
		if _, err := store.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		if !store.EverCommitted() {
			t.Fatal("fixture did not commit its configuration")
		}

		d := &Daemon{store: store}
		if !d.shouldManageTransitGate() {
			t.Fatal("committed config did not establish host routing ownership")
		}
	})
}
