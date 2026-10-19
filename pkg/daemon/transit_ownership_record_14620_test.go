package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #14620: when the transit gate first latches ownership, xpfd must durably
// record that ownership plus the host's PRE-xpf sysctl values, so postrm
// can restore exactly those values on remove/purge — and only there. On a
// never-owned host no record may ever appear (postrm's gate).

func withTransitOwnershipRecord14620(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "transit-gate-owned")
	old := transitOwnershipRecordFile
	oldProbe := configstore.TransitOwnershipRecordPath
	transitOwnershipRecordFile = path
	configstore.TransitOwnershipRecordPath = path
	t.Cleanup(func() {
		transitOwnershipRecordFile = old
		configstore.TransitOwnershipRecordPath = oldProbe
	})
	return path
}

func readRecord14620(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read ownership record: %v", err)
	}
	return string(b)
}

func TestTransitOwnershipRecordedOnLatch14620(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "0")
	_ = v4
	_ = v6
	withApplianceMarker10733(t, false)
	rec := withTransitOwnershipRecord14620(t)
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.SetFromInput("system host-name owned-host"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	d := &Daemon{store: store}
	if !d.shouldManageTransitGate() {
		t.Fatal("committed host must latch transit ownership")
	}
	got := readRecord14620(t, rec)
	if !strings.Contains(got, "ipv4=0\n") || !strings.Contains(got, "ipv6=0\n") {
		t.Fatalf("ownership record = %q, want recorded priors ipv4=0/ipv6=0 (pre-xpf values)", got)
	}

	// A second latch (e.g. after the gate closed the sysctls, or a later
	// daemon lifetime) must NOT overwrite the recorded priors.
	for _, p := range []string{v4, v6} {
		if err := os.WriteFile(p, []byte("1\n"), 0o644); err != nil {
			t.Fatalf("rewrite sysctl: %v", err)
		}
	}
	d2 := &Daemon{store: store}
	if !d2.shouldManageTransitGate() {
		t.Fatal("second daemon must latch transit ownership")
	}
	if got2 := readRecord14620(t, rec); got2 != got {
		t.Fatalf("ownership record overwritten: first %q, second %q", got, got2)
	}
}

func TestTransitOwnershipNotRecordedOnNeverOwnedHost14620(t *testing.T) {
	withTempTransitForwardSysctls(t, "1")
	withApplianceMarker10733(t, false)
	rec := withTransitOwnershipRecord14620(t)
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if store.EverCommitted() {
		t.Fatal("fixture is not a never-committed host")
	}
	d := &Daemon{store: store}
	if d.shouldManageTransitGate() {
		t.Fatal("never-committed foreign host must not latch transit ownership")
	}
	if _, err := os.Stat(rec); !os.IsNotExist(err) {
		t.Fatalf("ownership record exists on never-owned host (err=%v); postrm would wrongly restore sysctls", err)
	}
}
