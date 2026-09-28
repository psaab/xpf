package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	xnft "github.com/psaab/xpf/pkg/nftables"
)

// TestTCPloosePostureReassertAfterModuleLoad10752 is the #10752 F2
// fault-injected lifecycle proof: on a modular kernel the conntrack proc entry
// is absent at early boot, appears after the first nft install loads the
// module, and every successful host-inbound apply re-establishes verified
// loose=0 with counted failures.
func TestTCPloosePostureReassertAfterModuleLoad10752(t *testing.T) {
	origPath, origWrite, origRead := looseTCPSysctlPath, hostPostureWriteFile, hostPostureReadFile
	defer func() { looseTCPSysctlPath, hostPostureWriteFile, hostPostureReadFile = origPath, origWrite, origRead }()

	dir := t.TempDir()
	looseFile := filepath.Join(dir, "nf_conntrack_tcp_loose")
	looseTCPSysctlPath = looseFile

	d := &Daemon{}
	hostPostureWriteFile = func(string, []byte, os.FileMode) error {
		return errors.New("no such file (conntrack module unloaded)")
	}
	hostPostureReadFile = func(string) ([]byte, error) {
		return nil, errors.New("no such file (conntrack module unloaded)")
	}
	d.reassertTCPloosePosture()
	if got := d.TCPloosePostureFailures(); got != 1 {
		t.Fatalf("failures after absent-proc reassert = %d, want 1", got)
	}
	if d.TCPlooseDisabled() {
		t.Fatal("disabled latch must be false when the proc entry is absent")
	}

	if err := os.WriteFile(looseFile, []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	hostPostureWriteFile = os.WriteFile
	hostPostureReadFile = os.ReadFile
	d.reassertTCPloosePosture()
	raw, err := os.ReadFile(looseFile)
	if err != nil || strings.TrimSpace(string(raw)) != "0" {
		t.Fatalf("loose value after reassert = %q err=%v, want 0", strings.TrimSpace(string(raw)), err)
	}
	if !d.TCPlooseDisabled() {
		t.Fatal("disabled latch must be true after verified zero")
	}
	if got := d.TCPloosePostureFailures(); got != 1 {
		t.Fatalf("failures after successful reassert = %d, want still 1", got)
	}

	if err := os.WriteFile(looseFile, []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	d.reassertTCPloosePosture()
	if !d.TCPlooseDisabled() {
		t.Fatal("manual revert must converge back to disabled on next reassert")
	}

	hostPostureWriteFile = func(string, []byte, os.FileMode) error { return nil }
	hostPostureReadFile = func(string) ([]byte, error) { return []byte("1"), nil }
	d.reassertTCPloosePosture()
	if got := d.TCPloosePostureFailures(); got != 2 {
		t.Fatalf("failures after verify mismatch = %d, want 2", got)
	}
	if d.TCPlooseDisabled() {
		t.Fatal("disabled latch must clear on verify mismatch")
	}
}

// TestHostInboundApplyReassertsTCPloose10752 proves the setting is zero after
// a successful host-inbound installation (F2 boot-artifact evidence): the
// apply path re-drives loose=0 once nft has guaranteed conntrack is loaded.
func TestHostInboundApplyReassertsTCPloose10752(t *testing.T) {
	origPath, origWrite, origRead := looseTCPSysctlPath, hostPostureWriteFile, hostPostureReadFile
	defer func() { looseTCPSysctlPath, hostPostureWriteFile, hostPostureReadFile = origPath, origWrite, origRead }()
	looseTCPSysctlPath = filepath.Join(t.TempDir(), "nf_conntrack_tcp_loose")
	hostPostureWriteFile = os.WriteFile
	hostPostureReadFile = os.ReadFile
	if err := os.WriteFile(looseTCPSysctlPath, []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}

	origInstaller := nftInstaller
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { return nil },
	}
	defer func() { nftInstaller = origInstaller }()

	cfg := hostInboundFlushTestConfig("snmp")
	d := &Daemon{}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("applyHostInboundFilter: %v", err)
	}
	raw, err := os.ReadFile(looseTCPSysctlPath)
	if err != nil || strings.TrimSpace(string(raw)) != "0" {
		t.Fatalf("loose value after successful apply = %q err=%v, want 0", strings.TrimSpace(string(raw)), err)
	}
	if !d.TCPlooseDisabled() {
		t.Fatal("disabled latch must be true after successful apply")
	}
}
