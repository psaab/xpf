package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/devicemap"
	"github.com/psaab/xpf/pkg/logging"
)

// strandDeviceMapConfig maps ge-0/0/1 onto the PCI slot the live management
// NIC occupies (0000:05:00.0) and maps NOTHING to a management name, so on
// next boot the mgmt NIC is renamed off and no interface carries fxp0 —
// management becomes unreachable (device-map strand, #1956 invariant 1).
const strandDeviceMapConfig = `
system {
    host-name day0-strand;
}
interfaces {
    fxp0 {
        unit 0 { family inet { dhcp; } }
    }
}
chassis {
    device-map {
        unmapped-interface-policy leave-alone;
        interface ge-0/0/1 {
            pci 0000:05:00.0;
        }
    }
}
`

// safeDeviceMapConfig maps a NIC onto fxp0, so management stays reachable.
const safeDeviceMapConfig = `
system {
    host-name day0-safe;
}
interfaces {
    fxp0 {
        unit 0 { family inet { dhcp; } }
    }
}
chassis {
    device-map {
        unmapped-interface-policy leave-alone;
        interface fxp0 {
            pci 0000:05:00.0;
        }
    }
}
`

const allUnboundDeviceMapConfig = `
system {
    host-name day0-unbound;
}
interfaces {
    fxp0 {
        unit 0 { family inet { dhcp; } }
    }
}
chassis {
    device-map {
        unmapped-interface-policy leave-alone;
        interface fxp0 {
            pci 0000:ff:00.0;
        }
    }
}
`

// strandNICs is the injected present-NIC inventory: the mgmt NIC at PCI
// 05:00.0 (currently named fxp0) plus a data NIC at 09:00.0.
func strandNICs() ([]devicemap.PresentNIC, error) {
	return []devicemap.PresentNIC{
		{Name: "fxp0", PCIAddr: "0000:05:00.0"},
		{Name: "enp9s0", PCIAddr: "0000:09:00.0"},
	}, nil
}

func withInjectedNICs(t *testing.T, fn func() ([]devicemap.PresentNIC, error)) {
	t.Helper()
	old := enumeratePresentNICsFn
	enumeratePresentNICsFn = fn
	t.Cleanup(func() { enumeratePresentNICsFn = old })
}

// offTargetNICs is a BUILD/DEPLOY-host inventory whose PCI addresses do NOT
// match any of the day-0 map's identities (the config-drive is built/deployed
// off the target). None of the mapped entries resolve here.
func offTargetNICs() ([]devicemap.PresentNIC, error) {
	return []devicemap.PresentNIC{
		{Name: "eno1", PCIAddr: "0000:aa:00.0"},
		{Name: "eno2", PCIAddr: "0000:bb:00.0"},
	}, nil
}

// TestCheckDeviceMapStrandsManagement pins #4183 (H-8), on-target: the day-0
// check-config helper reports a management-stranding device-map (when the
// mapped NICs are present) so the subcommand can hard-FAIL. RED-on-revert: the
// helper (and its check-config wiring) does not exist, so a strand config
// passes check-config.
func TestCheckDeviceMapStrandsManagement(t *testing.T) {
	withInjectedNICs(t, strandNICs)

	strand := compileText(t, strandDeviceMapConfig)
	reason, offTarget, err := CheckDeviceMapStrandsManagement(strand)
	if err != nil {
		t.Fatalf("CheckDeviceMapStrandsManagement(strand) err = %v, want nil", err)
	}
	if offTarget {
		t.Fatal("mapped NICs ARE present (on-target) — must not be flagged off-target")
	}
	if reason == "" {
		t.Fatal("expected a strand reason for a device-map that leaves no NIC with a management name")
	}

	safe := compileText(t, safeDeviceMapConfig)
	reason, offTarget, err = CheckDeviceMapStrandsManagement(safe)
	if err != nil {
		t.Fatalf("CheckDeviceMapStrandsManagement(safe) err = %v, want nil", err)
	}
	if offTarget || reason != "" {
		t.Fatalf("safe on-target device-map must not strand: reason=%q offTarget=%v", reason, offTarget)
	}

	// A config with no device-map is always safe (positional mode).
	plain := compileText(t, "system { host-name plain; }")
	if reason, offTarget, err := CheckDeviceMapStrandsManagement(plain); err != nil || reason != "" || offTarget {
		t.Fatalf("plain config: reason=%q offTarget=%v err=%v, want empty/false/nil", reason, offTarget, err)
	}
}

// TestCheckDeviceMapStrandsManagementOffTargetSkips pins the #4191-review
// MAJOR fix: `xpfd check-config` is invoked OFF the target hardware by the
// standard day-0 pipeline (config-drive built on the build host, installed
// from the deploy host). There enumeratePresentNICs SUCCEEDS but returns the
// build host's NICs — NONE at the target's mapped PCI addresses — so a naive
// strand check would false-reject a PERFECTLY VALID bare-metal map. When no
// mapped identity resolves, the check must SKIP (offTarget=true, reason="")
// instead of hard-failing. RED-on-revert: without the guard the same
// (valid) config is reported as a strand (reason != "").
func TestCheckDeviceMapStrandsManagementOffTargetSkips(t *testing.T) {
	withInjectedNICs(t, offTargetNICs)

	// A VALID bare-metal map (maps a NIC to fxp0) whose identities are simply
	// absent on the build host. Must be SKIPPED, never false-rejected.
	safe := compileText(t, safeDeviceMapConfig)
	reason, offTarget, err := CheckDeviceMapStrandsManagement(safe)
	if err != nil {
		t.Fatalf("off-target err = %v, want nil", err)
	}
	if !offTarget {
		t.Fatal("off-target (no mapped NIC present) must be reported as offTarget=true")
	}
	if reason != "" {
		t.Fatalf("off-target must NOT false-reject a valid map, got reason=%q", reason)
	}

	// Even a config that WOULD strand on-target must be skipped off-target
	// (its mapped identities are not present here — no basis to judge).
	strand := compileText(t, strandDeviceMapConfig)
	if reason, offTarget, err := CheckDeviceMapStrandsManagement(strand); err != nil || !offTarget || reason != "" {
		t.Fatalf("off-target strand config: reason=%q offTarget=%v err=%v, want empty/true/nil", reason, offTarget, err)
	}
}

// TestCheckDeviceMapStrandsManagementOnTargetAllUnboundFailsClosed10766F4
// distinguishes a target import from build/deploy-host validation. On a
// build/deploy host this map remains an off-target skip; on the target, the
// same all-unbound map must be evaluated and rejected just like bootstrap's
// import preflight.
func TestCheckDeviceMapStrandsManagementOnTargetAllUnboundFailsClosed10766F4(t *testing.T) {
	oldLifelineRecord := lifelineRecordFileForTest
	lifelineRecordFileForTest = filepath.Join(t.TempDir(), "no-lifeline")
	t.Cleanup(func() { lifelineRecordFileForTest = oldLifelineRecord })
	withInjectedNICs(t, offTargetNICs)
	typo := compileText(t, allUnboundDeviceMapConfig)

	reason, offTarget, err := CheckDeviceMapStrandsManagement(typo)
	if err != nil || !offTarget || reason != "" {
		t.Fatalf("build/deploy-host check: reason=%q offTarget=%v err=%v, want empty/true/nil",
			reason, offTarget, err)
	}

	reason, offTarget, err = CheckDeviceMapStrandsManagementOnTarget(typo)
	if err != nil || offTarget || reason == "" {
		t.Fatalf("on-target check: reason=%q offTarget=%v err=%v, want strand rejection",
			reason, offTarget, err)
	}
	if err := (&Daemon{}).deviceMapCommitPreflight(typo, nil); err == nil {
		t.Fatal("bootstrap/import preflight accepted the same all-unbound map")
	}
}

// TestCheckDeviceMapStrandsManagementOnTargetEnumErrorFailsClosed10766F4
// pins the on-target counterpart to bootstrap's #5490 fail-closed behavior.
func TestCheckDeviceMapStrandsManagementOnTargetEnumErrorFailsClosed10766F4(t *testing.T) {
	inventoryErr := errors.New("simulated NIC enumeration failure")
	withInjectedNICs(t, func() ([]devicemap.PresentNIC, error) {
		return nil, inventoryErr
	})
	typo := compileText(t, allUnboundDeviceMapConfig)

	if _, _, err := CheckDeviceMapStrandsManagementOnTarget(typo); !errors.Is(err, inventoryErr) {
		t.Fatalf("on-target check error = %v, want NIC enumeration error", err)
	}
	if err := (&Daemon{}).deviceMapCommitPreflight(typo, nil); err == nil {
		t.Fatal("bootstrap/import preflight accepted a config when NIC enumeration failed")
	}
}

// TestBootstrapFromFileRejectsStrandingDeviceMap pins #4183 (H-8): the day-0
// bootstrap import runs the SAME device-map strand preflight an interactive
// commit runs, and REFUSES to commit a stranding config (staying in the
// lifeline-safe bootstrap state). RED-on-revert: bootstrapFromFile commits
// the stranding config with no error.
func TestBootstrapFromFileRejectsStrandingDeviceMap(t *testing.T) {
	withInjectedNICs(t, strandNICs)

	dir := t.TempDir()
	path := filepath.Join(dir, "xpf.conf")
	if err := os.WriteFile(path, []byte(strandDeviceMapConfig), 0644); err != nil {
		t.Fatal(err)
	}
	s, err := configstore.New(filepath.Join(dir, "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{opts: Options{ConfigFile: path}, store: s}

	if err := d.bootstrapFromFile(); err == nil {
		t.Fatal("bootstrapFromFile(stranding device-map) = nil, want preflight rejection")
	} else if !strings.Contains(err.Error(), "preflight") && !strings.Contains(err.Error(), "strand") {
		t.Fatalf("bootstrapFromFile error = %v, want device-map preflight/strand rejection", err)
	}
	if d.store.ActiveConfig() != nil {
		t.Fatal("a rejected bootstrap config must NOT be committed (store must have no active config)")
	}
}

// TestBootstrapFromFileCommitsSafeDeviceMap guards against over-gating: a
// safe (non-stranding) device-map config still bootstraps and commits.
func TestBootstrapFromFileCommitsSafeDeviceMap(t *testing.T) {
	withInjectedNICs(t, strandNICs)

	dir := t.TempDir()
	path := filepath.Join(dir, "xpf.conf")
	if err := os.WriteFile(path, []byte(safeDeviceMapConfig), 0644); err != nil {
		t.Fatal(err)
	}
	s, err := configstore.New(filepath.Join(dir, "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{opts: Options{ConfigFile: path}, store: s}

	if err := d.bootstrapFromFile(); err != nil {
		t.Fatalf("bootstrapFromFile(safe device-map) = %v, want nil", err)
	}
	if d.store.ActiveConfig() == nil {
		t.Fatal("a safe bootstrap config must be committed")
	}
}

// TestParseNodeIDFileContent pins #4185 (H-12): the daemon's node-id file
// parser enforces the SAME strict 0|1 contract every other consumer uses.
// RED-on-revert: the historical fmt.Sscanf("%d") accepted "1garbage" (as 1)
// and any integer.
func TestParseNodeIDFileContent(t *testing.T) {
	cases := []struct {
		in     string
		wantN  int
		wantOk bool
	}{
		{"0", 0, true},
		{"1", 1, true},
		{" 1 \n", 1, true},
		{"1garbage", 0, false}, // Sscanf accepted this as 1
		{"2", 0, false},        // out of range
		{"-1", 0, false},       // standalone sentinel is not a valid file value
		{"", 0, false},
		{"abc", 0, false},
		{"0x1", 0, false},
	}
	for _, c := range cases {
		gotN, gotOk := parseNodeIDFileContent(c.in)
		if gotN != c.wantN || gotOk != c.wantOk {
			t.Errorf("parseNodeIDFileContent(%q) = (%d,%v), want (%d,%v)",
				c.in, gotN, gotOk, c.wantN, c.wantOk)
		}
	}
}

// TestRecordBootstrapImport pins #4184 (H-11): a failed day-0 import is
// recorded for /health AND emits a BOOTSTRAP_IMPORT_FAILED event, while the
// expected factory no-config state is recorded but NOT marked failed and
// emits no event. RED-on-revert: neither the snapshot nor the event exists.
func TestRecordBootstrapImport(t *testing.T) {
	d := &Daemon{eventBuf: logging.NewEventBuffer(16)}

	d.recordBootstrapImport(bootstrapImportFailed, "commit: parse error")
	snap := d.BootstrapImportSnapshot()
	if snap.Status != bootstrapImportFailed || !snap.Failed {
		t.Fatalf("snapshot = %+v, want status=import-failed failed=true", snap)
	}
	if snap.Error != "commit: parse error" {
		t.Errorf("snapshot error = %q, want the recorded detail", snap.Error)
	}
	if snap.UnixSec == 0 {
		t.Error("snapshot UnixSec must be stamped")
	}
	var sawEvent bool
	for _, e := range d.eventBuf.Latest(16) {
		if e.Type == "BOOTSTRAP_IMPORT_FAILED" && e.Reason == "commit: parse error" {
			sawEvent = true
		}
	}
	if !sawEvent {
		t.Error("a failed import must emit a BOOTSTRAP_IMPORT_FAILED event")
	}

	// The factory no-config state: recorded, not failed, no event.
	d2 := &Daemon{eventBuf: logging.NewEventBuffer(16)}
	d2.recordBootstrapImport(bootstrapImportNoConfig, "")
	snap2 := d2.BootstrapImportSnapshot()
	if snap2.Status != bootstrapImportNoConfig || snap2.Failed {
		t.Fatalf("no-config snapshot = %+v, want status=no-config failed=false", snap2)
	}
	if len(d2.eventBuf.Latest(16)) != 0 {
		t.Error("the factory no-config state must NOT emit an event")
	}
}

// compileText compiles a hierarchical config text the way bootstrap does,
// for the strand-check unit tests.
func compileText(t *testing.T, text string) *config.Config {
	t.Helper()
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs[0])
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}
