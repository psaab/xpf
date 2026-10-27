package config

// #5300: the `system dataplane shared-umem phase0-artifact-file` audit read
// must be NON-GATING (a read failure never fails the commit), DETERMINISTIC
// (the node-local file's presence/content never changes the typed config so a
// peer / restart host compiles the identical config), and NON-BLOCKING /
// bounded (a non-regular file such as a directory or FIFO is skipped, never
// opened+read, so it cannot hang the commit).
//
// These tests use the ParseSetCommand + tree.SetPath loop (never NewParser for
// set syntax, per CLAUDE.md).

import (
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

// hasWarningContaining is defined in vrrp_track_test.go (same package).

// buildSharedUMEMTree builds a userspace + cross-nic shared-umem tree that
// references artifactPath, via the flat-set ParseSetCommand + SetPath loop.
func buildSharedUMEMTree(t *testing.T, artifactPath string) *ConfigTree {
	t.Helper()
	lines := []string{
		"set system dataplane-type userspace",
		"set system dataplane shared-umem mode cross-nic",
		"set system dataplane shared-umem interface ge-0/0/1",
		"set system dataplane shared-umem interface ge-0/0/2",
		"set system dataplane shared-umem phase0-artifact-file " + artifactPath,
	}
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	return tree
}

// compileWithinTimeout compiles tree in a goroutine and fails the test if the
// compile does not return within d. This is the guard that makes the
// non-blocking assertion a clean FAIL (not a hung suite) on a regression to the
// old blocking os.Open of a FIFO/device.
func compileWithinTimeout(t *testing.T, tree *ConfigTree, d time.Duration) (*Config, error) {
	t.Helper()
	type result struct {
		cfg *Config
		err error
	}
	ch := make(chan result, 1)
	go func() {
		cfg, err := CompileConfig(tree)
		ch <- result{cfg, err}
	}()
	select {
	case r := <-ch:
		return r.cfg, r.err
	case <-time.After(d):
		t.Fatalf("CompileConfig did not return within %s — a blocking audit read hung the commit", d)
		return nil, nil // unreachable
	}
}

// TestSharedUMEMAuditMissingFileIsNonGating: a committed config that references
// an audit file which does NOT exist on this node must still COMPILE. RED on a
// revert to the blocking/gating read (which returns the os.Open error directly).
func TestSharedUMEMAuditMissingFileIsNonGating(t *testing.T) {
	defer stubSharedUMEMLiveEnv17134(t, goodSharedUMEMLiveEnv17134())()
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	tree := buildSharedUMEMTree(t, missing)

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig with a missing audit file must succeed (non-gating), got %v", err)
	}
	dp := cfg.System.UserspaceDataplane
	if dp == nil || dp.SharedUMEM == nil {
		t.Fatal("SharedUMEM config not compiled")
	}
	if dp.SharedUMEM.Mode != "cross-nic" {
		t.Fatalf("SharedUMEM.Mode = %q, want cross-nic", dp.SharedUMEM.Mode)
	}
	if dp.SharedUMEM.Phase0ArtifactFile != missing {
		t.Fatalf("Phase0ArtifactFile = %q, want %q", dp.SharedUMEM.Phase0ArtifactFile, missing)
	}
	if !hasWarningContaining(cfg.Warnings, "audit artifact unavailable") {
		t.Fatalf("expected non-blocking audit-unavailable warning, got %#v", cfg.Warnings)
	}
}

// TestSharedUMEMAuditDeterministic: the SAME committed tree must produce the
// IDENTICAL typed SharedUMEM config whether the node-local audit file is present
// (with content A), present with different content (B), or absent. RED on a
// revert that embeds the parsed file content into the typed config (present vs
// absent then differ) or that gates the compile on a missing file.
func TestSharedUMEMAuditDeterministic(t *testing.T) {
	defer stubSharedUMEMLiveEnv17134(t, goodSharedUMEMLiveEnv17134())()
	// Same declared path string across all three compiles.
	artifact := filepath.Join(t.TempDir(), "phase0.json")

	compile := func() *SharedUMEMConfig {
		t.Helper()
		cfg, err := CompileConfig(buildSharedUMEMTree(t, artifact))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if cfg.System.UserspaceDataplane == nil || cfg.System.UserspaceDataplane.SharedUMEM == nil {
			t.Fatal("SharedUMEM config not compiled")
		}
		return cfg.System.UserspaceDataplane.SharedUMEM
	}

	// (A) present, one content.
	if err := os.WriteFile(artifact, []byte(`{"passed":true,"kernel_release":"kA","selected_interfaces":["ge-0/0/1","ge-0/0/2"]}`), 0644); err != nil {
		t.Fatal(err)
	}
	present := compile()

	// (B) present, DIFFERENT content.
	if err := os.WriteFile(artifact, []byte(`{"passed":false,"kernel_release":"kB-totally-different","selected_interfaces":["ge-9/9/9"]}`), 0644); err != nil {
		t.Fatal(err)
	}
	differentContent := compile()

	// (C) absent.
	if err := os.Remove(artifact); err != nil {
		t.Fatal(err)
	}
	absent := compile()

	if !reflect.DeepEqual(present, differentContent) {
		t.Fatalf("typed SharedUMEM differs with file content:\n present=%#v\n different=%#v", present, differentContent)
	}
	if !reflect.DeepEqual(present, absent) {
		t.Fatalf("typed SharedUMEM differs with file presence:\n present=%#v\n absent=%#v", present, absent)
	}
	// Sanity: the invariant we assert is that only the DECLARED path is carried.
	if present.Phase0ArtifactFile != artifact {
		t.Fatalf("Phase0ArtifactFile = %q, want %q", present.Phase0ArtifactFile, artifact)
	}
}

// TestSharedUMEMAuditNonRegularDirectoryIsNonBlocking: a directory path is a
// non-regular file; the audit read must skip it (stat-first) rather than open
// it, so the compile succeeds quickly with a warning. Bounded by a timeout so a
// regression cannot hang the suite.
func TestSharedUMEMAuditNonRegularDirectoryIsNonBlocking(t *testing.T) {
	defer stubSharedUMEMLiveEnv17134(t, goodSharedUMEMLiveEnv17134())()
	dir := t.TempDir() // a directory is not a regular file
	tree := buildSharedUMEMTree(t, dir)

	cfg, err := compileWithinTimeout(t, tree, 10*time.Second)
	if err != nil {
		t.Fatalf("CompileConfig with a directory audit path must succeed (non-gating), got %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "not a regular file") {
		t.Fatalf("expected non-regular-file audit warning, got %#v", cfg.Warnings)
	}
}

// TestSharedUMEMAuditFIFOIsNonBlocking: a FIFO with no writer would block an
// os.Open(O_RDONLY) indefinitely. The stat-first non-regular skip (plus the
// O_NONBLOCK backstop) must make the compile return promptly. RED on a revert
// to the old blocking open: the compile goroutine blocks forever and the
// timeout guard fails the test.
func TestSharedUMEMAuditFIFOIsNonBlocking(t *testing.T) {
	defer stubSharedUMEMLiveEnv17134(t, goodSharedUMEMLiveEnv17134())()
	fifo := filepath.Join(t.TempDir(), "phase0.fifo")
	if err := syscall.Mkfifo(fifo, 0644); err != nil {
		t.Skipf("mkfifo unsupported here: %v", err)
	}
	tree := buildSharedUMEMTree(t, fifo)

	cfg, err := compileWithinTimeout(t, tree, 10*time.Second)
	if err != nil {
		t.Fatalf("CompileConfig with a FIFO audit path must succeed (non-gating), got %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "not a regular file") {
		t.Fatalf("expected non-regular-file audit warning for a FIFO, got %#v", cfg.Warnings)
	}
}

// #17134: the Go audit now owns the environment comparison the Rust
// helper used to run (kernel / PCI / driver / MTU / queue topology).
// A kernel mismatch and an MTU mismatch must each surface as a
// non-gating commit warning; matching artifacts stay silent.

func TestSharedUMEMAuditKernelMismatchWarns17134(t *testing.T) {
	artifact := t.TempDir() + "/phase0.json"
	body := `{"passed":true,"kernel_release":"stale-kernel","selected_interfaces":["ge-0/0/1","ge-0/0/2"],"selected_nic_pci_ids":["0000:08:00.0","0000:09:00.0"],"selected_device_set":["0000:08:00.0","0000:09:00.0"],"driver":"mlx5_core","mtu":1500,"queue_topology":4}`
	if err := os.WriteFile(artifact, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	restore := stubSharedUMEMLiveEnv17134(t, goodSharedUMEMLiveEnv17134())
	defer restore()
	cfg, err := compileWithinTimeout(t, buildSharedUMEMTree(t, artifact), 10*time.Second)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "kernel_release stale-kernel != current test-kernel") {
		t.Fatalf("expected kernel mismatch warning, got %#v", cfg.Warnings)
	}
}

func TestSharedUMEMAuditMTUMismatchWarns17134(t *testing.T) {
	artifact := t.TempDir() + "/phase0.json"
	body := `{"passed":true,"kernel_release":"test-kernel","selected_interfaces":["ge-0/0/1","ge-0/0/2"],"selected_nic_pci_ids":["0000:08:00.0","0000:09:00.0"],"selected_device_set":["0000:08:00.0","0000:09:00.0"],"driver":"mlx5_core","mtu":9000,"queue_topology":4}`
	if err := os.WriteFile(artifact, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	restore := stubSharedUMEMLiveEnv17134(t, goodSharedUMEMLiveEnv17134())
	defer restore()
	cfg, err := compileWithinTimeout(t, buildSharedUMEMTree(t, artifact), 10*time.Second)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "MTU") {
		t.Fatalf("expected MTU mismatch warning, got %#v", cfg.Warnings)
	}
}

func TestSharedUMEMAuditMatchingArtifactSilent17134(t *testing.T) {
	artifact := t.TempDir() + "/phase0.json"
	body := `{"passed":true,"kernel_release":"test-kernel","selected_interfaces":["ge-0/0/1","ge-0/0/2"],"selected_nic_pci_ids":["0000:08:00.0","0000:09:00.0"],"selected_device_set":["0000:08:00.0","0000:09:00.0"],"driver":"mlx5_core","mtu":1500,"queue_topology":4}`
	if err := os.WriteFile(artifact, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	restore := stubSharedUMEMLiveEnv17134(t, goodSharedUMEMLiveEnv17134())
	defer restore()
	cfg, err := compileWithinTimeout(t, buildSharedUMEMTree(t, artifact), 10*time.Second)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if hasWarningContaining(cfg.Warnings, "shared-umem phase0-artifact-file") {
		t.Fatalf("matching artifact must not warn, got %#v", cfg.Warnings)
	}
}

// TestSharedUMEMAuditConfiguredInterfacesMismatchWarns17134: #17134
// fold F3 — the audit must compare the artifact's selected interfaces
// against the CONFIGURED `shared-umem interface` list (threaded from
// `sharedUMEMAuditWarnings(cfg)`), not merely derive the list from
// the artifact itself. An artifact recorded for entirely different
// NICs than configured must warn even though it is self-consistent
// with its own NICs' (stubbed) live data.
func TestSharedUMEMAuditConfiguredInterfacesMismatchWarns17134(t *testing.T) {
	artifact := t.TempDir() + "/phase0.json"
	body := `{"passed":true,"kernel_release":"test-kernel","selected_interfaces":["ge-0/0/3","ge-0/0/4"],"selected_nic_pci_ids":["0000:08:00.0","0000:09:00.0"],"selected_device_set":["0000:08:00.0","0000:09:00.0"],"driver":"mlx5_core","mtu":1500,"queue_topology":4}`
	if err := os.WriteFile(artifact, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	restore := stubSharedUMEMLiveEnv17134(t, goodSharedUMEMLiveEnv17134())
	defer restore()
	// buildSharedUMEMTree configures ge-0/0/1 + ge-0/0/2.
	cfg, err := compileWithinTimeout(t, buildSharedUMEMTree(t, artifact), 10*time.Second)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "selected interfaces do not match configured") {
		t.Fatalf("expected configured-interface mismatch warning, got %#v", cfg.Warnings)
	}
}
