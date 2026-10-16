package upgrade

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #5076: on a purge FAILURE PruneInactiveSlot must NOT delete the candidate's
// package-owned /boot + /lib/modules payload (dpkg still records the package as
// installed; deleting the files leaves the DB and the filesystem inconsistent
// so a later same-version `apt-get install` without --reinstall never restores
// them). It must return a non-nil error and leave the slot selector pointed at
// the known-good kernel. Manual file cleanup may proceed ONLY after dpkg
// confirms the packages are actually gone.

// seedCandidatePayload lays down the /boot + /lib/modules files a candidate
// kernel owns under a temp fsRoot and returns the two paths the prune sweeps.
func seedCandidatePayload(t *testing.T, root, cand string) (modulesDir string, bootFile string) {
	t.Helper()
	modulesDir = filepath.Join(root, "lib", "modules", cand)
	if err := os.MkdirAll(modulesDir, 0755); err != nil {
		t.Fatalf("seed modules dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(modulesDir, "modules.dep"), []byte("x"), 0644); err != nil {
		t.Fatalf("seed modules.dep: %v", err)
	}
	bootDir := filepath.Join(root, "boot")
	if err := os.MkdirAll(bootDir, 0755); err != nil {
		t.Fatalf("seed boot dir: %v", err)
	}
	bootFile = filepath.Join(bootDir, "vmlinuz-"+cand)
	if err := os.WriteFile(bootFile, []byte("x"), 0644); err != nil {
		t.Fatalf("seed boot file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bootDir, "initrd.img-"+cand), []byte("x"), 0644); err != nil {
		t.Fatalf("seed initrd: %v", err)
	}
	return modulesDir, bootFile
}

func TestPruneInactiveSlot_PurgeFailureLeavesFiles(t *testing.T) {
	root := t.TempDir()
	const cand = "7.0.0-99-generic"
	const knownGood = "7.0.0-22-generic"
	modulesDir, bootFile := seedCandidatePayload(t, root, cand)

	var purgeArgs []string
	sys := &realKernelSystem{
		fsRoot:          root,
		runningKernelFn: func() (string, error) { return knownGood, nil },
		pkgInstalledFn:  func(string) (bool, error) { return true, nil }, // candidate installed
		aptGetFn: func(args ...string) error {
			purgeArgs = args
			return fmt.Errorf("dpkg: error: dpkg frontend lock held by another process")
		},
	}

	err := sys.PruneInactiveSlot("xpf-B", knownGood, cand)
	if err == nil {
		t.Fatal("expected non-nil error on purge failure, got nil")
	}
	if !strings.Contains(err.Error(), cand) {
		t.Errorf("error should name the candidate: %v", err)
	}
	// The purge was attempted with the held-package override.
	if len(purgeArgs) == 0 || purgeArgs[0] != "purge" {
		t.Fatalf("expected a purge attempt, got args %v", purgeArgs)
	}
	if !containsArg(purgeArgs, "--allow-change-held-packages") {
		t.Errorf("purge must pass --allow-change-held-packages, got %v", purgeArgs)
	}

	// Package-owned files MUST survive the failed purge.
	if _, statErr := os.Stat(modulesDir); statErr != nil {
		t.Errorf("/lib/modules/%s deleted after failed purge (%v) — leaves dpkg/FS inconsistent", cand, statErr)
	}
	if _, statErr := os.Stat(bootFile); statErr != nil {
		t.Errorf("/boot/vmlinuz-%s deleted after failed purge (%v)", cand, statErr)
	}

	// The slot selector must be left pointed at the known-good kernel.
	sel, selErr := sys.ReadSlotSelector("xpf-B")
	if selErr != nil {
		t.Fatalf("read slot selector: %v", selErr)
	}
	if sel != knownGood {
		t.Errorf("slot selector = %q, want known-good %q (must never point at a half-removed candidate)", sel, knownGood)
	}
}

func TestPruneInactiveSlot_PurgeSuccessSweepsFiles(t *testing.T) {
	root := t.TempDir()
	const cand = "7.0.0-99-generic"
	const knownGood = "7.0.0-22-generic"
	modulesDir, bootFile := seedCandidatePayload(t, root, cand)

	purged := false
	sys := &realKernelSystem{
		fsRoot:          root,
		runningKernelFn: func() (string, error) { return knownGood, nil },
		// Installed before the purge, absent after — dpkg confirms removal.
		pkgInstalledFn: func(string) (bool, error) { return !purged, nil },
		aptGetFn: func(args ...string) error {
			if len(args) > 0 && args[0] == "purge" {
				purged = true
			}
			return nil
		},
	}

	if err := sys.PruneInactiveSlot("xpf-B", knownGood, cand); err != nil {
		t.Fatalf("prune should succeed, got %v", err)
	}
	// dpkg confirmed the packages gone -> the orphaned files are swept.
	if _, statErr := os.Stat(modulesDir); !os.IsNotExist(statErr) {
		t.Errorf("/lib/modules/%s should be swept after confirmed removal (stat err=%v)", cand, statErr)
	}
	if _, statErr := os.Stat(bootFile); !os.IsNotExist(statErr) {
		t.Errorf("/boot/vmlinuz-%s should be swept after confirmed removal (stat err=%v)", cand, statErr)
	}
}

func TestPruneInactiveSlot_PartialPurgeKeepsFiles(t *testing.T) {
	// apt-get returns success but a package is still installed afterwards
	// (partial purge). Manual deletion must NOT proceed — a still-owned payload
	// is never deleted.
	root := t.TempDir()
	const cand = "7.0.0-99-generic"
	const knownGood = "7.0.0-22-generic"
	modulesDir, bootFile := seedCandidatePayload(t, root, cand)

	sys := &realKernelSystem{
		fsRoot:          root,
		runningKernelFn: func() (string, error) { return knownGood, nil },
		pkgInstalledFn:  func(string) (bool, error) { return true, nil }, // never confirmed absent
		aptGetFn:        func(args ...string) error { return nil },
	}

	err := sys.PruneInactiveSlot("xpf-B", knownGood, cand)
	if err == nil {
		t.Fatal("expected error when a package remains installed after purge")
	}
	if !strings.Contains(err.Error(), "still installed") {
		t.Errorf("error should flag the partial purge: %v", err)
	}
	if _, statErr := os.Stat(modulesDir); statErr != nil {
		t.Errorf("/lib/modules/%s deleted despite still-installed package (%v)", cand, statErr)
	}
	if _, statErr := os.Stat(bootFile); statErr != nil {
		t.Errorf("/boot/vmlinuz-%s deleted despite still-installed package (%v)", cand, statErr)
	}
}

func TestPruneInactiveSlot_NothingInstalledSweeps(t *testing.T) {
	// No candidate package is installed (never installed, or already gone). The
	// purge is skipped and any orphaned files are still swept.
	root := t.TempDir()
	const cand = "7.0.0-99-generic"
	const knownGood = "7.0.0-22-generic"
	modulesDir, bootFile := seedCandidatePayload(t, root, cand)

	purgeCalled := false
	sys := &realKernelSystem{
		fsRoot:          root,
		runningKernelFn: func() (string, error) { return knownGood, nil },
		pkgInstalledFn:  func(string) (bool, error) { return false, nil },
		aptGetFn: func(args ...string) error {
			purgeCalled = true
			return nil
		},
	}

	if err := sys.PruneInactiveSlot("xpf-B", knownGood, cand); err != nil {
		t.Fatalf("prune should succeed with nothing installed, got %v", err)
	}
	if purgeCalled {
		t.Error("purge must not run when no candidate package is installed")
	}
	if _, statErr := os.Stat(modulesDir); !os.IsNotExist(statErr) {
		t.Errorf("orphaned /lib/modules/%s should be swept (stat err=%v)", cand, statErr)
	}
	if _, statErr := os.Stat(bootFile); !os.IsNotExist(statErr) {
		t.Errorf("orphaned /boot/vmlinuz-%s should be swept (stat err=%v)", cand, statErr)
	}
}

// #5076: a same-version install where the packages are already recorded
// installed must force --reinstall so apt restores /boot + /lib/modules even
// though dpkg thinks the version is current.
func TestBuildInstallArgs_Reinstall(t *testing.T) {
	pkgs := []string{"linux-image-7.0.0-99-generic", "linux-modules-7.0.0-99-generic"}

	fresh := buildInstallArgs(pkgs, false)
	if containsArg(fresh, "--reinstall") {
		t.Errorf("fresh install must NOT use --reinstall: %v", fresh)
	}
	if fresh[0] != "install" || fresh[1] != "-y" {
		t.Errorf("unexpected install argv: %v", fresh)
	}
	if !containsArg(fresh, pkgs[0]) || !containsArg(fresh, pkgs[1]) {
		t.Errorf("install argv must include the packages: %v", fresh)
	}

	retry := buildInstallArgs(pkgs, true)
	if !containsArg(retry, "--reinstall") {
		t.Errorf("same-version retry with an already-installed package MUST use --reinstall: %v", retry)
	}
	if !containsArg(retry, pkgs[0]) || !containsArg(retry, pkgs[1]) {
		t.Errorf("reinstall argv must include the packages: %v", retry)
	}
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
