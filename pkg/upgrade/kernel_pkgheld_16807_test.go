package upgrade

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// #16807: isPkgInstalled matched only the literal "install ok installed", so a
// HELD candidate package ("hold ok installed") read as confirmed-absent.
// PruneInactiveSlot then skipped `apt-get purge` entirely and swept the
// package-owned /boot + /lib/modules payload, desyncing dpkg from the
// filesystem on every discarded/reverted roll (the #5076/#5428 guard rendered
// inert for the always-held candidate). Classification must be by the
// `${db:Status-Status}` word, with partial states (half-installed / unpacked /
// half-configured / triggers-*) treated as possibly-installed.

// writeFakeDpkgStatus lays down a minimal dpkg admindir whose status file
// carries the given (package, Status triple) entries, and points the real
// dpkg-query at it via DPKG_ADMINDIR (captureCmd inherits os.Environ). Each
// entry needs Maintainer/Architecture or dpkg-query treats the file as corrupt.
func writeFakeDpkgStatus(t *testing.T, entries ...[2]string) string {
	t.Helper()
	admindir := filepath.Join(t.TempDir(), "dpkg")
	if err := os.MkdirAll(filepath.Join(admindir, "updates"), 0o755); err != nil {
		t.Fatalf("mkdir admindir updates: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(admindir, "info"), 0o755); err != nil {
		t.Fatalf("mkdir admindir info: %v", err)
	}
	var b strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&b, "Package: %s\nStatus: %s\nPriority: optional\nSection: kernel\nMaintainer: Test <t@example.com>\nArchitecture: amd64\nVersion: 1.0\nDescription: test\n\n", e[0], e[1])
	}
	if err := os.WriteFile(filepath.Join(admindir, "status"), []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write fake dpkg status: %v", err)
	}
	t.Setenv("DPKG_ADMINDIR", admindir)
	return admindir
}

func requireDpkgQuery(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		t.Skip("dpkg-query not available")
	}
}

// TestIsPkgInstalled_HeldInstalled16807 is the defect cell: a real dpkg-query
// against a fake admindir reports "hold ok installed" for the held candidate.
// Pre-fix this returned (false, nil) — confirmed-absent — so the prune skipped
// the purge and swept owned files. It must now return (true, nil). The
// unheld control ("install ok installed") stays (true, nil) either way.
func TestIsPkgInstalled_HeldInstalled16807(t *testing.T) {
	requireDpkgQuery(t)
	const heldPkg = "linux-image-7.0.0-99-generic"
	const unheldPkg = "linux-headers-7.0.0-99-generic"
	writeFakeDpkgStatus(t,
		[2]string{heldPkg, "hold ok installed"},
		[2]string{unheldPkg, "install ok installed"},
	)

	installed, err := isPkgInstalled(heldPkg)
	if err != nil {
		t.Fatalf("held installed package: isPkgInstalled err = %v, want nil", err)
	}
	if !installed {
		t.Errorf("held package (%q) reported not-installed — prune would skip purge and sweep owned files", heldPkg)
	}

	installed, err = isPkgInstalled(unheldPkg)
	if err != nil {
		t.Fatalf("unheld installed package: isPkgInstalled err = %v, want nil", err)
	}
	if !installed {
		t.Errorf("unheld installed package (%q) reported not-installed", unheldPkg)
	}
}

// TestIsPkgInstalled_PartialAndAbsent16807 locks the wider status-word
// classification against the real dpkg-query: partial states count as
// possibly-installed, while config-files / not-installed count as absent.
func TestIsPkgInstalled_PartialAndAbsent16807(t *testing.T) {
	requireDpkgQuery(t)
	writeFakeDpkgStatus(t,
		[2]string{"pkg-half-installed", "install ok half-installed"},
		[2]string{"pkg-unpacked", "hold ok unpacked"},
		[2]string{"pkg-half-configured", "install ok half-configured"},
		[2]string{"pkg-config-files", "deinstall ok config-files"},
		[2]string{"pkg-not-installed", "deinstall ok not-installed"},
	)
	for _, pkg := range []string{"pkg-half-installed", "pkg-unpacked", "pkg-half-configured"} {
		installed, err := isPkgInstalled(pkg)
		if err != nil || !installed {
			t.Errorf("%s: isPkgInstalled = (%v, %v), want (true, nil) — partial state is possibly-installed", pkg, installed, err)
		}
	}
	for _, pkg := range []string{"pkg-config-files", "pkg-not-installed"} {
		installed, err := isPkgInstalled(pkg)
		if err != nil || installed {
			t.Errorf("%s: isPkgInstalled = (%v, %v), want (false, nil)", pkg, installed, err)
		}
	}
	// A genuinely unknown package stays confirmed-absent without an error.
	installed, err := isPkgInstalled("xpf-nonexistent-package-zzz-16807")
	if err != nil || installed {
		t.Errorf("unknown package: isPkgInstalled = (%v, %v), want (false, nil)", installed, err)
	}
}

// TestDpkgStatusInstalled16807 unit-locks the pure word classifier, including
// the triggers-* words a real dpkg-query refuses to synthesize in a bare
// status file (it validates trigger bookkeeping), so those cells are covered
// here rather than through the admindir fixture.
func TestDpkgStatusInstalled16807(t *testing.T) {
	for _, s := range []string{"installed", "half-installed", "unpacked", "half-configured", "triggers-awaited", "triggers-pending"} {
		if !dpkgStatusInstalled(s) {
			t.Errorf("dpkgStatusInstalled(%q) = false, want true (possibly-installed)", s)
		}
	}
	for _, s := range []string{"not-installed", "config-files", "", "bogus-word"} {
		if dpkgStatusInstalled(s) {
			t.Errorf("dpkgStatusInstalled(%q) = true, want false", s)
		}
	}
}

// TestPruneInactiveSlot_HeldCandidatePurged16807 is the acceptance cell from
// the issue: with a real-dpkg admindir fixture holding `hold ok installed`
// candidates, PruneInactiveSlot must issue
// `apt-get purge ... --allow-change-held-packages`. The fake apt-get flips the
// admindir entries to purged (removed from the DB), so the post-purge re-query
// confirms absence and the sweep may then proceed. Pre-fix no purge was issued
// at all (the held packages read as absent), so purgeArgs stayed empty.
func TestPruneInactiveSlot_HeldCandidatePurged16807(t *testing.T) {
	requireDpkgQuery(t)
	const cand = "7.0.0-99-generic"
	const knownGood = "7.0.0-22-generic"
	root := t.TempDir()
	modulesDir, bootFile := seedCandidatePayload(t, root, cand)

	candPkgs := []string{
		"linux-image-" + cand,
		"linux-modules-" + cand,
		"linux-modules-extra-" + cand,
		"linux-headers-" + cand,
	}
	entries := make([][2]string, 0, len(candPkgs))
	for _, p := range candPkgs {
		entries = append(entries, [2]string{p, "hold ok installed"})
	}
	admindir := writeFakeDpkgStatus(t, entries...)

	var purgeArgs []string
	sys := &realKernelSystem{
		fsRoot:          root,
		runningKernelFn: func() (string, error) { return knownGood, nil },
		// pkgInstalledFn deliberately nil: exercise the REAL isPkgInstalled
		// against the fake admindir — the seam the safety tests bypass.
		aptGetFn: func(args ...string) error {
			if len(args) > 0 && args[0] == "purge" {
				purgeArgs = append([]string(nil), args...)
				// Model a successful purge: dpkg drops the packages from the
				// DB entirely, so the re-query reports them unknown/absent.
				return os.WriteFile(filepath.Join(admindir, "status"), []byte(""), 0o644)
			}
			return fmt.Errorf("unexpected apt-get args %v", args)
		},
	}

	if err := sys.PruneInactiveSlot("xpf-B", knownGood, cand); err != nil {
		t.Fatalf("PruneInactiveSlot(held candidate) = %v, want nil (purge then sweep)", err)
	}
	if len(purgeArgs) == 0 {
		t.Fatal("no apt-get purge issued for held installed candidate — held packages misread as absent")
	}
	if purgeArgs[0] != "purge" || !containsArg(purgeArgs, "--allow-change-held-packages") {
		t.Errorf("purge args = %v, want purge ... --allow-change-held-packages", purgeArgs)
	}
	for _, p := range candPkgs {
		if !containsArg(purgeArgs, p) {
			t.Errorf("purge args = %v, missing held candidate package %s", purgeArgs, p)
		}
	}
	// Purge confirmed, so the now-orphaned payload is swept.
	if _, err := os.Stat(modulesDir); !os.IsNotExist(err) {
		t.Errorf("/lib/modules/%s should be swept after confirmed purge, stat err = %v", cand, err)
	}
	if _, err := os.Stat(bootFile); !os.IsNotExist(err) {
		t.Errorf("/boot/vmlinuz-%s should be swept after confirmed purge, stat err = %v", cand, err)
	}
	if sel, err := sys.ReadSlotSelector("xpf-B"); err != nil || sel != knownGood {
		t.Errorf("slot selector = %q (err %v), want known-good %q", sel, err, knownGood)
	}
}

// TestPruneInactiveSlot_HeldStillInstalledKeepsFiles16807 covers the second
// acceptance clause: it keeps the files if the re-query still reports
// installed. The fake apt-get "succeeds" but the admindir still reports
// `hold ok installed`, so the confirmed-absent gate must refuse the sweep.
func TestPruneInactiveSlot_HeldStillInstalledKeepsFiles16807(t *testing.T) {
	requireDpkgQuery(t)
	const cand = "7.0.0-99-generic"
	const knownGood = "7.0.0-22-generic"
	root := t.TempDir()
	modulesDir, bootFile := seedCandidatePayload(t, root, cand)

	candPkgs := []string{
		"linux-image-" + cand,
		"linux-modules-" + cand,
		"linux-modules-extra-" + cand,
		"linux-headers-" + cand,
	}
	entries := make([][2]string, 0, len(candPkgs))
	for _, p := range candPkgs {
		entries = append(entries, [2]string{p, "hold ok installed"})
	}
	writeFakeDpkgStatus(t, entries...)

	purgeAttempted := false
	sys := &realKernelSystem{
		fsRoot:          root,
		runningKernelFn: func() (string, error) { return knownGood, nil },
		aptGetFn: func(args ...string) error {
			if len(args) > 0 && args[0] == "purge" {
				purgeAttempted = true
			}
			return nil // claims success, but dpkg still reports installed
		},
	}

	err := sys.PruneInactiveSlot("xpf-B", knownGood, cand)
	if err == nil {
		t.Fatal("expected error when re-query still reports held candidate installed")
	}
	if !strings.Contains(err.Error(), "still installed") {
		t.Errorf("error should flag the unconfirmed removal: %v", err)
	}
	if !purgeAttempted {
		t.Error("purge must be attempted for held installed candidate")
	}
	if _, statErr := os.Stat(modulesDir); statErr != nil {
		t.Errorf("/lib/modules/%s deleted despite still-installed re-query (%v)", cand, statErr)
	}
	if _, statErr := os.Stat(bootFile); statErr != nil {
		t.Errorf("/boot/vmlinuz-%s deleted despite still-installed re-query (%v)", cand, statErr)
	}
}
