package upgrade

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// #16812: currentLinuxPackages enumerated `dpkg-query -W 'linux-*'` with
// only ${binary:Package}, so it returned every name dpkg KNOWS OF — purged
// and never-installed names (linux-headers-3.0, linux-image-fb-generic on
// the Ubuntu 26.04 base) passed the kernel-prefix filter and were handed
// to `apt-mark hold`, which exits 100 on them. The rehold after a candidate
// install was therefore fatal and KernelHeld could never be true, so the
// LANE-1 kernel channel failed AFTER installing the candidate.
//
// The fix enumerates with -f='${db:Status-Status} ${binary:Package}\n'
// and keeps only "installed" rows (mirroring bake.py #1930), in the single
// helper used by hold, unhold and KernelHeld. The tests below drive the
// REAL dpkg-query and apt-mark binaries against a fixture admindir whose
// DB carries such not-installed names.
//
// RED evidence (pre-fix, separate base worktree): see docs/log/16812.md.

const kernel16812Status = `Package: linux-image-6.8.0-31-generic
Status: install ok installed
Priority: optional
Section: kernel
Maintainer: Test <t@example.com>
Architecture: amd64
Version: 6.8.0-31.31
Description: installed kernel image (control)

Package: linux-headers-6.8.0-31
Status: install ok installed
Priority: optional
Section: kernel
Maintainer: Test <t@example.com>
Architecture: amd64
Version: 6.8.0-31.31
Description: installed kernel headers (control)

Package: linux-headers-3.0
Status: purge ok not-installed
Priority: optional
Section: kernel
Maintainer: Test <t@example.com>
Architecture: amd64
Version: 3.0.0-1
Description: never-installed headers name dpkg merely knows of

Package: linux-image-fb-generic
Status: deinstall ok config-files
Priority: optional
Section: kernel
Maintainer: Test <t@example.com>
Architecture: amd64
Version: 1.0
Description: removed image, config-files only

Package: linux-image-generic
Status: purge ok not-installed
Priority: optional
Section: kernel
Maintainer: Test <t@example.com>
Architecture: amd64
Version: 1.0
Description: not-installed kernel meta

Package: linux-base
Status: install ok installed
Priority: optional
Section: misc
Maintainer: Test <t@example.com>
Architecture: all
Version: 4.5
Description: installed but NOT a kernel-family package

`

// setupKernel16812Fixture builds a dpkg admindir + apt state rooted in a
// temp dir and puts shim binaries first on PATH so the production helpers
// (which shell out to bare dpkg-query / apt-mark / apt-get /
// update-initramfs / update-grub) run against the fixture with the REAL
// dpkg-query and apt-mark binaries. Returns the admindir.
func setupKernel16812Fixture(t *testing.T) string {
	t.Helper()
	for _, tool := range []string{"dpkg-query", "apt-mark", "apt-get", "apt-cache"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	root := t.TempDir()
	admindir := filepath.Join(root, "admindir")
	stateLists := filepath.Join(root, "state", "lists")
	cacheArchives := filepath.Join(root, "cache", "archives")
	for _, d := range []string{admindir, stateLists, filepath.Join(stateLists, "partial"), cacheArchives, filepath.Join(cacheArchives, "partial")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(admindir, "status"), []byte(kernel16812Status), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"diversions", "statoverride"} {
		if err := os.WriteFile(filepath.Join(admindir, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	extendedStates := filepath.Join(root, "extended_states")
	if err := os.WriteFile(extendedStates, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	aptConf := filepath.Join(root, "apt.conf")
	aptConfBody := "Dir::State::status \"" + filepath.Join(admindir, "status") + "\";\n" +
		"Dir::State::extended_states \"" + extendedStates + "\";\n" +
		"Dir::State::lists \"" + stateLists + "\";\n" +
		"Dir::Cache \"" + filepath.Join(root, "cache") + "\";\n" +
		"Dir::Cache::archives \"" + cacheArchives + "\";\n" +
		"Dir::State::dpkg \"" + admindir + "\";\n" +
		"DPkg::Options { \"--admindir=" + admindir + "\"; };\n" +
		"APT::Get::AllowUnauthenticated \"true\";\n"
	if err := os.WriteFile(aptConf, []byte(aptConfBody), 0o644); err != nil {
		t.Fatal(err)
	}

	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	realDpkgQuery, err := exec.LookPath("dpkg-query")
	if err != nil {
		t.Fatal(err)
	}
	realAptMark, err := exec.LookPath("apt-mark")
	if err != nil {
		t.Fatal(err)
	}
	realAptCache, err := exec.LookPath("apt-cache")
	if err != nil {
		t.Fatal(err)
	}
	shims := map[string]string{
		// dpkg-query honours DPKG_ADMINDIR natively; the production code
		// passes no --admindir flag, so point the real binary at the fixture
		// via the environment it inherits.
		"dpkg-query": "#!/bin/sh\nexec " + realDpkgQuery + " \"$@\"\n",
		// apt-mark ignores DPKG_ADMINDIR; route it at the fixture status
		// file through APT_CONFIG, and give dpkg (invoked by apt for
		// selections) the admindir via the config's DPkg::Options.
		"apt-mark": "#!/bin/sh\nAPT_CONFIG=" + aptConf + " exec " + realAptMark + " \"$@\"\n",
		// The candidate install itself is a no-op in this fixture (there
		// are no .debs to install); only hold/unhold/KernelHeld semantics
		// are under test. Records its argv for control assertions.
		"apt-get":          "#!/bin/sh\nexit 0\n",
		"apt-cache":        "#!/bin/sh\nif [ \"$1\" = show ]; then exit 1; fi\nexec " + realAptCache + " \"$@\"\n",
		"update-initramfs": "#!/bin/sh\nexit 0\n",
		"update-grub":      "#!/bin/sh\nexit 0\n",
	}
	for name, body := range shims {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("DPKG_ADMINDIR", admindir)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return admindir
}

func TestCurrentLinuxPackages_InstalledOnly_16812(t *testing.T) {
	setupKernel16812Fixture(t)

	got := currentLinuxPackages()
	want := []string{"linux-headers-6.8.0-31", "linux-image-6.8.0-31-generic"}
	// dpkg-query output order follows the status file; compare as sets.
	if len(got) != len(want) {
		t.Fatalf("currentLinuxPackages() = %v, want installed-only %v", got, want)
	}
	seen := map[string]bool{}
	for _, p := range got {
		seen[p] = true
	}
	for _, p := range want {
		if !seen[p] {
			t.Errorf("currentLinuxPackages() missing installed package %q (got %v)", p, got)
		}
	}
	for _, bad := range []string{"linux-headers-3.0", "linux-image-fb-generic", "linux-image-generic", "linux-base"} {
		if seen[bad] {
			t.Errorf("currentLinuxPackages() included %q — not-installed/non-kernel names must be filtered (#16812)", bad)
		}
	}
}

func TestParseInstalledLinuxPackages_16812(t *testing.T) {
	out := "installed linux-image-6.8.0-31-generic\n" +
		"not-installed linux-headers-3.0\n" +
		"config-files linux-image-fb-generic\n" +
		"not-installed linux-image-generic\n" +
		"installed linux-base\n" +
		"installed linux-headers-6.8.0-31\n" +
		"installed linux-image-6.8.0-31-generic\n" +
		"\n" +
		"garbage-without-space\n"
	got := parseInstalledLinuxPackages(out)
	want := []string{"linux-image-6.8.0-31-generic", "linux-headers-6.8.0-31"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("parseInstalledLinuxPackages() = %v, want %v", got, want)
	}
}

func TestHoldAndKernelHeld_WithNotInstalledNames_16812(t *testing.T) {
	setupKernel16812Fixture(t)
	sys := &realKernelSystem{}

	// Nothing held yet: KernelHeld must be false (control — the installed
	// set is non-empty and unheld).
	held, err := sys.KernelHeld()
	if err != nil {
		t.Fatalf("KernelHeld (pre-hold): %v", err)
	}
	if held {
		t.Fatal("KernelHeld (pre-hold) = true, want false")
	}

	// The rehold that InstallCandidateKernel treats as FATAL: pre-fix this
	// failed with apt-mark exit 100 on linux-headers-3.0 /
	// linux-image-fb-generic / linux-image-generic.
	if err := holdLinuxPackages(); err != nil {
		t.Fatalf("holdLinuxPackages with not-installed names in dpkg DB: %v", err)
	}

	held, err = sys.KernelHeld()
	if err != nil {
		t.Fatalf("KernelHeld (post-hold): %v", err)
	}
	if !held {
		t.Fatal("KernelHeld (post-hold) = false, want true — every installed kernel package should be held")
	}

	// Unhold must likewise not trip over the not-installed names.
	unholdLinuxPackages()
	held, err = sys.KernelHeld()
	if err != nil {
		t.Fatalf("KernelHeld (post-unhold): %v", err)
	}
	if held {
		t.Fatal("KernelHeld (post-unhold) = true, want false")
	}
}

func TestInstallCandidateKernel_WithNotInstalledNames_16812(t *testing.T) {
	setupKernel16812Fixture(t)
	sys := &realKernelSystem{
		// apt-get / update-initramfs / update-grub are PATH shims (no-ops);
		// the dpkg candidate-payload probe uses the fixture too, but pin
		// the running kernel so /lib/modules checks stay off the host.
		runningKernelFn: func() (string, error) { return "6.8.0-31-generic", nil },
	}
	// Hold the installed set first, mirroring a shipped appliance.
	if err := holdLinuxPackages(); err != nil {
		t.Fatalf("initial hold: %v", err)
	}
	ver, err := sys.InstallCandidateKernel("6.8.0-31-generic")
	if err != nil {
		t.Fatalf("InstallCandidateKernel with not-installed names in dpkg DB: %v", err)
	}
	if ver != "6.8.0-31-generic" {
		t.Fatalf("InstallCandidateKernel returned %q, want candidate version", ver)
	}
	held, err := sys.KernelHeld()
	if err != nil {
		t.Fatalf("KernelHeld after install: %v", err)
	}
	if !held {
		t.Fatal("KernelHeld after InstallCandidateKernel = false, want true (rehold must have succeeded)")
	}
}

// Preflight must refuse a not-held kernel set BEFORE any install mutation
// (#16812 optional gate, now implemented): previously the failure surfaced
// only after the candidate was installed, leaving a PREFLIGHT journal.
func TestKernelPreflight_RefusesUnheldKernelSet_16812(t *testing.T) {
	f := newFakeKernelSystem()
	f.held = false
	r := newKernelRunner(t, f)
	err := r.Arm("6.18.5-12-generic")
	if err == nil {
		t.Fatal("Arm with unheld kernel set = nil, want preflight refusal")
	}
	if !strings.Contains(err.Error(), "not all held") {
		t.Fatalf("Arm error = %v, want kernel-hold preflight refusal", err)
	}
	if contains(f.calls, "install:6.18.5-12-generic") {
		t.Fatal("candidate was installed despite the preflight hold refusal — failure must precede mutation (#16812)")
	}
	j, jerr := r.loadKernelJournal()
	if jerr != nil {
		t.Fatalf("load journal: %v", jerr)
	}
	if j.State.atLeast(KernelStatePreflight) {
		t.Fatalf("journal state = %s, want pre-PREFLIGHT (no journal transition on hold refusal)", j.State)
	}
}
