package dataplane

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// #18966: the gate-attestation mktemp must honor the caller's TMPDIR
// across the sudo hop.
//
// Mechanism on origin/master: run_verifier's non-root arm runs
// `sudo -n mktemp -t shimverify-attestation.XXXXXX`. sudo scrubs TMPDIR
// from the environment, so mktemp resolved the template against /tmp no
// matter what the caller exported — the Makefile pins TMPDIR to
// /var/worktrees/.cache/tmpdir (#14833) precisely so build scratch
// never lands on /tmp. On a workstation whose /tmp tmpfs is full, the
// attestation was created there and shimverify's verdict write failed
// with ENOSPC, so `make generate-userspace-xdp` died at the verifier
// gate (parent-reproduced during PR #18965 verification). The root arm
// relied on the same implicit `mktemp -t` TMPDIR lookup instead of a
// directory the recipe captured before the hop.
//
// Coverage is layered, because the two arms are not equally reachable:
// under this repo's testguard (private net+mount namespace, uid mapped
// to 0) the behavioral probe below exercises the ROOT arm end-to-end;
// on a genuinely non-root host with passwordless sudo it exercises the
// sudo arm. The pre-fix `mktemp -t` shape happens to honor TMPDIR in
// the root arm (no sudo scrub there), so red/green discrimination for
// the scrubbed sudo arm is carried by the structural pin
// (TestBuildRecipePinsAttestationTmpdirThreading18966), which matches
// the recipe as CODE (comment-stripped shellCodeLines) — the same
// defense TestBuildRecipeHandlesShimverifyExitCodes uses against
// prose-satisfied assertions.

// TestBuildRecipePinsAttestationTmpdirThreading18966 pins the #18966
// recipe contract as code: both of run_verifier's attestation mktemp
// invocations must pass the pre-sudo ATTESTATION_TMPDIR explicitly and
// must not use the TMPDIR-scrubbed `mktemp -t` shape; the capture line
// must exist and precede them. sudo scrubs TMPDIR, so any attestation
// mktemp whose directory depends on the environment sudo hands to
// mktemp lands in /tmp — fatal on a /tmp-full workstation (#14833
// exists precisely to keep build scratch off /tmp).
func TestBuildRecipePinsAttestationTmpdirThreading18966(t *testing.T) {
	data, err := os.ReadFile("build-userspace-xdp.sh")
	if err != nil {
		t.Fatalf("read build-userspace-xdp.sh: %v", err)
	}
	code := shellCodeLines(string(data))
	captureIdx := -1
	var attestationMktemps []string
	for i, line := range code {
		if strings.Contains(line, `ATTESTATION_TMPDIR="${TMPDIR:-/tmp}"`) {
			captureIdx = i
		}
		if !strings.Contains(line, "mktemp") || !strings.Contains(line, "shimverify-attestation.XXXXXX") {
			continue
		}
		attestationMktemps = append(attestationMktemps, line)
		if strings.Contains(line, " -t ") {
			t.Errorf("#18966: attestation mktemp still uses the TMPDIR-scrubbed `mktemp -t` shape: %q", line)
		}
		if !strings.Contains(line, `"${ATTESTATION_TMPDIR}"`) {
			t.Errorf("#18966: attestation mktemp does not reference the pre-sudo ATTESTATION_TMPDIR: %q", line)
		}
		if captureIdx >= 0 && i < captureIdx {
			t.Errorf("#18966: attestation mktemp precedes the ATTESTATION_TMPDIR capture: %q", line)
		}
	}
	if captureIdx < 0 {
		t.Error(`#18966: no executable line captures ATTESTATION_TMPDIR from the pre-sudo TMPDIR (default /tmp)`)
	}
	if len(attestationMktemps) != 2 {
		t.Fatalf("#18966: expected the root and sudo arms' two attestation mktemp lines, got %d: %q",
			len(attestationMktemps), attestationMktemps)
	}
	// The sudo arm's mktemp runs with sudo's scrubbed environment: the
	// directory must survive the hop as explicit argv.
	sudoArm := false
	for _, line := range code {
		if strings.Contains(line, `sudo -n mktemp -p "${ATTESTATION_TMPDIR}"`) {
			sudoArm = true
		}
	}
	if !sudoArm {
		t.Error(`#18966: no executable line runs sudo -n mktemp -p "${ATTESTATION_TMPDIR}"; the sudo arm's attestation location again depends on the environment sudo scrubs`)
	}
}

// TestBuildRecipeAttestationHonorsPresudoTmpdir18966 is the behavioral
// half: drive the real recipe through run_verifier with stand-in
// cargo/go binaries (the #17729 fixture shape) and a caller-set TMPDIR.
// The stub shimverify records the --gate-verdict path it was handed and
// exits 99, a gate plumbing failure, so the install leg never runs
// against a stub-verified object. The attestation must exist, INSIDE
// the caller's TMPDIR, at verifier invocation time, and the EXIT trap
// must remove it (and every other recipe temp) afterwards.
func TestBuildRecipeAttestationHonorsPresudoTmpdir18966(t *testing.T) {
	if os.Getuid() != 0 {
		if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
			t.Skip("the attestation mktemp arms need root or passwordless sudo")
		}
	}
	sourceRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	attDir := filepath.Join(root, "att-tmpdir")
	if err := os.MkdirAll(attDir, 0o755); err != nil {
		t.Fatal(err)
	}

	fakeHome := filepath.Join(root, "home")
	fakeLinker := filepath.Join(fakeHome, ".cargo", "bin", "bpf-linker")
	if err := os.MkdirAll(filepath.Dir(fakeLinker), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fakeLinker, []byte("#!/usr/bin/env bash\necho 'bpf-linker 0.10.2'\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	repoRoot := filepath.Join(root, "checkout")
	crateDir := filepath.Join(repoRoot, "userspace-xdp")
	for _, dir := range []string{
		filepath.Join(repoRoot, "pkg", "dataplane"),
		filepath.Join(repoRoot, "bpf", "headers"),
		filepath.Join(crateDir, ".cargo"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	copyFile := func(src, dst string, mode os.FileMode) {
		t.Helper()
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, data, mode); err != nil {
			t.Fatal(err)
		}
	}
	copyFile(filepath.Join(sourceRoot, "pkg", "dataplane", "build-userspace-xdp.sh"), filepath.Join(repoRoot, "pkg", "dataplane", "build-userspace-xdp.sh"), 0o755)
	copyFile(filepath.Join(sourceRoot, "bpf", "headers", "xpf_common.h"), filepath.Join(repoRoot, "bpf", "headers", "xpf_common.h"), 0o644)
	copyFile(filepath.Join(sourceRoot, "userspace-xdp", "rust-toolchain.toml"), filepath.Join(crateDir, "rust-toolchain.toml"), 0o644)
	copyFile(filepath.Join(sourceRoot, "userspace-xdp", ".cargo", "config.toml"), filepath.Join(crateDir, ".cargo", "config.toml"), 0o644)
	if err := os.WriteFile(filepath.Join(crateDir, "Cargo.toml"), []byte("[package]\nname = \"attestation-tmpdir-probe\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Stand-in cargo: answers the toolchain probe, then produces the
	// fake candidate object the recipe requires before verifying.
	targetDir := filepath.Join(root, "target")
	cargo := filepath.Join(root, "cargo.sh")
	cargoScript := "#!/usr/bin/env bash\n" +
		"if [[ \"${1:-}\" == \"+nightly-2026-05-23\" && \"${2:-}\" == \"--version\" ]]; then echo 'cargo 1.98.0'; exit 0; fi\n" +
		"mkdir -p \"${CARGO_TARGET_DIR}/bpfel-unknown-none/release\"\n" +
		"printf fake > \"${CARGO_TARGET_DIR}/bpfel-unknown-none/release/libxpf_userspace_xdp.so\"\n"
	if err := os.WriteFile(cargo, []byte(cargoScript), 0o755); err != nil {
		t.Fatal(err)
	}

	// Stand-in shimverify, planted by the go stub's `build -o` (base64
	// so no quoting layer can mangle it): it records its argv and
	// whether the --gate-verdict file exists at invocation time, then
	// exits 99 so the recipe fails the gate instead of installing a
	// stub-verified object.
	record := filepath.Join(root, "shimverify-record.txt")
	shimverifyStub := "#!/usr/bin/env bash\n" +
		"printf 'call:\\n' > " + strconv.Quote(record) + "\n" +
		"printf '%s\\n' \"$@\" >> " + strconv.Quote(record) + "\n" +
		"att=''; prev=''\n" +
		"for a in \"$@\"; do if [[ \"$prev\" == \"--gate-verdict\" ]]; then att=\"$a\"; fi; prev=\"$a\"; done\n" +
		"if [[ -n \"$att\" && -f \"$att\" ]]; then printf 'attestation-present %s\\n' \"$att\" >> " + strconv.Quote(record) + "\n" +
		"else printf 'attestation-absent %s\\n' \"${att:-unset}\" >> " + strconv.Quote(record) + "; fi\n" +
		"exit 99\n"
	goStub := filepath.Join(root, "go-stub.sh")
	stubB64 := base64.StdEncoding.EncodeToString([]byte(shimverifyStub))
	goScript := "#!/usr/bin/env bash\n" +
		"if [[ \"$*\" == *print-build-digest* ]]; then printf '%064d\\n' 0; exit 0; fi\n" +
		"if [[ \"${1:-}\" == build ]]; then out=''; prev=''; for a in \"$@\"; do if [[ \"$prev\" == -o ]]; then out=\"$a\"; fi; prev=\"$a\"; done; " +
		"printf '%s' " + strconv.Quote(stubB64) + " | base64 -d > \"$out\"; chmod +x \"$out\"; exit 0; fi\n" +
		"exit 1\n"
	if err := os.WriteFile(goStub, []byte(goScript), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", filepath.Join(repoRoot, "pkg", "dataplane", "build-userspace-xdp.sh"))
	cmd.Dir = repoRoot
	envMap := make(map[string]string)
	for _, item := range os.Environ() {
		key, value, ok := strings.Cut(item, "=")
		if ok {
			envMap[key] = value
		}
	}
	envMap["HOME"] = fakeHome
	envMap["CARGO"] = cargo
	envMap["CARGO_TARGET_DIR"] = targetDir
	envMap["GO"] = goStub
	envMap["RUSTUP"] = filepath.Join(root, "no-rustup")
	envMap["TMPDIR"] = attDir // the pre-sudo TMPDIR the attestation must honor
	cmd.Env = make([]string, 0, len(envMap))
	for key, value := range envMap {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	output, runErr := cmd.CombinedOutput()
	exitErr, ok := runErr.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("build script exit = %v, want the rc=99 gate-plumbing failure (exit 1):\n%s", runErr, output)
	}
	if !strings.Contains(string(output), "cannot run the BPF verifier gate") {
		t.Fatalf("build script did not fail in the expected rc=99 arm:\n%s", output)
	}

	recordBytes, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("stub shimverify never ran (mktemp arm did not reach the verifier): %v\n%s", err, output)
	}
	var attestation string
	for _, line := range strings.Split(string(recordBytes), "\n") {
		if after, found := strings.CutPrefix(line, "attestation-present "); found {
			attestation = after
		}
		if strings.HasPrefix(line, "attestation-absent ") {
			t.Fatalf("#18966: verifier invoked without an existing attestation file: %s\n%s", line, recordBytes)
		}
	}
	if attestation == "" {
		t.Fatalf("no attestation path recorded:\n%s", recordBytes)
	}
	if !strings.HasPrefix(filepath.Base(attestation), "shimverify-attestation.") {
		t.Errorf("#18966: attestation %q is not a shimverify-attestation mktemp (confused with the shimverify binary?)", attestation)
	}
	if rel, err := filepath.Rel(attDir, attestation); err != nil || rel == ".." || rel == "." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		t.Errorf("#18966: attestation %q is not inside the pre-sudo TMPDIR %q (rel=%v err=%v) — the hop scrubbed it back to /tmp", attestation, attDir, rel, err)
	}
	if _, err := os.Stat(attestation); !os.IsNotExist(err) {
		t.Errorf("#18966: attestation %q survived the recipe's EXIT trap (stat=%v)", attestation, err)
	}
	if entries, err := os.ReadDir(attDir); err != nil || len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("#18966: attestation TMPDIR %q not fully cleaned by the EXIT trap: %v (err=%v)", attDir, names, err)
	}
}
