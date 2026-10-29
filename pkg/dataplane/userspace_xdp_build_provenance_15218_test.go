package dataplane

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// #15218 (A31-01): build provenance must be recorded in the gate
// verdict and enforced by every gate that trusts it.
//
// Mechanism on origin/master: build-userspace-xdp.sh computes
// SHIM_BUILD_DIGEST only over file contents, then runs cargo with the
// ambient environment. An unpinned install
// (XPF_SHIM_ALLOW_UNPINNED_INSTALL=1) or a pinned build under ambient
// RUSTFLAGS / CARGO_ENCODED_RUSTFLAGS therefore installs a verdict
// labelled PASS that records neither the toolchain, the pinned bit,
// the bpf-linker version, nor any codegen-env digest — and the
// freshness gate (ComputeUserspaceXDPManifest) and the release
// retention gate (scripts/dist/retain_shim_verdict.py) accept it,
// because neither knows provenance exists. The refusal text also
// pointed at a "PR reproducibility gate" that no workflow implements.
//
// These tests pin the post-fix contract: the manifest adopts a
// verdict's build digest ONLY when the verdict carries provenance
// proving a pinned build under the scrubbed codegen env; the
// committed verdict itself carries that provenance; and the recipe
// scrubs the codegen env, records provenance through shimverify, and
// names the local consumer gates instead of the phantom CI gate.

// writeProvenanceFixture builds a minimal repo tree sufficient for
// ComputeUserspaceXDPManifest: freshness inputs and the tracked object
// are copied from the real tree (so ReadShimFactsFromObject succeeds),
// then the caller-supplied verdict builder writes the sidecar.
func writeProvenanceFixture(t *testing.T, buildVerdict func(root string) []byte) string {
	t.Helper()
	const repoRoot = "../.."
	root := t.TempDir()
	paths, err := userspaceXDPFreshnessInputPaths(repoRoot)
	if err != nil {
		t.Fatalf("enumerate freshness inputs: %v", err)
	}
	copyFromRepo := func(rel string) {
		b, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		dst := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, rel := range paths {
		copyFromRepo(rel)
	}
	copyFromRepo(userspaceXDPObjectRelPath)
	if buildVerdict != nil {
		dst := filepath.Join(root, filepath.FromSlash(UserspaceXDPGateVerdictRelPath))
		if err := os.WriteFile(dst, buildVerdict(root), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// provenanceVerdict renders a schema-3 gate verdict over root's real
// object/input hashes (a measured OVERRIDDEN verdict, like the
// committed one), with the given provenance mutation applied.
func provenanceVerdict(t *testing.T, root string, mutate func(map[string]any)) []byte {
	t.Helper()
	objHash, err := sha256File(filepath.Join(root, filepath.FromSlash(userspaceXDPObjectRelPath)))
	if err != nil {
		t.Fatalf("hash fixture object: %v", err)
	}
	paths, err := userspaceXDPFreshnessInputPaths(root)
	if err != nil {
		t.Fatalf("enumerate fixture inputs: %v", err)
	}
	entries, err := hashUserspaceXDPInputs(root, paths)
	if err != nil {
		t.Fatalf("hash fixture inputs: %v", err)
	}
	kernelRelease, err := KernelRelease()
	if err != nil {
		t.Fatalf("read running kernel for provenance fixture: %v", err)
	}
	v := map[string]any{
		"schema_version":    3,
		"verified_at":       "2026-10-19T00:00:00Z",
		"object_sha256":     objHash,
		"build_digest":      userspaceXDPBuildDigest(entries),
		"verdict":           "OVERRIDDEN",
		"override_consumed": true,
		"reason":            "measured headroom 12.70% is below the 15.0% floor; installed with XPF_SHIM_ALLOW_LOW_HEADROOM=1",
		"stats": map[string]any{
			"measured": true, "processed_insns": 873042, "insn_limit": 1000000,
			"headroom_pct": 12.6958, "floor_pct": 15.0, "slack_to_floor_insns": -23042,
		},
		"provenance": map[string]any{
			"toolchain":          "nightly-2026-05-23",
			"pinned":             true,
			"bpf_linker":         "0.10.2",
			"codegen_env_digest": mustWellKnownDigest(t, root),
			"kernel_release":     kernelRelease,
		},
	}
	if mutate != nil {
		mutate(v)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustWellKnownDigest(t *testing.T, root string) string {
	t.Helper()
	d, err := WellKnownCodegenEnvDigest(root)
	if err != nil {
		t.Fatalf("well-known digest: %v", err)
	}
	return d
}

func prov(m map[string]any) map[string]any { return m["provenance"].(map[string]any) }

// TestProvenanceAdoption15218 is the freshness half of the gate: the
// manifest adopts a verdict's build digest (the object counts as
// verifier-gated) ONLY for pinned, scrubbed-env provenance.
func TestProvenanceAdoption15218(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		adopt  bool
	}{
		{name: "pinned scrubbed provenance adopted", adopt: true},
		{name: "schema 1 verdict without provenance rejected", mutate: func(v map[string]any) {
			v["schema_version"] = 1
			delete(v, "provenance")
		}},
		{name: "unpinned toolchain rejected", mutate: func(v map[string]any) {
			prov(v)["pinned"] = false
			prov(v)["toolchain"] = "nightly-2026-05-27"
		}},
		{name: "empty codegen env digest rejected", mutate: func(v map[string]any) {
			prov(v)["codegen_env_digest"] = ""
		}},
		{name: "foreign codegen env digest rejected", mutate: func(v map[string]any) {
			prov(v)["codegen_env_digest"] = strings.Repeat("0", 64)
		}},
		{name: "wrong bpf-linker rejected", mutate: func(v map[string]any) {
			prov(v)["bpf_linker"] = "0.9.0"
		}},
		{name: "provenance toolchain disagreeing with pin rejected", mutate: func(v map[string]any) {
			prov(v)["toolchain"] = "nightly-2026-05-27"
		}},
		{name: "missing kernel release rejected (#16701)", mutate: func(v map[string]any) {
			delete(prov(v), "kernel_release")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := writeProvenanceFixture(t, func(r string) []byte {
				return provenanceVerdict(t, r, tc.mutate)
			})
			m, err := ComputeUserspaceXDPManifest(root)
			if err != nil {
				t.Fatalf("compute manifest: %v", err)
			}
			if tc.adopt && m.BuildDigest == "" {
				t.Fatalf("#15218: pinned scrubbed verdict was not adopted (build_digest empty)")
			}
			if !tc.adopt && m.BuildDigest != "" {
				t.Fatalf("#15218: verdict with defective provenance was adopted (build_digest=%q); an unpinned or codegen-drifted install must read as stale", m.BuildDigest)
			}
		})
	}
}

// TestManifestFreshnessIgnoresVerifierKernel17768 keeps the manifest's
// source/object freshness contract independent of the kernel that will
// later load the shim. Release retention separately compares measured
// verdicts with its running kernel before accepting them.
func TestManifestFreshnessIgnoresVerifierKernel17768(t *testing.T) {
	runningKernel, err := KernelRelease()
	if err != nil {
		t.Fatalf("read running kernel: %v", err)
	}
	root := writeProvenanceFixture(t, func(r string) []byte {
		return provenanceVerdict(t, r, func(v map[string]any) {
			prov(v)["kernel_release"] = runningKernel + "-different"
		})
	})
	manifest, err := ComputeUserspaceXDPManifest(root)
	if err != nil {
		t.Fatalf("compute manifest: %v", err)
	}
	if manifest.BuildDigest == "" {
		t.Fatal("source/object freshness withheld build digest for a verdict measured on a different kernel")
	}
}

// TestCommittedVerdictCarriesProvenance15218 pins the SHIPPED record:
// the committed gate verdict must prove the tracked object was built
// with the pinned toolchain, the pinned bpf-linker and the scrubbed
// codegen env. On origin/master the verdict has no provenance block
// at all, so this fails pre-fix.
func TestCommittedVerdictCarriesProvenance15218(t *testing.T) {
	raw, err := os.ReadFile("userspace_xdp_gate_verdict.json")
	if err != nil {
		t.Fatalf("read gate verdict: %v", err)
	}
	var v struct {
		Provenance *struct {
			Toolchain        string `json:"toolchain"`
			Pinned           bool   `json:"pinned"`
			BPFLinker        string `json:"bpf_linker"`
			CodegenEnvDigest string `json:"codegen_env_digest"`
			KernelRelease    string `json:"kernel_release"`
		} `json:"provenance"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse gate verdict: %v", err)
	}
	if v.Provenance == nil {
		t.Fatalf("#15218: committed gate verdict records no build provenance; an unpinned or RUSTFLAGS build is indistinguishable from a pinned PASS")
	}
	pin, err := pinnedShimToolchain("../../userspace-xdp/rust-toolchain.toml")
	if err != nil {
		t.Fatalf("read toolchain pin: %v", err)
	}
	if !v.Provenance.Pinned || v.Provenance.Toolchain != pin {
		t.Fatalf("#15218: committed verdict provenance = toolchain %q pinned=%v, want pinned %q", v.Provenance.Toolchain, v.Provenance.Pinned, pin)
	}
	if v.Provenance.BPFLinker != ShimPinnedBPFLinkerVersion {
		t.Fatalf("#15218: committed verdict bpf_linker = %q, want pin %q", v.Provenance.BPFLinker, ShimPinnedBPFLinkerVersion)
	}
	want, err := WellKnownCodegenEnvDigest("../..")
	if err != nil {
		t.Fatalf("well-known digest: %v", err)
	}
	if v.Provenance.CodegenEnvDigest != want {
		t.Fatalf("#15218: committed verdict codegen_env_digest = %q, want scrubbed-env digest %q (object was built under an unscrubbed codegen env)", v.Provenance.CodegenEnvDigest, want)
	}
	if v.Provenance.KernelRelease == "" {
		t.Fatalf("#16701: committed verdict records no kernel_release; the headroom measurement names no kernel")
	}
}

// #16701: the kernel helper the verdict provenance and the guest
// pre-flight share must return the running kernel, never "".
func TestKernelReleaseNonEmpty16701(t *testing.T) {
	k, err := KernelRelease()
	if err != nil {
		t.Fatalf("KernelRelease: %v", err)
	}
	if k == "" || strings.ContainsAny(k, "\x00\n") {
		t.Fatalf("KernelRelease = %q, want a clean uname -r", k)
	}
}

// TestBuildRecipeRecordsProvenance15218 pins the recipe half: the
// executable lines of build-userspace-xdp.sh must scrub the codegen
// env before cargo, thread provenance into shimverify, and the
// unpinned refusal must name gates that exist.
func TestBuildRecipeRecordsProvenance15218(t *testing.T) {
	data, err := os.ReadFile("build-userspace-xdp.sh")
	if err != nil {
		t.Fatalf("read build-userspace-xdp.sh: %v", err)
	}
	code := shellCodeLines(string(data))
	joined := "\n" + strings.Join(code, "\n") + "\n"
	for _, want := range []string{
		"env -i",
		"\"CARGO_HOME=${SCRUBBED_CARGO_HOME}\"",
		"XPF_SHIM_TOOLCHAIN=",
		"XPF_SHIM_PINNED=",
		"XPF_SHIM_BPF_LINKER=",
		"XPF_SHIM_CODEGEN_ENV_DIGEST=",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("#15218/#16657: no executable line of build-userspace-xdp.sh contains %q; provenance is not scrubbed/recorded", want)
		}
	}
	if strings.Contains(string(data), "PR reproducibility gate") {
		t.Errorf("#15218: refusal text still cites the unimplemented 'PR reproducibility gate'; name the local freshness/retention gates instead")
	}
}

// TestBuildRecipeScrubsCargoEnv16657 is the stand-in-cargo probe for
// #16657: run the real recipe with a fake cargo and a fully tainted
// ambient environment; the environment/argv the build cargo receives
// must contain none of the listed overrides, a recipe-owned fresh
// CARGO_HOME, and the forced --config profile/linker values. The
// recipe then fails at the verifier gate (fake object / stub gate),
// which is expected — the probe asserts only what cargo saw.
func TestBuildRecipeScrubsCargoEnv16657(t *testing.T) {
	if _, err := os.Stat("/home/ps/.cargo/bin/bpf-linker"); err != nil {
		t.Skip("bpf-linker not installed on this host")
	}
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	fakeCargo := filepath.Join(dir, "fake-cargo.sh")
	envOut := filepath.Join(dir, "env.txt")
	argvOut := filepath.Join(dir, "argv.txt")
	script := "#!/usr/bin/env bash\n" +
		"env | sort >> \"" + envOut + "\"; echo ===CALL=== >> \"" + envOut + "\"\n" +
		"printf '%s\\n' \"$@\" >> \"" + argvOut + "\"; echo ===CALL=== >> \"" + argvOut + "\"\n" +
		"if [[ \"${1:-}\" == \"+nightly-2026-05-23\" && \"${2:-}\" == \"--version\" ]]; then echo \"cargo 1.98.0\"; exit 0; fi\n" +
		"TD=$(grep '^CARGO_TARGET_DIR=' \"" + envOut + "\" | tail -1 | cut -d= -f2-)\n" +
		"mkdir -p \"${TD}/bpfel-unknown-none/release\"\n" +
		"printf fake > \"${TD}/bpfel-unknown-none/release/libxpf_userspace_xdp.so\"\n"
	if err := os.WriteFile(fakeCargo, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	goStub := filepath.Join(dir, "go-stub.sh")
	goScript := "#!/usr/bin/env bash\n" +
		"if [[ \"$*\" == *print-build-digest* ]]; then echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; exit 0; fi\n" +
		"if [[ \"${1:-}\" == build ]]; then out=\"\"; prev=\"\"; for a in \"$@\"; do if [[ \"$prev\" == -o ]]; then out=\"$a\"; fi; prev=\"$a\"; done; printf '#!/usr/bin/env bash\\nexit 99\\n' > \"$out\"; chmod +x \"$out\"; exit 0; fi\n" +
		"exit 1\n"
	if err := os.WriteFile(goStub, []byte(goScript), 0o755); err != nil {
		t.Fatal(err)
	}
	targetDir := filepath.Join(dir, "target")
	cmd := exec.Command("bash", filepath.Join(repoRoot, "pkg/dataplane/build-userspace-xdp.sh"))
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"CARGO="+fakeCargo, "GO="+goStub, "CARGO_TARGET_DIR="+targetDir,
		"RUSTFLAGS=-C evil", "CARGO_ENCODED_RUSTFLAGS=evil",
		"CARGO_PROFILE_RELEASE_OPT_LEVEL=1", "CARGO_PROFILE_RELEASE_LTO=off",
		"CARGO_PROFILE_RELEASE_DEBUG=true", "CARGO_PROFILE_RELEASE_INCREMENTAL=true",
		"CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER=/tmp/evil-linker",
		"CARGO_TARGET_BPFEL_UNKNOWN_NONE_RUSTFLAGS=-C evil",
		"CARGO_BUILD_RUSTFLAGS=-C evil", "CARGO_BUILD_RUSTC=/tmp/evil-rustc",
		"CARGO_BUILD_RUSTC_WRAPPER=/tmp/evil", "CARGO_BUILD_TARGET_DIR=/tmp/evil-target",
		"RUSTC=/tmp/evil-rustc", "RUSTC_WRAPPER=/tmp/evil-wrapper",
		"RUSTC_WORKSPACE_WRAPPER=/tmp/evil", "RUSTDOCFLAGS=-C evil",
		"CARGO_HOME=/tmp/evil-home", "CARGO_INCREMENTAL=1",
	)
	_ = cmd.Run() // verifier gate must fail on the fake object; cargo env is the assertion
	envBytes, err := os.ReadFile(envOut)
	if err != nil {
		t.Fatalf("fake cargo never ran: %v", err)
	}
	calls := strings.Split(string(envBytes), "===CALL===\n")
	if len(calls) < 2 {
		t.Fatalf("expected at least the build cargo call, got %d calls", len(calls)-1)
	}
	buildEnv := calls[len(calls)-2]
	for _, bad := range []string{"evil", "CARGO_PROFILE_RELEASE", "CARGO_BUILD_", "CARGO_ENCODED_RUSTFLAGS=evil", "CARGO_INCREMENTAL", "RUSTC=", "RUSTC_WRAPPER", "RUSTDOCFLAGS", "RUSTFLAGS=-C"} {
		if strings.Contains(buildEnv, bad) {
			t.Errorf("#16657: tainted %q reached cargo build env:\n%s", bad, buildEnv)
		}
	}
	var cargoHome string
	for _, line := range strings.Split(buildEnv, "\n") {
		if strings.HasPrefix(line, "CARGO_HOME=") {
			cargoHome = strings.TrimPrefix(line, "CARGO_HOME=")
			break
		}
	}
	if !strings.HasPrefix(filepath.Base(cargoHome), "xpf-cargo-home.") ||
		strings.Contains(buildEnv, "CARGO_HOME=/tmp/evil-home") {
		t.Errorf("#16657: cargo build CARGO_HOME is not a fresh recipe-owned temp dir:\n%s", buildEnv)
	}
	if !strings.Contains(buildEnv, "RUSTUP_TOOLCHAIN=nightly-2026-05-23") {
		t.Errorf("#16657: cargo build missing pinned RUSTUP_TOOLCHAIN:\n%s", buildEnv)
	}
	argvBytes, err := os.ReadFile(argvOut)
	if err != nil {
		t.Fatal(err)
	}
	argv := string(argvBytes)
	for _, want := range []string{"profile.release.opt-level=3", "profile.release.lto=false", "target.bpfel-unknown-none.linker"} {
		if !strings.Contains(argv, want) {
			t.Errorf("#16657: cargo argv missing forced --config %q:\n%s", want, argv)
		}
	}
	// Digest of the actual build env (allowlisted keys, sorted) must
	// equal the well-known digest the consumer gates recompute.
	var pairs []string
	for _, line := range strings.Split(strings.TrimSpace(buildEnv), "\n") {
		k, _, _ := strings.Cut(line, "=")
		switch k {
		case "CARGO_HOME":
			pairs = append(pairs, "CARGO_HOME=<repo-controlled-empty>")
		case "CARGO_TARGET_DIR", "HOME", "PATH", "PWD", "RUSTUP_HOME", "SHLVL", "TERM", "_":
			// allowlisted plumbing, not codegen env
		default:
			pairs = append(pairs, line)
		}
	}
	// Reconstruct the canonical stream: every digest key empty except
	// MAX_INTERFACES / RUSTUP_TOOLCHAIN taken from the actual env.
	get := func(k string) string {
		for _, line := range strings.Split(buildEnv, "\n") {
			if strings.HasPrefix(line, k+"=") {
				return strings.TrimPrefix(line, k+"=")
			}
		}
		return ""
	}
	_ = pairs
	if got, want := ShimCodegenEnvDigest(get("MAX_INTERFACES"), get("RUSTUP_TOOLCHAIN")), func() string {
		d, e := WellKnownCodegenEnvDigest(repoRoot)
		if e != nil {
			t.Fatal(e)
		}
		return d
	}(); got != want {
		t.Errorf("#16657: digest of actual cargo env = %q, want well-known %q", got, want)
	}
}

// TestScrubDigestMatchesRecipe16657 pins the three implementations of
// the canonical stream (recipe printf, Go, Python) to the same value
// for the committed pin/header, and that WellKnown rejects the old
// #15218 constant.
func TestScrubDigestMatchesRecipe16657(t *testing.T) {
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	want, err := WellKnownCodegenEnvDigest(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("build-userspace-xdp.sh")
	if err != nil {
		t.Fatal(err)
	}
	code := strings.Join(shellCodeLines(string(data)), "\n")
	for _, frag := range []string{"CARGO_PROFILE_RELEASE_OPT_LEVEL=", "CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER=", "RUSTC_WORKSPACE_WRAPPER=", "RUSTUP_TOOLCHAIN=%s"} {
		if !strings.Contains(code, frag) {
			t.Errorf("#16657: recipe digest stream missing %q", frag)
		}
	}
	if want == "44d8a70acf9e98d41330740d3d7dccb0644235d84bcbc227c4845f44f61549b9" {
		t.Errorf("#16657: well-known digest still equals the #15218 two-variable constant")
	}
	// Old digest must be rejected by both consumer gates' predicate.
	root := writeProvenanceFixture(t, func(r string) []byte {
		return provenanceVerdict(t, r, func(v map[string]any) {
			prov(v)["codegen_env_digest"] = "44d8a70acf9e98d41330740d3d7dccb0644235d84bcbc227c4845f44f61549b9"
		})
	})
	m, err := ComputeUserspaceXDPManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if m.BuildDigest != "" {
		t.Errorf("#16657: freshness gate adopted the old #15218 digest")
	}
}

// TestCargoAncestorConfigIsolation17729 exercises Cargo itself rather
// than a stand-in: a wrapper and rustflags in a checkout ancestor take
// effect from the crate cwd, but not from an isolated cwd with
// --manifest-path (the recipe's #17729 invocation shape).
func TestCargoAncestorConfigIsolation17729(t *testing.T) {
	cargo, err := exec.LookPath("cargo")
	if err != nil {
		t.Skip("cargo is not installed")
	}
	root := t.TempDir()
	ancestor := filepath.Join(root, "checkout-parent")
	crate := filepath.Join(ancestor, "checkout", "userspace-xdp")
	if err := os.MkdirAll(filepath.Join(crate, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(root, "rustc-wrapper.sh")
	marker := filepath.Join(root, "wrapper-invoked")
	wrapperScript := "#!/usr/bin/env bash\nprintf invoked >> \"$XPF_TEST_WRAPPER_MARKER\"\nexec \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(wrapperScript), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ancestor, ".cargo"), 0o755); err != nil {
		t.Fatal(err)
	}
	config := "[build]\nrustc-wrapper = " + strconv.Quote(wrapper) +
		"\nrustflags = [\"--cfg=ancestor_cargo_config_marker\"]\n"
	if err := os.WriteFile(filepath.Join(ancestor, ".cargo", "config.toml"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crate, "Cargo.toml"), []byte("[package]\nname = \"ancestor-config-probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crate, "src", "lib.rs"), []byte("pub fn probe() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cargoHome := filepath.Join(root, "cargo-home")
	if err := os.Mkdir(cargoHome, 0o755); err != nil {
		t.Fatal(err)
	}
	makeEnv := func(target string) []string {
		envMap := make(map[string]string)
		for _, item := range os.Environ() {
			key, value, ok := strings.Cut(item, "=")
			if ok {
				envMap[key] = value
			}
		}
		for _, key := range []string{
			"CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTFLAGS",
			"CARGO_ENCODED_RUSTFLAGS", "CARGO_HOME", "CARGO_TARGET_DIR",
			"RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS",
		} {
			delete(envMap, key)
		}
		envMap["CARGO_HOME"] = cargoHome
		envMap["CARGO_TARGET_DIR"] = target
		envMap["XPF_TEST_WRAPPER_MARKER"] = marker
		env := make([]string, 0, len(envMap))
		for key, value := range envMap {
			env = append(env, key+"="+value)
		}
		return env
	}
	run := func(name, cwd string, args ...string) string {
		t.Helper()
		cmd := exec.Command(cargo, args...)
		cmd.Dir = cwd
		cmd.Env = makeEnv(filepath.Join(root, "target-"+name))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("cargo %s failed: %v\n%s", name, err, out)
		}
		return string(out)
	}

	// Control arm: the same ancestor wrapper and flags do apply when Cargo
	// starts in the checkout crate, proving the fixture is effective.
	control := run("control", crate, "build", "--offline", "-vv")
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("ancestor config wrapper did not run in the control arm: %v\n%s", err, control)
	}
	if !strings.Contains(control, "ancestor_cargo_config_marker") {
		t.Fatalf("ancestor rustflags did not reach rustc in the control arm:\n%s", control)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}

	isolated := filepath.Join(root, "isolated-cargo-cwd")
	if err := os.Mkdir(isolated, 0o755); err != nil {
		t.Fatal(err)
	}
	// Treatment arm: this is the production cwd/manifest arrangement.
	treatment := run("isolated", isolated, "build", "--offline", "-vv", "--manifest-path", filepath.Join(crate, "Cargo.toml"))
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("ancestor config wrapper took effect from isolated cwd (stat=%v):\n%s", err, treatment)
	}
	if strings.Contains(treatment, "ancestor_cargo_config_marker") {
		t.Fatalf("ancestor rustflags reached rustc from isolated cwd:\n%s", treatment)
	}
}

// TestBuildRecipeAncestorConfigAndCleanup17729 drives the real build
// script with a stand-in Cargo that fails. An ancestor config above the
// fixture checkout would affect the former crate-cwd invocation; the
// recipe must instead pass an isolated cwd + manifest path, and its
// EXIT trap must remove both fresh directories while preserving Cargo's
// failure status.
func TestBuildRecipeAncestorConfigAndCleanup17729(t *testing.T) {
	sourceRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	fakeHome := filepath.Join(root, "home")
	fakeLinker := filepath.Join(fakeHome, ".cargo", "bin", "bpf-linker")
	if err := os.MkdirAll(filepath.Dir(fakeLinker), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fakeLinker, []byte("#!/usr/bin/env bash\necho 'bpf-linker 0.10.2'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "fixture-parent")
	repoRoot := filepath.Join(parent, "checkout")
	crateDir := filepath.Join(repoRoot, "userspace-xdp")
	for _, dir := range []string{
		filepath.Join(repoRoot, "pkg", "dataplane"),
		filepath.Join(repoRoot, "bpf", "headers"),
		filepath.Join(crateDir, ".cargo"),
		filepath.Join(crateDir, "src"),
		filepath.Join(parent, ".cargo"),
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
	if err := os.WriteFile(filepath.Join(crateDir, "Cargo.toml"), []byte("[package]\nname = \"recipe-config-probe\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	wrapperMarker := filepath.Join(root, "ancestor-wrapper-invoked")
	wrapper := filepath.Join(parent, "wrapper.sh")
	wrapperScript := "#!/usr/bin/env bash\nprintf invoked >> " + strconv.Quote(wrapperMarker) + "\nexec \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(wrapperScript), 0o755); err != nil {
		t.Fatal(err)
	}
	ancestorConfig := "[build]\nrustc-wrapper = " + strconv.Quote(wrapper) +
		"\nrustflags = [\"--cfg=ancestor_cargo_config_marker\"]\n" +
		"[target.bpfel-unknown-none]\nrustflags = [\"--cfg=ancestor_target_config_marker\"]\n"
	if err := os.WriteFile(filepath.Join(parent, ".cargo", "config.toml"), []byte(ancestorConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	if rel, err := filepath.Rel(parent, crateDir); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		t.Fatalf("test ancestor config is not an ancestor of the original crate cwd: rel=%q err=%v", rel, err)
	}

	record := filepath.Join(root, "cargo-record.txt")
	cargo := filepath.Join(root, "cargo-fails.sh")
	cargoScript := "#!/usr/bin/env bash\n" +
		"if [[ \"${1:-}\" == \"+nightly-2026-05-23\" && \"${2:-}\" == \"--version\" ]]; then echo 'cargo test stub'; exit 0; fi\n" +
		"{ printf 'cwd=%s\\n' \"$PWD\"; printf 'home=%s\\n' \"$CARGO_HOME\"; printf 'arg=%s\\n' \"$@\"; } > " + strconv.Quote(record) + "\n" +
		"exit 23\n"
	if err := os.WriteFile(cargo, []byte(cargoScript), 0o755); err != nil {
		t.Fatal(err)
	}
	goStub := filepath.Join(root, "go-stub.sh")
	if err := os.WriteFile(goStub, []byte("#!/usr/bin/env bash\nprintf '%064d\\n' 0\n"), 0o755); err != nil {
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
	envMap["CARGO_TARGET_DIR"] = filepath.Join(root, "target")
	envMap["GO"] = goStub
	envMap["RUSTUP"] = filepath.Join(root, "no-rustup")
	cmd.Env = make([]string, 0, len(envMap))
	for key, value := range envMap {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	output, runErr := cmd.CombinedOutput()
	exitErr, ok := runErr.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 23 {
		t.Fatalf("build script exit = %v, want Cargo's status 23:\n%s", runErr, output)
	}
	if _, err := os.Stat(wrapperMarker); !os.IsNotExist(err) {
		t.Fatalf("ancestor rustc-wrapper took effect: stat=%v", err)
	}
	recordBytes, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("fake cargo did not receive the build invocation: %v\n%s", err, output)
	}
	var cwd, cargoHome string
	var args []string
	for _, line := range strings.Split(strings.TrimSpace(string(recordBytes)), "\n") {
		switch {
		case strings.HasPrefix(line, "cwd="):
			cwd = strings.TrimPrefix(line, "cwd=")
		case strings.HasPrefix(line, "home="):
			cargoHome = strings.TrimPrefix(line, "home=")
		case strings.HasPrefix(line, "arg="):
			args = append(args, strings.TrimPrefix(line, "arg="))
		}
	}
	defer func() {
		for _, temp := range []struct {
			path   string
			prefix string
		}{{cargoHome, "xpf-cargo-home."}, {cwd, "xpf-cargo-cwd."}} {
			if temp.path != "" && strings.HasPrefix(filepath.Base(temp.path), temp.prefix) {
				_ = os.RemoveAll(temp.path)
			}
		}
	}()
	if rel, err := filepath.Rel(parent, cwd); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		t.Errorf("Cargo cwd %q is still below ancestor config %q", cwd, parent)
	}
	if !containsString(args, "--manifest-path") || !containsString(args, filepath.Join(crateDir, "Cargo.toml")) {
		t.Errorf("Cargo argv lacks manifest-path for the fixture crate: %q", args)
	}
	for _, want := range []string{
		`build.target="bpfel-unknown-none"`,
		`unstable.build-std=["core"]`,
		`target.bpfel-unknown-none.linker="bpf-linker"`,
	} {
		if !containsString(args, want) {
			t.Errorf("Cargo argv lacks crate-local config override %q: %q", want, args)
		}
	}
	for _, path := range []string{cargoHome, cwd} {
		if path == "" {
			t.Errorf("fake cargo recorded an empty temporary path")
			continue
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("temporary build path %q survived failed Cargo invocation (stat=%v)", path, err)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
