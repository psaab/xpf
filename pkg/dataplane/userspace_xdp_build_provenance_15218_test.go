package dataplane

import (
	"encoding/json"
	"os"
	"path/filepath"
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

// provenanceVerdict renders a schema-2 gate verdict over root's real
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
	v := map[string]any{
		"schema_version":    2,
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
			"codegen_env_digest": WellKnownCodegenEnvDigest(),
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
	if want := WellKnownCodegenEnvDigest(); v.Provenance.CodegenEnvDigest != want {
		t.Fatalf("#15218: committed verdict codegen_env_digest = %q, want scrubbed-env digest %q (object was built under an unscrubbed codegen env)", v.Provenance.CodegenEnvDigest, want)
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
		"env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS",
		"XPF_SHIM_TOOLCHAIN=",
		"XPF_SHIM_PINNED=",
		"XPF_SHIM_BPF_LINKER=",
		"XPF_SHIM_CODEGEN_ENV_DIGEST=",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("#15218: no executable line of build-userspace-xdp.sh contains %q; provenance is not scrubbed/recorded", want)
		}
	}
	if strings.Contains(string(data), "PR reproducibility gate") {
		t.Errorf("#15218: refusal text still cites the unimplemented 'PR reproducibility gate'; name the local freshness/retention gates instead")
	}
}
