package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #16701: the gate verdict must name the kernel its processed-insn
// count was measured on. Before the fix the provenance was
// {toolchain, pinned, bpf_linker, codegen_env_digest} at schema 2 —
// the recorded 14.34% headroom therefore silently meant "on the
// build host (7.2.8)", while guest kernels charged +3.8-6.1% more
// (#15645, #15854). These tests run the real run path with an
// injected kernel release and pin: schema 3, the recorded release,
// the banner's kernel, and a fail-closed write when uname fails.
func verdictEnv(t *testing.T, override string) func(string) string {
	t.Helper()
	return func(key string) string {
		switch key {
		case "XPF_SHIM_BUILD_DIGEST":
			return strings.Repeat("a", 64)
		case "XPF_SHIM_TOOLCHAIN":
			return "nightly-2026-05-23"
		case "XPF_SHIM_PINNED":
			return "1"
		case "XPF_SHIM_BPF_LINKER":
			return "0.10.2"
		case "XPF_SHIM_CODEGEN_ENV_DIGEST":
			return dataplane.ShimCodegenEnvDigest("65536", "nightly-2026-05-23")
		case allowLowHeadroomEnv:
			return override
		}
		return ""
	}
}

func TestShimverifyVerdictNamesKernel16701(t *testing.T) {
	dir := t.TempDir()
	objectPath := filepath.Join(dir, "candidate.o")
	if err := os.WriteFile(objectPath, []byte("candidate object"), 0o600); err != nil {
		t.Fatal(err)
	}
	verdictPath := filepath.Join(dir, "gate-verdict.json")
	var stdout, stderr bytes.Buffer
	got := runWithKernel(
		[]string{"shimverify", objectPath, "--gate-verdict", verdictPath},
		&stdout, &stderr,
		verdictEnv(t, ""),
		func(string) (dataplane.ShimVerifierStats, error) {
			return dataplane.ShimVerifierStats{ProcessedInsns: 800000, InsnLimit: 1000000}, nil
		},
		func() (string, error) { return "7.0.0-30-generic", nil },
	)
	if got != 0 {
		t.Fatalf("run exit = %d, want 0; stdout=%q stderr=%q", got, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "on kernel 7.0.0-30-generic") {
		t.Fatalf("banner %q does not name the measuring kernel", stdout.String())
	}
	raw, err := os.ReadFile(verdictPath)
	if err != nil {
		t.Fatalf("read verdict: %v", err)
	}
	var verdict gateVerdict
	if err := json.Unmarshal(raw, &verdict); err != nil {
		t.Fatalf("decode verdict: %v", err)
	}
	if verdict.SchemaVersion != 3 {
		t.Errorf("schema_version = %d, want 3 (schema 2 named no kernel)", verdict.SchemaVersion)
	}
	if verdict.Provenance.KernelRelease != "7.0.0-30-generic" {
		t.Errorf("provenance.kernel_release = %q, want 7.0.0-30-generic", verdict.Provenance.KernelRelease)
	}
}

func TestShimverifyVerdictFailsClosedWithoutKernel16701(t *testing.T) {
	dir := t.TempDir()
	objectPath := filepath.Join(dir, "candidate.o")
	if err := os.WriteFile(objectPath, []byte("candidate object"), 0o600); err != nil {
		t.Fatal(err)
	}
	verdictPath := filepath.Join(dir, "gate-verdict.json")
	var stdout, stderr bytes.Buffer
	got := runWithKernel(
		[]string{"shimverify", objectPath, "--gate-verdict", verdictPath},
		&stdout, &stderr,
		verdictEnv(t, ""),
		func(string) (dataplane.ShimVerifierStats, error) {
			return dataplane.ShimVerifierStats{ProcessedInsns: 800000, InsnLimit: 1000000}, nil
		},
		func() (string, error) { return "", fmt.Errorf("uname unavailable") },
	)
	if got != 1 {
		t.Fatalf("run exit = %d, want 1 (fail closed); stdout=%q stderr=%q", got, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(verdictPath); !os.IsNotExist(err) {
		t.Fatalf("verdict written without a kernel: stat err = %v", err)
	}
	if !strings.Contains(stderr.String(), "kernel") {
		t.Fatalf("stderr %q does not name the missing kernel provenance", stderr.String())
	}
}
