package runtime

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRuntimePackageDoesNotImportBackendPackages enforces that the runtime
// package is backend-neutral.  It must not reference any concrete dataplane
// backend (userspace, dpdk), the root pkg/dataplane package (which contains
// BPF-shaped types and would cause an import cycle once pkg/dataplane imports
// pkg/dataplane/runtime), or the cilium/ebpf library.
func TestRuntimePackageDoesNotImportBackendPackages(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read runtime package: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(".", entry.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			checkForbiddenImport(t, entry.Name(), path)
		}
	}
}

// checkForbiddenImport fails the test if path is a forbidden backend import.
func checkForbiddenImport(t *testing.T, filename, path string) {
	t.Helper()

	// Backend sub-packages — never allowed.
	backendSubPkgs := []string{
		"github.com/psaab/xpf/pkg/dataplane/userspace",
		"github.com/psaab/xpf/pkg/dataplane/dpdk",
	}
	for _, forbidden := range backendSubPkgs {
		if path == forbidden || strings.HasPrefix(path, forbidden+"/") {
			t.Fatalf("runtime package imports forbidden backend sub-package in %s: %s", filename, path)
		}
	}

	// Root pkg/dataplane — importing it would cause a cycle once pkg/dataplane
	// imports pkg/dataplane/runtime, and it carries BPF-shaped types.
	const rootDP = "github.com/psaab/xpf/pkg/dataplane"
	if path == rootDP {
		t.Fatalf("runtime package imports root dataplane package in %s (would create import cycle)", filename)
	}

	// cilium/ebpf — BPF library; its presence in the runtime package would
	// break non-eBPF backends that import runtime.
	if path == "github.com/cilium/ebpf" || strings.HasPrefix(path, "github.com/cilium/ebpf/") {
		t.Fatalf("runtime package imports cilium/ebpf in %s: %s", filename, path)
	}
}
