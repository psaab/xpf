//go:build ignore

// Command gen_bins renders bins.txt from the SSOT in manifest.go
// (#17101). It runs only via `go generate ./pkg/upgrade/manifest/` and
// is never built into any binary. It deliberately duplicates the
// managed list: a generator in package manifest cannot import itself,
// so this copy is pinned directly to manifest.Names() by
// TestManagedBinaryDriftCanary, which extracts the literal below and
// compares it against Names() in order — a divergence here reds the
// canary at introduction, without regenerating bins.txt.
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	names := []string{"xpfd", "cli", "xpf-userspace-dp", "xpf-day0-config"}
	content := "# Managed upgrade binaries, space-separated, in manifest order.\n" +
		"# Source of truth: pkg/upgrade/manifest/manifest.go (manifest.Names).\n" +
		"# Regenerate: go generate ./pkg/upgrade/manifest/\n" +
		"# Consumers that cannot import Go (scripts/image/seed_layout_10771.py,\n" +
		"# scripts/image/test_seed_layout_10771.py) read this file instead of\n" +
		"# retyping the list (#17101). TestManagedBinaryDriftCanary pins it.\n" +
		strings.Join(names, " ") + "\n"
	if err := os.WriteFile("bins.txt", []byte(content), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
