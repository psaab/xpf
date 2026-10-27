package ipsec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #17051: the pkg/ipsec and pkg/networkd READMEs misstated file layout,
// dependencies and the reload command, and pkg/ipsec still documented the
// DNS family hint #14590 removed. This guard pins the corrected contract.
//
// FAIL-ON-REVERT: restoring any stale string below, dropping a production
// file from the Module layout, or re-attributing PrepareConfig /
// matchFamily / HasDHCPBoundGateway to policy.go fails this test.
func TestReadmeLayout17051(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(b)
	}
	ipsecREADME := read("pkg/ipsec/README.md")
	networkdREADME := read("pkg/networkd/README.md")
	generation := read("pkg/ipsec/generation.go")

	stale := []string{
		"swanctl --reload",
		"`pkg/config` only",
		"Standard library only",
		"DNS-derived",
		"through DNS",
	}
	for name, text := range map[string]string{
		"pkg/ipsec/README.md":     ipsecREADME,
		"pkg/networkd/README.md":  networkdREADME,
		"pkg/ipsec/generation.go": generation,
	} {
		for _, bad := range stale {
			if strings.Contains(text, bad) {
				t.Errorf("#17051: %s still contains stale claim %q", name, bad)
			}
		}
	}

	// Every non-test .go file in pkg/ipsec must be named in the Module
	// layout section.
	const startMarker = "## Module layout"
	start := strings.Index(ipsecREADME, startMarker)
	if start < 0 {
		t.Fatalf("ipsec README missing %q section", startMarker)
	}
	rest := ipsecREADME[start+len(startMarker):]
	end := strings.Index(rest, "\n## ")
	if end < 0 {
		t.Fatalf("ipsec README Module layout section has no following section")
	}
	layout := rest[:end]
	entries, err := os.ReadDir(filepath.Join(root, "pkg", "ipsec"))
	if err != nil {
		t.Fatalf("list pkg/ipsec: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if !strings.Contains(layout, "`"+name+"`") {
			t.Errorf("#17051: ipsec README Module layout does not name %s", name)
		}
	}

	// The address resolver moved to policy_addr.go (#6439).
	for _, want := range []string{
		"`PrepareConfig(cfg *config.Config) *config.IPsecConfig` — `policy_addr.go`",
		"`matchFamily` (`policy_addr.go`)",
		"(`HasDHCPBoundGateway`, `policy_addr.go`)",
	} {
		if !strings.Contains(ipsecREADME, want) {
			t.Errorf("#17051: ipsec README missing corrected attribution %q", want)
		}
	}

	// Dependencies must name the go list internal sets.
	for _, want := range []string{
		"`config`, `configstore`, `fsatomic`, `ipsecname`, `rendersafe`, `termsafe`",
		"Reloads via `swanctl --load-all`",
	} {
		if !strings.Contains(ipsecREADME, want) {
			t.Errorf("#17051: ipsec README missing %q", want)
		}
	}
	if !strings.Contains(networkdREADME, "`config`, `fsatomic`, `rendersafe`") {
		t.Errorf("#17051: networkd README missing corrected dependencies")
	}
}
