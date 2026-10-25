package nftables

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestInstallerMethodsDocumented_17011 keeps the package README aligned with
// the exported Installer contract (#17011).
func TestInstallerMethodsDocumented_17011(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	readme, err := os.ReadFile(filepath.Join(root, "pkg", "nftables", "README.md"))
	if err != nil {
		t.Fatalf("read nftables README: %v", err)
	}

	text := string(readme)
	const startMarker = "### Host-inbound / lo0 / fence installer (#6387)"
	start := strings.Index(text, startMarker)
	if start < 0 {
		t.Fatalf("nftables README missing Installer section %q", startMarker)
	}
	rest := text[start+len(startMarker):]
	const endMarker = "\n### Capability probe"
	end := strings.Index(rest, endMarker)
	if end < 0 {
		t.Fatalf("nftables README Installer section missing boundary %q", endMarker)
	}
	section := text[start : start+len(startMarker)+end]

	installer := reflect.TypeOf((*Installer)(nil)).Elem()
	for i := range installer.NumMethod() {
		method := installer.Method(i).Name
		if !strings.Contains(section, "`"+method+"(") {
			t.Errorf("nftables README Installer section is missing method %s", method)
		}
	}
}
