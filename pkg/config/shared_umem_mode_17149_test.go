package config

// #17149 (R4-Q48-05): `system dataplane shared-umem mode` was an untyped
// Go string. A typo (`cross-nick`) committed clean, was copied verbatim
// into SharedUMEM.Mode, and Rust's parse_shared_umem_mode mapped it
// through `_ => Off` — silently disabling shared UMEM (private UMEM +
// copy path), the opposite of the absent-key CrossNic default. The leaf
// is now a typed ValueEnumOf over exactly the four spellings Rust
// accepts, and Rust's 11-spelling alias table is reduced to those four
// with an explicit log-once unknown arm.
//
// FAIL-ON-REVERT: dropping valueType/validator from the mode leaf makes
// the typo/alias cells RED (SchemaValidate accepts); widening the Go
// enum or re-adding a Rust alias makes the parity cell RED.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// sharedUMEMModeValues17149 is the single accepted vocabulary. Keep in
// step with parse_shared_umem_mode in
// userspace-dp/src/afxdp/shared_umem.rs — pinned by
// TestSharedUMEMModeSetMatchesRust17149 below.
var sharedUMEMModeValues17149 = []string{"auto", "cross-nic", "off", "same-device-debug"}

func TestSharedUMEMModeSchemaGate17149(t *testing.T) {
	for _, mode := range sharedUMEMModeValues17149 {
		tree := parseSetCommands(t, "set system dataplane shared-umem mode "+mode)
		if err := SchemaValidate(tree); err != nil {
			t.Errorf("SchemaValidate rejected valid mode %q: %v", mode, err)
			continue
		}
		cfg := compileTreeStrictKit(t, tree)
		if cfg.System.UserspaceDataplane == nil || cfg.System.UserspaceDataplane.SharedUMEM == nil {
			t.Fatalf("mode %q: SharedUMEM not compiled", mode)
		}
		if got := cfg.System.UserspaceDataplane.SharedUMEM.Mode; got != mode {
			t.Errorf("mode %q compiled as %q", mode, got)
		}
	}
	// Typos, case variants and every former Rust alias must now fail
	// commit instead of silently selecting Off in the helper.
	for _, mode := range []string{
		"cross-nick", "crossnic", "Cross-Nic", "bogus",
		"on", "enable", "enabled", "disable", "disabled",
		"cross_nic", "same_device_debug", "shared",
	} {
		tree := parseSetCommands(t, "set system dataplane shared-umem mode "+mode)
		err := SchemaValidate(tree)
		if err == nil {
			t.Errorf("SchemaValidate accepted invalid mode %q (#17149)", mode)
		} else if !strings.Contains(err.Error(), mode) {
			t.Errorf("SchemaValidate error for %q must name the value: %v", mode, err)
		}
	}
	// Hierarchical spelling takes the same gate.
	tree := parseHierText(t, `system { dataplane { shared-umem { mode cross-nick; } } }`)
	if err := SchemaValidate(tree); err == nil {
		t.Error("hierarchical mode cross-nick must be refused at commit (#17149)")
	}
}

// TestSharedUMEMModeSetMatchesRust17149 parses the accepted string
// literals out of Rust's parse_shared_umem_mode and asserts the set
// equals the Go enum, and that no silent `_ =>` fallback arm remains.
// If either vocabulary changes, this test reds and names the other side.
func TestSharedUMEMModeSetMatchesRust17149(t *testing.T) {
	path := filepath.Join("..", "..", "userspace-dp", "src", "afxdp", "shared_umem.rs")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read Rust shared_umem source %s: %v", path, err)
	}
	src := string(body)
	start := strings.Index(src, "fn parse_shared_umem_mode")
	if start < 0 {
		t.Fatal("parse_shared_umem_mode not found in Rust source")
	}
	fnSrc := src[start:]
	if end := strings.Index(fnSrc, "\n}\n"); end >= 0 {
		fnSrc = fnSrc[:end]
	}
	if strings.Contains(fnSrc, "_ =>") {
		t.Errorf("parse_shared_umem_mode still has a silent `_ =>` arm (#17149):\n%s", fnSrc)
	}
	armRE := regexp.MustCompile(`(?m)^\s*((?:"[^"]+"\s*(?:\|\s*)?)+)=>`)
	litRE := regexp.MustCompile(`"([^"]+)"`)
	seen := map[string]bool{}
	var got []string
	for _, arm := range armRE.FindAllStringSubmatch(fnSrc, -1) {
		for _, m := range litRE.FindAllStringSubmatch(arm[1], -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				got = append(got, m[1])
			}
		}
	}
	sort.Strings(got)
	want := append([]string(nil), sharedUMEMModeValues17149...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Rust parse_shared_umem_mode accepted set diverged from Go schema enum.\n got: %v\nwant: %v\n"+
			"Update pkg/config/schema_system.go (shared-umem mode ValidateEnum) and "+
			"userspace-dp/src/afxdp/shared_umem.rs together (#17149).", got, want)
	}
	node := refSystemDataplaneSharedUMEM.resolve()
	if node == nil || node.children["mode"] == nil {
		t.Fatal("shared-umem mode schema node not found")
	}
	modeNode := node.children["mode"]
	if modeNode.valueType != ValueEnumOf || modeNode.validator == nil {
		t.Fatalf("mode leaf must be typed ValueEnumOf with a validator, got valueType=%v validator=%v (#17149)", modeNode.valueType, modeNode.validator != nil)
	}
	for _, v := range want {
		if err := modeNode.validator(v); err != nil {
			t.Errorf("Go validator rejects Rust-accepted mode %q: %v", v, err)
		}
	}
	if err := modeNode.validator("cross-nick"); err == nil {
		t.Error("Go validator accepted typo cross-nick (#17149)")
	}
}
