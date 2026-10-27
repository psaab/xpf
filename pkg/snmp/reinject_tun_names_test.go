//go:build linux

package snmp

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestReinjectTUNNamesPinnedToRust pins the snmp reinjection-TUN literals
// to the Rust dataplane declarations they mirror: a dataplane rename that
// updates nftables but not this check would silently stop matching and
// restore the #17832 reply strand with no other red test.
func TestReinjectTUNNamesPinnedToRust(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "userspace-dp", "src", "afxdp", "mod.rs"))
	if err != nil {
		t.Fatalf("reading Rust slow-path TUN names: %v", err)
	}
	m := regexp.MustCompile(`const DEFAULT_SLOW_PATH_TUN:\s*&str\s*=\s*"([^"]+)"`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("DEFAULT_SLOW_PATH_TUN declaration not found in userspace-dp/src/afxdp/mod.rs")
	}
	if got, want := reinjectTUNUSP0, string(m[1]); got != want {
		t.Errorf("snmp reinjectTUNUSP0 %q != Rust DEFAULT_SLOW_PATH_TUN %q", got, want)
	}
	d := regexp.MustCompile(`pub\(crate\) const DELEGATED_SLOW_PATH_TUN:\s*&str\s*=\s*"([^"]+)"`).FindSubmatch(raw)
	if d == nil {
		t.Fatal("DELEGATED_SLOW_PATH_TUN declaration not found in userspace-dp/src/afxdp/mod.rs")
	}
	if got, want := reinjectTUNUSP1, string(d[1]); got != want {
		t.Errorf("snmp reinjectTUNUSP1 %q != Rust DELEGATED_SLOW_PATH_TUN %q", got, want)
	}
}
