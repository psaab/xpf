package config_test

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestStableRethLinkLocalByteCompatibility17049 pins the fe80::bf72:CC:RR
// bytes for the single config definition (#17049); cluster delegates to it.
func TestStableRethLinkLocalByteCompatibility17049(t *testing.T) {
	if got := config.StableRethLinkLocal(1, 1).String(); got != "fe80::bf72:1:1" {
		t.Fatalf("StableRethLinkLocal(1,1) = %q, want fe80::bf72:1:1", got)
	}
	if got := config.StableRethLinkLocal(7, 2).String(); got != "fe80::bf72:7:2" {
		t.Fatalf("StableRethLinkLocal(7,2) = %q, want fe80::bf72:7:2", got)
	}
	if !config.IsStableRethLinkLocal(config.StableRethLinkLocal(1, 1)) {
		t.Fatal("IsStableRethLinkLocal must recognise the stable LL")
	}
}
