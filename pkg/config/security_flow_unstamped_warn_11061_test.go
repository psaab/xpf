package config

import (
	"strings"
	"testing"
)

// #11061 R3: the rolling-upgrade compatibility knob must warn at every commit
// so it cannot silently persist past the upgrade window.
func TestAllowUnstampedFabricIngressWarnsBoundedWindow(t *testing.T) {
	tree := &ConfigTree{}
	path, err := ParseSetCommand("set security flow allow-unstamped-fabric-ingress")
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if !cfg.Security.Flow.AllowUnstampedFabricIngress {
		t.Fatal("expected the knob to compile true")
	}
	found := false
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "allow-unstamped-fabric-ingress") && strings.Contains(w, "11061") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a bounded-window #11061 warning; warnings=%v", ValidateConfig(cfg))
	}

	plain, err := CompileConfig(&ConfigTree{})
	if err != nil {
		t.Fatalf("CompileConfig(empty): %v", err)
	}
	for _, w := range ValidateConfig(plain) {
		if strings.Contains(w, "allow-unstamped-fabric-ingress") {
			t.Errorf("knob-off config must not warn; got %q", w)
		}
	}
}
