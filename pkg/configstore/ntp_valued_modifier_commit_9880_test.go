package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9880 end-to-end: the operator commit path (compileTreeStrict runs the
// schema gate BEFORE compile) must accept valid Junos NTP modifiers and
// reject garbage naming the leaf. The per-spelling matrix lives in
// pkg/config (ntp_valued_modifier_strict_9880_test.go); these cells
// prove the commit pipeline itself, not just the gate in isolation.

func ntpTree9880(t *testing.T, cmds ...string) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

func Test9880_StrictCommitAcceptsValuedModifiers(t *testing.T) {
	tree := ntpTree9880(t,
		"set system ntp server 1.1.1.1 key 5 version 4",
		"set system ntp server 1.1.1.1 routing-instance foo",
		"set system ntp server 1.1.1.1 prefer",
		"set system ntp threshold 400 action accept",
	)
	cfg, err := compileTreeStrict(tree, -1)
	if err != nil {
		t.Fatalf("strict commit rejected valid Junos NTP modifiers: %v", err)
	}
	// Non-vacuous: the committed values must be the authored ones, not a
	// gate that waves everything through to a dropping compiler. The
	// SERVER LIST is asserted first, not merely the modifier fields: a
	// modifier-only statement the gate admits but the compiler reads as
	// address-less yields zero servers, and modifier-field assertions
	// alone cannot see that hole.
	if len(cfg.System.NTPServers) != 1 || cfg.System.NTPServers[0] != "1.1.1.1" {
		t.Fatalf("committed NTP servers = %v, want [1.1.1.1]", cfg.System.NTPServers)
	}
	opt := cfg.System.NTPServerOptions["1.1.1.1"]
	if opt.Key != 5 || opt.Version != 4 || opt.RoutingInstance != "foo" || !opt.Prefer {
		t.Fatalf("committed NTP options = %+v, want {Prefer:true Key:5 Version:4 RoutingInstance:foo}", opt)
	}
	if cfg.System.NTPThreshold != 400 || cfg.System.NTPThresholdAction != "accept" {
		t.Fatalf("committed threshold = %d/%q, want 400/accept",
			cfg.System.NTPThreshold, cfg.System.NTPThresholdAction)
	}
}

func Test9880_StrictCommitRejectsModifierGarbage(t *testing.T) {
	for _, tc := range []struct{ cmd, leaf string }{
		{"set system ntp server 1.1.1.1 key notanint", "system ntp server"},
		{"set system ntp threshold 400 action frobnicate", "system ntp threshold"},
	} {
		_, err := compileTreeStrict(ntpTree9880(t, tc.cmd), -1)
		if err == nil {
			t.Errorf("%s: strict commit accepted garbage, want reject", tc.cmd)
			continue
		}
		if !strings.Contains(err.Error(), tc.leaf) {
			t.Errorf("%s: rejection must name the leaf (%q), got: %v", tc.cmd, tc.leaf, err)
		}
	}
}

// Test9880_StrictCommitRejectsAddresslessModifiers pins the review fold at
// the commit pipeline: a modifier-headed multi-token statement
// (`server prefer key 5`) reads as modifiers-with-no-address to the
// compiler and yields zero servers, so the strict commit must reject it —
// in the hierarchical packed spelling that reaches the multi-token rule
// as well as the flat-set spelling.
func Test9880_StrictCommitRejectsAddresslessModifiers(t *testing.T) {
	p := config.NewParser("system {\n ntp {\n server prefer key 5;\n}\n}")
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if _, err := compileTreeStrict(tree, -1); err == nil {
		t.Error("hierarchical `server prefer key 5`: strict commit accepted an address-less statement, want reject")
	} else if !strings.Contains(err.Error(), "system ntp server") {
		t.Errorf("hierarchical `server prefer key 5`: rejection must name the leaf, got: %v", err)
	}
	if _, err := compileTreeStrict(ntpTree9880(t, "set system ntp server prefer key 5"), -1); err == nil {
		t.Error("flat-set `server prefer key 5`: strict commit accepted, want reject")
	} else if !strings.Contains(err.Error(), "system ntp server") {
		t.Errorf("flat-set `server prefer key 5`: rejection must name the leaf, got: %v", err)
	}
}
