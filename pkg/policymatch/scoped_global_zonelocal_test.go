package policymatch

import (
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// compileFromSet compiles a config from flat `set` commands using the
// ParseSetCommand + SetPath loop (NewParser must not be used for set syntax —
// see CLAUDE.md "Testing flat set syntax").
func compileFromSet(t *testing.T, cmds []string) *config.Config {
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
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func compileFromSetLenient(t *testing.T, cmds []string) *config.Config {
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
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

func compileFromSetErr(t *testing.T, cmds []string) error {
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
	_, err := config.CompileConfig(tree)
	return err
}

// TestScopedGlobalResolvesGlobalBook16596 pins #16596 (superseding #3287): a
// scoped global policy resolves its address names against the GLOBAL book,
// even when the scoped zone's book defines the same name. Before the fix the
// single-zone rewrite rebound BLOCKED to trust's 10.1.1.1/32, so the global
// deny silently enforced the wrong object.
func TestScopedGlobalResolvesGlobalBook16596(t *testing.T) {
	cmds := []string{
		"set security zones security-zone trust",
		// #3355: the egress zone must be a DEFINED zone.
		"set security zones security-zone untrust",
		"set security address-book global address BLOCKED 10.0.0.0/8",
		"set security zones security-zone trust address-book address BLOCKED 10.1.1.1/32",
		"set security policies global policy deny-blocked match source-address BLOCKED",
		"set security policies global policy deny-blocked match destination-address any",
		"set security policies global policy deny-blocked match application any",
		"set security policies global policy deny-blocked match from-zone trust",
		"set security policies global policy deny-blocked then deny",
		"set security policies default-policy deny-all",
	}
	cfg := compileFromSet(t, cmds)

	// 10.0.0.5 is inside the GLOBAL 10.0.0.0/8 but outside trust's /32: the
	// scoped global deny must match it (the pre-fix zone-local binding
	// missed it and fell through with the same deny action via the default
	// policy — so assert the POLICY identity, not just the action).
	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.0.0.5"),
	})
	if !res.Matched || !res.Global || res.PolicyName != "deny-blocked" {
		t.Fatalf("expected scoped-global deny-blocked match for global-BLOCKED source, got Matched=%v Global=%v policy=%q action=%v",
			res.Matched, res.Global, res.PolicyName, res.Action)
	}
	if res.Action != config.PolicyDeny {
		t.Errorf("Action = %v, want deny", res.Action)
	}

	// 10.1.1.1 is trust's zone-local twin AND inside the global /8, so it
	// still matches — via the global object.
	res2 := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.1.1.1"),
	})
	if !res2.Matched || res2.PolicyName != "deny-blocked" {
		t.Errorf("expected deny-blocked for 10.1.1.1 (global /8), got policy %q matched=%v", res2.PolicyName, res2.Matched)
	}

	// A source outside the global /8 must NOT match the global.
	res3 := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("192.0.2.1"),
	})
	if res3.Matched {
		t.Errorf("expected no scoped-global match for out-of-global-BLOCKED source, got policy %q", res3.PolicyName)
	}
}

// TestScopedGlobalLocalOnlyRejected16596: a scoped-global token defined only
// in the zone's book is a strict commit error (Junos requires the global
// book), and on the tolerant path the simulator must report the fail-closed
// snapshot retention rather than enforcing the zone-local object (or, here,
// fabricating the permit the old #3287 behaviour produced).
func TestScopedGlobalLocalOnlyRejected16596(t *testing.T) {
	cmds := []string{
		"set security zones security-zone trust address-book address LOCALNET 10.0.1.0/24",
		"set security zones security-zone untrust",
		"set security policies global policy allow-local match source-address LOCALNET",
		"set security policies global policy allow-local match destination-address any",
		"set security policies global policy allow-local match application any",
		"set security policies global policy allow-local match from-zone trust",
		"set security policies global policy allow-local then permit",
		"set security policies default-policy deny-all",
	}
	err := compileFromSetErr(t, cmds)
	if err == nil {
		t.Fatal("strict compile must reject local-only scoped global (#16596)")
	}
	if !strings.Contains(err.Error(), "LOCALNET") || !strings.Contains(err.Error(), "#16596") {
		t.Fatalf("strict error must name LOCALNET and #16596: %v", err)
	}

	cfg := compileFromSetLenient(t, cmds)
	res := Match(cfg, Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.0.1.5"),
	})
	if !res.ContentRejected {
		t.Fatalf("tolerant local-only scoped global must report ContentRejected (fail-closed retention), got Matched=%v policy=%q action=%v",
			res.Matched, res.PolicyName, res.Action)
	}
	if res.Matched {
		t.Errorf("ContentRejected result must not fabricate a match, got policy %q", res.PolicyName)
	}
	joined := strings.Join(res.ContentRejectionReasons, "\n")
	if !strings.Contains(joined, "allow-local") {
		t.Errorf("rejection reasons must name allow-local: %v", res.ContentRejectionReasons)
	}
}
