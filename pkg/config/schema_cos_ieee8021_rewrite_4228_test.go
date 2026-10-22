package config_test

// #4228 Gap 4: CoS `rewrite-rules ieee-802.1` (802.1p PCP egress rewrite) is
// now modeled in the config-mode grammar + compiler. The mapping
// (forwarding-class -> loss-priority -> code-point 0..7) is parsed, validated,
// and bindable on an interface unit, but is ACCEPTED-BUT-INERT: the userspace
// dataplane rewrites only DSCP on egress and does not yet own the 802.1Q tag
// write, so a commit advisory surfaces the inertness. The classifier side
// (classifiers ieee-802.1) is already enforced; only this egress-rewrite half
// awaits TX 802.1Q tag ownership (a Rust follow-up).
//
// FAIL-ON-REVERT: with the schema node + compiler loop removed, the
// `rewrite-rules ieee-802.1` leaf is UNKNOWN under the opt-in CoS grammar, so
// SchemaValidate rejects the definition (and the unit binding), the compiled
// IEEE8021RewriteRules map is absent, the unit's IEEE8021RewriteRule binding is
// empty, and the inert advisory + typo / out-of-range rejects all disappear.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// compileSet4228IEEE runs SchemaValidate (which MUST pass — the leaf is valid
// grammar) then returns the CompileConfig result so a reject test can assert
// the compiler-level error (out-of-range code point, loss-priority typo).
func compileSet4228IEEE(t *testing.T, cmds ...string) (*config.Config, error) {
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
	if err := config.SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate (leaf must be accepted grammar): %v", err)
	}
	return config.CompileConfig(tree)
}

func TestCoSIEEE8021Rewrite_AcceptsAndCompiles(t *testing.T) {
	cfg, err := compileSet4228IEEE(t,
		"set class-of-service forwarding-classes queue 3 voice",
		"set class-of-service rewrite-rules ieee-802.1 pcp-rw forwarding-class voice loss-priority low code-point 5",
		"set class-of-service interfaces ge-0-0-2 unit 0 rewrite-rules ieee-802.1 pcp-rw",
	)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	rr := cfg.ClassOfService.IEEE8021RewriteRules["pcp-rw"]
	if rr == nil {
		t.Fatal("expected ieee-802.1 rewrite-rule pcp-rw to be modeled")
	}
	if len(rr.Entries) != 1 {
		t.Fatalf("Entries = %d, want 1", len(rr.Entries))
	}
	e := rr.Entries[0]
	if e.ForwardingClass != "voice" || e.LossPriority != "low" || e.PCPValue != 5 {
		t.Fatalf("entry = %+v, want {voice low 5}", e)
	}
	// Interface-unit binding is captured.
	iface := cfg.ClassOfService.Interfaces["ge-0-0-2"]
	if iface == nil || iface.Units[0] == nil {
		t.Fatal("expected ge-0-0-2 unit 0 CoS binding")
	}
	if got := iface.Units[0].IEEE8021RewriteRule; got != "pcp-rw" {
		t.Fatalf("unit IEEE8021RewriteRule = %q, want pcp-rw", got)
	}
}

func TestCoSIEEE8021Rewrite_EmitsInertAdvisory(t *testing.T) {
	cfg, err := compileSet4228IEEE(t,
		"set class-of-service forwarding-classes queue 3 voice",
		"set class-of-service rewrite-rules ieee-802.1 pcp-rw forwarding-class voice loss-priority low code-point 5",
	)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	warnings := config.ValidateConfig(cfg)
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "rewrite-rules ieee-802.1") && strings.Contains(w, "inert") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an accepted-but-inert advisory for ieee-802.1 rewrite, got: %v", warnings)
	}
}

func TestCoSIEEE8021RewriteCodePointOutOfRange_Rejected(t *testing.T) {
	_, err := compileSet4228IEEE(t,
		"set class-of-service rewrite-rules ieee-802.1 pcp-rw forwarding-class voice loss-priority low code-point 8",
	)
	if err == nil {
		t.Fatal("expected error for 802.1p rewrite code-point 8 (must be 0..7)")
	}
	if !strings.Contains(err.Error(), "0..7") {
		t.Fatalf("error should reference the 0..7 domain: %v", err)
	}
}

func TestCoSIEEE8021RewriteLossPriorityTypo_Rejected(t *testing.T) {
	_, err := compileSet4228IEEE(t,
		"set class-of-service rewrite-rules ieee-802.1 pcp-rw forwarding-class voice loss-priority medum-low code-point 5",
	)
	if err == nil {
		t.Fatal("expected error for loss-priority typo `medum-low` on an ieee-802.1 rewrite")
	}
	if !strings.Contains(err.Error(), "loss-priority") {
		t.Fatalf("error should reference loss-priority: %v", err)
	}
}
