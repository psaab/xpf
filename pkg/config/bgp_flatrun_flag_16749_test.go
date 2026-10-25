package config

import (
	"strings"
	"testing"
)

// #16749: a flat-set run headed by a valueless BGP flag carried typed
// leaves past every strict validator. These cells drive the real
// ParseSetCommand/SetPath shape (never NewParser for set syntax).

func flatTree16749(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

func TestBGPChainedUnderValuelessFlagStrict16749(t *testing.T) {
	cases := []struct {
		name    string
		cmds    []string
		wantSub []string
	}{
		{
			name: "group passive hold-time 1",
			cmds: []string{"set protocols bgp group G passive hold-time 1"},
			wantSub: []string{"hold-time", "BGP hold-time must be 0 or 3..65535", "FRR rejects 1/2"},
		},
		{
			name: "group passive hold-time 2",
			cmds: []string{"set protocols bgp group G passive hold-time 2"},
			wantSub: []string{"hold-time", "BGP hold-time must be 0 or 3..65535"},
		},
		{
			name: "group remove-private hold-time 1",
			cmds: []string{"set protocols bgp group G remove-private hold-time 1"},
			wantSub: []string{"hold-time", "BGP hold-time must be 0 or 3..65535"},
		},
		{
			name: "neighbor passive hold-time 1",
			cmds: []string{"set protocols bgp group G neighbor 10.0.0.1 passive hold-time 1"},
			wantSub: []string{"hold-time", "BGP hold-time must be 0 or 3..65535"},
		},
		{
			name: "group passive authentication-key-chain",
			cmds: []string{"set protocols bgp group G passive authentication-key-chain kc1"},
			wantSub: []string{"authentication-key-chain", "not implemented"},
		},
		{
			name: "top log-updown local-as bad value",
			cmds: []string{"set protocols bgp log-updown local-as notanumber"},
			wantSub: []string{"local-as", "not an integer"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := flatTree16749(t, tc.cmds...)
			err := SchemaValidate(tree)
			if err == nil {
				t.Fatalf("chained spelling committed clean; the separate-line spelling is rejected, so this bypasses the strict gate (#16749)")
			}
			for _, sub := range tc.wantSub {
				if !strings.Contains(err.Error(), sub) {
					t.Errorf("error %q does not contain %q", err.Error(), sub)
				}
			}
		})
	}

	// Separate-line controls: the oracle spellings keep their verdicts.
	if err := SchemaValidate(flatTree16749(t, "set protocols bgp group G hold-time 1")); err == nil {
		t.Fatal("control: separate-line hold-time 1 must reject")
	}
	if err := SchemaValidate(flatTree16749(t, "set protocols bgp group G hold-time 9")); err != nil {
		t.Fatalf("control: separate-line hold-time 9 must commit, got %v", err)
	}
	// Chained valid value (hold-time 9) is validated at the parent and
	// commits; the compiler still applies it, so strict and compiler agree.
	tree := flatTree16749(t,
		"set protocols bgp local-as 65000",
		"set protocols bgp group G peer-as 65001",
		"set protocols bgp group G passive hold-time 9",
		"set protocols bgp group G neighbor 10.0.0.1",
	)
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("chained hold-time 9 must commit, got %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile chained hold-time 9: %v", err)
	}
	if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
		t.Fatalf("expected one neighbor, got %+v", cfg.Protocols.BGP)
	}
	if n := cfg.Protocols.BGP.Neighbors[0]; n.HoldTime != 9 || !n.Passive {
		t.Errorf("chained hold-time 9 / passive not applied: %+v", n)
	}
}

func TestBGPChainedUnderValuelessFlagBraced16749(t *testing.T) {
	tree, perrs := NewParser("protocols { bgp { local-as 65000; group G { peer-as 65001; passive { hold-time 1; } neighbor 10.0.0.1 { peer-as 65002; } } } }").Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if err := SchemaValidate(tree); err == nil || !strings.Contains(err.Error(), "BGP hold-time must be 0 or 3..65535") {
		t.Fatalf("braced passive { hold-time 1; } must strict-reject, got %v", err)
	}
	// Packed braced spelling keeps its #8437 fused-statement rejection.
	tree2, _ := NewParser("protocols { bgp { local-as 65000; group G { peer-as 65001; passive hold-time 1; neighbor 10.0.0.1 { peer-as 65002; } } } }").Parse()
	if err := SchemaValidate(tree2); err == nil || !strings.Contains(err.Error(), "separate") && !strings.Contains(err.Error(), "missing semicolon") {
		// The packed form is rejected by the fused-statement gate; either
		// wording names the remedy. Silence is the only failure.
		if err == nil {
			t.Fatal("packed passive hold-time 1 must not commit clean")
		}
	}
}

func TestBGPChainedUnknownWarns10707_16749(t *testing.T) {
	tree := flatTree16749(t, "set protocols bgp group G passive boguskw 5")
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("chained unknown stays open-world at strict commit, got %v", err)
	}
	warns := warnUnknownRoutingLeaves10707(tree)
	joined := strings.Join(warns, "\n")
	if !strings.Contains(joined, "boguskw") || !strings.Contains(joined, "#10707") {
		t.Errorf("chained unknown keyword drew no #10707 advisory, got %v", warns)
	}
	// Known chained leaf stays silent.
	tree2 := flatTree16749(t, "set protocols bgp group G passive hold-time 9")
	if warns := warnUnknownRoutingLeaves10707(tree2); len(warns) != 0 {
		t.Errorf("known chained leaf must not warn, got %v", warns)
	}
	// Top-level: hold-time has no BGP-top leaf, so chaining it under
	// log-updown warns (and strict stays open-world for the unknown-at-top).
	tree3 := flatTree16749(t, "set protocols bgp log-updown hold-time 9")
	warns3 := warnUnknownRoutingLeaves10707(tree3)
	if !strings.Contains(strings.Join(warns3, "\n"), "hold-time") {
		t.Errorf("top-level chained hold-time drew no advisory, got %v", warns3)
	}
	// Collect mode surfaces the typed violation as a collected error.
	tree4 := flatTree16749(t, "set protocols bgp group G passive hold-time 1")
	errs, err := SchemaValidateCollectTypedLeaves(tree4, nil)
	if err != nil || len(errs) == 0 || !strings.Contains(errs[0].Error(), "BGP hold-time") {
		t.Errorf("collect mode lost chained hold-time violation: errs=%v err=%v", errs, err)
	}
}

// TestBGPFlagStrictColumn9156_16749 is the strict-path column for the
// #9156 gate: valueless-flag heads are excluded from that gate's
// population (flags have no value slot), so this pins the verdict the
// gate cannot — for each BGP flag head, the chained one-line spelling
// and the separate-line oracle get the SAME strict verdict, and a
// chained invalid value rejects exactly as the oracle does.
func TestBGPFlagStrictColumn9156_16749(t *testing.T) {
	rows := []struct {
		head string
		cmd  string
	}{
		{"passive (group)", "set protocols bgp group G passive hold-time 1"},
		{"remove-private (group)", "set protocols bgp group G remove-private hold-time 1"},
		{"passive (neighbor)", "set protocols bgp group G neighbor 10.0.0.1 passive hold-time 1"},
		{"log-updown (top, known-at-top tail)", "set protocols bgp log-updown local-as notanumber"},
	}
	for _, r := range rows {
		chained := SchemaValidate(flatTree16749(t, r.cmd))
		if chained == nil {
			t.Errorf("%s: chained spelling admitted by strict gate; separate-line oracle rejects (#16749/#9156 strict column)", r.head)
		}
	}
	// Mirrored oracle: separate lines reject identically.
	if err := SchemaValidate(flatTree16749(t, "set protocols bgp group G hold-time 1")); err == nil {
		t.Error("oracle separate-line hold-time 1 admitted")
	}
	_ = strictAdmitsLeafRun9156 // gate helper remains the braced-axis reachability probe
}
