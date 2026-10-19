package config

import (
	"strings"
	"testing"
)

// #15776: protocols lldp packed/chained top-level leaves, sibling
// duplicate interfaces, and override-disabled duplicates.

func compiledLLDP15776(t *testing.T, text string) *LLDPConfig {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile %q: %v", text, err)
	}
	if cfg.Protocols.LLDP == nil {
		t.Fatalf("compile %q: LLDP nil", text)
	}
	return cfg.Protocols.LLDP
}

func flatLLDP15776(t *testing.T, cmds ...string) *LLDPConfig {
	t.Helper()
	tree := &ConfigTree{}
	for _, c := range cmds {
		p, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand %q: %v", c, err)
		}
		tree.SetPath(p)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile sets %v: %v", cmds, err)
	}
	return cfg.Protocols.LLDP
}

func TestLLDP15776PackedChainedTopLeaves(t *testing.T) {
	ctl := compiledLLDP15776(t, `protocols { lldp { transmit-interval 10; hold-multiplier 5; disable; interface ge-0/0/0; } }`)
	if ctl.Interval != 10 || ctl.HoldMultiplier != 5 || !ctl.Disable {
		t.Fatalf("control = %+v, want interval 10 hold 5 disable", ctl)
	}
	for _, tc := range []struct {
		name string
		text string
	}{
		{"packed run in braces", `protocols { lldp { transmit-interval 10 disable; } }`},
		{"packed hold run", `protocols { lldp { hold-multiplier 5 disable; interface ge-0/0/0; } }`},
		{"disable chained first", `protocols { lldp { disable transmit-interval 10; } }`},
		{"brace-elided lldp disable", `protocols { lldp disable; }`},
		{"protocols brace elided", `protocols lldp { transmit-interval 10; disable; }`},
		{"packed lldp node no braces", `protocols lldp disable;`},
		{"mixed tail beside braced body interval only", `protocols { lldp transmit-interval 10 disable; interface ge-0/0/0; }`},
		{"mixed tail disable beside body", `protocols { lldp transmit-interval 10 disable { interface ge-0/0/0; } }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := compiledLLDP15776(t, tc.text)
			if !got.Disable {
				t.Errorf("%s: Disable=false, want true (%+v)", tc.text, got)
			}
			if strings.Contains(tc.text, "transmit-interval") && got.Interval != 10 {
				t.Errorf("%s: Interval=%d, want 10", tc.text, got.Interval)
			}
			if strings.Contains(tc.text, "hold-multiplier") && got.HoldMultiplier != 5 {
				t.Errorf("%s: HoldMultiplier=%d, want 5", tc.text, got.HoldMultiplier)
			}
		})
	}
	if got := flatLLDP15776(t, "set protocols lldp transmit-interval 10 disable"); !got.Disable || got.Interval != 10 {
		t.Errorf("flat transmit+disable = %+v, want {10 disable}", got)
	}
	if got := flatLLDP15776(t, "set protocols lldp disable transmit-interval 10"); !got.Disable || got.Interval != 10 {
		t.Errorf("flat disable+transmit = %+v, want {10 disable}", got)
	}
	if got := flatLLDP15776(t, "set protocols lldp hold-multiplier 5 disable"); !got.Disable || got.HoldMultiplier != 5 {
		t.Errorf("flat hold+disable = %+v, want {5 disable}", got)
	}
	packed := compiledLLDP15776(t, `protocols { lldp { transmit-interval 10 disable; hold-multiplier 5; } }`)
	if packed.Interval != ctl.Interval || packed.HoldMultiplier != ctl.HoldMultiplier || packed.Disable != ctl.Disable {
		t.Errorf("packed %+v != control %+v", packed, ctl)
	}
}

func TestLLDP15776DuplicateInterfaceDisableWins(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{"enable then disable block", `protocols { lldp { interface ge-0/0/0; interface ge-0/0/0 { disable; } } }`},
		{"disable block then enable", `protocols { lldp { interface ge-0/0/0 { disable; } interface ge-0/0/0; } }`},
		{"duplicate enabled", `protocols { lldp { interface ge-0/0/0; interface ge-0/0/0; } }`},
		{"packed disable duplicate", `protocols { lldp { interface ge-0/0/0; interface ge-0/0/0 disable; } }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := compiledLLDP15776(t, tc.text)
			if len(got.Interfaces) != 1 {
				t.Fatalf("interfaces = %+v, want exactly one merged entry", got.Interfaces)
			}
			wantDisable := !strings.Contains(tc.name, "duplicate enabled")
			if got.Interfaces[0].Disable != wantDisable {
				t.Errorf("interface = %+v, want Disable=%v", got.Interfaces[0], wantDisable)
			}
		})
	}
	for _, cmds := range [][]string{
		{"set protocols lldp interface ge-0/0/0", "set protocols lldp interface ge-0/0/0 disable"},
		{"set protocols lldp interface ge-0/0/0 disable", "set protocols lldp interface ge-0/0/0"},
	} {
		got := flatLLDP15776(t, cmds...)
		if len(got.Interfaces) != 1 || !got.Interfaces[0].Disable {
			t.Errorf("sets %v = %+v, want one disabled entry", cmds, got.Interfaces)
		}
	}
	got := compiledLLDP15776(t, `protocols { lldp { interface ge-0/0/0 { disable; } interface ge-0/0/1; transmit-interval 30; } }`)
	if len(got.Interfaces) != 2 || !got.Interfaces[0].Disable || got.Interfaces[1].Disable || got.Interval != 30 {
		t.Errorf("distinct interfaces regressed: %+v", got)
	}
	sib := compiledLLDP15776(t, `protocols { lldp { interface ge-0/0/1; } lldp { transmit-interval 22; interface ge-0/0/1 { disable; } } }`)
	if sib.Interval != 22 || len(sib.Interfaces) != 1 || !sib.Interfaces[0].Disable {
		t.Errorf("sibling blocks = %+v, want interval 22 one disabled ge-0/0/1", sib)
	}
}
