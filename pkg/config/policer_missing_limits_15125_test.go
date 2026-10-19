package config

import (
	"strings"
	"testing"
)

// #15125 (A85-06): a single-rate `firewall policer` with no
// `bandwidth-limit`/`burst-size-limit`, or with a misspelt
// `if-exceding`/`bandwith-limit`, passed strict commit. The compiler then
// built a policer with BandwidthLimit==0 or BurstSizeLimit==0 and the
// dataplane lowers that to a fail-closed meter that drops every packet the
// policed term matches — a rate cap becomes a 100% blackhole with a green
// commit.
//
// Fix: `policer` and `if-exceeding` are closedWorld (typos refused at
// SchemaValidate), and validateFirewallPolicerLimitsStrict hard-rejects a
// policer missing either limit at strict CompileConfig. Lenient load warns
// (#1960 no-brick).
//
// FAIL-ON-REVERT: removing closedWorld makes the typo cases commit clean;
// removing validateFirewallPolicerLimitsStrict (or its uniform-gate wiring)
// makes the omitted/single-limit cases commit clean with a 0 limit.

func hier15125(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	return tree
}

func flat15125(t *testing.T, cmds ...string) *ConfigTree {
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

// strictCommit15125 mirrors the operator commit path: SchemaValidate then
// strict CompileConfig. Either may be the rejecting gate; both must agree
// the config does not commit.
func strictCommit15125(t *testing.T, tree *ConfigTree) error {
	t.Helper()
	if err := SchemaValidate(tree, nil); err != nil {
		return err
	}
	_, err := CompileConfig(tree)
	return err
}

func TestPolicer15125_MissingLimitsRejectedStrict(t *testing.T) {
	cases := []struct {
		name string
		tree func(t *testing.T) *ConfigTree
		want []string // substrings the error must name
	}{
		{"no if-exceeding hier", func(t *testing.T) *ConfigTree {
			return hier15125(t, `firewall { policer p1 { then { discard; } } }`)
		}, []string{"p1", "bandwidth-limit"}},
		{"no if-exceeding flat", func(t *testing.T) *ConfigTree {
			return flat15125(t, "set firewall policer p1 then discard")
		}, []string{"p1", "bandwidth-limit"}},
		{"only bandwidth-limit hier", func(t *testing.T) *ConfigTree {
			return hier15125(t, `firewall { policer p1 { if-exceeding { bandwidth-limit 1m; } then { discard; } } }`)
		}, []string{"p1", "burst-size-limit"}},
		{"only bandwidth-limit flat", func(t *testing.T) *ConfigTree {
			return flat15125(t,
				"set firewall policer p1 if-exceeding bandwidth-limit 1m",
				"set firewall policer p1 then discard")
		}, []string{"p1", "burst-size-limit"}},
		{"only burst-size-limit hier", func(t *testing.T) *ConfigTree {
			return hier15125(t, `firewall { policer p1 { if-exceeding { burst-size-limit 15k; } then { discard; } } }`)
		}, []string{"p1", "bandwidth-limit"}},
		{"only burst-size-limit flat", func(t *testing.T) *ConfigTree {
			return flat15125(t,
				"set firewall policer p1 if-exceeding burst-size-limit 15k",
				"set firewall policer p1 then discard")
		}, []string{"p1", "bandwidth-limit"}},
		{"empty if-exceeding hier", func(t *testing.T) *ConfigTree {
			return hier15125(t, `firewall { policer p1 { if-exceeding { } then { discard; } } }`)
		}, []string{"p1", "bandwidth-limit"}},
		{"typo if-exceding hier", func(t *testing.T) *ConfigTree {
			return hier15125(t, `firewall { policer p1 { if-exceding { bandwidth-limit 1m; burst-size-limit 15k; } then { discard; } } }`)
		}, []string{"if-exceding"}},
		{"typo if-exceding flat", func(t *testing.T) *ConfigTree {
			return flat15125(t,
				"set firewall policer p1 if-exceding bandwidth-limit 1m",
				"set firewall policer p1 if-exceding burst-size-limit 15k",
				"set firewall policer p1 then discard")
		}, []string{"if-exceding"}},
		{"typo bandwith-limit hier", func(t *testing.T) *ConfigTree {
			return hier15125(t, `firewall { policer p1 { if-exceeding { bandwith-limit 1m; burst-size-limit 15k; } then { discard; } } }`)
		}, []string{"bandwith-limit"}},
		{"typo bandwith-limit flat", func(t *testing.T) *ConfigTree {
			return flat15125(t,
				"set firewall policer p1 if-exceeding bandwith-limit 1m",
				"set firewall policer p1 if-exceeding burst-size-limit 15k",
				"set firewall policer p1 then discard")
		}, []string{"bandwith-limit"}},
		{"typo burst-size-limit hier", func(t *testing.T) *ConfigTree {
			return hier15125(t, `firewall { policer p1 { if-exceeding { bandwidth-limit 1m; burst-size-limt 15k; } then { discard; } } }`)
		}, []string{"burst-size-limt"}},
		{"unknown policer child hier", func(t *testing.T) *ConfigTree {
			return hier15125(t, `firewall { policer p1 { if-exceeding { bandwidth-limit 1m; burst-size-limit 15k; } boguskid { x; } then { discard; } } }`)
		}, []string{"boguskid"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := strictCommit15125(t, tc.tree(t))
			if err == nil {
				t.Fatalf("policer missing/misspelt limits committed clean at strict commit (#15125 fail-closed blackhole)")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error = %q, want it to name %q", err, want)
				}
			}
		})
	}
}

// The compiled-config gate alone (without SchemaValidate) must also reject:
// CompileConfig is the strict entry used by configstore commit paths that
// have already schema-validated an expanded tree, and it must not depend on
// the caller remembering SchemaValidate for the missing-limit half.
func TestPolicer15125_CompileConfigGateAlone(t *testing.T) {
	tree := hier15125(t, `firewall { policer p1 { if-exceeding { bandwidth-limit 1m; } then { discard; } } }`)
	if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "burst-size-limit") {
		t.Fatalf("CompileConfig = %v, want burst-size-limit rejection", err)
	}
	tree = hier15125(t, `firewall { policer p1 { then { discard; } } }`)
	if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "bandwidth-limit") {
		t.Fatalf("CompileConfig = %v, want bandwidth-limit rejection", err)
	}
}

// Positive control: the full policer is unchanged at strict commit.
func TestPolicer15125_FullPositiveControlUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		tree func(t *testing.T) *ConfigTree
	}{
		{"hier", func(t *testing.T) *ConfigTree {
			return hier15125(t, `firewall { policer p1 { if-exceeding { bandwidth-limit 1m; burst-size-limit 15k; } then { discard; } } }`)
		}},
		{"flat", func(t *testing.T) *ConfigTree {
			return flat15125(t,
				"set firewall policer p1 if-exceeding bandwidth-limit 1m",
				"set firewall policer p1 if-exceeding burst-size-limit 15k",
				"set firewall policer p1 then discard")
		}},
		{"hier marking", func(t *testing.T) *ConfigTree {
			return hier15125(t, `firewall { policer p1 { logical-interface-policer; if-exceeding { bandwidth-limit 1m; burst-size-limit 15k; } then { loss-priority high; } } }`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := tc.tree(t)
			if err := SchemaValidate(tree, nil); err != nil {
				t.Fatalf("SchemaValidate rejected full policer: %v", err)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig rejected full policer: %v", err)
			}
			pol := cfg.Firewall.Policers["p1"]
			if pol == nil || pol.BandwidthLimit != 125000 || pol.BurstSizeLimit != 15000 {
				t.Fatalf("full policer compiled changed: %+v", pol)
			}
		})
	}
}

// Tolerant path: warn, do not hard-fail (#1960 no-brick). The compiled
// policer is preserved exactly as before (0 limit), only now diagnosed.
func TestPolicer15125_LenientWarnsNotHardFail(t *testing.T) {
	tree := hier15125(t, `firewall { policer p1 { then { discard; } } }`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile hard-failed a limit-less policer: %v", err)
	}
	joined := strings.Join(cfg.Warnings, " ")
	if !strings.Contains(joined, "p1") || !strings.Contains(joined, "bandwidth-limit") {
		t.Fatalf("lenient warnings = %v, want policer p1 missing-limit warning", cfg.Warnings)
	}
	// Typo on the tolerant path must also warn (closedWorld is strict-only;
	// the missing-limit warning is the diagnostic).
	tree = hier15125(t, `firewall { policer p1 { if-exceding { bandwidth-limit 1m; burst-size-limit 15k; } then { discard; } } }`)
	cfg, err = CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile hard-failed a typo policer: %v", err)
	}
	if joined = strings.Join(cfg.Warnings, " "); !strings.Contains(joined, "bandwidth-limit") {
		t.Fatalf("lenient typo warnings = %v, want missing-limit warning", cfg.Warnings)
	}
	// Full policer: no missing-limit warning.
	tree = hier15125(t, `firewall { policer p1 { if-exceeding { bandwidth-limit 1m; burst-size-limit 15k; } then { discard; } } }`)
	cfg, err = CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient full policer: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "bandwidth-limit") && strings.Contains(w, "requires") {
			t.Fatalf("full policer got missing-limit warning: %q", w)
		}
	}
}
