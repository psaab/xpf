package config

import (
	"strings"
	"testing"
)

// `security flow tcp-session strict-syn-check` is a security knob (drop
// SYN-with-data and pre-handshake data, #16479). Every spelling Junos accepts
// must compile it to TCPSession.StrictSynCheck=true on BOTH the strict and the
// tolerant path. The brace-elided spelling used to commit clean while leaving
// the flag unset, because its (tcp-session, strict-syn-check) pair was never
// admitted to compactNormalizeInScope. That is the worst shape: it fails to a
// healthy-looking value, with `show configuration` echoing what was typed.
func TestStrictSynCheckEverySpellingSetsTheFlag(t *testing.T) {
	hier := map[string]string{
		"braced":       `security { flow { tcp-session { strict-syn-check; } } }`,
		"elided-once":  `security { flow { tcp-session strict-syn-check; } }`,
		"elided-twice": `security { flow tcp-session strict-syn-check; }`,
		"elided-fully": `security flow tcp-session strict-syn-check;`,
	}
	compile := func(t *testing.T, tree *ConfigTree, lenient bool) *Config {
		t.Helper()
		var (
			cfg *Config
			err error
		)
		if lenient {
			cfg, err = CompileConfigLenient(tree)
		} else {
			cfg, err = CompileConfig(tree)
		}
		if err != nil {
			t.Fatalf("compile (lenient=%v): %v", lenient, err)
		}
		return cfg
	}
	for name, text := range hier {
		for _, lenient := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "/strict", true: "/lenient"}[lenient], func(t *testing.T) {
				tree, perrs := NewParser(text).Parse()
				if len(perrs) > 0 {
					t.Fatalf("parse %q: %v", text, perrs)
				}
				cfg := compile(t, tree, lenient)
				if !cfg.Security.Flow.TCPSession.StrictSynCheck {
					t.Errorf("%q committed but StrictSynCheck is false: the flag was silently dropped", text)
				}
			})
		}
	}
	// The flat-set shape is a chain, not a packed tail; it must agree.
	for _, lenient := range []bool{false, true} {
		t.Run(map[bool]string{false: "flat-set/strict", true: "flat-set/lenient"}[lenient], func(t *testing.T) {
			tree := setTreeFromCommands(t, []string{"set security flow tcp-session strict-syn-check"})
			if cfg := compile(t, tree, lenient); !cfg.Security.Flow.TCPSession.StrictSynCheck {
				t.Error("flat-set `set security flow tcp-session strict-syn-check` left StrictSynCheck false")
			}
		})
	}
	// Control: a sibling flag in the same elided container must not turn the
	// knob on, so a fix that sets it whenever tcp-session is present fails.
	t.Run("control/sibling-flag-only", func(t *testing.T) {
		text := `security { flow { tcp-session no-sequence-check; } }`
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		cfg := compile(t, tree, false)
		if cfg.Security.Flow.TCPSession.StrictSynCheck {
			t.Error("StrictSynCheck set by an unrelated tcp-session flag")
		}
		if !cfg.Security.Flow.TCPSession.NoSequenceCheck {
			t.Error("positive control: the sibling no-sequence-check flag was not compiled, so this row observes nothing")
		}
	})
	if !strings.Contains(hier["elided-once"], "tcp-session strict-syn-check;") {
		t.Fatal("fixture drift")
	}
}

// Upgrade effect of #18762 (seat AC): while the admission was missing, an
// elided `tcp-session strict-syn-check;` was dropped before the #16479 mutual-
// exclusion gate saw it, so a config carrying it beside `no-syn-check`
// committed clean. Re-admitting the pair re-arms the gate. Pin both paths for
// both shapes: strict commit REJECTS; the tolerant load (boot / peer-sync)
// WARNS and keeps both flags (strict-syn-check wins in the dataplane).
func TestStrictSynCheckBesideNoSynCheckAfterReadmission18762(t *testing.T) {
	for name, text := range map[string]string{
		"braced": `security { flow { tcp-session { strict-syn-check; no-syn-check; } } }`,
		"elided": `security { flow { tcp-session strict-syn-check; tcp-session no-syn-check; } }`,
	} {
		t.Run(name, func(t *testing.T) {
			tree, perrs := NewParser(text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse: %v", perrs)
			}
			if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "cannot be enabled if `no-syn-check` is enabled") {
				t.Errorf("strict commit of %q = %v, want the #16479 mutual-exclusion rejection", text, err)
			}
			tree2, _ := NewParser(text).Parse()
			cfg, err := CompileConfigLenient(tree2)
			if err != nil {
				t.Fatalf("tolerant load of %q failed (it must boot, #1960): %v", text, err)
			}
			ts := cfg.Security.Flow.TCPSession
			if ts == nil || !ts.StrictSynCheck || !ts.NoSynCheck {
				t.Errorf("tolerant load lost a flag: %+v (want StrictSynCheck and NoSynCheck both set)", ts)
			}
			warned := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "strict-syn-check (downgraded to warning on tolerant path)") {
					warned = true
				}
			}
			if !warned {
				t.Errorf("tolerant load did not warn about the strict-syn-check / no-syn-check conflict: %v", cfg.Warnings)
			}
		})
	}
}
