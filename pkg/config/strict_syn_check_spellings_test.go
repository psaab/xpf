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
