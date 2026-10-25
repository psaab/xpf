package config

import (
	"strings"
	"testing"
)

// #16662 (R3-N08-06): packed hierarchical `time-wait-state
// session-timeout N;` / `time-wait-state session-ageout;` passed strict
// commit and compiled to nothing. The parser packs the leaf onto
// twNode.Keys[1:] with no Children, and compileFlow's time-wait-state
// loop iterated only twNode.Children, so TimeWaitStateSessionTimeout
// stayed 0 and TimeWaitStateSessionAgeout stayed false while `show`
// displayed the authored text. The runtime consumer
// (pkg/dataplane/userspace/flow.go) therefore kept its defaults.
//
// FAIL-ON-REVERT: restoring the Children-only loop makes every packed
// cell below compile to the empty-stanza values (timeout 0, flags
// false) while the braced controls stay correct.

func compileHier16662(t *testing.T, text string) *Config {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse %q: %v", text, perrs)
	}
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate %q: %v", text, err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig %q: %v", text, err)
	}
	return cfg
}

func TestTimeWaitStatePackedHierarchical16662(t *testing.T) {
	braced := compileHier16662(t, "security { flow { tcp-session { time-wait-state { session-timeout 120; } } } }")
	if ts := braced.Security.Flow.TCPSession; ts == nil || ts.TimeWaitStateSessionTimeout != 120 {
		t.Fatalf("braced control did not compile: %+v", ts)
	}

	cases := []struct {
		name    string
		text    string
		timeout int
		ageout  bool
		half    bool
	}{
		{
			name:    "packed session-timeout",
			text:    "security { flow { tcp-session { time-wait-state session-timeout 120; } } }",
			timeout: 120,
		},
		{
			name:   "packed session-ageout",
			text:   "security { flow { tcp-session { time-wait-state session-ageout; } } }",
			ageout: true,
		},
		{
			name: "packed apply-to-half-close-state (Junos)",
			text: "security { flow { tcp-session { time-wait-state apply-to-half-close-state; } } }",
			half: true,
		},
		{
			name: "packed apply-to-half-closed-state (deprecated alias)",
			text: "security { flow { tcp-session { time-wait-state apply-to-half-closed-state; } } }",
			half: true,
		},
		{
			name:    "packed multi-leaf run session-timeout + half-close",
			text:    "security { flow { tcp-session { time-wait-state session-timeout 120 apply-to-half-close-state; } } }",
			timeout: 120,
			half:    true,
		},
		{
			name:   "packed multi-leaf run ageout + half-close",
			text:   "security { flow { tcp-session { time-wait-state session-ageout apply-to-half-close-state; } } }",
			ageout: true,
			half:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileHier16662(t, tc.text)
			ts := cfg.Security.Flow.TCPSession
			if ts == nil {
				t.Fatalf("packed %q compiled to nil TCPSession", tc.text)
			}
			if ts.TimeWaitStateSessionTimeout != tc.timeout ||
				ts.TimeWaitStateSessionAgeout != tc.ageout ||
				ts.TimeWaitStateApplyToHalfClosed != tc.half {
				t.Fatalf("packed %q = timeout=%d ageout=%v half=%v, want timeout=%d ageout=%v half=%v",
					tc.text, ts.TimeWaitStateSessionTimeout, ts.TimeWaitStateSessionAgeout,
					ts.TimeWaitStateApplyToHalfClosed, tc.timeout, tc.ageout, tc.half)
			}
		})
	}

	// Packed and braced spellings must compile identically.
	packed := compileHier16662(t, "security { flow { tcp-session { time-wait-state session-timeout 120; } } }")
	if packed.Security.Flow.TCPSession.TimeWaitStateSessionTimeout != braced.Security.Flow.TCPSession.TimeWaitStateSessionTimeout {
		t.Fatalf("packed timeout %d != braced %d",
			packed.Security.Flow.TCPSession.TimeWaitStateSessionTimeout,
			braced.Security.Flow.TCPSession.TimeWaitStateSessionTimeout)
	}

	// Narrowness: a packed leaf must not set its siblings.
	only := compileHier16662(t, "security { flow { tcp-session { time-wait-state session-ageout; } } }")
	if ts := only.Security.Flow.TCPSession; ts.TimeWaitStateSessionTimeout != 0 || ts.TimeWaitStateApplyToHalfClosed {
		t.Fatalf("session-ageout alone set siblings: %+v", ts)
	}
}

// The packed spelling must go through the same strict gates as the
// braced one: `session-ageout` together with `session-timeout` is
// rejected at strict commit (#16485) in either spelling, and an
// out-of-range packed value is rejected by SchemaValidate.
func TestTimeWaitStatePackedStrictGates16662(t *testing.T) {
	tree, perrs := NewParser("security { flow { tcp-session { time-wait-state session-timeout 120 session-ageout; } } }").Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if _, err := CompileConfig(tree); err == nil ||
		!strings.Contains(err.Error(), "session-ageout") {
		t.Fatalf("packed ageout+timeout must be strict-rejected (#16485), got %v", err)
	}

	tree2, perrs := NewParser("security { flow { tcp-session { time-wait-state session-timeout 999999999999; } } }").Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if err := SchemaValidate(tree2); err == nil {
		t.Fatal("out-of-range packed session-timeout accepted by SchemaValidate")
	}

	// Near-miss packed leaf rejects like the braced spelling
	// (closed-world + packedTail validation, #16662).
	treeNear, perrs := NewParser("security { flow { tcp-session { time-wait-state session-timeou 120; } } }").Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if err := SchemaValidate(treeNear); err == nil {
		t.Fatal("near-miss packed leaf accepted by SchemaValidate")
	}

	// Lenient path keeps both (ageout wins at runtime, #16485).
	tree3, perrs := NewParser("security { flow { tcp-session { time-wait-state session-timeout 120 session-ageout; } } }").Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfigLenient(tree3)
	if err != nil {
		t.Fatalf("CompileConfigLenient packed both: %v", err)
	}
	if ts := cfg.Security.Flow.TCPSession; ts == nil || ts.TimeWaitStateSessionTimeout != 120 || !ts.TimeWaitStateSessionAgeout {
		t.Fatalf("lenient packed both not compiled: %+v", ts)
	}
}
