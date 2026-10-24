package config

import (
	"strings"
	"testing"
)

// #16479: Junos refuses `strict-syn-check` beside `no-syn-check` /
// `no-syn-check-in-tunnel`. Strict commit must reject the combination;
// the tolerant load path must warn and keep the config (no-brick,
// #1960), where the dataplane keeps strict-wins precedence.
//
// FAIL-ON-REVERT: delete validateStrictSynCheckStrict (or its dispatch
// in runUniformGatesClusterZone) and the strict cells below go GREEN on
// the forbidden combination.
func TestStrictSynCheckMutualExclusion16479(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmds []string
	}{
		{"strict+no-syn-check", []string{
			"set security flow tcp-session strict-syn-check",
			"set security flow tcp-session no-syn-check",
		}},
		{"strict+no-syn-check-in-tunnel", []string{
			"set security flow tcp-session strict-syn-check",
			"set security flow tcp-session no-syn-check-in-tunnel",
		}},
	} {
		t.Run(tc.name+" strict rejects", func(t *testing.T) {
			tree := buildTree(t, tc.cmds)
			if _, err := CompileConfig(tree); err == nil ||
				!strings.Contains(err.Error(), "strict-syn-check") {
				t.Fatalf("strict commit must reject %s, got err=%v", tc.name, err)
			}
		})
		t.Run(tc.name+" lenient warns and keeps", func(t *testing.T) {
			tree := buildTree(t, tc.cmds)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient load must not brick on %s: %v", tc.name, err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "strict-syn-check") {
					found = true
				}
			}
			if !found {
				t.Fatalf("lenient load must warn on %s, warnings=%v", tc.name, cfg.Warnings)
			}
		})
	}

	// Controls: strict alone, and each no-syn knob alone, still commit.
	for _, tc := range []struct {
		name string
		cmds []string
	}{
		{"strict alone", []string{"set security flow tcp-session strict-syn-check"}},
		{"no-syn-check alone", []string{"set security flow tcp-session no-syn-check"}},
		{"no-syn-check-in-tunnel alone", []string{"set security flow tcp-session no-syn-check-in-tunnel"}},
		{"no-syn pair without strict", []string{
			"set security flow tcp-session no-syn-check",
			"set security flow tcp-session no-syn-check-in-tunnel",
		}},
	} {
		t.Run(tc.name+" compiles", func(t *testing.T) {
			tree := buildTree(t, tc.cmds)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("%s must still compile: %v", tc.name, err)
			}
			if cfg.Security.Flow.TCPSession == nil {
				t.Fatalf("%s: TCPSession not compiled", tc.name)
			}
		})
	}

	// The lenient flag must be registered or the tolerant path bricks.
	if !lenientCompileOpts().lenientStrictSynCheck16479 {
		t.Fatal("lenientStrictSynCheck16479 is NOT registered in lenientCompileOpts() — a persisted or peer-synced config carrying strict+no-syn would fail to boot (#1960)")
	}
}
