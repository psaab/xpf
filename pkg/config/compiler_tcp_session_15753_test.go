package config

import (
	"strings"
	"testing"
)

func TestCompileTCPSessionFidelityKnobs15753(t *testing.T) {
	tree := buildTree(t, []string{
		"set security flow tcp-session rst-sequence-check",
		"set security flow tcp-session maximum-window 32768",
		"set security flow tcp-session rst-invalidate-session",
		"set security flow tcp-session no-syn-check-in-tunnel",
	})
	cfg, err := CompileConfig(tree)
	if err != nil { t.Fatalf("CompileConfig: %v", err) }
	ts := cfg.Security.Flow.TCPSession
	if ts == nil || !ts.RstSequenceCheck || ts.MaximumWindow != 32768 || !ts.RstInvalidateSession || !ts.NoSynCheckInTunnel {
		t.Fatalf("fidelity knobs not compiled: %+v", ts)
	}
	for _, w := range ValidateConfig(cfg) {
		for _, tok := range []string{"rst-invalidate-session", "no-syn-check-in-tunnel"} {
			if strings.Contains(w, tok) && strings.Contains(w, "accepted-only") {
				t.Fatalf("enforced knob still warned accepted-only: %q", w)
			}
		}
	}
}
