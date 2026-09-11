package config

import (
	"strings"
	"testing"
)

func allowRules9633(t *testing.T, allow string) CompiledLoginRegexes {
	t.Helper()
	cfg := &Config{}
	cfg.System.Login = &LoginConfig{Classes: []*LoginClass{{
		Name: "ops", AllowCommands: allow, AllowLeavesPresent: []string{"allow-commands"},
	}}}
	rules, ok, err := OperationalLoginRegexesFor(cfg, "ops")
	if err != nil || !ok {
		t.Fatalf("precondition: allow-commands %q compiled: ok=%v err=%v", allow, ok, err)
	}
	return rules
}

// TestAllowPatternThatPermitsNothingIsReported9633 is V068: an allow pattern that
// matches no registered command is reported for that surface, one that matches
// is not, and a class with no allow source is never reported.
func TestAllowPatternThatPermitsNothingIsReported9633(t *testing.T) {
	withSurface(t, "grpc", []string{"show interfaces", "show route"})
	if got := UnenforceableAllowSurfaces(allowRules9633(t, "zzz-nothing")); len(got) != 1 || got[0] != "grpc" {
		t.Fatalf("an allow pattern matching no command must be reported on the surface, got %v", got)
	}
	if got := UnenforceableAllowSurfaces(allowRules9633(t, "show interfaces")); len(got) != 0 {
		t.Fatalf("an allow pattern that permits a command must not be reported, got %v", got)
	}
	if got := UnenforceableAllowSurfaces(CompiledLoginRegexes{}); got != nil {
		t.Fatalf("no allow source must report nothing, got %v", got)
	}
}

// TestAllowPatternThatPermitsNothingWarnsAtCommit9633 binds the commit advisory.
func TestAllowPatternThatPermitsNothingWarnsAtCommit9633(t *testing.T) {
	withSurface(t, "grpc", []string{"show interfaces", "show route"})
	cfg := compileSetLines(t, []string{
		"set system login class ops permissions all",
		"set system login class ops allow-commands zzz-nothing",
	})
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "allow-commands") && strings.Contains(w, "#9633") {
			found = true
		}
	}
	if !found {
		t.Fatalf("an allow-commands pattern that permits nothing must warn at commit: %v", cfg.Warnings)
	}
}
