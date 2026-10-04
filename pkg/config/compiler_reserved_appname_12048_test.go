package config

import (
	"strings"
	"testing"
)

// #12048: lowercase `any` is interpreted as the match-all keyword before
// application/application-set lookup. A user definition with that exact name is
// therefore unreachable and must be rejected at commit with an actionable
// diagnostic. Tolerant loads retain the #1960 no-brick warning behavior.
//
// FAIL-ON-REVERT: removing the `any` check from
// validateReservedApplicationNamesStrict makes every CompileConfig call below
// accept the unreachable definitions instead of rejecting them.
func TestReservedApplicationMatchAllKeywordRejected12048(t *testing.T) {
	for _, tc := range []struct {
		name     string
		commands []string
		kind     string
	}{
		{
			name: "application",
			commands: []string{
				"set applications application any protocol tcp",
				"set applications application any destination-port 80",
			},
			kind: "application",
		},
		{
			name: "application-set",
			commands: []string{
				"set applications application-set any application junos-http",
			},
			kind: "application-set",
		},
		{
			name: "multi-term-application",
			commands: []string{
				"set applications application any term web protocol tcp destination-port 80",
				"set applications application any term dns protocol udp destination-port 53",
			},
			kind: "application-set",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTreeFromSet(t, tc.commands)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatal("CompileConfig: expected rejection of definition named `any`, got nil")
			}
			for _, want := range []string{"reserved", "any", tc.kind, "match application any", "#12048"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("CompileConfig error %q does not name %q", err, want)
				}
			}
		})
	}
}

// FAIL-ON-REVERT: bypassing validateReservedApplicationNamesStrict makes every
// CompileConfig call above accept these definitions, and removing the tolerant
// downgrade makes these calls return an error instead of the named warning.
func TestReservedApplicationMatchAllKeywordLenientWarning12048(t *testing.T) {
	for _, tc := range []struct {
		name     string
		commands []string
	}{
		{
			name: "application",
			commands: []string{
				"set applications application any protocol tcp",
				"set applications application any destination-port 80",
			},
		},
		{
			name: "application-set",
			commands: []string{
				"set applications application-set any application junos-http",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTreeFromSet(t, tc.commands)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient: expected warning and successful load, got %v", err)
			}
			if cfg == nil {
				t.Fatal("CompileConfigLenient: expected non-nil config")
			}
			for _, want := range []string{"reserved application name", "any", "match application any", "#12048"} {
				found := false
				for _, warning := range cfg.Warnings {
					if strings.Contains(warning, want) {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("CompileConfigLenient warnings %q do not name %q", cfg.Warnings, want)
				}
			}
		})
	}
}

func TestReservedApplicationMatchAllKeywordIsCaseSensitive12048(t *testing.T) {
	tree := buildTreeFromSet(t, []string{
		"set applications application ANY protocol tcp",
		"set applications application ANY destination-port 80",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig: exact lowercase `any` is reserved; uppercase ANY should remain distinct, got %v", err)
	}
}
