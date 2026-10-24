package api

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compileRESTDenyConfig11678(t *testing.T, pattern string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, line := range []string{
		"set system login class limited permissions view",
		`set system login class limited deny-commands "` + pattern + `"`,
	} {
		path, quoted, err := config.ParseSetCommandQuoted(line)
		if err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		if err := tree.SetPathQuoted(path, quoted); err != nil {
			t.Fatalf("set %q: %v", line, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile config: %v", err)
	}
	return cfg
}

// #16067: argument-scoped patterns are now ENFORCED on REST (the gate
// reconstructs `show route table secret-vrf` from ?topic=), so the
// commit advisory must stop naming them. A pattern naming no command
// in any spelling keeps its advisory.
func TestRESTArgumentScopedDenyHasCommitAdvisory_11678(t *testing.T) {
	const restSurface = "the REST surface"
	for _, tc := range []struct {
		name         string
		pattern      string
		wantAdvisory bool
	}{
		{
			name:         "argument-scoped deny is now enforced on REST and stays quiet",
			pattern:      `^show route table secret-vrf$`,
			wantAdvisory: false,
		},
		{
			name:         "deny naming no command is named as unenforced on REST",
			pattern:      `^zzz-not-a-command$`,
			wantAdvisory: true,
		},
		{
			name:         "deny matching a REST command stays quiet",
			pattern:      `^show route$`,
			wantAdvisory: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileRESTDenyConfig11678(t, tc.pattern)
			var restAdvisories []string
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, restSurface) && strings.Contains(warning, "REGISTERED command set") {
					restAdvisories = append(restAdvisories, warning)
				}
			}
			if tc.wantAdvisory {
				if len(restAdvisories) != 1 {
					t.Fatalf("unenforceable deny needs exactly one advisory naming REST; got %q", cfg.Warnings)
				}
				for _, want := range []string{"deny-commands", tc.pattern, "on-box CLI"} {
					if !strings.Contains(restAdvisories[0], want) {
						t.Errorf("REST advisory missing %q: %s", want, restAdvisories[0])
					}
				}
			} else if len(restAdvisories) != 0 {
				t.Errorf("REST-enforceable pattern produced false advisory: %q", restAdvisories)
			}
		})
	}
}
