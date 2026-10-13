package config

import (
	"strings"
	"testing"
)

func TestPackedApplyGroupUnsupportedTailSurvivesInlinePeer12530(t *testing.T) {
	for _, tc := range []struct {
		name, tail, want string
	}{
		{"filter", "filter input f", "#12090"},
		{"unit-mac", "mac 00:11:22:33:44:55", "#2008 H10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := `groups { g { interfaces { ge-0/0/0 { unit 0 ` + tc.tail + `; } } } } ` +
				`apply-groups g; interfaces { ge-0/0/0 { unit 0 { ` +
				`family inet { address 10.0.0.1/24; } } } }`
			if tc.want == "#12090" {
				src += ` firewall { family inet { filter f { term t { then accept; } } } }`
			}
			assertCommitRejects(t, hierTree(t, src), tc.want)

			cfg, err := CompileConfigLenient(hierTree(t, src))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			count := 0
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, tc.want) {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("lenient warnings = %q; want exactly one %s warning", cfg.Warnings, tc.want)
			}
		})
	}
}

func TestPackedApplyGroupFilterTailWithoutInlinePeerStillRejected12530(t *testing.T) {
	src := `groups { g { interfaces { ge-0/0/0 { unit 0 filter input f; } } } } ` +
		`apply-groups g; interfaces { ge-0/0/0 { description inline; } } ` +
		`firewall { family inet { filter f { term t { then accept; } } } }`
	assertCommitRejects(t, hierTree(t, src), "#12090")
	assertLenientWarns(t, hierTree(t, src), "#12090")
}
