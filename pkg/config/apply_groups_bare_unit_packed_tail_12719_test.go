package config

import (
	"strings"
	"testing"
)

func TestPackedFilterAndMACTailSurvivesBareUnitPeer12719(t *testing.T) {
	for _, tc := range []struct {
		name, groupBody, want string
	}{
		{"filter-interface", `interfaces { ge-0/0/0 unit 0 filter input f; }`, "#12090"},
		{"filter-unit", `interfaces { ge-0/0/0 { unit 0 filter input f; } }`, "#12090"},
		{"mac-interface", `interfaces { ge-0/0/0 unit 0 mac 00:11:22:33:44:55; }`, "#2008 H10"},
		{"mac-unit", `interfaces { ge-0/0/0 { unit 0 mac 00:11:22:33:44:55; } }`, "#2008 H10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := `groups { g { ` + tc.groupBody + ` } } apply-groups g; ` +
				`interfaces { ge-0/0/0 { unit 0; } } ` +
				`firewall { family inet { filter f { term t { then accept; } } } }`
			_, err := CompileConfig(hierTree(t, src))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("strict compile error = %v; want %s rejection", err, tc.want)
			}
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
				t.Fatalf("warnings = %q; want exactly one %s warning", cfg.Warnings, tc.want)
			}
		})
	}
}

func TestPackedUnsupportedTailStillRejectsWithExplicitUnitPeer12719(t *testing.T) {
	for _, tc := range []struct{ name, stmt, want string }{
		{"filter", "filter input f", "#12090"},
		{"mac", "mac 00:11:22:33:44:55", "#2008 H10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := `groups { g { interfaces { ge-0/0/0 { unit 0 ` + tc.stmt + `; } } } } ` +
				`apply-groups g; interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } } ` +
				`firewall { family inet { filter f { term t { then accept; } } } }`
			_, err := CompileConfig(hierTree(t, src))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("strict compile error = %v; want %s rejection", err, tc.want)
			}
		})
	}
}

func TestPackedUnsupportedTailSurvivesNonzeroBareUnitPeer12719(t *testing.T) {
	src := `groups { g { interfaces { ge-0/0/0 unit 7 mac 00:11:22:33:44:55; } } } ` +
		`apply-groups g; interfaces { ge-0/0/0 { unit 7; } }`
	_, err := CompileConfig(hierTree(t, src))
	if err == nil || !strings.Contains(err.Error(), "#2008 H10") {
		t.Fatalf("strict compile error = %v; want #2008 H10 rejection", err)
	}
}

func TestPackedUnitTailPreservesNestedGroupExcept12719(t *testing.T) {
	build := func(except string) *ConfigTree {
		src := `groups { g { apply-groups h; } h { interfaces { ge-0/0/0 unit 0 mac 00:11:22:33:44:55; } } } ` +
			`apply-groups g; interfaces { ge-0/0/0 { ` + except + `unit 0; } }`
		return hierTree(t, src)
	}
	_, err := CompileConfig(build(""))
	if err == nil || !strings.Contains(err.Error(), "#2008 H10") {
		t.Fatalf("strict compile error = %v; want #2008 H10 without exclusion", err)
	}
	if _, err := CompileConfig(build("apply-groups-except h; ")); err != nil {
		t.Fatalf("nested group's excluded MAC tail was not filtered: %v", err)
	}
}
