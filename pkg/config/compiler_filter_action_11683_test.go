package config

import (
	"strings"
	"testing"
)

func TestFilterAction_UnkeyedRejectPreservesNestedCount11683(t *testing.T) {
	spellings := []struct {
		name  string
		build func(*testing.T) *ConfigTree
	}{
		{
			name: "flat-set chain",
			build: func(t *testing.T) *ConfigTree {
				return flatTreeFromSets(t,
					"set firewall family inet filter f1 term t1 from protocol tcp",
					"set firewall family inet filter f1 term t1 then reject count c1",
				)
			},
		},
		{
			name: "hierarchical nested reject",
			build: func(t *testing.T) *ConfigTree {
				return hierTree(t, `firewall { family inet { filter f1 { term t1 {
					from { protocol tcp; } then { reject { count c1; } }
				} } } }`)
			},
		},
		{
			name: "packed line",
			build: func(t *testing.T) *ConfigTree {
				return hierTree(t, `firewall { family inet { filter f1 { term t1 {
					from { protocol tcp; } then reject count c1;
				} } } }`)
			},
		},
		{
			name: "hierarchical siblings",
			build: func(t *testing.T) *ConfigTree {
				return hierTree(t, `firewall { family inet { filter f1 { term t1 {
					from { protocol tcp; } then { reject; count c1; }
				} } } }`)
			},
		},
	}

	assertRejectCount := func(t *testing.T, cfg *Config) {
		t.Helper()
		term := cfg.Firewall.FiltersInet["f1"].Terms[0]
		if term.Action != "reject" || term.RejectMessageType != "" ||
			term.Count != "c1" || len(term.UnknownActions) != 0 {
			t.Fatalf("compiled action=%q message=%q count=%q unknown=%v; want unkeyed reject, c1, no unknown actions",
				term.Action, term.RejectMessageType, term.Count, term.UnknownActions)
		}
	}

	for _, tc := range spellings {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(tc.build(t))
			if err != nil {
				t.Fatalf("strict compile rejected valid unkeyed reject/count: %v", err)
			}
			assertRejectCount(t, cfg)

			cfg, err = CompileConfigLenient(tc.build(t))
			if err != nil {
				t.Fatalf("lenient compile rejected valid unkeyed reject/count: %v", err)
			}
			assertRejectCount(t, cfg)
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "firewall filter action") {
					t.Fatalf("valid unkeyed reject/count emitted action warning: %v", cfg.Warnings)
				}
			}
		})
	}
}

func TestFilterAction_UnknownUnkeyedRejectChildStillRejected11683(t *testing.T) {
	spellings := []struct {
		name  string
		build func(*testing.T) *ConfigTree
	}{
		{
			name: "packed typo",
			build: func(t *testing.T) *ConfigTree {
				return flatTreeFromSets(t,
					"set firewall family inet filter f1 term t1 from protocol tcp",
					"set firewall family inet filter f1 term t1 then reject blorp",
				)
			},
		},
		{
			name: "nested typo",
			build: func(t *testing.T) *ConfigTree {
				return hierTree(t, `firewall { family inet { filter f1 { term t1 {
					from { protocol tcp; } then { reject { blorp; } }
				} } } }`)
			},
		},
	}
	for _, tc := range spellings {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(tc.build(t))
			if err == nil || !strings.Contains(err.Error(), "blorp") {
				t.Fatalf("strict compile error = %v, want rejection naming blorp", err)
			}
		})
	}
}
