package config

import (
	"strings"
	"testing"
)

// Repeated clauses must behave like flat set paths: only an explicitly
// repeated leaf replaces an earlier value, never the entire SYN-flood config.
func TestSynFloodRepeated12870(t *testing.T) {
	wantAll := SynFloodConfig{AlarmThreshold: 90, AttackThreshold: 75, SourceThreshold: 30, DestinationThreshold: 60, Timeout: 15}
	cases := []struct {
		name string
		body string
		want SynFloodConfig
	}{
		{"blocks", `syn-flood { attack-threshold 75; source-threshold 30; }
			syn-flood { destination-threshold 60; }
			syn-flood { alarm-threshold 90; timeout 15; }`, wantAll},
		{"lines", `syn-flood attack-threshold 75; syn-flood source-threshold 30;
			syn-flood destination-threshold 60; syn-flood alarm-threshold 90; syn-flood timeout 15;`, wantAll},
		{"reverse_order", `syn-flood { alarm-threshold 90; timeout 15; }
			syn-flood { destination-threshold 60; }
			syn-flood { attack-threshold 75; source-threshold 30; }`, wantAll},
		{"single_block", `syn-flood { alarm-threshold 90; attack-threshold 75;
			source-threshold 30; destination-threshold 60; timeout 15; }`, wantAll},
		{"empty_last", `syn-flood { attack-threshold 75; source-threshold 30; } syn-flood;`,
			SynFloodConfig{AttackThreshold: 75, SourceThreshold: 30}},
		{"empty_first", `syn-flood; syn-flood { attack-threshold 75; source-threshold 30; }`,
			SynFloodConfig{AttackThreshold: 75, SourceThreshold: 30}},
		{"default_attack", `syn-flood { source-threshold 30; } syn-flood { timeout 15; }`,
			SynFloodConfig{AttackThreshold: defaultSynFloodAttackThreshold, SourceThreshold: 30, Timeout: 15}},
		{"last_explicit_leaf_wins", `syn-flood { attack-threshold 75; source-threshold 30; }
			syn-flood { attack-threshold 80; }`,
			SynFloodConfig{AttackThreshold: 80, SourceThreshold: 30}},
	}
	for _, tc := range cases {
		for _, lenient := range []bool{false, true} {
			mode := "strict"
			compile := CompileConfig
			if lenient {
				mode, compile = "lenient", CompileConfigLenient
			}
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				tree := parseHier5180(t, `security { screen {
					ids-option repeated { tcp { `+tc.body+` } }
					ids-option separate { tcp { syn-flood; } }
				} }`)
				cfg, err := compile(tree)
				if err != nil {
					t.Fatalf("compile: %v", err)
				}
				profile := cfg.Security.Screen["repeated"]
				if profile == nil || profile.TCP.SynFlood == nil {
					t.Fatal("repeated SYN-flood profile missing")
				}
				if got := *profile.TCP.SynFlood; got != tc.want {
					t.Errorf("threshold preservation: got %+v, want %+v", got, tc.want)
				}
				other := cfg.Security.Screen["separate"]
				if other == nil || other.TCP.SynFlood == nil {
					t.Fatal("separate SYN-flood profile missing")
				}
				if got := *other.TCP.SynFlood; got != (SynFloodConfig{AttackThreshold: defaultSynFloodAttackThreshold}) {
					t.Errorf("profile isolation: got %+v", got)
				}
				if tc.want == wantAll {
					flat := setTree5180(t, []string{
						"set security screen ids-option repeated tcp syn-flood alarm-threshold 90",
						"set security screen ids-option repeated tcp syn-flood attack-threshold 75",
						"set security screen ids-option repeated tcp syn-flood source-threshold 30",
						"set security screen ids-option repeated tcp syn-flood destination-threshold 60",
						"set security screen ids-option repeated tcp syn-flood timeout 15",
					})
					flatCfg, err := compile(flat)
					if err != nil {
						t.Fatalf("flat compile: %v", err)
					}
					flatProfile := flatCfg.Security.Screen["repeated"]
					if flatProfile == nil || flatProfile.TCP.SynFlood == nil || *flatProfile.TCP.SynFlood != *profile.TCP.SynFlood {
						t.Errorf("hierarchical/flat threshold mismatch: hierarchical %+v, flat %+v", profile, flatProfile)
					}
				}
			})
		}
	}
}

func TestSynFloodRepeatedDiagnostics12870(t *testing.T) {
	for _, bad := range []string{"source-threshold bogus", "source-threshold 0", "unsupported-knob 10"} {
		for _, badFirst := range []bool{false, true} {
			body := "syn-flood { attack-threshold 75; } syn-flood { " + bad + "; }"
			if badFirst {
				body = "syn-flood { " + bad + "; } syn-flood { attack-threshold 75; }"
			}
			t.Run(body, func(t *testing.T) {
				tree := parseHier5180(t, `security { screen { ids-option repeated { tcp { `+body+` } } } }`)
				if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), strings.Fields(bad)[0]) {
					t.Fatalf("strict must reject invalid leaf %q: %v", bad, err)
				}
				cfg, err := CompileConfigLenient(tree)
				if err != nil {
					t.Fatalf("lenient compile must retain diagnostics without bricking: %v", err)
				}
				if !strings.Contains(strings.Join(cfg.Warnings, "\n"), strings.Fields(bad)[0]) {
					t.Errorf("missing invalid-leaf warning: %v", cfg.Warnings)
				}
				profile := cfg.Security.Screen["repeated"]
				if profile == nil || profile.TCP.SynFlood == nil || profile.TCP.SynFlood.AttackThreshold != 75 {
					t.Errorf("invalid clause erased valid attack threshold: %+v", profile)
				}
			})
		}
	}
}
