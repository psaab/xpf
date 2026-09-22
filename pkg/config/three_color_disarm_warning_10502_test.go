package config

import (
	"strings"
	"testing"
)

// #10502: a color-aware three-color policer disarms ALL transit
// (ForwardingSupported=false) while the commit returns zero warnings. The
// warning-only fix names each disarming definition at commit (referenced or
// not — the gate is still definition-wide).

func compileThreeColorDisarm10502(t *testing.T, lenient bool, lines ...string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		p, err := ParseSetCommand(line)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatal(err)
		}
	}
	if lenient {
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile refused: %v", err)
		}
		return cfg
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile refused: %v", err)
	}
	return cfg
}

func countDisarmWarnings10502(warnings []string, name string) int {
	n := 0
	for _, w := range warnings {
		if strings.Contains(w, `three-color-policer "`+name+`"`) && strings.Contains(w, "transit will STOP") {
			n++
		}
	}
	return n
}

func TestThreeColorDisarmWarning10502(t *testing.T) {
	base := []string{
		"set firewall three-color-policer p1 single-rate committed-information-rate 1m",
		"set firewall three-color-policer p1 single-rate committed-burst-size 15k",
		"set firewall three-color-policer p1 single-rate excess-burst-size 30k",
		"set firewall three-color-policer p1 then discard",
	}
	attach := []string{
		"set firewall family inet filter f1 term t1 then policer p1",
		"set firewall family inet filter f1 term t1 then accept",
	}
	for _, c := range []struct {
		name    string
		lines   []string
		lenient bool
		want    int
	}{
		{"unreferenced color-aware warns", append(append([]string{}, base...), "set firewall three-color-policer p1 single-rate color-aware"), false, 1},
		{"attached color-aware warns", append(append(append([]string{}, base...), "set firewall three-color-policer p1 single-rate color-aware"), attach...), false, 1},
		{"unreferenced color-blind silent", append(append([]string{}, base...), "set firewall three-color-policer p1 single-rate color-blind"), false, 0},
		{"attached color-blind silent", append(append(append([]string{}, base...), "set firewall three-color-policer p1 single-rate color-blind"), attach...), false, 0},
		{"unspecified color silent", append([]string{}, base...), false, 0},
		{"lenient unreferenced color-aware warns", append(append([]string{}, base...), "set firewall three-color-policer p1 single-rate color-aware"), true, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg := compileThreeColorDisarm10502(t, c.lenient, c.lines...)
			if got := countDisarmWarnings10502(cfg.Warnings, "p1"); got != c.want {
				t.Errorf("disarm warnings naming p1 = %d, want %d: %q", got, c.want, cfg.Warnings)
			}
			if c.want == 1 {
				joined := strings.Join(cfg.Warnings, "\n")
				if !strings.Contains(joined, "color-aware") {
					t.Errorf("disarm warning must name the reason (color-aware): %q", cfg.Warnings)
				}
			}
		})
	}
}
