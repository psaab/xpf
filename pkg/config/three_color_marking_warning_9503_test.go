package config

import (
	"strings"
	"testing"
)

// #9503: `then loss-priority` on a three-color policer commits and warns that
// the marking is inert, naming the policer; `then discard` does not warn.
func TestThreeColorMarkingActionWarnsMeterOnly9503(t *testing.T) {
	for _, c := range []struct {
		then string
		warn bool
	}{
		{"loss-priority high", true},
		{"discard", false},
	} {
		tree := &ConfigTree{}
		for _, line := range []string{
			"set firewall three-color-policer pol-9503 single-rate committed-information-rate 1m",
			"set firewall three-color-policer pol-9503 single-rate committed-burst-size 15k",
			"set firewall three-color-policer pol-9503 single-rate excess-burst-size 30k",
			"set firewall three-color-policer pol-9503 then " + c.then,
		} {
			p, err := ParseSetCommand(line)
			if err != nil {
				t.Fatal(err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatal(err)
			}
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("then %s: strict compile refused: %v", c.then, err)
		}
		n := 0
		for _, w := range cfg.Warnings {
			if strings.Contains(w, `three-color-policer "pol-9503"`) && strings.Contains(w, "meters only") {
				n++
			}
		}
		if c.warn && n != 1 {
			t.Errorf("then %s: want one meter-only warning naming the policer, got %d: %q", c.then, n, cfg.Warnings)
		}
		if !c.warn && n != 0 {
			t.Errorf("then %s: a discard policer must not warn: %q", c.then, cfg.Warnings)
		}
	}
}
