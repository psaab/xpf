package config

import (
	"fmt"
	"testing"
)

func TestSnmpDiff8768(t *testing.T) {
	const packed = `snmp { community public { authorization read-only; } trap-group tg1 targets 10.0.0.1 version v2; }`
	const braced = `snmp { community public { authorization read-only; } trap-group tg1 { targets 10.0.0.1; version v2; } }`
	get := func(label, txt string) string {
		tr, perrs := NewParser(txt).Parse()
		if len(perrs) > 0 {
			return "<parse err>"
		}
		cfg, err := compileTree(tr, lenientCompileOpts(), nil)
		if err != nil || cfg == nil || cfg.System.SNMP == nil {
			return fmt.Sprintf("<err %v>", err)
		}
		out := ""
		for _, g := range cfg.System.SNMP.TrapGroups {
			out += fmt.Sprintf("targets=%v version=%q", g.Targets, g.Version)
		}
		return out
	}
	p := get("packed", packed)
	b := get("braced", braced)
	t.Logf("PACKED %s", p)
	t.Logf("BRACED %s", b)
	if p != b {
		t.Errorf("the two spellings must compile identically (#8768)")
	}
}
