package configstore

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9656 (M40): a security-zone group must meet the SAME commit gate as the
// longhand spelling, one statement per zone. Measured through CheckText at
// e09f425dd:
//
//	security-zone [ zga zgb ] screen edge;   committed, zga with no screen, no zgb
//	security-zone [ zga zgb ];               committed, no zgb; a policy naming zgb was refused
//	security-zone [ zga zgb ] { }            committed, no zgb
//	security-zone [ zga zgb ] apply-groups G;       committed, no zgb, and zga without the group
//	security-zone [ zga zgb ] { apply-groups G; }   committed, no zgb, and zga without the group
//
// Each cell requires the two spellings to reach the same verdict and to
// compile identically on the lenient path. It also checks substrings that both
// lenient compiles must carry, so a change that broke both spellings the same
// way cannot pass.
func TestZoneGroupMeetsTheLonghandCommitGate9656(t *testing.T) {
	const screens = `security { screen { ids-option edge { icmp { ping-death; } } } } `
	const policy = `security { policies { from-zone zgb to-zone zga { policy p { match { source-address any; destination-address any; application any; } then { permit; } } } } } `
	const groupG = `groups { G { security { zones { security-zone <*> { tcp-rst; } } } } } `
	zones := func(body string) string { return `security { zones { ` + body + ` } }` }
	cells := []struct {
		name, group, longhand string
		refusal               string // substring both refusals must name; "" means both must commit
		has                   []string
	}{
		{
			name:     "packed body",
			group:    screens + zones(`security-zone [ zga zgb ] screen edge;`),
			longhand: screens + zones(`security-zone zga { screen edge; } security-zone zgb { screen edge; }`),
			has:      []string{`"zgb":{"Name":"zgb"`, `"ScreenProfile":"edge"`},
		},
		{
			name:     "bare leaf, with a policy naming zgb",
			group:    policy + zones(`security-zone [ zga zgb ];`),
			longhand: policy + zones(`security-zone zga; security-zone zgb;`),
			has:      []string{`"zgb":{"Name":"zgb"`},
		},
		{
			name:     "braced empty body",
			group:    zones(`security-zone [ zga zgb ] { }`),
			longhand: zones(`security-zone zga { } security-zone zgb { }`),
			has:      []string{`"zgb":{"Name":"zgb"`},
		},
		{
			name:     "packed apply-groups",
			group:    groupG + zones(`security-zone [ zga zgb ] apply-groups G;`),
			longhand: groupG + zones(`security-zone zga { apply-groups G; } security-zone zgb { apply-groups G; }`),
			has:      []string{`"zgb":{"Name":"zgb"`, `"TCPRst":true`},
		},
		{
			name:     "braced apply-groups",
			group:    groupG + zones(`security-zone [ zga zgb ] { apply-groups G; }`),
			longhand: groupG + zones(`security-zone zga { apply-groups G; } security-zone zgb { apply-groups G; }`),
			has:      []string{`"zgb":{"Name":"zgb"`, `"TCPRst":true`},
		},
		{
			name:     "packed body naming an undefined screen",
			group:    zones(`security-zone [ zga zgb ] screen missing;`),
			longhand: zones(`security-zone zga { screen missing; } security-zone zgb { screen missing; }`),
			refusal:  "missing",
		},
	}
	for _, c := range cells {
		t.Run(c.name, func(t *testing.T) {
			_, gerr := CheckText(c.group, -1)
			_, lerr := CheckText(c.longhand, -1)
			if c.refusal != "" {
				if lerr == nil || !strings.Contains(lerr.Error(), c.refusal) {
					t.Errorf("CONTROL longhand %q: want a refusal naming %q, got %v", c.longhand, c.refusal, lerr)
				}
				if gerr == nil || !strings.Contains(gerr.Error(), c.refusal) {
					t.Errorf("group %q: want the longhand's refusal naming %q, got %v (#9656)", c.group, c.refusal, gerr)
				}
				return
			}
			if lerr != nil {
				t.Errorf("CONTROL longhand %q: want a commit, got %v", c.longhand, lerr)
			}
			if gerr != nil {
				t.Errorf("group %q: want a commit, as the longhand gets; got %v (#9656)", c.group, gerr)
			}
			gj := lenientJSON9656(t, "group", c.group)
			lj := lenientJSON9656(t, "longhand", c.longhand)
			if gj == "" || lj == "" {
				return
			}
			for _, want := range c.has {
				if !strings.Contains(lj, want) {
					t.Errorf("CONTROL longhand %q: lenient compile lacks %s", c.longhand, want)
				}
				if !strings.Contains(gj, want) {
					t.Errorf("group %q: lenient compile lacks %s, which the longhand carries (#9656)", c.group, want)
				}
			}
			if gj != lj {
				t.Errorf("group %q and longhand %q compile differently on the lenient path (#9656)", c.group, c.longhand)
			}
		})
	}
}

// lenientJSON9656 compiles text on the lenient path the boot and HA-sync
// loaders use. It renders the result without warnings.
func lenientJSON9656(t *testing.T, label, text string) string {
	t.Helper()
	tree, perrs := config.NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Errorf("%s %q: fixture must parse: %v", label, text, perrs)
		return ""
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Errorf("%s %q: lenient compile: %v", label, text, err)
		return ""
	}
	cfg.Warnings = nil
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Errorf("%s %q: marshal: %v", label, text, err)
		return ""
	}
	return string(b)
}
