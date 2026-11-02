package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #18762: the elided `tcp-session rst-sequence-check;` spelling committed clean
// but compiled RstSequenceCheck=false, so the flow snapshot the helper enforces
// carried false. This pins the compile -> snapshot reach for every spelling of
// the tcp-session security flags, not just the typed config.
func TestFlowSnapshotCarriesElidedTCPSessionFlags18762(t *testing.T) {
	compile := func(t *testing.T, text string) *config.Config {
		t.Helper()
		tree, perrs := config.NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse %q: %v", text, perrs)
		}
		cfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("compile %q: %v", text, err)
		}
		return cfg
	}
	for _, flag := range []struct {
		leaf string
		get  func(FlowSnapshot) bool
	}{
		{"rst-sequence-check", func(s FlowSnapshot) bool { return s.TCPRstSequenceCheck }},
		{"strict-syn-check", func(s FlowSnapshot) bool { return s.TCPStrictSynCheck }},
	} {
		for _, text := range []string{
			`security { flow { tcp-session { ` + flag.leaf + `; } } }`,
			`security { flow { tcp-session ` + flag.leaf + `; } }`,
			`security { flow tcp-session ` + flag.leaf + `; }`,
		} {
			if !flag.get(buildFlowSnapshot(compile(t, text))) {
				t.Errorf("%q committed but the flow snapshot carries %s=false", text, flag.leaf)
			}
		}
		if flag.get(buildFlowSnapshot(compile(t, `security { flow { tcp-session { no-sequence-check; } } }`))) {
			t.Errorf("control: an unrelated tcp-session flag set %s in the snapshot", flag.leaf)
		}
	}
}
