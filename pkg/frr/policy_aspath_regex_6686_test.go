package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6686 render-side belt. The strict commit gate hard-rejects an as-path
// whose regex is empty or malformed, but the tolerant load / peer-sync
// paths downgrade that to a warning (#1960 no-brick), so such a definition
// CAN reach the renderer on an already-persisted config. It must not be
// emitted: `bgp as-path access-list AP1 permit` with no argument is an
// incomplete FRR command and `(((` fails regcomp, and a single
// CMD_WARNING_CONFIG_FAILED exits the whole vtysh add-batch non-zero —
// failing the ENTIRE frr-reload, not just this list.

func aspathPO(t *testing.T, name, regex string) *config.PolicyOptionsConfig {
	t.Helper()
	return &config.PolicyOptionsConfig{
		ASPaths: map[string]*config.ASPathDef{
			name: {Name: name, Regex: regex},
		},
	}
}

// TestASPathRender6686EmitsAMultiTokenRegex is the positive control: a
// legitimate transit regex with spaces MUST still render, whole and
// TRANSLATED (#15007): Junos "." is one AS token, the match is implicitly
// anchored, so the FRR line carries ^...$ over [0-9]+ tokens. FRR's
// `bgp as-path access-list` DEFUN ends in a variadic `LINE...` that
// argv_concat rejoins with single spaces, which is what makes a multi-AS
// pattern expressible at all — so the belt must not treat a space as
// unrenderable.
func TestASPathRender6686EmitsAMultiTokenRegex(t *testing.T) {
	got := New().generatePolicyOptions(aspathPO(t, "AP1", `.* 65000 .*`))
	if !strings.Contains(got, "bgp as-path access-list AP1 permit ^(([0-9]+( [0-9]+)*) )?65000( ([0-9]+( [0-9]+)*))?$\n") {
		t.Fatalf("multi-token as-path regex not rendered whole:\n%s", got)
	}
}

// TestASPathRender6686OmitsUnrenderableRegexes is the belt itself.
//
// FAIL-ON-REVERT: deleting the ValidASPathRegex `continue` from
// generatePolicyOptions emits `bgp as-path access-list AP1 permit` (and
// `... permit (((`), which reds here.
func TestASPathRender6686OmitsUnrenderableRegexes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		regex string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"malformed", "((("},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := New().generatePolicyOptions(aspathPO(t, "AP1", tc.regex))
			if strings.Contains(got, "bgp as-path access-list AP1") {
				t.Fatalf("unrenderable as-path (%s) reached frr.conf — the line "+
					"fails frr-reload and takes the WHOLE reload down:\n%s", tc.name, got)
			}
		})
	}
}
