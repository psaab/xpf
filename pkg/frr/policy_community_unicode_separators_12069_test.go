package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12069 follow-up (MEDIUM, Codex/Astra hostile review on PR #12322): a
// Unicode separator survives sanitizeFRRValue unchanged, so the renderer must
// reject the malformed community operand and preserve sibling set actions.
func TestPolicyCommunityUnicodeSeparatorsOmitted12069(t *testing.T) {
	for _, tc := range []struct {
		name, separator string
	}{
		{"no-break space", "\u00a0"},
		{"em space", "\u2003"},
		{"line separator", "\u2028"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			term := &config.PolicyTerm{
				Name: "t1", CommunityOp: "add",
				CommunityAdd:    "65000:1" + tc.separator + "65000:2",
				LocalPreference: 200, HasLocalPreference: true, Action: "accept",
			}
			po := &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
				"P": {Name: "P", Terms: []*config.PolicyTerm{term}},
			}}
			got := New().generatePolicyOptions(po)
			if !strings.Contains(got, " set local-preference 200\n") {
				t.Fatalf("sibling set action lost while omitting Unicode-separated community:\n%s", got)
			}
			if strings.Contains(got, "set community") || strings.Contains(got, tc.separator) {
				t.Fatalf("renderer emitted a community operand with unsupported U+%04X separator: %q", []rune(tc.separator)[0], got)
			}
		})
	}
}
