package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14687: the typed-leaf arm of the judged-vs-executed differential.
// `show firewall filter secret family` judged that string, but the
// dispatcher needs len>=5 to read a family, so it ran
// showFirewallFilter("secret",""). An anchored deny on either form missed.
func TestAnchoredDenyDanglingTypedLeaf14687(t *testing.T) {
	for _, tc := range []struct {
		deny   string
		line   string
		denied bool
		why    string
	}{
		{"^show firewall filter secret$", "show firewall filter secret", true, "positive control"},
		{"^show firewall filter secret$", "show firewall filter secret family", true, "dangling family: pre-fix judged the 5-word string and ran the 4-word command"},
		{"^show firewall filter secret family inet$", "show firewall filter secret family", true, "dangling family also defeats the family-qualified deny"},
		{"^show firewall filter secret$", "show firewall filter secret family inet", false, "complete family form is a distinct command"},
		{"^show firewall filter secret$", "show firewall filter other", false, "negative control"},
		{"^show firewall$", "show firewall filter", true, "dangling filter selector fails closed for a restricted class"},
		{"^show security screen$", "show security screen ids-option", true, "dangling ids-option fails closed"},
		{"^show security screen$", "show security screen ids-option prof1", false, "complete ids-option is a distinct, narrower command"},
		{"^show route table secret-vrf$", "show route table", true, "dangling dynamic table fails closed"},
	} {
		rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, "", false, tc.deny, true)
		if err != nil {
			t.Fatalf("compile deny %q: %v", tc.deny, err)
		}
		err = evaluateCommandRegex(rules, "restricted", tc.line, "")
		if tc.denied && err == nil {
			t.Errorf("deny=%q line=%q: ALLOWED, want denied — %s", tc.deny, tc.line, tc.why)
		}
		if !tc.denied && err != nil {
			t.Errorf("deny=%q line=%q: denied (%v), want allowed — %s", tc.deny, tc.line, err, tc.why)
		}
	}
}
