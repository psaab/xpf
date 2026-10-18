package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14688: exact-anchored denies/allows must not be evaded by post-dynamic
// siblings or repeated CoS keys.
func TestAnchoredDenyPostDynamic14688(t *testing.T) {
	for _, tc := range []struct {
		deny, line string
		wantDeny   bool
		why        string
	}{
		{"^show interfaces ge-0/0/0$", "show interfaces ge-0/0/0", true, "positive control"},
		{"^show interfaces ge-0/0/0$", "show interfaces ge-0/0/0 terse", true, "post-dynamic terse evades exact deny if canonicalized"},
		{"^show interfaces ge-0/0/0$", "show interfaces ge-0/0/0 queue", true, "post-dynamic queue"},
		{"^show interfaces ge-0/0/0$", "show interfaces ge-0/0/0 detail", false, "detail honours selector, distinct command"},
		{"^show class-of-service classifier public-cls$", "show class-of-service classifier public-cls name secret-cls", true, "repeated name overwrites judged value"},
		{"^show security zones trust$", "show security zones trust terse", true, "post-dynamic terse"},
	} {
		rules := denyRules(t, tc.deny)
		err := evaluateCommandRegex(rules, "restricted", tc.line, "")
		if (err != nil) != tc.wantDeny {
			t.Errorf("deny=%q line=%q: denied=%v want %v (%s) err=%v", tc.deny, tc.line, err != nil, tc.wantDeny, tc.why, err)
		}
	}
	allowRules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily, "^show class-of-service classifier public-cls.*", true, "", false)
	if err != nil {
		t.Fatalf("compile allow: %v", err)
	}
	if err := evaluateCommandRegex(allowRules, "restricted", "show class-of-service classifier public-cls name secret-cls", ""); err == nil {
		t.Errorf("prefix allow for public-cls granted overwritten secret-cls command")
	}
	if err := evaluateCommandRegex(allowRules, "restricted", "show class-of-service classifier public-cls", ""); err != nil {
		t.Errorf("prefix allow control public-cls must pass: %v", err)
	}
}
