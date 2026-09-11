package userspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #9415 members 1 and 3: operator-facing text that described a posture the
// code no longer has.
//
// Member 1: the per-zone line of both `show security screen` status blocks said
// "no screen checks are enforced for this zone", while the Disposition printed
// two lines below said the dataplane enforces a substituted conservative
// default (#7168, #7888). The Disposition is the true one
// (userspace-dp/src/screen/unresolved.rs missing_profile_verdict). A reader of
// the first line alone concludes "unprotected", and deleting the `screen`
// statement to "fix" it really would leave the zone unprotected.
func TestScreenStatusBlocksDoNotClaimNoChecks_9415(t *testing.T) {
	cases := []struct {
		name        string
		lines       []string
		disposition string
	}{
		{
			name: "unresolved",
			lines: ScreenUnresolvedProfileLines(compileScreenCfgLenient7059(t, []string{
				"set security screen ids-option wan-screen tcp land",
				"set security zones security-zone trust screen wan-scren",
			})),
			disposition: ScreenUnresolvedDisposition,
		},
		{
			name: "inert",
			lines: ScreenInertProfileLines(compileScreenCfg7059(t, []string{
				"set security screen ids-option p alarm-without-drop",
				"set security zones security-zone trust screen p",
			})),
			disposition: ScreenInertDisposition,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			block := strings.Join(c.lines, "\n")
			if block == "" {
				t.Fatal("precondition: the fixture must render a status block")
			}
			if strings.Contains(block, "no screen checks are enforced") {
				t.Errorf("the per-zone line still claims no checks are enforced, which the "+
					"Disposition below contradicts:\n%s", block)
			}
			for _, want := range []string{"none of its configured checks are in effect", c.disposition} {
				if !strings.Contains(block, want) {
					t.Errorf("block missing %q:\n%s", want, block)
				}
			}
		})
	}
}

// Member 3: docs/syn-cookie-flood-protection.md said cookie replies bypass output
// filters, CoS classification and DSCP rewrite. Since #2238 cookie_reply.rs runs
// classify_generated_reply and bypasses only mirroring. A future change that
// "aligned the code to the doc" would reopen the #2238 bypass.
func TestSynCookieDocDescribesClassifiedReplies_9415(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "syn-cookie-flood-protection.md"))
	if err != nil {
		t.Fatalf("read doc: %v", err)
	}
	doc := strings.Join(strings.Fields(string(b)), " ")
	if strings.Contains(doc, "intentionally bypass output filters") {
		t.Error("the doc still claims cookie replies bypass output filters, CoS and DSCP")
	}
	for _, want := range []string{"#2238", "classify_generated_reply", "Only mirroring is bypassed"} {
		if !strings.Contains(doc, want) {
			t.Errorf("the cookie-reply paragraph must carry %q", want)
		}
	}
}
