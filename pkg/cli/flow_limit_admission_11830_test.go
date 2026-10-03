package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #11830: the dispatcher accepts each spelling, but the old command tree
// rejected its trailing limit as CanonicalUnknown. A restricted class fails
// closed on that uncertainty, so the lawful diagnostic was inaccessible.
func TestRestrictedClassCanRunFlowLimitSpellings11830(t *testing.T) {
	rules, err := config.CompileLoginRegexes(
		config.LoginRegexPlainFamily,
		`^show chassis cluster data-plane flows (limit 10|10|limit=10)$`, true,
		"", false,
	)
	if err != nil {
		t.Fatalf("CompileLoginRegexes: %v", err)
	}
	for _, command := range []string{
		"show chassis cluster data-plane flows limit 10",
		"show chassis cluster data-plane flows 10",
		"show chassis cluster data-plane flows limit=10",
	} {
		if err := evaluateCommandRegex(rules, "restricted", command, ""); err != nil {
			t.Errorf("restricted class refused dispatcher-legal command %q: %v", command, err)
		}
	}
}
