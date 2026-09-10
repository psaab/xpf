package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9574: the compiled config keeps `any-ipv4` / `any-ipv6`, so the detail view
// renders the family line the `any` arm renders instead of treating the keyword
// as a name.
func TestPolicyDetailRendersFamilyKeywords9574(t *testing.T) {
	cfg := &config.Config{}
	pol := &config.Policy{Match: config.PolicyMatch{
		SourceAddresses:      []string{"any-ipv4"},
		DestinationAddresses: []string{"any-ipv6"},
	}}
	out := captureStdout(t, func() { printPolicyMatchAddresses(cfg, pol) })
	for _, want := range []string{"any-ipv4(global): 0.0.0.0/0", "any-ipv6(global): ::/0"} {
		if !strings.Contains(out, want) {
			t.Errorf("detail output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "any-ipv4(global): any-ipv4") {
		t.Errorf("the keyword was rendered as an unresolved name:\n%s", out)
	}
}
