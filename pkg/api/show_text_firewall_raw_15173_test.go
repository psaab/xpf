package api

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/firewallshow"
)

// #15173 (B18-02): the REST show-text `firewall` topic rendered only
// protocol / destination-port / source-address / dscp and omitted the
// action entirely for empty-action terms. It must now be byte-equal to
// the shared raw renderer the gRPC surface uses.

func TestAPIShowTextFirewallRawByteEqual15173(t *testing.T) {
	s := stageShowTextConfig(t, []string{
		"set firewall family inet filter edge term ssh-only from protocol tcp",
		"set firewall family inet filter edge term ssh-only from destination-port-except 22",
		"set firewall family inet filter edge term ssh-only then discard",
		"set firewall family inet filter edge term pass-on from protocol tcp",
		"set firewall family inet filter edge term pass-on then count hits",
		"set firewall family inet filter edge term pass-on then next term",
		"set firewall family inet filter edge term count-only from protocol udp",
		"set firewall family inet filter edge term count-only then count hits",
		"set firewall family inet filter edge term frag from is-fragment",
		"set firewall family inet filter edge term frag then reject tcp-reset",
	})
	out := renderShowTextBody(t, s, "firewall")

	var want strings.Builder
	firewallshow.WriteAllFilters(&want, s.store.ActiveConfig())
	if out != want.String() {
		t.Fatalf("REST firewall output is not byte-equal to the shared renderer.\nREST:\n%s\nwant:\n%s", out, want.String())
	}
	for _, needle := range []string{
		"    from destination-port-except 22\n",
		"    then next term\n",
		"    from is-fragment\n",
		"    then reject tcp-reset\n",
	} {
		if !strings.Contains(out, needle) {
			t.Errorf("REST firewall missing %q:\n%s", needle, out)
		}
	}
	// The fall-through term must not read as an accept.
	passIdx := strings.Index(out, "  Term: pass-on\n")
	if passIdx < 0 {
		t.Fatalf("pass-on term missing:\n%s", out)
	}
	passBlock := out[passIdx:]
	if idx := strings.Index(passBlock, "\n  Term: "); idx >= 0 {
		passBlock = passBlock[:idx]
	}
	if strings.Contains(passBlock, "then accept") {
		t.Errorf("REST fall-through term rendered as accept:\n%s", passBlock)
	}
}
