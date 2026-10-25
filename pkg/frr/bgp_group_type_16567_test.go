package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16567 acceptance render row: `type internal` without peer-as compiles
// (PeerAS derived from the local AS) and renders `remote-as 65000`.
func TestBGPGroupTypeInternalRendersRemoteAS16567(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set routing-options autonomous-system 65000",
		"set protocols bgp group ibgp type internal",
		"set protocols bgp group ibgp neighbor 10.0.2.3",
	} {
		toks, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("parse %q: %v", cmd, err)
		}
		if err := tree.SetPath(toks); err != nil {
			t.Fatalf("set %q: %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	out := New().generateProtocols(nil, nil, cfg.Protocols.BGP, nil, nil, "", 0, nil, nil)
	if !strings.Contains(out, "neighbor 10.0.2.3 remote-as 65000\n") {
		t.Fatalf("expected remote-as 65000 for derived iBGP peer, got:\n%s", out)
	}
}
