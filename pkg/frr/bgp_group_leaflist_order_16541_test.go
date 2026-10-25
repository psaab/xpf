package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16541 acceptance at the render layer: inline BGP export written as two
// `set` lines `a`, `b` plus group `c` must render the composed route-map
// `a-b-c-xpf-chain` (config.ReservedChainSuffix), not `a-c-b-xpf-chain`.
// The splice happened in pkg/config's group leaf-list union (the first
// same-key sibling won); this pins the end-to-end consequence the issue
// names, through ParseSetCommand + SetPath + CompileConfig + render.

func TestVA03ExportOrderRenderedChain16541(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group ext neighbor 192.0.2.1 peer-as 65002",
		"set protocols bgp group ext export a",
		"set protocols bgp group ext export b",
		"set groups G protocols bgp group ext export c",
		"set apply-groups G",
		"set policy-options policy-statement a term t then accept",
		"set policy-options policy-statement b term t then accept",
		"set policy-options policy-statement c term t then accept",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
		t.Fatalf("compiled BGP = %+v, want exactly one neighbor", cfg.Protocols.BGP)
	}
	if got, want := cfg.Protocols.BGP.Neighbors[0].Export, []string{"a", "b", "c"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("compiled Export = %v, want %v", got, want)
	}

	rendered := New().buildManagedSection(&FullConfig{BGP: cfg.Protocols.BGP, PolicyOptions: &cfg.PolicyOptions})
	const wantChain = "a-b-c" + config.ReservedChainSuffix
	if !strings.Contains(rendered, "neighbor 192.0.2.1 route-map "+wantChain+" out") {
		t.Fatalf("rendered config must reference %q for the neighbor:\n%s", wantChain, rendered)
	}
	const splicedChain = "a-c-b" + config.ReservedChainSuffix
	if strings.Contains(rendered, splicedChain) {
		t.Fatalf("rendered config must NOT contain the spliced chain %q:\n%s", splicedChain, rendered)
	}
	// The composed route-map definition itself must exist under the
	// correctly ordered name.
	if !strings.Contains(rendered, "route-map "+wantChain+" ") {
		t.Fatalf("rendered config must define composed route-map %q:\n%s", wantChain, rendered)
	}
}
