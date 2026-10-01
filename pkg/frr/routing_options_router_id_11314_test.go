package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestGlobalRoutingOptionsRouterIDReachesFRR11314(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, line := range []string{
		"set routing-options router-id 10.255.0.1",
		"set routing-options autonomous-system 65000",
		"set protocols bgp local-as 65000",
	} {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	compiled, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	rendered := New().generateProtocols(nil, nil, compiled.Protocols.BGP, nil, nil, "", 0, nil, nil)
	if !strings.Contains(rendered, "bgp router-id 10.255.0.1") {
		t.Fatalf("global routing-options router-id did not reach FRR BGP config:\n%s", rendered)
	}
}
