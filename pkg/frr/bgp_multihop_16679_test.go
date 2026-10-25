package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16679 render leg: the Junos multihop spellings must render
// `neighbor X ebgp-multihop <ttl>`; the bare form renders the Junos
// default TTL 64. Before the fix only `multihop <N>` compiled at all.
func TestBGPMultihopSpellingsRender16679(t *testing.T) {
	render := func(t *testing.T, src string) string {
		t.Helper()
		tree, perrs := config.NewParser(src).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		if err := config.SchemaValidate(tree); err != nil {
			t.Fatalf("SchemaValidate: %v", err)
		}
		cfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		return New().buildManagedSection(&FullConfig{BGP: cfg.Protocols.BGP, PolicyOptions: &cfg.PolicyOptions})
	}
	rows := []struct {
		name string
		src  string
		want string
	}{
		{"scalar control", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop 2; neighbor 10.0.0.1; } } }`, "neighbor 10.0.0.1 ebgp-multihop 2\n"},
		{"bare default", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop; neighbor 10.0.0.1; } } }`, "neighbor 10.0.0.1 ebgp-multihop 64\n"},
		{"ttl blocked", `protocols { bgp { local-as 65001; group G { peer-as 65002; multihop { ttl 5; } neighbor 10.0.0.1; } } }`, "neighbor 10.0.0.1 ebgp-multihop 5\n"},
		{"neighbor ttl blocked", `protocols { bgp { local-as 65001; group G { peer-as 65002; neighbor 10.0.0.1 { multihop { ttl 9; } } } } }`, "neighbor 10.0.0.1 ebgp-multihop 9\n"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got := render(t, row.src)
			if !strings.Contains(got, row.want) {
				t.Errorf("%s: rendered section missing %q:\n%s", row.name, row.want, got)
			}
		})
	}
	// Control: no multihop renders no ebgp-multihop line.
	got := render(t, `protocols { bgp { local-as 65001; group G { peer-as 65002; neighbor 10.0.0.1; } } }`)
	if strings.Contains(got, "ebgp-multihop") {
		t.Errorf("no-multihop control must render no ebgp-multihop line:\n%s", got)
	}
}
