package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #17833 render leg: bgp-level multihop — the third Junos hierarchy
// level of the #16679 contract — must reach FRR as
// `neighbor X ebgp-multihop <ttl>`. Before the fix the statement
// committed on the open-world bgp subtree behind only the generic
// #10707 advisory and rendered NOTHING: every inherited session ran
// at the FRR eBGP direct default.
func TestBGPMultihopBGPLevelRender17833(t *testing.T) {
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
		{"bgp-level bare default", `protocols { bgp { local-as 65001; multihop; group G { peer-as 65002; neighbor 10.0.0.1; } } }`, "neighbor 10.0.0.1 ebgp-multihop 64\n"},
		{"bgp-level ttl inherited", `protocols { bgp { local-as 65001; multihop { ttl 4; } group G { peer-as 65002; neighbor 10.0.0.1; } } }`, "neighbor 10.0.0.1 ebgp-multihop 4\n"},
		{"neighbor overrides bgp-level", `protocols { bgp { local-as 65001; multihop { ttl 4; } group G { peer-as 65002; neighbor 10.0.0.1 { multihop { ttl 9; } } } } }`, "neighbor 10.0.0.1 ebgp-multihop 9\n"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got := render(t, row.src)
			if !strings.Contains(got, row.want) {
				t.Errorf("%s: rendered section missing %q:\n%s", row.name, row.want, got)
			}
		})
	}
}
