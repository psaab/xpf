package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestQualifiedNextHopInterfaceBackupRendersTunnelRoute12909 is the
// compile-to-render cell for #12909: a floating backup authored as
// `qualified-next-hop st0.0 preference 200` must compile to an
// interface-only entry and render an interface route at its own admin
// distance on the tunnel device. Before #12909 the tunnel name sat in
// NextHopEntry.Address, which validFRRNextHopAddress discards (not an IP) —
// the backup line was silently dropped from the FRR config.
func TestQualifiedNextHopInterfaceBackupRendersTunnelRoute12909(t *testing.T) {
	src := `routing-options {
		static {
			route 10.9.0.0/16 {
				next-hop 10.0.0.1;
				qualified-next-hop st0.0 { preference 200; }
			}
		}
	}`
	tree, parseErrors := config.NewParser(src).Parse()
	if len(parseErrors) != 0 {
		t.Fatalf("parse static routes: %v", parseErrors)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile static routes: %v", err)
	}
	if len(cfg.RoutingOptions.StaticRoutes) != 1 {
		t.Fatalf("static routes = %+v, want exactly one", cfg.RoutingOptions.StaticRoutes)
	}
	declared := map[string]string{"st0.0": "st0.0"}
	m := New()
	managed := m.buildManagedSection(&FullConfig{
		StaticRoutes:    cfg.RoutingOptions.StaticRoutes,
		DeclaredNetdevs: declared,
	})
	for _, want := range []string{
		"ip route 10.9.0.0/16 10.0.0.1 5\n",
		"ip route 10.9.0.0/16 st0.0 200\n",
	} {
		if !strings.Contains(managed, want) {
			t.Errorf("managed section missing %q:\n%s", want, managed)
		}
	}
}
