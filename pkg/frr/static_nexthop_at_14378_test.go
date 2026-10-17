package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14378 (DR4-H6): strict-compiled `next-hop 10.0.0.1@eth0` / `@eth0`
// must render in the FRR managed section. Pre-fix the compiler stored
// the raw '@' scalar in Address, validFRRNextHopAddress rejected it,
// and the renderer silently emitted no line while the userspace FIB
// installed the route.
//
// RED pre-fix: no `ip route 192.0.2.0/24 ...` / `198.51.100.0/24 ...` lines.
func TestStaticNextHopAtInterfaceRendersFRR_14378(t *testing.T) {
	// Flat `set` cannot spell '@' (lexer), so author hierarchically quoted.
	tree, perrs := config.NewParser(`
routing-options {
    static {
        route 192.0.2.0/24 { next-hop "10.0.0.1@eth0"; }
        route 198.51.100.0/24 { next-hop "@eth0"; }
        route 203.0.113.0/24 { next-hop 10.0.0.1; }
    }
}`).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile must accept '@' next-hops: %v", err)
	}
	m := &Manager{}
	var b strings.Builder
	for _, sr := range cfg.RoutingOptions.StaticRoutes {
		b.WriteString(m.generateStaticRoute(sr, "", nil, nil, nil))
	}
	got := b.String()
	for _, want := range []string{
		"ip route 192.0.2.0/24 10.0.0.1 eth0 5\n",
		"ip route 198.51.100.0/24 eth0 5\n",
		"ip route 203.0.113.0/24 10.0.0.1 5\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("FRR managed section missing %q; got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "@") {
		t.Errorf("raw '@' scalar leaked into FRR config:\n%s", got)
	}
}
