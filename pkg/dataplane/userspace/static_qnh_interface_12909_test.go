package userspace

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestQualifiedNextHopInterfaceSnapshot12909 proves a promoted interface-only
// qualified-next-hop (#12909) reaches the userspace route snapshot as an
// `@st0.0` member at its own preference tier. Before #12909 the tunnel name
// was stored in NextHopEntry.Address and the snapshot carried the bare
// non-IP token `st0.0`, which the Rust FIB cannot parse — and with no
// resolvable gateway in the row, the whole route was dropped as
// unresolved-bare (#11317).
func TestQualifiedNextHopInterfaceSnapshot12909(t *testing.T) {
	src := `routing-options {
		static {
			route 198.51.100.0/24 {
				next-hop 192.0.2.1;
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
	routes, _, err := buildRouteSnapshots(cfg, []InterfaceSnapshot{{Name: "st0.0"}}, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	snapshot := &ConfigSnapshot{Routes: routes}
	wire, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	var got ConfigSnapshot
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	primary, backup := false, false
	for _, route := range got.Routes {
		if route.Table != "inet.0" || route.Destination != "198.51.100.0/24" {
			continue
		}
		switch {
		case len(route.NextHops) == 1 && route.NextHops[0] == "192.0.2.1" && route.Preference == 5:
			primary = true
		case len(route.NextHops) == 1 && route.NextHops[0] == "@st0.0" && route.Preference == 200:
			backup = true
		default:
			t.Errorf("unexpected snapshot tier for 198.51.100.0/24: %+v", route)
		}
	}
	if !primary {
		t.Errorf("primary tier 192.0.2.1 at preference 5 missing from inet.0 snapshot: %+v", got.Routes)
	}
	if !backup {
		t.Errorf("floating backup tier @st0.0 at preference 200 missing from inet.0 snapshot: %+v", got.Routes)
	}
}
