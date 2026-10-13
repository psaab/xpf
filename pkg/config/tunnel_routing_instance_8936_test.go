package config

import "testing"

// TestTunnelRoutingInstanceSpellingsAgree8936 pins the fix for the one site
// where the #8690 register's `partial` class was load-bearing.
//
// `partial` records that SOMETHING CONSUMED THE TAIL and infers that it was
// ENTITLED to. Here the consumer was the defect: the braced spelling gives
// `routing-instance` a CHILD named `destination`, while the elided spelling
// packs the tail onto the node's own Keys, so FindChild returned nil and the
// fallback nodeVal(prop) returned Keys[1] -- the literal keyword "destination".
//
// The tunnel compiled with RoutingInstance="destination", bound to a
// routing-instance that does not exist, and the operator's instance name was
// discarded. That is WORSE than a drop: a missing value leaves the tunnel
// visibly unbound, while this produced a plausible binding that resolves to
// nothing.
//
// Three spellings, because the fix has to leave the other two alone -- a repair
// that made the elided form right by breaking `routing-instance <name>;` would
// pass a two-spelling cell.
func TestTunnelRoutingInstanceSpellingsAgree8936(t *testing.T) {
	read := func(t *testing.T, txt string) string {
		t.Helper()
		tree, perrs := NewParser("routing-instances { vrf8936 { instance-type virtual-router; } } " + txt).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs[0])
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil || cfg == nil {
			t.Fatalf("fixture must compile: %v", err)
		}
		for _, i := range cfg.Interfaces.Interfaces {
			if i.Tunnel != nil {
				return i.Tunnel.RoutingInstance
			}
		}
		t.Fatal("no tunnel compiled; every assertion below would be vacuous")
		return ""
	}
	const head = `interfaces { gr-0/0/0 { tunnel { source 10.0.0.1; destination 10.0.0.2; `
	const tail = ` } } }`
	for _, c := range []struct{ name, txt string }{
		{"braced", head + `routing-instance { destination vrf8936; }` + tail},
		{"brace-elided", head + `routing-instance destination vrf8936;` + tail},
		{"bare instance name", head + `routing-instance vrf8936;` + tail},
	} {
		got := read(t, c.txt)
		if got != "vrf8936" {
			t.Errorf("%s spelling compiles RoutingInstance=%q, want %q. If it is "+
				"%q the packed tail is being read as the instance NAME again -- "+
				"the tunnel binds to a routing-instance that does not exist and "+
				"the operator's name is discarded (#8936).",
				c.name, got, "vrf8936", "destination")
		}
	}
}
