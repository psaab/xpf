package config

import (
	"reflect"
	"testing"
)

// #13534: `next-hop interface pp0.0` is the Junos interface-only
// next-hop form. At master the compiler emitted TWO hops,
// [{Address:"interface"} {Interface:pp0.0}] — a phantom gateway named
// "interface". The `interface` keyword must be consumed as the modifier
// even as the first token when a value follows it; only a bare trailing
// `interface` stays a gateway value (#3881).
func TestStaticRouteInterfaceOnlyNextHop_13534(t *testing.T) {
	want := []NextHopEntry{{Interface: "pp0.0"}}

	t.Run("hierarchical brace", func(t *testing.T) {
		c := compileHier3881(t,
			`routing-options { static { route 10.40.0.0/16 { next-hop interface pp0.0; } } }`)
		r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "10.40.0.0/16")
		if !reflect.DeepEqual(r.NextHops, want) {
			t.Fatalf("NextHops = %+v, want %+v", r.NextHops, want)
		}
	})

	t.Run("flat set", func(t *testing.T) {
		c := compileSets3870(t, []string{
			"set routing-options static route 10.40.0.0/16 next-hop interface pp0.0",
		})
		r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "10.40.0.0/16")
		if !reflect.DeepEqual(r.NextHops, want) {
			t.Fatalf("NextHops = %+v, want %+v", r.NextHops, want)
		}
	})

	t.Run("fully inline", func(t *testing.T) {
		c := compileHier3881(t,
			`routing-options { static { route 10.40.0.0/16 next-hop interface pp0.0; } }`)
		r := findStaticRoute3871(t, c.RoutingOptions.StaticRoutes, "10.40.0.0/16")
		if !reflect.DeepEqual(r.NextHops, want) {
			t.Fatalf("NextHops = %+v, want %+v", r.NextHops, want)
		}
	})
}
