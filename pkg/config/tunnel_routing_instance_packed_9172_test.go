package config

import (
	"strings"
	"testing"
)

// tunnelRoutingInstance9172 returns the tunnel routing-instance binding of
// gr-0/0/0, at interface or unit level, or "<no tunnel>".
func tunnelRoutingInstance9172(cfg *Config) string {
	if cfg == nil {
		return "<no config>"
	}
	ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if ifc == nil {
		return "<no interface>"
	}
	if ifc.Tunnel != nil {
		return ifc.Tunnel.RoutingInstance
	}
	for _, u := range ifc.Units {
		if u.Tunnel != nil {
			return u.Tunnel.RoutingInstance
		}
	}
	return "<no tunnel>"
}

// TestPackedBareTunnelRoutingInstanceBindsNothing9172 is #9172 V044.
//
// `routing-instance destination;` packed onto one line, with no instance name,
// compiled to RoutingInstance="destination" -- a binding to a routing-instance
// that does not exist, on a commit that reported success -- while the braced
// `routing-instance { destination; }` compiled to no binding and was refused
// at commit. Both tunnel sites (interface-level and unit-level) read the tail
// through the same helper, so both are cells.
//
// FAIL-ON-REVERT: restore the three-key guard in
// packedTunnelRoutingInstance8936 and the packed-bare compile cells bind
// "destination"; drop packedTail from the schema node and the packed-bare
// commit cells accept.
func TestPackedBareTunnelRoutingInstanceBindsNothing9172(t *testing.T) {
	const vrf = `routing-instances { vrf1 { instance-type virtual-router; } } `
	sites := []struct {
		name string
		wrap func(string) string
	}{
		{"unit-level tunnel", func(body string) string {
			return vrf + `interfaces { gr-0/0/0 { unit 0 { tunnel { source 10.0.0.1; destination 10.0.0.2; ` +
				body + ` } family inet { address 10.9.9.1/30; } } } }`
		}},
		{"interface-level tunnel", func(body string) string {
			return vrf + `interfaces { gr-0/0/0 { tunnel { source 10.0.0.1; destination 10.0.0.2; ` +
				body + ` } unit 0 { family inet { address 10.9.9.1/30; } } } }`
		}},
	}
	cases := []struct {
		name, body string
		wantRI     string
		wantReject bool
	}{
		{"braced named (control)", `routing-instance { destination vrf1; }`, "vrf1", false},
		{"packed named (#8936)", `routing-instance destination vrf1;`, "vrf1", false},
		{"braced bare (control)", `routing-instance { destination; }`, "", true},
		{"packed bare", `routing-instance destination;`, "", true},
	}
	for _, site := range sites {
		for _, c := range cases {
			t.Run(site.name+"/"+c.name, func(t *testing.T) {
				text := site.wrap(c.body)
				for _, strict := range []bool{true, false} {
					tree, errs := NewParser(text).Parse()
					if len(errs) > 0 {
						t.Fatalf("fixture does not parse: %v", errs)
					}
					var cfg *Config
					var err error
					if strict {
						cfg, err = CompileConfig(tree)
					} else {
						cfg, err = CompileConfigLenient(tree)
					}
					if err != nil {
						t.Fatalf("compile (strict=%v): %v", strict, err)
					}
					got := tunnelRoutingInstance9172(cfg)
					if strings.HasPrefix(got, "<") {
						t.Fatalf("CONTROL (strict=%v): the fixture built no tunnel (%s), so the "+
							"binding below would be about nothing", strict, got)
					}
					if got != c.wantRI {
						t.Errorf("strict=%v: RoutingInstance=%q, want %q", strict, got, c.wantRI)
					}
				}
				tree, _ := NewParser(text).Parse()
				verr := SchemaValidate(tree, nil)
				switch {
				case c.wantReject && (verr == nil || !strings.Contains(verr.Error(), "declares a value and none was given")):
					t.Errorf("commit gate: want the valueless-destination refusal, got %v", verr)
				case !c.wantReject && verr != nil:
					t.Errorf("commit gate refused a valid spelling: %v", verr)
				}
			})
		}
	}
}
