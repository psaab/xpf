package config

import (
	"reflect"
	"strings"
	"testing"
)

func parse10292(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

func flat10292(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree
}

func hostInbound10292(t *testing.T, tree *ConfigTree) *HostInboundTraffic {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	zone := cfg.Security.Zones["trust"]
	if zone == nil || zone.HostInboundTraffic == nil {
		t.Fatal("compiled trust zone has no host-inbound-traffic stanza")
	}
	return zone.HostInboundTraffic
}

// TestHostInboundExcept10292ShapesAgree is the RED-on-revert guard for the
// compiler boundary. Before #10292 the hierarchical `X { except; }` form was
// accepted but compiled as X, while the flat `X except` form was rejected by
// the strict token gate. Every accepted spelling below must produce the same
// effective positive set, and a normal non-except list is the unchanged control.
func TestHostInboundExcept10292ShapesAgree(t *testing.T) {
	const prefix = `security { zones { security-zone trust { host-inbound-traffic { `
	const suffix = ` } } } }`
	cases := []struct {
		name string
		tree *ConfigTree
		want []string
	}{
		{
			name: "hierarchical-subblock",
			tree: parse10292(t, prefix+`system-services { all; ssh { except; } }`+suffix),
			want: without10292(HostInboundAllExpansionServices(), "ssh"),
		},
		{
			name: "hierarchical-flat-tail",
			tree: parse10292(t, prefix+`system-services { all; ssh except; }`+suffix),
			want: without10292(HostInboundAllExpansionServices(), "ssh"),
		},
		{
			name: "flat-set-tail",
			tree: flat10292(t,
				"set security zones security-zone trust host-inbound-traffic system-services all",
				"set security zones security-zone trust host-inbound-traffic system-services ssh except"),
			want: without10292(HostInboundAllExpansionServices(), "ssh"),
		},
		{
			name: "repeated-host-inbound-blocks",
			tree: parse10292(t, `security { zones { security-zone trust {
				host-inbound-traffic { system-services { all; } }
				host-inbound-traffic { system-services { ssh { except; } } }
			} } }`),
			want: without10292(HostInboundAllExpansionServices(), "ssh"),
		},
		{
			name: "plain-control",
			tree: parse10292(t, prefix+`system-services { ssh; ping; }`+suffix),
			want: []string{"ssh", "ping"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hostInbound10292(t, tc.tree)
			if !reflect.DeepEqual(got.SystemServices, tc.want) {
				t.Fatalf("effective system-services = %v, want %v", got.SystemServices, tc.want)
			}
		})
	}
}

func TestHostInboundExcept10292Protocols(t *testing.T) {
	const prefix = `security { zones { security-zone trust { host-inbound-traffic { `
	const suffix = ` } } } }`
	want := without10292(HostInboundAllExpansionProtocols(), "ospf")
	cases := []struct {
		name string
		tree *ConfigTree
	}{
		{
			name: "hierarchical-subblock",
			tree: parse10292(t, prefix+`protocols { all; ospf { except; } }`+suffix),
		},
		{
			name: "hierarchical-flat-tail",
			tree: parse10292(t, prefix+`protocols { all; ospf except; }`+suffix),
		},
		{
			name: "flat-set-tail",
			tree: flat10292(t,
				"set security zones security-zone trust host-inbound-traffic protocols all",
				"set security zones security-zone trust host-inbound-traffic protocols ospf except"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hostInbound10292(t, tc.tree)
			if !reflect.DeepEqual(got.Protocols, want) {
				t.Fatalf("effective protocols = %v, want %v", got.Protocols, want)
			}
		})
	}
}

func TestHostInboundExcept10292UnknownOperandFails(t *testing.T) {
	const config = `security { zones { security-zone trust { host-inbound-traffic {
		system-services { all; ssssh except; }
	} } } }`
	_, err := CompileConfig(parse10292(t, config))
	if err == nil {
		t.Fatal("unknown except operand committed instead of reaching strict token validation")
	}
	if !strings.Contains(err.Error(), "ssssh") {
		t.Fatalf("strict error = %v, want unknown operand name", err)
	}
}

func TestHostInboundExcept10292StandaloneModifierFails(t *testing.T) {
	const config = `security { zones { security-zone trust { host-inbound-traffic {
		system-services { all; ssh; except; }
	} } } }`
	if _, err := CompileConfig(parse10292(t, config)); err == nil {
		t.Fatal("standalone except sibling was accepted as a modifier")
	}
}

func TestHostInboundExcept10292NestedNonExceptChildrenDoNotAdmit(t *testing.T) {
	const prefix = `security { zones { security-zone trust { host-inbound-traffic { `
	const suffix = ` } } } }`
	t.Run("nested-token-is-not-a-value", func(t *testing.T) {
		got := hostInbound10292(t, parse10292(t, prefix+`system-services { ssh { ping; } }`+suffix))
		if !reflect.DeepEqual(got.SystemServices, []string{"ssh"}) {
			t.Fatalf("effective system-services = %v, want [ssh]", got.SystemServices)
		}
	})
	t.Run("payload-after-except-is-rejected", func(t *testing.T) {
		_, err := CompileConfig(parse10292(t,
			prefix+`system-services { ssh { except; ping; } }`+suffix))
		if err == nil || !strings.Contains(err.Error(), "except") {
			t.Fatalf("compile error = %v, want malformed except rejection", err)
		}
	})
	t.Run("nested-except-payload-is-rejected", func(t *testing.T) {
		_, err := CompileConfig(parse10292(t,
			prefix+`system-services { ssh { except { ping; } } }`+suffix))
		if err == nil || !strings.Contains(err.Error(), "except") {
			t.Fatalf("compile error = %v, want malformed except rejection", err)
		}
	})
}

func TestHostInboundExcept10292QuotedExceptIsValue(t *testing.T) {
	const config = `security { zones { security-zone trust { host-inbound-traffic {
		system-services { ssh "except"; }
	} } } }`
	_, err := CompileConfig(parse10292(t, config))
	if err == nil || !strings.Contains(err.Error(), "except") {
		t.Fatalf("compile error = %v, want quoted except token rejection", err)
	}
}

func TestHostInboundExcept10292StandaloneShapesCompileEmpty(t *testing.T) {
	const prefix = `security { zones { security-zone trust { host-inbound-traffic { `
	const suffix = ` } } } }`
	cases := []struct {
		name string
		tree *ConfigTree
	}{
		{
			name: "services-hierarchical",
			tree: parse10292(t, prefix+`system-services { ssh { except; } }`+suffix),
		},
		{
			name: "services-flat",
			tree: flat10292(t,
				"set security zones security-zone trust host-inbound-traffic system-services ssh except"),
		},
		{
			name: "protocols-hierarchical",
			tree: parse10292(t, prefix+`protocols { ospf { except; } }`+suffix),
		},
		{
			name: "protocols-flat",
			tree: flat10292(t,
				"set security zones security-zone trust host-inbound-traffic protocols ospf except"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hostInbound10292(t, tc.tree)
			if !reflect.DeepEqual(got.SystemServices, []string{}) &&
				(tc.name == "services-hierarchical" || tc.name == "services-flat") {
				t.Fatalf("effective system-services = %v, want empty", got.SystemServices)
			}
			if !reflect.DeepEqual(got.Protocols, []string{}) &&
				(tc.name == "protocols-hierarchical" || tc.name == "protocols-flat") {
				t.Fatalf("effective protocols = %v, want empty", got.Protocols)
			}
		})
	}
}

func TestHostInboundExcept10292DoubleModifierFails(t *testing.T) {
	const config = `security { zones { security-zone trust { host-inbound-traffic {
		system-services { ssh except except; }
	} } } }`
	_, err := CompileConfig(parse10292(t, config))
	if err == nil || !strings.Contains(err.Error(), "except") {
		t.Fatalf("compile error = %v, want malformed modifier rejection", err)
	}
}

func hostInboundInterface10292(t *testing.T, tree *ConfigTree) *HostInboundTraffic {
	t.Helper()
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	zone := cfg.Security.Zones["trust"]
	if zone == nil {
		t.Fatal("compiled trust zone is missing")
	}
	hib := zone.InterfaceHostInbound["ge-0/0/0.0"]
	if hib == nil {
		t.Fatal("compiled interface host-inbound stanza is missing")
	}
	return hib
}

func TestHostInboundExcept10292PerInterfaceShapes(t *testing.T) {
	const hierarchical = `interfaces {
		ge-0/0/0 {
			unit 0 {
				family inet { address 10.0.0.1/24; }
			}
		}
	}
	security { zones { security-zone trust {
		interfaces { ge-0/0/0.0 {
			host-inbound-traffic {
				system-services { ssh { except; } }
				protocols { ospf { except; } }
			}
		} }
	} } }`
	cases := []struct {
		name string
		tree *ConfigTree
	}{
		{
			name: "hierarchical",
			tree: parse10292(t, hierarchical),
		},
		{
			name: "flat",
			tree: flat10292(t,
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
				"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services ssh except",
				"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic protocols ospf except"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hostInboundInterface10292(t, tc.tree)
			if len(got.SystemServices) != 0 {
				t.Fatalf("effective interface system-services = %v, want empty", got.SystemServices)
			}
			if len(got.Protocols) != 0 {
				t.Fatalf("effective interface protocols = %v, want empty", got.Protocols)
			}
		})
	}
}

func without10292(tokens []string, excluded string) []string {
	out := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if token != excluded {
			out = append(out, token)
		}
	}
	return out
}
