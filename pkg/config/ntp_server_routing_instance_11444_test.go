package config

import (
	"strings"
	"testing"
)

// TestNTPServerRoutingInstanceAdvisory_11444 was the VR-traffic-or-advisory
// cell for F-101: a per-server `routing-instance` was stored on
// NTPServerOption and then dropped by renderChronySources, so the commit had
// to WARN. #18584 made the routing-instance the source of chrony's single
// `bindacqdevice` when every server names the same VRF-backed instance, so a
// lone `routing-instance mgmt` is now ENFORCED and must NOT warn; the advisory
// survives for the shapes chrony cannot express (mixed instances, an instance
// with no VRF device), which this cell exercises through the same spellings.
//
// Every spelling (flat-set, packed, block) is checked both ways: the decision
// reads the typed NTPServerOptions, which #7132 unifies across spellings, so a
// spelling that parses but decides differently is the same defect in a new
// shape.
func TestNTPServerRoutingInstanceAdvisory_11444(t *testing.T) {
	flatTree := &ConfigTree{}
	path, err := ParseSetCommand("set system ntp server 10.0.0.1 routing-instance nosuch")
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := flatTree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	flat, err := CompileConfig(flatTree)
	if err != nil {
		t.Fatalf("strict flat-set compile: %v", err)
	}
	if err := SchemaValidate(flatTree); err != nil {
		t.Fatalf("SchemaValidate rejected accepted-inert flat-set NTP config: %v", err)
	}
	assertNTPRoutingInstanceWarns(t, "flat-set", flat, "10.0.0.1", "nosuch")

	for _, tc := range []struct{ name, text, server string }{
		{"packed", `system { ntp { server 10.0.0.2 routing-instance nosuch; } }`, "10.0.0.2"},
		{"block", "system { ntp { server 10.0.0.3 {\n routing-instance nosuch;\n} } }", "10.0.0.3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := NewParser(tc.text)
			tree, perrs := p.Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse %q: %v", tc.text, perrs)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("strict compile %q: %v", tc.text, err)
			}
			if err := SchemaValidate(tree); err != nil {
				t.Fatalf("SchemaValidate rejected accepted-inert NTP config: %v", err)
			}
			assertNTPRoutingInstanceWarns(t, tc.name, cfg, tc.server, "nosuch")
		})
	}
	for _, tc := range []struct{ name, text, server string }{
		{"packed-mgmt", `system { ntp { server 10.0.0.2 routing-instance mgmt; } }`, "10.0.0.2"},
		{"block-mgmt", "system { ntp { server 10.0.0.3 {\n routing-instance mgmt;\n} } }", "10.0.0.3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, perrs := NewParser(tc.text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse %q: %v", tc.text, perrs)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("strict compile %q: %v", tc.text, err)
			}
			assertNTPRoutingInstanceHonoured(t, tc.name, cfg, tc.server, "mgmt")
		})
	}
}

func assertNTPRoutingInstanceHonoured(t *testing.T, name string, cfg *Config, server, ri string) {
	t.Helper()
	if opt := cfg.System.NTPServerOptions[server]; opt.RoutingInstance != ri {
		t.Fatalf("%s: precondition: NTPServerOptions[%q] = %+v, want RoutingInstance %q", name, server, opt, ri)
	}
	if got, ok, reason := NTPAcquisitionInstance(&cfg.System, cfg.RoutingInstances); !ok || got != ri {
		t.Fatalf("%s: NTPAcquisitionInstance = (%q, %v, %q), want (%q, true)", name, got, ok, reason, ri)
	}
	if all := strings.Join(cfg.Warnings, "\n"); strings.Contains(all, "system ntp server routing-instance") {
		t.Errorf("%s: an honoured routing-instance must not carry the NOT-enforced advisory; warnings:\n%s", name, all)
	}
}

func assertNTPRoutingInstanceWarns(t *testing.T, name string, cfg *Config, server, ri string) {
	t.Helper()
	// Recorded, not removed: the advisory admits the knob is inert, it
	// does not delete it from the typed config.
	opt, ok := cfg.System.NTPServerOptions[server]
	if !ok || opt.RoutingInstance != ri {
		t.Fatalf("%s: precondition: NTPServerOptions[%q] = %+v, want RoutingInstance %q",
			name, server, opt, ri)
	}
	all := strings.Join(cfg.Warnings, "\n")
	for _, want := range []string{"system ntp server routing-instance", "NOT enforced"} {
		if !strings.Contains(all, want) {
			t.Errorf("%s: missing advisory %q (silent clean commit); warnings:\n%s", name, want, all)
		}
	}
}

// TestNTPServerRoutingInstanceAdvisoryLenient_11444 pins the tolerant path:
// a leniently loaded / peer-synced config carrying a per-server
// routing-instance warns too, like the `ntp source-address` advisory it
// mirrors. The knob is inert on every path, so the advisory fires on every
// path.
func TestNTPServerRoutingInstanceAdvisoryLenient_11444(t *testing.T) {
	p := NewParser(`system { ntp { server 10.0.0.4 { routing-instance nosuch; } } }`)
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil || cfg == nil {
		t.Fatalf("lenient compile: err=%v cfg=%v", err, cfg)
	}
	assertNTPRoutingInstanceWarns(t, "lenient", cfg, "10.0.0.4", "nosuch")
	// #18584: the tolerant path DECIDES like the strict one — the daemon
	// renders from a leniently loaded config at boot.
	tree, perrs = NewParser(`system { ntp { server 10.0.0.4 { routing-instance mgmt; } } }`).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err = CompileConfigLenient(tree)
	if err != nil || cfg == nil {
		t.Fatalf("lenient compile: err=%v cfg=%v", err, cfg)
	}
	assertNTPRoutingInstanceHonoured(t, "lenient-mgmt", cfg, "10.0.0.4", "mgmt")
}

// TestNTPServerRoutingInstanceAdvisoryScoped_11444 is the over-reach guard:
// a plain server, and servers carrying only honoured modifiers
// (key/version/prefer), must NOT emit the routing-instance advisory.
func TestNTPServerRoutingInstanceAdvisoryScoped_11444(t *testing.T) {
	cfg := compileSetLinesT(t, []string{
		"set system ntp server 10.0.0.5",
		"set system ntp server 10.0.0.6 key 5",
		"set system ntp server 10.0.0.7 version 4",
		"set system ntp server 10.0.0.8 prefer",
	})
	all := strings.Join(cfg.Warnings, "\n")
	if strings.Contains(all, "system ntp server routing-instance") {
		t.Errorf("plain/honoured-modifier servers must not warn; warnings:\n%s", all)
	}
}
