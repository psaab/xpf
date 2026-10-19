package config

import (
	"reflect"
	"strings"
	"testing"
)

// #15693 (V37-03): three DHCPv6-client defects.
//
//  1. `req-option` was declared args:1 WITHOUT multi:true and compiled with
//     nodeVal (Keys[1] only), so bracketed `req-option [ dns-server
//     domain-name ]` and a flat `req-option dns-server domain-name` kept only
//     the first option even though ReqOptions is a []string.
//  2. `client-type` / `duid-type` / `req-option` carried no valueType or
//     validator, so `client-type bogus` committed (daemon treats !=stateless
//     as stateful) and `duid-type vendor` silently fell back to duid-ll.
//  3. (pkg/dhcp) Option 24 was requested but never parsed — see
//     pkg/dhcp/domain_search_15693_test.go.
//
// FAIL-ON-REVERT: dropping `multi: true` from req-option or reverting the
// compiler to nodeVal turns the bracket/flat cells RED; dropping any
// ValidateEnum turns the bogus-value cells RED (SchemaValidate accepts).

func reqOptions15693(t *testing.T, cfg *Config) []string {
	t.Helper()
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil {
		t.Fatal("ge-0/0/0 not compiled")
	}
	unit := ifc.Units[0]
	if unit == nil || unit.DHCPv6Client == nil {
		t.Fatal("DHCPv6Client not compiled")
	}
	return unit.DHCPv6Client.ReqOptions
}

func TestReqOptionEverySpelling15693(t *testing.T) {
	want := []string{"dns-server", "domain-name"}

	t.Run("hierarchical repeated", func(t *testing.T) {
		cfg := compileHierarchical(t, `interfaces { ge-0/0/0 { unit 0 { family inet6 { dhcpv6-client { client-type stateful; req-option dns-server; req-option domain-name; } } } } }`)
		if got := reqOptions15693(t, cfg); !reflect.DeepEqual(got, want) {
			t.Fatalf("ReqOptions = %v, want %v", got, want)
		}
	})

	t.Run("hierarchical bracket", func(t *testing.T) {
		cfg := compileHierarchical(t, `interfaces { ge-0/0/0 { unit 0 { family inet6 { dhcpv6-client { client-type stateful; req-option [ dns-server domain-name ]; } } } } }`)
		if got := reqOptions15693(t, cfg); !reflect.DeepEqual(got, want) {
			t.Fatalf("ReqOptions = %v, want %v", got, want)
		}
	})

	t.Run("hierarchical block", func(t *testing.T) {
		cfg := compileHierarchical(t, `interfaces { ge-0/0/0 { unit 0 { family inet6 { dhcpv6-client { client-type stateful; req-option { dns-server; domain-name; } } } } } }`)
		if got := reqOptions15693(t, cfg); !reflect.DeepEqual(got, want) {
			t.Fatalf("ReqOptions = %v, want %v", got, want)
		}
	})

	t.Run("flat repeated", func(t *testing.T) {
		cfg, err := compileSet(t, []string{
			"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client client-type stateful",
			"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client req-option dns-server",
			"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client req-option domain-name",
		})
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if got := reqOptions15693(t, cfg); !reflect.DeepEqual(got, want) {
			t.Fatalf("ReqOptions = %v, want %v", got, want)
		}
	})

	t.Run("flat bracket", func(t *testing.T) {
		cfg, err := compileSet(t, []string{
			"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client client-type stateful",
			"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client req-option [ dns-server domain-name ]",
		})
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if got := reqOptions15693(t, cfg); !reflect.DeepEqual(got, want) {
			t.Fatalf("ReqOptions = %v, want %v", got, want)
		}
	})

	t.Run("flat packed tail", func(t *testing.T) {
		cfg, err := compileSet(t, []string{
			"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client client-type stateful",
			"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client req-option dns-server domain-name",
		})
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if got := reqOptions15693(t, cfg); !reflect.DeepEqual(got, want) {
			t.Fatalf("ReqOptions = %v, want %v", got, want)
		}
	})

	// Control: a single option still compiles to exactly that one option.
	t.Run("single req-option control", func(t *testing.T) {
		cfg, err := compileSet(t, []string{
			"set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client req-option dns-server",
		})
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if got := reqOptions15693(t, cfg); !reflect.DeepEqual(got, []string{"dns-server"}) {
			t.Fatalf("ReqOptions = %v, want [dns-server]", got)
		}
	})

	// Display-set replay is identical: render the hierarchical tree as set
	// lines, replay them, and the compiled option set must not shrink.
	t.Run("display-set replay identical", func(t *testing.T) {
		tree, perrs := NewParser(`interfaces { ge-0/0/0 { unit 0 { family inet6 { dhcpv6-client { client-type stateful; req-option dns-server; req-option domain-name; } } } } }`).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		setText := tree.FormatSet()
		if !strings.Contains(setText, "req-option") {
			t.Fatalf("display set lost req-option:\n%s", setText)
		}
		replayed := &ConfigTree{}
		for _, line := range strings.Split(strings.TrimSpace(setText), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			path, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := replayed.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		cfg, err := CompileConfig(replayed)
		if err != nil {
			t.Fatalf("CompileConfig(replayed): %v", err)
		}
		if got := reqOptions15693(t, cfg); !reflect.DeepEqual(got, want) {
			t.Fatalf("replayed ReqOptions = %v, want %v (set text:\n%s)", got, want, setText)
		}
	})
}

// TestDHCPv6ClientEnumValidation15693: bogus client-type / duid-type /
// req-option values must fail SchemaValidate (strict commit), while every
// valid value — including the newly admitted `autoconfig` — passes.
func TestDHCPv6ClientEnumValidation15693(t *testing.T) {
	validate := func(t *testing.T, setLine string) error {
		t.Helper()
		tree := &ConfigTree{}
		path, err := ParseSetCommand(setLine)
		if err != nil {
			t.Fatalf("ParseSetCommand: %v", err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		return SchemaValidate(tree, cfg)
	}
	base := "set interfaces ge-0/0/0 unit 0 family inet6 dhcpv6-client "

	for _, tc := range []struct {
		name string
		line string
	}{
		{"client-type bogus", base + "client-type bogus"},
		{"client-type statefull typo", base + "client-type statefull"},
		{"duid-type vendor", base + "client-identifier duid-type vendor"},
		{"duid-type duid-en", base + "client-identifier duid-type duid-en"},
		{"req-option bogus", base + "req-option bogus-option"},
	} {
		t.Run("reject "+tc.name, func(t *testing.T) {
			if err := validate(t, tc.line); err == nil {
				t.Fatalf("SchemaValidate(%q) = nil, want enum rejection", tc.line)
			}
		})
	}

	for _, tc := range []struct {
		name string
		line string
	}{
		{"client-type stateful", base + "client-type stateful"},
		{"client-type stateless", base + "client-type stateless"},
		{"client-type autoconfig", base + "client-type autoconfig"},
		{"duid-type duid-ll", base + "client-identifier duid-type duid-ll"},
		{"duid-type duid-llt", base + "client-identifier duid-type duid-llt"},
		{"req-option dns-server", base + "req-option dns-server"},
		{"req-option domain-name", base + "req-option domain-name"},
	} {
		t.Run("accept "+tc.name, func(t *testing.T) {
			if err := validate(t, tc.line); err != nil {
				t.Fatalf("SchemaValidate(%q) = %v, want nil", tc.line, err)
			}
		})
	}

	// autoconfig must COMPILE through to ClientType (it is a real Junos
	// client type, not just a tolerated token).
	t.Run("autoconfig compiles", func(t *testing.T) {
		cfg, err := compileSet(t, []string{base + "client-type autoconfig"})
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
		if ifc == nil || ifc.Units[0] == nil || ifc.Units[0].DHCPv6Client == nil {
			t.Fatal("DHCPv6Client not compiled")
		}
		if got := ifc.Units[0].DHCPv6Client.ClientType; got != "autoconfig" {
			t.Fatalf("ClientType = %q, want autoconfig", got)
		}
	})
}
