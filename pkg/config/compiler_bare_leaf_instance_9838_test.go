package config

import (
	"strings"
	"testing"
)

// #9838: an interface or a routing instance written as a bare leaf compiles
// to nothing while its empty braced spelling compiles — strict refuses the
// leaf spelling with a message naming it. Zones are the control: a zone
// written as a leaf already compiles, and keeps compiling.

func TestBareLeafInterfaceRefused9838(t *testing.T) {
	const leaf = `interfaces {
  ge-0/0/0;
  ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }
}`
	if _, err := CompileConfig(mustParse(t, leaf)); err == nil ||
		!strings.Contains(err.Error(), "interfaces ge-0/0/0") ||
		!strings.Contains(err.Error(), "#9838") {
		t.Fatalf("leaf: want the #9838 refusal naming interfaces ge-0/0/0, got %v", err)
	}

	const braced = `interfaces {
  ge-0/0/0 { }
  ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }
}`
	cfg, err := CompileConfig(mustParse(t, braced))
	if err != nil {
		t.Fatalf("braced: want a commit, got %v", err)
	}
	if cfg.Interfaces.Interfaces["ge-0/0/0"] == nil {
		t.Fatalf("braced: interface ge-0/0/0 missing from the compiled config")
	}

	// The leaf in a SECOND interfaces root is the same statement (#3562
	// bypass class): still refused.
	const secondRoot = `interfaces {
  ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }
}
interfaces {
  ge-0/0/0;
}`
	if _, err := CompileConfig(mustParse(t, secondRoot)); err == nil ||
		!strings.Contains(err.Error(), "interfaces ge-0/0/0") {
		t.Fatalf("second root: want the #9838 refusal naming interfaces ge-0/0/0, got %v", err)
	}
}

func TestBareLeafRoutingInstanceRefused9838(t *testing.T) {
	const leaf = `routing-instances {
  ri1;
}
interfaces {
  ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }
}`
	if _, err := CompileConfig(mustParse(t, leaf)); err == nil ||
		!strings.Contains(err.Error(), "routing-instances ri1") ||
		!strings.Contains(err.Error(), "#9838") {
		t.Fatalf("leaf: want the #9838 refusal naming routing-instances ri1, got %v", err)
	}

	const braced = `routing-instances {
  ri1 { }
}
interfaces {
  ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }
}`
	cfg, err := CompileConfig(mustParse(t, braced))
	if err != nil {
		t.Fatalf("braced: want a commit, got %v", err)
	}
	found := false
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == "ri1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("braced: routing instance ri1 missing from the compiled config")
	}

	const secondRoot = `routing-instances {
  ri1 { instance-type virtual-router; }
}
routing-instances {
  ri2;
}
interfaces {
  ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }
}`
	if _, err := CompileConfig(mustParse(t, secondRoot)); err == nil ||
		!strings.Contains(err.Error(), "routing-instances ri2") {
		t.Fatalf("second root: want the #9838 refusal naming routing-instances ri2, got %v", err)
	}
}

func TestBareLeafZoneStillCompiles9838(t *testing.T) {
	for _, spelling := range []string{"security-zone trust;", "security-zone trust { }"} {
		text := "security {\n zones {\n  " + spelling + "\n }\n}\ninterfaces {\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n"
		cfg, err := CompileConfig(mustParse(t, text))
		if err != nil {
			t.Fatalf("%s: want a commit, got %v", spelling, err)
		}
		if cfg.Security.Zones["trust"] == nil {
			t.Fatalf("%s: zone trust missing from the compiled config", spelling)
		}
	}
}

func TestBareLeafWildcardGroup9838(t *testing.T) {
	const ifaceGroup = `groups { G { interfaces { <*> { description fromgroup; } } } }
apply-groups G;
`
	const ifaceLeaf = ifaceGroup + `interfaces {
  ge-0/0/0;
  ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }
}`
	if _, err := CompileConfig(mustParse(t, ifaceLeaf)); err == nil ||
		!strings.Contains(err.Error(), "interfaces ge-0/0/0") {
		t.Fatalf("iface leaf + wildcard group: want the #9838 refusal, got %v", err)
	}

	const ifaceBraced = ifaceGroup + `interfaces {
  ge-0/0/0 { }
  ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }
}`
	cfg, err := CompileConfig(mustParse(t, ifaceBraced))
	if err != nil {
		t.Fatalf("iface braced + wildcard group: want a commit, got %v", err)
	}
	if ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]; ifc == nil || ifc.Description != "fromgroup" {
		t.Fatalf("iface braced + wildcard group: want ge-0/0/0 carrying the group's description, got %+v", ifc)
	}

	const riGroup = `groups { G { routing-instances { <*> { instance-type virtual-router; } } } }
apply-groups G;
`
	const riLeaf = riGroup + `routing-instances {
  ri1;
}
interfaces {
  ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }
}`
	if _, err := CompileConfig(mustParse(t, riLeaf)); err == nil ||
		!strings.Contains(err.Error(), "routing-instances ri1") {
		t.Fatalf("RI leaf + wildcard group: want the #9838 refusal, got %v", err)
	}

	const riBraced = riGroup + `routing-instances {
  ri1 { }
}
interfaces {
  ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }
}`
	cfg, err = CompileConfig(mustParse(t, riBraced))
	if err != nil {
		t.Fatalf("RI braced + wildcard group: want a commit, got %v", err)
	}
	gotType := ""
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == "ri1" {
			gotType = ri.InstanceType
		}
	}
	if gotType != "virtual-router" {
		t.Fatalf("RI braced + wildcard group: want ri1 carrying instance-type virtual-router, got %q", gotType)
	}
}

func TestBareLeafKeywordsNotInstances9838(t *testing.T) {
	// End to end: keyword statements directly under the two stanzas are
	// not interfaces / instances and commit cleanly.
	clean := map[string]string{
		"interfaces apply-macro": `interfaces {
  apply-macro foo bar;
  ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }
}`,
		"interfaces interface-range": `interfaces {
  interface-range R {
    member ge-0/0/2;
    mtu 9000;
  }
  ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }
}`,
		"routing-instances apply-macro": `routing-instances {
  apply-macro foo bar;
  ri1 { instance-type virtual-router; }
}
interfaces {
  ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }
}`,
	}
	for name, text := range clean {
		if _, err := CompileConfig(mustParse(t, text)); err != nil {
			t.Errorf("%s: want a commit, got %v", name, err)
		}
	}

	// Gate level: a BARE keyword leaf fires nothing — only names that
	// would read as an interface or an instance are refused.
	bare := map[string]string{
		"interfaces traceoptions":    "interfaces {\n traceoptions;\n}\n",
		"interfaces interface-range": "interfaces {\n interface-range;\n}\n",
		"interfaces apply-groups":    "interfaces {\n apply-groups;\n}\n",
		"interfaces apply-macro":     "interfaces {\n apply-macro;\n}\n",
		"routing-instances apply":    "routing-instances {\n apply-groups;\n}\n",
		"routing-instances macro":    "routing-instances {\n apply-macro;\n}\n",
		"routing-instances except":   "routing-instances {\n apply-groups-except;\n}\n",
	}
	for name, text := range bare {
		if _, err := validateBareLeafInstance9838(mustParse(t, text).Children, false); err != nil {
			t.Errorf("%s: want the gate silent, got %v", name, err)
		}
	}
	if _, err := validateBareLeafInstance9838(
		mustParse(t, "interfaces {\n ge-0/0/0;\n}\n").Children, false); err == nil {
		t.Errorf("gate: want the refusal for a bare interface leaf, got nil")
	}
}

func TestBareLeafLenientWarns9838(t *testing.T) {
	const ifaceLeaf = `interfaces {
  ge-0/0/0;
  ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }
}`
	cfg, err := CompileConfigLenient(mustParse(t, ifaceLeaf))
	if err != nil {
		t.Fatalf("lenient iface leaf: want a boot, got %v", err)
	}
	if cfg.Interfaces.Interfaces["ge-0/0/0"] != nil {
		t.Fatalf("lenient iface leaf: ge-0/0/0 compiled an interface it must not have")
	}
	joined := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(joined, "interfaces ge-0/0/0") || !strings.Contains(joined, "#9838") {
		t.Fatalf("lenient iface leaf: want a warning naming interfaces ge-0/0/0, got %q", joined)
	}

	const riLeaf = `routing-instances {
  ri1;
}
interfaces {
  ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }
}`
	cfg, err = CompileConfigLenient(mustParse(t, riLeaf))
	if err != nil {
		t.Fatalf("lenient RI leaf: want a boot, got %v", err)
	}
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == "ri1" {
			t.Fatalf("lenient RI leaf: ri1 compiled an instance it must not have")
		}
	}
	joined = strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(joined, "routing-instances ri1") || !strings.Contains(joined, "#9838") {
		t.Fatalf("lenient RI leaf: want a warning naming routing-instances ri1, got %q", joined)
	}
}

func TestBareLeafQuotedAndComment9838(t *testing.T) {
	// A quote does not survive rendering (an HA peer reparses the
	// unquoted form), and a trailing comment is not configuration, so
	// neither exempts the bare spelling — the refusal names the same
	// statement either way.
	refused := map[string]struct{ text, want string }{
		"quoted interface leaf": {
			"interfaces {\n \"ge-0/0/0\";\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n",
			"interfaces ge-0/0/0",
		},
		"commented interface leaf": {
			"interfaces {\n ge-0/0/0; # empty for now\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n",
			"interfaces ge-0/0/0",
		},
		"quoted RI leaf": {
			"routing-instances {\n \"ri1\";\n}\ninterfaces {\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n",
			"routing-instances ri1",
		},
		"commented RI leaf": {
			"routing-instances {\n ri1; # empty for now\n}\ninterfaces {\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n",
			"routing-instances ri1",
		},
	}
	for name, c := range refused {
		if _, err := CompileConfig(mustParse(t, c.text)); err == nil ||
			!strings.Contains(err.Error(), c.want) ||
			!strings.Contains(err.Error(), "#9838") {
			t.Errorf("%s: want the #9838 refusal naming %s, got %v", name, c.want, err)
		}
	}
	// Controls: quoting the BRACED spelling changes nothing.
	controls := map[string]string{
		"quoted braced interface": "interfaces {\n \"ge-0/0/0\" { }\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n",
		"quoted braced RI":        "routing-instances {\n \"ri1\" { }\n}\ninterfaces {\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n",
	}
	for name, text := range controls {
		cfg, err := CompileConfig(mustParse(t, text))
		if err != nil {
			t.Errorf("%s: want a commit, got %v", name, err)
			continue
		}
		if strings.Contains(name, "interface") && cfg.Interfaces.Interfaces["ge-0/0/0"] == nil {
			t.Errorf("%s: interface ge-0/0/0 missing from the compiled config", name)
		}
		if strings.Contains(name, "RI") {
			found := false
			for _, ri := range cfg.RoutingInstances {
				if ri.Name == "ri1" {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: routing instance ri1 missing from the compiled config", name)
			}
		}
	}
}
