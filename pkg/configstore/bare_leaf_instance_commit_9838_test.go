package configstore

import (
	"strings"
	"testing"
)

// #9838: the bare-leaf interface / routing-instance refusal through the
// strict commit gate, plus the zone control and the wildcard-group rows.
func TestBareLeafInstancesAtCommit9838(t *testing.T) {
	const ifaceBase = `
interfaces {
  ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }
}`
	refused := map[string]struct{ text, want string }{
		"iface leaf": {
			`interfaces {
  ge-0/0/0;
  ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }
}`,
			"interfaces ge-0/0/0",
		},
		"RI leaf": {
			`routing-instances {
  ri1;
}` + ifaceBase,
			"routing-instances ri1",
		},
		"iface leaf + wildcard group": {
			`groups { G { interfaces { <*> { description fromgroup; } } } }
apply-groups G;
interfaces {
  ge-0/0/0;
  ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }
}`,
			"interfaces ge-0/0/0",
		},
		"RI leaf + wildcard group": {
			`groups { G { routing-instances { <*> { instance-type virtual-router; } } } }
apply-groups G;
routing-instances {
  ri1;
}` + ifaceBase,
			"routing-instances ri1",
		},
	}
	for name, c := range refused {
		if _, err := CheckText(c.text, -1); err == nil ||
			!strings.Contains(err.Error(), c.want) ||
			!strings.Contains(err.Error(), "#9838") {
			t.Errorf("%s: want the #9838 refusal naming %s, got %v", name, c.want, err)
		}
	}

	const ifaceBraced = `interfaces {
  ge-0/0/0 { }
  ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }
}`
	cfg, err := CheckText(ifaceBraced, -1)
	if err != nil {
		t.Fatalf("iface braced: want a commit, got %v", err)
	}
	if cfg.Interfaces.Interfaces["ge-0/0/0"] == nil {
		t.Fatalf("iface braced: interface ge-0/0/0 missing from the committed config")
	}

	const riBraced = `routing-instances {
  ri1 { }
}` + ifaceBase
	cfg, err = CheckText(riBraced, -1)
	if err != nil {
		t.Fatalf("RI braced: want a commit, got %v", err)
	}
	found := false
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == "ri1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("RI braced: routing instance ri1 missing from the committed config")
	}

	// Control: a zone written as a leaf already compiles, and keeps
	// compiling — the gate must not touch zones.
	const zoneLeaf = `security {
  zones {
    security-zone trust;
  }
}` + ifaceBase
	cfg, err = CheckText(zoneLeaf, -1)
	if err != nil {
		t.Fatalf("zone leaf: want a commit, got %v", err)
	}
	if cfg.Security.Zones["trust"] == nil {
		t.Fatalf("zone leaf: zone trust missing from the committed config")
	}

	// A braced stanza still takes a wildcard group at commit.
	const ifaceWildBraced = `groups { G { interfaces { <*> { description fromgroup; } } } }
apply-groups G;
interfaces {
  ge-0/0/0 { }
  ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }
}`
	cfg, err = CheckText(ifaceWildBraced, -1)
	if err != nil {
		t.Fatalf("iface braced + wildcard group: want a commit, got %v", err)
	}
	if ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]; ifc == nil || ifc.Description != "fromgroup" {
		t.Fatalf("iface braced + wildcard group: want ge-0/0/0 carrying the group's description, got %+v", ifc)
	}
}
