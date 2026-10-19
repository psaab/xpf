package config

import (
	"reflect"
	"strings"
	"testing"
)

// #15668: `security zones functional-zone management` was rejected by the
// closed-world zones schema at commit and silently dropped by compileZones
// (which only read `security-zone` children), so management interfaces not
// named fxp0 lost their zone host-inbound treatment and fell into the
// unzoned junos-host catch-all. These tests pin the fix: the stanza is
// modelled in the schema and compiled into sec.Zones["management"] through
// the same zone-body compiler and strict validators as a security-zone.
//
// RED-on-revert: dropping the `functional-zone` schema node makes
// TestFunctionalZoneManagementSchemaValidates15668 fail with
// `unknown keyword "functional-zone"`; dropping the compileZones
// functional-zone arm makes the compile tests fail with zone "management"
// missing.

const functionalZoneMgmtHier15668 = `
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
    ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } }
}
security {
    screen { ids-option edge { icmp { ping-death; } } }
    zones {
        functional-zone {
            management {
                description mgmt-zone;
                screen edge;
                host-inbound-traffic { system-services { ssh; } protocols { ospf; } }
                interfaces {
                    ge-0/0/0.0;
                    ge-0/0/1.0 { host-inbound-traffic { system-services { https; } } }
                }
            }
        }
        security-zone trust { interfaces { lo0.0; } }
    }
}
`
func TestFunctionalZoneManagementSchemaValidates15668(t *testing.T) {
	tree := parseHierarchical(t, functionalZoneMgmtHier15668)
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate rejected valid functional-zone management: %v", err)
	}
	// Flat-set spelling reaches the same schema node.
	flat := buildTree(t, []string{
		"set interfaces ge-0/0/9 unit 0 family inet address 10.0.9.1/24",
		"set security zones functional-zone management interfaces ge-0/0/9.0",
		"set security zones functional-zone management host-inbound-traffic system-services ssh",
		"set security zones functional-zone management description mgmt",
	})
	if err := SchemaValidate(flat, nil); err != nil {
		t.Fatalf("SchemaValidate rejected flat-set functional-zone management: %v", err)
	}
}

func TestFunctionalZoneManagementCompiles15668(t *testing.T) {
	tree := parseHierarchical(t, functionalZoneMgmtHier15668)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict CompileConfig: %v", err)
	}
	z := cfg.Security.Zones["management"]
	if z == nil {
		t.Fatalf("zones = %v, want a compiled \"management\" zone", cfg.Security.Zones)
	}
	if z.Description != "mgmt-zone" {
		t.Fatalf("management description = %q, want mgmt-zone", z.Description)
	}
	if z.ScreenProfile != "edge" {
		t.Fatalf("management screen = %q, want edge", z.ScreenProfile)
	}
	if want := []string{"ge-0/0/0.0", "ge-0/0/1.0"}; !reflect.DeepEqual(z.Interfaces, want) {
		t.Fatalf("management interfaces = %v, want %v", z.Interfaces, want)
	}
	svc, proto, _ := z.InterfaceHostInboundEffective("ge-0/0/0.0")
	if !reflect.DeepEqual(svc, []string{"ssh"}) || !reflect.DeepEqual(proto, []string{"ospf"}) {
		t.Fatalf("management host-inbound = svc %v proto %v, want [ssh]/[ospf]", svc, proto)
	}
	if hib := z.InterfaceHostInbound["ge-0/0/1.0"]; hib == nil {
		t.Fatal("per-interface host-inbound override for ge-0/0/1.0 dropped")
	} else if svc, _, _ := z.InterfaceHostInboundEffective("ge-0/0/1.0"); !reflect.DeepEqual(svc, []string{"https"}) {
		t.Fatalf("ge-0/0/1.0 effective services = %v, want [https]", svc)
	}
	// Tolerant path compiles the same zone (previously silently dropped).
	cfgL, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient CompileConfig: %v", err)
	}
	if cfgL.Security.Zones["management"] == nil {
		t.Fatal("lenient compile dropped functional-zone management")
	}

	// Flat-set spelling compiles identically.
	flat := buildTree(t, []string{
		"set interfaces ge-0/0/9 unit 0 family inet address 10.0.9.1/24",
		"set security zones functional-zone management interfaces ge-0/0/9.0",
		"set security zones functional-zone management host-inbound-traffic system-services ssh",
		"set security zones functional-zone management description mgmt",
	})
	cfgF, err := CompileConfig(flat)
	if err != nil {
		t.Fatalf("strict CompileConfig (flat): %v", err)
	}
	zf := cfgF.Security.Zones["management"]
	if zf == nil || zf.Description != "mgmt" || !reflect.DeepEqual(zf.Interfaces, []string{"ge-0/0/9.0"}) {
		t.Fatalf("flat management zone = %+v, want description mgmt + [ge-0/0/9.0]", zf)
	}
}

func TestFunctionalZoneManagementStrictGates15668(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{
			name: "unknown child quarantined strict, warned lenient",
			text: `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
security { zones { functional-zone { management { interfaces { ge-0/0/0.0; } bogus-child x; } } } }`,
			want: "bogus-child",
		},
		{
			name: "unknown host-inbound token",
			text: `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
security { zones { functional-zone { management { interfaces { ge-0/0/0.0; } host-inbound-traffic { system-services { bogus-svc; } } } } } }`,
			want: "bogus-svc",
		},
		{
			name: "undefined screen profile",
			text: `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
security { zones { functional-zone { management { interfaces { ge-0/0/0.0; } screen nope; } } } }`,
			want: "nope",
		},
		{
			name: "undefined interface",
			text: `security { zones { functional-zone { management { interfaces { ge-0/0/7.0; } } } } }`,
			want: "ge-0/0/7.0",
		},
		{
			name: "packed interfaces tail",
			text: `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } } }
security { zones { functional-zone { management { interfaces [ ge-0/0/0.0 host-inbound-traffic ge-0/0/1.0 ]; } } } }`,
			want: "host-inbound-traffic",
		},
		{
			name: "empty interfaces stanza",
			text: `security { zones { functional-zone { management { interfaces { host-inbound-traffic { system-services ssh; } } } } } }`,
			want: "names no interface",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHierarchical(t, tc.text)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("strict CompileConfig accepted %s; want rejection naming %q", tc.name, tc.want)
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("strict error = %v, want it to name %q", err, tc.want)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient CompileConfig: %v", err)
			}
			if len(cfg.Warnings) == 0 {
				t.Fatalf("lenient compile produced no warning for %s", tc.name)
			}
		})
	}
}

func TestFunctionalZoneManagementConflictsAndDuplicates15668(t *testing.T) {
	// A security-zone literally named management shares the compiled zone:
	// duplicate blocks merge find-or-create, as duplicate security-zone
	// blocks already do (#4818).
	merged := parseHierarchical(t, `
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
security { zones {
    security-zone management { description from-security-zone; }
    functional-zone { management { interfaces { ge-0/0/0.0; } } }
} }`)
	cfg, err := CompileConfig(merged)
	if err != nil {
		t.Fatalf("CompileConfig (merge): %v", err)
	}
	z := cfg.Security.Zones["management"]
	if z == nil || z.Description != "from-security-zone" || !reflect.DeepEqual(z.Interfaces, []string{"ge-0/0/0.0"}) {
		t.Fatalf("merged management zone = %+v, want description + interface from both spellings", z)
	}

	// Same interface in management and another zone: membership conflict.
	conflict := parseHierarchical(t, `
interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } } }
security { zones {
    security-zone trust { interfaces { ge-0/0/0.0; } }
    functional-zone { management { interfaces { ge-0/0/0.0; } } }
} }`)
	if _, err := CompileConfig(conflict); err == nil {
		t.Fatal("strict CompileConfig accepted ge-0/0/0.0 in both trust and management")
	}
	if _, err := CompileConfigLenient(conflict); err != nil {
		t.Fatalf("lenient CompileConfig: %v", err)
	}
}
