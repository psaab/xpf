package config

import (
	"strings"
	"testing"
)

// #13108 (D1-03): packed resolving runs in security-zone must not hoist
// per-interface host-inbound-traffic to zone level nor bypass #6525/#6735.
// `description d1 interfaces ge-0/0/0.0 host-inbound-traffic;` — host-inbound
// was authored as per-interface body (packed), ambiguous. Compiler previously
// split at zone-level host-inbound-traffic, gates saw raw `description` node.

func zoneResolvingRunConfig() string {
	return `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone trust {
            description d1 interfaces ge-0/0/0.0 host-inbound-traffic;
        }
        security-zone untrust {
            description d2 interfaces apply-groups-except G;
        }
    }
}
`
}

func TestZoneResolvingRun13108StrictRejectsHoistAndEmpty(t *testing.T) {
	tree := parseHierarchical(t, zoneResolvingRunConfig())
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("strict CompileConfig accepted resolving-run zones; want rejection (#13108/#6525/#6735)")
	}
	if !strings.Contains(err.Error(), "host-inbound-traffic") && !strings.Contains(err.Error(), "interfaces") {
		t.Fatalf("strict error %q does not name interfaces/host-inbound-traffic", err)
	}
	t.Logf("strict rejection: %v", err)
}

func TestZoneResolvingRun13108LenientNoZoneHostInboundHoist(t *testing.T) {
	tree := parseHierarchical(t, zoneResolvingRunConfig())
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	trust := cfg.Security.Zones["trust"]
	if trust == nil {
		t.Fatal("trust zone missing")
	}
	if trust.HostInboundTraffic != nil {
		t.Fatalf("lenient compile hoisted per-interface host-inbound-traffic to zone level: %+v", trust.HostInboundTraffic)
	}
	// Lenient must warn (packed-tail or non-empty), not silently accept.
	joined := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(joined, "packed tail") && !strings.Contains(joined, "non-empty") && !strings.Contains(joined, "interfaces") {
		t.Fatalf("lenient warnings do not mention interfaces gate: %v", cfg.Warnings)
	}
}

func TestZoneResolvingRun13108PositiveControls(t *testing.T) {
	// Separate-lines spelling: description + interfaces + per-interface HIT block.
	src := `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}
security {
    zones {
        security-zone trust {
            description d1;
            interfaces {
                ge-0/0/0.0 {
                    host-inbound-traffic {
                        system-services ssh;
                    }
                }
            }
        }
    }
}
`
	tree := parseHierarchical(t, src)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("positive control strict compile: %v", err)
	}
	z := cfg.Security.Zones["trust"]
	if z.Description != "d1" {
		t.Fatalf("description = %q want d1", z.Description)
	}
	if len(z.Interfaces) != 1 || z.Interfaces[0] != "ge-0/0/0.0" {
		t.Fatalf("interfaces = %v", z.Interfaces)
	}
	if z.HostInboundTraffic != nil {
		t.Fatalf("zone-level HostInboundTraffic hoisted in control: %+v", z.HostInboundTraffic)
	}
	if z.InterfaceHostInbound["ge-0/0/0.0"] == nil {
		t.Fatalf("per-interface override missing: %v", z.InterfaceHostInbound)
	}

	// Pure leaf run: description + screen + tcp-rst packed must still expand.
	src2 := `
security {
    zones {
        security-zone trust {
            description hello screen my-screen tcp-rst;
        }
    }
    screen {
        ids-option my-screen {
            tcp {
                syn-flood {
                    timeout 20;
                }
            }
        }
    }
}
`
	tree2 := parseHierarchical(t, src2)
	cfg2, err := CompileConfig(tree2)
	if err != nil {
		t.Fatalf("leaf-run control strict compile: %v", err)
	}
	z2 := cfg2.Security.Zones["trust"]
	if z2.Description != "hello" || z2.ScreenProfile != "my-screen" || !z2.TCPRst {
		t.Fatalf("leaf-run control compiled desc=%q screen=%q tcpRst=%v", z2.Description, z2.ScreenProfile, z2.TCPRst)
	}
}
