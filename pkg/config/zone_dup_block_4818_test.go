package config

import "testing"

// Tests for #4818: a hand-authored `load override` config can carry two
// literal `security-zone <name> { ... }` TOP-LEVEL sibling blocks (e.g. from
// a copy-paste error, or concatenated config snippets/templates). The
// hierarchical parser (NewParser -> parseStatements) keeps them as separate
// same-key siblings — it does NOT merge same-name blocks — and `load
// override` (Store.LoadOverride, pkg/configstore/store_command.go) splices
// that raw candidate straight into the compiler with no FormatSet
// round-trip and no duplicate-block schema rejection. Before #4818,
// compileZones (pkg/config/compiler_security_zones.go) allocated a fresh
// ZoneConfig per instance and did an unconditional `sec.Zones[inst.name] =
// zone`, so the SECOND security-zone instance silently REPLACED the first,
// discarding its interfaces/host-inbound/address-book/description/screen/
// tcp-rst wholesale. Junos merges repeated blocks; the compiler now
// find-or-creates the ZoneConfig by name so properties from every sibling
// instance accumulate onto the SAME zone (mirroring the #4544 fix, which
// already merges repeated host-inbound-traffic blocks WITHIN one instance).
//
// SHAPE NOTE (per CLAUDE.md): a duplicate top-level security-zone block is
// only expressible via the hierarchical / NewParser (load-override) path.
// Flat-set ParseSetCommand + SetPath MERGES two lines with an identical
// key-path into one node, so it is structurally immune and is NOT the
// reproducer here — parseHierText is (see #4818's "Correction to the
// reviewed trace").
//
// zoneDup4818Iface0 pre-defines ge-0/0/0 under the top-level `interfaces {}`
// stanza so the (unrelated) #4515 zone->undefined-interface strict gate
// does not reject these fixtures; a zone `interfaces { ge-0/0/0; }` member
// must name a configured interface. Container form (braces) is required for
// the zone-level `interfaces` list itself — `interfaces ge-0/0/0;` (no
// braces) is a two-key leaf with no Children and silently binds no member.
const zoneDup4818Iface0 = `
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/24;
            }
        }
    }
}`

// TestZoneDupBlock4818InterfacesAndHostInboundMerge is the primary
// RED-on-revert guard: block 1 declares only `interfaces`, block 2 declares
// only `host-inbound-traffic`. Reverting compileZones to unconditionally
// allocate a fresh ZoneConfig per instance (`zone := &ZoneConfig{Name:
// inst.name}` before the find-or-create) makes the second instance replace
// the first, so Interfaces is empty (block 1's ge-0/0/0 dropped) — RED.
func TestZoneDupBlock4818InterfacesAndHostInboundMerge(t *testing.T) {
	tree := parseHierText(t, zoneDup4818Iface0+`
security {
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/0;
            }
        }
        security-zone trust {
            host-inbound-traffic {
                system-services ssh;
            }
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	z := cfg.Security.Zones["trust"]
	if z == nil {
		t.Fatalf("trust zone missing")
	}
	if !containsStr(z.Interfaces, "ge-0/0/0") {
		t.Fatalf("Interfaces = %v, want to contain ge-0/0/0 (block 1 dropped by block 2 overwrite — #4818)", z.Interfaces)
	}
	if z.HostInboundTraffic == nil || !containsStr(z.HostInboundTraffic.SystemServices, "ssh") {
		t.Fatalf("HostInboundTraffic = %+v, want SystemServices to contain ssh (#4818)", z.HostInboundTraffic)
	}
}

// TestZoneDupBlock4818ThreeInstancesAllPropertiesSurvive covers a THIRD
// dimension often missed by a two-instance test: interfaces, host-inbound,
// and address-book split across three separate top-level instances of the
// same zone name must all survive in the compiled zone.
func TestZoneDupBlock4818ThreeInstancesAllPropertiesSurvive(t *testing.T) {
	tree := parseHierText(t, zoneDup4818Iface0+`
security {
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/0;
            }
        }
        security-zone trust {
            host-inbound-traffic {
                system-services ssh;
            }
        }
        security-zone trust {
            address-book {
                address host1 10.1.1.1/32;
            }
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	z := cfg.Security.Zones["trust"]
	if z == nil {
		t.Fatalf("trust zone missing")
	}
	if !containsStr(z.Interfaces, "ge-0/0/0") {
		t.Fatalf("Interfaces = %v, want ge-0/0/0 (#4818)", z.Interfaces)
	}
	if z.HostInboundTraffic == nil || !containsStr(z.HostInboundTraffic.SystemServices, "ssh") {
		t.Fatalf("HostInboundTraffic = %+v, want ssh (#4818)", z.HostInboundTraffic)
	}
	if z.AddressBook == nil || z.AddressBook.Addresses["host1"] == nil {
		t.Fatalf("AddressBook = %+v, want host1 present (#4818)", z.AddressBook)
	}
}

// TestZoneDupBlock4818InterfaceHostInboundMergesAcrossInstances covers the
// #3362 per-interface host-inbound override merging across two duplicate
// top-level zone instances that BOTH name the same interface.
func TestZoneDupBlock4818InterfaceHostInboundMergesAcrossInstances(t *testing.T) {
	tree := parseHierText(t, zoneDup4818Iface0+`
security {
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/0 {
                    host-inbound-traffic {
                        system-services ssh;
                    }
                }
            }
        }
        security-zone trust {
            interfaces {
                ge-0/0/0 {
                    host-inbound-traffic {
                        protocols ospf;
                    }
                }
            }
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	z := cfg.Security.Zones["trust"]
	if z == nil {
		t.Fatalf("trust zone missing")
	}
	hib := z.InterfaceHostInbound["ge-0/0/0"]
	if hib == nil {
		t.Fatalf("per-interface host-inbound missing")
	}
	if !containsStr(hib.SystemServices, "ssh") {
		t.Fatalf("per-iface system-services = %v, want ssh (block 1 dropped — #4818)", hib.SystemServices)
	}
	if !containsStr(hib.Protocols, "ospf") {
		t.Fatalf("per-iface protocols = %v, want ospf (#4818)", hib.Protocols)
	}
}

// TestZoneDupBlock4818SingleBlockUnchanged is the byte-identical negative
// control: a single security-zone instance must compile exactly as before
// the find-or-create change (no dedup, no reordering).
func TestZoneDupBlock4818SingleBlockUnchanged(t *testing.T) {
	tree := parseHierText(t, zoneDup4818Iface0+`
security {
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/0;
            }
            host-inbound-traffic {
                system-services ssh;
            }
            tcp-rst;
            description "trust zone";
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	z := cfg.Security.Zones["trust"]
	if z == nil {
		t.Fatalf("trust zone missing")
	}
	if !equalStrs4544(z.Interfaces, []string{"ge-0/0/0"}) {
		t.Fatalf("Interfaces = %v, want [ge-0/0/0] byte-identical single-block behaviour", z.Interfaces)
	}
	if !z.TCPRst {
		t.Fatalf("TCPRst = false, want true")
	}
	if z.Description != "trust zone" {
		t.Fatalf("Description = %q, want %q", z.Description, "trust zone")
	}
}
