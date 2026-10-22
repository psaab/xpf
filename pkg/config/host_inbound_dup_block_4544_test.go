package config

import "testing"

// Tests for #4544: a hand-authored `load override` config can carry two literal
// `host-inbound-traffic { ... }` blocks under one security-zone (or one
// interface). The hierarchical parser (NewParser → parseStatements) keeps them
// as separate same-key siblings — it does NOT merge same-key blocks — and
// `load override` splices that raw candidate straight into the compiler with no
// FormatSet round-trip and no duplicate-block schema rejection. Before #4544
// the zone-level `case "host-inbound-traffic"` OVERWROTE on the second block
// and the interface-level reader used FindChild (first-wins), so the second
// block was silently dropped: host-inbound admission narrowed (service DoS) or
// fail-opened if the dropped block was the restrictive one. Junos MERGES
// repeated blocks; the compiler now unions their system-services / protocols
// via mergeHostInbound at BOTH levels.
//
// SHAPE NOTE (per CLAUDE.md): duplicate same-key blocks are only expressible via
// the hierarchical / NewParser (load-override) path. Flat-set ParseSetCommand +
// SetPath MERGES two lines with an identical key-path into one node, so it is
// structurally immune and is NOT the reproducer here — parseHierText is.
//
// #6525: the configs below gained a top-level `interfaces ge-0/0/0 { ... }`
// definition. They use the compact-leaf zone-membership spelling
// `interfaces ge-0/0/0;`, which before #6525 compiled to an EMPTY member set —
// so the strict zone-interface-defined gate passed vacuously and the missing
// definition went unnoticed. Now the member actually lands in zone membership
// and the gate (correctly) demands the interface exist.

// TestHostInboundDupBlock4544ZoneMerges is the primary zone-level RED-on-revert
// guard: two host-inbound-traffic blocks (block 1: system-services ssh; block 2:
// protocols ospf) must compile to ONE merged HostInboundTraffic carrying BOTH
// ssh AND ospf. Reverting the zone-level merge to `zone.HostInboundTraffic =
// parseHostInboundNode(prop)` overwrites with the last block (only ospf, ssh
// lost) and this goes RED.
func TestHostInboundDupBlock4544ZoneMerges(t *testing.T) {
	tree := parseHierText(t, `
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
            interfaces ge-0/0/0;
            host-inbound-traffic {
                system-services ssh;
            }
            host-inbound-traffic {
                protocols ospf;
            }
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	z := cfg.Security.Zones["trust"]
	if z == nil || z.HostInboundTraffic == nil {
		t.Fatalf("trust zone host-inbound-traffic missing")
	}
	if !containsStr4544(z.HostInboundTraffic.SystemServices, "ssh") {
		t.Fatalf("system-services = %v, want to contain ssh (zone overwrite dropped block 1 — #4544)",
			z.HostInboundTraffic.SystemServices)
	}
	if !containsStr4544(z.HostInboundTraffic.Protocols, "ospf") {
		t.Fatalf("protocols = %v, want to contain ospf (#4544)", z.HostInboundTraffic.Protocols)
	}
}

// TestHostInboundDupBlock4544InterfaceMerges is the interface-level RED-on-revert
// guard (#3362 per-interface override): two host-inbound-traffic blocks under one
// interface must merge. Reverting to FindChild reads only block 1 (ssh, ospf
// lost) and this goes RED.
func TestHostInboundDupBlock4544InterfaceMerges(t *testing.T) {
	// Junos / load-override interface block spelling (`interfaces { ifN { ... } }`).
	tree := parseHierText(t, `
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
            interfaces {
                ge-0/0/0 {
                    host-inbound-traffic {
                        system-services ssh;
                    }
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
	hib := cfg.Security.Zones["trust"].InterfaceHostInbound["ge-0/0/0"]
	if hib == nil {
		t.Fatalf("per-interface host-inbound missing")
	}
	if !containsStr4544(hib.SystemServices, "ssh") {
		t.Fatalf("per-iface system-services = %v, want to contain ssh (FindChild first-wins dropped block 2 — #4544)",
			hib.SystemServices)
	}
	if !containsStr4544(hib.Protocols, "ospf") {
		t.Fatalf("per-iface protocols = %v, want to contain ospf (#4544)", hib.Protocols)
	}
}

// TestHostInboundDupBlock4544MergeDedups confirms the merged token sets are
// deduplicated: two blocks that both list ssh yield a SINGLE ssh, and the
// distinct tokens across blocks all survive.
func TestHostInboundDupBlock4544MergeDedups(t *testing.T) {
	tree := parseHierText(t, `
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
            interfaces ge-0/0/0;
            host-inbound-traffic {
                system-services [ ssh https ];
                protocols ospf;
            }
            host-inbound-traffic {
                system-services [ ssh ping ];
                protocols ospf;
            }
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	hib := cfg.Security.Zones["trust"].HostInboundTraffic
	if hib == nil {
		t.Fatalf("trust zone host-inbound-traffic missing")
	}
	if n := countStr4544(hib.SystemServices, "ssh"); n != 1 {
		t.Fatalf("ssh appears %d times in %v, want exactly 1 (merge must dedup — #4544)", n, hib.SystemServices)
	}
	for _, want := range []string{"ssh", "https", "ping"} {
		if !containsStr4544(hib.SystemServices, want) {
			t.Fatalf("system-services = %v, want to contain %q (#4544)", hib.SystemServices, want)
		}
	}
	if n := countStr4544(hib.Protocols, "ospf"); n != 1 {
		t.Fatalf("ospf appears %d times in %v, want exactly 1 (merge must dedup — #4544)", n, hib.Protocols)
	}
}

// TestHostInboundDupBlock4544SingleBlockUnchanged is the byte-identical negative
// control: a SINGLE host-inbound-traffic block must produce the exact token
// multiset the block authored, with no dedup and no reordering — the #4544 merge
// must not perturb the overwhelmingly-common single-block case. A single block
// with a deliberate duplicate token keeps BOTH copies (mergeHostInbound returns
// the first parse unchanged when there is nothing to merge into).
func TestHostInboundDupBlock4544SingleBlockUnchanged(t *testing.T) {
	// Zone-level single block.
	ztree := parseHierText(t, `
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
            interfaces ge-0/0/0;
            host-inbound-traffic {
                system-services [ ssh ssh https ];
                protocols ospf;
            }
        }
    }
}`)
	zcfg, err := CompileConfig(ztree)
	if err != nil {
		t.Fatalf("CompileConfig (zone): %v", err)
	}
	zhib := zcfg.Security.Zones["trust"].HostInboundTraffic
	if !equalStrs4544(zhib.SystemServices, []string{"ssh", "ssh", "https"}) {
		t.Fatalf("single-block zone system-services = %v, want [ssh ssh https] byte-identical (no dedup on single block — #4544)",
			zhib.SystemServices)
	}
	if !equalStrs4544(zhib.Protocols, []string{"ospf"}) {
		t.Fatalf("single-block zone protocols = %v, want [ospf] (#4544)", zhib.Protocols)
	}

	// Interface-level single block (Junos block spelling).
	itree := parseHierText(t, `
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
            interfaces {
                ge-0/0/0 {
                    host-inbound-traffic {
                        system-services [ ssh ssh https ];
                        protocols ospf;
                    }
                }
            }
        }
    }
}`)
	icfg, err := CompileConfig(itree)
	if err != nil {
		t.Fatalf("CompileConfig (iface): %v", err)
	}
	ihib := icfg.Security.Zones["trust"].InterfaceHostInbound["ge-0/0/0"]
	if ihib == nil {
		t.Fatalf("per-interface host-inbound missing")
	}
	if !equalStrs4544(ihib.SystemServices, []string{"ssh", "ssh", "https"}) {
		t.Fatalf("single-block iface system-services = %v, want [ssh ssh https] byte-identical (#4544)",
			ihib.SystemServices)
	}
	if !equalStrs4544(ihib.Protocols, []string{"ospf"}) {
		t.Fatalf("single-block iface protocols = %v, want [ospf] (#4544)", ihib.Protocols)
	}
}

func containsStr4544(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func countStr4544(s []string, want string) int {
	n := 0
	for _, v := range s {
		if v == want {
			n++
		}
	}
	return n
}

func equalStrs4544(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
