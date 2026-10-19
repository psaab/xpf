package config

import "testing"

// #15705: compileIPMonitoring rebuilt a fresh PreferredRoute list for every
// repeated `policy <name>` block and appended it to the existing policy, so
// the same (routing-instance, destination) appeared twice. A split
// refinement (next-hop in block 1, preferred-metric only in block 2) then
// failed strict validation on the metric-only entry's empty next-hop, and a
// next-hop override in block 2 lost to the first entry in
// computeOverlayLocked's first-wins winner resolution. Junos (and the
// flat-set spelling) merge the blocks per attribute, last writer wins.

const ipmonDupPreamble15705 = `
services {
    rpm {
        probe WAN {
            test wan-a {
                target address 1.1.1.1;
            }
        }
    }
}
routing-instances {
    ISP-B {
        instance-type virtual-router;
    }
}
`

func ipmonPolicy15705(t *testing.T, cfg *Config, name string) *IPMonitoringPolicy {
	t.Helper()
	if cfg.Services.IPMonitoring == nil {
		t.Fatalf("ip-monitoring did not compile")
	}
	pol := cfg.Services.IPMonitoring.Policies[name]
	if pol == nil {
		t.Fatalf("policy %q did not compile (policies: %v)", name, cfg.Services.IPMonitoring.Policies)
	}
	return pol
}

// Split refinement: next-hop authored in the first block, preferred-metric
// alone in the second. The merged control carries both on one route.
func TestIPMonitoringSplitPolicyBlocksMergeRoute15705(t *testing.T) {
	dup := mustCompile8436(t, ipmonDupPreamble15705+`
services {
    ip-monitoring {
        policy wan-failover {
            match { rpm-probe WAN; }
            then { preferred-route { route 0.0.0.0/0 { next-hop 192.0.2.1; } } }
        }
        policy wan-failover {
            then { preferred-route { route 0.0.0.0/0 { preferred-metric 10; } } }
        }
    }
}
`)
	merged := mustCompile8436(t, ipmonDupPreamble15705+`
services {
    ip-monitoring {
        policy wan-failover {
            match { rpm-probe WAN; }
            then { preferred-route {
                route 0.0.0.0/0 { next-hop 192.0.2.1; }
                route 0.0.0.0/0 { preferred-metric 10; }
            } }
        }
    }
}
`)
	for label, cfg := range map[string]*Config{"duplicate": dup, "merged": merged} {
		pol := ipmonPolicy15705(t, cfg, "wan-failover")
		if len(pol.PreferredRoutes) != 1 {
			t.Fatalf("%s: PreferredRoutes = %+v, want exactly 1 merged route", label, pol.PreferredRoutes)
		}
		r := pol.PreferredRoutes[0]
		if r.RoutingInstance != "" || r.Destination != "0.0.0.0/0" ||
			r.NextHop != "192.0.2.1" || r.PreferredMetric != 10 {
			t.Fatalf("%s: route = %+v, want master 0.0.0.0/0 via 192.0.2.1 metric 10", label, r)
		}
		if pol.MatchRPMProbe != "WAN" {
			t.Fatalf("%s: MatchRPMProbe = %q, want WAN", label, pol.MatchRPMProbe)
		}
	}
}

// Next-hop override: the second block restates the next-hop and omits the
// metric. Last writer wins for the next-hop; the metric from block 1 (not
// restated) survives, exactly as the merged single block compiles.
func TestIPMonitoringPolicyBlockNextHopOverride15705(t *testing.T) {
	dup := mustCompile8436(t, ipmonDupPreamble15705+`
services {
    ip-monitoring {
        policy wan-failover {
            match { rpm-probe WAN; }
            then { preferred-route { route 0.0.0.0/0 { next-hop 192.0.2.1; preferred-metric 10; } } }
        }
    }
    ip-monitoring {
        policy wan-failover {
            then { preferred-route { route 0.0.0.0/0 { next-hop 192.0.2.2; } } }
        }
    }
}
`)
	merged := mustCompile8436(t, ipmonDupPreamble15705+`
services {
    ip-monitoring {
        policy wan-failover {
            match { rpm-probe WAN; }
            then { preferred-route {
                route 0.0.0.0/0 { next-hop 192.0.2.1; preferred-metric 10; }
                route 0.0.0.0/0 { next-hop 192.0.2.2; }
            } }
        }
    }
}
`)
	for label, cfg := range map[string]*Config{"duplicate": dup, "merged": merged} {
		pol := ipmonPolicy15705(t, cfg, "wan-failover")
		if len(pol.PreferredRoutes) != 1 {
			t.Fatalf("%s: PreferredRoutes = %+v, want exactly 1 merged route", label, pol.PreferredRoutes)
		}
		r := pol.PreferredRoutes[0]
		if r.NextHop != "192.0.2.2" || r.PreferredMetric != 10 {
			t.Fatalf("%s: route = %+v, want next-hop 192.0.2.2 (last writer) metric 10 (preserved)", label, r)
		}
	}
}

// Routing-instance routes merge by (routing-instance, destination) too.
func TestIPMonitoringSplitPolicyBlocksMergeRIRoute15705(t *testing.T) {
	dup := mustCompile8436(t, ipmonDupPreamble15705+`
services {
    ip-monitoring {
        policy wan-failover {
            match { rpm-probe WAN; }
            then { preferred-route { routing-instance ISP-B { route 0.0.0.0/0 { next-hop 192.0.2.1; } } } }
        }
        policy wan-failover {
            then { preferred-route { routing-instance ISP-B { route 0.0.0.0/0 { preferred-metric 7; } } } }
        }
    }
}
`)
	pol := ipmonPolicy15705(t, dup, "wan-failover")
	if len(pol.PreferredRoutes) != 1 {
		t.Fatalf("PreferredRoutes = %+v, want exactly 1 merged RI route", pol.PreferredRoutes)
	}
	r := pol.PreferredRoutes[0]
	if r.RoutingInstance != "ISP-B" || r.NextHop != "192.0.2.1" || r.PreferredMetric != 7 {
		t.Fatalf("route = %+v, want ISP-B via 192.0.2.1 metric 7", r)
	}
}

// Canonical destination identity: 0.0.0.1/0 and 0.0.0.0/0 are the same
// prefix after canonicalisation (the identity computeOverlayLocked uses),
// so a refinement under the canonical spelling must merge, not duplicate.
func TestIPMonitoringPolicyBlocksCanonicalDestination15705(t *testing.T) {
	dup := mustCompile8436(t, ipmonDupPreamble15705+`
services {
    ip-monitoring {
        policy wan-failover {
            match { rpm-probe WAN; }
            then { preferred-route { route 0.0.0.1/0 { next-hop 192.0.2.1; } } }
        }
        policy wan-failover {
            then { preferred-route { route 0.0.0.0/0 { preferred-metric 10; } } }
        }
    }
}
`)
	pol := ipmonPolicy15705(t, dup, "wan-failover")
	if len(pol.PreferredRoutes) != 1 {
		t.Fatalf("PreferredRoutes = %+v, want exactly 1 canonically merged route", pol.PreferredRoutes)
	}
	if pol.PreferredRoutes[0].NextHop != "192.0.2.1" || pol.PreferredRoutes[0].PreferredMetric != 10 {
		t.Fatalf("route = %+v, want via 192.0.2.1 metric 10", pol.PreferredRoutes[0])
	}
}

// Controls: distinct destinations and distinct routing instances for the
// same destination stay distinct entries — the merge key is exactly
// (routing-instance, canonical destination).
func TestIPMonitoringPolicyBlocksDistinctRoutesStayDistinct15705(t *testing.T) {
	cfg := mustCompile8436(t, ipmonDupPreamble15705+`
services {
    ip-monitoring {
        policy wan-failover {
            match { rpm-probe WAN; }
            then { preferred-route { route 0.0.0.0/0 { next-hop 192.0.2.1; } } }
        }
        policy wan-failover {
            then { preferred-route {
                route 10.0.0.0/8 { next-hop 192.0.2.2; }
                routing-instance ISP-B { route 0.0.0.0/0 { next-hop 192.0.2.3; } }
            } }
        }
    }
}
`)
	pol := ipmonPolicy15705(t, cfg, "wan-failover")
	if len(pol.PreferredRoutes) != 3 {
		t.Fatalf("PreferredRoutes = %+v, want 3 distinct routes", pol.PreferredRoutes)
	}
}
