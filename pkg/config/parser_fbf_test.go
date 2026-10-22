package config

import (
	"testing"
)

// #1827 PR-2 — filter-based forwarding (FBF) composition tests.
//
// The FBF layer composes three existing pieces:
//   - `routing-instances <ri> instance-type forwarding` with statics,
//   - a firewall filter term `then routing-instance <ri>` (+ `count`),
//   - optionally `services ip-monitoring ... preferred-route
//     routing-instance <ri>` (the PR-1b commit-rejection of forwarding
//     targets is lifted in PR-2).
//
// Both AST shapes are exercised: flat set syntax via ParseSetCommand +
// SetPath (buildTree) and hierarchical block syntax via NewParser.

// fbfAssert checks the compiled config shape shared by both AST-shape
// tests below.
func fbfAssert(t *testing.T, cfg *Config) {
	t.Helper()
	var fbf *RoutingInstanceConfig
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == "ISP-B" {
			fbf = ri
		}
	}
	if fbf == nil {
		t.Fatal("routing instance ISP-B not compiled")
	}
	if fbf.InstanceType != "forwarding" {
		t.Fatalf("ISP-B instance-type = %q, want forwarding", fbf.InstanceType)
	}
	if fbf.TableID <= 0 {
		t.Fatalf("ISP-B TableID = %d, want auto-assigned > 0", fbf.TableID)
	}
	if len(fbf.StaticRoutes) != 1 || fbf.StaticRoutes[0].Destination != "0.0.0.0/0" ||
		len(fbf.StaticRoutes[0].NextHops) != 1 || fbf.StaticRoutes[0].NextHops[0].Address != "172.16.80.1" {
		t.Fatalf("ISP-B statics = %+v, want single 0.0.0.0/0 via 172.16.80.1", fbf.StaticRoutes)
	}

	filter := cfg.Firewall.FiltersInet["fbf-steer"]
	if filter == nil {
		t.Fatal("filter fbf-steer not compiled")
	}
	if len(filter.Terms) != 2 {
		t.Fatalf("fbf-steer terms = %d, want 2", len(filter.Terms))
	}
	steer := filter.Terms[0]
	if steer.Name != "to-isp-b" {
		t.Fatalf("first term = %q, want to-isp-b", steer.Name)
	}
	if steer.RoutingInstance != "ISP-B" {
		t.Fatalf("steer term routing-instance = %q, want ISP-B", steer.RoutingInstance)
	}
	if steer.Count != "fbf-isp-b" {
		t.Fatalf("steer term count = %q, want fbf-isp-b (per-policy FBF counter)", steer.Count)
	}
	if len(steer.SourceAddresses) != 1 || steer.SourceAddresses[0] != "10.0.61.0/24" {
		t.Fatalf("steer term source addresses = %+v", steer.SourceAddresses)
	}
	if filter.Terms[1].Action != FilterActionAccept {
		t.Fatalf("default term action = %q, want accept", filter.Terms[1].Action)
	}

	pol := cfg.Services.IPMonitoring.Policies["wan-failover"]
	if pol == nil {
		t.Fatal("ip-monitoring policy wan-failover not compiled")
	}
	if len(pol.PreferredRoutes) != 1 {
		t.Fatalf("PreferredRoutes = %+v, want 1", pol.PreferredRoutes)
	}
	pr := pol.PreferredRoutes[0]
	if pr.RoutingInstance != "ISP-B" || pr.Destination != "0.0.0.0/0" || pr.NextHop != "172.16.80.1" {
		t.Fatalf("preferred-route = %+v, want ISP-B 0.0.0.0/0 via 172.16.80.1", pr)
	}
}

// TestFBFCompositionFlatSet: forwarding instance + FBF filter +
// ip-monitoring preferred-route targeting the forwarding instance all
// compile from flat set syntax. This is the PR-2 regression for the
// lifted PR-1b commit-rejection — before PR-2 the last line was a hard
// commit error.
func TestFBFCompositionFlatSet(t *testing.T) {
	lines := append(rpmProbeLines(),
		"set routing-instances ISP-B instance-type forwarding",
		"set routing-instances ISP-B routing-options static route 0.0.0.0/0 next-hop 172.16.80.1",
		"set firewall family inet filter fbf-steer term to-isp-b from source-address 10.0.61.0/24",
		"set firewall family inet filter fbf-steer term to-isp-b then count fbf-isp-b",
		"set firewall family inet filter fbf-steer term to-isp-b then routing-instance ISP-B",
		"set firewall family inet filter fbf-steer term default then accept",
		"set services ip-monitoring policy wan-failover match rpm-probe WAN",
		"set services ip-monitoring policy wan-failover then preferred-route routing-instance ISP-B route 0.0.0.0/0 next-hop 172.16.80.1",
	)
	tree := buildTree(t, lines)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	fbfAssert(t, cfg)
}

// TestFBFCompositionHierarchical: the same composition in hierarchical
// block syntax.
func TestFBFCompositionHierarchical(t *testing.T) {
	input := `services {
    rpm {
        probe WAN {
            test wan-a {
                target address 1.1.1.1;
                destination-interface reth0.50;
                next-hop 172.16.50.1;
            }
        }
    }
    ip-monitoring {
        policy wan-failover {
            match {
                rpm-probe WAN;
            }
            then {
                preferred-route {
                    routing-instance ISP-B {
                        route 0.0.0.0/0 {
                            next-hop 172.16.80.1;
                        }
                    }
                }
            }
        }
    }
}
routing-instances {
    ISP-B {
        instance-type forwarding;
        routing-options {
            static {
                route 0.0.0.0/0 next-hop 172.16.80.1;
            }
        }
    }
}
firewall {
    family inet {
        filter fbf-steer {
            term to-isp-b {
                from {
                    source-address 10.0.61.0/24;
                }
                then {
                    count fbf-isp-b;
                    routing-instance ISP-B;
                }
            }
            term default {
                then accept;
            }
        }
    }
}
`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	fbfAssert(t, cfg)
}
