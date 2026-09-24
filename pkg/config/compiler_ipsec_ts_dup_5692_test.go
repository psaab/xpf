package config

import (
	"strings"
	"testing"
)

// #5692: repeated valid IPsec traffic-selector `local-ip` / `remote-ip` leaves
// under ONE traffic-selector pass strict admission (each is a well-formed CIDR),
// but the typed compiler (compiler_ipsec.go traffic-selector loop) reads them
// LAST-WINS, silently dropping every prefix but the last — a multi-selector
// policy that enforces only its last prefix. The hierarchical / load-merge /
// HA-config-sync parse path keeps the repeated sibling leaves (the flat-set
// commit path collapses them last-wins in SetPath, matching Junos "set
// replaces" for a single-value leaf, so it never produces the duplicate).
//
// Junos models each traffic-selector as exactly ONE local-ip + ONE remote-ip;
// multiple prefixes are expressed as separate NAMED traffic-selectors (each
// renders its own swanctl SA child). validateIPsecTrafficSelectorsStrict now
// REJECTS a duplicate at strict commit / commit-check (lenient-warn on load /
// peer-sync, #1960) so the truncation is operator-visible.

// TestTrafficSelectorDuplicateLocalIPRejectedStrict_5692 is the primary
// fail-on-revert guard: a hierarchical traffic-selector with TWO local-ip
// leaves is rejected at strict commit.
//
// FAIL-ON-REVERT: removing the #5692 value-count reject loop from
// validateIPsecTrafficSelectorsStrict makes CompileConfig accept the duplicate
// (silently keeping only the last local-ip), so this reject assertion fires RED.
func TestTrafficSelectorDuplicateLocalIPRejectedStrict_5692(t *testing.T) {
	tree := hierTree(t, `security {
    ipsec {
        vpn v1 {
            bind-interface st0;
            traffic-selector ts1 {
                local-ip 10.0.0.0/24;
                local-ip 10.0.1.0/24;
                remote-ip 192.0.2.0/24;
            }
        }
    }
}`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a traffic-selector with two local-ip leaves; want a strict reject (#5692)")
	}
	if !strings.Contains(err.Error(), "local-ip prefixes") || !strings.Contains(err.Error(), "ts1") {
		t.Fatalf("reject error %q must name the selector and the duplicate local-ip", err.Error())
	}
}

// TestTrafficSelectorDuplicateRemoteIPRejectedStrict_5692 is the remote-ip
// symmetric.
func TestTrafficSelectorDuplicateRemoteIPRejectedStrict_5692(t *testing.T) {
	tree := hierTree(t, `security {
    ipsec {
        vpn v1 {
            bind-interface st0;
            traffic-selector ts1 {
                local-ip 10.0.0.0/24;
                remote-ip 192.0.2.0/24;
                remote-ip 198.51.100.0/24;
            }
        }
    }
}`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a traffic-selector with two remote-ip leaves; want a strict reject (#5692)")
	}
	if !strings.Contains(err.Error(), "remote-ip prefixes") {
		t.Fatalf("reject error %q must reference the duplicate remote-ip", err.Error())
	}
}

// TestTrafficSelectorDuplicateLenientWarns_5692 proves the tolerant load /
// peer-sync path DOWNGRADES the duplicate to a warning (no hard fail, #1960
// no-brick) — an already-persisted config carrying a duplicate still BOOTS, and
// the compiler's last-wins keeps it inert (enforces the last, as before, now
// flagged).
func TestTrafficSelectorDuplicateLenientWarns_5692(t *testing.T) {
	tree := hierTree(t, `security {
    ipsec {
        vpn v1 {
            traffic-selector ts1 {
                local-ip 10.0.0.0/24;
                local-ip 10.0.1.0/24;
            }
        }
    }
}`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load must NOT hard-fail on a duplicate selector, got %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "local-ip prefixes") && strings.Contains(w, "ts1") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("tolerant load must record a duplicate-selector warning, got %v", cfg.Warnings)
	}
	// The compiler keeps the LAST prefix (unchanged runtime behavior).
	if got := cfg.Security.IPsec.VPNs["v1"].TrafficSelectors["ts1"].LocalIP; got != "10.0.1.0/24" {
		t.Fatalf("compiler must keep the last local-ip, got %q", got)
	}
}

// TestTrafficSelectorMultipleNamedSelectorsCompile_5692 proves the Junos-correct
// way to express multiple selectors — separate NAMED traffic-selectors, each
// with one local-ip/remote-ip — compiles clean via flat set, and BOTH are
// accumulated (not truncated).
func TestTrafficSelectorMultipleNamedSelectorsCompile_5692(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set security ipsec vpn v1 traffic-selector ts1 local-ip 10.0.0.0/24",
		"set security ipsec vpn v1 bind-interface st0",
		"set security ipsec vpn v1 traffic-selector ts1 remote-ip 192.0.2.0/24",
		"set security ipsec vpn v1 traffic-selector ts2 local-ip 10.0.1.0/24",
		"set security ipsec vpn v1 traffic-selector ts2 remote-ip 198.51.100.0/24",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("two named traffic-selectors must compile, got %v", err)
	}
	sel := cfg.Security.IPsec.VPNs["v1"].TrafficSelectors
	if len(sel) != 2 {
		t.Fatalf("expected 2 named traffic-selectors, got %d", len(sel))
	}
	if sel["ts1"].LocalIP != "10.0.0.0/24" || sel["ts2"].LocalIP != "10.0.1.0/24" {
		t.Fatalf("both named selectors must be accumulated, got ts1=%q ts2=%q", sel["ts1"].LocalIP, sel["ts2"].LocalIP)
	}
}

// TestTrafficSelectorFlatSetLastWinsCompiles_5692 proves the fix does NOT
// false-reject the normal commit path: repeated flat-set `local-ip` lines
// collapse last-wins in SetPath (Junos "set replaces" for a single-value leaf),
// so the AST carries only ONE local-ip and the duplicate gate does not fire.
func TestTrafficSelectorFlatSetLastWinsCompiles_5692(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set security ipsec vpn v1 traffic-selector ts1 local-ip 10.0.0.0/24",
		"set security ipsec vpn v1 bind-interface st0",
		"set security ipsec vpn v1 traffic-selector ts1 local-ip 10.0.1.0/24",
		"set security ipsec vpn v1 traffic-selector ts1 remote-ip 192.0.2.0/24",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("flat-set last-wins must still compile (SetPath collapsed the duplicate), got %v", err)
	}
	if got := cfg.Security.IPsec.VPNs["v1"].TrafficSelectors["ts1"].LocalIP; got != "10.0.1.0/24" {
		t.Fatalf("flat-set last-wins local-ip = %q, want 10.0.1.0/24", got)
	}
}
