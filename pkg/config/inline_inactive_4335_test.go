package config

// Regression tests for #4335 — an INLINE `inactive:` marker (mid-statement),
// not just a LEADING one.
//
// Junos collapses a deactivated sub-statement onto its parent statement's
// line, e.g. a destination-NAT pool address with a deactivated port:
//
//	address 2001:559:8585:80::7aef/128 inactive: port 32400;
//
// Here `inactive:` deactivates the `port 32400` modifier, leaving the address
// active as the pool member. Because `:` is an identifier character the lexer
// tokenizes `inactive:` as a single identifier, so before this fix it landed
// mid-Keys (`address 2001:...::7aef/128 inactive: port 32400`) and the DNAT
// pool compiler overwrote pool.Address with the literal "inactive:" token,
// rejecting the config with "address \"inactive:\" is not a single host
// address". The parser now drops the inline marker and every token it governs
// (the deactivated sub-statement) from the active statement, consistent with
// the #2008 H1 doctrine that a deactivated statement behaves as if absent.
//
// RED-on-revert: reverting the inline-marker branch in parseStatement makes
// the DNAT-pool commit assertion RED — pool.Address becomes "inactive:" and
// validateDNATPoolStrict rejects the config.

import (
	"reflect"
	"strings"
	"testing"
)

// TestInlineInactive_DNATPoolPortDeactivated is the core #4335 regression: a
// DNAT pool address with an inline `inactive: port <N>` commits, the address
// stays active as the pool member, and the deactivated port is absent
// (PortRaw == "" == preserve destination port).
func TestInlineInactive_DNATPoolPortDeactivated(t *testing.T) {
	tree := parseHierText(t, `security {
    nat {
        destination {
            pool p1 {
                address 2001:559:8585:80::7aef/128 inactive: port 32400;
            }
        }
    }
}`)

	// Parser: the inline marker and the token(s) it governs are dropped from
	// the active leaf's identity — pool.Address must NOT read "inactive:".
	addr := tree.FindChild("security").FindChild("nat").
		FindChild("destination").FindChild("pool").FindChild("address")
	if addr == nil {
		t.Fatal("address leaf not found")
	}
	if addr.Inactive {
		t.Fatal("the ADDRESS itself must stay active; only the port is deactivated")
	}
	wantKeys := []string{"address", "2001:559:8585:80::7aef/128"}
	if !reflect.DeepEqual(addr.Keys, wantKeys) {
		t.Fatalf("inline inactive: not pruned from Keys: got %v, want %v", addr.Keys, wantKeys)
	}

	// Compile: this is the drop-in blocker. Before the fix the compiler read
	// the literal "inactive:" as the pool address and rejected the config.
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile rejected an inline-inactive DNAT pool (#4335): %v", err)
	}
	pool := cfg.Security.NAT.Destination.Pools["p1"]
	if pool == nil {
		t.Fatalf("pool p1 not compiled; pools=%v", cfg.Security.NAT.Destination.Pools)
	}
	if pool.Address != "2001:559:8585:80::7aef/128" {
		t.Fatalf("pool.Address = %q, want the active host address", pool.Address)
	}
	// The deactivated port is absent -> preserve-destination-port (PortRaw "").
	if pool.PortRaw != "" || pool.Port != 0 {
		t.Fatalf("deactivated port must be absent: PortRaw=%q Port=%d, want \"\"/0",
			pool.PortRaw, pool.Port)
	}
}

// TestInlineInactive_EquivalentToPortAbsent proves the inline-inactive form
// compiles to exactly the same DNAT pool as authoring the address with no port
// leaf at all — the deactivated modifier truly behaves as if it were absent.
func TestInlineInactive_EquivalentToPortAbsent(t *testing.T) {
	withInline := parseHierText(t, `security {
    nat { destination { pool p1 {
        address 192.0.2.7/32 inactive: port 32400;
    } } }
}`)
	portAbsent := parseHierText(t, `security {
    nat { destination { pool p1 {
        address 192.0.2.7/32;
    } } }
}`)
	cfgA, err := CompileConfig(withInline)
	if err != nil {
		t.Fatalf("compile inline-inactive: %v", err)
	}
	cfgB, err := CompileConfig(portAbsent)
	if err != nil {
		t.Fatalf("compile port-absent: %v", err)
	}
	if !reflect.DeepEqual(cfgA.Security.NAT.Destination, cfgB.Security.NAT.Destination) {
		t.Fatalf("inline-inactive DNAT pool != port-absent pool:\n  inline=%+v\n  absent=%+v",
			cfgA.Security.NAT.Destination.Pools["p1"], cfgB.Security.NAT.Destination.Pools["p1"])
	}
}

// TestInlineInactive_ActivePortStillCompiles guards the sibling case: with NO
// inactive: marker the port modifier is honored (the fix must not swallow a
// legitimate inline port).
func TestInlineInactive_ActivePortStillCompiles(t *testing.T) {
	tree := parseHierText(t, `security {
    nat { destination { pool p1 {
        address 192.0.2.7/32 port 32400;
    } } }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile active port: %v", err)
	}
	pool := cfg.Security.NAT.Destination.Pools["p1"]
	if pool == nil || pool.Address != "192.0.2.7/32" {
		t.Fatalf("pool address wrong: %+v", pool)
	}
	if pool.Port != 32400 || pool.PortRaw != "32400" {
		t.Fatalf("active inline port dropped: Port=%d PortRaw=%q, want 32400", pool.Port, pool.PortRaw)
	}
}

// TestInlineInactive_LeadingMarkerStillLifted guards that the pre-existing
// LEADING `inactive:` handling is unchanged — the whole statement is
// deactivated and its real identity survives in Keys.
func TestInlineInactive_LeadingMarkerStillLifted(t *testing.T) {
	tree := parseHierText(t, `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                inactive: address 192.168.50.210/24;
            }
        }
    }
}`)
	addr := tree.FindChild("interfaces").FindChild("ge-0/0/0").
		FindChild("unit").FindChild("family").FindChild("address")
	if addr == nil {
		t.Fatal("address node not found")
	}
	if !addr.Inactive {
		t.Fatal("leading inactive: must deactivate the whole statement")
	}
	if got := addr.KeyPath(); got != "address 192.168.50.210/24" {
		t.Fatalf("leading inactive: leaked into Keys: %q", got)
	}
}

// TestInlineInactive_ParserDropsMarkerGenerically checks the parser-level
// behavior directly on a generic leaf (not DNAT-specific): the inline marker
// and everything it governs are dropped, leaving the active identity intact.
func TestInlineInactive_ParserDropsMarkerGenerically(t *testing.T) {
	tree := parseHierText(t, "system {\n    host-name keep inactive: extra token;\n}")
	hn := tree.FindChild("system").FindChild("host-name")
	if hn == nil {
		t.Fatalf("host-name not found; children=%v", tree.FindChild("system").Children)
	}
	if hn.Inactive {
		t.Fatal("the host-name statement itself must stay active")
	}
	want := []string{"host-name", "keep"}
	if !reflect.DeepEqual(hn.Keys, want) {
		t.Fatalf("inline marker not pruned generically: got %v, want %v", hn.Keys, want)
	}
	// No stray "inactive:" token survived anywhere in the identity.
	if strings.Contains(strings.Join(hn.Keys, " "), inactiveMarker) {
		t.Fatalf("inactive: marker leaked into Keys: %v", hn.Keys)
	}
}
