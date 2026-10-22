package config_test

// Regression tests for #2448: a static-route `destination` prefix and a
// next-hop value were accepted untyped at commit and then SILENTLY dropped
// downstream — a malformed destination falls out of the Rust FIB builder's
// parse loop (userspace-dp forwarding_build/fib.rs populate_routes) with no
// error, and a malformed next-hop either becomes an interface-only route or
// a next-hop with ifindex 0 (a blackhole). The FRR renderer
// (pkg/frr/config_render.go) likewise emits whatever string it is given.
// The operator committed the route successfully but it never installs.
//
// The fix types the `route` identity arg with ValidateRouteDestination
// (family-agnostic CIDR) and the `next-hop` value with ValidateStaticNextHop
// (IP / ip@interface / interface name). Each "RejectsBad" case FAILS to
// error before the fix and errors after it; each "AcceptsValid" case guards
// the spellings the compiler/renderer already accept against a false-reject.
//
// Fail-on-revert: temporarily strip keyValidator/validator from the route
// schema node (or run with origin/master), and the RejectsBad cases stop
// erroring — that is the pre-fix silent-accept behaviour these tests pin.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// --- destination: must be a valid CIDR ----------------------------------

func TestSchema2448_RouteDestination_RejectsBadCIDR(t *testing.T) {
	err := schemaCheck(t, `routing-options {
    static {
        route 10.0.0.0/99 {
            next-hop 192.168.1.1;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for malformed route destination 10.0.0.0/99, got nil")
	}
	if !strings.Contains(err.Error(), "10.0.0.0/99") {
		t.Fatalf("error should quote the bad destination: %v", err)
	}
}

func TestSchema2448_RouteDestination_RejectsGarbage(t *testing.T) {
	err := schemaCheck(t, `routing-options {
    static {
        route not-a-prefix {
            next-hop 192.168.1.1;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for garbage route destination, got nil")
	}
}

// A bare IP without a /prefix-length must be rejected: net.ParseCIDR fails
// and the route is silently dropped by both the FRR renderer and the FIB.
func TestSchema2448_RouteDestination_RejectsMissingLength(t *testing.T) {
	err := schemaCheck(t, `routing-options {
    static {
        route 10.0.0.0 {
            next-hop 192.168.1.1;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for route destination without /prefix-length, got nil")
	}
}

// The default routes and IPv6 destinations must NOT be rejected.
func TestSchema2448_RouteDestination_AcceptsValid(t *testing.T) {
	for _, dest := range []string{"0.0.0.0/0", "10.0.0.0/24", "172.16.0.0/12", "::/0", "2001:db8::/32"} {
		cfg := `routing-options {
    static {
        route ` + dest + ` {
            next-hop ` + nextHopFor(dest) + `;
        }
    }
}`
		if err := schemaCheck(t, cfg); err != nil {
			t.Fatalf("unexpected error for valid destination %s: %v", dest, err)
		}
	}
}

// nextHopFor picks a family-matched gateway so the AcceptsValid destination
// cases also exercise a valid next-hop (a v4 route with a v6 next-hop is a
// different concern than this test's subject).
func nextHopFor(dest string) string {
	if strings.Contains(dest, ":") {
		return "2001:db8::1"
	}
	return "192.168.1.1"
}

// --- next-hop: IP / ip@interface / interface name -----------------------

func TestSchema2448_NextHop_RejectsBadIP(t *testing.T) {
	err := schemaCheck(t, `routing-options {
    static {
        route 10.0.0.0/24 {
            next-hop 1.2.3.999;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for malformed next-hop 1.2.3.999, got nil")
	}
	if !strings.Contains(err.Error(), "1.2.3.999") {
		t.Fatalf("error should quote the bad next-hop: %v", err)
	}
}

func TestSchema2448_NextHop_RejectsBadV6(t *testing.T) {
	err := schemaCheck(t, `routing-options {
    static {
        route ::/0 {
            next-hop 2001:db8::garbage;
        }
    }
}`)
	if err == nil {
		t.Fatal("expected error for malformed IPv6 next-hop, got nil")
	}
}

// The ip@interface / @interface spec is a Rust-FIB-internal form
// (forwarding_build/fib.rs split_once('@')); the Junos lexer rejects '@' as
// an unexpected character, so it never reaches the config layer. The
// validator still classifies it correctly for any programmatic caller —
// covered by the unit test below rather than through the parser.
func TestSchema2448_ValidateStaticNextHop_AtSpec(t *testing.T) {
	// Bad IP before '@' must be rejected (would silently degrade to
	// interface-only in the FIB); a valid ip@iface / @iface is accepted.
	if err := config.ValidateStaticNextHop("notanip@eth0"); err == nil {
		t.Fatal("expected error for notanip@eth0, got nil")
	}
	if err := config.ValidateStaticNextHop("10.0.0.1@ge-0-0-0.0"); err != nil {
		t.Fatalf("unexpected error for 10.0.0.1@ge-0-0-0.0: %v", err)
	}
	if err := config.ValidateStaticNextHop("@reth0.50"); err != nil {
		t.Fatalf("unexpected error for @reth0.50: %v", err)
	}
	if err := config.ValidateStaticNextHop("10.0.0.1@"); err == nil {
		t.Fatal("expected error for trailing '@' with no interface, got nil")
	}
}

// TestStaticNextHop_ZoneIDPercentRejected_4423 pins the #4423 routing-audit
// L3 disposition (NOT-A-BUG): the RFC 4007 "scoped address" zone-id form
// `fe80::1%iface` — a Linux getaddrinfo() / `ip route` convention — is NOT a
// Junos next-hop spelling and must NOT be accepted. In Junos (and xpf) an
// IPv6 link-local gateway is written with an explicit egress clause,
// `next-hop fe80::1 interface reth0.50`, which the compiler encodes for the
// Rust FIB as the internal `ip@interface` spec (routes.go buildRouteSnapshots
// → forwarding_build/fib.rs split_once('@')). There is no `%` producer or
// consumer anywhere in the pipeline, so accepting `%iface` would create a
// second, silently-degrading link-local syntax (net.ParseIP rejects the
// zone-id, so the FIB would drop the gateway to ifindex 0). ValidateStaticNextHop
// (schema_validators.go) already rejects it because `%` is neither part of a
// parseable IP nor an allowed interface-name character; this test locks that
// contract so a well-meaning "accept %iface" change cannot regress it.
func TestStaticNextHop_ZoneIDPercentRejected_4423(t *testing.T) {
	for _, nh := range []string{
		"fe80::1%reth0",        // v6 link-local + zone-id (the finding's exact form)
		"fe80::1%eth0",         // kernel-name zone-id
		"fe80::1%reth0.50",     // sub-interface zone-id
		"192.168.1.1%ge-0-0-0", // v4 with a stray '%' — also not a real form
	} {
		if err := config.ValidateStaticNextHop(nh); err == nil {
			t.Fatalf("ValidateStaticNextHop(%q) accepted an RFC-4007 zone-id form; "+
				"xpf is Junos-syntax and expects `next-hop <ll> interface <if>`, "+
				"not the Linux %%iface convention", nh)
		}
	}
	// The correct Junos link-local spelling and the internal @iface encoding
	// stay accepted — the rejection above must not over-reach.
	if err := config.ValidateStaticNextHop("fe80::1@reth0.50"); err != nil {
		t.Fatalf("Junos-encoded link-local next-hop fe80::1@reth0.50 must be accepted: %v", err)
	}
}

func TestSchema2448_NextHop_AcceptsValidForms(t *testing.T) {
	for _, nh := range []string{
		"192.168.1.1", // bare IPv4
		"2001:db8::1", // bare IPv6
		"ge-0-0-0.0",  // bare interface name
		"eth1",        // bare kernel name
	} {
		cfg := `routing-options {
    static {
        route 10.0.0.0/24 {
            next-hop ` + nh + `;
        }
    }
}`
		if err := schemaCheck(t, cfg); err != nil {
			t.Fatalf("unexpected error for valid next-hop %q: %v", nh, err)
		}
	}
}

// A PLAIN next-hop with an explicit egress interface must commit. The
// compiler (compiler_routing.go) supports this for IPv6 link-local
// gateways in BOTH the hierarchical `next-hop fe80::50 { interface
// reth0.50; }` and the flat/inline `next-hop fe80::50 interface reth0.50`
// shapes. Modeling next-hop as a typed value-leaf REGRESSED this to
// `unknown modifier "reth0.50"` (the interface value token was rejected);
// the container model with a keyValidator restores it. Pinning both shapes
// (the AcceptsValid masked the gap by only covering qualified-next-hop).
func TestSchema2448_NextHop_AcceptsExplicitInterface(t *testing.T) {
	// hierarchical: interface is a block child of next-hop.
	if err := schemaCheck(t, `routing-options {
    static {
        route ::/0 {
            next-hop fe80::50 {
                interface reth0.50;
            }
        }
    }
}`); err != nil {
		t.Fatalf("hierarchical next-hop <ip> interface <iface> should commit: %v", err)
	}
	// flat/inline: interface follows the gateway on one set line.
	if err := flatSchemaCheck(t,
		"set routing-options static route ::/0 next-hop fe80::50 interface reth0.50",
	); err != nil {
		t.Fatalf("flat-inline next-hop <ip> interface <iface> should commit: %v", err)
	}
	// The gateway is still validated even when an interface is present: a
	// malformed gateway with an interface must be rejected (the keyValidator
	// runs on the gateway identity arg, not bypassed by the child).
	if err := flatSchemaCheck(t,
		"set routing-options static route ::/0 next-hop 2001:db8::garbage interface reth0.50",
	); err == nil {
		t.Fatal("malformed gateway with interface should still be rejected, got nil")
	}
}

// discard / next-table routes (no next-hop) and qualified-next-hop with a
// link-local IPv6 + interface must all still commit.
func TestSchema2448_Route_AcceptsDiscardAndQualified(t *testing.T) {
	for name, cfg := range map[string]string{
		"discard": `routing-options {
    static {
        route 192.168.99.0/24 {
            discard;
        }
    }
}`,
		"next-table": `routing-options {
    static {
        route 0.0.0.0/0 {
            next-table Comcast-GigabitPro.inet.0;
        }
    }
}`,
		"qualified-next-hop": `routing-options {
    static {
        route ::/0 {
            qualified-next-hop fe80::2d0:f6ff:feda:c180 {
                interface reth2.0;
            }
        }
    }
}`,
	} {
		if err := schemaCheck(t, cfg); err != nil {
			t.Fatalf("unexpected error for %s route: %v", name, err)
		}
	}
}

// --- flat-set parity ----------------------------------------------------

func TestSchema2448_FlatSet_RouteDestination_RejectsBad(t *testing.T) {
	err := flatSchemaCheck(t,
		"set routing-options static route 10.0.0.0/99 next-hop 192.168.1.1",
	)
	if err == nil {
		t.Fatal("expected error for flat-set malformed destination, got nil")
	}
}

func TestSchema2448_FlatSet_NextHop_RejectsBad(t *testing.T) {
	err := flatSchemaCheck(t,
		"set routing-options static route 10.0.0.0/24 next-hop 1.2.3.999",
	)
	if err == nil {
		t.Fatal("expected error for flat-set malformed next-hop, got nil")
	}
}

func TestSchema2448_FlatSet_Route_AcceptsValid(t *testing.T) {
	if err := flatSchemaCheck(t,
		"set routing-options static route 0.0.0.0/0 next-hop 192.168.1.1",
		"set routing-options static route 10.10.0.0/16 next-hop 10.0.0.2",
		"set routing-options static route 192.168.99.0/24 discard",
		"set routing-options static route 172.16.0.0/12 next-hop 10.0.0.3",
		"set routing-options static route 172.16.0.0/12 preference 100",
		"set routing-options static route ::/0 next-hop 2001:db8::1",
		"set routing-options static route ::/0 qualified-next-hop fe80::2d0:f6ff:feda:c180 interface reth2.0",
	); err != nil {
		t.Fatalf("unexpected error for valid flat-set static routes: %v", err)
	}
}

// Routing-instances and per-rib mirrors carry the same typed route node.
func TestSchema2448_RoutingInstances_RouteDestination_RejectsBad(t *testing.T) {
	err := flatSchemaCheck(t,
		"set routing-instances ATT routing-options static route 10.0.0.0/99 next-hop 192.168.1.1",
	)
	if err == nil {
		t.Fatal("expected error for flat-set routing-instances malformed destination, got nil")
	}
}

func TestSchema2448_Rib_NextHop_RejectsBad(t *testing.T) {
	err := flatSchemaCheck(t,
		"set routing-options rib inet6.0 static route ::/0 next-hop 2001:db8::garbage",
	)
	if err == nil {
		t.Fatal("expected error for flat-set per-rib malformed next-hop, got nil")
	}
}
