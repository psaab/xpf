package config

import (
	"strings"
	"testing"
)

// #8800: `security nat source pool <p> address <a>;` — the brace-ELIDED
// ("packed") spelling of a source NAT pool address — compiled to a pool with
// ZERO addresses, while the braced spelling `pool <p> { address <a>; }`
// compiled correctly.
//
// The cause was not the fold and not an arity: `address` was never declared as
// a schema child of `pool` at all. The compiler has read it since #4521
// (multi-value: Keys[1:] plus block children), but with no declaration the
// brace-elision pass was never even ASKED about the ("pool","address") pair —
// isBody is false for a head that is not a schema child — so no scope entry
// could ever have named this site. That is why it appears in no census: the
// inventory is built by running the pass, and the pass never saw it.
//
// The remedy is therefore two parts, and BOTH are required: declare `address`
// in setSchema (schema_security.go) so the pass asks, and admit the
// ("pool","address") pair in compactNormalizeInScope so the pass says yes.
// Declaring alone was measured to leave the packed spelling still compiling to
// zero addresses.
//
// Severity, established by measurement rather than inferred from the family:
// the strict commit path REJECTS the zero-address pool (the EmptyPool error
// below), so this never silently committed, and the dataplane marks such a
// pool unusable and drops — it fails CLOSED, not open. The flat `set` spelling
// was never affected. It was a config-FILE-only defect.
func TestSourceNATPoolPackedAddress8800(t *testing.T) {
	const zones = "security { zones { security-zone z1 { host-inbound-traffic { system-services ping; } } " +
		"security-zone z2 { host-inbound-traffic { system-services ping; } } } "
	mk := func(pool string) string {
		return zones + "nat { source { " + pool +
			" rule-set rs1 { from zone z1; to zone z2; rule r1 { match { source-address 10.0.0.0/8; } " +
			"then { source-nat { pool p1; } } } } } } }"
	}

	// compile returns the pool's addresses under the LENIENT path (what
	// Store.Load uses) plus whether the STRICT path (what commit uses)
	// rejects. normalize==false pre-normalises with the ("pool","address")
	// pair masked out and sets skipCompactNormalize, which reproduces
	// pre-#8800 behaviour exactly. Compiling a pre-normalised tree WITHOUT
	// that opt would not be a baseline: the pass runs inside
	// compileConfigWithOpts and would simply re-fold with the real scope.
	compile := func(t *testing.T, txt string, masked bool) (addrs []string, strictRejects bool) {
		t.Helper()
		norm := func() *ConfigTree {
			tr, perrs := NewParser(txt).Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse %q: %v", txt, perrs)
			}
			if masked {
				normalizeCompactStanzasWithScope(tr, func(kw, head string) bool {
					if kw == "pool" && head == "address" {
						return false
					}
					return compactNormalizeInScope(kw, head)
				})
			} else {
				normalizeCompactStanzas(tr)
			}
			return tr
		}
		lo := lenientCompileOpts()
		lo.skipCompactNormalize = true
		cfg, err := compileConfigWithOpts(norm(), lo)
		if err != nil {
			t.Fatalf("lenient compile of %q: %v", txt, err)
		}
		for _, p := range cfg.Security.NAT.SourcePools {
			if p.Name == "p1" {
				addrs = p.Addresses
			}
		}
		_, serr := compileConfigWithOpts(norm(), compileOpts{skipCompactNormalize: true})
		return addrs, serr != nil
	}

	// ---- the two-spelling differential ----------------------------------
	// Every shape a source pool address can take. packed and braced must
	// agree; this is the acceptance criterion, not a count of sites.
	for _, tc := range []struct{ name, packed, braced string }{
		{"single", "pool p1 address 10.0.0.1/32;", "pool p1 { address 10.0.0.1/32; }"},
		{"range", "pool p1 address 10.0.0.1/32 to 10.0.0.9/32;", "pool p1 { address 10.0.0.1/32 to 10.0.0.9/32; }"},
		{"bracket-list", "pool p1 address [ 10.0.0.1/32 10.0.0.2/32 ];", "pool p1 { address [ 10.0.0.1/32 10.0.0.2/32 ]; }"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pa, pr := compile(t, mk(tc.packed), false)
			ba, br := compile(t, mk(tc.braced), false)
			if strings.Join(pa, ",") != strings.Join(ba, ",") || pr != br {
				t.Errorf("packed and braced DIFFER for a source NAT pool address (#8800)\n"+
					"  packed %q -> addrs=%v strictRejects=%v\n"+
					"  braced %q -> addrs=%v strictRejects=%v\n"+
					"MEASURED, NOT DIAGNOSED: this cell knows only that the two "+
					"spellings disagree. The #8800 cause was a MISSING SCHEMA "+
					"DECLARATION (`address` was not a child of `pool`, so the "+
					"brace-elision pass was never asked about the pair) — check "+
					"that before assuming the fold or an arity, and note that a "+
					"scope entry alone cannot fix an undeclared head.",
					tc.packed, pa, pr, tc.braced, ba, br)
			}
			if len(pa) == 0 {
				t.Errorf("packed %q compiled to a ZERO-address pool — the #8800 defect itself", tc.packed)
			}
		})
	}

	// ---- the defect, pinned against its own baseline ---------------------
	t.Run("baseline-was-broken", func(t *testing.T) {
		txt := mk("pool p1 address 10.0.0.1/32;")
		base, baseRejects := compile(t, txt, true)
		if len(base) != 0 || !baseRejects {
			t.Fatalf("the pre-#8800 baseline no longer reproduces the defect "+
				"(addrs=%v strictRejects=%v). This cell's masked gate is meant to "+
				"reproduce it exactly; if the defect is now unreachable by that "+
				"route, this guard is measuring nothing and must be re-derived.",
				base, baseRejects)
		}
		fixed, fixedRejects := compile(t, txt, false)
		if len(fixed) == 0 || fixedRejects {
			t.Fatalf("fixed path regressed: addrs=%v strictRejects=%v", fixed, fixedRejects)
		}
	})

	// ---- what the fix does NOT cover -------------------------------------
	// A MULTI-STATEMENT packed pool (`address <a> port no-translation;`) is
	// not valid Junos as a single statement and no tool emits it. The fold
	// yields one leaf, so the trailing tokens land on the address list. The
	// binding property is that this is NOT a new acceptance: the strict path
	// rejects it both before and after #8800, so it cannot reach a committed
	// config either way. Opting `pool` into the #8768 packedStatements split
	// was measured to be a no-op here — splitPackedStatements8768 resolves
	// each head against the CONTAINER only, and `no-translation` is a child
	// of `port`, not of `pool`, so the split bails out ("do not guess").
	t.Run("multi-statement-packed-rejects-both-ways", func(t *testing.T) {
		txt := mk("pool p1 address 10.0.0.1/32 port no-translation;")
		_, baseRejects := compile(t, txt, true)
		_, fixedRejects := compile(t, txt, false)
		if !baseRejects || !fixedRejects {
			t.Errorf("multi-statement packed pool changed acceptance: "+
				"strictRejects base=%v fixed=%v — #8800 must not make the strict "+
				"path ACCEPT a spelling it rejected, nor reject one it accepted",
				baseRejects, fixedRejects)
		}
	})

	// ---- the second symptom of the missing declaration --------------------
	// An undeclared child is invisible to completion too, so `address` was
	// never offered to an operator typing the pool path.
	t.Run("completion-offers-address", func(t *testing.T) {
		comps := CompleteSetPath(strings.Fields("security nat source pool p1"))
		if !contains8800(comps, "address") {
			t.Errorf("completion after `set security nat source pool <p>` does not "+
				"offer `address`: %v", comps)
		}
	})
}

// The SAME defect at the sibling path. compileNATDestination reads `address`
// under a destination NAT pool (parseDNATPoolAddress, which deliberately walks
// every token so `address <ip> port <n>` captures both), and that pool declared
// `children: nil`, so the packed spelling compiled to an EMPTY address exactly
// as the source pool did.
//
// This is here because fixing only the source pool would have been the partial
// fix that reads as complete: the scope entry ("pool","address") is pair-keyed
// and so ALREADY covered this path, which meant the missing half was invisible
// from the source side. Found by asking what other container the same compiler
// arm shape appears in, not by a test failing.
func TestDestinationNATPoolPackedAddress8800(t *testing.T) {
	const zones = "security { zones { security-zone z1 { host-inbound-traffic { system-services ping; } } " +
		"security-zone z2 { host-inbound-traffic { system-services ping; } } } "
	mk := func(pool string) string {
		return zones + "nat { destination { " + pool +
			" rule-set rs1 { from zone z1; rule r1 { match { destination-address 10.0.0.0/8; } " +
			"then { destination-nat { pool p1; } } } } } } }"
	}
	get := func(t *testing.T, txt string) (addr string, port int, strictRejects bool) {
		t.Helper()
		tr, perrs := NewParser(txt).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		cfg, err := compileConfigWithOpts(tr, lenientCompileOpts())
		if err != nil {
			t.Fatalf("lenient compile: %v", err)
		}
		if cfg.Security.NAT.Destination != nil {
			for _, p := range cfg.Security.NAT.Destination.Pools {
				if p.Name == "p1" {
					addr, port = p.Address, p.Port
				}
			}
		}
		tr2, _ := NewParser(txt).Parse()
		_, serr := compileConfigWithOpts(tr2, compileOpts{})
		return addr, port, serr != nil
	}
	for _, tc := range []struct{ name, packed, braced string }{
		{"address", "pool p1 address 10.0.0.5/32;", "pool p1 { address 10.0.0.5/32; }"},
		{"address-port", "pool p1 address 10.0.0.5/32 port 8080;", "pool p1 { address 10.0.0.5/32 port 8080; }"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pa, pp, pr := get(t, mk(tc.packed))
			ba, bp, br := get(t, mk(tc.braced))
			if pa != ba || pp != bp || pr != br {
				t.Errorf("packed and braced DIFFER for a destination NAT pool address (#8800)\n"+
					"  packed %q -> addr=%q port=%d strictRejects=%v\n"+
					"  braced %q -> addr=%q port=%d strictRejects=%v\n"+
					"MEASURED, NOT DIAGNOSED. The #8800 cause at this path was a "+
					"MISSING SCHEMA DECLARATION (`address` was not a child of the "+
					"destination `pool`), not the fold and not the scope entry -- "+
					"the pair (\"pool\",\"address\") is shared with the source pool "+
					"and was already admitted, so a scope check will look correct "+
					"while this path is broken.",
					tc.packed, pa, pp, pr, tc.braced, ba, bp, br)
			}
			if pa == "" {
				t.Errorf("packed %q compiled to an EMPTY destination pool address", tc.packed)
			}
		})
	}
}

func contains8800(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
