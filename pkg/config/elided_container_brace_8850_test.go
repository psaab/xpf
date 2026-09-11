package config

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// #8850: an elided CONTAINER brace dropped the entire stanza -- zones, screens
// and filters compiled to EMPTY with no error on either path.
//
//	security { zones { security-zone z1 { ... } } }   zones=1
//	security { zones security-zone z1 { ... } }       zones=0
//
// normalizeCompactNodes gated on `len(node.Children) == 0`, and the elided form
// is precisely a node with a packed tail AND a braced body: eliding the
// container brace leaves the inner stanza's own braces intact. Such nodes were
// declined SILENTLY -- the pass asked nothing (`asked=[]`), so no scope entry
// could have reached them either.
//
// ASSERT CONTENTS, NEVER COUNTS. The naive fix -- dropping the guard and
// leaving the braced body as a SIBLING of the packed statement -- makes every
// count go green while the body is lost:
//
//	BRACED  zone="z1" hostInboundTraffic=[ping]
//	ELIDED  zone="z1" hostInboundTraffic=<nil>
//
// That converts a MISSING zone into an EMPTY zone, which is strictly worse: an
// absent zone is detectable as absent, a zone named z1 with no body reads as
// configured. This cell exists because a count-based version of it passed.
func TestElidedContainerBraceKeepsBody8850(t *testing.T) {
	zoneOf := func(t *testing.T, txt string) (name string, services []string, n int) {
		t.Helper()
		tree, errs := NewParser(txt).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		n = len(cfg.Security.Zones)
		for k, z := range cfg.Security.Zones {
			name = k
			if z.HostInboundTraffic != nil {
				services = z.HostInboundTraffic.SystemServices
			}
		}
		return
	}

	bn, bs, bc := zoneOf(t, "security { zones { security-zone z1 { host-inbound-traffic { system-services ping; } } } }")
	en, es, ec := zoneOf(t, "security { zones security-zone z1 { host-inbound-traffic { system-services ping; } } }")

	if bc != 1 || ec != 1 || bn != en {
		t.Errorf("zone COUNT differs braced=%d elided=%d (names %q vs %q)", bc, ec, bn, en)
	}
	if len(es) == 0 {
		t.Errorf("the elided zone compiled with an EMPTY body (services=%v, braced had %v).\n"+
			"That is the sibling-attachment failure, not a fix: the zone exists and "+
			"reads as configured while its host-inbound-traffic is gone. The braced "+
			"body must be re-parented UNDER the deepest packed statement, which is "+
			"the rule packedBodyChildren applies for readers (#6821).", es, bs)
	}
	if fmt.Sprint(bs) != fmt.Sprint(es) {
		t.Errorf("zone body differs: braced=%v elided=%v", bs, es)
	}

	// The same shape for screen profiles.
	// CONTENTS, NOT COUNTS -- this half was `len(cfg.Security.Screen)` on both
	// arms, so with compileScreen never called at all both are 0 and it passes,
	// against this file's own stated rule. It now renders the profile name AND
	// the enabled check, so a screen that materialises EMPTY reds.
	screens := func(t *testing.T, txt string) string {
		t.Helper()
		tree, _ := NewParser(txt).Parse()
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		var out []string
		for name, sc := range cfg.Security.Screen {
			out = append(out, fmt.Sprintf("%s:pingDeath=%v", name, sc != nil && sc.ICMP.PingDeath))
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	braced := screens(t, "security { screen { ids-option s1 { icmp { ping-death; } } } }")
	// LIVENESS: an equality assertion between two empty strings is satisfied
	// perfectly, and that is exactly what a never-called compileScreen produces.
	if braced == "" {
		t.Fatalf("the BRACED screen reference compiled NOTHING, so comparing the " +
			"elided spelling against it proves nothing (#8850)")
	}
	if e := screens(t, "security { screen ids-option s1 { icmp { ping-death; } } }"); braced != e {
		t.Errorf("screen profile differs braced=%q elided=%q (#8850); a profile "+
			"that exists with its checks OFF reads as configured and is worse "+
			"than one that is absent", braced, e)
	}
}

// NEGATIVE CONTROL. Nodes carrying a packed MULTI-VALUE PAYLOAD alongside
// braced children are the shape the old `Children == 0` guard excluded
// wholesale, and where a wrong relaxation would re-parent a value list under a
// node that should not exist.
//
// The discriminator that makes the relaxation safe is NOT the removed guard --
// it is the check immediately below it: a tail reads as an elided BODY only if
// its first token NAMES A CHILD of this container, otherwise it is the node's
// own payload and is left alone.
//
// These fingerprints were byte-compared against master before the change and
// were identical; this cell pins that they stay so.
func TestElidedBraceLeavesPayloadsAlone8850(t *testing.T) {
	fp := func(t *testing.T, txt string, skipPass bool) string {
		t.Helper()
		tree, errs := NewParser(txt).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs)
		}
		opts := lenientCompileOpts()
		opts.skipCompactNormalize = skipPass
		cfg, err := compileConfigWithOpts(tree, opts)
		if err != nil {
			t.Fatalf("compile (skipPass=%v): %v", skipPass, err)
		}
		j, _ := json.Marshal(cfg)
		return fmt.Sprintf("%x", sha256.Sum256(j))[:16]
	}
	for _, c := range []struct{ name, txt string }{
		{"bracket-list-in-term", "firewall { family inet { filter f1 { term t1 { from { protocol [ tcp udp icmp ]; } then { accept; } } } } }"},
		{"policy-application-list", "security { policies { from-zone a to-zone b { policy p1 { match { source-address any; destination-address any; application [ junos-http junos-https ]; } then { permit; } } } } }"},
		{"ospf-auth-md5-with-body", "protocols { ospf { area 0.0.0.0 { interface ge-0/0/0 { authentication md5 7 { key \"x\"; } } } } }"},
		{"static-route-with-body", "routing-options { static { route 10.0.0.0/24 { next-hop 10.0.0.1; preference 5; } } }"},
		{"vrrp-virtual-address", "interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24 { vrrp-group 1 { virtual-address 10.0.0.9; priority 120; } } } } } }"},
	} {
		t.Run(c.name, func(t *testing.T) {
			// COMPARE THE PASS AGAINST ITSELF DISABLED, not an input against
			// itself.
			//
			// This previously read `a, b := fp(t, c.txt), fp(t, c.txt)` -- the
			// SAME string hashed twice -- and carried a `want` field that every
			// row set to "" and nothing ever read. An unread field is the tell:
			// an assertion intended and never wired. It could not fail:
			// reintroducing the #2419 multi-value drop moved every fixture's
			// hash identically and all five subtests still passed.
			//
			// A pinned hash would be the obvious repair and is the wrong one --
			// it changes whenever any unrelated Config field is added, so it
			// would be deleted the first time it reds for an innocent reason.
			//
			// The property actually worth asserting is that the brace-elision
			// pass LEAVES THESE NODES ALONE. Each fixture is a node carrying a
			// multi-value payload or a braced body that the pass must not fold,
			// so compiling with the pass and with it disabled must agree. That
			// is stable under unrelated schema growth, and it fails for exactly
			// the reason this cell exists: the relaxation starting to touch a
			// payload node.
			withPass := fp(t, c.txt, false)
			without := fp(t, c.txt, true)
			if withPass != without {
				t.Errorf("the brace-elision pass CHANGED a node it must leave "+
					"alone (#8850)\n  %s\n  with pass %s\n  pass disabled %s\n"+
					"These fixtures are multi-value payloads and braced bodies, "+
					"not elided containers. The pass folding one of them is the "+
					"#2419 class returning through the relaxation.",
					c.txt, withPass, without)
			}
		})
	}

	// LIVENESS FOR THE COMPARISON ITSELF, and it is not optional here.
	//
	// Measured: forcing the pass's gate FULLY OPEN -- `isBody || inScope(...) ||
	// true` -- leaves all five fixtures above byte-identical. The pass does not
	// reach them under any mutation of its gate, so their agreement is not
	// evidence that the pass declined; it is evidence that the pass was never
	// asked. Five green subtests that cannot move are exactly the shape this
	// cell was rewritten to stop being.
	//
	// So the fixtures above are BREADTH, not sensitivity, and this control is
	// what makes the comparison mean anything: a node the pass certainly DOES
	// fold, asserted to DIFFER between pass-on and pass-off. If this ever stops
	// differing, `fp` is comparing something that no longer depends on the pass
	// and every row above went vacuous with it.
	t.Run("control-the-pass-is-live", func(t *testing.T) {
		const elided = "security { zones security-zone z1 { host-inbound-traffic " +
			"{ system-services { ping; } } } }"
		withPass, without := fp(t, elided, false), fp(t, elided, true)
		if withPass == without {
			t.Errorf("pass-on and pass-off agree on a node the pass MUST fold "+
				"(#8850)\n  %s\n  both %s\n"+
				"`fp` is no longer sensitive to the brace-elision pass, so every "+
				"agreement asserted above is vacuous.", elided, withPass)
		}
	})
}

// #8850. The relaxation DECLINES one shape: a packed tail that splits into
// several statements while the node also carries a braced body. Nothing in the
// tree says which statement the body belongs to, and guessing "the last one"
// is measurably worse than declining -- on
// `address-book address-set s1 { address a1; } address a2 ...;` it produced
// set:s1 with NO members, where master produces set:s1(a1).
//
// Declining must be a NO-OP, not an early exit. The decline sits inside the
// per-node loop whose LAST statement recurses into the node's children:
//
//	n += normalizeCompactNodes(node.Children, childSub, inScope)
//
// so leaving the branch with `continue` skips it, and every elided container
// inside the declined node's BODY stays unfolded. That is a change master does
// not make, and it is invisible to every other cell in this package: the full
// suite was GREEN with the `continue` in place.
//
// The fixture has to sit on a site that REALLY declines. The first one written
// here did not -- an ipsec `gateway gw1 address ... { dead-peer-detection ... }`
// never enters the branch at all, because ("gateway","address") is not in
// scope, so the cell passed against the mutant and measured nothing. This one
// is built on a CONFIRMED decline site: `address-book` is opted in to the
// #8768 split, its two `address` statements make len(stmts)==2, and the braced
// body makes len(body)>0 -- both decline conditions. The body then holds
// `address-set s1 address a1;`, itself an elided container that only keeps its
// member if the recursion still runs:
//
//	fall through   set:s1(a1)
//	continue       set:s1()     <- member silently gone
//
// The declined node losing a1/a2 as ADDRESSES is not what this cell measures
// and is not a regression: master loses them identically, because a
// multi-statement run followed by a brace is not a spelling Junos produces.
// What must hold is that declining changed nothing ELSE.
func TestDeclinedFoldStillRecursesIntoBody8850(t *testing.T) {
	const cfgText = "security { zones { security-zone trust { address-book " +
		"address a1 10.0.0.1/32 address a2 10.0.0.2/32 " +
		"{ address-set s1 address a1; } } } }"

	tree, errs := NewParser(cfgText).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var book *AddressBook
	for _, z := range cfg.Security.Zones {
		book = z.AddressBook
	}
	if book == nil {
		t.Fatalf("no address book compiled, so this cell cannot see the body at "+
			"all and the fixture no longer builds the declined shape: %s", cfgText)
	}
	set, ok := book.AddressSets["s1"]
	if !ok {
		t.Fatalf("address-set s1 absent; the fixture must reach the BODY of the "+
			"declined node for this cell to mean anything: %s", cfgText)
	}
	// LIVENESS: `address-set s1 address a1;` is an ELIDED container inside the
	// declined node's body. Skip the recursion and the set still exists -- it is
	// just EMPTY, which is the silent direction.
	if len(set.Addresses) != 1 || set.Addresses[0] != "a1" {
		t.Errorf("address-set inside a DECLINED node's braced body lost its "+
			"members: got %v, want [a1] (#8850)\n"+
			"The decline branch must restore the node and fall THROUGH to "+
			"normalizeCompactNodes(node.Children, ...). Leaving with `continue` "+
			"keeps the set and drops its contents, and no other cell in this "+
			"package sees it.", set.Addresses)
	}
}
