package config

import (
	"net"
	"testing"
)

// TestPackedCommunityStillEnforcesClients8778 pins the SECURITY OUTCOME of a
// one-line `snmp community` statement, not the agreement of two spellings.
//
// #8778 was a fail-OPEN. `set snmp community public authorization read-only
// clients 10.0.0.0/8` compiled to an EMPTY allowlist, and AllowsSource
// documents `len(Clients) == 0` as allow-all (the Junos default) — so the
// dropped restriction did not shrink the allowlist, it INVERTED it. The
// community answered from every source while the config said otherwise and the
// commit reported success. Writing the same statements on two `set` lines
// enforced correctly: the difference was a line break.
//
// TWO SHAPES, ONE DEFECT. Flat `set` builds a CHAIN — `clients` nests under
// `authorization` — while the brace-elided hierarchical spelling packs every
// token onto one node's Keys. The compiler handled neither, for different
// reasons, so both are asserted here.
//
// WHY THIS ASSERTS THE OUTCOME AND NOT AN EQUALITY. The obvious guard is
// "packed compiles to what braced compiles to". That guard passes when BOTH
// are allow-all, which is exactly the regression it would exist to catch — an
// agreement check goes green on the failure. So each spelling is asserted to
// DENY an outside address, which is false of an empty allowlist however the
// other spelling behaves. (Design constraint: team-lead.)
func TestPackedCommunityStillEnforcesClients8778(t *testing.T) {
	inside := net.ParseIP("10.1.2.3").To4()
	outside := net.ParseIP("192.0.2.7").To4()

	check := func(t *testing.T, label string, cm *SNMPCommunity) {
		t.Helper()
		if cm == nil {
			t.Fatalf("%s: no `public` community compiled at all", label)
		}
		if len(cm.Clients) == 0 {
			t.Errorf("%s: clients allowlist is EMPTY. AllowsSource reads that as "+
				"ALLOW-ALL, so the operator's `clients 10.0.0.0/8` restriction is not "+
				"merely lost — it is inverted, and the commit reports success (#8778)",
				label)
			return
		}
		if !cm.AllowsSource(inside) {
			t.Errorf("%s: an address INSIDE the allowlist is denied — the allowlist "+
				"compiled but does not match what the operator wrote", label)
		}
		if cm.AllowsSource(outside) {
			t.Errorf("%s: an address OUTSIDE the allowlist is ALLOWED. This is the "+
				"#8778 fail-open: the community answers from every source (#8778)", label)
		}
	}

	t.Run("flat-set one line", func(t *testing.T) {
		tree := &ConfigTree{}
		// CLAUDE.md: flat set MUST be built with ParseSetCommand + SetPath.
		for _, line := range []string{
			"set snmp community public authorization read-only clients 10.0.0.0/8",
		} {
			p, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		cfg, err := compileConfigWithOpts(tree, compileOpts{})
		if err != nil {
			t.Fatalf("strict compile: %v", err)
		}
		check(t, "flat-set one line", cfg.System.SNMP.Communities["public"])
	})

	t.Run("hierarchical packed", func(t *testing.T) {
		tr, perrs := NewParser(
			`snmp { community public authorization read-only clients 10.0.0.0/8; }`).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		cfg, err := compileConfigWithOpts(tr, compileOpts{})
		if err != nil {
			t.Fatalf("strict compile: %v", err)
		}
		check(t, "hierarchical packed", cfg.System.SNMP.Communities["public"])
	})

	// POSITIVE CONTROL on the guard itself: the spelling that always worked
	// must still work. If this ever fails the fix has broken the ordinary path,
	// and the two assertions above would still pass.
	t.Run("control separate set lines", func(t *testing.T) {
		tree := &ConfigTree{}
		for _, line := range []string{
			"set snmp community public authorization read-only",
			"set snmp community public clients 10.0.0.0/8",
		} {
			p, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", line, err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatalf("SetPath(%q): %v", line, err)
			}
		}
		cfg, err := compileConfigWithOpts(tree, compileOpts{})
		if err != nil {
			t.Fatalf("strict compile: %v", err)
		}
		check(t, "control separate set lines", cfg.System.SNMP.Communities["public"])
	})

	// The `restrict` modifier must survive the packed spelling too: a packed
	// `clients <p> restrict` that lost its modifier would be a DIFFERENT
	// fail-open — a deny-except entry silently becoming a plain allow.
	t.Run("restrict modifier survives packing", func(t *testing.T) {
		tr, perrs := NewParser(
			`snmp { community public authorization read-only clients 10.0.0.0/8 restrict; }`).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		cfg, err := compileConfigWithOpts(tr, compileOpts{})
		if err != nil {
			t.Fatalf("strict compile: %v", err)
		}
		cm := cfg.System.SNMP.Communities["public"]
		if cm == nil || len(cm.Clients) == 0 {
			t.Fatalf("no clients compiled from the packed restrict spelling")
		}
		if !cm.Clients[0].Restrict {
			t.Errorf("`restrict` was dropped by the packed spelling: the entry became a "+
				"plain ALLOW for %s instead of a deny (#8778)", cm.Clients[0].Prefix)
		}
	})
	// SECOND INGESTION SURFACE. docs/config-schema.md records that snmp is
	// compiled from TWO places — the top-level `snmp {}` stanza via
	// compiler_dispatch.go, and `system { snmp {} }` via compiler_system.go —
	// and that a defect has already been reachable from one and not the other
	// (#4289), on the spelling test/incus/xpf-test.conf actually uses. Both call
	// the same compileSNMP today, so this asserts that rather than assuming it.
	t.Run("under system { snmp { } }", func(t *testing.T) {
		tr, perrs := NewParser(
			`system { snmp { community public authorization read-only clients 10.0.0.0/8; } }`).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		cfg, err := compileConfigWithOpts(tr, compileOpts{})
		if err != nil {
			t.Fatalf("strict compile: %v", err)
		}
		if cfg.System.SNMP == nil {
			t.Fatalf("no SNMP compiled from the system{} surface at all")
		}
		check(t, "system{snmp{}} packed", cfg.System.SNMP.Communities["public"])
	})
}
