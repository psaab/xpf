package config

import (
	"strings"
	"testing"
)

// #6564 — the strict-reject members (2, 5, 6).
//
// These three differ from the compact-leaf shape family (#7365): there the
// operand was DROPPED and the fix makes the statement take effect. Here the
// statement is structurally readable but its VALUE is malformed or its trailing
// token is unreachable, and the compiler silently coerced or discarded it. The
// only honest repair is to refuse it, because there is no correct value to
// infer.
//
//	routing-options autonomous-system <bad>
//	    strconv.ParseUint's error was discarded with no else and no record, so
//	    AutonomousSystem stayed 0 and resolveBGPAutonomousSystem left LocalAS
//	    0 — pkg/frr gates `router bgp` on LocalAS > 0, so a typo in ONE leaf
//	    silently disabled BGP ENTIRELY.
//
//	security-zone <z> screen <p> <trailing>
//	    the zone compiler reads Keys[1] via nodeVal and never looks at the
//	    node's children, so a chained statement after the profile name is
//	    dropped.
//
//	protocols ospf area <bad>
//	    no key validator at all, so a malformed area id was rendered VERBATIM
//	    into frr.conf — the sibling `route` and `next-hop` keys both carry one.
//
// POSTURE (#1960 no-brick, and the #1319 PR 2 split that implements it):
// SchemaValidate is STRICT on the operator commit / commit-check path
// (Store.compileTree) and DOWNGRADED TO A WARNING on the tolerant
// Store.Load / Store.SyncApply path (Store.compileTreeLenient). A config an
// older binary accepted must still BOOT after an upgrade; only a new operator
// edit is refused. Both directions are asserted below — a fix that rejected on
// BOTH paths would pass a strict-only matrix and brick a box on upgrade.

// schemaErr6564 runs the typed-leaf gate the way the strict commit path does.
func schemaErr6564(t *testing.T, cmds ...string) error {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return SchemaValidate(tree)
}

// --- Member 2: a malformed autonomous-system silently disables BGP ----------

func TestStrictRejectAutonomousSystem6564(t *testing.T) {
	for _, bad := range []string{"notanumber", "4294967296", "-1", "65001x"} {
		t.Run(bad, func(t *testing.T) {
			err := schemaErr6564(t, "set routing-options autonomous-system "+bad)
			if err == nil {
				t.Fatalf("#6564: `autonomous-system %s` must be REJECTED at strict commit — "+
					"the compiler discards ParseUint's error, leaves AutonomousSystem 0, and "+
					"pkg/frr then renders NO `router bgp` block at all, so one bad token "+
					"silently disables BGP entirely", bad)
			}
			if !strings.Contains(err.Error(), "autonomous-system") {
				t.Fatalf("the rejection must name the leaf; got %v", err)
			}
		})
	}

	// A valid AS in both spellings must still pass.
	for _, ok := range []string{"1", "65001", "4294967295"} {
		if err := schemaErr6564(t, "set routing-options autonomous-system "+ok); err != nil {
			t.Fatalf("valid autonomous-system %s must be accepted; got %v", ok, err)
		}
	}
}

// --- Member 5: a chained zone `screen` statement is dropped -----------------

func TestStrictRejectZoneScreenTrailingToken6564(t *testing.T) {
	err := schemaErr6564(t, "set security zones security-zone untrust screen sc tcp-rst")
	if err == nil {
		t.Fatal("#6564: a trailing statement after `screen <profile>` must be REJECTED at " +
			"strict commit — the zone compiler reads Keys[1] and never the node's children, " +
			"so the chained statement is silently dropped and the operator believes they " +
			"configured something that does not exist")
	}
	if !strings.Contains(err.Error(), "screen") {
		t.Fatalf("the rejection must name the leaf; got %v", err)
	}

	// The bare, correct form must still pass.
	if err := schemaErr6564(t, "set security zones security-zone untrust screen sc"); err != nil {
		t.Fatalf("a plain `screen <profile>` must be accepted; got %v", err)
	}
}

// --- Member 6: a malformed OSPF area id renders verbatim into FRR -----------

func TestStrictRejectOSPFAreaID6564(t *testing.T) {
	// All four schema sites: ospf / ospf3, top-level and routing-instance.
	prefixes := []string{
		"set protocols ospf area ",
		"set protocols ospf3 area ",
		"set routing-instances RI protocols ospf area ",
		"set routing-instances RI protocols ospf3 area ",
	}
	for _, p := range prefixes {
		for _, bad := range []string{"not-an-area", "999.999.999.999", "4294967296", "0.0.0"} {
			t.Run(strings.TrimSpace(p)+"/"+bad, func(t *testing.T) {
				if err := schemaErr6564(t, p+bad); err == nil {
					t.Fatalf("#6564: `%s%s` must be REJECTED at strict commit — there is no "+
						"area-id key validator, so the malformed id is rendered VERBATIM into "+
						"frr.conf (its sibling `route`/`next-hop` keys both validate)", p, bad)
				}
			})
		}
		// Both legitimate Junos spellings must still pass.
		for _, ok := range []string{"0", "0.0.0.0", "1", "10.1.2.3", "4294967295"} {
			if err := schemaErr6564(t, p+ok); err != nil {
				t.Fatalf("valid area id %q under %q must be accepted; got %v", ok, p, err)
			}
		}
	}
}

// --- The no-brick direction (#1960): the tolerant path must NOT refuse ------

// TestStrictRejectFamilyIsWarnOnlyOnTolerantPath6564 is the OTHER direction of
// the posture, and it is the cell a strict-only matrix would miss.
//
// A config an older binary accepted is already persisted on disk and already
// arriving over HA config-sync. If these gates refused on the tolerant path
// too, the version bump would blackout-boot the node (Store.Load) or
// alarm-loop config sync (Store.SyncApply) — and it would do so during an
// upgrade, potentially on the standby of an HA pair mid-ISSU.
//
// The split lives in Store.compileTreeLenient, which logs and continues rather
// than returning the SchemaValidate error. This asserts the compiler itself
// still COMPILES each offending config, so the tolerant path has something to
// continue with; a fix that made the COMPILER refuse would brick the same boot
// the lenient wrapper is there to protect.
//
// FAIL-ON-REVERT: make any of the three fixes a hard compiler error rather than
// a schema-gate rejection.
func TestStrictRejectFamilyIsWarnOnlyOnTolerantPath6564(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmds []string
	}{
		{"autonomous-system", []string{"set routing-options autonomous-system notanumber"}},
		{"zone-screen-trailing", []string{
			// The screen profile must EXIST: an undefined reference is a
			// separate, pre-existing gate, and leaving it undefined would make
			// this cell pass for the wrong reason.
			"set security screen ids-option sc icmp ping-death",
			"set security zones security-zone untrust screen sc tcp-rst",
		}},
		{"ospf-area", []string{"set protocols ospf area not-an-area"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := &ConfigTree{}
			for _, cmd := range tc.cmds {
				path, err := ParseSetCommand(cmd)
				if err != nil {
					t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
				}
				if err := tree.SetPath(path); err != nil {
					t.Fatalf("SetPath(%q): %v", cmd, err)
				}
			}

			// Strict gate refuses...
			if err := SchemaValidate(tree); err == nil {
				t.Fatalf("setup: the strict typed-leaf gate must reject %s", tc.name)
			}

			// ...but the COMPILER must still produce a config, so
			// Store.compileTreeLenient can warn and continue rather than
			// refusing a config that boots today (#1960 no-brick).
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("#1960 no-brick: the tolerant load / peer-sync path must still COMPILE "+
					"%s (Store.compileTreeLenient warns on the schema violation and continues). "+
					"A hard compiler error here blackout-boots a node whose persisted config an "+
					"older binary accepted; got %v", tc.name, err)
			}
		})
	}
}
