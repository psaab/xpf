package config

import (
	"strings"
	"testing"
)

// #8597 (muse-004 K15) — a leaf that DECLARES a value, authored with none,
// walked out of the schema gate entirely.
//
// `walkSchemaNode` computes `missingArgs := declaredKeyTokens - consumed` and,
// when that is positive, delegates to `walkInstanceChildren` — the dual-AST
// path, where a hierarchical spelling supplies the missing name/arg levels as
// nested children. With ZERO children it iterates nothing and returns nil, so
// the missing value was never noticed.
//
// The finding names the static-route next-hop `interface` modifier, and that is
// the instance with the sharpest consequence: an IPv6 link-local gateway is
// meaningless without its egress interface, and
//
//	next-hop fe80::1 interface        (no interface name)
//
// committed clean and compiled to `Interface: ""` — an UNSCOPED link-local
// next-hop, on the one route an operator can least afford to mis-scope.
//
// The population is larger than the finding's, and the cells below record it:
// `family inet address` and `policy ... match source-address` are still
// untyped valueless leaves, so the generic walker gate owns them. `system
// host-name` is now a typed scalar leaf (#10003); its typed-leaf branch owns
// the same missing-value refusal with the shorter typed diagnostic.

func schemaVerdict(t *testing.T, cmd string) error {
	t.Helper()
	tree := &ConfigTree{}
	path, err := ParseSetCommand(cmd)
	if err != nil {
		t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath(%q): %v", cmd, err)
	}
	return SchemaValidate(tree, nil)
}

// TestValuelessLeafIsRejected_8597 is the RED-on-revert core. Each of these
// declares a value and gives none.
func TestValuelessLeafIsRejected_8597(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmd  string
		why  string
		want string
	}{
		{
			name: "static-route next-hop interface modifier",
			cmd:  "set routing-options rib inet6.0 static route 2001:db8::/64 next-hop fe80::1 interface",
			why:  "an unscoped IPv6 link-local next-hop — the finding's instance",
			want: "declares a value and none was given",
		},
		{
			name: "system host-name",
			cmd:  "set system host-name",
			why:  "typed scalar leaf — covered by the #10003 admission validator",
			want: "missing value",
		},
		{
			name: "interface address",
			cmd:  "set interfaces ge-0/0/0 unit 0 family inet address",
			why:  "same",
			want: "declares a value and none was given",
		},
		{
			name: "policy match source-address",
			cmd:  "set security policies from-zone trust to-zone untrust policy p match source-address",
			why:  "same",
			want: "declares a value and none was given",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := schemaVerdict(t, tc.cmd)
			if err == nil {
				t.Fatalf("the gate ACCEPTED a valueless leaf (%s): the compiler drops it, so "+
					"this commits clean and the configuration silently does not carry the "+
					"statement (#8597/K15)", tc.why)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("rejected with %q, not the expected missing-value diagnostic: %v", tc.want, err)
			}
		})
	}
}

// TestValuedLeavesStillCommit_8597 is the OVER-BROAD control, and the one that
// decides whether this gate can ship. K16 in this same tracker is a case where
// a gate of exactly this family rejected the project's own shipped config; a
// missing-value gate that condemned any legitimate spelling would be the same
// mistake.
//
// The full pkg/config and pkg/configstore suites are the wider control, but a
// gate needs its own statement of what it must NOT reject, next to what it
// must.
func TestValuedLeavesStillCommit_8597(t *testing.T) {
	for _, cmd := range []string{
		// The finding's leaf, correctly authored.
		"set routing-options rib inet6.0 static route 2001:db8::/64 next-hop fe80::1 interface ge-0/0/0.0",
		"set system host-name fw1",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		// A multi-value leaf: its extra Keys are VALUES, not a missing arg.
		"set routing-options static route 10.0.0.0/8 next-hop 192.168.1.1",
		// A zero-arg FLAG leaf legitimately carries no value and must be
		// untouched — the gate keys on a DECLARED arg, not on arity alone.
		"set interfaces ge-0/0/0 unit 0 family inet dhcp",
		// A CONTAINER whose missing name level arrives as nested children is
		// the case the delegating branch exists for; it must still work.
		"set class-of-service schedulers be transmit-rate 1g",
	} {
		if err := schemaVerdict(t, cmd); err != nil {
			t.Errorf("the gate rejected a valid statement %q: %v", cmd, err)
		}
	}
}

// TestValuelessLeafGateIsScopedToLEAVES_8597 pins the discriminator.
//
// The `missingArgs > 0` branch below the gate is the dual-AST path: a CONTAINER
// legitimately takes its missing name level from nested AST children, which is
// how the hierarchical spelling works. Rejecting on missingArgs alone would
// break every hierarchical container in the tree, so the gate additionally
// requires the schema node to be a leaf (no schema children) AND the AST node
// to have no children.
func TestValuelessLeafGateIsScopedToLEAVES_8597(t *testing.T) {
	// Hierarchical spelling: the instance name arrives as an AST child.
	p := NewParser("class-of-service { schedulers { be { transmit-rate 1g; } } }")
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("the gate rejected a hierarchical container whose missing name level "+
			"arrives as an AST child — that is the shape the branch it guards exists "+
			"for: %v", err)
	}
}

// TestValuelessLeafRejectionIsStrictOnly_8597 pins the #1960 half.
//
// SchemaValidate IS the strict gate; Store.compileTreeLenient downgrades
// everything it returns to a warning on the tolerant Load / peer-sync ingress.
// So a persisted config carrying a valueless leaf still BOOTS — this cell
// asserts the compile itself does not fail, which is what "no-brick" means
// here, and it is the reason the gate can be a hard reject at commit.
func TestValuelessLeafRejectionIsStrictOnly_8597(t *testing.T) {
	tree := &ConfigTree{}
	path, err := ParseSetCommand("set routing-options rib inet6.0 static route 2001:db8::/64 next-hop fe80::1 interface")
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	if _, err := CompileConfigLenient(tree); err != nil {
		t.Fatalf("the tolerant compile must not fail on a valueless leaf (#1960 no-brick): %v", err)
	}
}

// TestValuelessNextHopInterfaceWasReallyUnscoped_8597 is the non-vacuity
// control for the whole file: it proves the rejected input is the one that
// produced the harmful compile, rather than merely being malformed.
//
// The gate is at SchemaValidate, so the compiler still accepts the shape. This
// drives the compile directly and asserts what it produced BEFORE the gate
// existed — an empty Interface on a link-local next-hop. If a future change
// makes the compiler reject or default it, this cell fails and says the gate's
// justification needs re-deriving rather than leaving a guard whose reason has
// quietly evaporated.
func TestValuelessNextHopInterfaceWasReallyUnscoped_8597(t *testing.T) {
	tree := &ConfigTree{}
	path, err := ParseSetCommand("set routing-options rib inet6.0 static route 2001:db8::/64 next-hop fe80::1 interface")
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	var found bool
	for _, sr := range cfg.RoutingOptions.Inet6StaticRoutes {
		for _, nh := range sr.NextHops {
			if nh.Address != "fe80::1" {
				continue
			}
			found = true
			if nh.Interface != "" {
				t.Errorf("the compiler now yields Interface=%q for a valueless `interface` "+
					"modifier; the gate's justification (an UNSCOPED link-local next-hop) "+
					"no longer holds and should be re-derived", nh.Interface)
			}
		}
	}
	if !found {
		t.Fatal("the fixture produced no fe80::1 next-hop at all; the cells above are " +
			"rejecting something other than the shape this gate is about")
	}
}
