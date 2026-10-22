package config

import (
	"strings"
	"testing"
)

func ospfIfTypeHier8481(t *testing.T, val string) *ConfigTree {
	t.Helper()
	src := `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { interface-type ` +
		val + `; } } } }`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v", perrs)
	}
	return tree
}

// TestOSPFInterfaceTypeIsTyped8481 is the #8481 gate.
//
// The consequence is NOT the one the issue reported. `interface-type` is stored
// verbatim and written verbatim into the FRR managed section as
// `ip ospf network <token>`; one line vtysh rejects fails the whole reload and
// takes down all dynamic routing. So this leaf was a way to break FRR from a
// clean commit, not an inert one.
func TestOSPFInterfaceTypeIsTyped8481(t *testing.T) {
	rows := []struct {
		val     string
		wantErr bool
	}{
		// The four FRR spellings.
		{"broadcast", false},
		{"non-broadcast", false},
		{"point-to-multipoint", false},
		{"point-to-point", false},
		// The three Junos spellings, accepted and translated.
		{"p2p", false},
		{"nbma", false},
		{"p2mp", false},
		// The issue's own example, and the shapes that reach vtysh as garbage.
		{"p2P", true},
		{"pointtopoint", true},
		{"bogus", true},
	}
	for _, row := range rows {
		t.Run(row.val, func(t *testing.T) {
			err := SchemaValidate(ospfIfTypeHier8481(t, row.val))
			if row.wantErr && err == nil {
				t.Fatalf("%q must be rejected — it reaches frr.conf verbatim as "+
					"`ip ospf network %s` and fails the managed-section reload",
					row.val, row.val)
			}
			if !row.wantErr && err != nil {
				t.Fatalf("%q must commit: %v", row.val, err)
			}
		})
	}
}

// TestOSPFInterfaceTypeIsCanonicalizedForFRR8481 pins the half a validator
// cannot: that what COMMITS also RENDERS a token vtysh knows. Validating the
// authored value and then passing it through unchanged would accept `p2p` and
// still emit `ip ospf network p2p`.
func TestOSPFInterfaceTypeIsCanonicalizedForFRR8481(t *testing.T) {
	rows := []struct{ authored, want string }{
		{"point-to-point", "point-to-point"},
		{"p2p", "point-to-point"},
		{"nbma", "non-broadcast"},
		{"p2mp", "point-to-multipoint"},
		{"broadcast", "broadcast"},
	}
	for _, row := range rows {
		t.Run(row.authored, func(t *testing.T) {
			cfg, err := CompileConfig(ospfIfTypeHier8481(t, row.authored))
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			got := cfg.Protocols.OSPF.Areas[0].Interfaces[0].NetworkType
			if got != row.want {
				t.Fatalf("authored %q -> NetworkType %q, want %q (this string is "+
					"written verbatim into `ip ospf network`)",
					row.authored, got, row.want)
			}
			if _, ok := CanonicalOSPFNetworkType(got); !ok {
				t.Fatalf("NetworkType %q is not itself a value FRR accepts — "+
					"canonicalization is not idempotent", got)
			}
		})
	}
}

// TestOSPFInterfaceTypeUnresolvableIsDroppedNotPassedThrough8481 is the
// no-brick half, and it is the reason the compiler canonicalizes instead of
// trusting the validator to have run.
//
// compileTreeLenient (Store.Load / SyncApply) downgrades every SchemaValidate
// violation to a warning and continues, so a config an older binary persisted
// with `interface-type p2P` reaches the compiler UNVALIDATED. Passing that
// through would emit `ip ospf network p2P` and fail the managed-section reload
// on a boot the operator did not initiate — the gate would have converted a
// commit-time defect into a boot-time outage.
func TestOSPFInterfaceTypeUnresolvableIsDroppedNotPassedThrough8481(t *testing.T) {
	tree := ospfIfTypeHier8481(t, "p2P")

	if err := SchemaValidate(tree); err == nil {
		t.Fatal("control failed: the strict path must reject this, or the " +
			"lenient assertion below proves nothing")
	}

	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("the tolerant path must not fail: %v", err)
	}
	got := cfg.Protocols.OSPF.Areas[0].Interfaces[0].NetworkType
	if got != "" {
		t.Fatalf("an unresolvable interface-type must be DROPPED on the "+
			"tolerant path, not passed to FRR; got %q, which renders "+
			"`ip ospf network %s` and fails the reload", got, got)
	}
}

// TestOSPFInterfaceTypeErrorNamesBothSpellings8481 pins the message content,
// because an operator who typed the Junos spelling and is told only "expected
// one of: broadcast, non-broadcast, ..." learns the wrong thing — that the
// product does not accept the syntax it claims to.
func TestOSPFInterfaceTypeErrorNamesBothSpellings8481(t *testing.T) {
	err := ValidateOSPFInterfaceType("p2P")
	if err == nil {
		t.Fatal("must reject")
	}
	for _, want := range []string{"point-to-point", "p2p", "nbma", "p2mp"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the rejection must name %q so the operator can act on it: %v",
				want, err)
		}
	}
}
