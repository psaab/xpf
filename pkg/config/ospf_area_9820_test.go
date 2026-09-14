package config

import (
	"strings"
	"testing"
)

// #9820 (Path A): the schema gate refuses IPv4-mapped and padded OSPF area
// IDs at strict commit. Mirrors the #6564 area cells (schemaErr6564 path).

func schemaErr9820(t *testing.T, cmds ...string) error {
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
	return SchemaValidate(tree, nil)
}

func TestOSPFAreaMappedRefused_9820(t *testing.T) {
	prefixes := []string{
		"set protocols ospf area ",
		"set protocols ospf3 area ",
		"set routing-instances RI protocols ospf area ",
		"set routing-instances RI protocols ospf3 area ",
	}
	for _, p := range prefixes {
		for _, bad := range []string{"::ffff:192.0.2.1", "::ffff:c000:201"} {
			t.Run(strings.TrimSpace(p)+"/"+bad, func(t *testing.T) {
				err := schemaErr9820(t, p+bad)
				if err == nil {
					t.Fatalf("`%s%s` must be REJECTED — an IPv4-mapped literal is outside FRR's area grammar", p, bad)
				}
				if !strings.Contains(err.Error(), "IPv4-mapped") {
					t.Fatalf("error should name the mapped reason, got: %v", err)
				}
			})
		}
		for _, ok := range []string{"0", "0.0.0.0", "0.0.0.1", "10.1.2.3", "4294967295"} {
			if err := schemaErr9820(t, p+ok); err != nil {
				t.Fatalf("valid area id %q under %q must be accepted; got %v", ok, p, err)
			}
		}
	}
}

// The transit-area leaf shares the validator and inherits both arms.
func TestOSPFTransitAreaMappedRefused_9820(t *testing.T) {
	err := schemaErr9820(t,
		"set protocols ospf area 0.0.0.1 virtual-link 10.0.0.2 transit-area ::ffff:192.0.2.1")
	if err == nil || !strings.Contains(err.Error(), "IPv4-mapped") {
		t.Fatalf("mapped transit-area must be refused with the mapped reason, got: %v", err)
	}
	if err := schemaErr9820(t,
		"set protocols ospf area 0.0.0.1 virtual-link 10.0.0.2 transit-area 0.0.0.3"); err != nil {
		t.Fatalf("valid transit-area must be accepted, got: %v", err)
	}
}

// Flat `set` field-splits padding away, so padded IDs reach the schema
// gate only as hierarchical quoted values. The validator refuses them.
func TestOSPFAreaPaddedRefused_9820(t *testing.T) {
	tree, perrs := NewParser(`
protocols {
    ospf {
        area " 0.0.0.0 " {
            interface ge-0/0/0.0;
        }
    }
}`).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse errors: %v", perrs)
	}
	err := SchemaValidate(tree, nil)
	if err == nil || !strings.Contains(err.Error(), "whitespace is not allowed") {
		t.Fatalf("padded area id must be refused with the padding reason, got: %v", err)
	}
}

// Direct validator cells for spellings no `set` line can carry
// (newlines) plus the boundary set.
func TestValidateOSPFAreaBoundary_9820(t *testing.T) {
	for _, bad := range []string{
		"\n0.0.0.0", "0.0.0.0\n", " 0.0.0.0 ", "\t0.0.0.0\t",
		"0 1", "not-an-area", "2001:db8::1",
	} {
		if err := ValidateOSPFArea(bad, nil); err == nil {
			t.Errorf("ValidateOSPFArea(%q) accepted, want rejection", bad)
		}
	}
	for _, ok := range []string{"0", "0.0.0.0", "10.1.2.3", "4294967295"} {
		if err := ValidateOSPFArea(ok, nil); err != nil {
			t.Errorf("ValidateOSPFArea(%q) = %v, want nil", ok, err)
		}
	}
}
