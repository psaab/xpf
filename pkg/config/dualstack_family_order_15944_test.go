package config

import "testing"

// #15944 H4-01: per-family primary/preferred compilation must be
// order-independent. Before the fix, authoring `family inet6` before
// `family inet` mirrored the IPv6 primary/preferred into the shared
// legacy slots while empty, and the later IPv4 values were dropped by
// the first-wins guard — PreferredAddressForFamily(false) returned the
// IPv6 CIDR for an IPv4 query, leaking a v6 address into IPv4 consumers
// (syslog source / IPsec candidate selection).
//
// FAIL-ON-REVERT: restoring the inet6 mirror-while-empty (or the
// inet primary's unconditional overwrite) makes the inet6-first cells
// below return the v6 CIDR from the IPv4 accessors.

func dualStackUnit15944(t *testing.T, inet6First bool) *InterfaceUnit {
	t.Helper()
	inet := "      family inet {\n" +
		"        address 10.0.0.1/24;\n" +
		"        address 10.0.0.2/24 { primary; }\n" +
		"        address 10.0.0.3/24 { preferred; }\n" +
		"      }\n"
	inet6 := "      family inet6 {\n" +
		"        address 2001:db8::1/64;\n" +
		"        address 2001:db8::2/64 { primary; }\n" +
		"        address 2001:db8::3/64 { preferred; }\n" +
		"      }\n"
	fams := inet + inet6
	if inet6First {
		fams = inet6 + inet
	}
	cfg := compileHierStrict(t, "interfaces {\n"+
		"  ge-0/0/0 {\n"+
		"    unit 0 {\n"+fams+
		"    }\n"+
		"  }\n"+
		"}\n"+
		"security { zones { security-zone trust { interfaces { ge-0/0/0.0; } } } }\n")
	unit := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
	if unit == nil {
		t.Fatal("unit 0 missing")
	}
	return unit
}

func TestDualStackFamilyOrderIndependent15944(t *testing.T) {
	for _, inet6First := range []bool{false, true} {
		unit := dualStackUnit15944(t, inet6First)
		if got := unit.PrimaryAddressForFamily(false); got != "10.0.0.2/24" {
			t.Errorf("inet6First=%v: PrimaryAddressForFamily(false) = %q, want 10.0.0.2/24", inet6First, got)
		}
		if got := unit.PreferredAddressForFamily(false); got != "10.0.0.3/24" {
			t.Errorf("inet6First=%v: PreferredAddressForFamily(false) = %q, want 10.0.0.3/24", inet6First, got)
		}
		if got := unit.PrimaryAddressForFamily(true); got != "2001:db8::2/64" {
			t.Errorf("inet6First=%v: PrimaryAddressForFamily(true) = %q, want 2001:db8::2/64", inet6First, got)
		}
		if got := unit.PreferredAddressForFamily(true); got != "2001:db8::3/64" {
			t.Errorf("inet6First=%v: PreferredAddressForFamily(true) = %q, want 2001:db8::3/64", inet6First, got)
		}
		// The legacy slots hold IPv4 values only, in both orders.
		if unit.PrimaryAddress != "10.0.0.2/24" || unit.PreferredAddress != "10.0.0.3/24" {
			t.Errorf("inet6First=%v: legacy slots = %q/%q, want 10.0.0.2/24 / 10.0.0.3/24",
				inet6First, unit.PrimaryAddress, unit.PreferredAddress)
		}
		if unit.PrimaryAddressV6 != "2001:db8::2/64" || unit.PreferredAddressV6 != "2001:db8::3/64" {
			t.Errorf("inet6First=%v: v6 slots = %q/%q, want 2001:db8::2/64 / 2001:db8::3/64",
				inet6First, unit.PrimaryAddressV6, unit.PreferredAddressV6)
		}
	}
}

// The family guard on the accessors themselves: a hand-built unit whose
// legacy slot holds a v6 CIDR (pre-#15653 shape) must not leak it to an
// IPv4 query, and must still serve it to an IPv6 query.
func TestPrimaryAddressForFamilyRejectsWrongFamily15944(t *testing.T) {
	u := &InterfaceUnit{
		PrimaryAddress:   "2001:db8::2/64",
		PreferredAddress: "2001:db8::3/64",
	}
	if got := u.PrimaryAddressForFamily(false); got != "" {
		t.Errorf("PrimaryAddressForFamily(false) = %q, want \"\" (v6 CIDR must not leak)", got)
	}
	if got := u.PreferredAddressForFamily(false); got != "" {
		t.Errorf("PreferredAddressForFamily(false) = %q, want \"\" (v6 CIDR must not leak)", got)
	}
	if got := u.PrimaryAddressForFamily(true); got != "2001:db8::2/64" {
		t.Errorf("PrimaryAddressForFamily(true) = %q, want 2001:db8::2/64 (legacy fallback)", got)
	}
	if got := u.PreferredAddressForFamily(true); got != "2001:db8::3/64" {
		t.Errorf("PreferredAddressForFamily(true) = %q, want 2001:db8::3/64 (legacy fallback)", got)
	}
}
