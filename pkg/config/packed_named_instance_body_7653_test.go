package config

import "testing"

// packed_named_instance_body_7653_test.go — #7653.
//
// The #2419 class has a shape distinct from the packed LEAF closed by
// #6818/#6822: the packed body on a NAMED INSTANCE. `namedInstances`
// recognises the instance from Keys[0..1] and the compiler then reads
// `inst.node.Children` — which is EMPTY when the operator packed the body onto
// the instance line. The instance is created and everything inside it is
// dropped.
//
// That is worse than not recognising the instance at all, because the
// half-built object reaches the renderer and the runtime. All three shapes
// below COMMIT CLEANLY — strict CompileConfig accepts, and the schema walker
// ignores leftover keys on a named container by design — so nothing warns.
//
// WHY EACH CELL ASSERTS AN ABSOLUTE VALUE AND NOT ONLY PACKED==EXPANDED.
// Equivalence alone is satisfied when BOTH spellings are broken, which is
// exactly the state a regression here would produce: a future change that
// stops reading the body on both paths would leave every equivalence cell
// green. So each cell pins what the packed spelling must COMPILE TO, and uses
// the expanded spelling as a same-run reference rather than as the assertion.

func compilePacked7653(t *testing.T, src string) *Config {
	t.Helper()
	p := NewParser(src)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// A packed OSPF interface instance must not silently drop its authentication.
//
// The consequence is not a cosmetic config-render difference: pkg/frr emits
// interface activation UNCONDITIONALLY while `ip ospf authentication` is
// conditional on AuthType. A dropped AuthType therefore brings the adjacency up
// with NO authentication, from a config whose text says otherwise.
func TestPackedOSPFInterfaceKeepsItsAuthentication7653(t *testing.T) {
	const packed = `protocols { ospf { area 0.0.0.0 {
    interface ge-0/0/0.0 authentication simple-password "secret";
} } }`
	const expanded = `protocols { ospf { area 0.0.0.0 {
    interface ge-0/0/0.0 { authentication { simple-password "secret"; } }
} } }`

	got := compilePacked7653(t, packed)
	if len(got.Protocols.OSPF.Areas) == 0 || len(got.Protocols.OSPF.Areas[0].Interfaces) == 0 {
		t.Fatal("packed spelling produced no OSPF interface at all")
	}
	iface := got.Protocols.OSPF.Areas[0].Interfaces[0]
	if iface.AuthType != "simple" {
		t.Errorf("packed `interface ge-0/0/0.0 authentication simple-password ...` "+
			"compiled AuthType=%q, want \"simple\". An empty AuthType means pkg/frr "+
			"activates the interface with NO authentication while the configuration "+
			"text authorises one (#7653)", iface.AuthType)
	}
	if iface.AuthKey.Reveal() != "secret" {
		t.Errorf("packed spelling compiled AuthKey=%q, want \"secret\"; an AuthType "+
			"with an empty key renders an authentication line with no credential",
			iface.AuthKey.Reveal())
	}

	// Same-run reference: the expanded spelling is the meaning the packed one
	// is claiming to have. If this half ever diverges, the two spellings are
	// no longer the same configuration and the cell above is pinning a value
	// that is merely self-consistent.
	ref := compilePacked7653(t, expanded)
	rIface := ref.Protocols.OSPF.Areas[0].Interfaces[0]
	if iface.AuthType != rIface.AuthType || iface.AuthKey.Reveal() != rIface.AuthKey.Reveal() {
		t.Errorf("packed {%q,%q} != expanded {%q,%q}: the two spellings of one "+
			"configuration compile differently", iface.AuthType, iface.AuthKey.Reveal(),
			rIface.AuthType, rIface.AuthKey.Reveal())
	}
}

// The OSPFv3 loop is a SEPARATE call site with its own schema path, so fixing
// v2 and not v3 is a live possibility — and an OSPFv3 adjacency is no less
// worth authenticating.
func TestPackedOSPFv3InterfaceKeepsItsBody7653(t *testing.T) {
	got := compilePacked7653(t, `protocols { ospf3 { area 0.0.0.0 {
    interface ge-0/0/0.0 hello-interval 3;
} } }`)
	if len(got.Protocols.OSPFv3.Areas) == 0 || len(got.Protocols.OSPFv3.Areas[0].Interfaces) == 0 {
		t.Fatal("packed spelling produced no OSPFv3 interface at all")
	}
	if hi := got.Protocols.OSPFv3.Areas[0].Interfaces[0].HelloInterval; hi != 3 {
		t.Errorf("packed `interface ge-0/0/0.0 hello-interval 3` compiled "+
			"HelloInterval=%d, want 3 (#7653)", hi)
	}
}

// A packed SNMPv3 user instance must not be registered WITHOUT its credential.
//
// This is the sharpest of the three: the user is not skipped, it is installed
// with no derived key. Minimum-security enforcement keys on key presence, so a
// noAuthNoPriv request naming this user bypasses the authentication the
// operator authored — a downgrade, not an outage, and therefore silent.
func TestPackedSNMPv3UserKeepsItsCredential7653(t *testing.T) {
	got := compilePacked7653(t, `snmp { v3 { usm { local-engine {
    user ops authentication-sha256 authentication-password "s3cretpass";
} } } }`)
	u := got.System.SNMP.V3Users["ops"]
	if u == nil {
		t.Fatalf("packed spelling registered no user \"ops\" (users=%d)", len(got.System.SNMP.V3Users))
	}
	if u.AuthProtocol != "sha256" {
		t.Errorf("packed user compiled AuthProtocol=%q, want \"sha256\" (#7653)", u.AuthProtocol)
	}
	if u.AuthPassword.Reveal() == "" {
		t.Error("packed user compiled with an EMPTY AuthPassword. The user is still " +
			"registered, and minimum-security enforcement keys on key presence, so a " +
			"noAuthNoPriv request naming \"ops\" bypasses the authentication the " +
			"configuration authorises (#7653)")
	}
}

// `usm local-engine { ... }` packs an INTERMEDIATE CONTAINER, not a body —
// a different mechanism from the two cells above, and the loudest failure of
// the three: FindChild("local-engine") returns nil and EVERY v3 user
// disappears. Not a credential downgrade but an SNMPv3 management outage.
func TestPackedUSMLocalEngineKeepsItsUsers7653(t *testing.T) {
	got := compilePacked7653(t, `snmp { v3 { usm local-engine {
    user ops { authentication-sha256 { authentication-password "s3cretpass"; } }
} } }`)
	if n := len(got.System.SNMP.V3Users); n != 1 {
		t.Fatalf("packed `usm local-engine { ... }` compiled %d v3 users, want 1. "+
			"local-engine sits in usm's own Keys, so the FindChild lookup returns "+
			"nil and every SNMPv3 user disappears — an SNMPv3 management outage "+
			"from a configuration whose text is correct (#7653)", n)
	}
	if u := got.System.SNMP.V3Users["ops"]; u == nil || u.AuthProtocol != "sha256" {
		t.Errorf("packed local-engine user compiled %+v, want AuthProtocol=sha256", u)
	}
}

// CONTROL. The expanded spellings must be untouched by all of the above. A fix
// that expands a packed tail can attach the rebuilt children in the wrong place
// (#6818 had to learn to nest rather than sibling), which shows up here as the
// EXPANDED spelling regressing while every packed cell passes.
func TestExpandedSpellingsAreUnchanged7653(t *testing.T) {
	ospf := compilePacked7653(t, `protocols { ospf { area 0.0.0.0 {
    interface ge-0/0/0.0 { authentication { simple-password "secret"; } hello-interval 7; }
} } }`)
	i := ospf.Protocols.OSPF.Areas[0].Interfaces[0]
	if i.AuthType != "simple" || i.AuthKey.Reveal() != "secret" || i.HelloInterval != 7 {
		t.Errorf("expanded OSPF interface regressed: AuthType=%q AuthKey=%q Hello=%d",
			i.AuthType, i.AuthKey.Reveal(), i.HelloInterval)
	}

	snmp := compilePacked7653(t, `snmp { v3 { usm { local-engine {
    user ops { authentication-sha256 { authentication-password "s3cretpass"; } }
} } } }`)
	if u := snmp.System.SNMP.V3Users["ops"]; u == nil || u.AuthProtocol != "sha256" || u.AuthPassword.Reveal() == "" {
		t.Errorf("expanded SNMPv3 user regressed: %+v", u)
	}
}
