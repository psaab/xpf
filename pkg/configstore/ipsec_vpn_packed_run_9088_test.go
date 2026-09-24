package configstore

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// ipsecPreamble9088 is a COMPLETE IPsec configuration, so that nothing below can
// be rejected for an undefined reference and mistaken for the gate under test.
const ipsecPreamble9088 = `security {
    ike {
        proposal PR { authentication-method pre-shared-keys; }
        policy IKEP { proposals PR; }
        gateway G {
            ike-policy IKEP;
            address 203.0.113.9;
            external-interface ge-0/0/0.0;
        }
    }
    ipsec {
        proposal IPR { protocol esp; encryption-algorithm aes-256-cbc; authentication-algorithm hmac-sha-256-128; }
        policy P { proposals IPR; }
`

// #9088: a packed one-liner under `security ipsec vpn <name>` COMMITS CLEAN and
// silently drops the crypto policy and the XFRM binding.
//
// This drives configstore.CheckText — the strict pipeline behind every `commit`
// and `commit check` — deliberately, and NOT config.CompileConfig. The whole
// point of #9088 is that this site is reachable from an operator's keyboard,
// and a cell on CompileConfig measures the tolerant Load/SyncApply channel
// while reporting on the operator one. That substitution is the instrument
// defect the issue calls out; repeating it here would leave the claim untested
// on the channel that matters.
func TestPackedIPsecVPNRunKeepsEveryLeaf9088(t *testing.T) {
	vpn := func(body string) string {
		return ipsecPreamble9088 + "        vpn v1 {\n" + body + "\n        }\n    }\n}\n"
	}
	check := func(t *testing.T, text string) *config.IPsecVPN {
		t.Helper()
		cfg, err := CheckText(text, 0)
		if err != nil {
			t.Fatalf("strict commit-check REJECTED the config: %v", err)
		}
		v := cfg.Security.IPsec.VPNs["v1"]
		if v == nil {
			t.Fatal("no vpn v1 in the compiled config")
		}
		return v
	}

	// REFERENCE ARM: the three-statement spelling, which is what the packed one
	// is compared against. If this ever stops setting all three, the equality
	// below is between two equally-broken configs.
	want := check(t, vpn("            gateway G;\n"+
		"            ipsec-policy P;\n"+
		"            bind-interface st0.1;"))
	if want.Gateway == "" || want.IPsecPolicy == "" || want.BindInterface == "" {
		t.Fatalf("the CONTROL spelling did not set all three: %+v", want)
	}

	got := check(t, vpn("            gateway G ipsec-policy P bind-interface st0.1;"))

	if got.IPsecPolicy != want.IPsecPolicy {
		t.Errorf("packed ipsec-policy = %q, want %q. A dropped ipsec-policy makes "+
			"phase 2 negotiate the strongSwan DEFAULT proposal set instead of the "+
			"configured crypto — the failure the phase-1 ike-policy gate exists to "+
			"prevent, on a path that gate does not watch",
			got.IPsecPolicy, want.IPsecPolicy)
	}
	if got.BindInterface != want.BindInterface {
		t.Errorf("packed bind-interface = %q, want %q. A dropped bind-interface "+
			"leaves xfrmiIfID() at 0, so a route-based VPN commits with NO XFRM "+
			"interface — the silent-tunnel-down condition #5297 exists to prevent",
			got.BindInterface, want.BindInterface)
	}
	if got.Gateway != want.Gateway {
		t.Errorf("packed gateway = %q, want %q", got.Gateway, want.Gateway)
	}
}

// NARROWNESS: each leaf alone must set only itself. A run-splitter that is too
// eager invents values, which on this container means binding a VPN to an XFRM
// interface nobody asked for.
//
// #10638: strict commit now rejects a VPN with no bind-interface at all, so
// the single-leaf rows carry bind-interface as required context (the leaf
// under test must still set nothing BEYOND itself and the context). The
// instrument stays on the strict operator channel; the bind-interface row
// itself is unchanged — it compiles alone.
func TestPackedIPsecVPNRunIsNarrow9088(t *testing.T) {
	one := func(t *testing.T, line string) *config.IPsecVPN {
		t.Helper()
		cfg, err := CheckText(ipsecPreamble9088+"        vpn v1 {\n            "+
			line+"\n        }\n    }\n}\n", 0)
		if err != nil {
			t.Fatalf("strict commit-check rejected %q: %v", line, err)
		}
		return cfg.Security.IPsec.VPNs["v1"]
	}
	if v := one(t, "gateway G bind-interface st0;"); v.IPsecPolicy != "" || v.BindInterface != "st0" {
		t.Errorf("`gateway G` set ipsec-policy=%q bind-interface=%q, want only gateway + the bind context",
			v.IPsecPolicy, v.BindInterface)
	}
	if v := one(t, "ipsec-policy P bind-interface st0;"); v.Gateway != "" || v.BindInterface != "st0" {
		t.Errorf("`ipsec-policy P` set gateway=%q bind-interface=%q, want only ipsec-policy + the bind context",
			v.Gateway, v.BindInterface)
	}
	if v := one(t, "bind-interface st0.1;"); v.Gateway != "" || v.IPsecPolicy != "" {
		t.Errorf("`bind-interface st0.1` alone set gateway=%q ipsec-policy=%q",
			v.Gateway, v.IPsecPolicy)
	}
}

// THE GATE BYPASS, and this is the sharpest statement of what #9088 cost.
//
// `bind-interface ge-0/0/0` is REJECTED by the #5297 gate on the strict path: a
// route-based VPN must bind an st0 unit. Before this fix the packed spelling
// DROPPED bind-interface entirely, so #5297 never saw a value to reject and the
// config committed clean -- with no XFRM interface at all, which is the very
// condition #5297 was written to prevent.
//
// So the loss did not merely discard a value; it removed a security gate's
// subject. A cell that only compares two compiled configs cannot see that,
// because both spellings are "accepted" either way. This one asserts the gate
// FIRES on the packed spelling.
func TestPackedIPsecVPNRunIsSubjectToTheBindInterfaceGate9088(t *testing.T) {
	body := func(line string) string {
		return ipsecPreamble9088 + "        vpn v1 {\n            " + line +
			"\n        }\n    }\n}\n"
	}

	// REFERENCE ARM: the gate really does reject this on the SPLIT spelling.
	// If it ever stops, the assertion below passes for the wrong reason.
	if _, err := CheckText(body("gateway G;\n            ipsec-policy P;\n"+
		"            bind-interface ge-0/0/0;"), 0); err == nil {
		t.Fatal("the #5297 bind-interface gate did not reject ge-0/0/0 on the SPLIT " +
			"spelling; this cell is measuring nothing")
	}

	// The packed spelling must reach the same gate.
	if _, err := CheckText(body("gateway G ipsec-policy P bind-interface ge-0/0/0;"), 0); err == nil {
		t.Error("the packed spelling COMMITTED with bind-interface ge-0/0/0. The " +
			"value is being dropped before the #5297 gate can see it, so the gate " +
			"is bypassed by a spelling rather than satisfied by the config — and " +
			"the VPN commits with no XFRM interface")
	}

	// NARROWNESS: a VALID packed bind-interface must still commit. A fix that
	// simply rejected every packed run would satisfy the row above.
	if _, err := CheckText(body("gateway G ipsec-policy P bind-interface st0.1;"), 0); err != nil {
		t.Errorf("a valid packed spelling must still commit: %v", err)
	}
}
