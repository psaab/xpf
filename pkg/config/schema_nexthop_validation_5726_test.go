package config

import (
	"strings"
	"testing"
)

// #5726: two commit-time next-hop gateway validation gaps.
//
//   - F-01: the `qualified-next-hop <gateway>` node carried NO keyValidator
//     (unlike the sibling `next-hop`), so a typo'd floating-backup gateway
//     committed clean and FRR rendered it verbatim -> the backup silently
//     never installed.
//   - F-02: an ECMP `next-hop [ gw1 gw2 ]` collapses onto ONE leaf
//     (Keys=["next-hop", gw1, gw2], #2419), but the shared schema_walk
//     container keyValidator loop validated only the first token
//     (argEnd = 1+args), so every 2nd+ gateway bypassed validation while the
//     compiler installed it as an equal-cost next-hop.
//
// Both are fail-open: the malformed gateway commits, FRR emits it verbatim,
// and the route/backup/ECMP member silently never installs. ValidateStaticNextHop
// already rejects the bad token (`1.2.3.999`) — the fix simply invokes it on
// these two paths.
//
// FAIL-ON-REVERT:
//   - Drop the keyValidator from the qualified-next-hop node -> F-01 reject
//     cases stop erroring (RED).
//   - Restore the schema_walk container loop to the argEnd=1+args span (drop
//     the `multi` branch) -> F-02 second-gateway reject stops erroring (RED),
//     while the interface-modifier accept case is unaffected either way.

// schemaValidate5726 builds a flat-set tree (ParseSetCommand + SetPath — never
// NewParser, per CLAUDE.md; the bracket list needs the flat-set collapse) and
// runs the commit-check schema gate.
func schemaValidate5726(t *testing.T, sets ...string) error {
	t.Helper()
	return SchemaValidate(flatTreeFromSets(t, sets...))
}

// --- F-01: qualified-next-hop gateway is validated at commit ---------------

func TestSchema5726_QualifiedNextHop_RejectsBadGateway(t *testing.T) {
	err := schemaValidate5726(t,
		"set routing-options static route 10.0.0.0/8 next-hop 192.168.1.1",
		"set routing-options static route 10.0.0.0/8 qualified-next-hop 1.2.3.999 preference 100",
	)
	if err == nil {
		t.Fatal("expected SchemaValidate to reject qualified-next-hop 1.2.3.999, got nil (the #5726 F-01 silent-accept)")
	}
	if !strings.Contains(err.Error(), "1.2.3.999") {
		t.Fatalf("error should name the bad qualified-next-hop gateway: %v", err)
	}
}

func TestSchema5726_QualifiedNextHop_AcceptsValid(t *testing.T) {
	// A valid IPv4/IPv6 gateway and a bare interface-name backup must all pass;
	// the inline preference/interface modifiers must not be mis-validated as a
	// gateway.
	cases := [][]string{
		{"set routing-options static route 10.0.0.0/8 qualified-next-hop 192.168.1.2 preference 100"},
		{"set routing-options static route ::/0 qualified-next-hop 2001:db8::1 preference 50"},
		{"set routing-options static route 10.0.0.0/8 qualified-next-hop 192.168.1.2 interface ge-0/0/0.0"},
	}
	for _, sets := range cases {
		if err := schemaValidate5726(t, sets...); err != nil {
			t.Fatalf("valid qualified-next-hop must pass commit-check, got %v (sets=%v)", err, sets)
		}
	}
}

// --- F-02: every gateway in an ECMP next-hop list is validated -------------

func TestSchema5726_ECMPNextHopList_RejectsBadSecondGateway(t *testing.T) {
	// First gateway valid, SECOND a typo. Pre-#5726 only the first was checked,
	// so this committed clean and FRR then dropped the bad ECMP member.
	err := schemaValidate5726(t,
		"set routing-options static route 0.0.0.0/0 next-hop [ 192.168.1.1 1.2.3.999 ]",
	)
	if err == nil {
		t.Fatal("expected SchemaValidate to reject the 2nd ECMP gateway 1.2.3.999, got nil (the #5726 F-02 silent-accept)")
	}
	if !strings.Contains(err.Error(), "1.2.3.999") {
		t.Fatalf("error should name the bad ECMP gateway: %v", err)
	}
}

func TestSchema5726_ECMPNextHopList_RejectsBadThirdGateway(t *testing.T) {
	// Guard the tail beyond position 2 as well.
	err := schemaValidate5726(t,
		"set routing-options static route 0.0.0.0/0 next-hop [ 192.168.1.1 192.168.1.2 999.999.999.999 ]",
	)
	if err == nil {
		t.Fatal("expected SchemaValidate to reject the 3rd ECMP gateway, got nil")
	}
}

func TestSchema5726_ECMPNextHopList_AcceptsAllValid(t *testing.T) {
	if err := schemaValidate5726(t,
		"set routing-options static route 0.0.0.0/0 next-hop [ 192.168.1.1 192.168.1.2 192.168.1.3 ]",
	); err != nil {
		t.Fatalf("a fully-valid ECMP next-hop list must pass commit-check, got %v", err)
	}
}

// TestSchema5726_NextHop_InterfaceModifierNotValidatedAsGateway is the critical
// guard that the widened validation still EXCLUDES the `interface <name>`
// egress modifier: an ifname like ge-0/0/0 is NOT a valid gateway literal
// (ValidateStaticNextHop rejects the slash form), so validating it as a gateway
// would falsely reject a legitimate `next-hop <gw> interface <if>` config.
func TestSchema5726_NextHop_InterfaceModifierNotValidatedAsGateway(t *testing.T) {
	cases := []string{
		// Single gateway + inline interface modifier.
		"set routing-options static route 0.0.0.0/0 next-hop 10.0.0.1 interface ge-0/0/0.0",
		// Bracket form carrying the interface modifier after the gateway.
		"set routing-options static route 0.0.0.0/0 next-hop [ 10.0.0.1 interface ge-0/0/0.0 ]",
		// IPv6 link-local gateway REQUIRES an egress interface — must pass.
		"set routing-options static route ::/0 next-hop fe80::1 interface reth0.50",
	}
	for _, s := range cases {
		if err := schemaValidate5726(t, s); err != nil {
			t.Fatalf("next-hop with an interface modifier must pass (ifname is not a gateway): %v (set=%q)", err, s)
		}
	}
}
