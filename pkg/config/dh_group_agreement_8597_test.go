package config

import "testing"

// #8597 (muse-004 K88) — ValidateDHGroup accepted any positive integer while
// pkg/ipsec's renderer could spell only an explicit table.
//
// Measured before the fix: `dh-group 99` committed clean and rendered
// `modp99`; 17 rendered `modp17`, 33 `modp33`, 0 `modp0`. charon rejects all of
// them, so IPsec never establishes and the diagnostics point at charon rather
// than at the one-line value the operator typed.
//
// The defect is not "the validator is loose". It is that the VALIDATOR and the
// RENDERER had different ideas of the accepted set, so the fix is one map both
// consult — `config.DHGroupKeyword` — rather than a second list in the gate.
//
// 17 and 18 deserve naming: they are REAL IKE groups (RFC 3526 modp6144 and
// modp8192) that this table does not carry, so their old render was not merely
// unspelled but WRONG. They are omitted rather than guessed at — adding a
// keyword is a claim about what strongSwan accepts. Rejecting them at commit,
// with the accepted set named, is strictly better than silently mis-rendering.

func TestValidateDHGroupAcceptsExactlyWhatCanBeSpelled_8597(t *testing.T) {
	// Every accepted group must have a keyword, and every group with a keyword
	// must be accepted. Stated as a round-trip so neither side can grow
	// without the other.
	for _, g := range SupportedDHGroups() {
		kw, ok := DHGroupKeyword(g)
		if !ok || kw == "" {
			t.Errorf("group %d is in SupportedDHGroups but has no keyword", g)
		}
		if err := ValidateDHGroup(itoaDH(g)); err != nil {
			t.Errorf("group %d has keyword %q but the validator rejects it: %v", g, kw, err)
		}
	}
}

func TestValidateDHGroupRejectsUnspellableGroups_8597(t *testing.T) {
	for _, tc := range []struct {
		group int
		why   string
	}{
		{99, "the finding's value: rendered modp99"},
		{33, "just past the elliptic-curve range: rendered modp33"},
		{17, "a REAL group (RFC 3526 modp6144) this table does not carry — it rendered modp17, which is wrong rather than merely unspelled"},
		{18, "same, modp8192"},
		{3, "unassigned"},
		{1000000, "far out of range"},
	} {
		if err := ValidateDHGroup(itoaDH(tc.group)); err == nil {
			t.Errorf("group %d accepted (%s); it renders a proposal keyword strongSwan "+
				"does not take, so IPsec never establishes and the operator debugs "+
				"charon instead of their config", tc.group, tc.why)
		}
	}
}

// TestDHGroupSpellingsAreNotBitCounts_8597 pins the #2392/#2604 property the
// old fall-through kept breaking: an elliptic-curve group is a CURVE, and a bit
// count is not its name.
func TestDHGroupSpellingsAreNotBitCounts_8597(t *testing.T) {
	for group, want := range map[int]string{
		19: "ecp256", 20: "ecp384", 21: "ecp521",
		31: "curve25519", 32: "curve448",
		1: "modp768", 2: "modp1024", 14: "modp2048", 16: "modp4096",
		22: "modp1024s160", 24: "modp2048s256",
	} {
		got, ok := DHGroupKeyword(group)
		if !ok {
			t.Errorf("group %d has no keyword", group)
			continue
		}
		if got != want {
			t.Errorf("group %d spells %q, want %q", group, got, want)
		}
	}
}

// TestDHGroupValidatorStillAcceptsTheGroupPrefix_8597 is the OVER-BROAD
// control on the parsing half: tightening the accepted SET must not break the
// `group14` spelling, or every config using it fails to commit.
func TestDHGroupValidatorStillAcceptsTheGroupPrefix_8597(t *testing.T) {
	for _, raw := range []string{"14", "group14", " group19 ", "2", "group32"} {
		if err := ValidateDHGroup(raw); err != nil {
			t.Errorf("ValidateDHGroup(%q) = %v; both the bare-integer and group<N> "+
				"spellings must keep working", raw, err)
		}
	}
	// And the pre-existing rejections stay rejections, each for its own reason.
	for _, raw := range []string{"", "abc", "0", "-5", "group0"} {
		if err := ValidateDHGroup(raw); err == nil {
			t.Errorf("ValidateDHGroup(%q) accepted; the pre-#8597 rejections must "+
				"survive the tightening", raw)
		}
	}
}

func itoaDH(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}
