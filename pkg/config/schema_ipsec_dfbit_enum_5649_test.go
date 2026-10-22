package config

import (
	"strings"
	"testing"
)

// #5649 (codex-181 C181-M22) — `set security ipsec vpn <v> df-bit <mode>` was
// an untyped free-form leaf (args:1, no validator), so a typo committed CLEAN
// and was then silently dropped by the strongSwan generator: pkg/ipsec/policy.go
// only emits `copy_df` for copy/set/clear and OMITS the directive for anything
// else, leaving strongSwan's copy-DF default. An operator intending `df-bit
// clear` who typed `cler` would therefore keep the outer DF copied (the
// opposite of clear) and blackhole oversized encapsulated packets via PMTUD —
// while commit reported success. The leaf is now typed with ValidateEnum over
// exactly {copy, set, clear}, matching the renderer's switch (the #4301
// establish-tunnels pattern).
//
// FAIL-ON-REVERT: reverting the df-bit leaf in schema_security.go back to
// untyped (args:1 with no validator) makes every reject case below return nil
// and go RED — a typo would commit clean and silently invert DF handling.
func TestIPsecDFBitEnumSchemaGate_5649(t *testing.T) {
	reject := func(set, badVal string) {
		t.Helper()
		tree := flatTreeFromSets(t, set)
		err := SchemaValidate(tree)
		if err == nil {
			t.Fatalf("%q: expected SchemaValidate to REJECT typo, got nil (silent copy-DF default)", set)
		}
		if !strings.Contains(err.Error(), badVal) {
			t.Fatalf("%q: reject error %q should name the bad value %q", set, err, badVal)
		}
	}
	accept := func(set string) {
		t.Helper()
		tree := flatTreeFromSets(t, set)
		if err := SchemaValidate(tree); err != nil {
			t.Fatalf("%q: expected SchemaValidate to ACCEPT valid value, got %v", set, err)
		}
	}

	// --- Typos / unhandled tokens are rejected (fail-closed, error names value) ---
	reject("set security ipsec vpn tun1 df-bit cler", "cler")   // → would keep copy-DF default
	reject("set security ipsec vpn tun1 df-bit copyy", "copyy") // → renderer omits copy_df
	reject("set security ipsec vpn tun1 df-bit on", "on")       // unhandled mode
	reject("set security ipsec vpn tun1 df-bit yes", "yes")     // unhandled mode

	// --- Every value the renderer handles must still commit (no false reject) ---
	for _, v := range []string{"copy", "set", "clear"} {
		accept("set security ipsec vpn tun1 df-bit " + v)
	}
}
