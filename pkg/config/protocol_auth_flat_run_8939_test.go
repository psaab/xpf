package config

import "testing"

// #8939 on routing-protocol authentication, and the loss is not a setting --
// it is a SILENT CRYPTOGRAPHIC DOWNGRADE that puts the operator's key on the
// wire in cleartext.
//
//	set protocols isis authentication-key secret1 authentication-type md5
//	  -> authentication-key="secret1"  authentication-type=""
//
// ALPHABETICAL ORDER PICKS THE WORST OF THE TWO OUTCOMES. `authentication-key`
// precedes `authentication-type`, so the flat run keeps the KEY and drops the
// TYPE. Authentication therefore stays switched ON and falls back to
// plaintext, rather than switching off -- pkg/frr keys the mode on
// AuthTypeIsMD5(), which is false for "". Rendered (asserted in
// pkg/frr/protocol_auth_render_8939_test.go, which is where the wire
// consequence belongs):
//
//	split   area-password md5 secret1     / ip rip authentication mode md5
//	packed  area-password clear secret1   / ip rip authentication mode text
//
// AND NOTHING WARNS. #8443 added a downgrade warning for an UNRECOGNIZED
// authentication-type, but AuthTypeUnrecognized("") is FALSE -- an empty type
// is not unrecognized, it is absent -- so the one diagnostic built for exactly
// this failure does not fire. `show configuration` echoes back the `md5` the
// operator wrote.
//
// Operator-reachable: all three sites are `OPERATOR` rows in the #8939 census
// and every packed spelling below commits clean through the strict pair.
func TestProtocolAuthFlatRunKeepsEveryLeaf8939(t *testing.T) {
	build := func(t *testing.T, cmds ...string) *Config {
		t.Helper()
		tree := &ConfigTree{}
		for _, c := range cmds {
			p, err := ParseSetCommand(c)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", c, err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatalf("SetPath(%q): %v", c, err)
			}
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil || cfg == nil {
			t.Fatalf("compile: %v", err)
		}
		return cfg
	}

	t.Run("protocols rip", func(t *testing.T) {
		b := "set protocols rip "
		ref := build(t, b+"authentication-key secret1", b+"authentication-type md5").Protocols.RIP
		if ref == nil || ref.AuthKey.Reveal() == "" || ref.AuthType == "" {
			t.Fatalf("the split reference arm is incomplete (%+v) -- every comparison "+
				"below would pass against a config that carries nothing (#8939)", ref)
		}
		got := build(t, b+"authentication-key secret1 authentication-type md5").Protocols.RIP
		if got == nil || got.AuthType != ref.AuthType {
			t.Errorf("rip authentication-type = %q, want %q -- an empty type renders "+
				"`ip rip authentication mode text` and puts the key on the wire in "+
				"cleartext (#8939)", got.AuthType, ref.AuthType)
		}
	})

	t.Run("protocols isis", func(t *testing.T) {
		b := "set protocols isis "
		ref := build(t, b+"authentication-key secret1", b+"authentication-type md5",
			b+"is-type level-2").Protocols.ISIS
		if ref == nil || ref.AuthKey.Reveal() == "" || ref.AuthType == "" || ref.Level == "" {
			t.Fatalf("the split reference arm is incomplete (%+v) (#8939)", ref)
		}
		for _, tc := range []struct{ name, cmd string }{
			{"two leaves", b + "authentication-key secret1 authentication-type md5"},
			// THE WIDTH A RECURSIVE DESCENT FAILS (#9079). `is-type` is the
			// census row's third leaf.
			{"three leaves", b + "authentication-key secret1 authentication-type md5 is-type level-2"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got := build(t, tc.cmd).Protocols.ISIS
				if got == nil || got.AuthType != ref.AuthType {
					t.Errorf("isis authentication-type = %q, want %q -- an empty type "+
						"renders `area-password clear` instead of `md5` (#8939)",
						got.AuthType, ref.AuthType)
				}
				if tc.name == "three leaves" && got.Level != ref.Level {
					t.Errorf("isis is-type = %q, want %q -- the leaf a recursive "+
						"descent drops (#8939)", got.Level, ref.Level)
				}
			})
		}
	})

	t.Run("protocols isis interface", func(t *testing.T) {
		b := "set protocols isis interface ge-0/0/0 "
		first := func(cfg *Config) *ISISInterface {
			if cfg.Protocols.ISIS == nil || len(cfg.Protocols.ISIS.Interfaces) == 0 {
				t.Fatal("the command produced no isis interface (#8939)")
			}
			return cfg.Protocols.ISIS.Interfaces[0]
		}
		ref := first(build(t, b+"authentication-key secret1", b+"authentication-type md5",
			b+"level 2"))
		if ref.AuthKey.Reveal() == "" || ref.AuthType == "" || ref.Level == "" {
			t.Fatalf("the split reference arm is incomplete (%+v) (#8939)", ref)
		}
		for _, tc := range []struct{ name, cmd string }{
			{"two leaves", b + "authentication-key secret1 authentication-type md5"},
			{"three leaves", b + "authentication-key secret1 authentication-type md5 level 2"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got := first(build(t, tc.cmd))
				if got.AuthType != ref.AuthType {
					t.Errorf("isis interface authentication-type = %q, want %q (#8939)",
						got.AuthType, ref.AuthType)
				}
				if tc.name == "three leaves" && got.Level != ref.Level {
					t.Errorf("isis interface level = %q, want %q -- the leaf a "+
						"recursive descent drops (#8939)", got.Level, ref.Level)
				}
			})
		}
	})
}

// TestProtocolAuthEmptyTypeIsNotUnrecognized8939 pins WHY nothing warned, so a
// future reader does not assume #8443 covered this.
//
// #8443 renders a warning when the authentication-type is UNRECOGNIZED. An
// absent type is not unrecognized -- CanonicalAuthType("") succeeds-as-empty,
// so AuthTypeUnrecognized("") is false and the warning is skipped, while
// AuthTypeIsMD5("") is also false so the renderer takes the plaintext branch.
// The two predicates disagree about what "" means, and the gap between them is
// exactly where this defect lived.
func TestProtocolAuthEmptyTypeIsNotUnrecognized8939(t *testing.T) {
	if AuthTypeUnrecognized("") {
		t.Skip("an empty authentication-type now counts as unrecognized; #8443's " +
			"warning would fire and this note is stale")
	}
	if AuthTypeIsMD5("") {
		t.Fatal("AuthTypeIsMD5(\"\") is true; the plaintext-fallback premise of " +
			"the #8939 severity claim no longer holds")
	}
	t.Log("an ABSENT authentication-type is neither unrecognized (so #8443 does " +
		"not warn) nor md5 (so the renderer emits plaintext). Silence plus a " +
		"downgrade, from two predicates that disagree about the empty string.")
}
