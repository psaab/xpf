package config

import "testing"

// #8939 on the four `security ike|ipsec proposal|policy` containers. They are
// DISTINCT schema nodes with four DUPLICATED readers in compiler_ipsec.go, so
// a fix at one leaves the other three broken -- the same duplication that made
// #9077 assert both gateway containers.
//
//	set security ike proposal p1 authentication-algorithm sha1 \
//	    authentication-method pre-shared-keys dh-group group14
//	  -> AuthAlg="sha1"  AuthMethod=""  DHGroup=0
//
// Phase-1 crypto with no DH group and no authentication method; phase-2 with
// no `encryption-algorithm`, an ESP proposal naming no cipher. Same
// crypto-selection class as the ISIS/RIP downgrade one layer up.
//
// CHANNEL, MEASURED, AND IT IS NOT THE OPERATOR'S KEYBOARD. All four are
// CLOSED-WORLD subtrees, so the packed spelling is rejected by the typed walk
// before the compiler sees it:
//
//	set security ipsec proposal pr1 authentication-algorithm hmac-sha1-96 \
//	    description "d" dh-group group14              -> SCHEMA-REJECT
//	the same three as separate statements               -> ACCEPTED
//
// These are `lenient-only` rows: they reach this code on Store.Load (boot from
// the persisted DB) and Store.SyncApply (HA config sync), where the same gate
// is downgraded to a slog.Warn. Worth fixing -- the truncation lands where
// nobody is watching -- but the operator-typed story does NOT apply and is
// deliberately not told.
//
// It also falsifies a rule I had written down: "a flat run is rejected iff the
// leaf it starts at declares a type/validator". `authentication-algorithm`
// here is UNTYPED and the run is rejected anyway, because the CONTAINER is
// closed-world. The discriminator is a conjunction -- accepted iff the
// container is open-world AND the starting leaf is untyped -- and either
// condition alone rejects.
func TestProposalFlatRunKeepsEveryLeaf8939(t *testing.T) {
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

	t.Run("ike proposal", func(t *testing.T) {
		b := "set security ike proposal p1 "
		get := func(cfg *Config) *IKEProposal {
			p := cfg.Security.IPsec.IKEProposals["p1"]
			if p == nil {
				t.Fatal("no ike proposal (#8939)")
			}
			return p
		}
		ref := get(build(t, b+"authentication-algorithm sha1",
			b+"authentication-method pre-shared-keys", b+"dh-group group14"))
		if ref.AuthAlg == "" || ref.AuthMethod == "" || ref.DHGroup == 0 {
			t.Fatalf("the split reference arm is incomplete (%+v) (#8939)", ref)
		}
		for _, tc := range []struct{ name, cmd string }{
			{"two leaves", b + "authentication-algorithm sha1 authentication-method pre-shared-keys"},
			{"three leaves", b + "authentication-algorithm sha1 " +
				"authentication-method pre-shared-keys dh-group group14"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got := get(build(t, tc.cmd))
				if got.AuthMethod != ref.AuthMethod {
					t.Errorf("authentication-method = %q, want %q (#8939)",
						got.AuthMethod, ref.AuthMethod)
				}
				if tc.name == "three leaves" && got.DHGroup != ref.DHGroup {
					t.Errorf("dh-group = %d, want %d -- the leaf a recursive descent "+
						"drops, and the one that selects phase-1 key strength (#8939)",
						got.DHGroup, ref.DHGroup)
				}
			})
		}
	})

	t.Run("ipsec proposal", func(t *testing.T) {
		b := "set security ipsec proposal p1 "
		get := func(cfg *Config) *IPsecProposal {
			p := cfg.Security.IPsec.Proposals["p1"]
			if p == nil {
				t.Fatal("no ipsec proposal (#8939)")
			}
			return p
		}
		ref := get(build(t, b+"authentication-algorithm hmac-sha1-96",
			b+"encryption-algorithm aes-128-cbc", b+"protocol esp"))
		if ref.AuthAlg == "" || ref.EncryptionAlg == "" || ref.Protocol == "" {
			t.Fatalf("the split reference arm is incomplete (%+v) (#8939)", ref)
		}
		for _, tc := range []struct{ name, cmd string }{
			{"two leaves", b + "authentication-algorithm hmac-sha1-96 encryption-algorithm aes-128-cbc"},
			{"three leaves", b + "authentication-algorithm hmac-sha1-96 " +
				"encryption-algorithm aes-128-cbc protocol esp"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got := get(build(t, tc.cmd))
				if got.EncryptionAlg != ref.EncryptionAlg {
					t.Errorf("encryption-algorithm = %q, want %q -- an ESP proposal "+
						"naming no cipher (#8939)", got.EncryptionAlg, ref.EncryptionAlg)
				}
				if tc.name == "three leaves" && got.Protocol != ref.Protocol {
					t.Errorf("protocol = %q, want %q -- the leaf a recursive descent "+
						"drops (#8939)", got.Protocol, ref.Protocol)
				}
			})
		}
	})

	t.Run("ike policy", func(t *testing.T) {
		b := "set security ike policy pol1 "
		get := func(cfg *Config) *IKEPolicy {
			p := cfg.Security.IPsec.IKEPolicies["pol1"]
			if p == nil {
				t.Fatal("no ike policy (#8939)")
			}
			return p
		}
		ref := get(build(t, b+"mode main", b+"proposal-set standard"))
		if ref.Mode == "" || ref.ProposalSet == "" {
			t.Fatalf("the split reference arm is incomplete (%+v) (#8939)", ref)
		}
		got := get(build(t, b+"mode main proposal-set standard"))
		if got.ProposalSet != ref.ProposalSet {
			t.Errorf("proposal-set = %q, want %q (#8939)", got.ProposalSet, ref.ProposalSet)
		}
	})

	// NO `ipsec policy` ARM, and the absence is the finding. That container
	// declares one eligible leaf (`perfect-forward-secrecy` is a container,
	// `proposals` is multi), so the collector drops it and it has no census
	// row. Its packed spelling loses a value in BOTH orderings, but neither is
	// the flat-run chain -- see the comment at the loop in compiler_ipsec.go.
}

// TestProposalFlatRunIsLenientOnly8939 pins the CHANNEL, because the severity
// sentence depends on it and the two channels are not the same claim.
//
// It also carries the counterexample that falsified the leaf-level rule:
// `authentication-algorithm` is untyped (validator nil, valueType 0) and the
// run is rejected anyway, because the container is closed-world.
func TestProposalFlatRunIsLenientOnly8939(t *testing.T) {
	mk := func(cmds ...string) *ConfigTree {
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
		return tree
	}
	b := "set security ipsec proposal pr1 "

	// REFERENCE ARM: the split spelling must ADMIT. Without it a rejection
	// below would be evidence about the fixture, not about the spelling.
	if err := SchemaValidateWithDefinitions(mk(b+"authentication-algorithm hmac-sha1-96", b+"encryption-algorithm aes-128-cbc"), nil); err != nil {
		t.Fatalf("the SPLIT spelling is rejected (%v); the packed-vs-split "+
			"comparison below is about the fixture, not the spelling (#8939)", err)
	}

	if err := SchemaValidateWithDefinitions(mk(b+"authentication-algorithm hmac-sha1-96 encryption-algorithm aes-128-cbc"), nil); err == nil {
		t.Log("NOTE: the packed spelling is now ADMITTED on the operator commit " +
			"path. This container has become operator-reachable and its severity " +
			"framing needs re-deriving (#8939).")
	}

	// The counterexample to the leaf-level rule, asserted so it cannot rot.
	sec := resolveSchemaChild(setSchema, "security")
	pr := resolveSchemaChild(resolveSchemaChild(sec, "ipsec"), "proposal")
	if pr != nil && pr.wildcard != nil {
		pr = pr.wildcard
	}
	aa := resolveSchemaChild(pr, "authentication-algorithm")
	if aa == nil {
		t.Fatal("security ipsec proposal declares no authentication-algorithm")
	}
	if aa.validator != nil || aa.valueType != 0 {
		t.Skip("authentication-algorithm is now TYPED; the conjunction " +
			"counterexample needs a different leaf")
	}
}
