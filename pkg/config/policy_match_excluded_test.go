package config

import (
	"strings"
	"testing"
)

// buildPolicyConfig compiles a set-syntax config into a *Config.
func buildPolicyConfig(t *testing.T, setCommands []string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range setCommands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig failed: %v", err)
	}
	return cfg
}

func findPolicy(t *testing.T, cfg *Config, from, to, name string) *Policy {
	t.Helper()
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil || zpp.FromZone != from || zpp.ToZone != to {
			continue
		}
		for _, p := range zpp.Policies {
			if p != nil && p.Name == name {
				return p
			}
		}
	}
	t.Fatalf("policy %q (%s->%s) not found in compiled config", name, from, to)
	return nil
}

// TestPolicyMatchAddressExcluded asserts the Junos
// `source-address-excluded` / `destination-address-excluded` match
// modifiers are compiled into PolicyMatch (#2008 H2). Before the fix
// the compiler had no switch case for these tokens, so they were
// silently dropped and the booleans stayed false.
func TestPolicyMatchAddressExcluded(t *testing.T) {
	cfg := buildPolicyConfig(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security address-book global address blocked 10.0.0.0/8",
		"set security policies from-zone trust to-zone untrust policy excl match source-address blocked",
		"set security policies from-zone trust to-zone untrust policy excl match source-address-excluded",
		"set security policies from-zone trust to-zone untrust policy excl match destination-address blocked",
		"set security policies from-zone trust to-zone untrust policy excl match destination-address-excluded",
		"set security policies from-zone trust to-zone untrust policy excl match application any",
		"set security policies from-zone trust to-zone untrust policy excl then permit",
	})
	pol := findPolicy(t, cfg, "trust", "untrust", "excl")
	if !pol.Match.SourceAddressExcluded {
		t.Errorf("SourceAddressExcluded = false, want true")
	}
	if !pol.Match.DestinationAddressExcluded {
		t.Errorf("DestinationAddressExcluded = false, want true")
	}
	if len(pol.Match.SourceAddresses) != 1 || pol.Match.SourceAddresses[0] != "blocked" {
		t.Errorf("SourceAddresses = %v, want [blocked]", pol.Match.SourceAddresses)
	}
}

// TestPolicyMatchAddressExcludedDefaultFalse guards against a stray
// always-true wiring: a normal policy without the modifier must keep
// the excluded flags false.
func TestPolicyMatchAddressExcludedDefaultFalse(t *testing.T) {
	cfg := buildPolicyConfig(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy plain match source-address any",
		"set security policies from-zone trust to-zone untrust policy plain match destination-address any",
		"set security policies from-zone trust to-zone untrust policy plain match application any",
		"set security policies from-zone trust to-zone untrust policy plain then permit",
	})
	pol := findPolicy(t, cfg, "trust", "untrust", "plain")
	if pol.Match.SourceAddressExcluded {
		t.Errorf("SourceAddressExcluded = true on a plain policy, want false")
	}
	if pol.Match.DestinationAddressExcluded {
		t.Errorf("DestinationAddressExcluded = true on a plain policy, want false")
	}
}

// TestPolicyMatchAnyIPv4IPv6KeptAsKeywords pins where the Junos family-scoped
// wildcards `any-ipv4` / `any-ipv6` are turned into CIDRs.
//
// #2008 H11 rewrote them to `0.0.0.0/0` / `::/0` HERE, at compile time, because
// the tokens otherwise reached the dataplane as opaque strings that failed CIDR
// parsing, so a policy keyed on `any-ipv4` never matched v4 traffic. That reason
// still holds, and the dataplane still receives the CIDR. #9574 moved the rewrite
// into the userspace snapshot builder, AFTER the token is classified as a keyword
// (TestAnyIPv4KeywordReachesTheWireAsCIDR9574). The compile-time position was
// the defect: the keyword became `0.0.0.0/0` before address-book resolution, so
// an object NAMED `0.0.0.0/0` captured every `any-ipv4`. The compiled config
// therefore keeps the keyword.
func TestPolicyMatchAnyIPv4IPv6KeptAsKeywords(t *testing.T) {
	cfg := buildPolicyConfig(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy v4only match source-address any-ipv4",
		"set security policies from-zone trust to-zone untrust policy v4only match destination-address any-ipv6",
		"set security policies from-zone trust to-zone untrust policy v4only match application any",
		"set security policies from-zone trust to-zone untrust policy v4only then permit",
	})
	pol := findPolicy(t, cfg, "trust", "untrust", "v4only")
	if len(pol.Match.SourceAddresses) != 1 || pol.Match.SourceAddresses[0] != "any-ipv4" {
		t.Errorf("SourceAddresses = %v, want [any-ipv4] (the keyword is kept until the snapshot, #9574)", pol.Match.SourceAddresses)
	}
	if len(pol.Match.DestinationAddresses) != 1 || pol.Match.DestinationAddresses[0] != "any-ipv6" {
		t.Errorf("DestinationAddresses = %v, want [any-ipv6] (the keyword is kept until the snapshot, #9574)", pol.Match.DestinationAddresses)
	}
}

// TestPolicyMatchExcludedSchemaValidates asserts the new schema
// leaves are accepted by SchemaValidate (commit-time validation +
// CLI completion). Before the fix the schema had no
// source-address-excluded / destination-address-excluded children, so
// the path would be flagged as an unknown statement.
func TestPolicyMatchExcludedSchemaValidates(t *testing.T) {
	commands := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy excl match source-address any",
		"set security policies from-zone trust to-zone untrust policy excl match destination-address any",
		"set security policies from-zone trust to-zone untrust policy excl match application any",
		"set security policies from-zone trust to-zone untrust policy excl match source-address-excluded",
		"set security policies from-zone trust to-zone untrust policy excl match destination-address-excluded",
		"set security policies from-zone trust to-zone untrust policy excl then permit",
		"set security policies global policy g match source-address any",
		"set security policies global policy g match destination-address any",
		"set security policies global policy g match application any",
		"set security policies global policy g match source-address-excluded",
		"set security policies global policy g match destination-address-excluded",
		"set security policies global policy g then permit",
	}
	tree := &ConfigTree{}
	for _, cmd := range commands {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if err := SchemaValidate(tree, cfg); err != nil {
		t.Errorf("SchemaValidate rejected the excluded match leaves: %v", err)
	}
}

// TestPolicyMatchAddressTypoFailsCommit asserts that a policy match
// source/destination address that is neither an address-book name, the
// `any` keyword, nor a valid CIDR/IP is HARD-REJECTED at commit (#2008).
// Before the fix such a typo was only a warning, reached the dataplane,
// was silently dropped to an empty set, and (under `*-address-excluded`
// inversion) FAILED OPEN to match-all.
func TestPolicyMatchAddressTypoFailsCommit(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{
			name: "bogus source-address under exclusion",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy p match source-address totally-bogus",
				"set security policies from-zone trust to-zone untrust policy p match source-address-excluded",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
		},
		{
			name: "malformed CIDR source-address",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				// missing octet — net.ParseCIDR rejects, ParseIP rejects.
				"set security policies from-zone trust to-zone untrust policy p match source-address 192.18.1/24",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
		},
		{
			name: "bogus destination-address",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address nope-not-real",
				"set security policies from-zone trust to-zone untrust policy p match application any",
				"set security policies from-zone trust to-zone untrust policy p then permit",
			},
		},
		{
			name: "bogus address in a global policy",
			cmds: []string{
				"set security zones security-zone trust",
				"set security policies global policy g match source-address typo-here",
				"set security policies global policy g match destination-address any",
				"set security policies global policy g match application any",
				"set security policies global policy g then permit",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.cmds)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("expected commit to reject a typo'd policy address, got nil error")
			} else if !strings.Contains(err.Error(), "not a defined address-book entry") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestPolicyMatchAddressLegitimateFormsCommit asserts the strict
// validator does NOT reject any legitimate address form (#2008): an
// address-book name, `any`, `any-ipv4` / `any-ipv6`, a literal CIDR,
// and a bare IP — including under `*-address-excluded`.
func TestPolicyMatchAddressLegitimateFormsCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security address-book global address blocked 10.0.0.0/8",
		// book name + exclusion
		"set security policies from-zone trust to-zone untrust policy book match source-address blocked",
		"set security policies from-zone trust to-zone untrust policy book match source-address-excluded",
		"set security policies from-zone trust to-zone untrust policy book match destination-address any",
		"set security policies from-zone trust to-zone untrust policy book match application any",
		"set security policies from-zone trust to-zone untrust policy book then permit",
		// any-ipv4 / any-ipv6 family-scoped wildcards
		"set security policies from-zone trust to-zone untrust policy fam match source-address any-ipv4",
		"set security policies from-zone trust to-zone untrust policy fam match destination-address any-ipv6",
		"set security policies from-zone trust to-zone untrust policy fam match application any",
		"set security policies from-zone trust to-zone untrust policy fam then permit",
		// literal CIDR + bare IP (v4 and v6)
		"set security policies from-zone trust to-zone untrust policy lit match source-address 172.16.0.0/16",
		"set security policies from-zone trust to-zone untrust policy lit match destination-address 2001:db8::1",
		"set security policies from-zone trust to-zone untrust policy lit match application any",
		"set security policies from-zone trust to-zone untrust policy lit then permit",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("strict commit rejected a legitimate policy address form: %v", err)
	}
}

// TestPolicyMatchAddressTypoLenientDowngradesToWarning asserts the
// tolerant load / peer-sync path downgrades the same typo to a warning
// instead of failing the compile, so an already-persisted bad config
// still boots (#2008). The dataplane's fail-closed handling of an empty
// excluded set is the runtime backstop.
func TestPolicyMatchAddressTypoLenientDowngradesToWarning(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address totally-bogus",
		"set security policies from-zone trust to-zone untrust policy p match source-address-excluded",
		"set security policies from-zone trust to-zone untrust policy p match application any",
		"set security policies from-zone trust to-zone untrust policy p then permit",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not fail on a typo'd policy address: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "policy match-address (downgraded to warning on tolerant path)") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a downgraded policy match-address warning, got warnings: %v", cfg.Warnings)
	}
}
