package config

import (
	"strings"
	"testing"
)

// #13210 (D3-04): nat64PrefixOwnerKey must agree with
// NormaliseNAT64PrefixForSnapshot / dataplaneAcceptsNAT64Mask on the
// leading-'+' mask spelling the dataplane accepts. Normalising
// "64:ff9b::/+96" yields a live "64:ff9b::/96" allocator, so the owner key
// must classify it as an owner; otherwise #9555 shadowing and #5144
// external-tuple overlap detection silently skip a live allocator on the
// tolerant load / peer-sync path.
func TestNAT64PrefixOwnerKeyMatchesNormaliseForSnapshot13210(t *testing.T) {
	// Control: canonical spelling is an owner.
	if key, ok := nat64PrefixOwnerKey("64:ff9b::/96"); !ok || key != "64:ff9b::/96" {
		t.Fatalf("canonical: nat64PrefixOwnerKey = (%q, %v), want (64:ff9b::/96, true)", key, ok)
	}
	// Regression: the normalised spelling must produce the same owner key.
	norm := NormaliseNAT64PrefixForSnapshot("64:ff9b::/+96")
	if norm != "64:ff9b::/96" {
		t.Fatalf("NormaliseNAT64PrefixForSnapshot(64:ff9b::/+96) = %q, want 64:ff9b::/96", norm)
	}
	key, ok := nat64PrefixOwnerKey("64:ff9b::/+96")
	if !ok {
		t.Fatal("nat64PrefixOwnerKey(64:ff9b::/+96) = not-owner, but Normalise installs 64:ff9b::/96 in the dataplane")
	}
	if want, _ := nat64PrefixOwnerKey(norm); key != want {
		t.Fatalf("nat64PrefixOwnerKey(64:ff9b::/+96) = %q, want same key as normalised %q", key, want)
	}
	// The '+' spelling must also participate in #9555 shadowing: a second
	// rule-set under the same canonical prefix is shadowed regardless of
	// which spelling each rule-set used.
	cfg := &Config{Security: SecurityConfig{NAT: NATConfig{NAT64: []*NAT64RuleSet{
		{Name: "first", Prefix: "64:ff9b::/+96"},
		{Name: "second", Prefix: "64:ff9b::/96"},
	}}}}
	if shadowed := nat64ShadowedRuleSets(cfg); len(shadowed) != 1 {
		t.Fatalf("nat64ShadowedRuleSets with +96 first rule-set: got %d shadowed, want 1", len(shadowed))
	}
	// #5144 must see a live NAT64 owner using the +96 spelling when it shares
	// an address with the independent source-NAT allocator on tolerant load.
	cmds := []string{
		"set security nat source pool P address 100.64.0.7/32",
		"set security nat nat64 rule-set N64 prefix 64:ff9b::/+96",
		"set security nat nat64 rule-set N64 source-pool P",
	}
	cmds = append(cmds, srcRule("RS", "r1", "P")...)
	lenientCfg, err := CompileConfigLenient(natOverlapTree(t, cmds...))
	if err != nil {
		t.Fatalf("lenient compile unexpectedly failed: %v", err)
	}
	foundOverlap := false
	for _, warning := range lenientCfg.Warnings {
		if strings.Contains(warning, "#5144") {
			foundOverlap = true
			break
		}
	}
	if !foundOverlap {
		t.Fatalf("NAT64 +96 allocator did not participate in #5144 overlap detection; warnings = %v", lenientCfg.Warnings)
	}

	// Fail-closed controls: masks the dataplane does not accept stay non-owners.
	for _, p := range []string{"64:ff9b::/++96", "64:ff9b::/+64", "64:ff9b::/+96x", "64:ff9b::/+"} {
		if _, ok := nat64PrefixOwnerKey(p); ok {
			t.Errorf("nat64PrefixOwnerKey(%q) = owner, want non-owner", p)
		}
	}
}
