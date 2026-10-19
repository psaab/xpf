package config

import (
	"strings"
	"testing"
)

// TestDynamicAddressNoProfileRejected15685 covers #15685: a
// `security dynamic-address address-name <name>` with NO `profile feed-name`
// (an empty profile, or no profile at all) compiles into an AddressBinding
// with zero FeedNames. Before the fix the strict cross-reference gate only
// iterated PRESENT FeedNames, so the orphan binding committed clean, shadowed
// any same-named static address-book entry at userspace lowering (a declared
// binding absent from the feed overlay is unrepresentable), and poisoned the
// referencing policy to __unsupported_address__ — aborting the whole userspace
// snapshot publication. Junos requires profile feed-name at commit check.
//
// RED-on-revert: dropping the len(ab.FeedNames)==0 arm in
// validateDynamicAddressFeedReferencesStrict makes the strict subtests accept
// the orphan (CompileConfig returns nil); dropping
// validateDynamicAddressStaticCollisionStrict makes the collision subtests
// accept the shadowing pair.
func TestDynamicAddressNoProfileRejected15685(t *testing.T) {
	t.Run("commit rejects bare address-name with no profile", func(t *testing.T) {
		tree := buildTree3300(t, []string{
			"set security dynamic-address address-name foo",
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("CompileConfig should reject address-name with no profile feed-name")
		}
		if !strings.Contains(err.Error(), `"foo"`) || !strings.Contains(err.Error(), "no profile feed-name") {
			t.Fatalf("error should name the address-name and the missing feed-name, got: %v", err)
		}
	})

	t.Run("commit rejects address-name with fail-mode but no feed-name", func(t *testing.T) {
		// A profile carrying only fail-mode still binds to no feed: the
		// binding can never resolve, regardless of the retained/drop intent.
		tree := buildTree3300(t, []string{
			"set security dynamic-address address-name foo profile fail-mode drop",
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("CompileConfig should reject address-name whose profile has no feed-name")
		}
		if !strings.Contains(err.Error(), "no profile feed-name") {
			t.Fatalf("error should name the missing feed-name, got: %v", err)
		}
	})

	t.Run("commit rejects bare address-name shadowing static address", func(t *testing.T) {
		tree := buildTree3300(t, []string{
			"set security address-book global address foo 10.0.0.0/24",
			"set security dynamic-address address-name foo",
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("CompileConfig should reject a feed-less address-name colliding with a static address")
		}
		if !strings.Contains(err.Error(), `"foo"`) {
			t.Fatalf("error should name the colliding name, got: %v", err)
		}
	})

	t.Run("commit rejects feed-backed binding colliding with static address", func(t *testing.T) {
		// Even a VALID feed binding must not share a name with a static
		// address/address-set: userspace resolution checks the declared
		// binding before the static book, so while the feed is unready the
		// name fails closed and once ready it enforces the union — neither
		// is the single meaning the operator wrote for the static entry.
		tree := buildTree3300(t, []string{
			"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
			"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
			"set security dynamic-address address-name blocked profile feed-name malware",
			"set security address-book global address blocked 10.0.0.0/24",
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("CompileConfig should reject dynamic address-name colliding with a static address")
		}
		if !strings.Contains(err.Error(), `"blocked"`) || !strings.Contains(err.Error(), "collides") {
			t.Fatalf("error should name the collision, got: %v", err)
		}
	})

	t.Run("commit rejects feed-backed binding colliding with static address-set", func(t *testing.T) {
		tree := buildTree3300(t, []string{
			"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
			"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
			"set security dynamic-address address-name blocked profile feed-name malware",
			"set security address-book global address inner 10.0.0.1/32",
			"set security address-book global address-set blocked address inner",
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("CompileConfig should reject dynamic address-name colliding with a static address-set")
		}
		if !strings.Contains(err.Error(), `"blocked"`) {
			t.Fatalf("error should name the colliding name, got: %v", err)
		}
	})

	t.Run("commit rejects binding colliding with zone-local address", func(t *testing.T) {
		tree := buildTree3300(t, []string{
			"set security zones security-zone trust interfaces eth0",
			"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
			"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
			"set security dynamic-address address-name blocked profile feed-name malware",
			"set security zones security-zone trust address-book address blocked 10.0.0.0/24",
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("CompileConfig should reject dynamic address-name colliding with a zone-local address")
		}
		if !strings.Contains(err.Error(), `"blocked"`) {
			t.Fatalf("error should name the colliding name, got: %v", err)
		}
	})

	t.Run("lenient load downgrades orphan and collision to warnings", func(t *testing.T) {
		tree := buildTree3300(t, []string{
			"set security address-book global address foo 10.0.0.0/24",
			"set security dynamic-address address-name foo",
		})
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile should not brick on a feed-less colliding binding, got: %v", err)
		}
		var feedWarn, collisionWarn bool
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "no profile feed-name") {
				feedWarn = true
			}
			if strings.Contains(w, "collides") {
				collisionWarn = true
			}
		}
		if !feedWarn {
			t.Fatalf("lenient compile should warn about the missing feed-name, warnings=%v", cfg.Warnings)
		}
		if !collisionWarn {
			t.Fatalf("lenient compile should warn about the static collision, warnings=%v", cfg.Warnings)
		}
		// The binding survives the tolerant load (runtime stays fail-closed
		// for it via the declared-binding guard); nothing is silently fixed.
		if cfg.Security.DynamicAddress.AddressBindings["foo"] == nil {
			t.Fatal("lenient load must retain the orphan binding, not drop it silently")
		}
	})

	t.Run("valid distinct names still compile", func(t *testing.T) {
		tree := buildTree3300(t, []string{
			"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
			"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
			"set security dynamic-address address-name bad-actors profile feed-name malware",
			"set security address-book global address good-host 10.0.0.0/24",
			"set security address-book global address-set trusted address good-host",
		})
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("distinct dynamic/static names must compile clean, got: %v", err)
		}
	})

	// Direct-validator determinism: with several orphan bindings the first
	// reported name is the lexicographically smallest, regardless of map
	// iteration order (mirrors the existing typo gate's sorted walk).
	t.Run("validator reports first orphan deterministically", func(t *testing.T) {
		cfg := &Config{}
		cfg.Security.DynamicAddress.AddressBindings = map[string]*AddressBinding{
			"zeta":  {Name: "zeta"},
			"alpha": {Name: "alpha"},
		}
		err := validateDynamicAddressFeedReferencesStrict(cfg)
		if err == nil || !strings.Contains(err.Error(), `"alpha"`) {
			t.Fatalf("validator should report alpha first, got: %v", err)
		}
		if err := validateDynamicAddressStaticCollisionStrict(cfg); err != nil {
			t.Fatalf("no static book means no collision, got: %v", err)
		}
		cfg.Security.AddressBook = &AddressBook{Addresses: map[string]*Address{"alpha": {Name: "alpha", Value: "10.0.0.0/24"}}}
		if err := validateDynamicAddressStaticCollisionStrict(cfg); err == nil ||
			!strings.Contains(err.Error(), `"alpha"`) {
			t.Fatalf("validator should report the alpha collision, got: %v", err)
		}
	})
}
