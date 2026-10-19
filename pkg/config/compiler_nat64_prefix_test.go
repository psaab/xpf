package config

import (
	"strings"
	"testing"
)

// #3886: commit-time validation for a NAT64 rule-set `prefix`.
//
// The prefix is read verbatim into the wire snapshot (compileNAT64 ->
// buildNAT64Snapshots) and parsed at dataplane apply by the Rust
// Nat64State::try_from_snapshots /96-integrity check (userspace-dp/src/nat64.rs).
// That check REQUIRES an IPv6 `<address>/96`: it splits on '/', the token after
// the first '/' must parse as a decimal 96 (only /96 is supported), and the
// address token before the '/' must parse as an IPv6 address. Anything else
// makes try_from_snapshots return a SnapshotIntegrityError, which aborts the
// ENTIRE build_reconcile_forwarding without publishing — freezing the dataplane
// at the last-good snapshot so every later commit silently stops reaching it.
//
// The commit gate rejects a non-/96 or malformed prefix at commit so the
// operator gets an error instead of a silent dataplane freeze. RED-on-revert:
// deleting validateNAT64PrefixStrict makes each reject-case below compile
// cleanly (commit green, then dataplane-rebuild freeze) -> the reject tests go
// RED.
//
// All tests use the production ParseSetCommand + SetPath path (buildTree),
// never NewParser (the flat-set gotcha in CLAUDE.md).

// nat64Set builds a minimal NAT64 rule-set with the given prefix and a
// defined source pool (#15000: an omitted pool is now strict-rejected, so
// prefix fixtures must carry a valid pool to reach the prefix gate).
func nat64Set(prefix string) []string {
	return []string{
		"set security nat source pool p64 address 100.64.0.7/32",
		"set security nat nat64 rule-set rs1 prefix " + prefix,
		"set security nat nat64 rule-set rs1 source-pool p64",
	}
}

func TestNAT64PrefixWellKnownSlash96OK(t *testing.T) {
	// RFC 6052 well-known prefix 64:ff9b::/96 — must compile on the strict path.
	tree := buildTree(t, nat64Set("64:ff9b::/96"))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("well-known 64:ff9b::/96 must compile, got: %v", err)
	}
}

func TestNAT64PrefixNSPSlash96OK(t *testing.T) {
	// A /96 network-specific prefix — must compile on the strict path.
	for _, p := range []string{"2001:db8::/96", "2001:db8:1:2:3:4::/96"} {
		tree := buildTree(t, nat64Set(p))
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("/96 NSP %q must compile, got: %v", p, err)
		}
	}
}

func TestNAT64PrefixWithSourcePoolSlash96OK(t *testing.T) {
	// A complete NAT64 rule-set (prefix + valid /32 source pool) must compile.
	tree := buildTree(t, []string{
		"set security nat source pool p64 address 100.64.0.7/32",
		"set security nat nat64 rule-set rs1 prefix 64:ff9b::/96",
		"set security nat nat64 rule-set rs1 source-pool p64",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("valid NAT64 rule-set must compile, got: %v", err)
	}
}

func TestNAT64PrefixRejectsNonSlash96(t *testing.T) {
	// A non-/96 length (the exact case in the issue) — reject at commit. The
	// Rust /96-integrity check aborts the whole forwarding rebuild otherwise.
	tree := buildTree(t, nat64Set("2001:db8::/64"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("NAT64 prefix /64 (non-/96) must be rejected at commit")
	}
	msg := err.Error()
	if !strings.Contains(msg, "rs1") ||
		!strings.Contains(msg, "2001:db8::/64") ||
		!strings.Contains(msg, "/96") {
		t.Fatalf("error must name the rule-set + offending prefix + /96 requirement, got: %v", err)
	}
}

func TestNAT64PrefixRejectsOtherLengths(t *testing.T) {
	// Every non-96 mask length must be rejected (the translator supports /96
	// only; any other length is silently dropped -> rebuild abort).
	for _, p := range []string{"64:ff9b::/32", "64:ff9b::/48", "64:ff9b::/64", "64:ff9b::/128", "64:ff9b::/95"} {
		tree := buildTree(t, nat64Set(p))
		if _, err := CompileConfig(tree); err == nil {
			t.Fatalf("NAT64 prefix %q (non-/96) must be rejected at commit", p)
		}
	}
}

func TestNAT64PrefixRejectsMissingMask(t *testing.T) {
	// A bare address with no mask — Rust `parts.get(1)` is None -> reject.
	tree := buildTree(t, nat64Set("64:ff9b::"))
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("NAT64 prefix with no /mask must be rejected at commit")
	}
}

func TestNAT64PrefixRejectsGarbageMask(t *testing.T) {
	// A non-numeric or empty mask — Rust `.parse::<u8>()` fails -> reject.
	for _, p := range []string{"64:ff9b::/", "64:ff9b::/xx", "64:ff9b::/96x", "64:ff9b::/300"} {
		tree := buildTree(t, nat64Set(p))
		if _, err := CompileConfig(tree); err == nil {
			t.Fatalf("NAT64 prefix %q (garbage mask) must be rejected at commit", p)
		}
	}
}

func TestNAT64PrefixRejectsMalformedAddress(t *testing.T) {
	// The mask is /96 but the address part does not parse as IPv6 — Rust
	// `parts[0].parse::<Ipv6Addr>()` fails -> reject. Covers a garbage token
	// and an IPv4 dotted-quad (which Rust's Ipv6Addr::from_str rejects).
	for _, p := range []string{"nonsense/96", "192.0.2.0/96", "64:ff9b:::/96", "g::1/96"} {
		tree := buildTree(t, nat64Set(p))
		if _, err := CompileConfig(tree); err == nil {
			t.Fatalf("NAT64 prefix %q (malformed IPv6 address) must be rejected at commit", p)
		}
	}
}

func TestNAT64PrefixRejectsIPv4(t *testing.T) {
	// An IPv4 CIDR — Rust rejects (not an Ipv6Addr, and /24 != 96) -> reject.
	tree := buildTree(t, nat64Set("192.0.2.0/24"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("NAT64 IPv4 prefix must be rejected at commit")
	}
	if !strings.Contains(err.Error(), "rs1") {
		t.Fatalf("error must name the rule-set, got: %v", err)
	}
}

// Lenient path (#1960 / #1979 doctrine): a bad NAT64 prefix in an
// already-persisted or peer-synced config must NOT hard-fail the compile
// (that would brick the daemon on restart); it is downgraded to a warning.
func TestNAT64PrefixLenientDowngradesToWarning(t *testing.T) {
	for _, p := range []string{"2001:db8::/64", "64:ff9b::", "nonsense/96", "192.0.2.0/24"} {
		tree := buildTree(t, nat64Set(p))
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile must NOT hard-fail on bad NAT64 prefix %q, got: %v", p, err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "rs1") && strings.Contains(w, p) && strings.Contains(w, "nat64") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("lenient compile must emit a warning naming the bad NAT64 prefix %q, warnings: %v", p, cfg.Warnings)
		}
	}
}

// The valid well-known prefix must NOT warn on the lenient path either — the
// gate must be silent on good input (no warning-noise regression).
func TestNAT64PrefixLenientNoWarningOnValid(t *testing.T) {
	tree := buildTree(t, nat64Set("64:ff9b::/96"))
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile of valid prefix must not fail, got: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "nat64") && strings.Contains(w, "prefix") {
			t.Fatalf("valid NAT64 prefix must not warn, got: %q", w)
		}
	}
}
