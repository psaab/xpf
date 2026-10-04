package config

import (
	"strings"
	"testing"
)

// Tests for #5676 (codex-review-182 M10, High): an address book (global or
// zone-local) that defines the SAME name as BOTH a plain `address` AND an
// `address-set`. The two kinds share one operator-visible namespace but are
// stored in separate maps (AddressBook.Addresses / AddressBook.AddressSets), so
// the collision committed silently and every name→prefix resolver
// (pkg/dataplane/userspace expandBookNameRecursive, host-inbound junos_host_deny)
// resolved address-first — the plain address SHADOWED the same-named
// address-set, dropping the set's other members and changing which traffic a
// permit/deny rule covers with no diagnostic.
//
// The fix hard-rejects the collision on the strict commit / commit-check path
// (validateAddressBookNameCollisionStrict, wired in runEarlyStrictAndFolds).
// Tolerant loads still boot and retain the typed entries with a warning, but
// record the colliding name so userspace policy references fail closed with the
// __unsupported_address__ sentinel and a non-empty rejection mirror (#12049).
//
// FAIL-ON-REVERT: dropping the `if err := validateAddressBookNameCollisionStrict(
// cfg); ... ` dispatch in compiler_earlystrict.go turns every strict-reject case
// GREEN (CompileConfig accepts the collision) and drops the lenient warning — so
// TestAddrSetCollision{Global,ZoneLocal}RejectedAtCommit and
// TestAddrSetCollisionLenientDowngrades go RED.

// TestAddrSetCollisionGlobalRejectedAtCommit — a global address book that names
// the same token as both an `address` and an `address-set` is rejected at strict
// commit, and the diagnostic names both the colliding entry and the book.
func TestAddrSetCollisionGlobalRejectedAtCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set security address-book global address blocklist 10.0.1.0/24",
		"set security address-book global address other 10.9.9.9/32",
		"set security address-book global address-set blocklist address other",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected strict commit to reject a same-name address + address-set collision in the global book")
	}
	msg := err.Error()
	for _, want := range []string{"blocklist", "address", "address-set", "global"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("collision error %q does not mention %q", msg, want)
		}
	}
}

// TestAddrSetCollisionGlobalRejectedBothOrderings — the reject is independent of
// the order the two entries appear in the config (the collision is a property of
// the two maps, not of set-command line order). Junos-parity: vSRX rejects the
// second same-name definition regardless of which kind was declared first.
func TestAddrSetCollisionGlobalRejectedBothOrderings(t *testing.T) {
	orderings := map[string][]string{
		"address-first": {
			"set security address-book global address dup 10.0.1.0/24",
			"set security address-book global address m 10.2.2.2/32",
			"set security address-book global address-set dup address m",
		},
		"set-first": {
			"set security address-book global address m 10.2.2.2/32",
			"set security address-book global address-set dup address m",
			"set security address-book global address dup 10.0.1.0/24",
		},
	}
	for name, cmds := range orderings {
		t.Run(name, func(t *testing.T) {
			if _, err := CompileConfig(buildTree(t, cmds)); err == nil {
				t.Fatalf("expected strict commit to reject the collision (%s ordering)", name)
			}
		})
	}
}

// TestAddrSetCollisionZoneLocalRejectedAtCommit — the gate covers zone-local
// address books too (#3061), and names the offending zone (validated on the
// pristine book BEFORE the zone-local fold).
func TestAddrSetCollisionZoneLocalRejectedAtCommit(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust interfaces eth0",
		"set security zones security-zone trust address-book address grp 10.0.5.0/24",
		"set security zones security-zone trust address-book address inner 10.0.6.7/32",
		"set security zones security-zone trust address-book address-set grp address inner",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected strict commit to reject a same-name collision in a zone-local address book")
	}
	msg := err.Error()
	for _, want := range []string{"grp", "trust", "address-set"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("zone-local collision error %q does not mention %q", msg, want)
		}
	}
}

// TestAddrSetCollisionLenientDowngrades — tolerant load / peer-sync (#1960)
// must remain bootable and report the collision; the dataplane separately
// refuses any policy reference to the ambiguous name (#12049).
func TestAddrSetCollisionLenientDowngrades(t *testing.T) {
	tree := buildTree(t, []string{
		"set security address-book global address blocklist 10.0.1.0/24",
		"set security address-book global address other 10.9.9.9/32",
		"set security address-book global address-set blocklist address other",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not brick on a pre-existing collision: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "collision") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile must record a collision warning; warnings = %v", cfg.Warnings)
	}
	// Both entries survive in their distinct maps — the namespace is tagged at
	// storage, and the runtime resolver picks the documented winner.
	ab := cfg.Security.AddressBook
	if _, ok := ab.Addresses["blocklist"]; !ok {
		t.Fatalf("expected the plain address `blocklist` to survive the lenient load")
	}
	if _, ok := ab.AddressSets["blocklist"]; !ok {
		t.Fatalf("expected the address-set `blocklist` to survive the lenient load")
	}
}


// TestAddrSetNoCollisionCompilesUnchanged — configs that do NOT collide must
// keep compiling clean on the strict path: only an address, only a set, an
// address-set whose MEMBER shares a distinct address's name, and a global
// `address foo` alongside a DIFFERENT zone's zone-local `address-set foo`
// (distinct namespaces after the zone-local fold — NOT a collision).
func TestAddrSetNoCollisionCompilesUnchanged(t *testing.T) {
	cases := map[string][]string{
		"only-address": {
			"set security address-book global address foo 10.0.1.0/24",
		},
		"only-set": {
			"set security address-book global address bar 10.0.2.0/24",
			"set security address-book global address-set foo address bar",
		},
		"set-member-shares-address-name": {
			// The classic valid shape: `servers` is a set whose member is the
			// address `web-server`. Different names — never a collision.
			"set security address-book global address web-server 10.0.1.0/24",
			"set security address-book global address-set servers address web-server",
		},
		"global-address-vs-different-zone-set": {
			"set interfaces eth0 unit 0 family inet address 10.0.0.1/24",
			"set security zones security-zone trust interfaces eth0",
			"set security address-book global address shared 10.0.1.0/24",
			"set security zones security-zone trust address-book address m 10.0.9.0/24",
			"set security zones security-zone trust address-book address-set shared address m",
		},
	}
	for name, cmds := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := CompileConfig(buildTree(t, cmds)); err != nil {
				t.Fatalf("non-colliding config %q must compile clean on the strict path: %v", name, err)
			}
		})
	}
}
