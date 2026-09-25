package userspace

import (
	"slices"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// compileSet builds a typed config from a flat-set command list, failing the
// test on any parse / set / compile error.
func compileSet(t *testing.T, cmds []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func policySnapshotAddrs(t *testing.T, snap *ConfigSnapshot, fromZone, toZone, name string, source bool) []string {
	t.Helper()
	for i := range snap.Policies {
		p := &snap.Policies[i]
		if p.FromZone != fromZone || p.ToZone != toZone || p.Name != name {
			continue
		}
		legacy, literals, ids := p.DestinationAddresses, p.DestinationLiterals, p.DestinationBookIDs
		if source {
			legacy, literals, ids = p.SourceAddresses, p.SourceLiterals, p.SourceBookIDs
		}
		if len(literals) == 0 && len(ids) == 0 {
			return legacy
		}
		out := append([]string(nil), literals...)
		for _, id := range ids {
			found := false
			for _, book := range snap.AddressBooks {
				if book.ID == id {
					out = append(out, book.PrefixesV4...)
					out = append(out, book.PrefixesV6...)
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("policy %s->%s %q references missing address-book ID %d", fromZone, toZone, name, id)
			}
		}
		slices.Sort(out)
		return out
	}
	t.Fatalf("policy %s->%s %q not found in snapshot", fromZone, toZone, name)
	return nil
}

func policySourceAddrs(t *testing.T, snap *ConfigSnapshot, fromZone, toZone, name string) []string {
	return policySnapshotAddrs(t, snap, fromZone, toZone, name, true)
}

func policyDestAddrs(t *testing.T, snap *ConfigSnapshot, fromZone, toZone, name string) []string {
	return policySnapshotAddrs(t, snap, fromZone, toZone, name, false)
}

// TestZoneLocalAddressBookResolves is the #3061 resolution guard. A policy
// referencing a name defined ONLY in its from-zone's zone-local address book
// must commit and reach the dataplane snapshot with the address expanded to
// its prefix. Before #3061 the zone-local book was parsed but silently
// dropped, so the name was undefined globally and CompileConfig rejected the
// policy (validatePolicyMatchAddressesStrict) — i.e. this test goes RED on
// revert at the CompileConfig step.
func TestZoneLocalAddressBookResolves(t *testing.T) {
	cfg := compileSet(t, []string{
		"set interfaces eth0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces eth1 unit 0 family inet address 10.0.2.1/24",
		"set security zones security-zone trust interfaces eth0",
		"set security zones security-zone untrust interfaces eth1",
		"set security zones security-zone trust address-book address web-server 10.0.1.100/32",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address web-server",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
	})

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{Workers: 1, RingEntries: 2048}, 1, 1)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	src := policySourceAddrs(t, snap, "trust", "untrust", "p1")
	if !slices.Contains(src, "10.0.1.100/32") {
		t.Fatalf("zone-local source-address web-server did not resolve; SourceAddresses = %v, want it to contain 10.0.1.100/32", src)
	}
}

// TestZoneLocalAddressBookScoping is the #3061 precedence + scoping guard.
// The same name (web-server) is defined BOTH globally (10.9.9.9/32) and in
// zone trust's local book (10.0.1.100/32):
//
//   - A policy whose from-zone is trust resolves web-server to the ZONE-LOCAL
//     value (10.0.1.100/32) — zone-local wins over global.
//   - A policy whose from-zone is dmz (no local book) resolves web-server to
//     the GLOBAL value (10.9.9.9/32) — the trust-local value does NOT leak to
//     another zone (scoping).
//   - destination-address resolves against the TO zone's book the same way.
//
// On revert the zone-local book is dropped, so the trust policy would resolve
// to the global 10.9.9.9/32 — the zone-local assertion goes RED.
func TestZoneLocalAddressBookScoping(t *testing.T) {
	cfg := compileSet(t, []string{
		"set interfaces eth0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces eth1 unit 0 family inet address 10.0.2.1/24",
		"set interfaces eth2 unit 0 family inet address 10.0.3.1/24",
		"set security zones security-zone trust interfaces eth0",
		"set security zones security-zone untrust interfaces eth1",
		"set security zones security-zone dmz interfaces eth2",
		"set security address-book global address web-server 10.9.9.9/32",
		"set security zones security-zone trust address-book address web-server 10.0.1.100/32",
		// from-zone trust: source resolves zone-local first.
		"set security policies from-zone trust to-zone untrust policy local match source-address web-server",
		"set security policies from-zone trust to-zone untrust policy local match destination-address any",
		"set security policies from-zone trust to-zone untrust policy local match application any",
		"set security policies from-zone trust to-zone untrust policy local then permit",
		// from-zone dmz: no local book, source falls back to global.
		"set security policies from-zone dmz to-zone untrust policy fallback match source-address web-server",
		"set security policies from-zone dmz to-zone untrust policy fallback match destination-address any",
		"set security policies from-zone dmz to-zone untrust policy fallback match application any",
		"set security policies from-zone dmz to-zone untrust policy fallback then permit",
		// to-zone trust: destination resolves zone-local first.
		"set security policies from-zone untrust to-zone trust policy dst match source-address any",
		"set security policies from-zone untrust to-zone trust policy dst match destination-address web-server",
		"set security policies from-zone untrust to-zone trust policy dst match application any",
		"set security policies from-zone untrust to-zone trust policy dst then permit",
	})

	snap, err := buildSnapshot(cfg, config.UserspaceConfig{Workers: 1, RingEntries: 2048}, 1, 1)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}

	local := policySourceAddrs(t, snap, "trust", "untrust", "local")
	if !slices.Contains(local, "10.0.1.100/32") || slices.Contains(local, "10.9.9.9/32") {
		t.Fatalf("trust from-zone source must resolve zone-local web-server (10.0.1.100/32), not global (10.9.9.9/32); got %v", local)
	}

	fallback := policySourceAddrs(t, snap, "dmz", "untrust", "fallback")
	if !slices.Contains(fallback, "10.9.9.9/32") || slices.Contains(fallback, "10.0.1.100/32") {
		t.Fatalf("dmz from-zone source must resolve GLOBAL web-server (10.9.9.9/32); the trust-local value (10.0.1.100/32) must not leak; got %v", fallback)
	}

	dst := policyDestAddrs(t, snap, "untrust", "trust", "dst")
	if !slices.Contains(dst, "10.0.1.100/32") || slices.Contains(dst, "10.9.9.9/32") {
		t.Fatalf("trust to-zone destination must resolve zone-local web-server (10.0.1.100/32), not global (10.9.9.9/32); got %v", dst)
	}
}
