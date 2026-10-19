package config

import (
	"fmt"
	"testing"
)

// #6779: a VRRP virtual-address set larger than the advertisement's single-byte
// address count (RFC 5798 §5.2.4) makes EVERY advert fail to build — and
// pkg/vrrp sendAdvert discards that Marshal error at slog.Debug. The failure is
// an ORDERING problem: becomeMaster claims the VIPs and publishes MASTER first,
// so the node owns the addresses while advertising nothing. Its peer stops
// hearing a master, promotes itself, and both answer for the same addresses.
//
// validateVRRPVIPCountStrict rejects such a set at commit / commit-check.
//
// FAIL-ON-REVERT: drop the validateVRRPVIPCountStrict dispatch in
// compiler_uniformgates_cluster_zone.go (or the comparison inside
// vrrpVIPCountErr) and the over-cap subtests below go green on the BAD config.

// vipCountV4 returns n distinct IPv4 host literals inside 10.9.0.0/16, so every
// VIP is contained by the unit subnet the #3013 containment gate requires.
func vipCountV4(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		// Start at 10.9.0.2 so the unit's own .1 address is not duplicated.
		out = append(out, fmt.Sprintf("10.9.%d.%d", (i+1)>>8, (i+1)&0xff))
	}
	return out
}

// vipCountV6 returns n distinct IPv6 host literals inside 2001:db8::/64.
func vipCountV6(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("2001:db8::%x", i+2))
	}
	return out
}

// vrrpGroupVIPSetLines builds a unit carrying a vrrp-group with n VIPs of the
// requested family. A vrrp-group is authored UNDER a specific `family <af>
// address <prefix>` in Junos, and that prefix is the covering subnet the #3013
// containment gate requires, so every VIP falls inside it.
func vrrpGroupVIPSetLines(n int, isIPv6 bool) []string {
	var base string
	var vips []string
	if isIPv6 {
		base = "set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64 "
		vips = vipCountV6(n)
	} else {
		base = "set interfaces ge-0/0/0 unit 0 family inet address 10.9.0.1/16 "
		vips = vipCountV4(n)
	}
	lines := make([]string, 0, n)
	for _, vip := range vips {
		// #15050: author the VIPs as CIDRs (the enclosing prefix) — a bare
		// literal is now hard-rejected at strict commit for the unrelated
		// missing-prefix reason, which would mask the count gate here.
		if isIPv6 {
			vip += "/64"
		} else {
			vip += "/16"
		}
		lines = append(lines, base+"vrrp-group 1 virtual-address "+vip)
	}
	return lines
}

// compiledGroupVIPCount returns the number of virtual addresses the compiler
// actually stored for the single vrrp-group in cfg, and whether a group was
// found at all.
//
// Every test below that asserts "this config commits cleanly" calls it. Without
// that, a fixture whose set-syntax silently produced NO vrrp-group also commits
// cleanly — the pass would be indistinguishable from a healthy one while
// exercising nothing. (An earlier revision of these fixtures authored
// `vrrp-group` directly under `family inet`, which compiles to zero groups.)
func compiledGroupVIPCount(cfg *Config) (int, bool) {
	for _, ifc := range cfg.Interfaces.Interfaces {
		for _, unit := range ifc.Units {
			for _, vg := range unit.VRRPGroups {
				if vg != nil {
					return len(vg.VirtualAddresses), true
				}
			}
		}
	}
	return 0, false
}

// TestVRRPVIPCountOverCapFailsCommit is the fail-on-revert gate. cap+1 is the
// SMALLEST failing value for each family — the boundary nothing else covers.
func TestVRRPVIPCountOverCapFailsCommit(t *testing.T) {
	for _, tc := range []struct {
		name   string
		isIPv6 bool
		cap    int
	}{
		{"inet", false, MaxVRRPVirtualAddressesIPv4},
		{"inet6", true, MaxVRRPVirtualAddressesIPv6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			over := tc.cap + 1
			tree := buildTree(t, vrrpGroupVIPSetLines(over, tc.isIPv6))

			cfg, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to reject %d %s virtual addresses "+
					"(cap %d): every advert would fail to build while the node "+
					"still owned the VIPs; got nil error (warnings=%v)",
					over, tc.name, tc.cap, cfg.Warnings)
			}
			if !stringContainsAll(err.Error(), "virtual addresses", "exceeds") {
				t.Fatalf("error %q does not describe the over-capacity VIP set",
					err.Error())
			}

			// Tolerant path (load / peer-sync) must NOT brick — #1960 no-brick.
			// The pkg/vrrp runtime guards hold the group out of the election, so
			// a leniently-loaded oversized set is bounded, not a silent owner.
			lcfg, lerr := CompileConfigLenient(tree)
			if lerr != nil {
				t.Fatalf("lenient compile must not reject an oversized VRRP VIP "+
					"set (no-brick), got %v", lerr)
			}
			if !warningsContain(lcfg.Warnings, "virtual address") {
				t.Fatalf("lenient compile should have warned about the VIP count; "+
					"warnings=%v", lcfg.Warnings)
			}
		})
	}
}

// TestVRRPVIPCountAtCapCommits is the TIGHTENING control paired with the test
// above: exactly `cap` addresses is the LARGEST legal set and must commit
// cleanly with no warning. A guard mutated from `>` to `>=` reds here; a guard
// deleted entirely reds the over-cap test. Neither mutation can pass both.
func TestVRRPVIPCountAtCapCommits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		isIPv6 bool
		cap    int
	}{
		{"inet", false, MaxVRRPVirtualAddressesIPv4},
		{"inet6", true, MaxVRRPVirtualAddressesIPv6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, vrrpGroupVIPSetLines(tc.cap, tc.isIPv6))
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("%d %s virtual addresses is exactly the cap and must "+
					"commit, got %v", tc.cap, tc.name, err)
			}
			// The clean commit must come from a config that REALLY carries the
			// cap, not from a fixture that compiled to no group at all.
			got, found := compiledGroupVIPCount(cfg)
			if !found {
				t.Fatalf("fixture produced no vrrp-group: the clean commit "+
					"proves nothing about a %d-address set", tc.cap)
			}
			if got != tc.cap {
				t.Fatalf("fixture compiled to %d %s virtual addresses, want %d "+
					"(exactly the cap) — the boundary is not being exercised",
					got, tc.name, tc.cap)
			}
			if warningsContain(cfg.Warnings, "exceeds the maximum") {
				t.Fatalf("a VIP set at the cap must not warn; warnings=%v",
					cfg.Warnings)
			}
		})
	}
}

// rethVIPCountSetLines builds an untagged RETH in a redundancy group carrying n
// unit addresses. CollectRethInstances turns those unit addresses INTO the
// advertised VIP set, so the same cap applies even though no `vrrp-group` block
// is authored. `no-private-rg-election` is required for RETH VRRP instances to
// be synthesized at all (private RG election is the compiler default).
func rethVIPCountSetLines(n int) []string {
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6779",
		"set chassis cluster reth-count 1",
		"set chassis cluster no-private-rg-election",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
	}
	for _, vip := range vipCountV4(n) {
		lines = append(lines, "set interfaces reth0 unit 0 family inet address "+
			vip+"/16")
	}
	return lines
}

// TestRethDerivedVIPCountOverCapFailsCommit covers the SECOND VIP source. A
// RETH interface authors no vrrp-group at all — its unit addresses become the
// advertised set — so a gate that only walked unit.VRRPGroups would miss this
// entirely while the runtime still built an unadvertisable instance.
func TestRethDerivedVIPCountOverCapFailsCommit(t *testing.T) {
	over := MaxVRRPVirtualAddressesIPv4 + 1
	tree := buildTree(t, rethVIPCountSetLines(over))

	cfg, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("expected commit to reject a RETH carrying %d unit addresses "+
			"(cap %d) — CollectRethInstances advertises them as the VIP set; "+
			"got nil error (warnings=%v)", over, MaxVRRPVirtualAddressesIPv4,
			cfg.Warnings)
	}
	if !stringContainsAll(err.Error(), "reth", "exceeds") {
		t.Fatalf("error %q does not name the reth-derived VRRP VIP set",
			err.Error())
	}

	lcfg, lerr := CompileConfigLenient(tree)
	if lerr != nil {
		t.Fatalf("lenient compile must not reject the reth-derived oversized "+
			"set (no-brick), got %v", lerr)
	}
	if !warningsContain(lcfg.Warnings, "virtual address") {
		t.Fatalf("lenient compile should have warned; warnings=%v", lcfg.Warnings)
	}
}

// TestRethDerivedVIPCountSkippedWhenRGElectionPrivate pins that the gate mirrors
// CollectRethInstances' own early return. Under private RG election (the
// compiler default for any `chassis cluster` stanza) NO reth VRRP instance is
// synthesized, so an oversized unit address list has no advert consequence and
// must not be rejected.
//
// Without this the gate would reject a working configuration — the guard must
// be scoped to configs that actually build a RETH VRRP instance.
func TestRethDerivedVIPCountSkippedWhenRGElectionPrivate(t *testing.T) {
	lines := rethVIPCountSetLines(MaxVRRPVirtualAddressesIPv4 + 1)
	// Drop the no-private-rg-election line, restoring the private-election
	// default under which no RETH VRRP instance exists.
	kept := lines[:0]
	for _, l := range lines {
		if l == "set chassis cluster no-private-rg-election" {
			continue
		}
		kept = append(kept, l)
	}
	tree := buildTree(t, kept)

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("private-rg-election synthesizes no RETH VRRP instance, so an "+
			"oversized unit address list must not be rejected, got %v", err)
	}
	// The clean commit must come from a genuinely OVERSIZED reth: if the
	// fixture lost its addresses, "not rejected" would be true for the wrong
	// reason and this test would pass with the gate scoping removed.
	reth := cfg.Interfaces.Interfaces["reth0"]
	if reth == nil || reth.Units[0] == nil {
		t.Fatalf("fixture produced no reth0 unit 0")
	}
	if n := len(reth.Units[0].Addresses); n <= MaxVRRPVirtualAddressesIPv4 {
		t.Fatalf("fixture compiled to %d reth unit addresses, want more than the "+
			"cap %d — the skip-when-private-election path is not being exercised",
			n, MaxVRRPVirtualAddressesIPv4)
	}
	if warningsContain(cfg.Warnings, "exceeds the maximum") {
		t.Fatalf("no RETH VRRP instance exists — must not warn; warnings=%v",
			cfg.Warnings)
	}
}

// TestVRRPVIPCountConstantsAreInternallyConsistent is the pkg/config half of
// the two-test binding on a number that is necessarily spelled twice (#6779).
//
// pkg/vrrp imports pkg/config and never the reverse, so the per-family ceiling
// exists both here and as vrrp.MaxConfiguredVIPs. The BEHAVIOURAL binding —
// "these constants equal what the real Marshal accepts" — can only live in
// pkg/vrrp, because only that package can see the wire builder. A developer
// running just `go test ./pkg/config/` would therefore not observe a broken
// constant at all; only the repo-wide gate would.
//
// This test closes that window from the config side by pinning the RELATIONSHIP
// rather than either value: an IPv6 advertisement must carry the virtual
// router's link-local first (RFC 5798 §6.1), and pkg/vrrp sendPacketIPv6
// prepends it, so exactly ONE slot is unavailable to configured IPv6 VIPs.
// Editing either constant without the other reds here immediately.
func TestVRRPVIPCountConstantsAreInternallyConsistent(t *testing.T) {
	if d := MaxVRRPVirtualAddressesIPv4 - MaxVRRPVirtualAddressesIPv6; d != 1 {
		t.Fatalf("IPv4 cap %d - IPv6 cap %d = %d, want exactly 1: the IPv6 advert "+
			"reserves one slot for the mandatory link-local prepend, so the two "+
			"caps must differ by exactly that slot (see pkg/vrrp "+
			"MaxConfiguredVIPs, bound behaviourally in "+
			"advert_capacity_agreement_6779_test.go)",
			MaxVRRPVirtualAddressesIPv4, MaxVRRPVirtualAddressesIPv6, d)
	}
	// Both caps must be expressible in the single wire byte they describe.
	for _, c := range []int{MaxVRRPVirtualAddressesIPv4, MaxVRRPVirtualAddressesIPv6} {
		if c < 1 || c > 255 {
			t.Errorf("cap %d does not fit the one-byte Count IPvX Addr field "+
				"(RFC 5798 §5.2.4)", c)
		}
	}
}
