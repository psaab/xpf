// #5382: GetDHCPLeases must report IPv6 delegated prefixes (IA_PD) even for
// an interface that has ONLY prefix delegation and no IA_NA address lease.
// The pre-fix aggregation gated the standalone PD-only lease entry behind
// `len(resp.Leases) > 0`, so a PD-only interface (or any config with no IA_NA
// leases at all) silently dropped its delegated prefix from the response.
// These tests exercise the pure aggregation helper so no live dhcp.Manager or
// netlink handle is needed.
package grpcapi

import (
	"net/netip"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dhcp"
)

// TestBuildDHCPLeasesResponse_PDOnlyReported asserts a delegated prefix is
// surfaced when the interface has no IA_NA address lease. RED before the fix:
// with the `len(resp.Leases) > 0` guard and an empty lease set, no entry is
// appended and the delegated prefix is dropped.
func TestBuildDHCPLeasesResponse_PDOnlyReported(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:db8:abcd::/48")
	pds := []dhcp.DelegatedPrefix{{
		Interface:         "ge-0-0-3",
		Prefix:            prefix,
		PreferredLifetime: 30 * time.Minute,
		ValidLifetime:     time.Hour,
		Obtained:          time.Unix(1_700_000_000, 0).UTC(),
	}}

	// No IA_NA leases: a legitimate PD-only client.
	resp := BuildDHCPLeasesResponse(nil, pds)

	if len(resp.Leases) != 1 {
		t.Fatalf("PD-only interface: expected 1 standalone lease entry, got %d (delegated prefix dropped)", len(resp.Leases))
	}
	got := resp.Leases[0]
	if got.Interface != "ge-0-0-3" {
		t.Errorf("standalone PD entry interface = %q, want ge-0-0-3", got.Interface)
	}
	if got.Family != "inet6" {
		t.Errorf("standalone PD entry family = %q, want inet6", got.Family)
	}
	if len(got.DelegatedPrefixes) != 1 {
		t.Fatalf("standalone PD entry: expected 1 delegated prefix, got %d", len(got.DelegatedPrefixes))
	}
	if got.DelegatedPrefixes[0].Prefix != prefix.String() {
		t.Errorf("delegated prefix = %q, want %q", got.DelegatedPrefixes[0].Prefix, prefix.String())
	}
}

// TestBuildDHCPLeasesResponse_PDAttachesToInetLease confirms the normal path
// is unchanged: when a matching inet6 IA_NA lease exists, the delegated prefix
// attaches to it rather than creating a standalone entry.
func TestBuildDHCPLeasesResponse_PDAttachesToInetLease(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:db8:abcd::/48")
	leases := []*dhcp.Lease{{
		Interface: "ge-0-0-3",
		Family:    dhcp.AFInet6,
		Address:   netip.MustParsePrefix("2001:db8:1::10/64"),
		LeaseTime: time.Hour,
		Obtained:  time.Unix(1_700_000_000, 0).UTC(),
	}}
	pds := []dhcp.DelegatedPrefix{{
		Interface: "ge-0-0-3",
		Prefix:    prefix,
	}}

	resp := BuildDHCPLeasesResponse(leases, pds)

	if len(resp.Leases) != 1 {
		t.Fatalf("expected 1 lease entry (PD attached to IA_NA lease), got %d", len(resp.Leases))
	}
	if len(resp.Leases[0].DelegatedPrefixes) != 1 {
		t.Fatalf("expected delegated prefix attached to the inet6 lease, got %d", len(resp.Leases[0].DelegatedPrefixes))
	}
	if resp.Leases[0].DelegatedPrefixes[0].Prefix != prefix.String() {
		t.Errorf("attached prefix = %q, want %q", resp.Leases[0].DelegatedPrefixes[0].Prefix, prefix.String())
	}
}

// TestBuildDHCPLeasesResponse_MultiPDOnlyGrouped confirms that a second
// delegated prefix on the same PD-only interface groups into the standalone
// entry created for the first, rather than producing a duplicate entry.
func TestBuildDHCPLeasesResponse_MultiPDOnlyGrouped(t *testing.T) {
	p1 := netip.MustParsePrefix("2001:db8:1::/48")
	p2 := netip.MustParsePrefix("2001:db8:2::/48")
	pds := []dhcp.DelegatedPrefix{
		{Interface: "ge-0-0-3", Prefix: p1},
		{Interface: "ge-0-0-3", Prefix: p2},
	}

	resp := BuildDHCPLeasesResponse(nil, pds)

	if len(resp.Leases) != 1 {
		t.Fatalf("expected 1 grouped standalone entry for the PD-only interface, got %d", len(resp.Leases))
	}
	if len(resp.Leases[0].DelegatedPrefixes) != 2 {
		t.Fatalf("expected both delegated prefixes grouped, got %d", len(resp.Leases[0].DelegatedPrefixes))
	}
}
