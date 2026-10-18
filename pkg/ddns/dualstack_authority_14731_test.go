package ddns

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #14731 (D20-04): dual-stack DDNS collapsed both families' co-ownership
// authority onto the v4 policy. Manager stored a single aggregate
// lastPolicy (pol4 when v4 enabled) and both wireRRSharedWithOther and
// rebuildWireRRClaimsLocked stamped currentAuthorityLocked() — that one
// scalar — on records of BOTH families. With distinct ddns4/ddns6 RFC2136
// servers (#2663), every AAAA claim therefore carried the v4 fingerprint.
//
// Consequences pinned below:
//   - false negative: a v6 lease expiry deletes a live Surface-A AAAA
//     published on the v6 server (the lease's owned claim carries the v4
//     fingerprint, so coOwns against the Surface-A v6 fingerprint fails);
//   - false positive / orphan: a Surface-A AAAA claim at the v4 authority
//     wrongly suppresses the v6 lease delete, orphaning the AAAA on the
//     v6 server (and symmetrically a Surface-A teardown defers to a lease
//     claim stamped with the wrong family's authority).
//
// Fix: resolve authority per record family from the last resolved
// per-family policies (Manager.lastPolicies, stored by ReconcileScoped)
// instead of the collapsed aggregate. No durable-store change: the stored
// BackendFingerprint is in the #5814 namespace (TSIG-name/transport) and
// never equals a Surface A authority, so it is not consulted here.

func cfg14731(server4, server6 string) *config.DHCPServerConfig {
	return &config.DHCPServerConfig{
		DynamicDNS: &config.DHCPDynamicDNSConfig{
			Enabled: true, Domain: "example.com", TTLSeconds: 300,
			Backend: "rfc2136", UpdateServer: server4,
		},
		DynamicDNSv6: &config.DHCPDynamicDNSConfig{
			Enabled: true, Domain: "example.com", TTLSeconds: 300,
			Backend: "rfc2136", UpdateServer: server6,
		},
	}
}

// TestDualStackWireClaimsCarryPerFamilyAuthority14731 is the decisive
// regression: dual-stack ReconcileScoped with distinct servers must publish
// a WireRRClaims snapshot whose A claim carries the v4 authority and whose
// AAAA claim carries the v6 authority, and wireRRSharedWithOther for the v6
// record must see a Surface-A AAAA claim on the v6 server as a co-owner.
//
// On the pre-fix code both claims carry pol4.authority and the v6 check
// returns false, so this fails RED.
func TestDualStackWireClaimsCarryPerFamilyAuthority14731(t *testing.T) {
	upd4 := newFakeUpdater()
	upd6 := newFakeUpdater()
	dir := t.TempDir()
	src := &fakeLeaseSource{
		v4: []Lease{{Family: 4, Address: "10.0.0.10", Identity: "mac:aa", HostName: "host-a", SubnetID: "1"}},
		v6: []Lease{{Family: 6, Address: "2001:db8::10", Identity: "duid:aa", HostName: "host-a", SubnetID: "1"}},
	}
	m := newManagerForTesting(
		src.parser(),
		nopUpdater{},
		filepath.Join(dir, "state.json"),
		filepath.Join(dir, "leases4.csv"),
		filepath.Join(dir, "leases6.csv"),
		"node0",
		func() time.Time { return time.Unix(1_700_000_000, 0) },
	)
	m.newUpdater = func(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
		if pol.backend != "rfc2136" || c == nil || c.UpdateServer == "" {
			return nopUpdater{}, nil
		}
		switch c.UpdateServer {
		case "ns4.example.net:53":
			return upd4, nil
		case "ns6.example.net:53":
			return upd6, nil
		}
		return nopUpdater{}, nil
	}

	// Surface A co-owns the AAAA record on the v6 server only.
	auth6 := leaseAuthorityFingerprint(cfg14731("ns4.example.net:53", "ns6.example.net:53").DynamicDNSv6)
	auth4 := leaseAuthorityFingerprint(cfg14731("ns4.example.net:53", "ns6.example.net:53").DynamicDNS)
	if auth4 == "" || auth6 == "" || auth4 == auth6 {
		t.Fatalf("fixture authorities must be distinct non-empty: v4=%q v6=%q", auth4, auth6)
	}
	m.surfaceACoowners = func() []WireRRClaim {
		return []WireRRClaim{wireRRClaim("host-a.example.com", "AAAA", "2001:db8::10", auth6)}
	}

	if err := m.Reconcile(context.Background(), cfg14731("ns4.example.net:53", "ns6.example.net:53")); err != nil {
		t.Fatalf("dual-stack reconcile: %v", err)
	}

	// Wire-claim snapshot must be per-family.
	claims := m.WireRRClaims()
	var aClaim, aaaaClaim *WireRRClaim
	for i := range claims {
		c := claims[i]
		switch c.ForwardType {
		case "A":
			cc := c
			aClaim = &cc
		case "AAAA":
			cc := c
			aaaaClaim = &cc
		}
	}
	if aClaim == nil || aaaaClaim == nil {
		t.Fatalf("expected one A and one AAAA claim, got %+v", claims)
	}
	if aClaim.Authority != auth4 {
		t.Errorf("A claim authority = %q, want v4 authority %q", aClaim.Authority, auth4)
	}
	if aaaaClaim.Authority != auth6 {
		t.Errorf("AAAA claim authority = %q, want v6 authority %q (pre-fix carries the collapsed v4 authority %q)", aaaaClaim.Authority, auth6, auth4)
	}

	// The v6 lease teardown guard must see the Surface-A AAAA co-owner.
	m.mu.Lock()
	var owned6 *ownedRecord
	for _, r := range m.state.records {
		if r.Family == 6 {
			rr := r
			owned6 = &rr
		}
	}
	if owned6 == nil {
		m.mu.Unlock()
		t.Fatalf("v6 record not owned after reconcile: %+v", m.state.records)
	}
	if !m.wireRRSharedWithOther(*owned6) {
		m.mu.Unlock()
		t.Fatalf("wireRRSharedWithOther(v6 AAAA) = false, want true: Surface-A AAAA on the v6 server co-owns it (pre-fix stamps the v4 authority, so coOwns fails)")
	}
	m.mu.Unlock()

	// End-to-end teardown: expiring the v6 lease must NOT delete the AAAA
	// that Surface A still owns on the v6 server, while the v4 lease expiry
	// still deletes its own A record (no Surface-A co-owner for A).
	src.v6 = nil
	upd6.deletes = nil
	upd4.deletes = nil
	// Keep v4 lease live so only v6 teardown is exercised here.
	if err := m.Reconcile(context.Background(), cfg14731("ns4.example.net:53", "ns6.example.net:53")); err != nil {
		t.Fatalf("v6-expiry reconcile: %v", err)
	}
	if names := upd6.deleteNames(); len(names) != 0 {
		t.Fatalf("v6 lease expiry deleted a live Surface-A AAAA on the v6 server: %v", names)
	}
	if got := m.deleteCoowned.Load(); got != 1 {
		t.Fatalf("expected exactly one co-owned suppression for the AAAA, got %d", got)
	}
	if n := len(upd4.deleteNames()); n != 0 {
		t.Fatalf("v4 record must not be deleted while its lease is live, got %v", upd4.deleteNames())
	}
}

// TestDualStackDistinctAuthorityNotSuppressed14731 is the false-positive
// control: the same (FQDN, AAAA, rdata) at a DIFFERENT authority must not
// suppress the lease teardown delete. Pre-fix, the lease's collapsed v4
// stamp could equal a Surface-A claim's v4 authority and suppress a needed
// v6 delete, orphaning the record on the v6 server.
func TestDualStackDistinctAuthorityNotSuppressed14731(t *testing.T) {
	upd4 := newFakeUpdater()
	upd6 := newFakeUpdater()
	dir := t.TempDir()
	src := &fakeLeaseSource{
		v6: []Lease{{Family: 6, Address: "2001:db8::10", Identity: "duid:aa", HostName: "host-a", SubnetID: "1"}},
	}
	m := newManagerForTesting(
		src.parser(),
		nopUpdater{},
		filepath.Join(dir, "state.json"),
		filepath.Join(dir, "leases4.csv"),
		filepath.Join(dir, "leases6.csv"),
		"node0",
		func() time.Time { return time.Unix(1_700_000_000, 0) },
	)
	m.newUpdater = func(pol ddnsPolicy, c *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
		if pol.backend != "rfc2136" || c == nil || c.UpdateServer == "" {
			return nopUpdater{}, nil
		}
		switch c.UpdateServer {
		case "ns4.example.net:53":
			return upd4, nil
		case "ns6.example.net:53":
			return upd6, nil
		}
		return nopUpdater{}, nil
	}
	auth4 := leaseAuthorityFingerprint(cfg14731("ns4.example.net:53", "ns6.example.net:53").DynamicDNS)
	// Surface A claim uses the V4 authority — a different DNS server from
	// the v6 lease's authority, so it is NOT the same wire resource.
	m.surfaceACoowners = func() []WireRRClaim {
		return []WireRRClaim{wireRRClaim("host-a.example.com", "AAAA", "2001:db8::10", auth4)}
	}
	cfg := cfg14731("ns4.example.net:53", "ns6.example.net:53")
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("publish reconcile: %v", err)
	}
	src.v6 = nil
	upd6.deletes = nil
	if err := m.Reconcile(context.Background(), cfg); err != nil {
		t.Fatalf("expiry reconcile: %v", err)
	}
	if names := upd6.deleteNames(); len(names) != 1 {
		t.Fatalf("distinct-authority AAAA must still be deleted on lease expiry (no orphan), got %v", names)
	}
	if got := m.deleteCoowned.Load(); got != 0 {
		t.Fatalf("distinct authority must not count as co-owned suppression, got %d", got)
	}
}

// TestLeaseAuthorityForRecordPerFamily14731 pins the per-family lookup:
// each record resolves to its OWN family's authority (never the collapsed
// v4 aggregate), and with no policies resolved yet the authority is unknown
// (""). The stored BackendFingerprint is deliberately NOT consulted: it is
// in the #5814 namespace and never equals a Surface A authority.
func TestLeaseAuthorityForRecordPerFamily14731(t *testing.T) {
	pol4 := policyFromConfig(&config.DHCPDynamicDNSConfig{
		Enabled: true, Backend: "rfc2136", UpdateServer: "ns4.example.net:53", Domain: "example.com",
	})
	pol6 := policyFromConfig(&config.DHCPDynamicDNSConfig{
		Enabled: true, Backend: "rfc2136", UpdateServer: "ns6.example.net:53", Domain: "example.com",
	})
	m := &Manager{}
	m.lastPolicies.Store(&[2]ddnsPolicy{pol4, pol6})

	if got := m.authorityForRecordLocked(ownedRecord{Family: 4}); got != pol4.authority {
		t.Errorf("v4 authority = %q, want %q", got, pol4.authority)
	}
	if got := m.authorityForRecordLocked(ownedRecord{Family: 6}); got != pol6.authority {
		t.Errorf("v6 authority = %q, want %q (pre-fix aggregate returned the v4 authority)", got, pol6.authority)
	}
	// No policies resolved yet => unknown ("").
	m2 := &Manager{}
	if got := m2.authorityForRecordLocked(ownedRecord{Family: 6}); got != "" {
		t.Errorf("no-policy authority = %q, want empty (unknown)", got)
	}
	if got := m2.authorityForRecordLocked(ownedRecord{Family: 4}); got != "" {
		t.Errorf("no-policy authority = %q, want empty (unknown)", got)
	}
}
