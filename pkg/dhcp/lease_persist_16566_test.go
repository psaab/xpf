package dhcp

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"net"
)

// #16566: after a simulated restart with a silent server, Leases()
// returns the unexpired persisted lease, the first wire exchange is
// RENEW/RENEWING (not DISCOVER/SOLICIT), and an expired or
// kernel-missing lease is never re-adopted.

func persistTestManager(t *testing.T, dir string) *Manager {
	t.Helper()
	m := NewManagerForTesting(nil)
	m.SetStateDirForTesting(dir)
	disarmRecompile(m)
	return m
}

func TestPersistedLeaseReadoptedAfterRestart16566(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	lease := &Lease{
		Interface: "wan0",
		Family:    AFInet,
		Address:   netip.MustParsePrefix("192.0.2.50/24"),
		Gateway:   netip.MustParseAddr("192.0.2.1"),
		DNS:       []netip.Addr{netip.MustParseAddr("192.0.2.53")},
		ClasslessRoutes: []LeaseRoute{
			{Destination: netip.MustParsePrefix("10.0.0.0/8"), Gateway: netip.MustParseAddr("192.0.2.1")},
		},
		LeaseTime: 2 * time.Hour,
		Obtained:  now.Add(-time.Minute),
		serverID:  netip.MustParseAddr("192.0.2.1"),
	}
	key := clientKey{iface: "wan0", family: AFInet}

	m1 := persistTestManager(t, dir)
	if err := m1.commitLease(key, lease, nil, nil, nil, false); err != nil {
		t.Fatalf("commitLease: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "dhcp-lease-wan0-v4")); err != nil {
		t.Fatalf("lease state not persisted: %v", err)
	}

	// Simulated restart: a fresh Manager over the same state dir has no
	// lease until adoption, then renders it (the daemon's FRR/DNS input).
	m2 := persistTestManager(t, dir)
	if got := m2.Leases(); len(got) != 0 {
		t.Fatalf("pre-adoption Leases() = %d, want 0 (RED pre-fix: always 0)", len(got))
	}
	m2.AdoptPersistedLeases([]ClientSpec{{Iface: "wan0", Family: AFInet}})
	got := m2.Leases()
	if len(got) != 1 {
		t.Fatalf("post-adoption Leases() = %d, want 1", len(got))
	}
	if got[0].Address != lease.Address || got[0].Gateway != lease.Gateway {
		t.Errorf("adopted lease = %v via %v, want %v via %v", got[0].Address, got[0].Gateway, lease.Address, lease.Gateway)
	}
	if len(got[0].ClasslessRoutes) != 1 || got[0].ClasslessRoutes[0].Destination != netip.MustParsePrefix("10.0.0.0/8") {
		t.Errorf("adopted classless routes = %+v, want the 10/8 route (FRR render input)", got[0].ClasslessRoutes)
	}
	if len(got[0].DNS) != 1 {
		t.Errorf("adopted DNS = %v, want 1 server", got[0].DNS)
	}
}

func TestPersistedLeaseNotAdoptedWhenExpiredOrKernelMissing16566(t *testing.T) {
	dir := t.TempDir()
	key := clientKey{iface: "wan0", family: AFInet}
	expired := &Lease{
		Interface: "wan0", Family: AFInet,
		Address:   netip.MustParsePrefix("192.0.2.50/24"),
		Gateway:   netip.MustParseAddr("192.0.2.1"),
		LeaseTime: time.Hour,
		Obtained:  time.Now().Add(-2 * time.Hour),
		serverID:  netip.MustParseAddr("192.0.2.1"),
	}
	m1 := persistTestManager(t, dir)
	// Persist directly (commitLease of an expired lease is not a real
	// path; write the file the way a live commit would have earlier).
	m1.persistLease(key, expired)
	m2 := persistTestManager(t, dir)
	m2.AdoptPersistedLeases([]ClientSpec{{Iface: "wan0", Family: AFInet}})
	if got := m2.Leases(); len(got) != 0 {
		t.Fatalf("expired lease adopted: %v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "dhcp-lease-wan0-v4")); !os.IsNotExist(err) {
		t.Errorf("expired lease state file not removed, stat err=%v", err)
	}

	// Unexpired but kernel address gone (kernel lifetime expired it).
	live := &Lease{
		Interface: "wan0", Family: AFInet,
		Address:   netip.MustParsePrefix("192.0.2.50/24"),
		LeaseTime: 2 * time.Hour,
		Obtained:  time.Now(),
		serverID:  netip.MustParseAddr("192.0.2.1"),
	}
	m1.persistLease(key, live)
	m3 := persistTestManager(t, dir)
	m3.SetKernelHasAddressForTesting(func(string, *Lease) bool { return false })
	m3.AdoptPersistedLeases([]ClientSpec{{Iface: "wan0", Family: AFInet}})
	if got := m3.Leases(); len(got) != 0 {
		t.Fatalf("kernel-missing lease adopted: %v", got)
	}
}

func TestRestartResumeFirstExchangeIsRenewV4_16566(t *testing.T) {
	dir := t.TempDir()
	lease := &Lease{
		Interface: "wan0", Family: AFInet,
		Address:   netip.MustParsePrefix("192.0.2.50/24"),
		Gateway:   netip.MustParseAddr("192.0.2.1"),
		LeaseTime: 100 * time.Second,
		Obtained:  time.Now(),
		serverID:  netip.MustParseAddr("192.0.2.1"),
	}
	m1 := persistTestManager(t, dir)
	if err := m1.commitLease(clientKey{iface: "wan0", family: AFInet}, lease, nil, nil, nil, false); err != nil {
		t.Fatal(err)
	}

	// Fresh manager, silent-then-renewing server: the FIRST exchange
	// must be RENEW, never DISCOVER. Pre-fix the first mode was acquire.
	m2 := persistTestManager(t, dir)
	m2.v4opts["wan0"] = &DHCPv4Options{}
	var modes []dhcpExchangeMode
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m2.afterForTest = immediateAfter
	m2.doV4ExchangeForTest = func(_ context.Context, _ string, mode dhcpExchangeMode, _ *Lease) (*Lease, error) {
		modes = append(modes, mode)
		if mode == exchangeRenew {
			renewed := *lease
			renewed.Obtained = time.Now()
			return &renewed, nil
		}
		return nil, errors.New("unexpected acquire on resume")
	}
	if !m2.Start(ctx, "wan0", AFInet) {
		t.Fatal("Start refused")
	}
	defer m2.StopAll()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(modes) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if len(modes) == 0 || modes[0] != exchangeRenew {
		t.Fatalf("first exchange after restart = %v, want [renew ...] (no DISCOVER)", modes)
	}
	if got := m2.Leases(); len(got) != 1 {
		t.Fatalf("Leases() after resumed renew = %d, want 1", len(got))
	}
}

func TestRestartResumeFirstExchangeIsRenewV6_16566(t *testing.T) {
	dir := t.TempDir()
	hw, _ := net.ParseMAC("02:00:00:0a:0b:0c")
	serverDUID := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: hw}
	lease := &Lease{
		Interface:    "wan0",
		Family:       AFInet6,
		Address:      netip.MustParsePrefix("2001:db8::5/128"),
		LeaseTime:    2 * time.Hour,
		Obtained:     time.Now().Add(-time.Minute),
		v6ServerDUID: serverDUID,
	}
	pds := []DelegatedPrefix{{
		Interface:         "wan0",
		Prefix:            netip.MustParsePrefix("2001:db8:1000::/48"),
		PreferredLifetime: time.Hour,
		ValidLifetime:     2 * time.Hour,
		Obtained:          time.Now().Add(-time.Minute),
	}}
	key := clientKey{iface: "wan0", family: AFInet6}
	m1 := persistTestManager(t, dir)
	if err := m1.commitLease(key, lease, nil, pds, nil, true); err != nil {
		t.Fatal(err)
	}

	m2 := persistTestManager(t, dir)
	m2.v6opts["wan0"] = &DHCPv6Options{IATypes: []string{"ia-na", "ia-pd"}}
	m2.AdoptPersistedLeases([]ClientSpec{{Iface: "wan0", Family: AFInet6}})
	if got := m2.DelegatedPrefixes(); len(got) != 1 {
		t.Fatalf("adopted PDs = %d, want 1 (PD-RA render input)", len(got))
	}
	var modes []dhcpExchangeMode
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m2.afterForTest = immediateAfter
	m2.waitLinkLocalForTest = func(context.Context, string, time.Duration) error { return nil }
	m2.doV6ExchangeForTest = func(_ context.Context, _ string, mode dhcpExchangeMode, _ *Lease, _ []DelegatedPrefix) (*dhcpv6Result, error) {
		modes = append(modes, mode)
		if mode == exchangeRenew {
			renewed := *lease
			renewed.Obtained = time.Now()
			return &dhcpv6Result{lease: &renewed, prefixes: pds}, nil
		}
		return nil, errors.New("unexpected solicit on resume")
	}
	if !m2.Start(ctx, "wan0", AFInet6) {
		t.Fatal("Start refused")
	}
	defer m2.StopAll()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(modes) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if len(modes) == 0 || modes[0] != exchangeRenew {
		t.Fatalf("first v6 exchange after restart = %v, want [renew ...] (no SOLICIT)", modes)
	}
}

func TestPersistedLeaseDeletedOnNAK16566(t *testing.T) {
	dir := t.TempDir()
	m := persistTestManager(t, dir)
	lease := &Lease{
		Interface: "wan0", Family: AFInet,
		Address:   netip.MustParsePrefix("192.0.2.50/24"),
		LeaseTime: time.Hour,
		Obtained:  time.Now(),
		serverID:  netip.MustParseAddr("192.0.2.1"),
	}
	key := clientKey{iface: "wan0", family: AFInet}
	if err := m.commitLease(key, lease, nil, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	m.abandonLeaseAfterNAK(key, lease)
	if _, err := os.Stat(filepath.Join(dir, "dhcp-lease-wan0-v4")); !os.IsNotExist(err) {
		t.Errorf("persisted lease survived NAK, stat err=%v (a later restart would resurrect a revoked lease)", err)
	}
}

// TestRestartLosesLeasePreFix16566 is the behavior-level RED cell: it
// uses only pre-existing seams (commitLease, Leases, Start, exchange
// seams), so it compiles and FAILS on the pre-fix tree — a fresh
// Manager over the same state dir renders no lease and its first
// exchange is DISCOVER. Post-fix it passes via re-adoption + RENEW.
// (Kept alongside the persistence-specific cells above, which do not
// compile pre-fix because they name the new API.)
func TestRestartLosesLeasePreFix16566(t *testing.T) {
	dir := t.TempDir()
	lease := &Lease{
		Interface: "wan0", Family: AFInet,
		Address:   netip.MustParsePrefix("192.0.2.50/24"),
		Gateway:   netip.MustParseAddr("192.0.2.1"),
		LeaseTime: 100 * time.Second,
		Obtained:  time.Now(),
		serverID:  netip.MustParseAddr("192.0.2.1"),
	}
	m1 := NewManagerForTesting(nil)
	m1.stateDir = dir
	if err := m1.commitLease(clientKey{iface: "wan0", family: AFInet}, lease, nil, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	defer disarmRecompile(m1)

	m2 := NewManagerForTesting(nil)
	m2.stateDir = dir
	m2.v4opts["wan0"] = &DHCPv4Options{}
	defer disarmRecompile(m2)
	var modes []dhcpExchangeMode
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m2.afterForTest = immediateAfter
	m2.doV4ExchangeForTest = func(_ context.Context, _ string, mode dhcpExchangeMode, _ *Lease) (*Lease, error) {
		modes = append(modes, mode)
		renewed := *lease
		renewed.Obtained = time.Now()
		return &renewed, nil
	}
	if !m2.Start(ctx, "wan0", AFInet) {
		t.Fatal("Start refused")
	}
	defer m2.StopAll()
	if got := m2.Leases(); len(got) != 1 {
		t.Fatalf("after simulated restart Leases() = %d, want 1 (startup FRR/DNS render is empty pre-fix)", len(got))
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(modes) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if len(modes) == 0 || modes[0] != exchangeRenew {
		t.Fatalf("first exchange after restart = %v, want renew (pre-fix: acquire/DISCOVER)", modes)
	}
}
