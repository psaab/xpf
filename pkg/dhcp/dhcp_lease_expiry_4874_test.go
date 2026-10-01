package dhcp

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

// Tests for #4874:
//   - A2: terminal-cleanup paths (finishClient max-attempts exit,
//     abandonLeaseAfterNAK) must schedule a recompile so the FRR default
//     route + v6 RA prefix withdraw in lock-step with the address, not
//     just the ip-monitoring overlay.
//   - A1: a renew/rebind TIMEOUT still RETAINS the lease+address (the
//     deliberate #1844 design) — a guard against accidental clock-expiry.
//   - B: a valid-lifetime-0 IA_PD is an RFC 8415 withdrawal — dropped from
//     the stored/advertised set, never re-granted at the RA 30-day default.

// ---- A2: terminal cleanup schedules a recompile ---------------------------

// TestFinishClientSchedulesRecompile: a terminal client exit that removes
// a committed lease record must arm the debounced recompile so applyConfig
// re-renders the FRR default route + v6 RA prefix from the now-absent
// lease. RED on revert: without the scheduleRecompile in finishClient the
// timer stays nil and the withdrawn gateway is advertised indefinitely.
func TestFinishClientSchedulesRecompile(t *testing.T) {
	m := NewManagerForTesting(nil)
	key := clientKey{iface: "ge-0-0-3", family: AFInet}
	dc := &dhcpClient{cancel: func() {}, done: make(chan struct{})}
	// Register the client so finishClient's successor guard passes.
	m.mu.Lock()
	m.clients[key] = dc
	m.mu.Unlock()
	m.SeedLeaseForTesting("ge-0-0-3", AFInet, v4Lease("10.0.0.5/24"))
	disarmRecompile(m)

	m.finishClient(key, dc)

	if m.LeaseFor("ge-0-0-3", AFInet) != nil {
		t.Fatal("lease record not removed on terminal exit")
	}
	if !recompileArmed(m) {
		t.Fatal("terminal exit with a committed lease must arm recompile (FRR route/RA re-render)")
	}
	disarmRecompile(m)
}

// TestFinishClientNoLeaseNoRecompile: a terminal exit with no committed
// lease (the pure-failure shape — client never acquired) has nothing to
// withdraw and must not arm a recompile. Also covers the successor-guard
// early return (already exercised for the gateway hook), which changed no
// state and must likewise stay silent.
func TestFinishClientNoLeaseNoRecompile(t *testing.T) {
	t.Run("no lease ever committed", func(t *testing.T) {
		m := NewManagerForTesting(nil)
		key := clientKey{iface: "ge-0-0-3", family: AFInet}
		dc := &dhcpClient{cancel: func() {}, done: make(chan struct{})}
		m.mu.Lock()
		m.clients[key] = dc
		m.mu.Unlock()
		disarmRecompile(m)

		m.finishClient(key, dc)

		if recompileArmed(m) {
			t.Fatal("terminal exit with no lease must not arm recompile")
		}
	})

	t.Run("successor-guard early return", func(t *testing.T) {
		m := NewManagerForTesting(nil)
		// dc is NOT registered → successor guard early-returns.
		m.finishClient(clientKey{iface: "ge-0-0-3", family: AFInet}, &dhcpClient{})
		if recompileArmed(m) {
			t.Fatal("successor-guard early return must not arm recompile")
		}
	})
}

// TestAbandonLeaseAfterNAKSchedulesRecompile: a DHCPNAK abandon must
// withdraw the FRR default route too, not just the kernel address — arm
// the recompile so applyConfig re-renders. This is what makes the README
// "a NAK deconfigures the interface immediately" promise (#3956) cover the
// route. RED on revert.
func TestAbandonLeaseAfterNAKSchedulesRecompile(t *testing.T) {
	m := NewManagerForTesting(nil)
	key := clientKey{iface: "ge-0-0-3", family: AFInet}
	committed := v4Lease("10.0.0.5/24")
	m.SeedLeaseForTesting("ge-0-0-3", AFInet, committed)
	disarmRecompile(m)

	m.abandonLeaseAfterNAK(key, committed)

	if m.LeaseFor("ge-0-0-3", AFInet) != nil {
		t.Fatal("lease record not dropped after NAK")
	}
	if !recompileArmed(m) {
		t.Fatal("NAK abandon must arm recompile (withdraw FRR default route in lock-step)")
	}
	disarmRecompile(m)
}

// ---- A1: timeout retention is KEPT ---------------------------------------

// TestRunDHCPv4TimeoutRetainsLeaseA1 guards the deliberate #1844
// last-known-gateway retention: a renew (T1) and rebind (T2) TIMEOUT — not
// a NAK — must NOT deconfigure; the lease + address stay installed while
// the outer loop re-acquires. This is the chosen RFC 2131 §4.4.5
// divergence for WAN availability (#4874 A1). RED if a future change adds
// clock-expiry to the timeout path and deletes the lease before re-acquire.
func TestRunDHCPv4TimeoutRetainsLeaseA1(t *testing.T) {
	leaseA := &Lease{
		Interface: "wan0",
		Family:    AFInet,
		Address:   netip.MustParsePrefix("192.0.2.50/24"),
		Gateway:   netip.MustParseAddr("192.0.2.1"),
		serverID:  netip.MustParseAddr("192.0.2.1"),
		LeaseTime: 100 * time.Second,
		Obtained:  time.Now(),
	}

	var leaseAtReacquire *Lease
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := &Manager{
		leases:       map[clientKey]*Lease{},
		delegatedPDs: map[string][]DelegatedPrefix{},
		v4opts:       map[string]*DHCPv4Options{"wan0": {}},
		afterForTest: immediateAfter,
	}
	var n int
	m.doV4ExchangeForTest = func(_ context.Context, _ string, _ dhcpExchangeMode, _ *Lease) (*Lease, error) {
		n++
		switch n {
		case 1: // initial acquire
			return leaseA, nil
		case 2: // T1 renew — TIMEOUT (falls through to T2)
			return nil, context.DeadlineExceeded
		case 3: // T2 rebind — TIMEOUT (falls back to full re-acquire)
			return nil, context.DeadlineExceeded
		default: // re-acquire: the retained lease must still be installed
			leaseAtReacquire = m.LeaseFor("wan0", AFInet)
			cancel()
			return nil, context.Canceled
		}
	}

	done := make(chan struct{})
	go func() { m.runDHCPv4(ctx, "wan0"); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runDHCPv4 did not terminate")
	}

	if leaseAtReacquire == nil || leaseAtReacquire.Address != leaseA.Address {
		t.Fatalf("lease at re-acquire = %v, want RETAINED %s (timeout must not deconfigure — #1844)",
			leaseAtReacquire, leaseA.Address)
	}
}

// ---- Expiry after failed re-acquisition -----------------------------------

func TestRunDHCPv4ExpiryAfterFailedReacquire(t *testing.T) {
	leaseA := &Lease{
		Interface: "wan0",
		Family:    AFInet,
		Address:   netip.MustParsePrefix("192.0.2.50/24"),
		Gateway:   netip.MustParseAddr("192.0.2.1"),
		LeaseTime: 2 * time.Second,
		Obtained:  time.Now().Add(-1500 * time.Millisecond),
	}

	var removed []*Lease
	gatewayChanges := 0
	var leaseAtReacquire *Lease
	var leaseDuringRetry *Lease
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &Manager{
		leases:               map[clientKey]*Lease{},
		delegatedPDs:         map[string][]DelegatedPrefix{},
		v4opts:               map[string]*DHCPv4Options{"wan0": {}},
		afterForTest:         immediateAfter,
		removeAddressForTest: func(_ string, lease *Lease) { removed = append(removed, lease) },
		onGatewayChange:      func() { gatewayChanges++ },
	}
	var n int
	m.doV4ExchangeForTest = func(_ context.Context, _ string, _ dhcpExchangeMode, _ *Lease) (*Lease, error) {
		n++
		switch n {
		case 1:
			return leaseA, nil
		case 2:
			disarmRecompile(m)
			return nil, context.DeadlineExceeded
		case 3:
			return nil, context.DeadlineExceeded
		case 4:
			leaseDuringRetry = m.LeaseFor("wan0", AFInet)
			return nil, context.DeadlineExceeded
		default:
			leaseAtReacquire = m.LeaseFor("wan0", AFInet)
			cancel()
			return nil, context.Canceled
		}
	}

	done := make(chan struct{})
	go func() { m.runDHCPv4(ctx, "wan0"); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runDHCPv4 did not terminate")
	}
	defer disarmRecompile(m)

	if leaseDuringRetry == nil {
		t.Fatal("lease must remain installed during re-acquisition before expiry")
	}
	if leaseAtReacquire != nil {
		t.Fatalf("lease at re-acquire = %v, want nil after Obtained+LeaseTime", leaseAtReacquire)
	}
	if got := m.LeaseFor("wan0", AFInet); got != nil {
		t.Fatalf("expired lease = %v, want removed", got)
	}
	if len(removed) != 1 || removed[0] != leaseA {
		t.Fatalf("removed addresses = %v, want %p exactly once", removed, leaseA)
	}
	if gatewayChanges < 2 {
		t.Fatalf("gateway-change hook calls = %d, want commit + expiry", gatewayChanges)
	}
	if !recompileArmed(m) {
		t.Fatal("lease expiry must arm a recompile to withdraw DHCP routes")
	}
}

func TestRunDHCPv6ExpiryAfterFailedReacquire(t *testing.T) {
	leaseA := &Lease{
		Interface: "wan0",
		Family:    AFInet6,
		Address:   netip.MustParsePrefix("2001:db8::50/128"),
		LeaseTime: 2 * time.Second,
		Obtained:  time.Now().Add(-1500 * time.Millisecond),
	}
	pd := DelegatedPrefix{
		Interface:     "wan0",
		Prefix:        netip.MustParsePrefix("2001:db8:1000::/48"),
		ValidLifetime: 2 * time.Second,
		Obtained:      leaseA.Obtained,
	}

	var removed []*Lease
	gatewayChanges := 0
	var leaseAtReacquire *Lease
	var leaseDuringRetry *Lease
	var pdsDuringRetry []DelegatedPrefix
	var pdsAtReacquire []DelegatedPrefix
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &Manager{
		leases:       map[clientKey]*Lease{},
		delegatedPDs: map[string][]DelegatedPrefix{},
		v6opts: map[string]*DHCPv6Options{"wan0": {
			IATypes: []string{"ia-na", "ia-pd"},
			RAIface: "lan0",
		}},
		afterForTest:         immediateAfter,
		waitLinkLocalForTest: func(context.Context, string, time.Duration) error { return nil },
		removeAddressForTest: func(_ string, lease *Lease) { removed = append(removed, lease) },
		onGatewayChange:      func() { gatewayChanges++ },
	}
	var n int
	m.doV6ExchangeForTest = func(_ context.Context, _ string, _ dhcpExchangeMode, _ *Lease, _ []DelegatedPrefix) (*dhcpv6Result, error) {
		n++
		switch n {
		case 1:
			return &dhcpv6Result{lease: leaseA, prefixes: []DelegatedPrefix{pd}}, nil
		case 2:
			disarmRecompile(m)
			return nil, context.DeadlineExceeded
		case 3:
			return nil, context.DeadlineExceeded
		case 4:
			leaseDuringRetry = m.LeaseFor("wan0", AFInet6)
			pdsDuringRetry = m.DelegatedPrefixes()
			return nil, context.DeadlineExceeded
		default:
			leaseAtReacquire = m.LeaseFor("wan0", AFInet6)
			pdsAtReacquire = m.DelegatedPrefixes()
			cancel()
			return nil, context.Canceled
		}
	}

	done := make(chan struct{})
	go func() { m.runDHCPv6(ctx, "wan0"); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runDHCPv6 did not terminate")
	}
	defer disarmRecompile(m)

	if leaseDuringRetry == nil || len(pdsDuringRetry) != 1 {
		t.Fatalf("lease/PD state during re-acquisition = %v/%+v, want retained before expiry",
			leaseDuringRetry, pdsDuringRetry)
	}
	if leaseAtReacquire != nil {
		t.Fatalf("lease at re-acquire = %v, want nil after Obtained+LeaseTime", leaseAtReacquire)
	}
	if got := m.LeaseFor("wan0", AFInet6); got != nil {
		t.Fatalf("expired DHCPv6 lease = %v, want removed", got)
	}
	if len(pdsAtReacquire) != 0 || len(m.DelegatedPrefixes()) != 0 {
		t.Fatalf("delegated PDs at re-acquire=%+v after expiry=%+v, want both empty",
			pdsAtReacquire, m.DelegatedPrefixes())
	}
	if len(removed) != 1 || removed[0] != leaseA {
		t.Fatalf("removed addresses = %v, want %p exactly once", removed, leaseA)
	}
	if gatewayChanges < 2 {
		t.Fatalf("gateway-change hook calls = %d, want commit + expiry", gatewayChanges)
	}
	if !recompileArmed(m) {
		t.Fatal("lease expiry must arm a recompile to withdraw DHCP routes and PDs")
	}
}

// TestRunDHCPv6StatelessRefreshFailureRetainsOptions guards the distinct
// stateless contract: LeaseTime is the Information-Request refresh interval,
// not an address/PD binding lifetime. A failed refresh across that interval
// must not drop the DNS options from Leases().
func TestRunDHCPv6StatelessRefreshFailureRetainsOptions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &Manager{
		leases:       map[clientKey]*Lease{},
		delegatedPDs: map[string][]DelegatedPrefix{},
		v6opts:       map[string]*DHCPv6Options{"wan0": {Stateless: true}},
		afterForTest: immediateAfter,
		waitLinkLocalForTest: func(context.Context, string, time.Duration) error {
			return nil
		},
	}
	dns := netip.MustParseAddr("2001:db8::53")
	var modes []dhcpExchangeMode
	var leaseAtNextRefresh *Lease
	m.doV6ExchangeForTest = func(_ context.Context, _ string, mode dhcpExchangeMode, _ *Lease, _ []DelegatedPrefix) (*dhcpv6Result, error) {
		modes = append(modes, mode)
		switch len(modes) {
		case 1:
			return &dhcpv6Result{lease: &Lease{
				Interface: "wan0",
				Family:    AFInet6,
				DNS:       []netip.Addr{dns},
				LeaseTime: time.Second,
				Obtained:  time.Now(),
			}}, nil
		case 2, 3, 4:
			return nil, context.DeadlineExceeded
		default:
			leaseAtNextRefresh = m.LeaseFor("wan0", AFInet6)
			cancel()
			return nil, context.Canceled
		}
	}

	done := make(chan struct{})
	go func() { m.runDHCPv6(ctx, "wan0"); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("runDHCPv6 did not retry the failed stateless refresh")
	}
	defer disarmRecompile(m)

	want := []dhcpExchangeMode{
		exchangeAcquire, exchangeRenew, exchangeRebind, exchangeAcquire, exchangeAcquire,
	}
	if len(modes) != len(want) {
		t.Fatalf("exchange modes = %v, want %v", modes, want)
	}
	for i := range want {
		if modes[i] != want[i] {
			t.Errorf("exchange %d = %s, want %s", i, modes[i], want[i])
		}
	}
	if leaseAtNextRefresh == nil || len(leaseAtNextRefresh.DNS) != 1 || leaseAtNextRefresh.DNS[0] != dns {
		t.Fatalf("stateless options at next refresh = %+v, want retained DNS %s", leaseAtNextRefresh, dns)
	}
}

func TestRunDHCPv4RebindBoundByLeaseExpiry(t *testing.T) {
	leaseA := &Lease{
		Interface: "wan0",
		Family:    AFInet,
		Address:   netip.MustParsePrefix("192.0.2.50/24"),
		LeaseTime: 2 * time.Second,
		Obtained:  time.Now().Add(-1500 * time.Millisecond),
	}

	var removed []*Lease
	gatewayChanges := 0
	var leaseAtReacquire *Lease
	var blockedMode dhcpExchangeMode
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &Manager{
		leases:               map[clientKey]*Lease{},
		delegatedPDs:         map[string][]DelegatedPrefix{},
		v4opts:               map[string]*DHCPv4Options{"wan0": {}},
		afterForTest:         immediateAfter,
		removeAddressForTest: func(_ string, lease *Lease) { removed = append(removed, lease) },
		onGatewayChange:      func() { gatewayChanges++ },
	}
	var n int
	m.doV4ExchangeForTest = func(exchangeCtx context.Context, _ string, mode dhcpExchangeMode, _ *Lease) (*Lease, error) {
		n++
		switch n {
		case 1:
			return leaseA, nil
		case 2:
			disarmRecompile(m)
			return nil, context.DeadlineExceeded
		case 3:
			blockedMode = mode
			<-exchangeCtx.Done()
			return nil, exchangeCtx.Err()
		default:
			leaseAtReacquire = m.LeaseFor("wan0", AFInet)
			cancel()
			return nil, context.Canceled
		}
	}

	done := make(chan struct{})
	go func() { m.runDHCPv4(ctx, "wan0"); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("runDHCPv4 did not stop the blocked REBIND at lease expiry")
	}
	defer disarmRecompile(m)

	if blockedMode != exchangeRebind {
		t.Fatalf("blocked exchange mode = %s, want REBIND", blockedMode)
	}
	if leaseAtReacquire != nil {
		t.Fatalf("lease at re-acquire = %v, want nil after expiry during REBIND", leaseAtReacquire)
	}
	if len(removed) != 1 || removed[0] != leaseA {
		t.Fatalf("removed addresses = %v, want %p exactly once", removed, leaseA)
	}
	if gatewayChanges < 2 || !recompileArmed(m) {
		t.Fatalf("expiry notifications: gateway changes=%d, recompile armed=%t",
			gatewayChanges, recompileArmed(m))
	}
}

func TestRunDHCPv6RebindBoundByLeaseExpiry(t *testing.T) {
	cases := []struct {
		name               string
		address            netip.Prefix
		iaTypes            []string
		wantAddressRemoval bool
	}{
		{
			name:               "stateful_IA_NA_and_IA_PD",
			address:            netip.MustParsePrefix("2001:db8::50/128"),
			iaTypes:            []string{"ia-na", "ia-pd"},
			wantAddressRemoval: true,
		},
		{
			name:    "PD_only",
			iaTypes: []string{"ia-pd"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leaseA := &Lease{
				Interface: "wan0",
				Family:    AFInet6,
				Address:   tc.address,
				LeaseTime: 2 * time.Second,
				Obtained:  time.Now().Add(-1500 * time.Millisecond),
			}
			pd := DelegatedPrefix{
				Interface:     "wan0",
				Prefix:        netip.MustParsePrefix("2001:db8:1000::/48"),
				ValidLifetime: 2 * time.Second,
				Obtained:      leaseA.Obtained,
			}

			var removed []*Lease
			gatewayChanges := 0
			var leaseAtReacquire *Lease
			var pdsAtReacquire []DelegatedPrefix
			var blockedMode dhcpExchangeMode
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			m := &Manager{
				leases:               map[clientKey]*Lease{},
				delegatedPDs:         map[string][]DelegatedPrefix{},
				v6opts:               map[string]*DHCPv6Options{"wan0": {IATypes: tc.iaTypes, RAIface: "lan0"}},
				afterForTest:         immediateAfter,
				waitLinkLocalForTest: func(context.Context, string, time.Duration) error { return nil },
				removeAddressForTest: func(_ string, lease *Lease) { removed = append(removed, lease) },
				onGatewayChange:      func() { gatewayChanges++ },
			}
			var n int
			m.doV6ExchangeForTest = func(exchangeCtx context.Context, _ string, mode dhcpExchangeMode, _ *Lease, _ []DelegatedPrefix) (*dhcpv6Result, error) {
				n++
				switch n {
				case 1:
					return &dhcpv6Result{lease: leaseA, prefixes: []DelegatedPrefix{pd}}, nil
				case 2:
					disarmRecompile(m)
					return nil, context.DeadlineExceeded
				case 3:
					blockedMode = mode
					<-exchangeCtx.Done()
					return nil, exchangeCtx.Err()
				default:
					leaseAtReacquire = m.LeaseFor("wan0", AFInet6)
					pdsAtReacquire = m.DelegatedPrefixes()
					cancel()
					return nil, context.Canceled
				}
			}

			done := make(chan struct{})
			go func() { m.runDHCPv6(ctx, "wan0"); close(done) }()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				cancel()
				t.Fatal("runDHCPv6 did not stop the blocked REBIND at lease expiry")
			}
			defer disarmRecompile(m)

			if blockedMode != exchangeRebind {
				t.Fatalf("blocked exchange mode = %s, want REBIND", blockedMode)
			}
			if leaseAtReacquire != nil || len(pdsAtReacquire) != 0 {
				t.Fatalf("lease/PDs at re-acquire = %v/%+v, want both removed at expiry",
					leaseAtReacquire, pdsAtReacquire)
			}
			if tc.wantAddressRemoval {
				if len(removed) != 1 || removed[0] != leaseA {
					t.Fatalf("removed addresses = %v, want %p exactly once", removed, leaseA)
				}
			} else if len(removed) != 0 {
				t.Fatalf("address removals = %v, want none for a PD-only lease", removed)
			}
			if gatewayChanges < 2 || !recompileArmed(m) {
				t.Fatalf("expiry notifications: gateway changes=%d, recompile armed=%t",
					gatewayChanges, recompileArmed(m))
			}
		})
	}
}

// ---- B: zero-lifetime IA_PD is a withdrawal ------------------------------

func pdPrefixOpt(t *testing.T, cidr string, pref, valid time.Duration) *dhcpv6.OptIAPrefix {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("bad test CIDR %q: %v", cidr, err)
	}
	return &dhcpv6.OptIAPrefix{
		PreferredLifetime: pref,
		ValidLifetime:     valid,
		Prefix:            ipnet,
	}
}

// iaPDReply builds a DHCPv6 Reply carrying a single IA_PD with the given
// IAPREFIX options, in order.
func iaPDReply(t *testing.T, prefixes ...*dhcpv6.OptIAPrefix) *dhcpv6.Message {
	t.Helper()
	adv, err := dhcpv6.NewMessage()
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	adv.MessageType = dhcpv6.MessageTypeReply
	iapd := &dhcpv6.OptIAPD{IaId: [4]byte{0, 0, 0, 1}}
	for _, p := range prefixes {
		iapd.Options.Add(p)
	}
	adv.AddOption(iapd)
	return adv
}

// TestExtractDelegatedPrefixesPartition: a valid-lifetime-0 IA_PD is sorted
// into the withdrawn set, never the live set (mirroring the IA_NA skip).
func TestExtractDelegatedPrefixesPartition(t *testing.T) {
	now := time.Now()
	msg := iaPDReply(t,
		pdPrefixOpt(t, "2001:db8:1000::/48", 3600*time.Second, 7200*time.Second),
		pdPrefixOpt(t, "2001:db8:dead::/56", 0, 0), // withdrawn
	)
	live, withdrawn := extractDelegatedPrefixes(msg, "wan0", now)
	if len(live) != 1 || live[0].Prefix != netip.MustParsePrefix("2001:db8:1000::/48") {
		t.Fatalf("live = %+v, want the single /48", live)
	}
	if len(withdrawn) != 1 || withdrawn[0].Prefix != netip.MustParsePrefix("2001:db8:dead::/56") {
		t.Fatalf("withdrawn = %+v, want the single /56", withdrawn)
	}
}

// TestReconcileDelegatedPDs pins the per-prefix withdrawal semantics
// (plan §7): retain on silence, clear on all-withdrawn, mixed live/
// withdrawn, per-prefix partial withdrawal (never clear-all), and a normal
// renewal (live wins with fresh lifetimes).
func TestReconcileDelegatedPDs(t *testing.T) {
	pd := func(cidr string, valid time.Duration) DelegatedPrefix {
		return DelegatedPrefix{
			Interface:     "wan0",
			Prefix:        netip.MustParsePrefix(cidr),
			ValidLifetime: valid,
		}
	}
	p48 := pd("2001:db8:1000::/48", 7200*time.Second)
	p56 := pd("2001:db8:2000::/56", 3600*time.Second)

	tests := []struct {
		name      string
		prior     []DelegatedPrefix
		live      []DelegatedPrefix
		withdrawn []DelegatedPrefix
		wantSet   []netip.Prefix
		wantApply bool
	}{
		{"retain on silence (no IA_PD)", []DelegatedPrefix{p48}, nil, nil,
			[]netip.Prefix{p48.Prefix}, false},
		{"all-withdrawn clears", []DelegatedPrefix{p56}, nil, []DelegatedPrefix{p56},
			nil, true},
		{"acquire stores live", nil, []DelegatedPrefix{p48}, nil,
			[]netip.Prefix{p48.Prefix}, true},
		{"mixed live+withdrawn", []DelegatedPrefix{p56}, []DelegatedPrefix{p48}, []DelegatedPrefix{p56},
			[]netip.Prefix{p48.Prefix}, true},
		{"partial multi-PD (reply omits /48)", []DelegatedPrefix{p48, p56}, nil, []DelegatedPrefix{p56},
			[]netip.Prefix{p48.Prefix}, true},
		{"normal renewal (live echoes prior)", []DelegatedPrefix{p48}, []DelegatedPrefix{p48}, nil,
			[]netip.Prefix{p48.Prefix}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, apply := reconcileDelegatedPDs(tt.prior, tt.live, tt.withdrawn)
			if apply != tt.wantApply {
				t.Errorf("apply = %v, want %v", apply, tt.wantApply)
			}
			if len(got) != len(tt.wantSet) {
				t.Fatalf("result = %+v, want prefixes %v", got, tt.wantSet)
			}
			for i, want := range tt.wantSet {
				if got[i].Prefix != want {
					t.Errorf("result[%d].Prefix = %s, want %s", i, got[i].Prefix, want)
				}
			}
		})
	}
}

// TestParseV6ReplyWithdrawnPD: parseV6Reply routes a valid-lifetime-0 IA_PD
// into withdrawnPDs (not prefixes), and a PD-only reply whose ONLY prefix
// is withdrawn is an acquisition failure — the guard counts LIVE prefixes
// regardless of wantNA so a PD-only client (wantNA=false) cannot fall
// through to an empty 1h lease (#4874 B, Codex F6, nit i).
func TestParseV6ReplyWithdrawnPD(t *testing.T) {
	m := &Manager{} // nil nlHandle → no gateway discovery

	t.Run("live IA_NA + withdrawn IA_PD populates withdrawnPDs", func(t *testing.T) {
		opts := &DHCPv6Options{IATypes: []string{"ia-na", "ia-pd"}}
		adv := iaNAReply(t, &dhcpv6.OptIAAddress{
			IPv6Addr:          mustIP(t, "2001:db8::5"),
			PreferredLifetime: 100 * time.Second,
			ValidLifetime:     500 * time.Second,
		})
		adv.AddOption(&dhcpv6.OptIAPD{IaId: [4]byte{0, 0, 0, 1},
			Options: dhcpv6.PDOptions{Options: dhcpv6.Options{
				pdPrefixOpt(t, "2001:db8:1000::/48", 0, 0)}}})

		res, err := m.parseV6Reply(context.Background(), "wan0", adv, opts)
		if err != nil {
			t.Fatalf("parseV6Reply: %v", err)
		}
		if len(res.prefixes) != 0 {
			t.Errorf("live prefixes = %+v, want none (the PD was withdrawn)", res.prefixes)
		}
		if len(res.withdrawnPDs) != 1 {
			t.Fatalf("withdrawnPDs = %+v, want the single withdrawn /48", res.withdrawnPDs)
		}
		if !res.lease.Address.IsValid() {
			t.Error("IA_NA address should still commit despite the PD withdrawal")
		}
	})

	t.Run("PD-only, only-withdrawn PD => acquisition failure", func(t *testing.T) {
		opts := &DHCPv6Options{IATypes: []string{"ia-pd"}} // wantNA=false
		adv := iaPDReply(t, pdPrefixOpt(t, "2001:db8:1000::/48", 0, 0))
		if _, err := m.parseV6Reply(context.Background(), "wan0", adv, opts); err == nil {
			t.Fatal("PD-only reply whose only IA_PD is withdrawn must fail acquisition, not settle an empty lease")
		}
	})
}

// TestCommitLeaseAllWithdrawnClearsPD: commitLease with applyPDs=true and an
// empty (all-withdrawn) reconciled set must DELETE the stored delegation so
// DelegatedPrefixesForRA stops advertising it, and must fire the recompile
// (the withdrawal is a real change). RED on revert: the pre-#4874 commitLease
// only stored when len(prefixes)>0, so it never cleared.
func TestCommitLeaseAllWithdrawnClearsPD(t *testing.T) {
	m := NewManagerForTesting(nil)
	m.v6opts["ge-0-0-3"] = &DHCPv6Options{IATypes: []string{"ia-pd"}, RAIface: "lan0"}
	key := clientKey{iface: "ge-0-0-3", family: AFInet6}
	pds := []DelegatedPrefix{{
		Interface:     "ge-0-0-3",
		Prefix:        netip.MustParsePrefix("2001:db8:1000::/48"),
		ValidLifetime: 2 * time.Hour,
	}}
	lease := &Lease{Interface: "ge-0-0-3", Family: AFInet6, LeaseTime: time.Hour, Obtained: time.Now()}

	if err := m.commitLease(key, lease, nil, pds, nil, true); err != nil {
		t.Fatalf("initial commitLease: %v", err)
	}
	if len(m.DelegatedPrefixesForRA()) != 1 {
		t.Fatalf("PD not advertised after initial commit")
	}
	disarmRecompile(m)

	// All-withdrawn reconcile → empty set, applyPDs=true → clears the map.
	if err := m.commitLease(key, lease, lease, nil, pds, true); err != nil {
		t.Fatalf("withdrawal commitLease: %v", err)
	}
	if got := m.DelegatedPrefixesForRA(); len(got) != 0 {
		t.Fatalf("DelegatedPrefixesForRA after all-withdrawn = %+v, want empty", got)
	}
	if !recompileArmed(m) {
		t.Fatal("clearing a delegated prefix must arm recompile so RA reconverges")
	}
	disarmRecompile(m)
}

// TestRunDHCPv6WithdrawnPDClearsAndStopsEcho drives the real runDHCPv6 loop:
// a RENEW that withdraws the held IA_PD (valid-lifetime 0) must (a) clear
// the stored/advertised prefix and (b) update committedPDs so the NEXT
// RENEW does not echo the withdrawn prefix (nit ii) — otherwise the server
// could re-grant it via the RENEW IA_PD echo (renew.go).
func TestRunDHCPv6WithdrawnPDClearsAndStopsEcho(t *testing.T) {
	leaseA := &Lease{
		Interface: "wan0",
		Family:    AFInet6,
		LeaseTime: 100 * time.Second,
		Obtained:  time.Now(),
	} // PD-only, no address
	live := DelegatedPrefix{
		Interface:         "wan0",
		Prefix:            netip.MustParsePrefix("2001:db8:1000::/48"),
		PreferredLifetime: 50 * time.Second,
		ValidLifetime:     100 * time.Second,
	}
	withdrawn := DelegatedPrefix{
		Interface:     "wan0",
		Prefix:        netip.MustParsePrefix("2001:db8:1000::/48"),
		ValidLifetime: 0,
	}

	var prevPDsSeen [][]DelegatedPrefix
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := &Manager{
		leases:       map[clientKey]*Lease{},
		delegatedPDs: map[string][]DelegatedPrefix{},
		v6opts: map[string]*DHCPv6Options{"wan0": {
			IATypes: []string{"ia-pd"}, RAIface: "lan0"}},
		afterForTest:         immediateAfter,
		waitLinkLocalForTest: func(context.Context, string, time.Duration) error { return nil },
	}
	m.doV6ExchangeForTest = func(_ context.Context, _ string, _ dhcpExchangeMode, _ *Lease, prevPDs []DelegatedPrefix) (*dhcpv6Result, error) {
		prevPDsSeen = append(prevPDsSeen, prevPDs)
		switch len(prevPDsSeen) {
		case 1: // acquire → one live PD
			return &dhcpv6Result{lease: leaseA, prefixes: []DelegatedPrefix{live}}, nil
		case 2: // T1 renew → server withdraws the PD (valid-lifetime 0)
			return &dhcpv6Result{lease: leaseA, withdrawnPDs: []DelegatedPrefix{withdrawn}}, nil
		default: // next renew: prevPDs proves committedPDs was reconciled
			cancel()
			return nil, context.Canceled
		}
	}

	done := make(chan struct{})
	go func() { m.runDHCPv6(ctx, "wan0"); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runDHCPv6 did not terminate")
	}

	if got := m.DelegatedPrefixesForRA(); len(got) != 0 {
		t.Fatalf("DelegatedPrefixesForRA after withdrawal = %+v, want empty (RA must stop advertising)", got)
	}
	if got := m.DelegatedPrefixes(); len(got) != 0 {
		t.Fatalf("DelegatedPrefixes after withdrawal = %+v, want empty", got)
	}
	if len(prevPDsSeen) < 3 {
		t.Fatalf("expected >=3 exchanges, got %d", len(prevPDsSeen))
	}
	if len(prevPDsSeen[2]) != 0 {
		t.Errorf("post-withdrawal RENEW echoed %+v, want no PDs (committedPDs must reflect the reconciled set)",
			prevPDsSeen[2])
	}
}
