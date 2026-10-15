package dhcp

// #13559: a DHCPv6 explicit-invalidation teardown (errV6AddrInvalidated on
// RENEW or REBIND) must mirror abandonLeaseAfterExpiry: it removes the lease
// and delegated PDs (already done), clears the run-loop committed/committedPDs
// state, fires onGatewayChange, and schedules a recompile so compiled routes
// and RA state are withdrawn. The pre-fix handlers deleted the lease/PD maps
// but never fired either hook, leaving compiled routes / the gateway overlay
// advertising a server-withdrawn address indefinitely.
//
// FAIL-ON-REVERT: deleting the fireGatewayChange/scheduleRecompile calls (and
// the committed-state clears that feed them) from the invalidation branches
// makes these tests RED on the gateway/recompile assertions while the lease
// deletion assertions still pass.

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// runInvalidationScenario drives runDHCPv6 through acquire (installing a
// lease + delegated PD) and then an explicit invalidation on either the T1
// RENEW (rebind=false) or the T2 REBIND (rebind=true). In the rebind case a
// generic transient error on RENEW makes the loop fall through to T2, where
// the REBIND reply invalidates the address. After the invalidation the next
// acquire attempt cancels the context so the loop exits — but first it probes
// the manager state exactly as the re-acquire would see it: no held lease, no
// delegated PDs, a fired gateway-change hook, and an armed recompile timer.
func runInvalidationScenario(t *testing.T, rebind bool) {
	t.Helper()

	leaseX := &Lease{
		Interface: "wan0",
		Family:    AFInet6,
		Address:   netip.MustParsePrefix("2001:db8::1/128"),
		LeaseTime: 100 * time.Second,
		Obtained:  time.Now(),
	}
	pd := DelegatedPrefix{
		Interface:     "wan0",
		Prefix:        netip.MustParsePrefix("2001:db8:1000::/48"),
		ValidLifetime: 100 * time.Second,
		Obtained:      leaseX.Obtained,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var gatewayChanges int
	m := &Manager{
		leases:               map[clientKey]*Lease{},
		delegatedPDs:         map[string][]DelegatedPrefix{},
		v6opts:               map[string]*DHCPv6Options{"wan0": {IATypes: []string{"ia-na", "ia-pd"}}},
		afterForTest:         immediateAfter,
		waitLinkLocalForTest: func(context.Context, string, time.Duration) error { return nil },
		onGatewayChange:      func() { gatewayChanges++ },
	}

	var leaseAtReacquire *Lease
	var pdsAtReacquire []DelegatedPrefix
	var gatewayChangesAfterAcquire, gatewayChangesAtReacquire int
	var recompileAtReacquire bool

	// invalidateOn: 2 for RENEW, 3 for REBIND (after a transient RENEW error).
	invalidateOn := 2
	if rebind {
		invalidateOn = 3
	}

	var n int
	m.doV6ExchangeForTest = func(_ context.Context, _ string, _ dhcpExchangeMode, _ *Lease, _ []DelegatedPrefix) (*dhcpv6Result, error) {
		n++
		switch n {
		case 1: // acquire → install X + PD
			return &dhcpv6Result{lease: leaseX, prefixes: []DelegatedPrefix{pd}}, nil
		case invalidateOn: // T1 renew (or T2 rebind) → explicit invalidation
			// Snapshot the baseline after the acquire-commit notifications so
			// the invalidation teardown's own callbacks are isolated.
			gatewayChangesAfterAcquire = gatewayChanges
			disarmRecompile(m)
			return nil, fmt.Errorf("exchange: %w", errV6AddrInvalidated)
		default:
			if rebind && n == 2 {
				// Transient RENEW failure → keep + wait for T2.
				return nil, fmt.Errorf("no usable IA_NA address or live IA_PD prefix in DHCPv6 reply on wan0")
			}
			// Re-acquire reached: probe state as the fresh solicit sees it,
			// then cancel so the loop exits.
			leaseAtReacquire = m.LeaseFor("wan0", AFInet6)
			pdsAtReacquire = m.DelegatedPrefixes()
			gatewayChangesAtReacquire = gatewayChanges
			recompileAtReacquire = recompileArmed(m)
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
		t.Fatal("runDHCPv6 did not terminate")
	}
	defer disarmRecompile(m)

	if leaseAtReacquire != nil {
		t.Errorf("lease at re-acquire = %v, want nil after explicit invalidation", leaseAtReacquire)
	}
	if len(pdsAtReacquire) != 0 {
		t.Errorf("delegated PDs at re-acquire = %+v, want none after explicit invalidation", pdsAtReacquire)
	}
	if got := m.LeaseFor("wan0", AFInet6); got != nil {
		t.Errorf("lease after invalidation = %v, want removed", got)
	}
	if got := m.DelegatedPrefixes(); len(got) != 0 {
		t.Errorf("delegated PDs after invalidation = %+v, want none", got)
	}
	if gatewayChangesAtReacquire <= gatewayChangesAfterAcquire {
		t.Errorf("gateway-change hook after invalidation = %d (baseline after acquire %d): the invalidation teardown must fire onGatewayChange so the gateway overlay withdraws the invalidated lease",
			gatewayChangesAtReacquire, gatewayChangesAfterAcquire)
	}
	if !recompileAtReacquire {
		t.Error("recompile not armed at re-acquire: the invalidation teardown must scheduleRecompile so compiled routes / RA state for the invalidated lease are withdrawn")
	}
}

func TestRunDHCPv6InvalidationOnRenewMirrorsExpiryTeardown_13559(t *testing.T) {
	runInvalidationScenario(t, false)
}

func TestRunDHCPv6InvalidationOnRebindMirrorsExpiryTeardown_13559(t *testing.T) {
	runInvalidationScenario(t, true)
}
