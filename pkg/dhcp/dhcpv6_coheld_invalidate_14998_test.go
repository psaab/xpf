package dhcp

// #14998 (D40-04): Co-held IA_NA + IA_PD renewal. Two defects in one mechanism:
//
// Leg 1 (orphaned WAN address): a RENEW/REBIND Reply carrying explicit
// valid-lifetime-0 IA_NA (all IAADDRs 0) TOGETHER WITH a live IA_PD prefix
// bypasses the errV6AddrInvalidated sentinel — parseV6ReplyChecked returns a
// success lease whose Address is invalid and whose LeaseTime is the PD
// lifetime (or the 3600s floor). commitLease then stores that address-less
// lease WITHOUT removing the previously installed kernel WAN address
// (its remove-old only fires when the new lease HAS an address), and the
// renewalTimers are recomputed from the bogus lease. The WAN kernel address
// is orphaned while the lease record still (implicitly) holds it.
//
// Leg 2 (timer reset): a legitimately co-held lease sitting in the T1 wait
// wakes at the earliest PD expiry (waitOutcomePDExpired, #14598), prunes the
// PD, and the caller loops `continue t1WaitLoop` — which re-derives
// t1Wait = m.after(t1) with the FULL t1 from the top of the renewal loop.
// A T1 of 1800s with a PD expiring at T+100 therefore delays renewal by a
// further full 1800s (effectively 1900s), and periodic PD expiry can push
// T1 arbitrarily past the true T1 (and past expiry concerns in Path A).
// Same for the T2 wait. Path B past-expiry safety is bounded by the lease
// deadline (leaseCtx) — excluded from scope, do not reintroduce.
//
// FAIL-ON-REVERT:
//   - Leg 1: restoring parseV6ReplyChecked's old guard (sentinel only when
//     no live PD) makes TestParseV6ReplyCoHeldInvalidation14998 go RED
//     (err == nil, address-less lease returned); restoring commitLease's
//     skip on invalid new address makes TestCommitLeaseInvalidatedRemoves
//     Address14998 go RED (no removeAddress call).
//   - Leg 2: reverting the T1/T2 wait to a fresh full m.after(t1/t2Remaining)
//     after a PD-prune makes the T1/T2 expiry test time out >3s (renew never
//     fires within the remaining allowance) or fire at ~full delay.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

// ---------------------------------------------------------------------------
// Parse layer: co-held IA_NA invalidated + live IA_PD must still be the
// explicit-invalidation sentinel, not a success lease.
// ---------------------------------------------------------------------------

func coHeldReply(t *testing.T) *dhcpv6.Message {
	t.Helper()
	msg, err := dhcpv6.NewMessage()
	if err != nil {
		t.Fatal(err)
	}
	msg.MessageType = dhcpv6.MessageTypeReply
	ianaOpt := &dhcpv6.OptIANA{IaId: [4]byte{0, 0, 0, 1}}
	ianaOpt.Options.Add(&dhcpv6.OptIAAddress{
		IPv6Addr:          net.ParseIP("2606:4700::1"),
		PreferredLifetime: 100 * time.Second,
		ValidLifetime:     0, // explicit invalidation
	})
	msg.AddOption(ianaOpt)
	iapd := &dhcpv6.OptIAPD{IaId: [4]byte{0, 0, 0, 2}}
	iapd.Options.Add(&dhcpv6.OptIAPrefix{
		PreferredLifetime: 3600 * time.Second,
		ValidLifetime:     3600 * time.Second,
		Prefix: &net.IPNet{
			IP:   net.ParseIP("2606:4700:1000::"),
			Mask: net.CIDRMask(48, 128),
		},
	})
	iapd.Options.Add(&dhcpv6.OptStatusCode{
		StatusCode:    iana.StatusSuccess,
		StatusMessage: "ok",
	})
	msg.AddOption(iapd)
	return msg
}

func TestParseV6ReplyCoHeldInvalidation14998(t *testing.T) {
	m := &Manager{
		leases:       map[clientKey]*Lease{},
		delegatedPDs: map[string][]DelegatedPrefix{},
		v6opts: map[string]*DHCPv6Options{
			"wan0": {IATypes: []string{"ia-na", "ia-pd"}},
		},
	}
	res, err := m.parseV6ReplyChecked(context.Background(), "wan0", coHeldReply(t), m.v6opts["wan0"], nil, nil)
	if !errors.Is(err, errV6AddrInvalidated) {
		t.Fatalf("co-held IA_NA invalidated + live IA_PD: err=%v res=%+v, want errV6AddrInvalidated; a success address-less lease orphans the WAN address", err, res)
	}
	if res != nil {
		t.Fatalf("co-held invalidation returned res=%+v, want nil", res)
	}
}

// Control: co-held reply with a POSITIVE IA_NA and a live IA_PD installs
// normally (no sentinel, address present).
func TestParseV6ReplyCoHeldPositiveControl14998(t *testing.T) {
	msg, err := dhcpv6.NewMessage()
	if err != nil {
		t.Fatal(err)
	}
	msg.MessageType = dhcpv6.MessageTypeReply
	ianaOpt := &dhcpv6.OptIANA{IaId: [4]byte{0, 0, 0, 1}}
	ianaOpt.Options.Add(&dhcpv6.OptIAAddress{
		IPv6Addr:          net.ParseIP("2606:4700::1"),
		PreferredLifetime: 100 * time.Second,
		ValidLifetime:     3600 * time.Second,
	})
	msg.AddOption(ianaOpt)
	iapd := &dhcpv6.OptIAPD{IaId: [4]byte{0, 0, 0, 2}}
	iapd.Options.Add(&dhcpv6.OptIAPrefix{
		PreferredLifetime: 3600 * time.Second,
		ValidLifetime:     3600 * time.Second,
		Prefix:            &net.IPNet{IP: net.ParseIP("2606:4700:1000::"), Mask: net.CIDRMask(48, 128)},
	})
	msg.AddOption(iapd)

	m := &Manager{
		leases:       map[clientKey]*Lease{},
		delegatedPDs: map[string][]DelegatedPrefix{},
		v6opts:       map[string]*DHCPv6Options{"wan0": {IATypes: []string{"ia-na", "ia-pd"}}},
	}
	res, err := m.parseV6ReplyChecked(context.Background(), "wan0", msg, m.v6opts["wan0"], nil, nil)
	if err != nil {
		t.Fatalf("co-held positive reply: %v", err)
	}
	if !res.lease.Address.IsValid() {
		t.Fatal("co-held positive reply: address not installed")
	}
	if len(res.prefixes) != 1 {
		t.Fatalf("co-held positive reply: prefixes=%d want 1", len(res.prefixes))
	}
}

// ---------------------------------------------------------------------------
// Commit layer: committing an address-less successor over a held address
// must remove the old kernel address (defence in depth for Leg 1).
// ---------------------------------------------------------------------------

func TestCommitLeaseInvalidatedRemovesAddress14998(t *testing.T) {
	key := clientKey{iface: "wan0", family: AFInet6}
	prev := &Lease{
		Interface: "wan0", Family: AFInet6,
		Address:   netip.MustParsePrefix("2001:db8::1/128"),
		LeaseTime: time.Hour, Obtained: time.Now(),
	}
	var removed []*Lease
	m := &Manager{
		leases:       map[clientKey]*Lease{key: prev},
		delegatedPDs: map[string][]DelegatedPrefix{},
		removeAddressForTest: func(_ string, lease *Lease) {
			removed = append(removed, lease)
		},
	}
	// Address-less successor lease (invalid Address, as produced by the
	// pre-fix co-held invalidation parse).
	next := &Lease{
		Interface: "wan0", Family: AFInet6,
		// Address invalid
		LeaseTime: time.Hour, Obtained: time.Now(),
	}
	if err := m.commitLease(key, next, prev, nil, nil, false); err != nil {
		t.Fatalf("commitLease: %v", err)
	}
	if len(removed) != 1 || removed[0] != prev {
		t.Fatalf("removed=%v, want [prev] (orphaned WAN address removal)", removed)
	}
}

// Control: same-address renewal must not remove the address.
func TestCommitLeaseSameAddressNoRemove14998(t *testing.T) {
	key := clientKey{iface: "wan0", family: AFInet6}
	prev := &Lease{
		Interface: "wan0", Family: AFInet6,
		Address:   netip.MustParsePrefix("2001:db8::1/128"),
		LeaseTime: time.Hour, Obtained: time.Now(),
	}
	var removed []*Lease
	m := &Manager{
		leases:       map[clientKey]*Lease{key: prev},
		delegatedPDs: map[string][]DelegatedPrefix{},
		removeAddressForTest: func(_ string, lease *Lease) {
			removed = append(removed, lease)
		},
	}
	next := &Lease{
		Interface: "wan0", Family: AFInet6,
		Address:   netip.MustParsePrefix("2001:db8::1/128"),
		LeaseTime: time.Hour, Obtained: time.Now(),
	}
	if err := m.commitLease(key, next, prev, nil, nil, false); err != nil {
		t.Fatalf("commitLease: %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("same-address renewal removed addresses %v, want none", removed)
	}
}

// ---------------------------------------------------------------------------
// Run-loop leg 1: co-held renewal returning the invalidation sentinel must
// remove the WAN kernel address and clear the stored lease.
// ---------------------------------------------------------------------------

func TestRunDHCPv6CoHeldInvalidationRemovesWANAddress14998(t *testing.T) {
	leaseX := &Lease{
		Interface: "wan0", Family: AFInet6,
		Address:   netip.MustParsePrefix("2001:db8::1/128"),
		LeaseTime: 200 * time.Second, Obtained: time.Now(),
	}
	pd := DelegatedPrefix{
		Interface: "wan0", Prefix: netip.MustParsePrefix("2001:db8:1000::/48"),
		ValidLifetime: 100 * time.Second, Obtained: leaseX.Obtained,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var removed []*Lease
	m := &Manager{
		leases:       map[clientKey]*Lease{},
		delegatedPDs: map[string][]DelegatedPrefix{},
		v6opts:       map[string]*DHCPv6Options{"wan0": {IATypes: []string{"ia-na", "ia-pd"}}},
		afterForTest: immediateAfter,
		waitLinkLocalForTest: func(context.Context, string, time.Duration) error {
			return nil
		},
		removeAddressForTest: func(_ string, lease *Lease) {
			removed = append(removed, lease)
		},
	}
	var n int
	var removedAtReacquire []*Lease
	var leaseAtReacquire *Lease
	m.doV6ExchangeForTest = func(_ context.Context, _ string, _ dhcpExchangeMode, _ *Lease, _ []DelegatedPrefix) (*dhcpv6Result, error) {
		n++
		switch n {
		case 1:
			return &dhcpv6Result{lease: leaseX, prefixes: []DelegatedPrefix{pd}}, nil
		case 2:
			// RENEW reply: explicit IA_NA 0 + live IA_PD. Through the real
			// parse path this would surface via parseV6ReplyChecked; the
			// seam returns the sentinel exactly as parse now does post-fix.
			return nil, fmt.Errorf("renew: %w", errV6AddrInvalidated)
		default:
			removedAtReacquire = append([]*Lease(nil), removed...)
			leaseAtReacquire = m.LeaseFor("wan0", AFInet6)
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
	if len(removedAtReacquire) == 0 {
		t.Fatal("kernel WAN address was not removed on co-held IA_NA invalidation (orphaned address)")
	}
	if leaseAtReacquire != nil {
		t.Fatalf("lease at re-acquire = %v, want nil", leaseAtReacquire)
	}
}

// ---------------------------------------------------------------------------
// Run-loop leg 2: PD prune during T1 wait must not restart the full T1 wait.
//
// Deterministic timer: t1 = 100s (lease 200s), PD already expired at wait
// entry. The wait wakes via the RA tick (20ms), prunes the PD, and reports
// PDExpired. Pre-fix the outer loop restarts m.after(100s). Post-fix the
// remaining wait stays anchored. We assert the RENEW exchange fires well
// within 3s of loop start even though the scripted RA tick is 20ms.
// ---------------------------------------------------------------------------

func TestRunDHCPv6PDPruneDoesNotResetT1Wait14998(t *testing.T) {
	// LeaseTime 40s obtained 19s ago: T1 (20s) is only ~1s away, lease
	// deadline (Obtained+40s) is ~21s away. PD already expired. If the
	// PD-prune path restarts a fresh full m.after(t1=20s), the recorded
	// post-prune wait is 20s; anchored, it is ~1s.
	leaseA := &Lease{
		Interface: "wan0", Family: AFInet6,
		Address:   netip.MustParsePrefix("2606:4700::50/128"),
		LeaseTime: 40 * time.Second, Obtained: time.Now().Add(-19 * time.Second),
	}
	pd := DelegatedPrefix{
		Interface: "wan0", Prefix: netip.MustParsePrefix("2606:4700:1000::/48"),
		PreferredLifetime: time.Second, ValidLifetime: time.Second,
		Obtained: time.Now().Add(-1500 * time.Millisecond),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var t1Durations []time.Duration
	m := &Manager{
		leases:       map[clientKey]*Lease{},
		delegatedPDs: map[string][]DelegatedPrefix{},
		v6opts:       map[string]*DHCPv6Options{"wan0": {IATypes: []string{"ia-na", "ia-pd"}, RAIface: "lan0"}},
		waitLinkLocalForTest: func(context.Context, string, time.Duration) error {
			return nil
		},
	}
	// Every m.after() duration is recorded with its real wait capped at
	// 150ms so the production code can re-schedule freely; the SELECT in
	// waitForIPv6TimerOrRAWithPD races this against the 20ms RA tick, so
	// whether the prune is observed depends on implementation: pre-fix
	// the prune WILL be observed (and a full 20s wait re-issued) because
	// the post-prune wait is again capped but recorded as 20s.
	m.afterForTest = func(d time.Duration) <-chan time.Time {
		wait := d
		if d >= time.Second {
			t1Durations = append(t1Durations, d)
			wait = 150 * time.Millisecond
		}
		ch := make(chan time.Time, 1)
		go func() {
			time.Sleep(wait)
			ch <- time.Now()
		}()
		return ch
	}
	m.raAfterForTest = func(time.Duration) <-chan time.Time {
		ch := make(chan time.Time, 1)
		go func() {
			time.Sleep(20 * time.Millisecond)
			ch <- time.Now()
		}()
		return ch
	}

	renewAt := make(chan time.Duration, 1)
	start := time.Now()
	var n int
	m.doV6ExchangeForTest = func(_ context.Context, _ string, mode dhcpExchangeMode, _ *Lease, _ []DelegatedPrefix) (*dhcpv6Result, error) {
		n++
		if n == 1 {
			return &dhcpv6Result{lease: leaseA, prefixes: []DelegatedPrefix{pd}}, nil
		}
		if mode == exchangeRenew {
			renewAt <- time.Since(start)
			cancel()
			return nil, context.Canceled
		}
		cancel()
		return nil, context.Canceled
	}
	done := make(chan struct{})
	go func() { m.runDHCPv6(ctx, "wan0"); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("runDHCPv6 did not terminate")
	}
	defer disarmRecompile(m)

	select {
	case elapsed := <-renewAt:
		if elapsed > 3*time.Second {
			t.Fatalf("RENEW fired after %v", elapsed)
		}
	default:
		t.Fatal("RENEW exchange never fired")
	}
	if len(t1Durations) == 0 {
		t.Fatal("no T1 wait was scheduled")
	}
	// Decisive: any wait issued after the first (i.e. after the PD prune)
	// must be the remaining time to the anchored T1 (~1s), never the full
	// t1 (20s). If exactly one wait was recorded the renew raced ahead of
	// the prune — acceptable only because T1 was ~1s out in any case.
	for i, d := range t1Durations[1:] {
		if d >= 10*time.Second {
			t.Fatalf("post-prune T1 wait #%d = %v, want remaining ~1s (anchored), not full t1=20s reset", i+2, d)
		}
	}
}

// Control for leg 2: with no expired PD the T1 wait is issued once at the
// normal anchored remaining duration.
func TestRunDHCPv6NoPDExpirySingleT1Wait14998(t *testing.T) {
	leaseA := &Lease{
		Interface: "wan0", Family: AFInet6,
		Address:   netip.MustParsePrefix("2606:4700::50/128"),
		LeaseTime: time.Hour, Obtained: time.Now(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var waits []time.Duration
	m := &Manager{
		leases:       map[clientKey]*Lease{},
		delegatedPDs: map[string][]DelegatedPrefix{},
		v6opts:       map[string]*DHCPv6Options{"wan0": {IATypes: []string{"ia-na", "ia-pd"}}},
		waitLinkLocalForTest: func(context.Context, string, time.Duration) error {
			return nil
		},
	}
	m.afterForTest = func(d time.Duration) <-chan time.Time {
		waits = append(waits, d)
		ch := make(chan time.Time, 1)
		go func() { time.Sleep(10 * time.Millisecond); ch <- time.Now() }()
		return ch
	}
	m.raAfterForTest = func(time.Duration) <-chan time.Time {
		ch := make(chan time.Time, 1)
		go func() { time.Sleep(50 * time.Millisecond); ch <- time.Now() }()
		return ch
	}
	var n int
	m.doV6ExchangeForTest = func(_ context.Context, _ string, mode dhcpExchangeMode, _ *Lease, _ []DelegatedPrefix) (*dhcpv6Result, error) {
		n++
		if n == 1 {
			return &dhcpv6Result{lease: leaseA}, nil
		}
		cancel()
		return nil, context.Canceled
	}
	done := make(chan struct{})
	go func() { m.runDHCPv6(ctx, "wan0"); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("runDHCPv6 did not terminate")
	}
	defer disarmRecompile(m)
	if len(waits) == 0 {
		t.Fatal("no T1 wait scheduled")
	}
}
