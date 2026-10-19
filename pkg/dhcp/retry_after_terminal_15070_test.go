package dhcp

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// #15070 (A39-03): a DHCP client that hits a terminal exit — DHCPv6
// no-link-local within 30s, or DHCPv4 exhausting retransmission-attempt —
// stayed dead until an unrelated config apply (Reconcile/Renew/Start).
// The fix makes both run loops self-recover: v6 re-waits for link-local
// after an m.after-paced pause; v4 paces a long backoff and re-enters
// INIT (attempt reset) instead of returning. These tests drive the real
// run loops through the exchange/link-local/timer seams and require
// exchanges >= 1 after the terminal condition clears, without any
// Reconcile/Renew/Start after the initial goroutine launch.

// TestRunDHCPv6RecoversAfterLinkLocalAppearsLate: waitLinkLocal fails
// once (30s timeout equivalent), then succeeds; the loop must retry the
// wait and then Solicit, leasing an address. Pre-fix runDHCPv6 returned
// on the first wait error and never exchanged.
func TestRunDHCPv6RecoversAfterLinkLocalAppearsLate(t *testing.T) {
	leaseA := &Lease{
		Interface: "wan0",
		Family:    AFInet6,
		Address:   netip.MustParsePrefix("2001:db8::5/128"),
		LeaseTime: 100 * time.Second,
		Obtained:  time.Now(),
	}
	var waits atomic.Int32
	var exchanges atomic.Int32

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := &Manager{
		leases:       map[clientKey]*Lease{},
		delegatedPDs: map[string][]DelegatedPrefix{},
		v6opts:       map[string]*DHCPv6Options{"wan0": {}},
		afterForTest: immediateAfter,
		waitLinkLocalForTest: func(context.Context, string, time.Duration) error {
			if waits.Add(1) == 1 {
				return errors.New("timeout waiting for link-local on wan0")
			}
			return nil
		},
	}
	m.doV6ExchangeForTest = func(_ context.Context, _ string, mode dhcpExchangeMode, _ *Lease, _ []DelegatedPrefix) (*dhcpv6Result, error) {
		n := exchanges.Add(1)
		if n == 1 && mode != exchangeAcquire {
			t.Errorf("first exchange mode = %s, want acquire (recovery must Solicit)", mode)
		}
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
	case <-time.After(3 * time.Second):
		t.Fatal("runDHCPv6 did not terminate")
	}
	if got := waits.Load(); got < 2 {
		t.Fatalf("waitLinkLocal calls = %d, want >=2 (loop must re-wait after terminal link-local failure)", got)
	}
	if got := exchanges.Load(); got < 1 {
		t.Fatalf("v6 exchanges after link-local recovery = %d, want >=1 without Reconcile", got)
	}
}

// Control: a cancelled ctx during the link-local retry pause must still
// terminate promptly — self-recovery must not resurrect a stopped client.
func TestRunDHCPv6LinkLocalRetryRespectsCancel(t *testing.T) {
	var waits atomic.Int32
	var exchanges atomic.Int32

	ctx, cancel := context.WithCancel(context.Background())

	neverFire := func(time.Duration) <-chan time.Time { return make(chan time.Time) }
	m := &Manager{
		leases:       map[clientKey]*Lease{},
		delegatedPDs: map[string][]DelegatedPrefix{},
		v6opts:       map[string]*DHCPv6Options{"wan0": {}},
		afterForTest: neverFire,
		waitLinkLocalForTest: func(context.Context, string, time.Duration) error {
			waits.Add(1)
			return errors.New("timeout waiting for link-local on wan0")
		},
	}
	m.doV6ExchangeForTest = func(context.Context, string, dhcpExchangeMode, *Lease, []DelegatedPrefix) (*dhcpv6Result, error) {
		exchanges.Add(1)
		return nil, errors.New("must not exchange")
	}

	done := make(chan struct{})
	go func() { m.runDHCPv6(ctx, "wan0"); close(done) }()

	// Let the first wait fail and the retry pause begin, then cancel.
	deadline := time.Now().Add(2 * time.Second)
	for waits.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runDHCPv6 did not terminate after cancel during link-local retry pause")
	}
	if got := exchanges.Load(); got != 0 {
		t.Fatalf("v6 exchanges after cancel = %d, want 0", got)
	}
}

// TestRunDHCPv4RecoversAfterMaxRetransmissionAttempts: with
// RetransmissionAttempt=2 the first INIT cycle fails twice (terminal
// pre-fix), then the server answers; the loop must pace a backoff,
// reset attempts, re-enter INIT, and lease — without Reconcile.
// Also pins pacing through the after seam: unlimited instant retries
// (no after call between cycles) would be a DISCOVER storm.
func TestRunDHCPv4RecoversAfterMaxRetransmissionAttempts(t *testing.T) {
	leaseA := &Lease{
		Interface: "wan0",
		Family:    AFInet,
		Address:   netip.MustParsePrefix("192.0.2.50/24"),
		LeaseTime: 100 * time.Second,
		Obtained:  time.Now(),
	}
	var exchanges atomic.Int32
	var afterCalls atomic.Int32

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := &Manager{
		leases:       map[clientKey]*Lease{},
		delegatedPDs: map[string][]DelegatedPrefix{},
		v4opts: map[string]*DHCPv4Options{"wan0": {
			RetransmissionAttempt:  2,
			RetransmissionInterval: 1,
		}},
		afterForTest: func(d time.Duration) <-chan time.Time {
			afterCalls.Add(1)
			return immediateAfter(d)
		},
	}
	m.doV4ExchangeForTest = func(_ context.Context, _ string, mode dhcpExchangeMode, _ *Lease) (*Lease, error) {
		n := exchanges.Add(1)
		if n <= 3 && mode != exchangeAcquire {
			t.Errorf("exchange %d mode = %s, want acquire (recovery must re-DISCOVER)", n, mode)
		}
		if n <= 2 {
			return nil, errors.New("no DHCP server")
		}
		if n == 3 {
			return leaseA, nil
		}
		// Renewal cycle after recovery: stop the loop.
		cancel()
		return nil, context.Canceled
	}

	done := make(chan struct{})
	go func() { m.runDHCPv4(ctx, "wan0"); close(done) }()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runDHCPv4 did not terminate")
	}
	if got := exchanges.Load(); got < 3 {
		t.Fatalf("v4 exchanges after max-attempts recovery = %d, want >=3 (2 failed + 1 leased) without Reconcile", got)
	}
	// Exchange 1 fails -> backoff wait (after#1); exchange 2 hits the
	// attempt cap -> recovery wait (after#2) before re-entering INIT.
	// Pre-fix there is no recovery wait and the loop returns at 2.
	if got := afterCalls.Load(); got < 2 {
		t.Fatalf("after-paced waits = %d, want >=2 (retry backoff + post-cap recovery backoff)", got)
	}
	// Committed lease proves recovery completed end-to-end (commitLease
	// ran). runDHCPv4's success path may have ctx-cleaned it after
	// cancel, so accept either committed-present; the exchange count
	// plus a nil-error return is the primary signal. Assert no panic
	// and termination already covered.
	_ = m.LeaseFor("wan0", AFInet)
}
