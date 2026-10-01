package dhcp

// #5927: a DHCPv6 Reply with an EXPLICIT valid-lifetime 0 for the held IA_NA
// address (RFC 8415 §18.2.10.1 — "stop using this address") must DISCARD the
// address: deconfigure + re-acquire, not keep it in service. The floor at
// dhcp.go (`if lease.LeaseTime == 0 { 3600 }`) was a RED HERRING for this —
// selectIANAAddress (#4383) already skips valid-lifetime-0 IAADDRs, so the
// address is never selected and parseV6Reply errors before the floor. The real
// residual was the RENEW/REBIND loop treating that error as a TRANSIENT failure
// (keep-and-wait-T2) instead of an explicit invalidation.
//
// The fix threads a present-0-vs-absent signal through selectIANAAddress /
// parseV6Reply (the errV6AddrInvalidated sentinel) so the loop can DECONFIGURE
// on an explicit invalidation (b) while KEEPING the address on a merely absent /
// transient reply (d) — the correct #4874/#1844 anti-outage behavior.
//
// FAIL-ON-REVERT: remove the `errors.Is(rerr, errV6AddrInvalidated)` deconfigure
// branch from the renew loop → an explicit invalidation is treated as a generic
// failure → the loop keeps the address and issues a REBIND (kept-and-wait-T2) →
// TestRunDHCPv6ExplicitInvalidationDeconfigures_5927's "no REBIND / lease
// deleted" assertions go RED. The (d) absent test guards against over-correcting
// the transient path into a deconfigure.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

// (parse layer) present-0 → sentinel; absent → generic; positive/infinite → install.
func TestParseV6ReplyZeroLifetimeDistinction_5927(t *testing.T) {
	m := &Manager{}

	// (b) The only IA_NA IAADDR has valid-lifetime 0 → explicit invalidation.
	advZero := iaNAReply(t, &dhcpv6.OptIAAddress{
		IPv6Addr:          mustIP(t, "2001:db8::1"),
		PreferredLifetime: 100 * time.Second,
		ValidLifetime:     0,
	})
	if _, err := m.parseV6Reply(context.Background(), "wan0", advZero, nil); !errors.Is(err, errV6AddrInvalidated) {
		t.Fatalf("explicit valid-lifetime-0 IA_NA: err=%v, want errV6AddrInvalidated (present-0 invalidation)", err)
	}

	// (d) No IA_NA option at all → absent/transient → generic error, NOT the
	// sentinel (the loop must keep + retry, never deconfigure on this).
	advAbsent, err := dhcpv6.NewMessage()
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	advAbsent.MessageType = dhcpv6.MessageTypeReply
	_, err = m.parseV6Reply(context.Background(), "wan0", advAbsent, nil)
	if err == nil {
		t.Fatal("absent IA_NA: want an error")
	}
	if errors.Is(err, errV6AddrInvalidated) {
		t.Fatal("absent IA_NA wrongly returned the invalidation sentinel — would deconfigure on a transient reply (over-correction)")
	}

	// (ii) Positive lifetime → installs normally, no sentinel.
	advPos := iaNAReply(t, &dhcpv6.OptIAAddress{
		IPv6Addr:          mustIP(t, "2001:db8::2"),
		PreferredLifetime: 50 * time.Second,
		ValidLifetime:     100 * time.Second,
	})
	res, err := m.parseV6Reply(context.Background(), "wan0", advPos, nil)
	if err != nil {
		t.Fatalf("positive lifetime: %v", err)
	}
	if !res.lease.Address.IsValid() || res.lease.LeaseTime != 100*time.Second {
		t.Fatalf("positive lifetime: addr=%v leaseTime=%v, want installed with 100s", res.lease.Address, res.lease.LeaseTime)
	}

	// (iii) 0xFFFFFFFF (infinite) is a non-zero lifetime → installed normally,
	// never mistaken for an invalidation.
	advInf := iaNAReply(t, &dhcpv6.OptIAAddress{
		IPv6Addr:          mustIP(t, "2001:db8::3"),
		PreferredLifetime: 0xFFFFFFFF * time.Second,
		ValidLifetime:     0xFFFFFFFF * time.Second,
	})
	res, err = m.parseV6Reply(context.Background(), "wan0", advInf, nil)
	if err != nil {
		t.Fatalf("infinite lifetime: %v", err)
	}
	if !res.lease.Address.IsValid() {
		t.Fatal("infinite lifetime: address not installed")
	}
}

func newV6InvalidationManager(modes *[]dhcpExchangeMode, exchange func(n int, mode dhcpExchangeMode) (*dhcpv6Result, error)) *Manager {
	m := &Manager{
		leases:               map[clientKey]*Lease{},
		delegatedPDs:         map[string][]DelegatedPrefix{},
		v6opts:               map[string]*DHCPv6Options{"wan0": {IATypes: []string{"ia-na"}}},
		afterForTest:         immediateAfter,
		waitLinkLocalForTest: func(context.Context, string, time.Duration) error { return nil },
	}
	m.doV6ExchangeForTest = func(_ context.Context, _ string, mode dhcpExchangeMode, _ *Lease, _ []DelegatedPrefix) (*dhcpv6Result, error) {
		*modes = append(*modes, mode)
		return exchange(len(*modes), mode)
	}
	return m
}

// (b) run loop: an explicit invalidation on RENEW deconfigures the held address
// and re-acquires via a fresh SOLICIT — it does NOT keep it and wait for T2.
func TestRunDHCPv6ExplicitInvalidationDeconfigures_5927(t *testing.T) {
	leaseX := &Lease{
		Interface: "wan0", Family: AFInet6,
		Address:   netip.MustParsePrefix("2001:db8::1/128"),
		LeaseTime: 100 * time.Second,
		Obtained:  time.Now(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var modes []dhcpExchangeMode
	m := newV6InvalidationManager(&modes, func(n int, _ dhcpExchangeMode) (*dhcpv6Result, error) {
		switch n {
		case 1: // acquire → install X
			return &dhcpv6Result{lease: leaseX}, nil
		case 2: // T1 renew → server explicitly invalidates X (valid-lifetime 0)
			return nil, fmt.Errorf("renew: %w", errV6AddrInvalidated)
		default: // re-acquire SOLICIT reached → cancel so the loop exits
			cancel()
			return nil, context.Canceled
		}
	})

	done := make(chan struct{})
	go func() { m.runDHCPv6(ctx, "wan0"); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runDHCPv6 did not terminate")
	}

	key := clientKey{iface: "wan0", family: AFInet6}
	m.mu.Lock()
	_, stillHeld := m.leases[key]
	m.mu.Unlock()
	if stillHeld {
		t.Fatal("held address was NOT deconfigured on explicit invalidation (lease still present) — kept an address the server invalidated")
	}
	if len(modes) < 3 {
		t.Fatalf("expected >=3 exchanges (acquire, renew, re-solicit), got %d: %v", len(modes), modes)
	}
	for i, md := range modes {
		if md == exchangeRebind {
			t.Fatalf("loop issued a REBIND (exchange %d) after explicit invalidation — that is kept-and-wait-T2; want deconfigure + fresh SOLICIT, modes=%v", i, modes)
		}
	}
}

// (d) run loop guardrail: an ABSENT / transient RENEW reply (generic error, NOT
// the invalidation sentinel) must KEEP the held address and fall through to the
// T2 REBIND — the fix must not over-correct the transient path into a deconfigure.
func TestRunDHCPv6AbsentIANAKeepsAddress_5927(t *testing.T) {
	leaseX := &Lease{
		Interface: "wan0", Family: AFInet6,
		Address:   netip.MustParsePrefix("2001:db8::1/128"),
		LeaseTime: 100 * time.Second,
		Obtained:  time.Now(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var modes []dhcpExchangeMode
	m := newV6InvalidationManager(&modes, func(n int, _ dhcpExchangeMode) (*dhcpv6Result, error) {
		switch n {
		case 1: // acquire → install X
			return &dhcpv6Result{lease: leaseX}, nil
		case 2: // T1 renew → generic transient failure (NO usable IA_NA), NOT the sentinel
			return nil, fmt.Errorf("no usable IA_NA address or live IA_PD prefix in DHCPv6 reply on wan0")
		default: // T2 REBIND reached (address was KEPT) → cancel so the loop exits
			cancel()
			return nil, context.Canceled
		}
	})

	done := make(chan struct{})
	go func() { m.runDHCPv6(ctx, "wan0"); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runDHCPv6 did not terminate")
	}

	key := clientKey{iface: "wan0", family: AFInet6}
	m.mu.Lock()
	held := m.leases[key]
	m.mu.Unlock()
	if held == nil {
		t.Fatal("held address was deconfigured on a transient absent-IA_NA renew — over-correction; the transient path must keep + retry")
	}
	if len(modes) < 3 || modes[2] != exchangeRebind {
		t.Fatalf("expected acquire→renew→REBIND (keep-and-wait-T2), got modes=%v", modes)
	}
}
