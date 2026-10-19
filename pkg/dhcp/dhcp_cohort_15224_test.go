package dhcp

// #15224 (A39-02, A39-08):
//
// A39-02: a PD-only client (wantNA=false, wantPD=true) whose RENEW/REBIND
// Reply carries IA_PD NoPrefixAvail and no address currently gets a
// generic "no usable IA_NA address or live IA_PD prefix" error from
// parseV6ReplyChecked. The run loop treats that as a transient failure
// (keep-and-wait-T2 / re-acquire) and never clears the held delegation,
// so DelegatedPrefixesForRA keeps advertising the refused prefix until
// its own valid lifetime ends — the #14598 refusal is discarded on the
// PD-only path. The mixed ia-na+ia-pd path already clears via the
// pdRefused arm because parse succeeds there.
//
// Fix: parseV6ReplyChecked returns a typed errV6PDRefused when
// pdRefused is set and no usable address or live prefix was granted, and
// the run loop clears the delegated set (committedPDs + stored PDs +
// recompile) on that sentinel at RENEW and REBIND, without discarding a
// held IA_NA address (PD-only holds none; a mixed client never reaches
// the sentinel because its address makes parse succeed).
//
// A39-08: the RFC 8415 infinite lifetime is 0xFFFFFFFF seconds decoded
// by the dhcpv6 library as time.Duration(math.MaxUint32)*time.Second
// (~4.29e18 ns), which is BELOW the old 1<<62 sentinel (~4.61e18 ns).
// Infinite PDs/leases were therefore treated as finite: decayed by
// RemainingLifetimes, given a finite ExpiresAt, pruned after ~136 years
// (and, via ExpiresAt, fed finite expiry into the RA/cluster paths).
//
// Fix: infiniteLifetime is the wire value itself.
//
// RED on revert: restoring the generic guard / the 1<<62 sentinel makes
// the parse test see a non-typed error, the run-loop test keep the
// refused prefix, and the infinite-lifetime test observe decay/finite
// expiry.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

// --- A39-08: wire infinite lifetime -------------------------------------

func TestInfiniteLifetimeIsWireValue15224(t *testing.T) {
	wire := time.Duration(math.MaxUint32) * time.Second
	if infiniteLifetime != wire {
		t.Fatalf("infiniteLifetime = %v, want wire value %v (0xFFFFFFFF s)", infiniteLifetime, wire)
	}

	now := time.Now()
	// A delegated prefix granted with the wire infinite lifetimes must
	// never expire and never decay, even far in the future.
	dp := DelegatedPrefix{
		Interface:         "wan0",
		Prefix:            netip.MustParsePrefix("2001:db8:1000::/48"),
		PreferredLifetime: wire,
		ValidLifetime:     wire,
		Obtained:          now.Add(-24 * time.Hour),
	}
	if exp := dp.ExpiresAt(); !exp.IsZero() {
		t.Fatalf("infinite PD ExpiresAt = %v, want zero (never expires)", exp)
	}
	if exp := dp.PreferredExpiresAt(); !exp.IsZero() {
		t.Fatalf("infinite PD PreferredExpiresAt = %v, want zero", exp)
	}
	if dp.Expired(now) {
		t.Fatal("infinite PD reported Expired")
	}
	pref, valid := dp.RemainingLifetimes(now)
	if pref != wire || valid != wire {
		t.Fatalf("infinite PD RemainingLifetimes = (%v,%v), want (%v,%v) undecayed", pref, valid, wire, wire)
	}

	// Same for an IA_NA lease carrying the wire infinite lifetime.
	lease := &Lease{
		Address:   netip.MustParsePrefix("2606:4700::50/128"),
		LeaseTime: wire,
		Obtained:  now.Add(-24 * time.Hour),
	}
	if exp := lease.ExpiresAt(); !exp.IsZero() {
		t.Fatalf("infinite lease ExpiresAt = %v, want zero", exp)
	}
	lp, lv := lease.RemainingLifetimes(now)
	if lp != infiniteLifetime || lv != infiniteLifetime {
		t.Fatalf("infinite lease RemainingLifetimes = (%v,%v), want infinite sentinel", lp, lv)
	}
	if v, p := kernelAddrLifetimes(lease, now); v != 0xffffffff || p != 0xffffffff {
		t.Fatalf("kernelAddrLifetimes(infinite) = (%d,%d), want (0xffffffff,0xffffffff)", v, p)
	}

	// Control: a finite lifetime still decays and expires — the fix must
	// not make every lifetime infinite.
	finite := DelegatedPrefix{
		Interface:         "wan0",
		Prefix:            netip.MustParsePrefix("2001:db8:2000::/48"),
		PreferredLifetime: time.Hour,
		ValidLifetime:     time.Hour,
		Obtained:          now.Add(-2 * time.Hour),
	}
	if !finite.Expired(now) {
		t.Fatal("finite expired PD not reported Expired (control)")
	}
	if _, v := finite.RemainingLifetimes(now); v != 0 {
		t.Fatalf("finite expired PD remaining valid = %v, want 0 (control)", v)
	}
}

// --- A39-02: PD-only NoPrefixAvail refusal ------------------------------

func pdOnlyRefusalMessage(t *testing.T) *dhcpv6.Message {
	t.Helper()
	msg, err := dhcpv6.NewMessage()
	if err != nil {
		t.Fatal(err)
	}
	msg.MessageType = dhcpv6.MessageTypeReply
	iapd := &dhcpv6.OptIAPD{IaId: [4]byte{0, 0, 0, 1}}
	iapd.Options.Add(&dhcpv6.OptStatusCode{StatusCode: iana.StatusNoPrefixAvail, StatusMessage: "no prefixes"})
	msg.AddOption(iapd)
	return msg
}

func TestParseV6ReplyPDOnlyNoPrefixAvailTypedRefusal15224(t *testing.T) {
	m := &Manager{}
	opts := &DHCPv6Options{IATypes: []string{"ia-pd"}}

	res, err := m.parseV6Reply(context.Background(), "wan0", pdOnlyRefusalMessage(t), opts)
	if !errors.Is(err, errV6PDRefused) {
		t.Fatalf("PD-only NoPrefixAvail: err=%v res=%+v, want errV6PDRefused", err, res)
	}
	if res != nil {
		t.Fatalf("PD-only NoPrefixAvail: res=%+v, want nil", res)
	}

	// Control: PD-only silence (no IA_PD at all) is NOT a refusal — it
	// stays the generic transient error so keep-and-retry is preserved.
	silent, err := dhcpv6.NewMessage()
	if err != nil {
		t.Fatal(err)
	}
	silent.MessageType = dhcpv6.MessageTypeReply
	_, err = m.parseV6Reply(context.Background(), "wan0", silent, opts)
	if err == nil {
		t.Fatal("PD-only silent reply: want generic error")
	}
	if errors.Is(err, errV6PDRefused) {
		t.Fatal("PD-only silent reply wrongly typed as refusal — would clear PDs on silence")
	}

	// Control: PD-only live grant still succeeds.
	live := iaPDReply(t, pdPrefixOpt(t, "2606:4700:1000::/48", time.Hour, 2*time.Hour))
	res, err = m.parseV6Reply(context.Background(), "wan0", live, opts)
	if err != nil {
		t.Fatalf("PD-only live grant: %v (control)", err)
	}
	if len(res.prefixes) != 1 {
		t.Fatalf("PD-only live grant prefixes = %+v, want 1 (control)", res.prefixes)
	}
}

// TestRunDHCPv6PDOnlyRefusalClearsDelegated15224 drives the real
// runDHCPv6 loop: acquisition grants a PD-only lease + prefix, the T1
// RENEW is refused with NoPrefixAvail (typed sentinel via the seam,
// exactly as parse now returns it), and the stored delegation must be
// empty immediately — DelegatedPrefixesForRA must not keep advertising
// the refused prefix until its lifetime ends.
func TestRunDHCPv6PDOnlyRefusalClearsDelegated15224(t *testing.T) {
	for _, rebind := range []bool{false, true} {
		name := "renew"
		if rebind {
			name = "rebind"
		}
		t.Run(name, func(t *testing.T) {
			leasePDOnly := &Lease{
				Interface: "wan0",
				Family:    AFInet6,
				LeaseTime: time.Hour,
				Obtained:  time.Now(),
			}
			pd := DelegatedPrefix{
				Interface:         "wan0",
				Prefix:            netip.MustParsePrefix("2001:db8:1000::/48"),
				PreferredLifetime: time.Hour,
				ValidLifetime:     time.Hour,
				Obtained:          time.Now(),
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			m := &Manager{
				leases:       map[clientKey]*Lease{},
				delegatedPDs: map[string][]DelegatedPrefix{},
				v6opts: map[string]*DHCPv6Options{"wan0": {
					IATypes: []string{"ia-pd"},
					RAIface: "lan0",
				}},
				afterForTest:         immediateAfter,
				waitLinkLocalForTest: func(context.Context, string, time.Duration) error { return nil },
				removeAddressForTest: func(string, *Lease) {},
			}
			var n int
			var pdsAtReacquire []PDRAMapping
			m.doV6ExchangeForTest = func(_ context.Context, _ string, mode dhcpExchangeMode, _ *Lease, _ []DelegatedPrefix) (*dhcpv6Result, error) {
				n++
				switch {
				case n == 1: // acquire: PD-only lease + live PD
					return &dhcpv6Result{lease: leasePDOnly, prefixes: []DelegatedPrefix{pd}}, nil
				case !rebind && n == 2: // T1 RENEW refused
					return nil, fmt.Errorf("DHCPv6 reply on wan0: %w", errV6PDRefused)
				case rebind && n == 2: // T1 RENEW transient failure -> wait T2
					return nil, fmt.Errorf("no usable IA_NA address or live IA_PD prefix in DHCPv6 reply on wan0")
				case rebind && n == 3: // T2 REBIND refused
					return nil, fmt.Errorf("DHCPv6 reply on wan0: %w", errV6PDRefused)
				default: // re-acquire reached: snapshot, then stop
					pdsAtReacquire = m.DelegatedPrefixesForRA()
					cancel()
					return nil, context.Canceled
				}
			}
			done := make(chan struct{})
			go func() { m.runDHCPv6(ctx, "wan0"); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("runDHCPv6 did not terminate")
			}
			if len(pdsAtReacquire) != 0 {
				t.Fatalf("DelegatedPrefixesForRA after PD-only NoPrefixAvail %s = %+v, want empty (refused prefix must stop being advertised immediately)", name, pdsAtReacquire)
			}
			if got := m.DelegatedPrefixes(); len(got) != 0 {
				t.Fatalf("DelegatedPrefixes after refusal = %+v, want empty", got)
			}
			if !recompileArmed(m) {
				t.Fatal("clearing a refused PD must arm recompile so RA reconverges")
			}
			disarmRecompile(m)
			_ = net.IPv4len // keep net import if helpers change
		})
	}
}
