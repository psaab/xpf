package dhcp

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
)

// #16553: the client never read server T1/T2 (IA_NA / IA_PD T1/T2,
// DHCPv4 options 58/59). renewalTimers was always 50%/87.5% of the
// single IA_NA LeaseTime, so a PD whose valid lifetime ended before
// that T1 was pruned and withdrawn from LAN RA, only re-requested at
// the IA_NA T1, every cycle. RFC 8415 §18.2.4 requires Renew/Rebind
// not later than the earliest T1/T2 of ANY held binding; RFC 2131
// §4.4.5 makes 0.5/0.875 only defaults when options 58/59 are absent.
//
// RED-on-revert: drop the RenewAt/RebindAt plumbing (lease/PD fields
// stay zero, run loops call renewalTimers) and every server-timer
// row below fails — the schedule collapses to 50%/87.5% of LeaseTime.

func TestRenewalScheduleServerT1T2_16553(t *testing.T) {
	hour := time.Hour
	tests := []struct {
		name      string
		leaseTime time.Duration
		pds       []DelegatedPrefix
		srvT1     time.Duration
		srvT2     time.Duration
		wantT1    time.Duration
		wantT2Rem time.Duration
		wantOK    bool
	}{
		{
			name:      "no server timers keeps RFC defaults (control)",
			leaseTime: hour, wantT1: 30 * time.Minute, wantT2Rem: 22*time.Minute + 30*time.Second, wantOK: true,
		},
		{
			name:      "IA_NA T1=60s schedules renew at 60s (issue acceptance)",
			leaseTime: hour, srvT1: 60 * time.Second,
			wantT1: 60 * time.Second, wantT2Rem: 51*time.Minute + 30*time.Second, wantOK: true,
		},
		{
			name:      "server T2 honored",
			leaseTime: hour, srvT1: 60 * time.Second, srvT2: 120 * time.Second,
			wantT1: 60 * time.Second, wantT2Rem: 60 * time.Second, wantOK: true,
		},
		{
			// Defect cell lifetimes: IA_NA valid 3600s, PD valid 100s,
			// no server T1/T2 -> T1 must be 50s (half shortest), well
			// before the PD expires at 100s. Pre-fix T1 was 1800s.
			name:      "short PD without server timers renews at half PD valid",
			leaseTime: hour,
			pds:       []DelegatedPrefix{{ValidLifetime: 100 * time.Second}},
			wantT1:    50 * time.Second, wantT2Rem: 37*time.Second + 500*time.Millisecond, wantOK: true,
		},
		{
			// Defect cell with IA_PD T1=1s: Renew before 1s cap —
			// T1 must be <= the PD T1 (1s), never the IA_NA T1.
			name:      "IA_PD T1=1s beats IA_NA default",
			leaseTime: hour,
			pds:       []DelegatedPrefix{{ValidLifetime: 100 * time.Second, RenewAt: time.Second, RebindAt: 80 * time.Second}},
			wantT1:    time.Second, wantT2Rem: 79 * time.Second, wantOK: true,
		},
		{
			name:      "earliest PD T1 across prefixes wins",
			leaseTime: hour,
			pds: []DelegatedPrefix{
				{ValidLifetime: 200 * time.Second, RenewAt: 90 * time.Second, RebindAt: 150 * time.Second},
				{ValidLifetime: 300 * time.Second, RenewAt: 30 * time.Second, RebindAt: 250 * time.Second},
			},
			wantT1: 30 * time.Second, wantT2Rem: 120 * time.Second, wantOK: true,
		},
		{
			name:      "IA_PD T1 earlier than IA_NA T1 wins",
			leaseTime: hour, srvT1: 500 * time.Second, srvT2: 3000 * time.Second,
			pds:    []DelegatedPrefix{{ValidLifetime: 100 * time.Second, RenewAt: 40 * time.Second, RebindAt: 70 * time.Second}},
			wantT1: 40 * time.Second, wantT2Rem: 30 * time.Second, wantOK: true,
		},
		{
			name:      "one-sided T1 only: T2 falls back to shortest default",
			leaseTime: hour,
			pds:       []DelegatedPrefix{{ValidLifetime: 100 * time.Second, RenewAt: 10 * time.Second}},
			wantT1:    10 * time.Second, wantT2Rem: 77*time.Second + 500*time.Millisecond, wantOK: true,
		},
		{
			name:      "one-sided T2 only: T1 falls back to shortest default",
			leaseTime: hour,
			pds:       []DelegatedPrefix{{ValidLifetime: 100 * time.Second, RebindAt: 60 * time.Second}},
			wantT1:    50 * time.Second, wantT2Rem: 10 * time.Second, wantOK: true,
		},
		{
			// Degenerate server: T1 at/after expiry must be pulled
			// back before expiry; T1 < T2 < shortest still holds.
			name:      "server T1 at expiry clamped pre-expiry",
			leaseTime: 100 * time.Second, srvT1: 100 * time.Second, srvT2: 200 * time.Second,
			wantT1: 50 * time.Second, wantT2Rem: 37*time.Second + 500*time.Millisecond, wantOK: true,
		},
		{
			name:      "server T2 before T1 does not collapse tiers",
			leaseTime: 100 * time.Second, srvT1: 80 * time.Second, srvT2: 40 * time.Second,
			wantT1: 20 * time.Second, wantT2Rem: 20 * time.Second, wantOK: true,
		},
		{
			name:      "zero lease invalid even with server timers",
			leaseTime: 0, srvT1: time.Second, wantOK: false,
		},
		{
			name:      "infinite sentinel with server timers keeps T1<T2",
			leaseTime: infiniteLifetime, srvT1: time.Hour, srvT2: 2 * time.Hour,
			wantT1: time.Hour, wantT2Rem: time.Hour, wantOK: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t1, t2Rem, ok := renewalSchedule(tt.leaseTime, tt.pds, tt.srvT1, tt.srvT2)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if t1 != tt.wantT1 || t2Rem != tt.wantT2Rem {
				t.Fatalf("schedule = (t1=%v, t2Remaining=%v), want (%v, %v)", t1, t2Rem, tt.wantT1, tt.wantT2Rem)
			}
			shortest := tt.leaseTime
			for _, dp := range tt.pds {
				if dp.ValidLifetime > 0 && dp.ValidLifetime < shortest {
					shortest = dp.ValidLifetime
				}
			}
			if t1 <= 0 || t1+t2Rem <= t1 {
				t.Fatalf("tiers collapsed: t1=%v t2Abs=%v", t1, t1+t2Rem)
			}
			if shortest < infiniteLifetime && t1+t2Rem >= shortest {
				t.Fatalf("T2 absolute %v must be < shortest valid %v", t1+t2Rem, shortest)
			}
		})
	}
}

// Parse-level: a Reply carrying IA_NA T1=60s and a shorter IA_PD
// (valid 100s, T1=1s/T2=80s) must surface both timers.
func TestParseV6ReplyCarriesServerT1T2_16553(t *testing.T) {
	m := &Manager{}
	now := time.Now()
	_ = now
	msg, err := dhcpv6.NewMessage()
	if err != nil {
		t.Fatalf("NewMessage: %v", err)
	}
	msg.MessageType = dhcpv6.MessageTypeReply
	iana := &dhcpv6.OptIANA{IaId: [4]byte{0, 0, 0, 1}, T1: 60 * time.Second, T2: 3000 * time.Second}
	iana.Options.Add(&dhcpv6.OptIAAddress{
		IPv6Addr:          net.ParseIP("2606:4700::50"),
		PreferredLifetime: 3600 * time.Second, ValidLifetime: 3600 * time.Second,
	})
	msg.AddOption(iana)
	iapd := &dhcpv6.OptIAPD{IaId: [4]byte{0, 0, 0, 1}, T1: time.Second, T2: 80 * time.Second}
	iapd.Options.Add(&dhcpv6.OptIAPrefix{
		PreferredLifetime: 50 * time.Second, ValidLifetime: 100 * time.Second,
		Prefix: &net.IPNet{IP: net.ParseIP("2606:4700:1000::"), Mask: net.CIDRMask(48, 128)},
	})
	msg.AddOption(iapd)

	opts := &DHCPv6Options{IATypes: []string{"ia-na", "ia-pd"}}
	res, err := m.parseV6ReplyChecked(context.Background(), "wan0", msg, opts, nil, nil)
	if err != nil {
		t.Fatalf("parseV6ReplyChecked: %v", err)
	}
	if res.lease.RenewAt != 60*time.Second || res.lease.RebindAt != 3000*time.Second {
		t.Fatalf("lease timers = (%v, %v), want IA_NA (60s, 3000s)", res.lease.RenewAt, res.lease.RebindAt)
	}
	if res.lease.LeaseTime != 3600*time.Second {
		t.Fatalf("LeaseTime = %v, want IA_NA valid 3600s (expiry anchor unchanged)", res.lease.LeaseTime)
	}
	if len(res.prefixes) != 1 {
		t.Fatalf("prefixes = %+v, want 1", res.prefixes)
	}
	pd := res.prefixes[0]
	if pd.RenewAt != time.Second || pd.RebindAt != 80*time.Second || pd.ValidLifetime != 100*time.Second {
		t.Fatalf("PD timers = (T1 %v, T2 %v, valid %v), want (1s, 80s, 100s)", pd.RenewAt, pd.RebindAt, pd.ValidLifetime)
	}
	// Effective schedule: earliest T1 across IAs is the PD's 1s.
	t1, t2Rem, ok := renewalSchedule(res.lease.LeaseTime, res.prefixes, res.lease.RenewAt, res.lease.RebindAt)
	if !ok || t1 != time.Second || t1+t2Rem != 80*time.Second {
		t.Fatalf("effective schedule = (t1 %v, t2Abs %v, ok %v), want (1s, 80s, true)", t1, t1+t2Rem, ok)
	}
}

// Control: a Reply with no T1/T2 (zero) keeps today's defaults.
func TestParseV6ReplyNoServerT1T2Control_16553(t *testing.T) {
	m := &Manager{}
	msg := iaNAReply(t, &dhcpv6.OptIAAddress{
		IPv6Addr:          mustIP(t, "2606:4700::5"),
		PreferredLifetime: 100 * time.Second, ValidLifetime: 500 * time.Second,
	})
	res, err := m.parseV6ReplyChecked(context.Background(), "wan0", msg, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("parseV6ReplyChecked: %v", err)
	}
	if res.lease.RenewAt != 0 || res.lease.RebindAt != 0 {
		t.Fatalf("lease timers = (%v,%v), want zero (server supplied none)", res.lease.RenewAt, res.lease.RebindAt)
	}
	t1, t2Rem, ok := renewalSchedule(res.lease.LeaseTime, res.prefixes, res.lease.RenewAt, res.lease.RebindAt)
	if !ok || t1 != 250*time.Second || t1+t2Rem != 437*time.Second+500*time.Millisecond {
		t.Fatalf("control schedule = (t1 %v, t2Abs %v, ok %v), want (250s, 437.5s, true)", t1, t1+t2Rem, ok)
	}
}

// DHCPv4 options 58/59 are honored; absent options stay zero.
func TestLeaseFromACKv4ServerT1T2_16553(t *testing.T) {
	ack := classlessACK(t,
		dhcpv4.OptIPAddressLeaseTime(3600*time.Second),
		dhcpv4.OptRenewTimeValue(60*time.Second),
		dhcpv4.OptRebindingTimeValue(120*time.Second),
	)
	lease, err := leaseFromACKv4WithProtected("wan0", ack, nil)
	if err != nil {
		t.Fatalf("leaseFromACKv4: %v", err)
	}
	if lease.RenewAt != 60*time.Second || lease.RebindAt != 120*time.Second {
		t.Fatalf("v4 timers = (%v,%v), want (60s,120s) from options 58/59", lease.RenewAt, lease.RebindAt)
	}
	t1, t2Rem, ok := renewalSchedule(lease.LeaseTime, nil, lease.RenewAt, lease.RebindAt)
	if !ok || t1 != 60*time.Second || t1+t2Rem != 120*time.Second {
		t.Fatalf("v4 schedule = (t1 %v, t2Abs %v, ok %v), want (60s,120s,true)", t1, t1+t2Rem, ok)
	}

	bare, err := leaseFromACKv4WithProtected("wan0", classlessACK(t, dhcpv4.OptIPAddressLeaseTime(3600*time.Second)), nil)
	if err != nil {
		t.Fatalf("leaseFromACKv4 bare: %v", err)
	}
	if bare.RenewAt != 0 || bare.RebindAt != 0 {
		t.Fatalf("bare ACK timers = (%v,%v), want zero", bare.RenewAt, bare.RebindAt)
	}
}

// Run-loop defect cell: IA_NA valid 3600s, IA_PD valid 100s with
// IA_PD T1=1s. The Renew must be scheduled at ~1s (recorded wait
// < 2s, never the pre-fix 1800s), and at Renew time the PD (valid
// 100s, freshly obtained) must still be in DelegatedPrefixesForRA.
func TestRunDHCPv6ServerPDT1RenewsBeforePDExpiry16553(t *testing.T) {
	obtained := time.Now()
	leaseA := &Lease{
		Interface: "wan0", Family: AFInet6,
		Address:   netip.MustParsePrefix("2606:4700::50/128"),
		LeaseTime: time.Hour, Obtained: obtained,
		RenewAt: 3600 * time.Second, RebindAt: 3000 * time.Second,
	}
	pd := DelegatedPrefix{
		Interface: "wan0", Prefix: netip.MustParsePrefix("2606:4700:1000::/48"),
		PreferredLifetime: 50 * time.Second, ValidLifetime: 100 * time.Second,
		Obtained: obtained, RenewAt: time.Second, RebindAt: 80 * time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var waits []time.Duration
	m := &Manager{
		leases:               map[clientKey]*Lease{},
		delegatedPDs:         map[string][]DelegatedPrefix{},
		v6opts:               map[string]*DHCPv6Options{"wan0": {IATypes: []string{"ia-na", "ia-pd"}, RAIface: "lan0"}},
		waitLinkLocalForTest: func(context.Context, string, time.Duration) error { return nil },
		removeAddressForTest: func(string, *Lease) {},
	}
	m.afterForTest = func(d time.Duration) <-chan time.Time {
		waits = append(waits, d)
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch
	}
	m.raAfterForTest = func(time.Duration) <-chan time.Time {
		ch := make(chan time.Time, 1)
		go func() { time.Sleep(20 * time.Millisecond); ch <- time.Now() }()
		return ch
	}
	var n int
	var pdsAtRenew []PDRAMapping
	var modeAtRenew dhcpExchangeMode
	m.doV6ExchangeForTest = func(_ context.Context, _ string, mode dhcpExchangeMode, _ *Lease, _ []DelegatedPrefix) (*dhcpv6Result, error) {
		n++
		if n == 1 {
			return &dhcpv6Result{lease: leaseA, prefixes: []DelegatedPrefix{pd}}, nil
		}
		modeAtRenew = mode
		pdsAtRenew = m.DelegatedPrefixesForRA()
		cancel()
		return nil, context.Canceled
	}
	done := make(chan struct{})
	go func() { m.runDHCPv6(ctx, "wan0"); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runDHCPv6 did not terminate")
	}
	defer disarmRecompile(m)
	if modeAtRenew != exchangeRenew {
		t.Fatalf("second exchange mode = %v, want renew", modeAtRenew)
	}
	if len(waits) == 0 {
		t.Fatal("no renewal wait recorded")
	}
	// The T1 wait is the first m.after in the renewal cycle; the RA/PD
	// wake uses raAfterForTest. It must be the PD T1 (~1s), not 1800s.
	if waits[0] <= 0 || waits[0] > 2*time.Second {
		t.Fatalf("first renewal wait = %v, want ~1s (IA_PD T1), not IA_NA half-life 1800s; all waits %v", waits[0], waits)
	}
	if len(pdsAtRenew) != 1 {
		t.Fatalf("DelegatedPrefixesForRA at Renew = %+v, want PD still advertised (Renew fired before PD expiry)", pdsAtRenew)
	}
}

// Run-loop control: same lifetimes, no server T1/T2 anywhere. The
// fallback (half the shortest valid, 50s) still renews before the
// PD's 100s expiry — but crucially the recorded wait equals the
// fallback, proving the defect cell above is driven by the server
// timer, not by an unrelated early fire.
func TestRunDHCPv6NoServerT1FallbackRenewsBeforePDExpiry16553(t *testing.T) {
	obtained := time.Now()
	leaseA := &Lease{
		Interface: "wan0", Family: AFInet6,
		Address:   netip.MustParsePrefix("2606:4700::50/128"),
		LeaseTime: time.Hour, Obtained: obtained,
	}
	pd := DelegatedPrefix{
		Interface: "wan0", Prefix: netip.MustParsePrefix("2606:4700:1000::/48"),
		PreferredLifetime: 50 * time.Second, ValidLifetime: 100 * time.Second,
		Obtained: obtained,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var waits []time.Duration
	m := &Manager{
		leases:               map[clientKey]*Lease{},
		delegatedPDs:         map[string][]DelegatedPrefix{},
		v6opts:               map[string]*DHCPv6Options{"wan0": {IATypes: []string{"ia-na", "ia-pd"}, RAIface: "lan0"}},
		waitLinkLocalForTest: func(context.Context, string, time.Duration) error { return nil },
		removeAddressForTest: func(string, *Lease) {},
	}
	m.afterForTest = func(d time.Duration) <-chan time.Time {
		waits = append(waits, d)
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch
	}
	m.raAfterForTest = func(time.Duration) <-chan time.Time {
		ch := make(chan time.Time, 1)
		go func() { time.Sleep(20 * time.Millisecond); ch <- time.Now() }()
		return ch
	}
	var n int
	var pdsAtRenew []PDRAMapping
	m.doV6ExchangeForTest = func(_ context.Context, _ string, _ dhcpExchangeMode, _ *Lease, _ []DelegatedPrefix) (*dhcpv6Result, error) {
		n++
		if n == 1 {
			return &dhcpv6Result{lease: leaseA, prefixes: []DelegatedPrefix{pd}}, nil
		}
		pdsAtRenew = m.DelegatedPrefixesForRA()
		cancel()
		return nil, context.Canceled
	}
	done := make(chan struct{})
	go func() { m.runDHCPv6(ctx, "wan0"); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runDHCPv6 did not terminate")
	}
	defer disarmRecompile(m)
	if len(waits) == 0 || waits[0] <= 49*time.Second || waits[0] > 50*time.Second {
		t.Fatalf("fallback first renewal wait = %v (all %v), want ~50s = half shortest valid (PD 100s), anchored to Obtained", waits, waits)
	}
	if len(pdsAtRenew) != 1 {
		t.Fatalf("DelegatedPrefixesForRA at Renew = %+v, want 1", pdsAtRenew)
	}
}
