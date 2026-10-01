package dhcp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

// immediateAfter returns a seam that fires every renewal wait instantly,
// so the run-loop tests never block on the real 30 s T1 / 1 s T2 clamps.
func immediateAfter(time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	ch <- time.Now()
	return ch
}

func TestBuildV4RenewRequest(t *testing.T) {
	hw, _ := net.ParseMAC("02:00:00:00:00:01")
	prev := &Lease{
		Interface: "wan0",
		Family:    AFInet,
		Address:   netip.MustParsePrefix("192.0.2.50/24"),
		serverID:  netip.MustParseAddr("192.0.2.1"),
		LeaseTime: 3600 * time.Second,
	}

	req, err := buildV4RenewRequest(hw, prev, nil)
	if err != nil {
		t.Fatalf("buildV4RenewRequest: %v", err)
	}

	if req.MessageType() != dhcpv4.MessageTypeRequest {
		t.Errorf("message type = %s, want REQUEST (RENEW must not DISCOVER)", req.MessageType())
	}
	if !req.ClientIPAddr.Equal(net.ParseIP("192.0.2.50")) {
		t.Errorf("ciaddr = %v, want 192.0.2.50 (held address)", req.ClientIPAddr)
	}
	// RFC 2131 Table 5: BOUND/RENEW/REBIND MUST NOT set requested-IP or
	// server-identifier options.
	if ip := req.RequestedIPAddress(); ip != nil {
		t.Errorf("requested-IP option present (%v); must be absent in RENEW", ip)
	}
	if sid := req.ServerIdentifier(); sid != nil {
		t.Errorf("server-identifier option present (%v); must be absent in RENEW", sid)
	}
	if req.IsBroadcast() {
		t.Errorf("broadcast flag set; client owns the address and accepts unicast")
	}
}

func TestV4RenewDest(t *testing.T) {
	prev := &Lease{
		Address:  netip.MustParsePrefix("192.0.2.50/24"),
		serverID: netip.MustParseAddr("192.0.2.1"),
	}

	// RENEW (T1) → unicast to the granting server.
	d := v4RenewDest(prev, false)
	if !d.IP.Equal(net.ParseIP("192.0.2.1")) || d.Port != 67 {
		t.Errorf("renew dest = %v, want 192.0.2.1:67 (unicast to server)", d)
	}

	// REBIND (T2) → broadcast.
	d = v4RenewDest(prev, true)
	if !d.IP.Equal(net.IPv4bcast) || d.Port != 67 {
		t.Errorf("rebind dest = %v, want 255.255.255.255:67 (broadcast)", d)
	}

	// RENEW without a recorded server-identifier → broadcast fallback.
	noSID := &Lease{Address: netip.MustParsePrefix("192.0.2.50/24")}
	d = v4RenewDest(noSID, false)
	if !d.IP.Equal(net.IPv4bcast) {
		t.Errorf("renew-without-serverID dest = %v, want broadcast fallback", d)
	}
}

func TestBuildV6RenewMessage(t *testing.T) {
	hw, _ := net.ParseMAC("02:00:00:0a:0b:0c")
	serverDUID := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: hw}
	prev := &Lease{
		Family:       AFInet6,
		Address:      netip.MustParsePrefix("2001:db8::5/128"),
		v6ServerDUID: serverDUID,
		LeaseTime:    3600 * time.Second,
	}
	prevPDs := []DelegatedPrefix{
		{Prefix: netip.MustParsePrefix("2001:db8:1000::/48"), ValidLifetime: 7200 * time.Second},
	}

	t.Run("renew echoes server-id and bindings", func(t *testing.T) {
		msg, err := buildV6RenewMessage(hw, prev, prevPDs, false, nil)
		if err != nil {
			t.Fatal(err)
		}
		if msg.MessageType != dhcpv6.MessageTypeRenew {
			t.Errorf("type = %s, want RENEW (must not SOLICIT)", msg.MessageType)
		}
		if msg.Options.ServerID() == nil {
			t.Error("RENEW must include the granting server's DUID")
		}
		if msg.Options.OneIANA() == nil {
			t.Error("RENEW must echo the held IA_NA")
		}
		if msg.Options.OneIAPD() == nil {
			t.Error("RENEW must echo the held IA_PD")
		}
	})

	t.Run("rebind omits server-id", func(t *testing.T) {
		msg, err := buildV6RenewMessage(hw, prev, prevPDs, true, nil)
		if err != nil {
			t.Fatal(err)
		}
		if msg.MessageType != dhcpv6.MessageTypeRebind {
			t.Errorf("type = %s, want REBIND", msg.MessageType)
		}
		if msg.Options.ServerID() != nil {
			t.Error("REBIND must NOT include a server DUID")
		}
		if msg.Options.OneIANA() == nil {
			t.Error("REBIND must echo the held IA_NA")
		}
	})
}

// TestRunDHCPv4RenewUsesRenewNotDiscover drives the real runDHCPv4 state
// machine through the exchange/timer seams and asserts the RFC sequence:
// acquire (DISCOVER) → renew → renew → rebind → acquire (after both renew
// and rebind fail). The T2 timeout starts a fresh acquire while the current
// lease remains active until replacement or its absolute expiry. Reverting
// T1/T2 to a full DORA (exchangeAcquire) turns this RED.
func TestRunDHCPv4RenewUsesRenewNotDiscover(t *testing.T) {
	leaseA := &Lease{
		Interface: "wan0",
		Family:    AFInet,
		Address:   netip.MustParsePrefix("192.0.2.50/24"),
		serverID:  netip.MustParseAddr("192.0.2.1"),
		LeaseTime: 100 * time.Second,
		Obtained:  time.Now(),
	}

	type call struct {
		mode     dhcpExchangeMode
		prevAddr netip.Prefix
	}
	var calls []call

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := &Manager{
		leases:       map[clientKey]*Lease{},
		delegatedPDs: map[string][]DelegatedPrefix{},
		v4opts:       map[string]*DHCPv4Options{"wan0": {}},
		afterForTest: immediateAfter,
	}
	m.doV4ExchangeForTest = func(_ context.Context, _ string, mode dhcpExchangeMode, prev *Lease) (*Lease, error) {
		c := call{mode: mode}
		if prev != nil {
			c.prevAddr = prev.Address
		}
		calls = append(calls, c)
		switch len(calls) {
		case 1: // initial acquire
			return leaseA, nil
		case 2: // T1 renew — succeeds, returns the SAME lease (no churn)
			return leaseA, nil
		case 3: // T1 renew on next cycle — fails
			return nil, context.DeadlineExceeded
		case 4: // T2 rebind — fails; the client re-acquires before expiry
			return nil, context.DeadlineExceeded
		default: // first post-T2 re-acquire: stop the loop
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

	wantModes := []dhcpExchangeMode{exchangeAcquire, exchangeRenew, exchangeRenew, exchangeRebind, exchangeAcquire}
	if len(calls) != len(wantModes) {
		t.Fatalf("got %d exchanges, want %d: %+v", len(calls), len(wantModes), calls)
	}
	for i, want := range wantModes {
		if calls[i].mode != want {
			t.Errorf("exchange %d mode = %s, want %s", i, calls[i].mode, want)
		}
	}
	// Key anti-regression: T1 is a RENEW, not a DISCOVER, and it operates
	// on the held lease.
	if calls[1].mode != exchangeRenew {
		t.Fatalf("T1 ran %s, want renew (full-DORA-on-renew regression)", calls[1].mode)
	}
	if calls[1].prevAddr != leaseA.Address {
		t.Errorf("T1 renew prev address = %s, want held %s", calls[1].prevAddr, leaseA.Address)
	}
	// The post-T2 path is a full acquire with no prior-lease argument.
	if calls[4].mode != exchangeAcquire || calls[4].prevAddr.IsValid() {
		t.Errorf("post-T2 acquire = %s prev=%s, want acquire with nil prev", calls[4].mode, calls[4].prevAddr)
	}
	// The held lease is preserved across the successful renew (never
	// deleted/churned by the renewal path).
	if got := m.LeaseFor("wan0", AFInet); got == nil || got.Address != leaseA.Address {
		t.Errorf("lease after renew = %v, want preserved %s", got, leaseA.Address)
	}
}

// TestRunDHCPv6RenewUsesRenewNotSolicit is the DHCPv6 analogue: T1 must
// RENEW and T2 must REBIND; a T2 timeout begins a fresh Solicit while the
// prior binding is retained until replacement or its absolute expiry.
func TestRunDHCPv6RenewUsesRenewNotSolicit(t *testing.T) {
	leaseA := &Lease{
		Interface: "wan0",
		Family:    AFInet6,
		Address:   netip.MustParsePrefix("2001:db8::5/128"),
		LeaseTime: 100 * time.Second,
		Obtained:  time.Now(),
	}

	var modes []dhcpExchangeMode

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := &Manager{
		leases:               map[clientKey]*Lease{},
		delegatedPDs:         map[string][]DelegatedPrefix{},
		v6opts:               map[string]*DHCPv6Options{"wan0": {}},
		afterForTest:         immediateAfter,
		waitLinkLocalForTest: func(context.Context, string, time.Duration) error { return nil },
	}
	m.doV6ExchangeForTest = func(_ context.Context, _ string, mode dhcpExchangeMode, _ *Lease, _ []DelegatedPrefix) (*dhcpv6Result, error) {
		modes = append(modes, mode)
		switch len(modes) {
		case 1:
			return &dhcpv6Result{lease: leaseA}, nil
		case 2:
			return &dhcpv6Result{lease: leaseA}, nil // T1 renew ok
		case 3:
			return nil, context.DeadlineExceeded // T1 renew fails
		case 4:
			return nil, context.DeadlineExceeded // T2 rebind fails
		default:
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

	want := []dhcpExchangeMode{exchangeAcquire, exchangeRenew, exchangeRenew, exchangeRebind, exchangeAcquire}
	if len(modes) != len(want) {
		t.Fatalf("got %d exchanges, want %d: %v", len(modes), len(want), modes)
	}
	for i, w := range want {
		if modes[i] != w {
			t.Errorf("exchange %d = %s, want %s", i, modes[i], w)
		}
	}
	if modes[1] != exchangeRenew {
		t.Fatalf("T1 ran %s, want renew (full-Solicit-on-renew regression)", modes[1])
	}
	if got := m.LeaseFor("wan0", AFInet6); got == nil || got.Address != leaseA.Address {
		t.Errorf("lease after renew = %v, want preserved %s", got, leaseA.Address)
	}
}

// TestRunDHCPv4RenewingNAKRestartsDiscover pins RFC 2131 §4.4.5 (#3956): a
// DHCPNAK received in the RENEWING state must abandon the address and
// return to INIT (fresh DISCOVER) IMMEDIATELY — it must NOT fall through
// to the T2 REBINDING attempt. Reverting the fix (treating a NAK like a
// renew timeout) turns this RED: the third exchange would be a REBIND and
// the revoked lease would still be recorded.
func TestRunDHCPv4RenewingNAKRestartsDiscover(t *testing.T) {
	leaseA := &Lease{
		Interface: "wan0",
		Family:    AFInet,
		Address:   netip.MustParsePrefix("192.0.2.50/24"),
		Gateway:   netip.MustParseAddr("192.0.2.1"),
		serverID:  netip.MustParseAddr("192.0.2.1"),
		LeaseTime: 100 * time.Second,
		Obtained:  time.Now(),
	}

	var modes []dhcpExchangeMode
	var leaseAtRestart *Lease
	gwHooks := 0

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := &Manager{
		leases:          map[clientKey]*Lease{},
		delegatedPDs:    map[string][]DelegatedPrefix{},
		v4opts:          map[string]*DHCPv4Options{"wan0": {}},
		afterForTest:    immediateAfter,
		onGatewayChange: func() { gwHooks++ },
	}
	m.doV4ExchangeForTest = func(_ context.Context, _ string, mode dhcpExchangeMode, _ *Lease) (*Lease, error) {
		modes = append(modes, mode)
		switch len(modes) {
		case 1: // initial acquire
			return leaseA, nil
		case 2: // T1 renew — server NAKs (lease revoked)
			return nil, fmt.Errorf("DHCPv4 renew: %w", errDHCPNAK)
		default: // must be a fresh DISCOVER, not a REBIND
			leaseAtRestart = m.LeaseFor("wan0", AFInet)
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

	want := []dhcpExchangeMode{exchangeAcquire, exchangeRenew, exchangeAcquire}
	if len(modes) != len(want) {
		t.Fatalf("got %d exchanges, want %d: %v", len(modes), len(want), modes)
	}
	for i, w := range want {
		if modes[i] != w {
			t.Errorf("exchange %d = %s, want %s", i, modes[i], w)
		}
	}
	// The anti-regression: the exchange AFTER the RENEWING NAK is a fresh
	// DISCOVER (INIT restart), NOT a REBIND (waiting for T2).
	if modes[2] != exchangeAcquire {
		t.Fatalf("post-NAK exchange = %s, want acquire (NAK must not wait for T2)", modes[2])
	}
	// The revoked lease must be gone by the time the client re-DISCOVERs.
	if leaseAtRestart != nil {
		t.Errorf("lease still recorded after RENEWING NAK = %v, want removed", leaseAtRestart)
	}
	if got := m.LeaseFor("wan0", AFInet); got != nil {
		t.Errorf("lease after RENEWING NAK = %v, want nil (deconfigured)", got)
	}
	// Deconfigure must fire the gateway-change hook so the ip-monitoring
	// overlay withdraws the resolved next-hop (once for the initial commit,
	// once for the abandon).
	if gwHooks < 2 {
		t.Errorf("onGatewayChange fired %d times, want >=2 (commit + abandon)", gwHooks)
	}
}

// TestRunDHCPv4RebindingNAKRestartsDiscover pins the REBINDING half of
// RFC 2131 §4.4.5 (#3956): a renew TIMEOUT at T1 still falls through to
// the T2 REBINDING attempt, but a DHCPNAK there abandons the address and
// restarts DISCOVER from INIT. Reverting the fix keeps the revoked lease
// recorded across the re-acquire.
func TestRunDHCPv4RebindingNAKRestartsDiscover(t *testing.T) {
	leaseA := &Lease{
		Interface: "wan0",
		Family:    AFInet,
		Address:   netip.MustParsePrefix("192.0.2.50/24"),
		Gateway:   netip.MustParseAddr("192.0.2.1"),
		serverID:  netip.MustParseAddr("192.0.2.1"),
		LeaseTime: 100 * time.Second,
		Obtained:  time.Now(),
	}

	var modes []dhcpExchangeMode
	var leaseAtRestart *Lease

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := &Manager{
		leases:       map[clientKey]*Lease{},
		delegatedPDs: map[string][]DelegatedPrefix{},
		v4opts:       map[string]*DHCPv4Options{"wan0": {}},
		afterForTest: immediateAfter,
	}
	m.doV4ExchangeForTest = func(_ context.Context, _ string, mode dhcpExchangeMode, _ *Lease) (*Lease, error) {
		modes = append(modes, mode)
		switch len(modes) {
		case 1: // initial acquire
			return leaseA, nil
		case 2: // T1 renew — genuine TIMEOUT, must fall through to T2
			return nil, context.DeadlineExceeded
		case 3: // T2 rebind — server NAKs (lease revoked)
			return nil, fmt.Errorf("DHCPv4 rebind: %w", errDHCPNAK)
		default: // must be a fresh DISCOVER
			leaseAtRestart = m.LeaseFor("wan0", AFInet)
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

	want := []dhcpExchangeMode{exchangeAcquire, exchangeRenew, exchangeRebind, exchangeAcquire}
	if len(modes) != len(want) {
		t.Fatalf("got %d exchanges, want %d: %v", len(modes), len(want), modes)
	}
	for i, w := range want {
		if modes[i] != w {
			t.Errorf("exchange %d = %s, want %s", i, modes[i], w)
		}
	}
	// A timeout at T1 still reaches REBIND (unchanged from prior behavior).
	if modes[2] != exchangeRebind {
		t.Fatalf("post-T1-timeout exchange = %s, want rebind", modes[2])
	}
	// The REBINDING NAK abandons the lease before the re-DISCOVER.
	if leaseAtRestart != nil {
		t.Errorf("lease still recorded after REBINDING NAK = %v, want removed", leaseAtRestart)
	}
	if got := m.LeaseFor("wan0", AFInet); got != nil {
		t.Errorf("lease after REBINDING NAK = %v, want nil (deconfigured)", got)
	}
}

// mustV4ACK builds a minimal DHCPv4 ACK carrying yourIP and, when non-nil,
// the given subnet mask (option 1). A nil mask omits the option so the
// leaseFromACKv4 fallback path is exercised.
func mustV4ACK(t *testing.T, yourIP net.IP, mask net.IPMask) *dhcpv4.DHCPv4 {
	t.Helper()
	mods := []dhcpv4.Modifier{
		dhcpv4.WithMessageType(dhcpv4.MessageTypeAck),
		dhcpv4.WithYourIP(yourIP),
	}
	if mask != nil {
		mods = append(mods, dhcpv4.WithNetmask(mask))
	}
	ack, err := dhcpv4.New(mods...)
	if err != nil {
		t.Fatalf("build DHCPv4 ACK: %v", err)
	}
	return ack
}

// TestLeaseFromACKv4RejectsDegenerateMask locks in the #4101 fix: a rogue or
// broken server that ACKs with a zero (0.0.0.0 → /0) or non-contiguous subnet
// mask must NOT yield a YourIP/0 lease — the kernel would install an on-link
// 0.0.0.0/0 connected route and blackhole all IPv4 forwarding. leaseFromACKv4
// must reject such an ACK (error, no lease). RED-on-revert: without the guard,
// the zero/non-contiguous cases parse to a valid Lease at 192.0.2.50/0.
func TestLeaseFromACKv4RejectsDegenerateMask(t *testing.T) {
	yourIP := net.ParseIP("192.0.2.50")

	tests := []struct {
		name     string
		mask     net.IPMask
		wantErr  bool
		wantOnes int // expected prefix bits when accepted
	}{
		{
			name:    "zero mask 0.0.0.0 (/0) rejected",
			mask:    net.IPMask{0, 0, 0, 0},
			wantErr: true,
		},
		{
			name:    "non-contiguous mask 255.255.0.255 rejected",
			mask:    net.IPMask{255, 255, 0, 255},
			wantErr: true,
		},
		{
			name:     "normal /24 accepted",
			mask:     net.IPMask{255, 255, 255, 0},
			wantErr:  false,
			wantOnes: 24,
		},
		{
			name:     "host /32 accepted",
			mask:     net.IPMask{255, 255, 255, 255},
			wantErr:  false,
			wantOnes: 32,
		},
		{
			name:     "point-to-point /31 accepted",
			mask:     net.IPMask{255, 255, 255, 254},
			wantErr:  false,
			wantOnes: 31,
		},
		{
			name:     "absent mask falls back to /24",
			mask:     nil,
			wantErr:  false,
			wantOnes: 24,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ack := mustV4ACK(t, yourIP, tc.mask)
			lease, err := leaseFromACKv4("wan0", ack)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("leaseFromACKv4 accepted degenerate mask; got lease %v, want error (no YourIP/0)",
						lease.Address)
				}
				if lease != nil {
					t.Errorf("lease returned alongside error = %v, want nil", lease.Address)
				}
				return
			}
			if err != nil {
				t.Fatalf("leaseFromACKv4 rejected a valid mask: %v", err)
			}
			if got := lease.Address.Bits(); got != tc.wantOnes {
				t.Errorf("lease prefix = /%d, want /%d", got, tc.wantOnes)
			}
			if lease.Address.Bits() == 0 {
				t.Errorf("lease installed YourIP/0 (%v) — would blackhole IPv4", lease.Address)
			}
		})
	}
}
