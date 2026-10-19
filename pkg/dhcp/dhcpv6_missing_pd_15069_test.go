package dhcp

// #15069 (A39-01): a configured ia-pd delegation that is not held is
// never requested again while IA_NA keeps renewing.
//
// Defect (pre-fix): buildV6RenewMessage only echoes held PDs
// (if len(prevPDs) > 0 { WithIAPD(held...) }), and doDHCPv6 passes only
// the held set, so after a boot-time NoPrefixAvail, a refusal, a
// withdrawal, or a #14598 expiry prune the committed set is empty and
// every subsequent RENEW/REBIND carries no IA_PD at all. The IA_NA
// renews successfully forever, so the client never falls back to a
// fresh Solicit and the LAN IPv6 (RA prefix/SLAAC) stays absent until
// manual request dhcp renew or restart.
//
// Fix: buildV6RenewMessage now takes the configured IA types and the
// acquisition hint; when no PD is held but ia-pd is configured it
// emits an empty IA_PD (IAID {0,0,0,1}) carrying the hint, exactly as
// acquisition does. Held-PD echo, and the no-PD-configured shape, are
// unchanged.
//
// RED on revert: restoring the pre-fix builder (and dropping the new
// arguments) makes the renew/rebind builder below emit no IA_PD when
// nothing is held, so this file fails to compile / the IA_PD-present
// assertions fail; the run-loop test then never sees a PD-carrying
// reply committed. The no-ia-pd and held-PD controls stay GREEN under
// the revert, pinning that the fix adds no IA_PD where none was
// configured and never clobbers the held echo.

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

// missingPDLeaseA is the held IA_NA lease used by the builder and
// run-loop tests: an address is committed, no delegation is held.
func missingPDLeaseA() *Lease {
	return &Lease{
		Interface: "wan0",
		Family:    AFInet6,
		Address:   netip.MustParsePrefix("2606:4700::5/128"),
		LeaseTime: 100 * time.Second,
		Obtained:  time.Now(),
	}
}

// iapdWirePrefixLens returns the prefix-length of every IAPREFIX inside
// every IA_PD of msg, read from the serialised bytes (the byte the
// server parses), plus whether any IA_PD is present at all.
func iapdWirePrefixLens(t *testing.T, msg *dhcpv6.Message) (lens []int, sawIAPD bool) {
	t.Helper()
	raw := msg.ToBytes()
	decoded, err := dhcpv6.MessageFromBytes(raw)
	if err != nil {
		t.Fatalf("decode message: %v", err)
	}
	for _, opt := range decoded.Options.Options {
		pd, ok := opt.(*dhcpv6.OptIAPD)
		if !ok {
			continue
		}
		sawIAPD = true
		for _, p := range pd.Options.Prefixes() {
			if p.Prefix == nil {
				continue
			}
			ones, bits := p.Prefix.Mask.Size()
			if bits != 128 {
				t.Fatalf("IAPREFIX mask bits = %d, want 128", bits)
			}
			lens = append(lens, ones)
		}
	}
	return lens, sawIAPD
}

// hint56 is the acquisition PD hint for a /56: an IAPREFIX of ::/56,
// exactly what buildDHCPv6Modifiers builds for PDPrefLen 56 and what
// doDHCPv6 now passes to the renew builder when nothing is held.
var hint56 = &dhcpv6.OptIAPrefix{
	Prefix: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(56, 128)},
}

func TestBuildV6RenewMessageReRequestsMissingPD15069(t *testing.T) {
	hw, _ := net.ParseMAC("02:00:00:0a:0b:0c")
	serverDUID := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: hw}
	prev := missingPDLeaseA()
	prev.v6ServerDUID = serverDUID

	for _, tc := range []struct {
		name    string
		rebind  bool
		pdHint  *dhcpv6.OptIAPrefix
		wantLen []int // nil means: IA_PD present, no IAPREFIX hint
	}{
		{name: "renew with hint carries IA_PD hint", rebind: false, pdHint: hint56, wantLen: []int{56}},
		{name: "rebind with hint carries IA_PD hint", rebind: true, pdHint: hint56, wantLen: []int{56}},
		{name: "renew without hint carries empty IA_PD", rebind: false, pdHint: nil, wantLen: nil},
		{name: "rebind without hint carries empty IA_PD", rebind: true, pdHint: nil, wantLen: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := buildV6RenewMessage(hw, prev, nil, tc.rebind, nil, []string{"ia-na", "ia-pd"}, tc.pdHint)
			if err != nil {
				t.Fatal(err)
			}
			wantType := dhcpv6.MessageTypeRenew
			if tc.rebind {
				wantType = dhcpv6.MessageTypeRebind
			}
			if msg.MessageType != wantType {
				t.Errorf("type = %s, want %s", msg.MessageType, wantType)
			}
			if msg.Options.OneIANA() == nil {
				t.Error("must still echo the held IA_NA")
			}
			lens, sawIAPD := iapdWirePrefixLens(t, msg)
			if !sawIAPD {
				t.Fatalf("RENEW/REBIND with ia-pd configured and no PD held carries no IA_PD; " +
					"the missing delegation is never re-requested (#15069)")
			}
			if len(lens) != len(tc.wantLen) {
				t.Fatalf("IAPREFIX prefix-lengths = %v, want %v", lens, tc.wantLen)
			}
			for i, w := range tc.wantLen {
				if lens[i] != w {
					t.Errorf("IAPREFIX[%d] prefix-length = %d, want %d", i, lens[i], w)
				}
			}
			// The re-request must use the acquisition IAID so the
			// server matches the same IA_PD binding.
			if got := msg.Options.OneIAPD(); got == nil || got.IaId != ([4]byte{0, 0, 0, 1}) {
				t.Errorf("IA_PD = %v, want IAID {0,0,0,1}", got)
			}
		})
	}
}

// Control: ia-pd NOT configured — the renew/rebind must carry no IA_PD
// at all. The fix must not invent a delegation request.
func TestBuildV6RenewMessageNoPDConfigured15069(t *testing.T) {
	hw, _ := net.ParseMAC("02:00:00:0a:0b:0c")
	prev := missingPDLeaseA()

	for _, iaTypes := range [][]string{nil, {"ia-na"}} {
		for _, rebind := range []bool{false, true} {
			msg, err := buildV6RenewMessage(hw, prev, nil, rebind, nil, iaTypes, hint56)
			if err != nil {
				t.Fatal(err)
			}
			if _, saw := iapdWirePrefixLens(t, msg); saw {
				t.Errorf("iaTypes=%v rebind=%v: IA_PD present, want none (ia-pd not configured)", iaTypes, rebind)
			}
		}
	}
}

// Control: a held PD still echoes the held prefix, never the hint —
// the re-request arm must not replace or augment the held echo.
func TestBuildV6RenewMessageHeldPDStillEchoed15069(t *testing.T) {
	hw, _ := net.ParseMAC("02:00:00:0a:0b:0c")
	prev := missingPDLeaseA()
	held := []DelegatedPrefix{
		{Prefix: netip.MustParsePrefix("2001:db8:1000::/48"), PreferredLifetime: time.Hour, ValidLifetime: 2 * time.Hour},
	}

	msg, err := buildV6RenewMessage(hw, prev, held, false, nil, []string{"ia-na", "ia-pd"}, hint56)
	if err != nil {
		t.Fatal(err)
	}
	lens, saw := iapdWirePrefixLens(t, msg)
	if !saw {
		t.Fatal("held PD: no IA_PD, want echo of the held /48")
	}
	if len(lens) != 1 || lens[0] != 48 {
		t.Fatalf("IAPREFIX prefix-lengths = %v, want [48] (held echo, not the /56 hint)", lens)
	}
	pd := msg.Options.OneIAPD()
	if pd == nil {
		t.Fatal("OneIAPD nil")
	}
	prefixes := pd.Options.Prefixes()
	if len(prefixes) != 1 || prefixes[0].Prefix.String() != "2001:db8:1000::/48" {
		t.Errorf("echoed prefixes = %v, want [2001:db8:1000::/48]", prefixes)
	}
}

// TestRunDHCPv6MissingPDCommittedOnRenew15069 drives the real runDHCPv6
// loop: acquisition grants IA_NA but no PD (the boot-time NoPrefixAvail
// shape: a successful IA_NA reply whose IA_PD was refused — the run loop
// clears the empty reconciled set and committedPDs stays empty). The
// first RENEW's reply carries a live PD; the reconciled set must be
// committed without waiting for IA_NA expiry, so DelegatedPrefixes()
// shows it while the IA_NA lease is still the original one.
func TestRunDHCPv6MissingPDCommittedOnRenew15069(t *testing.T) {
	leaseA := missingPDLeaseA()
	livePD := DelegatedPrefix{
		Interface:         "wan0",
		Prefix:            netip.MustParsePrefix("2001:db8:1000::/48"),
		PreferredLifetime: 50 * time.Second,
		ValidLifetime:     100 * time.Second,
		Obtained:          time.Now(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := &Manager{
		leases:       map[clientKey]*Lease{},
		delegatedPDs: map[string][]DelegatedPrefix{},
		v6opts: map[string]*DHCPv6Options{"wan0": {
			IATypes: []string{"ia-na", "ia-pd"}}},
		afterForTest:         immediateAfter,
		waitLinkLocalForTest: func(context.Context, string, time.Duration) error { return nil },
	}

	var modes []dhcpExchangeMode
	var prevPDsSeen [][]DelegatedPrefix
	var during []DelegatedPrefix
	var duringLease *Lease
	m.doV6ExchangeForTest = func(_ context.Context, _ string, mode dhcpExchangeMode, _ *Lease, prevPDs []DelegatedPrefix) (*dhcpv6Result, error) {
		modes = append(modes, mode)
		prevPDsSeen = append(prevPDsSeen, prevPDs)
		switch len(modes) {
		case 1: // acquire: IA_NA only, PD refused (empty held set)
			return &dhcpv6Result{lease: leaseA}, nil
		case 2: // T1 RENEW reply now grants the PD
			return &dhcpv6Result{lease: leaseA, prefixes: []DelegatedPrefix{livePD}}, nil
		default: // next RENEW: snapshot the committed PD set, then stop
			during = m.DelegatedPrefixes()
			duringLease = m.LeaseFor("wan0", AFInet6)
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

	if len(modes) < 3 {
		t.Fatalf("got %d exchanges %v, want acquire + renew + renew", len(modes), modes)
	}
	if modes[1] != exchangeRenew {
		t.Fatalf("exchange 2 = %s, want renew (the missing PD must be re-requested on RENEW, #15069)", modes[1])
	}
	if len(prevPDsSeen[1]) != 0 {
		t.Errorf("first RENEW prevPDs = %+v, want empty (nothing held yet)", prevPDsSeen[1])
	}
	if len(prevPDsSeen[2]) != 1 || prevPDsSeen[2][0].Prefix != livePD.Prefix {
		t.Errorf("second RENEW prevPDs = %+v, want the PD granted on the first RENEW echoed back", prevPDsSeen[2])
	}
	got := during
	if len(got) != 1 || got[0].Prefix != livePD.Prefix {
		t.Fatalf("DelegatedPrefixes during next RENEW = %+v, want [%s] committed from the RENEW reply without IA_NA expiry (#15069)", got, livePD.Prefix)
	}
	if duringLease == nil || duringLease.Address != leaseA.Address {
		t.Errorf("lease during next RENEW = %v, want preserved %s", duringLease, leaseA.Address)
	}
}
