package daemon

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// pdOnlyZonedConfig16785: PD-only DHCPv6 WAN in untrust (ssh) plus an
// addressed LAN zone permitting ssh — the #16785 defect shape.
func pdOnlyZonedConfig16785(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-1": {Name: "ge-0-0-1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCPv6: true, DHCPv6Client: &config.DHCPv6ClientConfig{
				ClientType: "stateful", ClientIATypes: []string{"ia-pd"},
			}},
		}},
		"ge-0-0-2": {Name: "ge-0-0-2", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.9.0.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {Name: "untrust", Interfaces: []string{"ge-0-0-1.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
		"trust": {Name: "trust", Interfaces: []string{"ge-0-0-2.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh", "ping"}}},
	}
	return cfg
}

func iaNAZonedConfig16785(t *testing.T) *config.Config {
	t.Helper()
	cfg := pdOnlyZonedConfig16785(t)
	cfg.Interfaces.Interfaces["ge-0-0-1"].Units[0].DHCPv6Client.ClientIATypes = []string{"ia-na"}
	return cfg
}

func neverLeasingZonedConfig16785(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-3": {Name: "ge-0-0-3", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true, DHCPv6: true},
		}},
		"ge-0-0-2": {Name: "ge-0-0-2", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.9.0.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {Name: "untrust", Interfaces: []string{"ge-0-0-3.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
		"trust": {Name: "trust", Interfaces: []string{"ge-0-0-2.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh", "ping"}}},
	}
	return cfg
}

func barrierRemoves16785(fake *fakeNftInstaller) int {
	n := 0
	for _, c := range fake.earlyInputBarrierCalls {
		if c == "remove" {
			n++
		}
	}
	return n
}

// withLANRow16785 scripts the handoff re-sample so the addressed LAN
// unit's static address is visible (BuildInterfaceSnapshots reads the
// kernel, which has no such address in the sandbox).
func withLANRow16785(t *testing.T) []dpuserspace.InterfaceSnapshot {
	t.Helper()
	orig := sampleHostInboundSnapshots
	t.Cleanup(func() { sampleHostInboundSnapshots = orig })
	snaps := []dpuserspace.InterfaceSnapshot{
		{
			Name: "ge-0-0-1.0", Zone: "untrust", IsUnit: true, LinuxName: "ge-0-0-1",
			Addresses: []dpuserspace.InterfaceAddressSnapshot{
				{Family: "inet6", Address: "fe80::1/64", Scope: 253},
			},
		},
		{
			Name: "ge-0-0-2.0", Zone: "trust", IsUnit: true, LinuxName: "ge-0-0-2",
			Addresses: []dpuserspace.InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.9.0.1/24"},
			},
		},
	}
	sampleHostInboundSnapshots = func(cfg *config.Config) []dpuserspace.InterfaceSnapshot {
		return snaps
	}
	return snaps
}

// TestEarlyInputPDOnlyZonedHandsOff16785 pins the PD-only defect row: a
// successful PD-only lease never installs a WAN address, so the zoned
// inet6 family must not be pending and the first apply hands off.
// FAIL-ON-REVERT: restoring the `(DHCPv6 || DHCPv6Client != nil)` pending
// test without the address-expectation gate retains the barrier here
// (removes=0, handoffDone=false) while the apply returns nil.
func TestEarlyInputPDOnlyZonedHandsOff16785(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	fake := &fakeNftInstaller{}
	nftInstaller = fake
	snaps := withLANRow16785(t)
	cfg := pdOnlyZonedConfig16785(t)
	if hostInboundHasPendingEnforcingIntentFromSnapshots(cfg, snaps) {
		t.Fatal("PD-only zoned unit still reads pending; the handoff half would be vacuous")
	}
	// The PD-only unit must also carry no v6 backstop drop that would
	// blanket-drop its link-local host traffic forever.
	var spec xnft.HostInboundSpec
	fake.hostInbound = func(s xnft.HostInboundSpec) error { spec = s; return nil }
	d := &Daemon{}
	for i := range 3 {
		if err := d.applyHostInboundFilter(cfg); err != nil {
			t.Fatalf("apply %d: %v", i, err)
		}
	}
	// Post-handoff applies remove idempotently; the defect shape is
	// ZERO removes, so at least one is the precise assertion.
	if got := barrierRemoves16785(fake); got < 1 {
		t.Fatalf("barrier calls = %v, want at least one handoff remove", fake.earlyInputBarrierCalls)
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("PD-only zoned apply must mark handoff done")
	}
	if len(spec.UnleasedV6) != 0 {
		t.Fatalf("PD-only spec UnleasedV6 = %v, want none", spec.UnleasedV6)
	}
	if st := d.HostInboundApplied(); st.BarrierRetained {
		t.Fatalf("applied state = %+v, want barrier not retained", st)
	}
}

// TestEarlyInputNeverLeasingZonedBound16785 pins the never-leasing rows:
// an address-expecting zoned unit (ia-na, or bare dhcp+dhcpv6) retains
// the barrier within the bound — with BarrierRetained surfaced — and
// hands off once the bound expires, without any lease landing.
// FAIL-ON-REVERT: removing the bound leaves removes=0 after expiry.
func TestEarlyInputNeverLeasingZonedBound16785(t *testing.T) {
	orig := nftInstaller
	origBound := earlyInputPendingHandoffBound
	t.Cleanup(func() { nftInstaller = orig; earlyInputPendingHandoffBound = origBound })
	earlyInputPendingHandoffBound = time.Minute

	for _, tc := range []struct {
		name string
		cfg  func(*testing.T) *config.Config
	}{
		{"ia-na never leases", iaNAZonedConfig16785},
		{"bare dhcp never leases", neverLeasingZonedConfig16785},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeNftInstaller{}
			nftInstaller = fake
			snaps := withLANRow16785(t)
			cfg := tc.cfg(t)
			if !hostInboundHasPendingEnforcingIntentFromSnapshots(cfg, snaps) {
				t.Fatal("fixture has no pending intent; retention half would be vacuous")
			}
			now := time.Unix(1700000000, 0)
			d := &Daemon{}
			d.earlyInputBarrierRetainedNowFn = func() time.Time { return now }
			// Within bound: retained, no remove, surfaced.
			if err := d.applyHostInboundFilter(cfg); err != nil {
				t.Fatalf("within-bound apply: %v", err)
			}
			if got := barrierRemoves16785(fake); got != 0 {
				t.Fatalf("within-bound barrier calls = %v, want no remove", fake.earlyInputBarrierCalls)
			}
			if d.earlyInputHandoffDone.Load() {
				t.Fatal("within-bound apply must not mark handoff done")
			}
			st := d.HostInboundApplied()
			if !st.BarrierRetained || st.BarrierPendingDetail == "" {
				t.Fatalf("within-bound applied = %+v, want barrier retained with detail", st)
			}
			if !st.Current() {
				t.Fatalf("within-bound applied = %+v, want Current real table (barrier is separate)", st)
			}
			// Still within bound on a second apply: hold start must not reset.
			now = now.Add(30 * time.Second)
			if err := d.applyHostInboundFilter(cfg); err != nil {
				t.Fatalf("second within-bound apply: %v", err)
			}
			if got := barrierRemoves16785(fake); got != 0 {
				t.Fatalf("second within-bound barrier calls = %v, want no remove", fake.earlyInputBarrierCalls)
			}
			// Past bound (from FIRST retention): hands off.
			now = now.Add(31 * time.Second)
			if err := d.applyHostInboundFilter(cfg); err != nil {
				t.Fatalf("expired apply: %v", err)
			}
			if got := barrierRemoves16785(fake); got != 1 {
				t.Fatalf("expired barrier calls = %v, want one remove", fake.earlyInputBarrierCalls)
			}
			if !d.earlyInputHandoffDone.Load() {
				t.Fatal("expired apply must mark handoff done")
			}
			if st := d.HostInboundApplied(); st.BarrierRetained {
				t.Fatalf("expired applied = %+v, want barrier cleared", st)
			}
		})
	}
}
