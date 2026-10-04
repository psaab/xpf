package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #5644 (M37): cold boot with BOTH nft tables absent must not publish host
// service / VIP / HA-ready over an UNENFORCED host input path. On COLD BOOT
// there is no prior host-inbound table to retain, so a failed install (the boot
// apply only logs+discards the error) would leave host-bound services reachable
// with no host-inbound default-deny (fail-open). The fix installs a fail-closed
// DENY-ALL fence when the real ruleset fails to load and no enforcement table
// exists yet, so enforcement is established (fail-closed) before any host
// service is exposed. These are the fail-on-revert proofs: neutralize the fence
// (drop the installHostInboundColdBootFence call, or its emitted drops) and the
// cold-boot assertions go RED.

// TestColdBootHostInboundInstallFailureInstallsFence is the primary #5644
// fail-on-revert proof: at cold boot, when the real host-inbound `nft -f -`
// install fails and no enforcement table has ever loaded this boot, a fail-closed
// DENY-ALL fence MUST be installed so host-bound services stay fenced. It also
// asserts the commit still fails (the error is surfaced) so the retry/re-render
// path is driven. Reverting the fence makes the fence-installed assertion and the
// hostInboundEnforced assertion RED.
func TestColdBootHostInboundInstallFailureInstallsFence(t *testing.T) {
	cfg := hostInboundTestConfig()

	injected := errors.New("nftables: rule load failed")
	var hostInboundCalls, fenceCalls int
	var fenceSpec xnft.FenceSpec
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error {
			hostInboundCalls++
			return injected // real ruleset install fails (injected cold-boot install failure)
		},
		coldBootFence: func(spec xnft.FenceSpec) error {
			fenceCalls++
			fenceSpec = spec
			return nil // the fence installs
		},
	}
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	// Cold boot: no enforcement table has ever loaded.
	if d.hostInboundEnforced.Load() {
		t.Fatal("precondition: hostInboundEnforced must start false (cold boot)")
	}

	err := d.applyHostInboundFilter(cfg)

	// The commit must still fail closed (the real ruleset did not load).
	if err == nil {
		t.Fatal("cold-boot install failure must be surfaced as an error, got nil")
	}
	if !errors.Is(err, injected) {
		t.Errorf("returned error must wrap the netlink failure, got %v", err)
	}

	// A fence must have been installed (exactly one cold-boot fence install).
	if fenceCalls != 1 {
		t.Fatalf("cold-boot install failure must install exactly one fail-closed fence, got %d", fenceCalls)
	}
	if hostInboundCalls != 1 {
		t.Errorf("expected exactly one real host-inbound install attempt, got %d", hostInboundCalls)
	}

	// Enforcement is now established (via the fence) — a later day-2 failure is
	// retained by the atomic load and needs no fence.
	if !d.hostInboundEnforced.Load() {
		t.Error("hostInboundEnforced must be true after the fence installs (enforcement established)")
	}

	// The fence must DENY host services to the enforced zone's addresses (both
	// families) — the wan v4 + v6 firewall-local addresses appear in the fence's
	// DROP scope. (A FenceSpec structurally carries NO per-service accept, so the
	// "fence must not accept a service" fail-open is guaranteed by the type; the
	// exact drop-rule rendering is pinned by the PR-2 netlink builder + parity CI.)
	if !sliceContains(fenceViewAddrs(fenceSpec, false), "172.16.50.8") {
		t.Errorf("fence must fence the enforced wan v4 address 172.16.50.8:\n%+v", fenceSpec)
	}
	if !sliceContains(fenceViewAddrs(fenceSpec, true), "2001:db8:50::8") {
		t.Errorf("fence must fence the enforced wan v6 address 2001:db8:50::8:\n%+v", fenceSpec)
	}
}

// TestColdBootFenceIsLifelineSafe proves the cold-boot fence never denies a
// management / cluster-control lifeline address: fxp0 (mgmt) and em0 (control)
// are lifelines, so their addresses are excluded from the deny sets and must not
// appear in the fence. A fence that dropped a lifeline address could strand
// management or break HA. Reverting the lifeline exclusion (or fencing on
// lifeline addrs) makes this RED.
func TestColdBootFenceIsLifelineSafe(t *testing.T) {
	cfg := hostInboundTestConfig()
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	unzonedV4, unzonedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
	fence := buildHostInboundFencePayload(views, unzonedV4, unzonedV6, nil, nil, nil, nil, dhcpBackstopVRFLists{})

	// em0's cluster-control address must never be fenced (lifeline).
	if strings.Contains(fence, "10.99.0.1") {
		t.Errorf("fence must not deny the em0 cluster-control lifeline address:\n%s", fence)
	}
	// The enforced wan address must be fenced.
	if !strings.Contains(fence, "ip daddr 172.16.50.8 drop") {
		t.Errorf("fence must deny the enforced wan address:\n%s", fence)
	}
}

// TestColdBootFenceAdmitsMandatoryL3 proves the fence still admits return
// traffic and mandatory L3 control (established, raw ESP/AH, IPv6 ND, v4/v6
// PMTUD+error), so the deny-all fence does not black-hole core operation.
func TestColdBootFenceAdmitsMandatoryL3(t *testing.T) {
	cfg := hostInboundTestConfig()
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	unzonedV4, unzonedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
	fence := buildHostInboundFencePayload(views, unzonedV4, unzonedV6, nil, nil, nil, nil, dhcpBackstopVRFLists{})

	for _, want := range []string{
		"ct state established,related accept",
		"meta l4proto { 50, 51 } accept",
		"icmpv6 type { 133, 134, 135, 136, 137 } accept",
		"icmp type { destination-unreachable, time-exceeded, parameter-problem } accept",
	} {
		if !strings.Contains(fence, want) {
			t.Errorf("fence missing mandatory L3 admit %q\n---\n%s", want, fence)
		}
	}
}

// TestColdBootFenceAdmitsWireGuardPort proves that a responder-only tunnel's
// configured listen port remains available only on the address scope of its
// serving zone while the cold-boot fence is active.
func TestColdBootFenceAdmitsWireGuardPort(t *testing.T) {
	cfg := hostInboundWireGuardTestConfig()
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	fence := buildHostInboundFencePayload(views, nil, nil, cfg.WireGuardListenPorts(), cfg.WireGuardZonePorts(), nil, nil, dhcpBackstopVRFLists{})
	for _, want := range []string{
		"ip daddr 172.16.50.8 udp dport 51820 accept",
		"ip6 daddr 2001:db8:50::8 udp dport 51820 accept",
	} {
		if !strings.Contains(fence, want) {
			t.Errorf("fence must emit scoped WG accept %q:\n%s", want, fence)
		}
	}
	for _, line := range strings.Split(fence, "\n") {
		if strings.Contains(line, "udp dport 51820 accept") && !strings.Contains(line, "daddr") {
			t.Errorf("fence must not globally admit WG port 51820:\n%s", fence)
		}
	}
}

// TestDay2HostInboundInstallFailureNoFence proves the NORMAL (tables-present)
// path is unchanged: once a real host-inbound table has installed
// (hostInboundEnforced == true), a LATER failed install must NOT install a fence
// — the atomic `-f -` load already retains the prior table (fail-closed). Only
// the real payload is attempted; no fence is emitted. This is the no-regression
// guard: if the cold-boot fence were installed unconditionally it would clobber
// the retained day-2 table with a deny-all, so this goes RED.
func TestDay2HostInboundInstallFailureNoFence(t *testing.T) {
	cfg := hostInboundTestConfig()

	// First apply: real install succeeds → enforcement established.
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{} // all succeed
	d := &Daemon{}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("first (successful) apply: %v", err)
	}
	if !d.hostInboundEnforced.Load() {
		t.Fatal("hostInboundEnforced must be true after a successful real install")
	}

	// Second apply: real install fails. The prior table is retained by the atomic
	// load, and the desired coverage is unchanged (same config), so NEITHER the
	// cold-boot fence NOR the additive gap fence must be installed.
	injected := errors.New("nftables: transient failure")
	var hostInboundCalls, fenceCalls, gapCalls int
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { hostInboundCalls++; return injected },
		coldBootFence: func(xnft.FenceSpec) error {
			fenceCalls++
			t.Errorf("day-2 failure must NOT install a cold-boot fence")
			return nil
		},
		gapFence: func(xnft.GapFenceSpec) error {
			gapCalls++
			t.Errorf("day-2 failure with full coverage must NOT install a gap fence")
			return nil
		},
	}
	defer func() { nftInstaller = orig }()

	err := d.applyHostInboundFilter(cfg)
	if err == nil {
		t.Fatal("day-2 install failure must still be surfaced as an error")
	}
	if !errors.Is(err, injected) {
		t.Errorf("returned error must wrap the netlink failure, got %v", err)
	}
	if hostInboundCalls != 1 {
		t.Errorf("day-2 failure must attempt exactly one real install, got %d", hostInboundCalls)
	}
	if fenceCalls != 0 || gapCalls != 0 {
		t.Errorf("day-2 failure must install no fence (cold-boot=%d, gap=%d)", fenceCalls, gapCalls)
	}
}

// TestColdBootFenceCatastrophicFailureSurfaced proves that when the real install
// AND the fence both fail (nft itself broken), both errors are surfaced so the
// commit fails closed and the operator sees the fail-open guard fire.
func TestColdBootFenceCatastrophicFailureSurfaced(t *testing.T) {
	cfg := hostInboundTestConfig()

	realErr := errors.New("nftables: rule load failed")
	fenceErr := errors.New("nftables: kernel refused fence")
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		hostInbound:   func(xnft.HostInboundSpec) error { return realErr },
		coldBootFence: func(xnft.FenceSpec) error { return fenceErr },
	}
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	err := d.applyHostInboundFilter(cfg)
	if err == nil {
		t.Fatal("catastrophic cold-boot failure must be surfaced as an error")
	}
	if !errors.Is(err, realErr) || !errors.Is(err, fenceErr) {
		t.Errorf("error must join both the real and fence failures, got %v", err)
	}
	// The fence never loaded, so enforcement is NOT established.
	if d.hostInboundEnforced.Load() {
		t.Error("hostInboundEnforced must stay false when the fence also fails")
	}
}

// TestColdBootCatalogFenceAddsAddressGap5759 proves that an addressless ingress
// already has a catalog-multicast default-deny fence; when a DHCP address later
// appears, a separate additive gap fence covers that newly visible unicast
// destination without replacing the retained multicast fence. The DHCP assertion
// proves classification only; this invokes applyHostInboundFilter directly.
func TestColdBootCatalogFenceAddsAddressGap5759(t *testing.T) {
	unit := &config.InterfaceUnit{Number: 0, DHCP: true}
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"xpf5759wan": {
			Name:  "xpf5759wan",
			Units: map[int]*config.InterfaceUnit{0: unit},
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {
			Name:               "untrust",
			Interfaces:         []string{"xpf5759wan.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}
	cfg.Security.AddressBook = &config.AddressBook{Addresses: map[string]*config.Address{
		"bad-host": {Name: "bad-host", Value: "10.0.0.5/32"},
	}}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "untrust",
		ToZone:   "junos-host",
		Policies: []*config.Policy{{
			Name:   "block-bad-host",
			Action: config.PolicyDeny,
			Match: config.PolicyMatch{
				SourceAddresses: []string{"bad-host"},
				Applications:    []string{"any"},
			},
		}},
	}}

	d := &Daemon{}
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true, "fab0": true, "em0": true})
	if !d.dhcpLeaseChangeRequiresRecompile(cfg, false) {
		t.Fatal("fixture must be classified for full recompile; this does not prove the apply reaches host authorization")
	}

	assertProjection := func(wantV bool) {
		t.Helper()
		programs := dpuserspace.BuildJunosHostPrograms(cfg)
		if len(programs) != 1 {
			t.Fatalf("P = %d programs, want exactly 1", len(programs))
		}
		views := dpuserspace.BuildZoneHostInboundViews(cfg)
		gotV := hostInboundHasEnforceableView(views)
		if gotV != wantV {
			t.Fatalf("V = %t, want %t; views=%+v", gotV, wantV, views)
		}
		unzonedV4, unzonedV6 := dpuserspace.BuildUnzonedHostInboundAddrs(cfg)
		if len(unzonedV4) != 0 || len(unzonedV6) != 0 {
			t.Fatalf("U4/U6 must both be false, got v4=%v v6=%v", unzonedV4, unzonedV6)
		}
		gotD := gotV || len(unzonedV4) > 0 || len(unzonedV6) > 0
		if gotD != wantV {
			t.Fatalf("D = %t, want %t solely from V", gotD, wantV)
		}
	}
	assertProjection(true)
	if d.hostInboundEnforced.Load() {
		t.Fatal("precondition: hostInboundEnforced must start false")
	}

	injected := errors.New("nftables: issue 5759 real load failure")
	var realSpecs []xnft.HostInboundSpec
	var fenceSpecs []xnft.FenceSpec
	var gapSpecs []xnft.GapFenceSpec
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(spec xnft.HostInboundSpec) error {
			realSpecs = append(realSpecs, spec)
			return injected // the real ruleset always fails
		},
		coldBootFence: func(spec xnft.FenceSpec) error {
			fenceSpecs = append(fenceSpecs, spec)
			return nil // the multicast fence loads
		},
		gapFence: func(spec xnft.GapFenceSpec) error {
			gapSpecs = append(gapSpecs, spec)
			return nil
		},
	}
	defer func() { nftInstaller = orig }()

	// --- Apply 1: addressless ingress — the fence denies catalog multicast. ---
	err := d.applyHostInboundFilter(cfg)
	if !errors.Is(err, injected) {
		t.Fatalf("initial apply error = %v, want wrapped sentinel", err)
	}
	if !d.hostInboundEnforced.Load() {
		t.Fatal("addressless multicast fallback must establish scoped enforcement")
	}
	if len(realSpecs) != 1 || len(fenceSpecs) != 1 || len(gapSpecs) != 0 {
		t.Fatalf("apply 1 call counts: real=%d fence=%d gap=%d, want 1/1/0", len(realSpecs), len(fenceSpecs), len(gapSpecs))
	}
	// The real spec carries the junos-host iifname DENY for 10.0.0.5/32.
	if !hostInboundProgramHasSrc(realSpecs[0], "xpf5759wan", "10.0.0.5/32") {
		t.Fatalf("initial real spec missing the junos-host iifname deny for 10.0.0.5/32:\n%+v", realSpecs[0])
	}
	if len(fenceViewAddrs(fenceSpecs[0], false)) != 0 || len(fenceViewAddrs(fenceSpecs[0], true)) != 0 {
		t.Fatalf("initial fallback must have no address-scoped drop:\n%+v", fenceSpecs[0])
	}
	if len(fenceSpecs[0].Views) != 1 || !sliceContains(fenceSpecs[0].Views[0].IngressNetdevs, "xpf5759wan") {
		t.Fatalf("addressless catalog fence lost the zone's ingress scope: %+v", fenceSpecs[0].Views)
	}
	payload := buildHostInboundFencePayload(dpuserspace.BuildZoneHostInboundViews(cfg), nil, nil, nil, nil, nil, nil, dhcpBackstopVRFLists{})
	wantMulticastDrop := `iifname "xpf5759wan" ip daddr ` + nftAddrSet(config.HostInboundMulticastGroupsForFamily("ip")) + " drop"
	if !strings.Contains(payload, wantMulticastDrop) {
		t.Fatalf("addressless fallback must deny catalog multicast on its ingress:\n%s", payload)
	}

	// --- Apply 2: an address appears — the multicast fence stays; a gap fence
	// covers the new v4 local destination without replacing the retained table. ---
	unit.Addresses = []string{"198.51.100.57/24"}
	assertProjection(true)
	err = d.applyHostInboundFilter(cfg)
	if !errors.Is(err, injected) {
		t.Fatalf("addressed apply error = %v, want wrapped sentinel", err)
	}
	if !d.hostInboundEnforced.Load() {
		t.Fatal("address-gap fallback must preserve established enforcement")
	}
	if len(realSpecs) != 2 || len(fenceSpecs) != 1 || len(gapSpecs) != 1 {
		t.Fatalf("apply 2 call counts: real=%d fence=%d gap=%d, want 2/1/1", len(realSpecs), len(fenceSpecs), len(gapSpecs))
	}
	// The addressed real spec still carries the program AND the appeared destination.
	if !hostInboundProgramHasSrc(realSpecs[1], "xpf5759wan", "10.0.0.5/32") {
		t.Fatalf("addressed real spec missing the junos-host iifname deny:\n%+v", realSpecs[1])
	}
	if !sliceContains(hostInboundViewAddrs(realSpecs[1], false), "198.51.100.57") {
		t.Fatalf("addressed real spec missing the appeared destination 198.51.100.57:\n%+v", realSpecs[1])
	}
	// The additive gap fences EXACTLY the appeared v4 address, nothing v6.
	if !sliceContains(gapSpecs[0].UncoveredV4, "198.51.100.57") {
		t.Fatalf("address-gap fallback must include 198.51.100.57, got %+v", gapSpecs[0])
	}
	if len(gapSpecs[0].UncoveredV6) != 0 {
		t.Fatalf("address-gap fallback must not fence a v6 address:\n%+v", gapSpecs[0])
	}
}

// TestColdBootFenceUnzonedDropPublishesState5759 proves the independent U4 and
// U6 terms of D. Each row uses a fresh daemon and a successful one-family
// fallback transaction with nil views, so publication derives solely from the
// selected unzoned-address term.
func TestColdBootFenceUnzonedDropPublishesState5759(t *testing.T) {
	tests := []struct {
		name      string
		views     []dpuserspace.ZoneHostInboundView
		unzonedV4 []string
		unzonedV6 []string
	}{
		{
			name:      "ipv4",
			unzonedV4: []string{"192.0.2.57"},
		},
		{
			name:      "ipv6",
			unzonedV6: []string{"2001:db8:5759::57"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &Daemon{}
			v := hostInboundHasEnforceableView(tc.views)
			u4 := len(tc.unzonedV4) > 0
			u6 := len(tc.unzonedV6) > 0
			if v {
				t.Fatal("V must be false for nil views")
			}
			if tc.name == "ipv4" && (!u4 || u6) {
				t.Fatalf("ipv4 U terms = U4:%t U6:%t, want true/false", u4, u6)
			}
			if tc.name == "ipv6" && (u4 || !u6) {
				t.Fatalf("ipv6 U terms = U4:%t U6:%t, want false/true", u4, u6)
			}
			if dValue := v || u4 || u6; !dValue {
				t.Fatal("D must be true solely from the selected U term")
			}
			if d.hostInboundEnforced.Load() {
				t.Fatal("fresh daemon state must be false")
			}

			calls := 0
			var fenceSpec xnft.FenceSpec
			orig := nftInstaller
			nftInstaller = &fakeNftInstaller{
				coldBootFence: func(spec xnft.FenceSpec) error {
					calls++
					fenceSpec = spec
					return nil
				},
			}
			defer func() { nftInstaller = orig }()

			sets := dpuserspace.FenceAddrSets{
				Views: tc.views, UnzonedV4: tc.unzonedV4, UnzonedV6: tc.unzonedV6,
			}
			if err := d.installHostInboundColdBootFence(sets, nil, nil); err != nil {
				t.Fatalf("installHostInboundColdBootFence: %v", err)
			}
			if calls != 1 {
				t.Fatalf("fence install call count = %d, want exactly 1", calls)
			}
			// The fence scopes EXACTLY the selected-family unzoned address and nothing
			// in the opposite family (a FenceSpec structurally carries no iifname /
			// counter / service accept). Views are empty in this table-driven case.
			wantAddrs, wantV6 := tc.unzonedV4, false
			if tc.name == "ipv6" {
				wantAddrs, wantV6 = tc.unzonedV6, true
			}
			if got := fenceViewAddrs(fenceSpec, wantV6); len(got) != 1 || got[0] != wantAddrs[0] {
				t.Fatalf("fence must scope exactly %v, got %v:\n%+v", wantAddrs, got, fenceSpec)
			}
			if got := fenceViewAddrs(fenceSpec, !wantV6); len(got) != 0 {
				t.Fatalf("fence must not scope the opposite family, got %v:\n%+v", got, fenceSpec)
			}
			if !d.hostInboundEnforced.Load() {
				t.Fatal("successful U-only fallback must publish true")
			}
		})
	}
}
