package daemon

import (
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #17049: stable RETH router link-local placement was implemented four
// times (install, remove, NA announce, host-inbound mirror) with different
// predicates. The fix adds the single definition
// pkg/config.Config.StableRethLinkLocalPlacements and makes every caller
// iterate it. This matrix test asserts, for each named cell, that
//
//	install netdevs == NA stable-LL netdevs == mirror IfRefs mapped through
//	config placement Netdevs == RA bind netdev
//
// (the RA bind netdev is placement.Netdev for the RA's unit; the RA cell
// additionally asserts buildRAConfigs binds the stable source there iff a
// placement exists).
//
// The matrix runs on hand-built *config.Config values shared verbatim with
// the userspace mirror (dpuserspace.StableRethLinkLocalTargetsForTest), so
// no configstore spelling can drift one side of the comparison. Outcomes
// below are the PRE-FIX behaviours noted per cell: the suite goes RED on
// the pre-fix tree wherever a cell records a divergence (the hand-built
// inputs bypass configstore, so the pre-fix lossy re-derivations — mirror
// DHCPv6Client term, install FamilyInet6/DHCPv6Client blindness, disabled
// skips — are exactly what the cells pin).

type placementCell17049 struct {
	name string
	cfg  *config.Config
	// raUnit is the unit the RA interface names (reth0.<raUnit>); -1 = no RA cell.
	raUnit int
	// wantIfRefs are mirror IfRefs (reth0.<unit>); wantNetdevs the matching
	// install/NA-stable set. Empty = no stable LL anywhere.
	wantIfRefs []string
	// wantRA is the expected buildRAConfigs SourceLinkLocal ("" = no RA
	// stable binding expected).
	wantRA string
	// wantNAConfigured are (netdev -> configured LL) the NA leg must also
	// announce (configured-link-local units, not stable placements).
	wantNAConfigured map[string]string
	// wantRemove is the full RemoveNetdevs sweep: bare member plus every
	// unit's VlanID netdev, regardless of placement predicates.
	wantRemove []string
}

func cellCfg17049(units map[int]*config.InterfaceUnit) *config.Config {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{ClusterID: 1}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0":    {Name: "reth0", RedundancyGroup: 1, Units: units},
		"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
		"ge-7/0/0": {Name: "ge-7/0/0", RedundantParent: "reth0"},
	}
	return cfg
}

func stable17049() string { return config.StableRethLinkLocal(1, 1).String() }

func placementCells17049() []placementCell17049 {
	stable := stable17049()
	return []placementCell17049{
		{
			name: "untagged-unit0-ll",
			cfg: cellCfg17049(map[int]*config.InterfaceUnit{
				0:  {Number: 0, Addresses: []string{"fe80::10:1/64", "2001:db8:0::1/64"}},
				50: {Number: 50, VlanID: 50, Addresses: []string{"2001:db8:50::1/64"}},
				60: {Number: 60, VlanID: 60, Addresses: []string{"fe80::60:1/64", "2001:db8:60::1/64"}},
				70: {Number: 70, VlanID: 70, Addresses: []string{"10.0.70.1/24"}},
			}),
			raUnit: 50, wantIfRefs: []string{"reth0.50"}, wantRA: stable,
			wantNAConfigured: map[string]string{"ge-0-0-0": "fe80::10:1", "ge-0-0-0.60": "fe80::60:1"},
			wantRemove:       []string{"ge-0-0-0", "ge-0-0-0.50", "ge-0-0-0.60", "ge-0-0-0.70"},
		},
		{
			name: "tagged-unit0-ll",
			cfg: cellCfg17049(map[int]*config.InterfaceUnit{
				0:  {Number: 0, VlanID: 100, Addresses: []string{"fe80::100:1/64", "2001:db8:100::1/64"}},
				50: {Number: 50, VlanID: 50, Addresses: []string{"2001:db8:50::1/64"}},
			}),
			raUnit: 50, wantIfRefs: []string{"reth0.50"}, wantRA: stable,
			wantNAConfigured: map[string]string{"ge-0-0-0.100": "fe80::100:1"},
			wantRemove:       []string{"ge-0-0-0", "ge-0-0-0.100", "ge-0-0-0.50"},
		},
		{
			name: "tagged-unit0-without-ll",
			cfg: cellCfg17049(map[int]*config.InterfaceUnit{
				0:  {Number: 0, VlanID: 100, Addresses: []string{"2001:db8:100::1/64"}},
				10: {Number: 10, VlanID: 10, Addresses: []string{"2001:db8:10::1/64"}},
			}),
			raUnit: 0, wantIfRefs: []string{"reth0.0", "reth0.10"}, wantRA: stable,
			wantRemove: []string{"ge-0-0-0", "ge-0-0-0.10", "ge-0-0-0.100"},
		},
		{
			// Pre-fix: daemon UnitHasIPv6 (addresses + DHCPv6 bool only)
			// missed DHCPv6Client, so install/NA had no unit-50 placement
			// while the mirror emitted reth0.50.
			name: "dhcpv6-client-unit",
			cfg: cellCfg17049(map[int]*config.InterfaceUnit{
				0:  {Number: 0, Addresses: []string{"2001:db8:0::1/64"}},
				50: {Number: 50, VlanID: 50, DHCPv6Client: &config.DHCPv6ClientConfig{ClientType: "stateful"}},
			}),
			raUnit: 50, wantIfRefs: []string{"reth0.0", "reth0.50"}, wantRA: stable,
			wantRemove: []string{"ge-0-0-0", "ge-0-0-0.50"},
		},
		{
			name: "disabled-unit",
			cfg: cellCfg17049(map[int]*config.InterfaceUnit{
				0:  {Number: 0, Addresses: []string{"2001:db8:0::1/64"}},
				50: {Number: 50, VlanID: 50, Disable: true, Addresses: []string{"2001:db8:50::1/64"}},
			}),
			raUnit: 0, wantIfRefs: []string{"reth0.0"}, wantRA: stable,
			wantRemove: []string{"ge-0-0-0", "ge-0-0-0.50"},
		},
		{
			name: "disabled-interface",
			cfg: func() *config.Config {
				c := cellCfg17049(map[int]*config.InterfaceUnit{
					0: {Number: 0, Addresses: []string{"2001:db8:0::1/64"}},
				})
				c.Interfaces.Interfaces["reth0"].Disable = true
				return c
			}(),
			raUnit: 0, wantIfRefs: nil, wantRA: "",
			wantRemove: []string{"ge-0-0-0"},
		},
		{
			// Pre-fix: daemon UnitHasIPv6 missed FamilyInet6, so an
			// addressless-but-inet6 unit got no install while the mirror
			// (addresses-only) also missed it; now both see it.
			name: "family-inet6-no-address-unit",
			cfg: cellCfg17049(map[int]*config.InterfaceUnit{
				0:  {Number: 0, FamilyInet6: true},
				50: {Number: 50, VlanID: 50, Addresses: []string{"2001:db8:50::1/64"}},
			}),
			raUnit: 50, wantIfRefs: []string{"reth0.0", "reth0.50"}, wantRA: stable,
			wantRemove: []string{"ge-0-0-0", "ge-0-0-0.50"},
		},
		{
			// RA on an IPv4-only unit (70) alongside a placement-bearing
			// sibling (unit 0): the RA's unit has NO placement, so the
			// stable source must NOT bind — a sibling placement does not
			// install the address on ge-0-0-0.70 and pkg/ra would fail
			// every NDP listen there (Rev18119 blocker).
			name: "ra-ipv4-only-unit-with-placement-sibling",
			cfg: cellCfg17049(map[int]*config.InterfaceUnit{
				0:  {Number: 0, Addresses: []string{"2001:db8:0::1/64"}},
				70: {Number: 70, VlanID: 70, Addresses: []string{"10.0.70.1/24"}},
			}),
			raUnit: 70, wantIfRefs: []string{"reth0.0"}, wantRA: "",
			wantRemove: []string{"ge-0-0-0", "ge-0-0-0.70"},
		},
		{
			// Control: same shape, RA on the placement-bearing unit
			// itself — the stable source DOES bind.
			name: "ra-on-placement-unit-control",
			cfg: cellCfg17049(map[int]*config.InterfaceUnit{
				0:  {Number: 0, Addresses: []string{"2001:db8:0::1/64"}},
				70: {Number: 70, VlanID: 70, Addresses: []string{"10.0.70.1/24"}},
			}),
			raUnit: 0, wantIfRefs: []string{"reth0.0"}, wantRA: stable,
			wantRemove: []string{"ge-0-0-0", "ge-0-0-0.70"},
		},
	}
}
func netdevsOf17049(placements []config.StableLLPlacement) []string {
	var out []string
	for _, p := range placements {
		out = append(out, p.Netdev)
	}
	sort.Strings(out)
	return out
}

func ifRefsOf17049(placements []config.StableLLPlacement) []string {
	var out []string
	for _, p := range placements {
		out = append(out, p.IfRef)
	}
	sort.Strings(out)
	return out
}

func equalStrs17049(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestStableRethPlacementMatrix17049 is the #17049 acceptance matrix: for
// every cell, install (addStableRethLinkLocal seams over placements),
// router-NA stable netdevs (directSendGARPs seams), the userspace mirror
// IfRefs mapped to netdevs, and the RA bind source all agree.
func TestStableRethPlacementMatrix17049(t *testing.T) {
	for _, cell := range placementCells17049() {
		t.Run(cell.name, func(t *testing.T) {
			cfg := cell.cfg
			stable := stable17049()

			placements := cfg.StableRethLinkLocalPlacements(1)
			installNetdevs := netdevsOf17049(placements)
			installIfRefs := ifRefsOf17049(placements)
			if !equalStrs17049(installIfRefs, cell.wantIfRefs) {
				t.Fatalf("placements IfRefs = %v, want %v", installIfRefs, cell.wantIfRefs)
			}

			// Mirror: exported test seam over the same cfg.
			targets := dpuserspace.StableRethLinkLocalTargetsForTest(cfg)
			var mirrorIfRefs []string
			byIfRef := make(map[string]config.StableLLPlacement, len(placements))
			for _, p := range placements {
				byIfRef[p.IfRef] = p
			}
			var mirrorNetdevs []string
			for _, tg := range targets {
				mirrorIfRefs = append(mirrorIfRefs, tg.Iface)
				if tg.Addr != stable {
					t.Errorf("mirror target %s addr = %q, want stable %q", tg.Iface, tg.Addr, stable)
				}
				p, ok := byIfRef[tg.Iface]
				if !ok {
					t.Errorf("mirror IfRef %s has no placement", tg.Iface)
					continue
				}
				mirrorNetdevs = append(mirrorNetdevs, p.Netdev)
			}
			sort.Strings(mirrorIfRefs)
			sort.Strings(mirrorNetdevs)
			if !equalStrs17049(mirrorIfRefs, installIfRefs) {
				t.Fatalf("mirror IfRefs = %v, install IfRefs = %v", mirrorIfRefs, installIfRefs)
			}
			if !equalStrs17049(mirrorNetdevs, installNetdevs) {
				t.Fatalf("mirror netdevs = %v, install netdevs = %v", mirrorNetdevs, installNetdevs)
			}

			// NA stable set + configured set (config-level seams; the
			// daemon NA leg iterates RouterLinkLocalPlacements verbatim).
			router := cfg.RouterLinkLocalPlacements(1)
			var naStable, naAll []string
			naByNetdev := make(map[string]string)
			for _, p := range router {
				naAll = append(naAll, p.Netdev)
				naByNetdev[p.Netdev] = p.Addr.String()
				if p.Addr.String() == stable {
					naStable = append(naStable, p.Netdev)
				}
			}
			sort.Strings(naStable)
			sort.Strings(naAll)
			if !equalStrs17049(naStable, installNetdevs) {
				t.Fatalf("NA stable netdevs = %v, install netdevs = %v", naStable, installNetdevs)
			}
			for netdev, ll := range cell.wantNAConfigured {
				if got := naByNetdev[netdev]; got != ll {
					t.Errorf("NA configured[%s] = %q, want %q (all NA: %v)", netdev, got, ll, naByNetdev)
				}
			}
			if len(naAll) != len(naStable)+len(cell.wantNAConfigured) {
				t.Errorf("NA placements = %v, want stable %v + configured %v", naAll, naStable, cell.wantNAConfigured)
			}

			// Remove sweep: install set plus documented extras, sorted.
			wantRemove := append([]string{}, cell.wantRemove...)
			sort.Strings(wantRemove)
			if got := cfg.RemoveNetdevs(1); !equalStrs17049(got, wantRemove) {
				t.Fatalf("RemoveNetdevs = %v, want %v", got, wantRemove)
			}

			// RA bind for this cell's RA unit.
			raCfg := cloneCfgForRA17049(cfg, cell.raUnit)
			d := &Daemon{}
			ras := d.buildRAConfigs(raCfg)
			if len(ras) != 1 {
				t.Fatalf("buildRAConfigs returned %d RAs, want 1", len(ras))
			}
			if ras[0].SourceLinkLocal != cell.wantRA {
				t.Fatalf("RA SourceLinkLocal = %q, want %q", ras[0].SourceLinkLocal, cell.wantRA)
			}
			if cell.wantRA != "" {
				// RA bind netdev: when the RA unit itself carries a
				// placement, the resolved netdev must be that placement's
				// netdev. When it carries none, wantRA == "" above already
				// pins that the stable source does not bind at all (the
				// mixed cells pin it against a placement-bearing sibling).
				for _, p := range placements {
					if p.Unit == cell.raUnit {
						if got := raCfg.ResolveKernelIfName(ras[0].Interface); got != p.Netdev {
							t.Fatalf("RA bind netdev = %q, want placement netdev %q", got, p.Netdev)
						}
					}
				}
			}
		})
	}
}

// cloneCfgForRA17049 returns cfg plus a router-advertisement on
// reth0.<raUnit>. The Interfaces map values are shared (buildRAConfigs only
// reads them; it clones the RA entries it returns).
func cloneCfgForRA17049(cfg *config.Config, raUnit int) *config.Config {
	out := *cfg
	out.Protocols.RouterAdvertisement = []*config.RAInterfaceConfig{
		{Interface: "reth0." + strconv.Itoa(raUnit)},
	}
	return &out
}

// TestStableRethPlacementDaemonSeams17049 drives the real daemon entry
// points (add/remove/NA) through a committed configstore for two
// representative cells, proving the wrappers iterate the placements rather
// than re-deriving them. The full matrix above covers every cell at the
// config seam the wrappers delegate to.
func TestStableRethPlacementDaemonSeams17049(t *testing.T) {
	s := perUnitVLANStore17049(t)
	stableLL := cluster.StableRethLinkLocal(1, 1)

	var added []string
	origAdd := addStableLLToInterfaceFn
	addStableLLToInterfaceFn = func(ifName string, ll net.IP) { added = append(added, ifName) }
	t.Cleanup(func() { addStableLLToInterfaceFn = origAdd })

	var removed []string
	origRem := removeStableLLFromInterfaceFn
	removeStableLLFromInterfaceFn = func(ifName string, ll net.IP) { removed = append(removed, ifName) }
	t.Cleanup(func() { removeStableLLFromInterfaceFn = origRem })

	d := &Daemon{store: s}
	d.addStableRethLinkLocal(1)
	sort.Strings(added)
	if !equalStrs17049(added, []string{"ge-0-0-0.50"}) {
		t.Fatalf("daemon install = %v, want [ge-0-0-0.50]", added)
	}

	d.removeStableRethLinkLocal(1)
	sort.Strings(removed)
	wantRemoved := []string{"ge-0-0-0", "ge-0-0-0.50", "ge-0-0-0.60", "ge-0-0-0.70"}
	if !equalStrs17049(removed, wantRemoved) {
		t.Fatalf("daemon remove = %v, want %v", removed, wantRemoved)
	}

	// NA: stable NA on .50, configured NAs on bare + .60, none on .70.
	type naCall struct{ iface, ip string }
	var nas []naCall
	installBurstSeams(t,
		func(string, net.IP, int, cluster.BurstStillValid) error { return nil },
		func(iface string, ip net.IP, _ int, _ cluster.BurstStillValid) error {
			nas = append(nas, naCall{iface, ip.String()})
			return nil
		})
	prevProbe := directARPProbeFn
	directARPProbeFn = func(string, net.IP, net.IP) error { return nil }
	t.Cleanup(func() { directARPProbeFn = prevProbe })
	d2 := &Daemon{
		store:             s,
		rgStates:          make(map[int]*rgStateMachine),
		directVIPOwned:    map[int]bool{1: true},
		directAnnounceSeq: map[int]uint64{1: 1},
	}
	d2.directSendGARPs(1)
	seenNA := make(map[naCall]bool)
	var routerNAs []naCall
	for _, n := range nas {
		if ip := net.ParseIP(n.ip); ip != nil && ip.IsLinkLocalUnicast() && !seenNA[n] {
			seenNA[n] = true
			routerNAs = append(routerNAs, n)
		}
	}
	sort.Slice(routerNAs, func(i, j int) bool { return routerNAs[i].iface < routerNAs[j].iface })
	wantNAs := []naCall{
		{"ge-0-0-0", "fe80::10:1"},
		{"ge-0-0-0.50", stableLL.String()},
		{"ge-0-0-0.60", "fe80::60:1"},
	}
	if len(routerNAs) != len(wantNAs) {
		t.Fatalf("router NAs = %v, want %v", routerNAs, wantNAs)
	}
	for i := range wantNAs {
		if routerNAs[i] != wantNAs[i] {
			t.Fatalf("router NAs = %v, want %v", routerNAs, wantNAs)
		}
	}
}

// perUnitVLANStore17049 is the committed per-unit fixture (unit 0 explicit
// LL, unit 50 global-only, unit 60 explicit LL, unit 70 IPv4-only).
func perUnitVLANStore17049(t *testing.T) *configstore.Store {
	t.Helper()
	s, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadSet(
		"set chassis cluster cluster-id 1\n" +
			"set chassis cluster authentication-key test-cluster-psk-6611\n" +
			"set chassis cluster control-interface em0\n" +
			"set chassis cluster peer-address 10.99.0.2\n" +
			"set interfaces em0 unit 0 family inet address 10.99.0.1/24\n" +
			"set chassis cluster redundancy-group 1 node 0 priority 200\n" +
			"set chassis cluster redundancy-group 1 node 1 priority 100\n" +
			"set interfaces reth0 vlan-tagging\n" +
			"set interfaces reth0 redundant-ether-options redundancy-group 1\n" +
			"set interfaces ge-0/0/0 gigether-options redundant-parent reth0\n" +
			"set interfaces ge-7/0/0 gigether-options redundant-parent reth0\n" +
			"set interfaces reth0 unit 0 family inet6 address fe80::10:1/64\n" +
			"set interfaces reth0 unit 0 family inet6 address 2001:db8:0::1/64\n" +
			"set interfaces reth0 unit 50 vlan-id 50\n" +
			"set interfaces reth0 unit 50 family inet6 address 2001:db8:50::1/64\n" +
			"set interfaces reth0 unit 60 vlan-id 60\n" +
			"set interfaces reth0 unit 60 family inet6 address fe80::60:1/64\n" +
			"set interfaces reth0 unit 60 family inet6 address 2001:db8:60::1/64\n" +
			"set interfaces reth0 unit 70 vlan-id 70\n" +
			"set interfaces reth0 unit 70 family inet address 10.0.70.1/24\n",
	); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	s.ExitConfigure()
	return s
}
