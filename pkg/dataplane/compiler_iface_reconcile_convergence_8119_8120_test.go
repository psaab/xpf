package dataplane

import (
	"fmt"
	"net"
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #8119 / #8120: TWO consecutive applies of one unchanged config must leave the
// host in the same state.
//
// A single apply is self-consistent, which is why neither defect was caught by
// the existing suite: whichever way the zone map iterated, the result LOOKED
// deliberate. Only the second apply can contradict a reconcile, because it is
// the only witness that does not share the assumption that one pass converges.
//
// The fixture is one physical interface with TWO units and no VLAN ID — a shape
// strict validation deliberately accepts — carrying an interface-level MTU, two
// differing unit MTUs, and two differing address sets. That reaches both
// defects at once:
//
//   - #8119: the interface-level MTU write and the unit-level MTU write compare
//     against the SAME cached netlink.Link, whose attributes LinkSetMTU does not
//     refresh, so the two writes take turns on alternate applies.
//   - #8120: both units resolve to the same physical netdev, and the address
//     reconcile ran per unit against THAT unit's exact desired set, so whichever
//     unit the map yielded second deleted what the first had just added.

// fakeHost8119 is a simulated host: the MTU and address set of each netdev.
//
// It models the ONE property of vishvananda/netlink that #8119 depends on —
// LinkSetMTU sends RTM_SETLINK and never writes back to the caller's Link, so a
// later read of that object's Attrs() returns the pre-write value. A fake that
// refreshed the object would hide the defect entirely, and every assertion here
// would pass on the broken code.
type fakeHost8119 struct {
	mtu   map[string]int
	addrs map[string]map[string]bool
	index map[string]int
}

func (h *fakeHost8119) link(name string) netlink.Link {
	return &netlink.Device{LinkAttrs: netlink.LinkAttrs{
		Name:  name,
		Index: h.index[name],
		MTU:   h.mtu[name],
	}}
}

// snapshot renders the whole host as a comparable string.
func (h *fakeHost8119) snapshot() string {
	names := make([]string, 0, len(h.index))
	for n := range h.index {
		names = append(names, n)
	}
	sort.Strings(names)
	out := ""
	for _, n := range names {
		set := make([]string, 0, len(h.addrs[n]))
		for a := range h.addrs[n] {
			set = append(set, a)
		}
		sort.Strings(set)
		out += fmt.Sprintf("%s mtu=%d addrs=%v\n", n, h.mtu[n], set)
	}
	return out
}

// install points the reconcile-path seams at this fake for the test's lifetime.
func (h *fakeHost8119) install(t *testing.T) {
	t.Helper()
	oldMTU, oldByName := linkSetMTUSeam, addrLinkByNameSeam
	oldList, oldAdd, oldDel := addrListSeam, addrAddSeam, addrDelSeam
	t.Cleanup(func() {
		linkSetMTUSeam, addrLinkByNameSeam = oldMTU, oldByName
		addrListSeam, addrAddSeam, addrDelSeam = oldList, oldAdd, oldDel
	})

	linkSetMTUSeam = func(l netlink.Link, mtu int) error {
		// Deliberately does NOT update l.Attrs().MTU — see the type comment.
		h.mtu[l.Attrs().Name] = mtu
		return nil
	}
	addrLinkByNameSeam = func(name string) (netlink.Link, error) {
		if _, ok := h.index[name]; !ok {
			return nil, fmt.Errorf("no such device %q", name)
		}
		return h.link(name), nil
	}
	addrListSeam = func(l netlink.Link, _ int) ([]netlink.Addr, error) {
		var out []netlink.Addr
		for a := range h.addrs[l.Attrs().Name] {
			ip, ipnet, err := net.ParseCIDR(a)
			if err != nil {
				return nil, err
			}
			ipnet.IP = ip
			out = append(out, netlink.Addr{IPNet: ipnet})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].IPNet.String() < out[j].IPNet.String() })
		return out, nil
	}
	addrAddSeam = func(l netlink.Link, a *netlink.Addr) error {
		n := l.Attrs().Name
		if h.addrs[n] == nil {
			h.addrs[n] = map[string]bool{}
		}
		h.addrs[n][a.IPNet.String()] = true
		return nil
	}
	addrDelSeam = func(l netlink.Link, a *netlink.Addr) error {
		delete(h.addrs[l.Attrs().Name], a.IPNet.String())
		return nil
	}
}

type convergenceTestDP struct{ DataPlane }

func (convergenceTestDP) SetZoneConfig(uint16, ZoneConfig) error { return nil }
func (convergenceTestDP) SetZone(int, uint16, uint16, uint32, uint8, uint8, uint32) error {
	return nil
}
func (convergenceTestDP) AddTxPort(int) error                        { return nil }
func (convergenceTestDP) SetVlanIfaceInfo(int, int, uint16) error    { return nil }
func (convergenceTestDP) SetScreenConfig(uint32, ScreenConfig) error { return nil }
func (convergenceTestDP) DeleteStaleIfaceZone(map[IfaceZoneKey]bool) {}
func (convergenceTestDP) DeleteStaleVlanIface(map[uint32]bool)       {}
func (convergenceTestDP) ZeroStaleScreenConfigs(uint32)              {}

const convergePhys8119 = "ge-0-0-0"

func convergeConfig8119() *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{convergePhys8119 + ".0"}},
		"untrust": {Name: "untrust", Interfaces: []string{convergePhys8119 + ".1"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		convergePhys8119: {
			Name: convergePhys8119,
			MTU:  9000,
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"10.0.1.1/24"}, MTU: 1500},
				1: {Number: 1, Addresses: []string{"10.0.2.1/24"}, MTU: 1400},
			},
		},
	}
	return cfg
}

// applyOnce drives the real compileZones over the fake host, with a FRESH
// CompileResult per apply exactly as production has — the link cache lives for
// one apply and is populated once from the host, which is the lifetime #8119's
// stale read depends on.
func applyOnce8119(t *testing.T, h *fakeHost8119, cfg *config.Config) {
	t.Helper()
	result := newValidationResult()
	assignZoneIDs(result, cfg)
	assignScreenIDs(result, cfg)
	// Offload state is outside this MTU/address-union fixture.
	result.rxTagStripOffCache[convergePhys8119] = true
	idx := h.index[convergePhys8119]
	result.ifCache[convergePhys8119] = &net.Interface{Index: idx, Name: convergePhys8119}
	link := h.link(convergePhys8119)
	result.linkCache[convergePhys8119] = link
	result.linkIdxMap[idx] = link
	if err := compileZones(convergenceTestDP{}, cfg, result); err != nil {
		t.Fatalf("compileZones: %v", err)
	}
}

func newFakeHost8119() *fakeHost8119 {
	return &fakeHost8119{
		mtu:   map[string]int{convergePhys8119: 1500},
		addrs: map[string]map[string]bool{convergePhys8119: {}},
		index: map[string]int{convergePhys8119: 4211},
	}
}

func TestTwoAppliesOfOneConfigConverge_8119_8120(t *testing.T) {
	cfg := convergeConfig8119()

	// PREMISE, asserted rather than assumed: both unit refs must resolve to the
	// SAME physical netdev with vlanID 0. If a future change gave either one its
	// own netdev there would be no second writer, and this fixture would be
	// measuring nothing while still passing.
	p0, _, u0, v0 := resolveInterfaceRef(convergePhys8119+".0", cfg)
	p1, _, u1, v1 := resolveInterfaceRef(convergePhys8119+".1", cfg)
	if p0 != p1 || v0 != 0 || v1 != 0 || u0 == u1 {
		t.Fatalf("premise broken: refs resolve to (%s,u%d,v%d) and (%s,u%d,v%d); this fixture "+
			"only exercises #8120 when two DISTINCT units share one untagged netdev",
			p0, u0, v0, p1, u1, v1)
	}

	h := newFakeHost8119()
	h.install(t)
	applyOnce8119(t, h, cfg)
	first := h.snapshot()

	applyOnce8119(t, h, cfg)
	second := h.snapshot()

	if first != second {
		t.Errorf("a second apply of the SAME config changed the host.\n"+
			"after apply 1:\n%s\nafter apply 2:\n%s\n"+
			"An apply is not idempotent: the same netdev is reconciled more than once "+
			"with a different desired state each time and the last writer wins. An "+
			"operator watching `ip link` / `ip addr` sees this alternate on every commit.",
			first, second)
	}
}

// The address set must be the UNION of every unit that resolves to the netdev.
// Asserting convergence alone is not enough: a fix that made BOTH applies settle
// on unit 1's addresses would converge and still have silently dropped unit 0's.
func TestBothUnitsAddressesSurvive_8120(t *testing.T) {
	cfg := convergeConfig8119()
	h := newFakeHost8119()
	h.install(t)
	applyOnce8119(t, h, cfg)
	applyOnce8119(t, h, cfg)

	for _, want := range []string{"10.0.1.1/24", "10.0.2.1/24"} {
		if !h.addrs[convergePhys8119][want] {
			t.Errorf("address %s is missing after two applies; both units resolve to this "+
				"netdev, so its address set must be the union of theirs. Have: %v",
				want, h.snapshot())
		}
	}
}

// Convergence alone does not say the value is RIGHT. Pin what it converges to:
// the union of both units' addresses, and the lowest-numbered unit's MTU
// overriding the interface-level 9000.
func TestConvergedStateIsTheMergedOne_8119_8120(t *testing.T) {
	h := newFakeHost8119()
	h.install(t)
	cfg := convergeConfig8119()
	applyOnce8119(t, h, cfg)
	applyOnce8119(t, h, cfg)

	if got := h.mtu[convergePhys8119]; got != 1500 {
		t.Errorf("MTU = %d, want 1500 (unit 0 overrides the interface-level 9000, and the "+
			"lowest unit number wins between units)", got)
	}
	want := map[string]bool{"10.0.1.1/24": true, "10.0.2.1/24": true}
	got := h.addrs[convergePhys8119]
	if len(got) != len(want) {
		t.Errorf("addresses = %v, want exactly %v", got, want)
	}
	for a := range want {
		if !got[a] {
			t.Errorf("missing %s", a)
		}
	}
}

// The plan must be a function of the config alone. programZoneMaps used to
// range a Go map and actuate inside the loop, so the host state depended on an
// order that is randomised per run; this asserts the decision no longer can.
func TestPlanIsIndependentOfZoneMapOrder_8119_8120(t *testing.T) {
	cfg := convergeConfig8119()
	first := renderPlan8119(planPhysDesired(cfg))
	// Go randomises map iteration per range statement, so repeating the call is
	// a real sample of different orders rather than a replay of one.
	for i := 0; i < 200; i++ {
		if got := renderPlan8119(planPhysDesired(cfg)); got != first {
			t.Fatalf("plan differs between runs of the SAME config:\n%s\nvs\n%s", first, got)
		}
	}
}

func renderPlan8119(p map[string]*physDesired) string {
	names := make([]string, 0, len(p))
	for n := range p {
		names = append(names, n)
	}
	sort.Strings(names)
	out := ""
	for _, n := range names {
		pd := p[n]
		// Deliberately NOT sorted. Sorting here would hide the property this
		// renderer exists to expose: the ORDER units contribute addresses in is
		// exactly what a raw map range over the zones makes vary per run, and a
		// sorted render reports a stable plan whether or not the planner is
		// deterministic. Caught by a mutation — deleting the planner's
		// sort.Strings escaped until this line came out.
		out += fmt.Sprintf("%s mtu=%d skip=%v addrs=%v\n", n, pd.mtu, pd.skipAddrs, pd.addrs)
	}
	return out
}

// A DHCP unit must suppress reconciliation for the WHOLE netdev, not just its
// own reference: the DHCP client owns that interface's addresses, and a union
// that reconciled around it would fight the real owner.
func TestDHCPUnitSuppressesTheWholeNetdev_8119_8120(t *testing.T) {
	cfg := convergeConfig8119()
	cfg.Interfaces.Interfaces[convergePhys8119].Units[1].DHCP = true
	plan := planPhysDesired(cfg)
	pd := plan[convergePhys8119]
	if pd == nil {
		t.Fatal("no plan entry")
	}
	if !pd.skipAddrs {
		t.Error("a DHCP unit on the netdev must set skipAddrs for the netdev; otherwise the " +
			"static units' reconcile deletes whatever the DHCP client just installed")
	}
}
