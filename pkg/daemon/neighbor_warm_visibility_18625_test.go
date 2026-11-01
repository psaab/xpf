package daemon

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// Review of #18625: a warm-up that probes nothing looks like the fix working.
// These cells pin the surfaces that tell the two apart.

// The last pass renders in `show chassis cluster information`, through the
// Manager hook the daemon installs. RED if the hook or a counter line goes.
func TestWarmPassRendersInClusterInformation18625(t *testing.T) {
	d := &Daemon{neighborWarmDialer: newCountingWarmDialer(), neighborWarmPlanInputs: splitWarmInputs18617(map[int]bool{1: true})}
	d.setDataplane(&warmNeighborTestDP{store: &warmEndpointStore18617{
		v4: [][2]netip.Addr{{lanHost4, wanTarget4}, {poolAddr, wanTarget4}, {lanHost4, internetHost4}},
	}})
	m := cluster.NewManager(0, 1)
	m.SetInformationExtraFunc(d.neighborWarmInformation)
	if out := m.FormatInformation(); !strings.Contains(out, "Neighbor warm-up: no pass yet") {
		t.Fatalf("before any pass the information view must say so:\n%s", out)
	}
	d.warmNeighborCacheFor(splitWarmConfig18617())
	out := m.FormatInformation()
	for _, want := range []string{
		"Neighbor warm-up (last pass ",
		"Probed: 1 IPv4, 0 IPv6",
		"Skipped: 1 cluster-owned, 1 not held, 1 routed, 0 not unicast",
		"Socket bind failures: 0",
		"Primary prefixes not held: 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("information view lacks %q:\n%s", want, out)
		}
	}
}

// Primary for RG1 while the kernel holds no address in reth0.80's prefix: the
// plan records it, the count shows it, and it warns once, after the grace,
// re-arming when the prefix is held again. RED if the plan stops recording it
// or the Warn is level-triggered.
func TestWarmPrimaryNotHeldWarnsOnceAfterGrace18625(t *testing.T) {
	in := splitWarmInputs18617(map[int]bool{1: true})
	base := in.localAddrs
	in.localAddrs = func(ifname string) []netip.Prefix {
		if ifname == "ge-0-0-2.80" {
			return nil // the VIP did not land
		}
		return base(ifname)
	}
	plan := buildNeighborWarmPlan(splitWarmConfig18617(), in)
	if len(plan.primaryNotHeld) != 2 { // v4 and v6 prefixes of reth0.80
		t.Fatalf("primaryNotHeld = %v, want reth0.80's two prefixes", plan.primaryNotHeld)
	}
	for _, k := range plan.primaryNotHeld {
		if !strings.HasPrefix(k, "rg1 ge-0-0-2.80 ") {
			t.Errorf("unexpected key %q", k)
		}
	}
	var h neighborWarmHealth
	t0 := time.Unix(1000, 0)
	if w := h.notePrimaryNotHeld(plan.primaryNotHeld, t0); len(w) != 0 {
		t.Fatalf("warned on first sight: %v", w)
	}
	if w := h.notePrimaryNotHeld(plan.primaryNotHeld, t0.Add(2*time.Second)); len(w) != 0 {
		t.Fatalf("warned inside the grace: %v", w)
	}
	if w := h.notePrimaryNotHeld(plan.primaryNotHeld, t0.Add(6*time.Second)); len(w) != 2 {
		t.Fatalf("after the grace want 2 warns, got %v", w)
	}
	if w := h.notePrimaryNotHeld(plan.primaryNotHeld, t0.Add(30*time.Second)); len(w) != 0 {
		t.Fatalf("warned again while the condition persists: %v", w)
	}
	h.notePrimaryNotHeld(nil, t0.Add(31*time.Second))
	h.notePrimaryNotHeld(plan.primaryNotHeld, t0.Add(32*time.Second))
	if w := h.notePrimaryNotHeld(plan.primaryNotHeld, t0.Add(38*time.Second)); len(w) != 2 {
		t.Fatalf("a recurrence after recovery must warn again, got %v", w)
	}
	// The pass counts it too.
	d := &Daemon{neighborWarmDialer: newCountingWarmDialer(), neighborWarmPlanInputs: in}
	d.setDataplane(&warmNeighborTestDP{store: &warmEndpointStore18617{v4: [][2]netip.Addr{{lanHost4, wanTarget4}}}})
	d.warmNeighborCacheFor(splitWarmConfig18617())
	if c := d.lastNeighborWarmCounts.Load(); c == nil || c.primaryNotHeld != 2 {
		t.Fatalf("pass counts primaryNotHeld=%v, want 2", c)
	}
}

type failingWarmDialer struct{ opens int }

func (f *failingWarmDialer) open(string, string) (neighborWarmConn, error) {
	f.opens++
	return nil, errors.New("bind: no such device")
}

// A probe socket that cannot be bound is counted and warns once per
// (network, interface), not on every pass. RED if the count or the edge goes.
func TestWarmBindFailureCountedAndWarnedOnce18625(t *testing.T) {
	logs, restore := captureSlog(t)
	defer restore()
	dialer := &failingWarmDialer{}
	d := &Daemon{neighborWarmDialer: dialer, neighborWarmPlanInputs: splitWarmInputs18617(map[int]bool{1: true})}
	d.setDataplane(&warmNeighborTestDP{store: &warmEndpointStore18617{v4: [][2]netip.Addr{{lanHost4, wanTarget4}}}})
	for i := 0; i < 3; i++ {
		d.warmNeighborCacheFor(splitWarmConfig18617())
	}
	c := d.lastNeighborWarmCounts.Load()
	if c == nil || c.bindFailures != 1 || c.probedV4 != 0 {
		t.Fatalf("counts %+v, want bindFailures=1 probedV4=0", c)
	}
	if n := strings.Count(logs.String(), "cannot bind its probe socket"); n != 1 {
		t.Fatalf("bind-failure Warn logged %d times over 3 passes, want 1:\n%s", n, logs.String())
	}
	var h neighborWarmHealth
	if !h.noteBind("udp4", "x", errors.New("e")) || h.noteBind("udp4", "x", errors.New("e")) {
		t.Fatal("noteBind must warn on the first failure only")
	}
	h.noteBind("udp4", "x", nil)
	if !h.noteBind("udp4", "x", errors.New("e")) {
		t.Fatal("a failure after a recovery must warn again")
	}
}

// Unit number and VLAN id differ: the netdev is named by the VLAN id. Every
// other fixture had unit == vlan-id, so naming by unit survived. The DHCP
// subnet resolver shares the helper, so it must agree. RED if either names by
// the unit number.
func TestWarmUnitNamedByVlanIDNotUnitNumber18625(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/3": {Name: "ge-0/0/3", Units: map[int]*config.InterfaceUnit{
			0: {VlanID: 50, Addresses: []string{"10.50.0.1/24"}},
			7: {Addresses: []string{"10.77.0.1/24"}},
		}},
	}
	in := neighborWarmPlanInputs{localAddrs: func(ifname string) []netip.Prefix {
		switch ifname {
		case "ge-0-0-3.50":
			return []netip.Prefix{netip.MustParsePrefix("10.50.0.1/24")}
		case "ge-0-0-3.7":
			return []netip.Prefix{netip.MustParsePrefix("10.77.0.1/24")}
		}
		return nil
	}}
	plan := buildNeighborWarmPlan(cfg, in)
	if ifname, v := plan.classify(netip.MustParseAddr("10.50.0.9")); v != neighborWarmProbe || ifname != "ge-0-0-3.50" {
		t.Errorf("vlan-id 50 on unit 0: classified %v on %q, want probe on ge-0-0-3.50", v, ifname)
	}
	if ifname, v := plan.classify(netip.MustParseAddr("10.77.0.9")); v != neighborWarmProbe || ifname != "ge-0-0-3.7" {
		t.Errorf("untagged unit 7: classified %v on %q, want probe on ge-0-0-3.7", v, ifname)
	}
	if got, _, ok := resolveConfigSubnetLinuxName(cfg, net.ParseIP("10.50.0.9")); !ok || got != "ge-0-0-3.50" {
		t.Errorf("resolveConfigSubnetLinuxName = %q, want ge-0-0-3.50", got)
	}
}

// Adopted from review seat T: the PRODUCTION dialer really sets
// SO_BINDTODEVICE (the other cells use a fake dialer, so removing the bind
// survived them), and a missing interface is an open() error. Unprivileged:
// binding to lo needs no capability.
func TestWarmProductionDialerBindsDevice18625(t *testing.T) {
	c, err := udpNeighborWarmDialer{}.open("udp4", "lo")
	if err != nil {
		t.Fatalf("open udp4 on lo: %v", err)
	}
	defer c.Close()
	uc := c.(*udpNeighborWarmConn).conn
	raw, err := uc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var dev string
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		dev, gerr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil || dev != "lo" {
		t.Fatalf("SO_BINDTODEVICE readback = %q (err %v), want lo", dev, gerr)
	}
	if err := c.probe(netip.MustParseAddrPort("127.0.0.1:1")); err != nil {
		t.Errorf("probe through the lo-bound socket: %v", err)
	}
	if _, err := (udpNeighborWarmDialer{}).open("udp6", "nonexistent0"); err == nil {
		t.Fatal("binding to a missing interface did not error")
	}
}

// Force-probe's per-tick lines: the truncation Warn is edge-triggered and the
// count logs at Debug. RED if either goes back to firing every tick at
// Info/Warn.
func TestForceProbeLinesAreEdgeTriggered18625(t *testing.T) {
	var h neighborWarmHealth
	if !h.noteProbeTruncation(true, 900, 512) {
		t.Fatal("the first truncated pass must warn")
	}
	if h.noteProbeTruncation(true, 900, 512) {
		t.Fatal("a continuing truncation must not warn again")
	}
	h.noteProbeTruncation(false, 100, 512)
	if !h.noteProbeTruncation(true, 900, 512) {
		t.Fatal("truncation after a clean pass must warn again")
	}
	logs, restore := captureSlog(t)
	defer restore()
	d := &Daemon{neighborWarmPlanInputs: splitWarmInputs18617(map[int]bool{1: true})}
	d.setDataplane(&forceProbeDP18617{neighbors: []net.IP{net.ParseIP("127.0.0.2")}})
	d.forceProbeNeighbors(splitWarmConfig18617())
	line := ""
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, "force-probe neighbors") {
			line = l
		}
	}
	if line == "" || !strings.Contains(line, "level=DEBUG") {
		t.Fatalf("force-probe count line must log at Debug, got %q", line)
	}
}
