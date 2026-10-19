package vrrp

import (
	"errors"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/ipv4"
)

// #5083 — VRRP silently not built for some configs.
//
// The generic collector (CollectInstances) used to store the RAW Junos
// interface name (with '/', e.g. "ge-0/0/0") and NO unit, so the manager's
// net.InterfaceByName("ge-0/0/0") failed and NO instance was built. And the
// manager instance key was (interface, VRID) with no family/unit, so a
// dual-stack v4+v6 group on one unit — and two units sharing a VRID — collided
// to one key and last-wins silently dropped a family/segment.
//
// The fix: the collector resolves the CONFIGURED interface+unit to its KERNEL
// device name via the SSOT resolver (cfg.ResolveKernelIfName) and records the
// address family, and the manager key distinguishes
// (kernel-interface/unit, VRID, family).

// vrrpTestCfg builds a minimal *config.Config with a single interface carrying
// the supplied units, so the collector can be exercised without the parser.
func vrrpTestCfg(ifName string, vlanTagging bool, units map[int]*config.InterfaceUnit) *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				ifName: {
					Name:        ifName,
					VlanTagging: vlanTagging,
					Units:       units,
				},
			},
		},
	}
}

func findByFamily(insts []*Instance, family string) *Instance {
	for _, in := range insts {
		if in.Family == family {
			return in
		}
	}
	return nil
}

// (a) A Junos-slash interface "ge-0/0/0" must collect an instance whose stored
// Interface is the normalized KERNEL name "ge-0-0-0" (the form
// net.InterfaceByName accepts) — never the raw slash name.
//
// FAIL-ON-REVERT: revert the ResolveKernelIfName normalization in
// CollectInstances (store ifName) and inst.Interface is "ge-0/0/0", so this
// assertion fails — the exact name InterfaceByName cannot resolve, i.e. the
// instance would never be built at the manager.
func TestCollectInstances_NormalizesSlashToKernelName(t *testing.T) {
	cfg := vrrpTestCfg("ge-0/0/0", false, map[int]*config.InterfaceUnit{
		0: {
			Number: 0,
			VRRPGroups: map[string]*config.VRRPGroup{
				"10.0.0.2/24_grp10": {
					ID:               10,
					Priority:         200,
					VirtualAddresses: []string{"10.0.0.1"},
				},
			},
		},
	})

	insts := CollectInstances(cfg)
	if len(insts) != 1 {
		t.Fatalf("expected exactly 1 instance, got %d", len(insts))
	}
	if got := insts[0].Interface; got != "ge-0-0-0" {
		t.Fatalf("stored interface = %q, want kernel form %q (net.InterfaceByName cannot resolve a slash name)", got, "ge-0-0-0")
	}
	if insts[0].GroupID != 10 {
		t.Fatalf("GroupID = %d, want 10", insts[0].GroupID)
	}
}

// (a') A VLAN-tagged unit ("ge-0/0/0.100") must map to the VLAN sub-interface
// kernel device "ge-0-0-0.100" — the unit's VLAN is preserved, not dropped.
func TestCollectInstances_VlanUnitMapsToSubInterface(t *testing.T) {
	cfg := vrrpTestCfg("ge-0/0/0", true, map[int]*config.InterfaceUnit{
		100: {
			Number: 100,
			VlanID: 100,
			VRRPGroups: map[string]*config.VRRPGroup{
				"172.16.1.2/24_grp3": {
					ID:               3,
					VirtualAddresses: []string{"172.16.1.1"},
				},
			},
		},
	})

	insts := CollectInstances(cfg)
	if len(insts) != 1 {
		t.Fatalf("expected exactly 1 instance, got %d", len(insts))
	}
	if got := insts[0].Interface; got != "ge-0-0-0.100" {
		t.Fatalf("stored interface = %q, want VLAN sub-interface %q", got, "ge-0-0-0.100")
	}
}

// (b) A dual-stack VRRP group — an IPv4 and an IPv6 group on the SAME unit with
// the SAME VRID — must collect TWO instances (one per family), both present.
//
// FAIL-ON-REVERT: this depends only on the collector emitting a distinct
// Family per group; the manager-key half of the fix is asserted separately in
// TestManagerUpdateInstances_DualStackNoCollision.
func TestCollectInstances_DualStackSameVRIDTwoFamilies(t *testing.T) {
	cfg := vrrpTestCfg("ge-0/0/0", false, map[int]*config.InterfaceUnit{
		0: {
			Number: 0,
			VRRPGroups: map[string]*config.VRRPGroup{
				"10.0.0.2/24_grp5": {
					ID:               5,
					VirtualAddresses: []string{"10.0.0.1"},
				},
				"2001:db8::2/64_grp5": {
					ID:               5,
					VirtualAddresses: []string{"2001:db8::1"},
				},
			},
		},
	})

	insts := CollectInstances(cfg)
	if len(insts) != 2 {
		t.Fatalf("dual-stack v4+v6 on one unit/VRID must collect 2 instances, got %d", len(insts))
	}
	v4 := findByFamily(insts, "inet")
	v6 := findByFamily(insts, "inet6")
	if v4 == nil || v6 == nil {
		t.Fatalf("both families must be present: inet=%v inet6=%v", v4, v6)
	}
	// Both instances share the SAME kernel interface and VRID — they differ
	// ONLY by family. That is exactly the (interface, VRID) collision the
	// manager key must now avoid.
	if v4.Interface != "ge-0-0-0" || v6.Interface != "ge-0-0-0" {
		t.Fatalf("both should share kernel iface ge-0-0-0: v4=%q v6=%q", v4.Interface, v6.Interface)
	}
	if v4.GroupID != 5 || v6.GroupID != 5 {
		t.Fatalf("both should share VRID 5: v4=%d v6=%d", v4.GroupID, v6.GroupID)
	}
}

// (c) Two units on one interface with the SAME VRID must collect two
// instances with DISTINCT kernel names (the unit is encoded in the kernel
// name via the VLAN suffix).
//
// FAIL-ON-REVERT: revert the normalization (store ifName) and both units
// collapse to Interface "ge-0/0/0" with the same VRID — the manager key then
// collides and one unit is dropped (last-wins).
func TestCollectInstances_TwoUnitsSameVRIDDistinctNames(t *testing.T) {
	cfg := vrrpTestCfg("ge-0/0/0", true, map[int]*config.InterfaceUnit{
		100: {
			Number: 100, VlanID: 100,
			VRRPGroups: map[string]*config.VRRPGroup{
				"172.16.1.2/24_grp7": {ID: 7, VirtualAddresses: []string{"172.16.1.1"}},
			},
		},
		200: {
			Number: 200, VlanID: 200,
			VRRPGroups: map[string]*config.VRRPGroup{
				"172.16.2.2/24_grp7": {ID: 7, VirtualAddresses: []string{"172.16.2.1"}},
			},
		},
	})

	insts := CollectInstances(cfg)
	if len(insts) != 2 {
		t.Fatalf("two units sharing VRID 7 must collect 2 instances, got %d", len(insts))
	}
	names := []string{insts[0].Interface, insts[1].Interface}
	sort.Strings(names)
	if names[0] != "ge-0-0-0.100" || names[1] != "ge-0-0-0.200" {
		t.Fatalf("distinct VLAN sub-interfaces expected, got %v", names)
	}
}

// (d) A single-family (IPv4-only) group behaves exactly as before: one
// instance, family inet, kernel interface name.
func TestCollectInstances_SingleStackUnchanged(t *testing.T) {
	cfg := vrrpTestCfg("ge-0/0/1", false, map[int]*config.InterfaceUnit{
		0: {
			Number: 0,
			VRRPGroups: map[string]*config.VRRPGroup{
				"10.0.5.2/24_grp12": {ID: 12, VirtualAddresses: []string{"10.0.5.1"}},
			},
		},
	})

	insts := CollectInstances(cfg)
	if len(insts) != 1 {
		t.Fatalf("single-stack must collect exactly 1 instance, got %d", len(insts))
	}
	if insts[0].Family != "inet" {
		t.Fatalf("family = %q, want inet", insts[0].Family)
	}
	if insts[0].Interface != "ge-0-0-1" {
		t.Fatalf("interface = %q, want ge-0-0-1", insts[0].Interface)
	}
}

// vrrpFamilyManager returns a Manager whose resolveIface FAILS for any name
// containing a slash — mimicking net.InterfaceByName's real behavior on a raw
// Junos name — and whose socket/run/stop seams never touch the network.
func vrrpFamilyManager() *Manager {
	m := NewManager()
	m.linkState = func(string) (bool, error) { return true, nil }
	m.subscribeLinks = func(chan<- netlink.LinkUpdate, <-chan struct{}) error { return nil }
	m.subscribeAddrs = func(chan<- netlink.AddrUpdate, <-chan struct{}) error { return nil }
	m.resolveIface = func(name string) (*net.Interface, error) {
		for i := 0; i < len(name); i++ {
			if name[i] == '/' {
				return nil, &net.OpError{Op: "route", Err: errNoSuchIface}
			}
		}
		return &net.Interface{Name: name, Index: 1}, nil
	}
	m.openInstanceSocket = func(*vrrpInstance) error { return nil }
	m.runInstance = func(vi *vrrpInstance) { close(vi.stopped) }
	m.stopInstance = func(vi *vrrpInstance) {
		select {
		case <-vi.stopCh:
		default:
			close(vi.stopCh)
		}
	}
	return m
}

var errNoSuchIface = &noSuchIfaceError{}

type noSuchIfaceError struct{}

func (e *noSuchIfaceError) Error() string { return "test: no such network interface" }

// Manager half of the fix: two dual-stack Instances that share (interface,
// VRID) and differ only by family must produce TWO distinct instances — no
// last-wins.
//
// FAIL-ON-REVERT: drop `family` from instanceKey (and from the key built in
// UpdateInstances) and the two Instances collapse to one map entry — len == 1,
// a silently dropped family. This test then fails.
func TestManagerUpdateInstances_DualStackNoCollision(t *testing.T) {
	m := vrrpFamilyManager()
	defer stopManagerForTest(m)

	desired := []*Instance{
		{Interface: "ge-0-0-0", Family: "inet", GroupID: 5, VirtualAddresses: []string{"10.0.0.1"}},
		{Interface: "ge-0-0-0", Family: "inet6", GroupID: 5, VirtualAddresses: []string{"2001:db8::1"}},
	}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}

	m.mu.RLock()
	n := len(m.instances)
	_, haveV4 := m.instances[instanceKey{iface: "ge-0-0-0", groupID: 5, family: "inet"}]
	_, haveV6 := m.instances[instanceKey{iface: "ge-0-0-0", groupID: 5, family: "inet6"}]
	m.mu.RUnlock()

	if n != 2 {
		t.Fatalf("dual-stack v4+v6 (same iface+VRID) must build 2 instances, got %d", n)
	}
	if !haveV4 || !haveV6 {
		t.Fatalf("both family instances must be present: inet=%v inet6=%v", haveV4, haveV6)
	}
}

// A kernel-name (no-slash) Instance builds; a raw slash-name Instance does not
// (resolveIface fails, mirroring net.InterfaceByName). This ties the collector
// normalization to whether the manager can build the instance at all.
func TestManagerUpdateInstances_SlashNameNotBuilt(t *testing.T) {
	m := vrrpFamilyManager()
	defer stopManagerForTest(m)

	desired := []*Instance{
		{Interface: "ge-0/0/0", Family: "inet", GroupID: 9, VirtualAddresses: []string{"10.0.0.1"}}, // raw slash — unresolvable
		{Interface: "ge-0-0-1", Family: "inet", GroupID: 9, VirtualAddresses: []string{"10.0.1.1"}}, // kernel form — builds
	}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}

	m.mu.RLock()
	n := len(m.instances)
	_, haveKernel := m.instances[instanceKey{iface: "ge-0-0-1", groupID: 9, family: "inet"}]
	_, haveSlash := m.instances[instanceKey{iface: "ge-0/0/0", groupID: 9, family: "inet"}]
	m.mu.RUnlock()

	if !haveKernel {
		t.Error("kernel-named instance ge-0-0-1 should have been built")
	}
	if haveSlash {
		t.Error("raw slash-named instance should NOT build (InterfaceByName fails)")
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 built instance (the kernel-named one), got %d", n)
	}
}

// StateKey keeps the historical form for empty-family RETH instances and
// appends the family suffix for every generic instance, so dual-stack families
// never collide in Manager.States() / RXDropStats().
func TestStateKey_FamilySuffix(t *testing.T) {
	if got := StateKey("reth0.50", 101, ""); got != "VI_reth0.50_101" {
		t.Errorf("empty family must keep historical form, got %q", got)
	}
	v4 := StateKey("ge-0-0-0", 5, "inet")
	v6 := StateKey("ge-0-0-0", 5, "inet6")
	if v4 == v6 {
		t.Errorf("dual-stack keys must differ: %q == %q", v4, v6)
	}
	if v4 != "VI_ge-0-0-0_5_inet" || v6 != "VI_ge-0-0-0_5_inet6" {
		t.Errorf("unexpected keys: v4=%q v6=%q", v4, v6)
	}
}

// The parseVRRPGroups key records the configured Junos family and is more
// authoritative than a malformed VIP admitted by a lenient/peer load. The
// manager then rejects the mismatch instead of silently coupling elections.
func TestVRRPGroupFamily_ConfigAddressIsAuthoritative(t *testing.T) {
	if got := vrrpGroupFamily([]string{"10.0.0.1/24"}, "2001:db8::2/64_grp5"); got != "inet6" {
		t.Fatalf("family = %q, want inet6 from config-address key", got)
	}
}

func TestManagerUpdateInstances_SkipsDuplicateIdentityKeepingExisting(t *testing.T) {
	m := NewManager()
	key := instanceKey{iface: "ge-0-0-0", groupID: 5, family: "inet"}
	sentinel := newInstance(Instance{
		Interface: "ge-0-0-0", Family: "inet", GroupID: 5,
		VirtualAddresses: []string{"10.0.0.254/24"},
	}, &net.Interface{Name: "ge-0-0-0", Index: 7}, m.eventCh, nil)
	m.instances[key] = sentinel

	err := m.UpdateInstances([]*Instance{
		{Interface: "ge-0-0-0", Family: "inet", GroupID: 5, VirtualAddresses: []string{"10.0.0.1/24"}},
		{Interface: "ge-0-0-0", Family: "inet", GroupID: 5, VirtualAddresses: []string{"10.0.0.2/24"}},
	})
	if err != nil {
		t.Fatalf("duplicate runtime identity must be skipped, not abort the batch: %v", err)
	}

	m.mu.RLock()
	got, ok := m.instances[key]
	n := len(m.instances)
	_, publishedDesired := m.desiredIfaces["ge-0-0-0"]
	_, unbuilt := m.unbuiltDesired[key]
	m.mu.RUnlock()
	if !ok || got != sentinel || n != 1 {
		t.Fatalf("skipped duplicate mutated live set: present=%v same=%v len=%d", ok, got == sentinel, n)
	}
	if !publishedDesired {
		t.Fatal("accepted first claimant must publish its desired interface")
	}
	if !unbuilt {
		t.Fatal("rejected duplicate key must be recorded unbuilt")
	}
}

func TestManagerUpdateInstances_SkipsRethGenericWireOverlapInEitherOrder(t *testing.T) {
	generic := &Instance{
		Interface: "ge-0-0-0", Family: "inet", GroupID: 101,
		VirtualAddresses: []string{"10.0.0.1/24"},
	}
	reth := &Instance{
		Interface: "ge-0-0-0", GroupID: 101,
		VirtualAddresses: []string{"10.0.0.254/24", "2001:db8::1/64"},
	}
	for _, desired := range [][]*Instance{{generic, reth}, {reth, generic}} {
		m := vrrpFamilyManager()
		if err := m.UpdateInstances(desired); err != nil {
			t.Fatalf("RETH/generic overlap must be skipped, not abort the batch: %v", err)
		}
		m.mu.RLock()
		n := len(m.instances)
		unbuiltN := len(m.unbuiltDesired)
		m.mu.RUnlock()
		stopManagerForTest(m)
		if n != 1 || unbuiltN != 1 {
			t.Fatalf("overlap must seat exactly one instance and record one refusal: instances=%d unbuilt=%d", n, unbuiltN)
		}
	}
}

func TestManagerUpdateInstances_AllowsSeparateIPv4AndIPv6Domains(t *testing.T) {
	m := vrrpFamilyManager()
	defer stopManagerForTest(m)
	desired := []*Instance{
		{Interface: "ge-0-0-0", Family: "inet", GroupID: 5, VirtualAddresses: []string{"10.0.0.1/24"}},
		{Interface: "ge-0-0-0", Family: "inet6", GroupID: 5, VirtualAddresses: []string{"2001:db8::1/64"}},
	}
	if err := m.UpdateInstances(desired); err != nil {
		t.Fatalf("disjoint IPv4/IPv6 election domains rejected: %v", err)
	}
	if got := len(m.instances); got != 2 {
		t.Fatalf("built instances=%d, want 2", got)
	}
}

func TestManagerUpdateInstances_RejectsFamilyVIPMismatch(t *testing.T) {
	m := NewManager()
	err := m.UpdateInstances([]*Instance{{
		Interface: "ge-0-0-0", Family: "inet6", GroupID: 5,
		VirtualAddresses: []string{"10.0.0.1/24"},
	}})
	if err == nil {
		t.Fatal("cross-family identity must be rejected, got nil")
	}
	if len(m.instances) != 0 {
		t.Fatalf("rejected family mismatch built %d instances", len(m.instances))
	}
}

func TestFamilyTaggedInstances_IsolateAFPacketElectionDomains(t *testing.T) {
	v4Frame := buildEthFrame(t, 0, net.IPv4(10, 0, 0, 2), net.IPv4(224, 0, 0, 18), &VRRPPacket{
		VRID: 5, Priority: 100, MaxAdvertInt: 100,
		IPAddresses: []net.IP{net.IPv4(10, 0, 0, 1)},
	})
	v6Frame := buildEthIPv6Frame(t, 0, net.ParseIP("fe80::2"), net.ParseIP("ff02::12"), &VRRPPacket{
		VRID: 5, Priority: 100, MaxAdvertInt: 100,
		IPAddresses: []net.IP{net.ParseIP("2001:db8::1")},
	})

	tests := []struct {
		name       string
		family     string
		wantAfter4 int
		wantAfter6 int
	}{
		{name: "inet accepts only IPv4", family: "inet", wantAfter4: 1, wantAfter6: 1},
		{name: "inet6 accepts only IPv6", family: "inet6", wantAfter4: 0, wantAfter6: 1},
		{name: "RETH empty family keeps dual-stack", family: "", wantAfter4: 1, wantAfter6: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vi := newInstance(Instance{Interface: "ge-0-0-0", Family: tt.family, GroupID: 5},
				&net.Interface{Name: "ge-0-0-0", Index: 7}, make(chan VRRPEvent, 1), nil)
			vi.parseAfPacketIPv4(v4Frame, len(v4Frame), 14)
			if got := len(vi.rxCh); got != tt.wantAfter4 {
				t.Fatalf("after IPv4 frame rx len=%d, want %d", got, tt.wantAfter4)
			}
			vi.parseAfPacketIPv6(v6Frame, len(v6Frame), 14)
			if got := len(vi.rxCh); got != tt.wantAfter6 {
				t.Fatalf("after IPv6 frame rx len=%d, want %d", got, tt.wantAfter6)
			}
		})
	}
}

type closeTrackingPacketConn struct {
	closed bool
}

func (*closeTrackingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("test read")
}
func (*closeTrackingPacketConn) WriteTo([]byte, net.Addr) (int, error) { return 0, nil }
func (*closeTrackingPacketConn) Read([]byte) (int, error)              { return 0, errors.New("test read") }
func (*closeTrackingPacketConn) Write(p []byte) (int, error)           { return len(p), nil }
func (c *closeTrackingPacketConn) Close() error {
	c.closed = true
	return nil
}
func (*closeTrackingPacketConn) LocalAddr() net.Addr              { return nil }
func (*closeTrackingPacketConn) RemoteAddr() net.Addr             { return nil }
func (*closeTrackingPacketConn) SetDeadline(time.Time) error      { return nil }
func (*closeTrackingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*closeTrackingPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestOpenSocket_IPv6OnlyDoesNotRequireIPv4(t *testing.T) {
	vi := newInstance(Instance{
		Interface: "ge-0-0-0", Family: "inet6", GroupID: 5,
		VirtualAddresses: []string{"2001:db8::1/64"},
	}, &net.Interface{Name: "ge-0-0-0", Index: 7}, make(chan VRRPEvent, 1), nil)
	var ipv4Calls, ipv6Calls int
	v6Conn := &closeTrackingPacketConn{}
	err := vi.openSocketWith(
		func(string, *net.Interface, bool) (*ipv4.RawConn, net.PacketConn, error) {
			ipv4Calls++
			return nil, nil, errors.New("IPv4 must not be opened")
		},
		func(int) (int, error) { return -1, errors.New("AF_PACKET unavailable") },
		func(string, *net.Interface, bool) (net.PacketConn, int, error) {
			ipv6Calls++
			return v6Conn, 9, nil
		},
	)
	if err != nil {
		t.Fatalf("openSocketWith: %v", err)
	}
	if ipv4Calls != 0 || ipv6Calls != 1 {
		t.Fatalf("socket calls IPv4=%d IPv6=%d, want 0/1", ipv4Calls, ipv6Calls)
	}
	if vi.rawConn != nil || vi.conn != nil || vi.ipv6Conn == nil {
		t.Fatalf("wrong protocol sockets: raw=%v v4=%v v6=%v", vi.rawConn, vi.conn, vi.ipv6Conn)
	}
	vi.closeSockets()
	if !v6Conn.closed {
		t.Fatal("IPv6 connection was not closed")
	}
}

func TestOpenSocket_IPv6FailureRollsBackEarlierSockets(t *testing.T) {
	vi := newInstance(Instance{
		Interface: "ge-0-0-0", Family: "", GroupID: 101,
		VirtualAddresses: []string{"10.0.0.1/24", "2001:db8::1/64"},
	}, &net.Interface{Name: "ge-0-0-0", Index: 7}, make(chan VRRPEvent, 1), nil)
	v4Conn := &closeTrackingPacketConn{}
	err := vi.openSocketWith(
		func(string, *net.Interface, bool) (*ipv4.RawConn, net.PacketConn, error) {
			return nil, v4Conn, nil
		},
		func(int) (int, error) { return -1, errors.New("AF_PACKET unavailable") },
		func(string, *net.Interface, bool) (net.PacketConn, int, error) {
			return nil, -1, errors.New("IPv6 unavailable")
		},
	)
	if err == nil {
		t.Fatal("configured IPv6 family must fail closed when its socket cannot open")
	}
	if !v4Conn.closed {
		t.Fatal("IPv4 connection leaked after IPv6 open failure")
	}
	if vi.conn != nil || vi.rawConn != nil || vi.ipv6Conn != nil || vi.afPacketFD != -1 {
		t.Fatalf("partial sockets survived rollback: v4=%v raw=%v v6=%v af=%d", vi.conn, vi.rawConn, vi.ipv6Conn, vi.afPacketFD)
	}
}

func TestVRRPEvent_PreservesFamilyIdentity(t *testing.T) {
	events := make(chan VRRPEvent, 1)
	vi := newInstance(Instance{Interface: "ge-0-0-0", Family: "inet6", GroupID: 5},
		&net.Interface{Name: "ge-0-0-0", Index: 7}, events, nil)
	vi.emitEvent()
	if ev := <-events; ev.Family != "inet6" {
		t.Fatalf("event family=%q, want inet6", ev.Family)
	}
}

func TestClusterRGMethods_IgnoreStandaloneVRIDInRethRange(t *testing.T) {
	m := NewManager()
	standalone := newInstance(Instance{
		Interface: "ge-0-0-0", Family: "inet", GroupID: 101, Priority: 123,
	}, &net.Interface{Name: "ge-0-0-0", Index: 7}, m.eventCh, nil)
	m.instances[instanceKey{iface: "ge-0-0-0", groupID: 101, family: "inet"}] = standalone

	if ready, _ := m.RGVRRPReady(1, true); ready {
		t.Fatal("standalone VRID 101 falsely satisfied RETH RG1 readiness")
	}
	m.UpdateRGPriority(1, 222)
	if got := standalone.getPriority(); got != 123 {
		t.Fatalf("cluster priority update changed standalone instance to %d", got)
	}

	reth := newInstance(Instance{Interface: "reth0", GroupID: 101, Priority: 100},
		&net.Interface{Name: "reth0", Index: 8}, m.eventCh, nil)
	m.instances[instanceKey{iface: "reth0", groupID: 101}] = reth
	if ready, reasons := m.RGVRRPReady(1, true); !ready {
		t.Fatalf("RETH RG1 not ready: %v", reasons)
	}
	m.UpdateRGPriority(1, 222)
	if got := reth.getPriority(); got != 222 {
		t.Fatalf("cluster priority update missed RETH instance: %d", got)
	}
	if got := standalone.getPriority(); got != 123 {
		t.Fatalf("cluster priority update leaked to standalone instance: %d", got)
	}
}
