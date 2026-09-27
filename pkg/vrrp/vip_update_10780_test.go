package vrrp

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// TestUpdateInstances_VIPSetChangeKeepsMasterWithoutResignation covers a
// single-unit dual-stack RETH instance. The existing run loop is real so a
// restart regression exercises vi.stop()'s shutdown resignation path and puts
// actual priority-zero packets into the captured send seam (the pre-fix RED).
func TestUpdateInstances_VIPSetChangeKeepsMasterWithoutResignation(t *testing.T) {
	m := NewManager()
	m.resolveIface = func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name, Index: 17}, nil
	}
	m.subscribeAddrs = func(chan<- netlink.AddrUpdate, <-chan struct{}) error {
		return errAddrSubscribeDisabled
	}
	m.openInstanceSocket = func(*vrrpInstance) error { return nil }
	m.ensureVIPFamilySockets = func(*vrrpInstance, []string) error { return nil }
	m.runInstance = func(vi *vrrpInstance) { go vi.run() }
	var stopCalls atomic.Int32
	m.stopInstance = func(vi *vrrpInstance) {
		stopCalls.Add(1)
		vi.stop()
	}

	const iface = "reth10780"
	key := instanceKey{iface: iface, groupID: 101}
	oldVIP := "172.16.80.1/24"
	newVIP := "172.16.80.2/24"
	v6VIP := "2001:db8:80::1/64"
	vi := newInstance(Instance{
		Interface: iface, GroupID: 101, Priority: 200, Preempt: true,
		AdvertiseInterval: 100, GARPCount: 1,
		VirtualAddresses: []string{oldVIP, v6VIP},
	}, &net.Interface{Name: iface, Index: 17}, m.eventCh, nil)
	vi.suppressGARP.Store(true) // suppress only the synthetic startup tenure's GARP
	installFakeVIPNetlink(vi)
	var actMu sync.Mutex
	var actuations []string
	vi.addrAddFn = func(_ netlink.Link, addr *netlink.Addr) error {
		actMu.Lock()
		actuations = append(actuations, "add:"+addr.IPNet.String())
		actMu.Unlock()
		return nil
	}
	vi.addrDelFn = func(_ netlink.Link, addr *netlink.Addr) error {
		actMu.Lock()
		actuations = append(actuations, "del:"+addr.IPNet.String())
		actMu.Unlock()
		return nil
	}
	vi.addrsFn = func() ([]net.Addr, error) {
		return []net.Addr{ipnetAddr(t, "172.16.80.254/24"), ipnetAddr(t, "fe80::1/64")}, nil
	}
	m.instances[key] = vi

	var sendMu sync.Mutex
	var priorities []uint8
	var v4AdvertIPs, v6AdvertIPs []string
	prevSend := sendPacketFn
	sendPacketFn = func(_ *vrrpInstance, pkt *VRRPPacket, isIPv6 bool) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		priorities = append(priorities, pkt.Priority)
		var ips []string
		for _, ip := range pkt.IPAddresses {
			ips = append(ips, ip.String())
		}
		if isIPv6 {
			v6AdvertIPs = ips
		} else {
			v4AdvertIPs = ips
		}
		return nil
	}
	prevGARP, prevNA, prevProbe := garpBurstFn, naBurstFn, arpProbeFn
	var garped []string
	garpBurstFn = func(_ string, ip net.IP, _ int, _ cluster.BurstStillValid) error {
		garped = append(garped, ip.String())
		return nil
	}
	naBurstFn = func(string, net.IP, int, cluster.BurstStillValid) error { return nil }
	arpProbeFn = func(string, net.IP, net.IP) error { return nil }
	t.Cleanup(func() {
		// Let the run loop finish (including any shutdown send) before
		// restoring package-level seams it may still be using.
		vi.setState(StateBackup)
		m.Stop()
		sendPacketFn = prevSend
		garpBurstFn, naBurstFn, arpProbeFn = prevGARP, prevNA, prevProbe
	})

	go vi.run()
	select {
	case evt := <-m.Events():
		if evt.State != StateBackup {
			t.Fatalf("startup state = %s, want BACKUP", evt.State)
		}
	case <-time.After(time.Second):
		t.Fatal("VRRP run loop did not publish its startup BACKUP state")
	}
	actMu.Lock()
	actuations = nil // exclude the startup stale-VIP sweep
	actMu.Unlock()
	vi.setState(StateMaster)
	// Wake the run loop's BACKUP select so it observes MASTER before the
	// manager update; this advert is lower priority and cannot preempt us.
	vi.rxCh <- &VRRPPacket{Priority: 1, MaxAdvertInt: 10, SrcIP: net.ParseIP("192.0.2.2")}
	deadline := time.Now().Add(time.Second)
	for vi.getState() != StateMaster && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if vi.getState() != StateMaster {
		t.Fatal("fixture failed to put the live run loop in MASTER")
	}
	vi.suppressGARP.Store(false)

	if err := m.UpdateInstances([]*Instance{{
		Interface: iface, GroupID: 101, Priority: 200, Preempt: true,
		AdvertiseInterval: 100, GARPCount: 1,
		VirtualAddresses: []string{newVIP, v6VIP},
	}}); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}

	m.mu.RLock()
	gotInstance := m.instances[key]
	m.mu.RUnlock()
	if gotInstance != vi {
		t.Fatal("VIP-set commit replaced the live dual-stack instance")
	}
	if got := vi.getState(); got != StateMaster {
		t.Fatalf("state after VIP-set commit = %s, want MASTER", got)
	}
	if got := stopCalls.Load(); got != 0 {
		t.Fatalf("stopInstance calls = %d, want 0 for an ordinary VIP-set commit", got)
	}
	sendMu.Lock()
	gotPriorities := append([]uint8(nil), priorities...)
	gotV4, gotV6 := append([]string(nil), v4AdvertIPs...), append([]string(nil), v6AdvertIPs...)
	sendMu.Unlock()
	if len(gotPriorities) != 2 || gotPriorities[0] != 200 || gotPriorities[1] != 200 {
		t.Fatalf("advert priorities = %v, want one priority-200 v4 and v6 advert", gotPriorities)
	}
	actMu.Lock()
	gotActuations := append([]string(nil), actuations...)
	actMu.Unlock()
	if len(gotActuations) != 2 ||
		gotActuations[0] != "add:172.16.80.2/24" ||
		gotActuations[1] != "del:172.16.80.1/24" {
		t.Fatalf("VIP netlink delta = %v, want add new before deleting old", gotActuations)
	}
	if len(gotV4) != 1 || gotV4[0] != "172.16.80.2" {
		t.Fatalf("IPv4 advert VIPs = %v, want only new address 172.16.80.2", gotV4)
	}
	if len(gotV6) != 1 || gotV6[0] != "2001:db8:80::1" {
		t.Fatalf("IPv6 advert VIPs = %v, want unchanged address", gotV6)
	}
	if len(garped) != 1 || garped[0] != "172.16.80.2" {
		t.Fatalf("GARP VIPs = %v, want only newly added address", garped)
	}
}

func TestUpdateInstances_AddedFamilySocketReadyBeforeVIPPublish(t *testing.T) {
	m, _ := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	const iface = "reth10780-family"
	key := instanceKey{iface: iface, groupID: 101}
	oldVIP := "172.16.81.1/24"
	newVIP := "2001:db8:81::1/64"
	vi := seedRunningInstance(m, key, Instance{
		Interface: iface, GroupID: 101, Priority: 200, Preempt: true,
		VirtualAddresses: []string{oldVIP},
	}, 1)
	vi.setState(StateMaster)
	vi.suppressGARP.Store(true)
	installFakeVIPNetlink(vi)
	vi.addrsFn = func() ([]net.Addr, error) {
		return []net.Addr{ipnetAddr(t, "172.16.81.254/24"), ipnetAddr(t, "fe80::1/64")}, nil
	}

	ensureSawOldSet := false
	m.ensureVIPFamilySockets = func(existing *vrrpInstance, desired []string) error {
		if !vipsEqual(existing.vipsSnapshot(), []string{oldVIP}) ||
			!vipsEqual(desired, []string{oldVIP, newVIP}) {
			t.Errorf("socket ensure ordering: configured=%v desired=%v",
				existing.vipsSnapshot(), desired)
		}
		ensureSawOldSet = true
		existing.socketMu.Lock()
		existing.ipv6Conn = stubPacketConn{}
		existing.ipv6FD = -1
		existing.ipv6Send = func([]byte, *ipv6.ControlMessage, net.Addr) error { return nil }
		existing.socketMu.Unlock()
		return nil
	}

	prevSend := sendPacketFn
	var sendMu sync.Mutex
	var sentFamilies []bool
	sendPacketFn = func(_ *vrrpInstance, pkt *VRRPPacket, isIPv6 bool) error {
		sendMu.Lock()
		sentFamilies = append(sentFamilies, isIPv6)
		sendMu.Unlock()
		return nil
	}
	t.Cleanup(func() { sendPacketFn = prevSend })

	if err := m.UpdateInstances([]*Instance{{
		Interface: iface, GroupID: 101, Priority: 200, Preempt: true,
		VirtualAddresses: []string{oldVIP, newVIP},
	}}); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}
	if !ensureSawOldSet {
		t.Fatal("new-family socket ensure was not called before VIP publication")
	}
	vi.mu.RLock()
	gotVIPs := append([]string(nil), vi.cfg.VirtualAddresses...)
	vi.mu.RUnlock()
	if !vipsEqual(gotVIPs, []string{oldVIP, newVIP}) {
		t.Fatalf("published VIP set = %v, want IPv4+IPv6 set", gotVIPs)
	}
	vi.socketMu.RLock()
	hasIPv6Socket := vi.ipv6Conn != nil && vi.ipv6Send != nil
	vi.socketMu.RUnlock()
	if !hasIPv6Socket {
		t.Fatal("new IPv6 VIP set was published without a usable IPv6 socket")
	}
	sendMu.Lock()
	gotFamilies := append([]bool(nil), sentFamilies...)
	sendMu.Unlock()
	if len(gotFamilies) != 2 || gotFamilies[0] || !gotFamilies[1] {
		t.Fatalf("advert families = %v, want IPv4 then IPv6", gotFamilies)
	}
}

func TestUpdateInstances_FamilySocketFailureStillAppliesScalarConfig(t *testing.T) {
	m, _ := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	const iface = "reth10780-family-failure"
	oldVIP := "172.16.82.1/24"
	vi := seedRunningInstance(m, instanceKey{iface: iface, groupID: 101}, Instance{
		Interface: iface, GroupID: 101, Priority: 200, Preempt: true,
		VirtualAddresses: []string{oldVIP},
	}, 1)
	ensureCalls := 0
	m.ensureVIPFamilySockets = func(*vrrpInstance, []string) error {
		ensureCalls++
		return errSocketOpenFailed
	}

	if err := m.UpdateInstances([]*Instance{{
		Interface: iface, GroupID: 101, Priority: 220, Preempt: false,
		VirtualAddresses: []string{oldVIP, "2001:db8:82::1/64"},
	}}); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}
	if ensureCalls != 1 {
		t.Fatalf("new-family socket attempts = %d, want 1", ensureCalls)
	}
	vi.mu.RLock()
	gotPriority, gotPreempt := vi.cfg.Priority, vi.cfg.Preempt
	gotVIPs := append([]string(nil), vi.cfg.VirtualAddresses...)
	vi.mu.RUnlock()
	if gotPriority != 220 || gotPreempt {
		t.Fatalf("scalar config after socket failure = priority %d preempt %t, want 220/false",
			gotPriority, gotPreempt)
	}
	if !vipsEqual(gotVIPs, []string{oldVIP}) {
		t.Fatalf("VIP set after family socket failure = %v, want old set %v", gotVIPs, []string{oldVIP})
	}
}

// TestUpdateInstances_VLANUnitVIPChangeDoesNotBounceSibling covers the
// multi-unit VLAN-split case: a per-subinterface VIP edit keeps the changed
// unit's state machine and the sibling unit's state machine in place.
func TestUpdateInstances_VLANUnitVIPChangeDoesNotBounceSibling(t *testing.T) {
	m, rec := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	mk := func(iface, vip string) *vrrpInstance {
		vi := seedRunningInstance(m, instanceKey{iface: iface, groupID: 101}, Instance{
			Interface: iface, GroupID: 101, Priority: 200, Preempt: true,
			VirtualAddresses: []string{vip},
		}, 1)
		vi.setState(StateMaster)
		vi.suppressGARP.Store(true)
		installFakeVIPNetlink(vi)
		vi.addrsFn = func() ([]net.Addr, error) { return nil, nil }
		return vi
	}
	unit50 := mk("reth0.50", "172.16.50.1/24")
	unit80 := mk("reth0.80", "172.16.80.1/24")

	if err := m.UpdateInstances([]*Instance{
		{Interface: "reth0.50", GroupID: 101, Priority: 200, Preempt: true,
			VirtualAddresses: []string{"172.16.50.2/24"}},
		{Interface: "reth0.80", GroupID: 101, Priority: 200, Preempt: true,
			VirtualAddresses: []string{"172.16.80.1/24"}},
	}); err != nil {
		t.Fatalf("UpdateInstances: %v", err)
	}

	m.mu.RLock()
	got50 := m.instances[instanceKey{iface: "reth0.50", groupID: 101}]
	got80 := m.instances[instanceKey{iface: "reth0.80", groupID: 101}]
	m.mu.RUnlock()
	if got50 != unit50 || got80 != unit80 {
		t.Fatalf("VLAN unit instances changed: reth0.50 same=%v reth0.80 same=%v", got50 == unit50, got80 == unit80)
	}
	if unit50.getState() != StateMaster || unit80.getState() != StateMaster {
		t.Fatalf("VLAN unit states after VIP edit: reth0.50=%s reth0.80=%s, want both MASTER",
			unit50.getState(), unit80.getState())
	}
	if got := unit50.vipsSnapshot(); len(got) != 1 || got[0] != "172.16.50.2/24" {
		t.Fatalf("edited VLAN unit VIP set = %v, want replacement address", got)
	}
	if got := unit80.vipsSnapshot(); len(got) != 1 || got[0] != "172.16.80.1/24" {
		t.Fatalf("sibling VLAN unit VIP set = %v, want unchanged", got)
	}
	if open, run, stop := rec.snapshot(); open != 0 || run != 0 || stop != 0 {
		t.Fatalf("VLAN VIP edit caused lifecycle churn: open=%d run=%d stop=%d", open, run, stop)
	}
}

func TestEnsureVIPFamilySocketsOpensNewIPv6Family(t *testing.T) {
	vi := newInstance(Instance{Interface: "reth10780", Family: "inet6", GroupID: 101},
		&net.Interface{Name: "reth10780", Index: 17}, nil, nil)
	vi.afPacketFD = 99 // existing AF_PACKET receiver avoids raw fallback startup
	opened := 0
	err := vi.ensureVIPFamilySocketsWith([]string{"2001:db8:10780::1/64"},
		func(string, *net.Interface, bool) (*ipv4.RawConn, net.PacketConn, error) {
			t.Fatal("IPv4 socket opener called for IPv6-only desired set")
			return nil, nil, nil
		},
		func(string, *net.Interface, bool) (net.PacketConn, int, error) {
			opened++
			return newIPv6TestPacketConn(t), -1, nil
		})
	if err != nil {
		t.Fatalf("ensureVIPFamilySocketsWith: %v", err)
	}
	if opened != 1 || vi.ipv6Conn == nil || vi.ipv6FD != -1 || vi.ipv6Send == nil {
		t.Fatalf("IPv6 family socket setup: opened=%d conn=%v fd=%d send=%v",
			opened, vi.ipv6Conn != nil, vi.ipv6FD, vi.ipv6Send != nil)
	}
}

type ipv6TestPacketConn struct {
	net.Conn
}

func (c ipv6TestPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(p)
	return n, c.Conn.RemoteAddr(), err
}

func (c ipv6TestPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Conn.Write(p)
}

func newIPv6TestPacketConn(t *testing.T) net.PacketConn {
	t.Helper()
	conn, peer := net.Pipe()
	t.Cleanup(func() {
		_ = conn.Close()
		_ = peer.Close()
	})
	return ipv6TestPacketConn{Conn: conn}
}
