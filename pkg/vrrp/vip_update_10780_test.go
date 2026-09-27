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
	// Exercise the manager's MASTER update arm directly. A queued low-priority
	// peer advert could launch a separate winner-reaffirm GARP and contaminate
	// this test's capture of the membership-delta announcement.
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
	err := vi.ensureVIPFamilySocketsWith([]string{"2001:db8:1780::1/64"},
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

func TestUpdateInstances_PartialNetlinkFailureGatesReadinessAndRetries(t *testing.T) {
	tests := []struct {
		name          string
		oldVIPs       []string
		desiredVIPs   []string
		failedVIP     string
		failAdd       bool
		wantAfterFail []string
		wantGARP      string
	}{
		{
			name:          "add",
			oldVIPs:       []string{"172.16.83.1/32"},
			desiredVIPs:   []string{"172.16.83.1/32", "172.16.83.2/32"},
			failedVIP:     "172.16.83.2/32",
			failAdd:       true,
			wantAfterFail: []string{"172.16.83.1/32"},
			wantGARP:      "172.16.83.2",
		},
		{
			name:          "remove",
			oldVIPs:       []string{"172.16.84.1/32", "172.16.84.2/32"},
			desiredVIPs:   []string{"172.16.84.2/32"},
			failedVIP:     "172.16.84.1/32",
			wantAfterFail: []string{"172.16.84.2/32", "172.16.84.1/32"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := newTestManagerNoNetwork()
			defer stopManagerForTest(m)
			const iface = "reth10780-partial"
			key := instanceKey{iface: iface, groupID: 101}
			vi := seedRunningInstance(m, key, Instance{
				Interface: iface, GroupID: key.groupID, Priority: 200,
				VirtualAddresses: append([]string(nil), tc.oldVIPs...),
			}, 1)
			vi.setState(StateMaster)
			installFakeVIPNetlink(vi)

			failMutation := true
			vi.addrAddFn = func(_ netlink.Link, addr *netlink.Addr) error {
				if failMutation && tc.failAdd && addr.IPNet.String() == tc.failedVIP {
					return errSocketOpenFailed
				}
				return nil
			}
			vi.addrDelFn = func(_ netlink.Link, addr *netlink.Addr) error {
				if failMutation && !tc.failAdd && addr.IPNet.String() == tc.failedVIP {
					return errSocketOpenFailed
				}
				return nil
			}

			oldSend, oldGARP, oldNA, oldProbe := sendPacketFn, garpBurstFn, naBurstFn, arpProbeFn
			t.Cleanup(func() {
				sendPacketFn, garpBurstFn, naBurstFn, arpProbeFn = oldSend, oldGARP, oldNA, oldProbe
			})
			var adverts [][]string
			sendPacketFn = func(_ *vrrpInstance, pkt *VRRPPacket, _ bool) error {
				addrs := make([]string, 0, len(pkt.IPAddresses))
				for _, addr := range pkt.IPAddresses {
					addrs = append(addrs, addr.String())
				}
				adverts = append(adverts, addrs)
				return nil
			}
			var garps []string
			garpBurstFn = func(_ string, ip net.IP, _ int, _ cluster.BurstStillValid) error {
				garps = append(garps, ip.String())
				return nil
			}
			naBurstFn = func(_ string, _ net.IP, _ int, _ cluster.BurstStillValid) error { return nil }
			arpProbeFn = func(string, net.IP, net.IP) error { return nil }

			desired := &Instance{
				Interface: iface, GroupID: key.groupID, Priority: 200,
				VirtualAddresses: append([]string(nil), tc.desiredVIPs...),
			}
			if err := m.UpdateInstances([]*Instance{desired}); err != nil {
				t.Fatalf("UpdateInstances with injected netlink failure: %v", err)
			}
			if got := vi.vipsSnapshot(); !vipsEqual(got, tc.wantAfterFail) {
				t.Fatalf("VIPs after partial failure = %v, want %v", got, tc.wantAfterFail)
			}
			if vi.getState() != StateMaster {
				t.Fatalf("state after partial failure = %s, want MASTER", vi.getState())
			}
			if vi.vipUpdateFailures.Load() != 1 || !vi.vipUpdateDiverged.Load() {
				t.Fatalf("partial failure status: failures=%d diverged=%v, want 1/true",
					vi.vipUpdateFailures.Load(), vi.vipUpdateDiverged.Load())
			}
			if ready, reasons := m.RGVRRPReady(1, true); ready || len(reasons) == 0 {
				t.Fatalf("RGVRRPReady after partial failure = %v, reasons=%v; want not ready with reason",
					ready, reasons)
			}
			states := m.InstanceStates()
			if len(states) != 1 || !states[0].VIPDiverged ||
				states[0].VIPUpdateFailures != 1 ||
				!vipsEqual(states[0].VIPs, tc.wantAfterFail) {
				t.Fatalf("InstanceStates did not expose partial VIP divergence: %+v", states)
			}
			if len(adverts) == 0 || !vipsEqual(adverts[len(adverts)-1], wantIPs(tc.wantAfterFail)) {
				t.Fatalf("advertised addresses after partial failure = %v, want current safe set %v",
					adverts, wantIPs(tc.wantAfterFail))
			}
			if len(garps) != 0 {
				t.Fatalf("GARP sent for incomplete delta: %v", garps)
			}

			failMutation = false
			if err := m.UpdateInstances([]*Instance{desired}); err != nil {
				t.Fatalf("UpdateInstances retry: %v", err)
			}
			if got := vi.vipsSnapshot(); !vipsEqual(got, tc.desiredVIPs) {
				t.Fatalf("VIPs after retry = %v, want %v", got, tc.desiredVIPs)
			}
			if vi.getState() != StateMaster {
				t.Fatalf("state after retry = %s, want MASTER", vi.getState())
			}
			if vi.vipUpdateFailures.Load() != 1 || vi.vipUpdateDiverged.Load() {
				t.Fatalf("retry status: failures=%d diverged=%v, want 1/false",
					vi.vipUpdateFailures.Load(), vi.vipUpdateDiverged.Load())
			}
			if ready, reasons := m.RGVRRPReady(1, true); !ready {
				t.Fatalf("RGVRRPReady after successful retry = false: %v", reasons)
			}
			if tc.wantGARP != "" && (len(garps) != 1 || garps[0] != tc.wantGARP) {
				t.Fatalf("GARP after successful add retry = %v, want [%s]", garps, tc.wantGARP)
			}
			if tc.wantGARP == "" && len(garps) != 0 {
				t.Fatalf("GARP after remove retry = %v, want none", garps)
			}
		})
	}
}

func wantIPs(vips []string) []string {
	out := make([]string, 0, len(vips))
	for _, vip := range vips {
		ip, _, err := net.ParseCIDR(vip)
		if err != nil {
			continue
		}
		out = append(out, ip.String())
	}
	return out
}

func TestUpdateInstances_CapacityBoundaryFailedRemovalStaysAdvertisable(t *testing.T) {
	for _, isIPv6 := range []bool{false, true} {
		family := "ipv4"
		if isIPv6 {
			family = "ipv6"
		}
		t.Run(family, func(t *testing.T) {
			m, _ := newTestManagerNoNetwork()
			defer stopManagerForTest(m)

			const iface = "reth10780-capacity"
			key := instanceKey{iface: iface, groupID: 101}
			capacity := MaxConfiguredVIPs(isIPv6)
			oldVIPs := make([]string, 0, capacity)
			for i := 1; i <= capacity; i++ {
				oldVIPs = append(oldVIPs, capacityBoundaryVIP(isIPv6, i))
			}
			removedVIP := oldVIPs[len(oldVIPs)-1]
			desiredVIPs := append([]string(nil), oldVIPs[:len(oldVIPs)-1]...)
			desiredVIPs = append(desiredVIPs, capacityBoundaryVIP(isIPv6, capacity+1))

			vi := seedRunningInstance(m, key, Instance{
				Interface: iface, GroupID: key.groupID, Priority: 200,
				VirtualAddresses: append([]string(nil), oldVIPs...),
			}, 1)
			vi.setState(StateMaster)
			vi.suppressGARP.Store(true)
			installFakeVIPNetlink(vi)
			addCalls, delCalls := 0, 0
			vi.addrAddFn = func(netlink.Link, *netlink.Addr) error {
				addCalls++
				return nil
			}
			vi.addrDelFn = func(_ netlink.Link, addr *netlink.Addr) error {
				delCalls++
				if addr.IPNet.String() == removedVIP {
					return errSocketOpenFailed
				}
				return nil
			}

			oldSend := sendPacketFn
			t.Cleanup(func() { sendPacketFn = oldSend })
			marshalErrs := make([]error, 0, 1)
			sendPacketFn = func(_ *vrrpInstance, pkt *VRRPPacket, ipv6 bool) error {
				src, dst := net.ParseIP("198.18.255.254"), net.ParseIP("224.0.0.18")
				wire := *pkt
				if ipv6 {
					src, dst = net.ParseIP("fe80::1"), net.ParseIP("ff02::12")
					wire.IPAddresses = append([]net.IP{src}, pkt.IPAddresses...)
				}
				_, err := wire.Marshal(ipv6, src, dst)
				marshalErrs = append(marshalErrs, err)
				return err
			}

			desired := &Instance{
				Interface: iface, GroupID: key.groupID, Priority: 200,
				VirtualAddresses: desiredVIPs,
			}
			if err := m.UpdateInstances([]*Instance{desired}); err != nil {
				t.Fatalf("UpdateInstances at capacity boundary: %v", err)
			}
			if addCalls != 0 || delCalls != 1 {
				t.Fatalf("netlink operations after failed delete: adds=%d deletes=%d, want 0/1",
					addCalls, delCalls)
			}
			if got := vi.vipsSnapshot(); !vipsEqual(got, oldVIPs) {
				t.Fatalf("stored VIPs after failed delete = %d addresses, want original %d",
					len(got), len(oldVIPs))
			}
			if err := vi.getAdvertCapacityErr(); err != nil {
				t.Fatalf("retained advertisement set exceeds capacity: %v", err)
			}
			if vi.getState() != StateMaster {
				t.Fatalf("state after failed delete = %s, want MASTER", vi.getState())
			}
			if ready, reasons := m.RGVRRPReady(1, true); ready || len(reasons) == 0 {
				t.Fatalf("RGVRRPReady after incomplete delete = %v, reasons=%v; want not ready",
					ready, reasons)
			}
			if len(marshalErrs) != 1 || marshalErrs[0] != nil {
				t.Fatalf("advert Marshal results = %v, want one successful legal packet", marshalErrs)
			}
			states := m.InstanceStates()
			if len(states) != 1 || !states[0].VIPDiverged ||
				len(states[0].VIPs) != capacity {
				t.Fatalf("InstanceStates after capacity failure = %+v; want divergent full legal set", states)
			}
		})
	}
}

func TestUpdateInstances_RejectsOverCapacityDesiredWithoutStoppingMaster(t *testing.T) {
	m, rec := newTestManagerNoNetwork()
	defer stopManagerForTest(m)

	const iface = "reth10780-rejected"
	key := instanceKey{iface: iface, groupID: 101}
	const oldVIP = "198.18.111.1/32"
	vi := seedRunningInstance(m, key, Instance{
		Interface: iface, GroupID: key.groupID, Priority: 200,
		VirtualAddresses: []string{oldVIP},
	}, 1)
	vi.setState(StateMaster)

	overCapacity := []string{oldVIP}
	for i := 1; i <= MaxConfiguredVIPs(false); i++ {
		overCapacity = append(overCapacity, capacityBoundaryVIP(false, i))
	}
	if err := m.UpdateInstances([]*Instance{{
		Interface: iface, GroupID: key.groupID, Priority: 200,
		VirtualAddresses: overCapacity,
	}}); err != nil {
		t.Fatalf("UpdateInstances over-capacity desired set: %v", err)
	}
	m.mu.RLock()
	retained := m.instances[key]
	m.mu.RUnlock()
	if retained != vi || vi.getState() != StateMaster || !vipsEqual(vi.vipsSnapshot(), []string{oldVIP}) {
		t.Fatalf("rejected desired config changed live Master: same=%v state=%s VIPs=%v",
			retained == vi, vi.getState(), vi.vipsSnapshot())
	}
	if open, run, stop := rec.snapshot(); open != 0 || run != 0 || stop != 0 {
		t.Fatalf("rejected desired config caused lifecycle churn: open=%d run=%d stop=%d",
			open, run, stop)
	}
	if ready, reasons := m.RGVRRPReady(1, true); ready || len(reasons) == 0 {
		t.Fatalf("RGVRRPReady after rejected over-capacity config = %v, reasons=%v; want not ready",
			ready, reasons)
	}

	if err := m.UpdateInstances([]*Instance{{
		Interface: iface, GroupID: key.groupID, Priority: 200,
		VirtualAddresses: []string{oldVIP},
	}}); err != nil {
		t.Fatalf("UpdateInstances restoring valid desired set: %v", err)
	}
	if ready, reasons := m.RGVRRPReady(1, true); !ready {
		t.Fatalf("RGVRRPReady did not recover after valid desired set: %v", reasons)
	}
}

func capacityBoundaryVIP(isIPv6 bool, index int) string {
	if isIPv6 {
		ip := append(net.IP(nil), net.ParseIP("2001:db8::1").To16()...)
		ip[4] = byte(index >> 8)
		ip[5] = byte(index)
		ip[15] = 1
		return ip.String() + "/64"
	}
	return net.IPv4(198, 18, byte(index>>8), byte(index)).String() + "/32"
}

func TestVIPMembershipEpochSerializesGARPAndInvalidatesRemovedCallbacks(t *testing.T) {
	for _, isIPv6 := range []bool{false, true} {
		family := "ipv4"
		if isIPv6 {
			family = "ipv6"
		}
		t.Run(family, func(t *testing.T) {
			oldVIP, newVIP, keepVIP := "198.18.107.80/32", "198.18.107.81/32", "198.18.107.82/32"
			if isIPv6 {
				oldVIP, newVIP, keepVIP = "2001:db8:1078::1/64", "2001:db8:1078::2/64", "2001:db8:1078::3/64"
			}
			vi := newInstance(Instance{
				Interface: "reth10780-epoch", GroupID: 101, Priority: 200,
				VirtualAddresses: []string{oldVIP},
			}, &net.Interface{Name: "reth10780-epoch", Index: 10782}, nil, nil)
			vi.setState(StateMaster)
			installFakeVIPNetlink(vi)
			vi.addrsFn = func() ([]net.Addr, error) { return nil, nil }

			oldSend, oldGARP, oldNA, oldProbe := sendPacketFn, garpBurstFn, naBurstFn, arpProbeFn
			t.Cleanup(func() {
				sendPacketFn, garpBurstFn, naBurstFn, arpProbeFn = oldSend, oldGARP, oldNA, oldProbe
			})
			sendPacketFn = func(*vrrpInstance, *VRRPPacket, bool) error { return nil }

			var entered, release = make(chan struct{}), make(chan struct{})
			var callsMu sync.Mutex
			var sent []string
			burst := func(_ string, ip net.IP, _ int, valid cluster.BurstStillValid) error {
				callsMu.Lock()
				sent = append(sent, ip.String())
				first := len(sent) == 1
				callsMu.Unlock()
				if first {
					close(entered)
					<-release
				}
				if !valid() {
					t.Errorf("burst for %s was invalid while VIP update waited on the send lock", ip)
				}
				return nil
			}
			garpBurstFn, naBurstFn = burst, burst
			arpProbeFn = func(string, net.IP, net.IP) error { return nil }

			fullBurstDone := make(chan struct{})
			go func() {
				vi.sendGARP(false)
				close(fullBurstDone)
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("initial GARP/NA frame did not reach its seam")
			}
			updateDone := make(chan error, 1)
			updateStarted := make(chan struct{})
			go func() {
				close(updateStarted)
				updateDone <- vi.updateVIPs([]string{oldVIP, newVIP})
			}()
			<-updateStarted
			select {
			case err := <-updateDone:
				close(release)
				t.Fatalf("VIP update completed while the old burst still held vipMu: %v", err)
			case <-time.After(10 * time.Millisecond):
			}
			close(release)
			<-fullBurstDone
			if err := <-updateDone; err != nil {
				t.Fatalf("updateVIPs after serialized full-set burst: %v", err)
			}
			callsMu.Lock()
			gotSent := append([]string(nil), sent...)
			callsMu.Unlock()
			oldIP, _, _ := net.ParseCIDR(oldVIP)
			newIP, _, _ := net.ParseCIDR(newVIP)
			if len(gotSent) != 2 || gotSent[0] != oldIP.String() || gotSent[1] != newIP.String() {
				t.Fatalf("GARP/NA burst order = %v, want [%s %s]", gotSent, oldIP, newIP)
			}

			callbackVI := newInstance(Instance{
				Interface: "reth10780-remove", GroupID: 101, Priority: 200,
				VirtualAddresses: []string{oldVIP, newVIP, keepVIP},
			}, &net.Interface{Name: "reth10780-remove", Index: 10783}, nil, nil)
			callbackVI.setState(StateMaster)
			installFakeVIPNetlink(callbackVI)
			callbackVI.addrsFn = func() ([]net.Addr, error) { return nil, nil }
			removeAIP, _, _ := net.ParseCIDR(oldVIP)
			var stillCurrent cluster.BurstStillValid
			capture := func(_ string, ip net.IP, _ int, valid cluster.BurstStillValid) error {
				if ip.Equal(removeAIP) {
					stillCurrent = valid
				}
				return nil
			}
			garpBurstFn, naBurstFn = capture, capture
			callbackVI.sendGARP(false)
			if stillCurrent == nil || !stillCurrent() {
				t.Fatal("captured callback is not valid before membership removal")
			}

			deletingB, releaseDeleteB := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			finishDeleteB := func() { releaseOnce.Do(func() { close(releaseDeleteB) }) }
			defer finishDeleteB()
			delCalls := 0
			callbackVI.addrDelFn = func(_ netlink.Link, addr *netlink.Addr) error {
				delCalls++
				switch delCalls {
				case 1:
					if addr.IPNet.String() != oldVIP {
						t.Errorf("first delete = %s, want captured VIP %s", addr.IPNet, oldVIP)
					}
					return nil // A is now removed; next delete remains pending.
				case 2:
					if addr.IPNet.String() != newVIP {
						t.Errorf("second delete = %s, want %s", addr.IPNet, newVIP)
					}
					if stillCurrent() {
						t.Error("captured A callback remained valid after A deletion while B deletion was pending")
					}
					close(deletingB)
					<-releaseDeleteB
					return nil
				default:
					t.Errorf("unexpected delete %d for %s", delCalls, addr.IPNet)
					return nil
				}
			}
			removalDone := make(chan error, 1)
			go func() { removalDone <- callbackVI.updateVIPs([]string{keepVIP}) }()
			select {
			case <-deletingB:
			case <-time.After(time.Second):
				t.Fatal("removal update did not reach the pending second delete")
			}
			if stillCurrent() {
				t.Fatal("captured callback was valid during an in-flight non-empty removal update")
			}
			finishDeleteB()
			if err := <-removalDone; err != nil {
				t.Fatalf("non-empty removal update: %v", err)
			}
			if got := callbackVI.vipsSnapshot(); !vipsEqual(got, []string{keepVIP}) {
				t.Fatalf("VIP set after removal-only update = %v, want [%s]", got, keepVIP)
			}
		})
	}
}

func TestGARPPerVIPLockBoundsDemotionWait(t *testing.T) {
	for _, isIPv6 := range []bool{false, true} {
		family := "ipv4"
		vips := []string{"198.18.107.80/32", "198.18.107.81/32", "198.18.107.82/32"}
		if isIPv6 {
			family = "ipv6"
			vips = []string{"2001:db8:1078::1/64", "2001:db8:1078::2/64", "2001:db8:1078::3/64"}
		}
		t.Run(family, func(t *testing.T) {
			vi := newInstance(Instance{
				Interface: "reth10780-demote", GroupID: 101, Priority: 200,
				VirtualAddresses: vips,
			}, &net.Interface{Name: "reth10780-demote", Index: 10784}, nil, nil)
			vi.setState(StateMaster)
			installFakeVIPNetlink(vi)

			oldGARP, oldNA, oldProbe := garpBurstFn, naBurstFn, arpProbeFn
			t.Cleanup(func() { garpBurstFn, naBurstFn, arpProbeFn = oldGARP, oldNA, oldProbe })
			var burstCalls atomic.Int32
			firstFrame, releaseFrame := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseFrame) }) }
			defer release()
			burst := func(string, net.IP, int, cluster.BurstStillValid) error {
				if burstCalls.Add(1) == 1 {
					close(firstFrame)
					<-releaseFrame
				}
				return nil
			}
			garpBurstFn, naBurstFn = burst, burst
			arpProbeFn = func(string, net.IP, net.IP) error { return nil }

			sendDone := make(chan struct{})
			go func() {
				vi.sendGARP(false)
				close(sendDone)
			}()
			select {
			case <-firstFrame:
			case <-time.After(time.Second):
				t.Fatal("first per-VIP frame did not reach its seam")
			}

			masterDownTimer, advertTimer := time.NewTimer(time.Hour), time.NewTimer(time.Hour)
			t.Cleanup(func() {
				masterDownTimer.Stop()
				advertTimer.Stop()
			})
			demoteDone := make(chan error, 1)
			demoteStarted := make(chan struct{})
			go func() {
				close(demoteStarted)
				demoteDone <- vi.becomeBackup(masterDownTimer, advertTimer)
			}()
			<-demoteStarted
			select {
			case err := <-demoteDone:
				release()
				t.Fatalf("demotion completed while the current VIP first frame was blocked: %v", err)
			case <-time.After(10 * time.Millisecond):
			}

			releaseAt := time.Now()
			release()
			select {
			case err := <-demoteDone:
				if err != nil {
					t.Fatalf("becomeBackup: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("demotion did not resume after the current per-VIP frame returned")
			}
			if elapsed := time.Since(releaseAt); elapsed > 250*time.Millisecond {
				t.Fatalf("demotion waited %s after releasing one VIP frame; want <250ms", elapsed)
			}
			select {
			case <-sendDone:
			case <-time.After(time.Second):
				t.Fatal("GARP sender did not stop after demotion")
			}
			if got := burstCalls.Load(); got != 1 {
				t.Fatalf("bursts sent before demotion completed = %d, want only current VIP's frame", got)
			}
			if vi.getState() != StateBackup {
				t.Fatalf("state after demotion = %s, want BACKUP", vi.getState())
			}
		})
	}
}
