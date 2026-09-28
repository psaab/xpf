package vrrp

import (
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

func goroutineWaitingOnVIPMu(vi *vrrpInstance, caller string, stack []byte) bool {
	n := runtime.Stack(stack, true)
	lockFrame := fmt.Sprintf("lockSlow(%p)", &vi.vipMu)
	for _, goroutine := range strings.Split(string(stack[:n]), "\n\n") {
		lineEnd := strings.IndexByte(goroutine, '\n')
		if lineEnd < 0 || !strings.Contains(goroutine[:lineEnd], "sync.Mutex.Lock") {
			continue
		}
		if strings.Contains(goroutine, caller) &&
			strings.Contains(goroutine, lockFrame) &&
			strings.Contains(goroutine, "sync.(*Mutex).Lock") {
			return true
		}
	}
	return false
}

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

// TestVIPSpellingAliasKeepsKernelAddressAndMasterReady covers raw IPv6
// spellings that parse to the same address/prefix. The fake kernel models
// EEXIST by binary address identity so add-first followed by delete would
// reproduce the dark-but-ready failure without a live interface.
func TestVIPSpellingAliasKeepsKernelAddressAndMasterReady(t *testing.T) {
	const iface = "reth10780-alias"
	const oldVIP = "2001:0DB8:0:0::1/64"
	const newVIP = "2001:db8::1/64"

	changedPrefix := "2001:db8::1/128"
	added, removed := vipSetDelta([]string{oldVIP}, []string{changedPrefix})
	if !vipsEqual(added, []string{changedPrefix}) || !vipsEqual(removed, []string{oldVIP}) {
		t.Fatalf("prefix change delta = added %v, removed %v; want replacement", added, removed)
	}

	m, _ := newTestManagerNoNetwork()
	defer stopManagerForTest(m)
	vi := newInstance(Instance{
		Interface: iface, GroupID: 101, Priority: 200, AdvertiseInterval: 100,
		GARPCount: 1, VirtualAddresses: []string{oldVIP},
	}, &net.Interface{Name: iface, Index: 1}, m.eventCh, nil)
	vi.setState(StateMaster)
	vi.vipMu.Lock()
	vi.addPendingGARPVIPsLocked([]string{oldVIP})
	vi.vipMu.Unlock()
	initialGarpEpoch := vi.garpEpoch.Load()
	installFakeVIPNetlink(vi)

	kernelVIPs := map[string]bool{canonicalVIPIdentity(oldVIP): true}
	var addCalls, deleteCalls int
	vi.addrAddFn = func(_ netlink.Link, addr *netlink.Addr) error {
		addCalls++
		key := canonicalVIPIdentity(addr.IPNet.String())
		if kernelVIPs[key] {
			return unix.EEXIST
		}
		kernelVIPs[key] = true
		return nil
	}
	vi.addrDelFn = func(_ netlink.Link, addr *netlink.Addr) error {
		deleteCalls++
		key := canonicalVIPIdentity(addr.IPNet.String())
		if !kernelVIPs[key] {
			return unix.EADDRNOTAVAIL
		}
		delete(kernelVIPs, key)
		return nil
	}
	key := instanceKey{iface: iface, groupID: 101}
	m.mu.Lock()
	m.instances[key] = vi
	m.mu.Unlock()

	oldSend, oldGARP, oldNA, oldProbe := sendPacketFn, garpBurstFn, naBurstFn, arpProbeFn
	t.Cleanup(func() {
		sendPacketFn = oldSend
		garpBurstFn, naBurstFn, arpProbeFn = oldGARP, oldNA, oldProbe
	})
	var advertised [][]string
	var advertFamilies []bool
	sendPacketFn = func(_ *vrrpInstance, pkt *VRRPPacket, isIPv6 bool) error {
		ips := make([]string, len(pkt.IPAddresses))
		for i, ip := range pkt.IPAddresses {
			ips[i] = ip.String()
		}
		advertised = append(advertised, ips)
		advertFamilies = append(advertFamilies, isIPv6)
		return nil
	}
	var garped []string
	burst := func(_ string, ip net.IP, _ int, _ cluster.BurstStillValid) error {
		garped = append(garped, ip.String())
		return nil
	}
	garpBurstFn, naBurstFn = burst, burst
	arpProbeFn = func(string, net.IP, net.IP) error { return nil }

	if err := m.UpdateInstances([]*Instance{{
		Interface: iface, GroupID: 101, Priority: 200, AdvertiseInterval: 100,
		GARPCount: 1, VirtualAddresses: []string{newVIP},
	}}); err != nil {
		t.Fatalf("spelling-only update: %v", err)
	}
	if !kernelVIPs[canonicalVIPIdentity(newVIP)] {
		t.Fatal("canonical VIP is absent from the fake kernel after the update")
	}
	if got := vi.garpEpoch.Load(); got != initialGarpEpoch {
		t.Fatalf("spelling-only update advanced GARP epoch: got %d, want %d",
			got, initialGarpEpoch)
	}
	if addCalls != 0 || deleteCalls != 0 {
		t.Fatalf("spelling-only update touched netlink: adds=%d deletes=%d", addCalls, deleteCalls)
	}
	vi.vipMu.Lock()
	var pendingVIPs []string
	for vip := range vi.pendingGARPVIPs {
		pendingVIPs = append(pendingVIPs, vip)
	}
	vi.vipMu.Unlock()
	if !vipsEqual(pendingVIPs, []string{newVIP}) {
		t.Fatalf("pending VIPs after spelling adoption = %v, want [%s]", pendingVIPs, newVIP)
	}
	if got := vi.vipsSnapshot(); !vipsEqual(got, []string{newVIP}) {
		t.Fatalf("stored VIP spelling = %v, want [%s]", got, newVIP)
	}
	if vi.getState() != StateMaster || vi.vipUpdateDiverged.Load() {
		t.Fatalf("state=%s diverged=%v, want healthy MASTER", vi.getState(), vi.vipUpdateDiverged.Load())
	}
	if ready, reasons := m.RGVRRPReady(1, true); !ready {
		t.Fatalf("RGVRRPReady = false after spelling-only update: %v", reasons)
	}
	if len(advertised) != 0 || len(garped) != 0 {
		t.Fatalf("spelling-only update caused a duplicate announcement: adverts=%v GARP/NA=%v",
			advertised, garped)
	}

	// Exercise the normal send paths after adoption: both must name the
	// normalized address once, without manufacturing a second update burst.
	vi.sendAdvert(vi.getPriority())
	vi.garpEpoch.Add(1)
	vi.sendGARP(true)
	vi.vipMu.Lock()
	pendingCount := len(vi.pendingGARPVIPs)
	vi.vipMu.Unlock()
	if pendingCount != 0 {
		t.Fatalf("successful canonical announcement left %d pending VIPs", pendingCount)
	}
	if len(advertised) != 1 || !advertFamilies[0] ||
		!vipsEqual(advertised[0], []string{"2001:db8::1"}) {
		t.Fatalf("IPv6 advert addresses = %v (families=%v), want one canonical VIP",
			advertised, advertFamilies)
	}
	if !vipsEqual(garped, []string{"2001:db8::1"}) {
		t.Fatalf("GARP/NA addresses = %v, want one canonical VIP", garped)
	}
	if addCalls != 0 || deleteCalls != 0 || len(garped) != 1 {
		t.Fatalf("duplicate or netlink work after send: adds=%d deletes=%d GARP/NA=%v",
			addCalls, deleteCalls, garped)
	}
}

// TestVIPSpellingAliasDuringReservedBurstDoesNotStrandPending pins the race
// where an old raw snapshot finishes after a spelling-only adoption. Pending
// state must use parsed identity so the old snapshot's successful completion
// cannot strand work under the new spelling.
func TestVIPSpellingAliasDuringReservedBurstDoesNotStrandPending(t *testing.T) {
	const iface = "reth10780-pending-alias"
	const vipCount = 16
	vips := make([]string, vipCount)
	for i := range vips {
		vips[i] = fmt.Sprintf("2001:db8:1078::%x/64", i+1)
	}
	aliasVips := append([]string(nil), vips...)
	aliasVips[vipCount-1] = "2001:0DB8:1078:0:0:0:0:10/64"
	if canonicalVIPIdentity(aliasVips[vipCount-1]) != canonicalVIPIdentity(vips[vipCount-1]) {
		t.Fatalf("test alias does not identify the final VIP: %s vs %s",
			aliasVips[vipCount-1], vips[vipCount-1])
	}
	addedVIP := "2001:db8:1078::11/64"

	vi := newInstance(Instance{
		Interface: iface, GroupID: 101, Priority: 200, GARPCount: 1,
		VirtualAddresses: vips,
	}, &net.Interface{Name: iface, Index: 10786}, make(chan VRRPEvent, 32), nil)
	vi.setState(StateMaster)
	vi.garpEpoch.Store(1)
	installFakeVIPNetlink(vi)
	vi.addrsFn = func() ([]net.Addr, error) { return nil, nil }

	oldSend, oldGARP, oldNA, oldProbe := sendPacketFn, garpBurstFn, naBurstFn, arpProbeFn
	t.Cleanup(func() {
		sendPacketFn = oldSend
		garpBurstFn, naBurstFn, arpProbeFn = oldGARP, oldNA, oldProbe
	})
	sendPacketFn = func(*vrrpInstance, *VRRPPacket, bool) error { return nil }
	var sentMu sync.Mutex
	var sent []string
	var burstCalls atomic.Int32
	fifteenEntered, releaseFifteen := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseFifteen) }) }
	burst := func(_ string, ip net.IP, _ int, _ cluster.BurstStillValid) error {
		call := burstCalls.Add(1)
		sentMu.Lock()
		sent = append(sent, ip.String())
		sentMu.Unlock()
		if call == 15 {
			close(fifteenEntered)
			<-releaseFifteen
		}
		return nil
	}
	garpBurstFn, naBurstFn = burst, burst
	arpProbeFn = func(string, net.IP, net.IP) error { return nil }

	sendDone := make(chan struct{})
	aliasDone := make(chan error, 1)
	addDone := make(chan error, 1)
	sendStarted, aliasStarted, addStarted := false, false, false
	sendFinished, aliasFinished, addFinished := false, false, false
	defer func() {
		release()
		if sendStarted && !sendFinished {
			select {
			case <-sendDone:
			case <-time.After(time.Second):
				t.Error("old-snapshot sender did not stop during cleanup")
			}
		}
		if aliasStarted && !aliasFinished {
			select {
			case <-aliasDone:
			case <-time.After(time.Second):
				t.Error("spelling update did not stop during cleanup")
			}
		}
		if addStarted && !addFinished {
			select {
			case <-addDone:
			case <-time.After(time.Second):
				t.Error("addition update did not stop during cleanup")
			}
		}
	}()

	sendStarted = true
	go func() {
		vi.sendGARP(false)
		close(sendDone)
	}()
	select {
	case <-fifteenEntered:
	case <-time.After(time.Second):
		t.Fatal("old snapshot did not reach VIP 15")
	}
	sentMu.Lock()
	beforeAlias := append([]string(nil), sent...)
	sentMu.Unlock()
	if len(beforeAlias) != 15 {
		t.Fatalf("frames before alias update = %d, want 15: %v", len(beforeAlias), beforeAlias)
	}

	aliasStarted = true
	go func() { aliasDone <- vi.updateVIPs(aliasVips) }()
	stack := make([]byte, 1<<20)
	parkDeadline := time.Now().Add(time.Second)
	for !goroutineWaitingOnVIPMu(vi, "updateVIPs", stack) &&
		time.Now().Before(parkDeadline) {
		runtime.Gosched()
	}
	if !goroutineWaitingOnVIPMu(vi, "updateVIPs", stack) {
		release()
		t.Fatalf("spelling update did not park on vipMu during frame 15:\n%s",
			stack[:runtime.Stack(stack, true)])
	}
	time.Sleep(10 * time.Millisecond)
	if !goroutineWaitingOnVIPMu(vi, "updateVIPs", stack) {
		release()
		t.Fatal("spelling update stopped waiting before frame 15 was released")
	}
	release()
	select {
	case err := <-aliasDone:
		aliasFinished = true
		if err != nil {
			t.Fatalf("spelling-only update: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("spelling-only update did not finish")
	}
	select {
	case <-sendDone:
		sendFinished = true
	case <-time.After(time.Second):
		t.Fatal("old-snapshot sender did not finish after spelling adoption")
	}

	vi.vipMu.Lock()
	pendingAfterOldBurst := len(vi.pendingGARPVIPs)
	vi.vipMu.Unlock()
	if pendingAfterOldBurst != 0 {
		t.Errorf("pending VIP identities after successful old snapshot = %d, want 0",
			pendingAfterOldBurst)
	}

	wantAfterAdd := append(append([]string(nil), aliasVips...), addedVIP)
	addStarted = true
	go func() { addDone <- vi.updateVIPs(wantAfterAdd) }()
	select {
	case err := <-addDone:
		addFinished = true
		if err != nil {
			t.Fatalf("unrelated VIP addition after alias completion: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("unrelated VIP addition did not finish")
	}

	lastIP, _, _ := net.ParseCIDR(aliasVips[vipCount-1])
	addedIP, _, _ := net.ParseCIDR(addedVIP)
	sentMu.Lock()
	gotSent := append([]string(nil), sent...)
	sentMu.Unlock()
	counts := make(map[string]int, len(gotSent))
	for _, ip := range gotSent {
		counts[ip]++
	}
	if counts[lastIP.String()] != 1 {
		t.Fatalf("aliased survivor first-frame count = %d, want 1; sent=%v",
			counts[lastIP.String()], gotSent)
	}
	if counts[addedIP.String()] != 1 || len(gotSent) != vipCount+1 {
		t.Fatalf("addition announcement was not bounded: new=%d total=%d sent=%v",
			counts[addedIP.String()], len(gotSent), gotSent)
	}
	vi.vipMu.Lock()
	pendingAfterAdd := len(vi.pendingGARPVIPs)
	vi.vipMu.Unlock()
	if pendingAfterAdd != 0 {
		t.Fatalf("pending VIP identities after successful add announcement = %d, want 0",
			pendingAfterAdd)
	}
}

func TestVIPMembershipRemovalPreservesUnsentSurvivorAnnouncement(t *testing.T) {
	for _, isIPv6 := range []bool{false, true} {
		family := "ipv4"
		vips := []string{
			"198.18.107.80/32", "198.18.107.81/32",
			"198.18.107.82/32", "198.18.107.83/32",
		}
		if isIPv6 {
			family = "ipv6"
			vips = []string{
				"2001:db8:1078::1/64", "2001:db8:1078::2/64",
				"2001:db8:1078::3/64", "2001:db8:1078::4/64",
			}
		}
		t.Run(family, func(t *testing.T) {
			eventCh := make(chan VRRPEvent, 8)
			vi := newInstance(Instance{
				Interface: "reth10780-survivor", GroupID: 101, Priority: 200,
				VirtualAddresses: vips,
			}, &net.Interface{Name: "reth10780-survivor", Index: 10785}, eventCh, nil)
			vi.setState(StateMaster)
			installFakeVIPNetlink(vi)
			vi.addrsFn = func() ([]net.Addr, error) { return nil, nil }

			oldSend, oldGARP, oldNA, oldProbe := sendPacketFn, garpBurstFn, naBurstFn, arpProbeFn
			t.Cleanup(func() {
				sendPacketFn, garpBurstFn, naBurstFn, arpProbeFn = oldSend, oldGARP, oldNA, oldProbe
			})
			sendPacketFn = func(*vrrpInstance, *VRRPPacket, bool) error { return nil }

			var sentMu sync.Mutex
			var sent []string
			var burstCalls atomic.Int32
			firstFrame, releaseFrame := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseFrame) }) }
			sendDone := make(chan struct{})
			updateDone := make(chan error, 1)
			updateStarted, sendFinished, updateFinished := false, false, false
			defer func() {
				release()
				if !sendFinished {
					select {
					case <-sendDone:
					case <-time.After(time.Second):
						t.Error("initial full-set sender did not stop during cleanup")
					}
				}
				if updateStarted && !updateFinished {
					select {
					case <-updateDone:
					case <-time.After(time.Second):
						t.Error("removal update did not stop during cleanup")
					}
				}
			}()
			burst := func(_ string, ip net.IP, _ int, _ cluster.BurstStillValid) error {
				call := burstCalls.Add(1)
				sentMu.Lock()
				sent = append(sent, ip.String())
				sentMu.Unlock()
				if call == 1 {
					close(firstFrame)
					<-releaseFrame
				} else {
					time.Sleep(5 * time.Millisecond)
				}
				return nil
			}
			garpBurstFn, naBurstFn = burst, burst
			arpProbeFn = func(string, net.IP, net.IP) error { return nil }

			deleteStarted := make(chan struct{})
			var firstDelete sync.Once
			var sentAtDelete []string
			vi.addrDelFn = func(netlink.Link, *netlink.Addr) error {
				firstDelete.Do(func() {
					sentMu.Lock()
					sentAtDelete = append([]string(nil), sent...)
					sentMu.Unlock()
					close(deleteStarted)
				})
				return nil
			}

			go func() {
				vi.sendGARP(false)
				close(sendDone)
			}()
			select {
			case <-firstFrame:
			case <-time.After(time.Second):
				t.Fatal("initial full-set burst did not send VIP A")
			}
			updateStarted = true
			go func() { updateDone <- vi.updateVIPs([]string{vips[0], vips[3]}) }()

			stack := make([]byte, 1<<20)
			parkDeadline := time.Now().Add(time.Second)
			for !goroutineWaitingOnVIPMu(vi, "updateVIPs", stack) &&
				time.Now().Before(parkDeadline) {
				runtime.Gosched()
			}
			if !goroutineWaitingOnVIPMu(vi, "updateVIPs", stack) {
				release()
				t.Fatalf("removal update did not park on vipMu while VIP A's frame was blocked:\n%s",
					stack[:runtime.Stack(stack, true)])
			}
			time.Sleep(10 * time.Millisecond)
			if !goroutineWaitingOnVIPMu(vi, "updateVIPs", stack) {
				release()
				t.Fatal("removal update stopped waiting on vipMu before the first frame was released")
			}
			release()

			select {
			case <-deleteStarted:
			case <-time.After(time.Second):
				t.Fatal("removal update did not reach its first deletion")
			}
			sentMu.Lock()
			beforeDelete := append([]string(nil), sentAtDelete...)
			sentMu.Unlock()
			lastIP, _, _ := net.ParseCIDR(vips[3])
			for _, ip := range beforeDelete {
				if ip == lastIP.String() {
					t.Fatalf("surviving VIP D was announced before the membership update: %v", beforeDelete)
				}
			}
			if len(beforeDelete) >= len(vips) {
				t.Fatalf("full old burst completed before removal began: %v", beforeDelete)
			}

			updateErr := <-updateDone
			updateFinished = true
			if updateErr != nil {
				t.Fatalf("removal-only update: %v", updateErr)
			}
			select {
			case <-sendDone:
				sendFinished = true
			case <-time.After(time.Second):
				t.Fatal("old full-set sender did not stop after the membership epoch changed")
			}
			gotVIPs, wantVIPs := vi.vipsSnapshot(), []string{vips[0], vips[3]}
			if !vipsEqual(gotVIPs, wantVIPs) {
				t.Fatalf("post-update VIP set = %v, want %v", gotVIPs, wantVIPs)
			}
			sentMu.Lock()
			gotSent := append([]string(nil), sent...)
			sentMu.Unlock()
			counts := make(map[string]int, len(gotSent))
			for _, ip := range gotSent {
				counts[ip]++
				if counts[ip] > 1 {
					t.Fatalf("duplicate GARP/NA for %s: sent=%v", ip, gotSent)
				}
			}
			if counts[lastIP.String()] != 1 {
				t.Fatalf("surviving VIP D sends = %d, want exactly one; sent=%v",
					counts[lastIP.String()], gotSent)
			}
			if len(gotSent) > len(vips) {
				t.Fatalf("membership update caused an unbounded duplicate burst: sent=%v", gotSent)
			}
		})
	}
}

// sync.Mutex permits barging in normal mode, so this proves a mid-burst
// starvation-mode handoff rather than requiring an exact one-VIP handoff. The
// parked demoter and paced 16-VIP burst keep contention active beyond Go's
// ~1ms waiter threshold; per-VIP unlocks provide a handoff point before the
// whole burst completes.
func TestGARPPerVIPLockBoundsDemotionWait(t *testing.T) {
	for _, isIPv6 := range []bool{false, true} {
		family := "ipv4"
		const vipCount = 16
		vips := make([]string, vipCount)
		for i := range vips {
			if isIPv6 {
				family = "ipv6"
				vips[i] = fmt.Sprintf("2001:db8:1078::%x/64", i+1)
			} else {
				vips[i] = fmt.Sprintf("198.18.107.%d/32", 80+i)
			}
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
			var burstsAtDemotion atomic.Int32
			var firstDelete sync.Once
			vi.addrDelFn = func(netlink.Link, *netlink.Addr) error {
				firstDelete.Do(func() { burstsAtDemotion.Store(burstCalls.Load()) })
				return nil
			}
			firstFrame, releaseFrame := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseFrame) }) }
			defer release()
			burst := func(string, net.IP, int, cluster.BurstStillValid) error {
				call := burstCalls.Add(1)
				if call == 1 {
					close(firstFrame)
					<-releaseFrame
				} else {
					// Keep the remaining send loop active beyond the mutex
					// starvation threshold while a verified waiter is queued.
					time.Sleep(5 * time.Millisecond)
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
			go func() {
				demoteDone <- vi.becomeBackup(masterDownTimer, advertTimer)
			}()
			stack := make([]byte, 1<<20)
			parkDeadline := time.Now().Add(time.Second)
			for !goroutineWaitingOnVIPMu(vi, "becomeBackup", stack) && time.Now().Before(parkDeadline) {
				runtime.Gosched()
			}
			if !goroutineWaitingOnVIPMu(vi, "becomeBackup", stack) {
				release()
				t.Fatalf("becomeBackup did not park on vipMu while the first frame was blocked:\n%s",
					stack[:runtime.Stack(stack, true)])
			}
			time.Sleep(10 * time.Millisecond)
			if !goroutineWaitingOnVIPMu(vi, "becomeBackup", stack) {
				release()
				t.Fatal("becomeBackup stopped waiting on vipMu before the frame was released")
			}
			select {
			case err := <-demoteDone:
				release()
				t.Fatalf("demotion completed while the current VIP first frame was blocked: %v", err)
			default:
			}

			releaseAt := time.Now()
			release()
			select {
			case err := <-demoteDone:
				if err != nil {
					t.Fatalf("becomeBackup: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("demotion did not resume after a per-VIP frame returned")
			}
			if elapsed := time.Since(releaseAt); elapsed > 250*time.Millisecond {
				t.Fatalf("demotion waited %s after releasing a VIP frame; want <250ms", elapsed)
			}
			select {
			case <-sendDone:
			case <-time.After(time.Second):
				t.Fatal("GARP sender did not stop after demotion")
			}
			gotAtDemotion := burstsAtDemotion.Load()
			if gotAtDemotion <= 0 || gotAtDemotion >= vipCount {
				t.Fatalf("demotion acquired vipMu after %d bursts; want mid-burst acquisition before %d VIPs finished",
					gotAtDemotion, vipCount)
			}
			if got := burstCalls.Load(); got != gotAtDemotion {
				t.Fatalf("bursts continued after demotion acquired vipMu: at acquisition=%d final=%d",
					gotAtDemotion, got)
			}
			if vi.getState() != StateBackup {
				t.Fatalf("state after demotion = %s, want BACKUP", vi.getState())
			}
		})
	}
}
