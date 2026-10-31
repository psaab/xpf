package daemon

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// #18597 fold of #18606: a commit that renumbers the control link (same
// interface, same peer) must restart cluster comms on the NEW local address.
// Before the #18597 gate, every apply restarted the heartbeat on the stale
// hbLocalAddr, the bind failed, and the commit failed loudly (#9751); once the
// restart became conditional, nothing in clusterTransportKey moved on a
// renumber, so step 20 kept heartbeat and session sync bound to an address the
// interface no longer had: silent until the peer declared this node lost.
//
// FAIL-ON-REVERT: drop LocalAddress from clusterTransportForConfig (or from the
// key) and the renumber cell reds: the generation does not advance and the
// heartbeat stays on 127.0.0.1. The steady cell is the soak property: an
// unchanged address must not restart comms.

func localAddrKeyCfg18597() []string {
	return []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key local-addr-key-18597",
		"set chassis cluster control-interface lo",
		"set chassis cluster peer-address 127.0.0.2",
	}
}

// stubControlAddr18597 makes lo report exactly one IPv4 address, switchable
// mid-test (the heartbeat retry and sync constructor goroutines read it).
func stubControlAddr18597(t *testing.T, first string) *atomic.Value {
	t.Helper()
	var cur atomic.Value
	cur.Store(first)
	prev := interfaceAddrsByName
	t.Cleanup(func() { interfaceAddrsByName = prev })
	interfaceAddrsByName = func(kernelName string) ([]net.Addr, error) {
		ip := net.ParseIP(cur.Load().(string))
		return []net.Addr{&net.IPNet{IP: ip, Mask: net.CIDRMask(8, 32)}}, nil
	}
	return &cur
}

func waitHeartbeatLocal18597(t *testing.T, d *Daemon, want string) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if d.cluster.HeartbeatRunning() && d.cluster.HeartbeatLocalAddr() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("heartbeat running=%v local=%q, want running on %q",
		d.cluster.HeartbeatRunning(), d.cluster.HeartbeatLocalAddr(), want)
}

func TestControlLinkRenumberRestartsCommsOnTheNewAddress18597(t *testing.T) {
	exhaustSyncAddressPolls15687(t)
	cur := stubControlAddr18597(t, "127.0.0.1")
	d := newVRFBindingRetryDaemon12168(t, localAddrKeyCfg18597(), false)
	cfg := d.store.ActiveConfig()

	d.startClusterComms(d.daemonCtx)
	waitVRFCommsConstructor12168(t, d)
	waitHeartbeatLocal18597(t, d, "127.0.0.1")
	if got := d.activeTransport().LocalAddress; got != "127.0.0.1" {
		t.Fatalf("precondition: epoch key LocalAddress = %q, want 127.0.0.1", got)
	}
	gen0 := warmVRFCommsGeneration12168(d)

	// The soak property: a commit that leaves the address alone restarts
	// nothing.
	d.reconcileClusterTransportBinding(cfg, false)
	if got := warmVRFCommsGeneration12168(d); got != gen0 {
		t.Fatalf("an unchanged control address restarted comms (generation %d -> %d)", gen0, got)
	}

	// Renumber: same interface, same peer, new local address.
	cur.Store("127.0.0.5")
	d.reconcileClusterTransportBinding(cfg, false)
	if got := warmVRFCommsGeneration12168(d); got == gen0 {
		t.Fatalf("a control-link renumber did not restart comms (generation stayed %d): heartbeat "+
			"and session sync stay bound to an address the interface no longer has", gen0)
	}
	waitVRFCommsConstructor12168(t, d)
	waitHeartbeatLocal18597(t, d, "127.0.0.5")
	if got := d.activeTransport().LocalAddress; got != "127.0.0.5" {
		t.Fatalf("after the renumber the epoch key LocalAddress = %q, want 127.0.0.5", got)
	}
	if ss := d.getSessionSync(); ss == nil {
		t.Fatal("the restarted epoch published no session sync")
	}

	// And the new epoch is steady again.
	gen1 := warmVRFCommsGeneration12168(d)
	d.reconcileClusterTransportBinding(cfg, false)
	if got := warmVRFCommsGeneration12168(d); got != gen1 {
		t.Fatalf("the renumbered epoch restarted again with no further change (generation %d -> %d)", gen1, got)
	}
}

// An epoch whose key opened with the address unresolved learns the address
// its heartbeat bound, so the next commit does not restart comms over a ""
// that only meant "not yet"; a bind on an address the key does not name marks
// the epoch for one restart.
func TestTransportKeyLearnsTheBoundLocalAddress18597(t *testing.T) {
	d := &Daemon{clusterCommsGen: 4, activeClusterTransport: clusterTransportKey{ControlInterface: "em0"}}
	d.noteClusterTransportLocalAddress(4, "10.99.14.1")
	if k := d.activeTransport(); k.LocalAddress != "10.99.14.1" || k.BindingChanged {
		t.Fatalf("learned key = %+v, want LocalAddress 10.99.14.1 and no BindingChanged", k)
	}
	d.noteClusterTransportLocalAddress(4, "10.99.14.1")
	if k := d.activeTransport(); k.BindingChanged {
		t.Fatalf("a matching bind marked the epoch changed: %+v", k)
	}
	d.noteClusterTransportLocalAddress(3, "10.99.14.9")
	if k := d.activeTransport(); k.LocalAddress != "10.99.14.1" || k.BindingChanged {
		t.Fatalf("a superseded epoch's bind changed the live key: %+v", k)
	}
	d.noteClusterTransportLocalAddress(4, "10.99.14.5")
	if k := d.activeTransport(); !k.BindingChanged {
		t.Fatalf("an off-key bind did not mark the epoch changed: %+v", k)
	}
}

// The key must resolve with the SAME peer the heartbeat and sync binds use: on
// a dual-stack control link with an IPv6 peer they bind the global IPv6
// address, and a key resolved without the peer would name the IPv4 one and
// restart comms on every commit (or miss an IPv6 renumber).
func TestTransportKeyResolvesAgainstThePeerFamily18597(t *testing.T) {
	prev := interfaceAddrsByName
	t.Cleanup(func() { interfaceAddrsByName = prev })
	interfaceAddrsByName = func(string) ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("10.99.14.1"), Mask: net.CIDRMask(30, 32)},
			&net.IPNet{IP: net.ParseIP("2001:db8:14::1"), Mask: net.CIDRMask(64, 128)},
		}, nil
	}
	cfg := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key local-addr-v6-18597",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 2001:db8:14::2",
	}).ActiveConfig()
	if bind := resolveClusterInterfaceAddr(cfg, "em0", "2001:db8:14::2", ""); bind != "2001:db8:14::1" {
		t.Fatalf("precondition: the heartbeat bind resolves %q, want 2001:db8:14::1", bind)
	}
	if got := clusterTransportLocalAddress(cfg); got != "2001:db8:14::1" {
		t.Fatalf("key LocalAddress = %q, want the address the binds use (2001:db8:14::1)", got)
	}
}
