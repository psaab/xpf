package daemon

import (
	"context"
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

func localAddrKeyCfg18597(addrs ...string) []string {
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key local-addr-key-18597",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 127.0.0.2",
	}
	for _, a := range addrs {
		lines = append(lines, "set interfaces em0 unit 0 family inet address "+a)
	}
	return lines
}

// stubControlAddr18597 makes every interface report the given IPv4 addresses
// (the kernel's view, switchable mid-test; the heartbeat retry and the sync
// constructor goroutines read it).
func stubControlAddr18597(t *testing.T, first ...string) *atomic.Value {
	t.Helper()
	var cur atomic.Value
	cur.Store(first)
	prev := interfaceAddrsByName
	t.Cleanup(func() { interfaceAddrsByName = prev })
	interfaceAddrsByName = func(kernelName string) ([]net.Addr, error) {
		var out []net.Addr
		for _, a := range cur.Load().([]string) {
			out = append(out, &net.IPNet{IP: net.ParseIP(a), Mask: net.CIDRMask(8, 32)})
		}
		return out, nil
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

// renumberStore18597 commits em0 from old to new in the daemon's store, as an
// operator commit would before step 20 runs.
func renumberStore18597(t *testing.T, d *Daemon, oldAddr, newAddr string) {
	t.Helper()
	d.store.ExitConfigure() // testStoreWithSetConfig leaves the session open
	if err := d.store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := d.store.DeleteFromInput("interfaces em0 unit 0 family inet address " + oldAddr); err != nil {
		t.Fatal(err)
	}
	if err := d.store.SetFromInput("interfaces em0 unit 0 family inet address " + newAddr); err != nil {
		t.Fatal(err)
	}
	if _, err := d.store.Commit(); err != nil {
		t.Fatalf("commit renumber: %v", err)
	}
	d.store.ExitConfigure()
}

func TestControlLinkRenumberRestartsCommsOnTheNewAddress18597(t *testing.T) {
	exhaustSyncAddressPolls15687(t)
	cur := stubControlAddr18597(t, "127.0.0.1")
	d := newVRFBindingRetryDaemon12168(t, localAddrKeyCfg18597("127.0.0.1/8"), false)

	d.startClusterComms(d.daemonCtx)
	waitVRFCommsConstructor12168(t, d)
	waitHeartbeatLocal18597(t, d, "127.0.0.1")
	if got := d.activeTransport().LocalAddress; got != "127.0.0.1" {
		t.Fatalf("precondition: epoch key LocalAddress = %q, want 127.0.0.1", got)
	}
	gen0 := warmVRFCommsGeneration12168(d)

	// The soak property: a commit that leaves the address alone restarts
	// nothing.
	d.reconcileClusterTransportBinding(d.store.ActiveConfig(), false)
	if got := warmVRFCommsGeneration12168(d); got != gen0 {
		t.Fatalf("an unchanged control address restarted comms (generation %d -> %d)", gen0, got)
	}

	// Renumber: same interface, same peer, new configured local address
	// (networkd has applied it to the kernel by step 20).
	renumberStore18597(t, d, "127.0.0.1/8", "127.0.0.5/8")
	cur.Store([]string{"127.0.0.5"})
	d.reconcileClusterTransportBinding(d.store.ActiveConfig(), false)
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
	d.reconcileClusterTransportBinding(d.store.ActiveConfig(), false)
	if got := warmVRFCommsGeneration12168(d); got != gen1 {
		t.Fatalf("the renumbered epoch restarted again with no further change (generation %d -> %d)", gen1, got)
	}
}

// A bind on an address config does not give the unit marks the epoch for one
// restart; a bind on ANOTHER configured address (the kernel listed them in a
// different order) does not.
func TestOffConfigBindMarksTheEpochChanged18597(t *testing.T) {
	cfg := testStoreWithSetConfig(t, localAddrKeyCfg18597("10.99.14.1/30", "10.99.14.3/30")).ActiveConfig()
	if got := clusterTransportLocalAddress(cfg); got != "10.99.14.1" {
		t.Fatalf("precondition: key LocalAddress = %q, want the first configured 10.99.14.1", got)
	}
	d := &Daemon{clusterCommsGen: 4, activeClusterTransport: clusterTransportKey{
		ControlInterface: "em0", PeerAddress: "127.0.0.2", LocalAddress: "10.99.14.1"}}
	for _, addr := range []string{"10.99.14.1", "10.99.14.3"} {
		d.noteClusterTransportLocalAddress(4, cfg, addr)
		if d.activeTransport().BindingChanged {
			t.Fatalf("a bind on configured address %s marked the epoch changed", addr)
		}
	}
	d.noteClusterTransportLocalAddress(3, cfg, "10.99.14.9")
	if d.activeTransport().BindingChanged {
		t.Fatal("a superseded epoch's bind marked the live epoch changed")
	}
	noStatic := testStoreWithSetConfig(t, localAddrKeyCfg18597()).ActiveConfig()
	d.noteClusterTransportLocalAddress(4, noStatic, "10.99.14.9")
	if d.activeTransport().BindingChanged {
		t.Fatal("a config with no static control address marked a bind changed: there is nothing to compare")
	}
	d.noteClusterTransportLocalAddress(4, cfg, "10.99.14.9")
	if !d.activeTransport().BindingChanged {
		t.Fatal("a bind on an address config does not name did not mark the epoch changed")
	}
}

// The key pairs with the peer exactly as the binds do: on a dual-stack control
// unit with an IPv6 peer it names the global IPv6 address.
func TestTransportKeyResolvesAgainstThePeerFamily18597(t *testing.T) {
	cfg := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key local-addr-v6-18597",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 2001:db8:14::2",
		"set interfaces em0 unit 0 family inet address 10.99.14.1/30",
		"set interfaces em0 unit 0 family inet6 address 2001:db8:14::1/64",
	}).ActiveConfig()
	if got := clusterTransportLocalAddress(cfg); got != "2001:db8:14::1" {
		t.Fatalf("key LocalAddress = %q, want the address the binds pair with an IPv6 peer (2001:db8:14::1)", got)
	}
}

// Seat AG's second edge: two IPv4 addresses on the control unit, listed by the
// kernel in a different order between the heartbeat's and the sync's lookups
// and step 20's. Neither is a renumber.
func TestKernelAddressReorderDoesNotRestartComms18597(t *testing.T) {
	exhaustSyncAddressPolls15687(t)
	var flip atomic.Int32
	prev := interfaceAddrsByName
	t.Cleanup(func() { interfaceAddrsByName = prev })
	interfaceAddrsByName = func(string) ([]net.Addr, error) {
		a := &net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)}
		b := &net.IPNet{IP: net.ParseIP("127.0.0.3"), Mask: net.CIDRMask(8, 32)}
		if flip.Add(1)%2 == 0 {
			return []net.Addr{b, a}, nil
		}
		return []net.Addr{a, b}, nil
	}
	d := newVRFBindingRetryDaemon12168(t, localAddrKeyCfg18597("127.0.0.1/8", "127.0.0.3/8"), false)
	d.startClusterComms(d.daemonCtx)
	waitVRFCommsConstructor12168(t, d)
	deadline := time.Now().Add(6 * time.Second)
	for !d.cluster.HeartbeatRunning() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !d.cluster.HeartbeatRunning() {
		t.Fatal("precondition: the heartbeat never started")
	}
	gen0 := warmVRFCommsGeneration12168(d)
	for i := 0; i < 4; i++ {
		d.reconcileClusterTransportBinding(d.store.ActiveConfig(), false)
	}
	if got := warmVRFCommsGeneration12168(d); got != gen0 {
		t.Fatalf("a kernel reorder of two configured addresses restarted comms (generation %d -> %d, "+
			"binding_changed=%v)", gen0, got, d.activeTransport().BindingChanged)
	}
}

// Review seat AH's probe (#18597): the control link loses carrier (a direct
// cable and a rebooting peer), networkd drops em0's static address, and the
// survivor's next apply resolves LocalAddress "". Comparing "" as a value tore
// comms down onto an unaddressed link: generation 1 -> 3 and the heartbeat
// left stopped. "" is "no evidence"; the epoch must be left alone.
func TestControlLinkAddressLossDoesNotRestartComms18597(t *testing.T) {
	exhaustSyncAddressPolls15687(t)
	cur := stubControlAddr18597(t, "127.0.0.1")
	d := newVRFBindingRetryDaemon12168(t, localAddrKeyCfg18597("127.0.0.1/8"), false)
	cfg := d.store.ActiveConfig()
	d.startClusterComms(d.daemonCtx)
	waitVRFCommsConstructor12168(t, d)
	waitHeartbeatLocal18597(t, d, "127.0.0.1")
	gen0 := warmVRFCommsGeneration12168(d)

	// Carrier loss: the kernel reports no address at all; config is unchanged.
	cur.Store([]string{})
	if got := resolveClusterInterfaceAddr(cfg, "em0", "127.0.0.2", ""); got != "" {
		t.Fatalf("precondition: the kernel view still resolved %q, want \"\"", got)
	}
	d.reconcileClusterTransportBinding(cfg, false)
	if got := warmVRFCommsGeneration12168(d); got != gen0 {
		t.Fatalf("an unaddressed control link restarted comms (generation %d -> %d): carrier loss on a "+
			"direct-cabled control link must not tear the epoch down", gen0, got)
	}
	if !d.cluster.HeartbeatRunning() || d.cluster.HeartbeatLocalAddr() != "127.0.0.1" {
		t.Fatalf("heartbeat running=%v local=%q after the address loss, want still running on 127.0.0.1",
			d.cluster.HeartbeatRunning(), d.cluster.HeartbeatLocalAddr())
	}

	// The peer returns and the address comes back unchanged: still nothing.
	cur.Store([]string{"127.0.0.1"})
	d.reconcileClusterTransportBinding(cfg, false)
	if got := warmVRFCommsGeneration12168(d); got != gen0 {
		t.Fatalf("the returning address restarted comms (generation %d -> %d)", gen0, got)
	}
}

// The boot edge: an epoch whose key opened with the address unresolved, and a
// step-20 apply that runs after the address appeared but before any socket
// learned it. "" on the ACTIVE side is no evidence either; the bind owners
// (learn-on-bind, the address-poll debt) own that window.
func TestUnresolvedKeyAndAppearingAddressDoesNotRestartComms18597(t *testing.T) {
	stubControlAddr18597(t, "127.0.0.1")
	d := newVRFBindingRetryDaemon12168(t, localAddrKeyCfg18597("127.0.0.1/8"), false)
	cfg := d.store.ActiveConfig()
	opened := d.clusterTransportForConfig(cfg)
	opened.LocalAddress = "" // an epoch opened while config named no static address
	d.clusterCommsGen = 1
	if !d.setActiveTransportIfCurrent(1, opened) {
		t.Fatal("precondition: could not publish the opened key")
	}
	var restarts int
	d.startClusterCommsFn = func(context.Context) { restarts++ }
	d.reconcileClusterTransportBinding(cfg, false)
	if restarts != 0 {
		t.Fatalf("an apply after the address appeared restarted comms %d times over a key that only meant "+
			"\"not yet\"", restarts)
	}
	// Positive control: the same fixture with a genuine A -> B change does restart.
	opened.LocalAddress = "127.0.0.9"
	if !d.setActiveTransportIfCurrent(d.clusterCommsGen, opened) {
		t.Fatal("precondition: could not republish the key")
	}
	d.reconcileClusterTransportBinding(cfg, false)
	if restarts != 1 {
		t.Fatalf("a real 127.0.0.9 -> 127.0.0.1 change restarted comms %d times, want 1", restarts)
	}
}

func TestSameClusterTransportTreatsEmptyLocalAddressAsNoEvidence18597(t *testing.T) {
	base := clusterTransportKey{ControlInterface: "em0", PeerAddress: "10.99.14.2", LocalAddress: "10.99.14.1"}
	for _, tc := range []struct {
		name  string
		a, b  string
		equal bool
	}{
		{"same", "10.99.14.1", "10.99.14.1", true},
		{"renumber", "10.99.14.1", "10.99.14.5", false},
		{"lost on the new side", "10.99.14.1", "", true},
		{"unresolved on the active side", "", "10.99.14.1", true},
		{"both unresolved", "", "", true},
	} {
		a, b := base, base
		a.LocalAddress, b.LocalAddress = tc.a, tc.b
		if got := sameClusterTransport(a, b); got != tc.equal {
			t.Errorf("%s: sameClusterTransport(%q, %q) = %v, want %v", tc.name, tc.a, tc.b, got, tc.equal)
		}
	}
	other := base
	other.PeerAddress = "10.99.14.6"
	other.LocalAddress = ""
	if sameClusterTransport(base, other) {
		t.Error("an empty LocalAddress must not mask a change in another field")
	}
}
