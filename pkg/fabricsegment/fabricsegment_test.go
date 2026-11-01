package fabricsegment

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/bpf"
)

func mac(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	m, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("ParseMAC(%q): %v", s, err)
	}
	return m
}

func testLink(t *testing.T) Link {
	return Link{
		Name:          "fab0",
		Parent:        "ge-0-0-0",
		ParentIfindex: 4,
		LocalMAC:      mac(t, "10:66:6a:00:00:01"),
		PeerMAC:       mac(t, "10:66:6a:00:00:02"),
	}
}

func frameFrom(src net.HardwareAddr) []byte {
	f := make([]byte, 60)
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(f[6:12], src)
	f[12], f[13] = 0x08, 0x06 // ARP
	return f
}

func TestForeignSourceClassification18719(t *testing.T) {
	link := testLink(t)
	tr := NewTracker(link, nil)
	cases := []struct {
		src  string
		want bool
		why  string
	}{
		{"10:66:6a:00:00:01", false, "this node's fabric MAC"},
		{"10:66:6a:00:00:02", false, "the peer's fabric MAC"},
		{"02:bf:72:fe:00:05", false, "V1 zone stamp"},
		{"02:bf:72:01:01:01", false, "RETH virtual MAC namespace"},
		{"02:bf:73:00:00:09", false, "V2 NAT-scope stamp"},
		{"00:00:00:00:00:00", false, "zero placeholder"},
		{"01:80:c2:00:00:00", false, "group address as a source is malformed"},
		{"18:e8:29:2c:13:7a", true, "a third host"},
		{"02:bf:74:00:00:01", true, "outside xpf's synthetic namespace"},
	}
	for _, tc := range cases {
		if got := tr.IsForeignSource(mac(t, tc.src)); got != tc.want {
			t.Errorf("%s (%s): foreign=%v, want %v", tc.src, tc.why, got, tc.want)
		}
	}
}

func TestTrackerRaisesAndClearsOnce18719(t *testing.T) {
	link := testLink(t)
	var mu sync.Mutex
	var edges []bool
	tr := NewTracker(link, func(_ Link, raised bool, _ string) {
		mu.Lock()
		edges = append(edges, raised)
		mu.Unlock()
	})
	t0 := time.Unix(1_000_000, 0)
	tr.Observe(link.PeerMAC, t0)
	if tr.Alarm(t0) != "" {
		t.Fatal("peer frames must not raise the alarm")
	}
	foreign := mac(t, "18:e8:29:2c:13:7a")
	tr.Observe(foreign, t0)
	tr.Observe(foreign, t0.Add(time.Second))
	alarm := tr.Alarm(t0.Add(2 * time.Second))
	for _, want := range []string{"fab0", "ge-0-0-0", "18:e8:29:2c:13:7a", "2 frame(s)", "#10105", "last 1s ago"} {
		if !strings.Contains(alarm, want) {
			t.Errorf("alarm %q lacks %q", alarm, want)
		}
	}
	tr.Tick(t0.Add(AlarmHold)) // still within the hold of the last frame
	if tr.Alarm(t0.Add(AlarmHold)) == "" {
		t.Fatal("alarm cleared inside the hold window")
	}
	tr.Tick(t0.Add(time.Second + AlarmHold + time.Second))
	if tr.Alarm(t0.Add(AlarmHold+2*time.Second)) != "" {
		t.Fatal("alarm not cleared after the hold window")
	}
	tr.Tick(t0.Add(2 * AlarmHold)) // no second clear edge
	mu.Lock()
	defer mu.Unlock()
	if len(edges) != 2 || !edges[0] || edges[1] {
		t.Fatalf("transition edges = %v, want [raise clear]", edges)
	}
}

// TestObserveFrameIgnoresLinkConstrainedGroups18719: an adjacent switch's
// STP/LACP/LLDP (IEEE 802.1 reserved 01:80:c2:00:00:00-0f, never relayed by
// a bridge) proves a bridge port, not a third host, so a fabric on a
// dedicated switch VLAN must not alarm on it. The same source to a relayed
// destination must raise: the first group past the block, broadcast and a
// unicast.
func TestObserveFrameIgnoresLinkConstrainedGroups18719(t *testing.T) {
	link := testLink(t)
	src := mac(t, "18:e8:29:00:00:c1")
	frame := func(dst string) []byte {
		f := make([]byte, 60)
		copy(f[0:6], mac(t, dst))
		copy(f[6:12], src)
		return f
	}
	for _, dst := range []string{"01:80:c2:00:00:00", "01:80:c2:00:00:02", "01:80:c2:00:00:03", "01:80:c2:00:00:0e", "01:80:c2:00:00:0f"} {
		tr := NewTracker(link, nil)
		tr.ObserveFrame(frame(dst), time.Now())
		if line := tr.Alarm(time.Now()); line != "" {
			t.Errorf("a frame to link-constrained %s raised: %s", dst, line)
		}
	}
	for _, dst := range []string{"01:80:c2:00:00:10", "01:80:c2:00:01:00", "ff:ff:ff:ff:ff:ff", "10:66:6a:00:00:02"} {
		tr := NewTracker(link, nil)
		tr.ObserveFrame(frame(dst), time.Now())
		if tr.Alarm(time.Now()) == "" {
			t.Errorf("a frame from %s to relayed %s did not raise", src, dst)
		}
	}
	tr := NewTracker(link, nil)
	tr.ObserveFrame(frame("ff:ff:ff:ff:ff:ff")[:11], time.Now())
	if tr.Alarm(time.Now()) != "" {
		t.Error("a runt without a whole source MAC raised")
	}
}

func TestTrackerBoundsTheSourceTable18719(t *testing.T) {
	tr := NewTracker(testLink(t), nil)
	now := time.Unix(2_000_000, 0)
	for i := 0; i < 3*maxTrackedMACs; i++ {
		tr.Observe(net.HardwareAddr{0x18, 0xe8, 0x29, 0x00, 0x00, byte(i + 1)}, now)
	}
	tr.mu.Lock()
	n, overflow := len(tr.sources), tr.overflow
	tr.mu.Unlock()
	if n != maxTrackedMACs || overflow != 2*maxTrackedMACs {
		t.Fatalf("tracked=%d overflow=%d, want %d and %d", n, overflow, maxTrackedMACs, 2*maxTrackedMACs)
	}
	if alarm := tr.Alarm(now); !strings.Contains(alarm, "and more") || !strings.Contains(alarm, "24 frame(s)") {
		t.Fatalf("an overflowed alarm must say so and count every frame: %q", alarm)
	}
}

// The exact instruction array the kernel runs, executed in a userspace VM.
func TestKnownSourceFilterDropsKnownAndSyntheticSources18719(t *testing.T) {
	link := testLink(t)
	raw, err := knownSourceFilter(link.LocalMAC, link.PeerMAC)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	prog, ok := bpf.Disassemble(raw)
	if !ok {
		t.Fatal("filter does not disassemble")
	}
	vm, err := bpf.NewVM(prog)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	cases := []struct {
		src    string
		accept bool
	}{
		{"10:66:6a:00:00:01", false}, // local
		{"10:66:6a:00:00:02", false}, // peer
		{"10:66:6a:00:00:03", true},  // same high word as both, different low half
		{"10:66:6b:00:00:01", true},  // local's low half, different high word
		{"10:66:6b:00:00:02", true},  // peer's low half, different high word
		{"18:e8:29:2c:13:7a", true},  // a third host
		{"02:bf:72:fe:00:05", false}, // V1 zone stamp / RETH MAC namespace
		{"02:bf:73:00:01:02", false}, // V2 scope stamp namespace
		{"02:bf:71:00:00:01", true},  // the neighbours of the masked compare
		{"02:bf:74:00:00:01", true},
		{"02:be:72:00:00:01", true},
		{"03:bf:72:00:00:01", true}, // group bit: userspace rejects it, not the filter
	}
	for _, tc := range cases {
		n, err := vm.Run(frameFrom(mac(t, tc.src)))
		if err != nil {
			t.Fatalf("vm.Run(%s): %v", tc.src, err)
		}
		if got := n > 0; got != tc.accept {
			t.Errorf("source %s: accepted=%v (len %d), want %v", tc.src, got, n, tc.accept)
		}
		if tc.accept && n != snapLen {
			t.Errorf("source %s: snap length %d, want %d", tc.src, n, snapLen)
		}
	}
	if n, _ := vm.Run(make([]byte, 8)); n != 0 {
		t.Errorf("a runt frame must be dropped, got %d", n)
	}
}

func TestMonitorArmsOnlyResolvedLinks18719(t *testing.T) {
	var mu sync.Mutex
	started := map[string]int{}
	mon := NewMonitor(func(ctx context.Context, link Link, _ *Tracker) error {
		mu.Lock()
		started[link.Name]++
		mu.Unlock()
		<-ctx.Done()
		return nil
	})
	defer mon.Stop()
	ready := testLink(t)
	// Three unresolved-peer shapes: no MAC yet, an all-zero placeholder (an
	// incomplete neighbour), and a malformed non-zero MAC. Each alone must
	// keep the link unarmed, or every peer frame reads as foreign.
	unresolved := map[string]net.HardwareAddr{
		"fab1": nil,
		"fab2": make(net.HardwareAddr, 6),
		"fab3": {0x10, 0x66, 0x6a, 0x01},
	}
	links := []Link{ready}
	for name, peer := range unresolved {
		l := ready
		l.Name, l.PeerMAC = name, peer
		links = append(links, l)
	}
	mon.Update(links)
	// Update registers an armed link synchronously, so this is exact.
	for _, l := range links[1:] {
		if mon.trackerFor(l) != nil {
			t.Errorf("%s with peer MAC %v was armed", l.Name, []byte(l.PeerMAC))
		}
	}
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return started["fab0"] == 1 })
	mu.Lock()
	for name, peer := range unresolved {
		if started[name] != 0 {
			t.Errorf("%s with peer MAC %v must not be sampled", name, []byte(peer))
		}
	}
	mu.Unlock()

	// Same identity again: the sampler and its evidence survive.
	tr := mon.trackerFor(ready)
	tr.Observe(mac(t, "18:e8:29:2c:13:7a"), time.Now())
	mon.Update([]Link{ready})
	if mon.trackerFor(ready) != tr {
		t.Fatal("an unchanged link restarted its tracker and lost its evidence")
	}
	if alarms := mon.Alarms(); len(alarms) != 1 || !strings.Contains(alarms[0], "fab0") {
		t.Fatalf("Alarms() = %v, want the fab0 alarm", alarms)
	}

	// A new peer MAC is a new identity: restart.
	moved := ready
	moved.PeerMAC = mac(t, "10:66:6a:00:00:09")
	mon.Update([]Link{moved})
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return started["fab0"] == 2 })
	if mon.trackerFor(ready) != nil || len(mon.Alarms()) != 0 {
		t.Fatal("the old identity's sampler and alarm must be gone after a peer MAC change")
	}

	mon.Update(nil)
	if len(mon.Alarms()) != 0 || mon.trackerFor(moved) != nil {
		t.Fatal("an empty update must stop every sampler")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestTrackerOverflowSourceHoldsTheAlarm18719 (#18751 review NIT): a ninth
// source that keeps sending after the eight tracked ones went quiet must
// keep the alarm raised. It must not clear and re-raise it at the moment the
// tracked entries expire.
func TestTrackerOverflowSourceHoldsTheAlarm18719(t *testing.T) {
	var edges []bool
	tr := NewTracker(testLink(t), func(_ Link, raised bool, _ string) { edges = append(edges, raised) })
	t0 := time.Unix(3_000_000, 0)
	for i := 0; i <= maxTrackedMACs; i++ { // eight tracked, the ninth overflows
		tr.Observe(net.HardwareAddr{0x18, 0xe8, 0x29, 0x00, 0x01, byte(i + 1)}, t0)
	}
	ninth := net.HardwareAddr{0x18, 0xe8, 0x29, 0x00, 0x01, byte(maxTrackedMACs + 1)}
	var last time.Time
	for m := 1; m <= 20; m++ {
		now := t0.Add(time.Duration(m) * time.Minute)
		tr.Tick(now.Add(-time.Second))
		tr.Observe(ninth, now)
		last = now
	}
	if len(edges) != 1 || !edges[0] {
		t.Fatalf("edges while the overflow source kept sending = %v, want [raise]", edges)
	}
	tr.Tick(last.Add(AlarmHold + time.Second))
	if len(edges) != 2 || edges[1] {
		t.Fatalf("edges after every source went quiet = %v, want [raise clear]", edges)
	}
}

// TestTrackerRetireLogsTheClearOnce18719: retiring a raised tracker reports
// exactly one clear with the reason; retiring again or retiring a tracker
// that never raised reports nothing.
func TestTrackerRetireLogsTheClearOnce18719(t *testing.T) {
	type edge struct {
		raised bool
		detail string
	}
	var edges []edge
	cb := func(_ Link, raised bool, detail string) { edges = append(edges, edge{raised, detail}) }
	quiet := NewTracker(testLink(t), cb)
	quiet.Retire("gone")
	if len(edges) != 0 {
		t.Fatalf("retiring an unraised tracker reported %v", edges)
	}
	tr := NewTracker(testLink(t), cb)
	tr.Observe(mac(t, "18:e8:29:2c:13:7a"), time.Now())
	tr.Retire("gone")
	tr.Retire("gone")
	if len(edges) != 2 || !edges[0].raised || edges[1].raised || edges[1].detail != "gone" {
		t.Fatalf("edges = %v, want a raise then one clear with the reason", edges)
	}
	if tr.Alarm(time.Now()) != "" {
		t.Fatal("a retired tracker still reports its alarm")
	}
}

// TestMonitorRetiresARekeyedLink18719 (#18751 review NIT): a link whose
// identity changes while its alarm is raised logs the clear, so the journal
// keeps one clear per raise.
func TestMonitorRetiresARekeyedLink18719(t *testing.T) {
	var mu sync.Mutex
	var edges []string
	mon := NewMonitor(func(ctx context.Context, _ Link, _ *Tracker) error { <-ctx.Done(); return nil })
	mon.transition = func(l Link, raised bool, detail string) {
		mu.Lock()
		defer mu.Unlock()
		if raised {
			edges = append(edges, "raise "+l.Name)
			return
		}
		edges = append(edges, "clear "+l.Name+": "+detail)
	}
	defer mon.Stop()
	link := testLink(t)
	mon.Update([]Link{link})
	mon.trackerFor(link).Observe(mac(t, "18:e8:29:2c:13:7a"), time.Now())
	moved := link
	moved.PeerMAC = mac(t, "10:66:6a:00:00:09")
	mon.Update([]Link{moved})
	mu.Lock()
	defer mu.Unlock()
	if len(edges) != 2 || edges[0] != "raise fab0" || !strings.HasPrefix(edges[1], "clear fab0: ") {
		t.Fatalf("edges = %v, want a raise then the re-key clear", edges)
	}
}

// TestMonitorRestartsAStoppedSampler18719 (#18751 review BLOCKING 1 and
// MINOR 3): a sampler that stops on its own is restarted with backoff and
// keeps its tracker, so evidence and a raised alarm survive the restart.
func TestMonitorRestartsAStoppedSampler18719(t *testing.T) {
	var mu sync.Mutex
	var trackers []*Tracker
	mon := NewMonitor(func(ctx context.Context, _ Link, tr *Tracker) error {
		mu.Lock()
		trackers = append(trackers, tr)
		n := len(trackers)
		mu.Unlock()
		if n <= 2 {
			return errors.New("simulated read failure")
		}
		<-ctx.Done()
		return nil
	})
	mon.backoffMin, mon.backoffMax = time.Millisecond, 2*time.Millisecond
	defer mon.Stop()
	link := testLink(t)
	mon.Update([]Link{link})
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(trackers) == 3 })
	mu.Lock()
	defer mu.Unlock()
	if trackers[0] != trackers[1] || trackers[1] != trackers[2] || trackers[0] != mon.trackerFor(link) {
		t.Fatal("a restart replaced the tracker and lost its evidence")
	}
}

// TestMonitorShowsAStoppedWatcher18719 (#18751 review BLOCKING 1): while a
// sampler is down, status says the link is not being watched, and a raised
// alarm is still listed.
func TestMonitorShowsAStoppedWatcher18719(t *testing.T) {
	mon := NewMonitor(func(context.Context, Link, *Tracker) error { return errors.New("network is down") })
	mon.backoffMin, mon.backoffMax = time.Hour, time.Hour
	defer mon.Stop()
	link := testLink(t)
	mon.Update([]Link{link})
	waitFor(t, func() bool {
		a := mon.Alarms()
		return len(a) == 1 && strings.Contains(a[0], "watcher is not running") && strings.Contains(a[0], "network is down")
	})
	mon.trackerFor(link).Observe(mac(t, "18:e8:29:2c:13:7a"), time.Now())
	if a := mon.Alarms(); len(a) != 2 || !strings.Contains(a[1], "18:e8:29:2c:13:7a") {
		t.Fatalf("Alarms() = %v, want the not-running line and the raised alarm", a)
	}
}
