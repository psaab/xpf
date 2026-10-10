package vrrp

import (
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
)

// #12201 — the routine MASTER transition's GARP/NA launch has no unit pin:
// deleting `go vi.sendGARP(false)` from becomeMaster leaves the whole
// pkg/vrrp suite green. The sender and the three non-routine launch sites
// (rx reaffirm #10777, VIP reconcile #2081, manager unsuppress #2940) are
// pinned; only this transition→launch edge is not.
//
// These tests drive becomeMaster() itself with capturing burst seams and fail
// if the launch is removed (mutant A).

type burstCapture12201 struct {
	family string // "GARP" (IPv4) or "NA" (IPv6)
	ip     string
}

// captureBursts12201 swaps the burst sender seams for channel-capturing stubs.
// Pattern mirrors captureReaffirmBursts10777.
func captureBursts12201(t *testing.T) <-chan burstCapture12201 {
	t.Helper()
	bursts := make(chan burstCapture12201, 8)
	origGARP, origNA, origProbe := garpBurstFn, naBurstFn, arpProbeFn
	garpBurstFn = func(_ string, ip net.IP, _ int, _ cluster.BurstStillValid) error {
		bursts <- burstCapture12201{family: "GARP", ip: ip.String()}
		return nil
	}
	naBurstFn = func(_ string, ip net.IP, _ int, _ cluster.BurstStillValid) error {
		bursts <- burstCapture12201{family: "NA", ip: ip.String()}
		return nil
	}
	arpProbeFn = func(string, net.IP, net.IP) error { return nil }
	t.Cleanup(func() { garpBurstFn, naBurstFn, arpProbeFn = origGARP, origNA, origProbe })
	return bursts
}

func newBecomeMasterGARPInstance12201(t *testing.T, vips []string) *vrrpInstance {
	t.Helper()
	eventCh := make(chan VRRPEvent, 8)
	vi := newInstance(Instance{
		Interface:         "xpf-12201-a0",
		GroupID:           1,
		Priority:          100,
		AdvertiseInterval: 1000,
		VirtualAddresses:  vips,
	}, &net.Interface{Name: "xpf-12201-a0"}, eventCh, nil)
	vi.setState(StateBackup) // the state becomeMaster transitions FROM
	// Fail-closed VIP actuation (#5082) must succeed so the transition — and
	// its burst — is reachable on a fake interface; the launch wiring under
	// test is what matters here.
	installFakeVIPNetlink(vi)
	return vi
}

// The routine unsuppressed transition emits exactly one burst per VIP family.
// RED-ON-REVERT: deleting the `go vi.sendGARP(false)` launch leaves
// lastGARPEpoch at 0 and the burst channel empty, so the test fails.
func TestBecomeMaster_LaunchesOneBurstPerVIPFamily_12201(t *testing.T) {
	bursts := captureBursts12201(t)
	vi := newBecomeMasterGARPInstance12201(t, []string{"10.0.61.1/24", "fd00:61::1/64"})

	if !vi.becomeMaster() {
		t.Fatal("FIXTURE: becomeMaster must claim ownership when VIP actuation succeeds")
	}
	if got := vi.garpEpoch.Load(); got != 1 {
		t.Fatalf("garpEpoch = %d, want 1 — the transition did not start a new burst tenure", got)
	}

	want := map[string]string{"GARP": "10.0.61.1", "NA": "fd00:61::1"}
	seen := make(map[string]string, 2)
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	for len(seen) < len(want) {
		select {
		case b := <-bursts:
			if _, dup := seen[b.family]; dup {
				t.Fatalf("duplicate %s burst for %s", b.family, b.ip)
			}
			seen[b.family] = b.ip
		case <-timer.C:
			stack := make([]byte, 1<<16)
			n := runtime.Stack(stack, true)
			t.Fatalf("timed out waiting for one burst per VIP family; got %v — "+
				"becomeMaster did not launch the GARP/NA burst (#12201)\n%s", seen, stack[:n])
		}
	}
	for family, wantIP := range want {
		if got := seen[family]; got != wantIP {
			t.Fatalf("%s burst announced %q, want %q", family, got, wantIP)
		}
	}
	// sendGARPReserved emits one seam call per VIP sequentially, so after both
	// arrivals the channel is deterministically drained — no quiescence wait.
	if n := len(bursts); n != 0 {
		t.Fatalf("unexpected duplicate bursts: %d still queued", n)
	}
	if got := vi.lastGARPEpoch.Load(); got != 1 {
		t.Fatalf("lastGARPEpoch = %d, want 1 — no burst was reserved for this tenure", got)
	}
}

// The strict-vip-ownership suppression gate must hold: a suppressed transition
// claims ownership (epoch bumped) but emits no burst. This pins the negative
// branch so the launch cannot be "fixed" into an unconditional send.
func TestBecomeMaster_SuppressedEmitsNoBurst_12201(t *testing.T) {
	bursts := captureBursts12201(t)
	vi := newBecomeMasterGARPInstance12201(t, []string{"10.0.61.1/24", "fd00:61::1/64"})
	vi.suppressGARP.Store(true)

	if !vi.becomeMaster() {
		t.Fatal("FIXTURE: a suppressed becomeMaster must still claim ownership")
	}
	if got := vi.garpEpoch.Load(); got != 1 {
		t.Fatalf("garpEpoch = %d, want 1 — the transition must still start a new tenure", got)
	}
	// Deterministic: nothing reserves a burst when the launch is gated.
	if got := vi.lastGARPEpoch.Load(); got != 0 {
		t.Fatalf("lastGARPEpoch = %d, want 0 — a suppressed transition reserved a burst", got)
	}
	// Plus a bounded drain window to catch a stray async burst.
	select {
	case b := <-bursts:
		t.Fatalf("suppressed becomeMaster emitted a %s burst for %s", b.family, b.ip)
	case <-time.After(200 * time.Millisecond):
	}
}
