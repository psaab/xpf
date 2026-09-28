package vrrp

import (
	"net"

	"github.com/psaab/xpf/pkg/cluster"
	"sync"
	"testing"
	"time"
)

// #8597 (muse-004 K20) — the send paths read mu-guarded config fields without
// the lock, racing the day-2 updateConfig writer.
//
// updateConfig (instance.go) writes Priority, Preempt, PreemptHoldTime,
// AdvertiseInterval, GARPCount, TrackInterface and TrackPriorityCost under
// vi.mu. Every reader in instance_preempt.go, track.go, manager.go and
// instance_timing.go takes the lock — the #6230/#5718 lock discipline. Four
// statements on the SEND paths did not:
//
//   - sendAdvert reads cfg.AdvertiseInterval twice (the v4 and v6 arms);
//   - sendGARP reads cfg.GARPCount;
//   - run()'s startup log reads cfg.Priority and cfg.Preempt.
//
// The writer is the #5087 day-2 path: a commit changing only
// reth-advertise-interval or gratuitous-arp-count reaches updateConfig on the
// manager goroutine while the instance run loop is advertising every 30ms on a
// RETH. Beyond the race itself, a torn MaxAdverInt feeds the PEER's master-down
// computation, which is the flapping mechanism gemini-048 finding 06 describes.
//
// These cells are only meaningful under `-race`. Without it a torn read is
// invisible, so each one carries a comment saying so rather than looking like
// a functional assertion.

// raceTestInstance builds an instance with no sockets. sendPacket returns nil
// when rawConn is nil and sendPacketIPv6 when ipv6Conn is nil, so the advert
// path runs end to end without touching the network — which is what lets the
// cell drive the REAL sendAdvert rather than a re-implementation of its read.
func raceTestInstance(t *testing.T) *vrrpInstance {
	t.Helper()
	return newInstance(Instance{
		Interface:         "xpf-8597-race",
		GroupID:           42,
		Priority:          200,
		AdvertiseInterval: 1000,
		GARPCount:         3,
		VirtualAddresses:  []string{"10.0.0.254/24"},
	}, &net.Interface{Name: "xpf-8597-race"}, nil, nil)
}

// hammerUpdateConfig runs the day-2 writer in a loop until stop closes.
func hammerUpdateConfig(vi *vrrpInstance, stop <-chan struct{}, done *sync.WaitGroup) {
	defer done.Done()
	interval := 1000
	garp := 3
	for {
		select {
		case <-stop:
			return
		default:
		}
		interval ^= 1000 ^ 30
		garp ^= 3 ^ 5
		vi.updateConfig(Instance{
			Interface:         "xpf-8597-race",
			GroupID:           42,
			Priority:          200,
			AdvertiseInterval: interval,
			GARPCount:         garp,
		})
	}
}

// TestSendAdvertReadsAdvertiseIntervalUnderTheLock_8597 drives the real
// sendAdvert against the real updateConfig.
//
// Under `-race` this FAILS on master, pointing at instance_send.go's
// `vi.cfg.AdvertiseInterval` read against instance.go's write. Without `-race`
// it passes either way — that is a property of the detector, not of the cell,
// and it is why this file exists rather than an assertion on a value.
func TestSendAdvertReadsAdvertiseIntervalUnderTheLock_8597(t *testing.T) {
	vi := raceTestInstance(t)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go hammerUpdateConfig(vi, stop, &wg)

	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		vi.sendAdvert(200)
	}
	close(stop)
	wg.Wait()
}

// TestSendGARPReadsGARPCountUnderTheLock_8597 is the sendGARP arm.
//
// The epoch is bumped each iteration so garpSendAllowed's per-epoch dedup does
// not short-circuit before the cfg.GARPCount read — without that the loop would
// return at the dedup and never reach the racing line, and the cell would pass
// on master for the wrong reason.
func TestSendGARPReadsGARPCountUnderTheLock_8597(t *testing.T) {
	prevBurst, prevProbe := garpBurstFn, arpProbeFn
	garpBurstFn = func(string, net.IP, int, cluster.BurstStillValid) error { return nil }
	arpProbeFn = func(string, net.IP, net.IP) error { return nil }
	t.Cleanup(func() { garpBurstFn, arpProbeFn = prevBurst, prevProbe })

	vi := raceTestInstance(t)
	vi.setState(StateMaster)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go hammerUpdateConfig(vi, stop, &wg)

	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		vi.garpEpoch.Add(1)
		vi.sendGARP(true)
	}
	close(stop)
	wg.Wait()
}

// TestGARPEpochBumpActuallyReachesTheCountRead_8597 is the non-vacuity control
// for the cell above.
//
// If garpSendAllowed short-circuited every call, sendGARP would return before
// reading cfg.GARPCount and the race cell would be green on master while
// exercising nothing. This asserts the burst function is actually invoked under
// the same epoch-bumping loop.
func TestGARPEpochBumpActuallyReachesTheCountRead_8597(t *testing.T) {
	var calls int
	prevBurst, prevProbe := garpBurstFn, arpProbeFn
	garpBurstFn = func(string, net.IP, int, cluster.BurstStillValid) error { calls++; return nil }
	arpProbeFn = func(string, net.IP, net.IP) error { return nil }
	t.Cleanup(func() { garpBurstFn, arpProbeFn = prevBurst, prevProbe })

	vi := raceTestInstance(t)
	vi.setState(StateMaster)
	for i := 0; i < 5; i++ {
		vi.garpEpoch.Add(1)
		vi.sendGARP(true)
	}
	if calls == 0 {
		t.Fatal("sendGARP never reached its burst: garpSendAllowed short-circuited every " +
			"call, so the race cell above never reaches the cfg.GARPCount read and is vacuous")
	}
}

// TestRunStartupLogReadsConfigUnderTheLock_8597 covers the third site. It is a
// log line, so the consequence is a possibly-stale field rather than a wrong
// forwarding decision — but a data race is a data race, and `go test -race`
// in CI does not grade them by consequence.
//
// The log read is inside run(), which also starts the state machine, so this
// drives the extracted snapshot helper the fix introduces and asserts the
// values it returns. The race arm is covered by the two cells above hammering
// the same writer; what this pins is that the helper reads BOTH fields, since a
// snapshot that grabbed only one would leave the other unlocked at the call
// site.
func TestRunStartupLogReadsConfigUnderTheLock_8597(t *testing.T) {
	vi := raceTestInstance(t)
	pri, preempt := vi.startupLogFields()
	if pri != 200 {
		t.Errorf("startupLogFields priority = %d, want 200", pri)
	}
	if preempt {
		t.Errorf("startupLogFields preempt = true, want false")
	}
	vi.updateConfig(Instance{
		Interface:         "xpf-8597-race",
		GroupID:           42,
		Priority:          150,
		Preempt:           true,
		AdvertiseInterval: 1000,
	})
	pri, preempt = vi.startupLogFields()
	if pri != 150 || !preempt {
		t.Errorf("startupLogFields = (%d, %v) after updateConfig, want (150, true) — the "+
			"snapshot must read BOTH fields, not one", pri, preempt)
	}
}

// TestGARPCountAccessorSnapshotsUnderTheLock_8597 pins the new accessor's
// value, so a snapshot helper that returned a constant (or the wrong field)
// would fail here rather than merely silencing the detector.
func TestGARPCountAccessorSnapshotsUnderTheLock_8597(t *testing.T) {
	vi := raceTestInstance(t)
	if got := vi.garpCount(); got != 3 {
		t.Errorf("garpCount() = %d, want 3", got)
	}
	vi.updateConfig(Instance{
		Interface:         "xpf-8597-race",
		GroupID:           42,
		Priority:          200,
		AdvertiseInterval: 1000,
		GARPCount:         7,
	})
	if got := vi.garpCount(); got != 7 {
		t.Errorf("garpCount() = %d after updateConfig, want 7", got)
	}
}

// TestOneAdvertCallUsesOneIntervalSnapshot_8597 pins the property the race
// detector CANNOT see, and the one the fix's comment claims.
//
// Taking the lock once per arm — `uint16(vi.advertiseIntervalMS() / 10)` in
// each branch — silences `-race` completely and is still wrong: a dual-stack
// instance sends its v4 and v6 adverts from ONE sendAdvert call, and a writer
// landing between them makes the two families advertise DIFFERENT MaxAdverInt
// values. The peer derives its master-down interval from that field, so the two
// families would disagree about the failover horizon.
//
// The cell is deterministic rather than probabilistic: the seam performs the
// config write from inside the v4 arm, so the interleaving the property forbids
// is GUARANTEED to occur rather than raced for. With one snapshot both packets
// carry the pre-write value; with a read per arm the v6 packet carries the new
// one.
func TestOneAdvertCallUsesOneIntervalSnapshot_8597(t *testing.T) {
	vi := raceTestInstance(t)
	vi.cfg.VirtualAddresses = []string{"10.0.0.254/24", "2001:db8::254/64"}

	var v4Seen, v6Seen uint16
	var sawV4, sawV6 bool

	prev := sendPacketFn
	sendPacketFn = func(inst *vrrpInstance, pkt *VRRPPacket, isIPv6 bool) error {
		if isIPv6 {
			v6Seen, sawV6 = pkt.MaxAdvertInt, true
			return nil
		}
		v4Seen, sawV4 = pkt.MaxAdvertInt, true
		// The writer, landing exactly between the two arms.
		inst.updateConfig(Instance{
			Interface:         "xpf-8597-race",
			GroupID:           42,
			Priority:          200,
			AdvertiseInterval: 30,
		})
		return nil
	}
	t.Cleanup(func() { sendPacketFn = prev })

	vi.sendAdvert(200)

	if !sawV4 || !sawV6 {
		t.Fatalf("sendAdvert emitted v4=%v v6=%v; the fixture must produce BOTH families "+
			"or the agreement it asserts is vacuous", sawV4, sawV6)
	}
	if v4Seen != v6Seen {
		t.Fatalf("one sendAdvert call advertised MaxAdverInt %d on IPv4 and %d on IPv6: the "+
			"interval is read per-arm rather than snapshotted once, so a day-2 commit "+
			"landing mid-call makes the two families disagree about the failover horizon "+
			"(#8597/K20)", v4Seen, v6Seen)
	}
	if v4Seen != 100 {
		t.Errorf("MaxAdverInt = %d, want 100 (1000ms/10); both packets must carry the value "+
			"read BEFORE the mid-call write, not after", v4Seen)
	}
}
