package vrrp

import (
	"net"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
)

// #14155 — becomeMaster bumps garpEpoch and unlocks vipMu WITHOUT recording
// the actuated VIPs as pending GARP announcements, then launches
// `go vi.sendGARP(false)`. If a concurrent updateVIPs adding a VIP runs
// before that deferred sender acquires vipMu, the update bumps the epoch
// again, sees an empty pending set, announces only the added VIP, and its
// reservation (lastGARPEpoch = new epoch) makes the deferred failover
// sender's epoch dedup suppress the original VIPs entirely. Neighbours keep
// stale ARP/NDP bindings for the pre-existing VIPs until cache expiry.
//
// The deferred sender is modelled deterministically here the same way
// TestBecomeMasterGARPIsDampened models the becomeMaster path: suppress the
// async launch inside becomeMaster, run the interleaving update, then invoke
// sendGARP(false) synchronously as the parked goroutine would once scheduled.
// sendGARP reads garpEpoch at acquisition time, so the synchronous call
// observes exactly the epoch state the parked goroutine would.
//
// RED on master: the update announces only 10.0.141.3 and the deferred sender
// is epoch-deduped, so 10.0.141.1/10.0.141.2 receive no burst at all.
func TestBecomeMasterGARPDeferredSenderSurvivesVIPAdd_14155(t *testing.T) {
	oldGARP, oldNA, oldProbe := garpBurstFn, naBurstFn, arpProbeFn
	t.Cleanup(func() { garpBurstFn, naBurstFn, arpProbeFn = oldGARP, oldNA, oldProbe })

	var mu sync.Mutex
	counts := map[string]int{}
	burst := func(_ string, ip net.IP, _ int, _ cluster.BurstStillValid) error {
		mu.Lock()
		counts[ip.String()]++
		mu.Unlock()
		return nil
	}
	garpBurstFn, naBurstFn = burst, burst
	arpProbeFn = func(string, net.IP, net.IP) error { return nil }

	v1, v2, v3 := "10.0.141.1/24", "10.0.141.2/24", "10.0.141.3/24"
	vi := newBecomeMasterGARPInstance12201(t, []string{v1, v2})
	// Suppress only becomeMaster's async launch so the test can run the
	// deferred sender synchronously after the interleaving update.
	vi.suppressGARP.Store(true)
	if !vi.becomeMaster() {
		t.Fatal("FIXTURE: becomeMaster must claim ownership when VIP actuation succeeds")
	}
	if got := vi.garpEpoch.Load(); got != 1 {
		t.Fatalf("garpEpoch after becomeMaster = %d, want 1", got)
	}
	// The deferred sender would have been launched unsuppressed; model that
	// sender, not a suppressed one, from here on.
	vi.suppressGARP.Store(false)

	// Concurrent membership update lands before the deferred sender runs.
	if err := vi.updateVIPs([]string{v1, v2, v3}); err != nil {
		t.Fatalf("updateVIPs adding a VIP during the failover GARP window: %v", err)
	}
	if got := vi.garpEpoch.Load(); got != 2 {
		t.Fatalf("garpEpoch after updateVIPs = %d, want 2", got)
	}

	// The parked becomeMaster sender now acquires vipMu.
	vi.sendGARP(false)

	mu.Lock()
	got := make(map[string]int, len(counts))
	for ip, n := range counts {
		got[ip] = n
	}
	mu.Unlock()
	for _, vip := range []string{v1, v2, v3} {
		ip, _, err := net.ParseCIDR(vip)
		if err != nil {
			t.Fatalf("FIXTURE: parse %s: %v", vip, err)
		}
		if got[ip.String()] != 1 {
			t.Fatalf("GARP bursts for %s = %d, want exactly 1 (all bursts: %v) — "+
				"the deferred failover GARP for pre-existing VIPs was suppressed "+
				"by the concurrent updateVIPs reservation (#14155)",
				ip, got[ip.String()], got)
		}
	}
	if len(got) != 3 {
		t.Fatalf("GARP bursts announced unexpected VIPs: %v", got)
	}
	vi.vipMu.Lock()
	pending := len(vi.pendingGARPVIPs)
	vi.vipMu.Unlock()
	if pending != 0 {
		t.Fatalf("pending GARP VIPs after all announcements = %d, want 0", pending)
	}
}

// Control: a suppressed becomeMaster followed by the unsuppress sender (the
// SetGARPSuppression true->false edge calls sendGARP(true) while MASTER) must
// still announce every VIP exactly once. Populating the pending set at
// becomeMaster must not turn the full-set unsuppress burst into a no-op or a
// duplicate.
func TestBecomeMasterSuppressedThenUnsuppressAnnouncesAll_14155(t *testing.T) {
	oldGARP, oldNA, oldProbe := garpBurstFn, naBurstFn, arpProbeFn
	t.Cleanup(func() { garpBurstFn, naBurstFn, arpProbeFn = oldGARP, oldNA, oldProbe })

	var mu sync.Mutex
	counts := map[string]int{}
	burst := func(_ string, ip net.IP, _ int, _ cluster.BurstStillValid) error {
		mu.Lock()
		counts[ip.String()]++
		mu.Unlock()
		return nil
	}
	garpBurstFn, naBurstFn = burst, burst
	arpProbeFn = func(string, net.IP, net.IP) error { return nil }

	v1, v2 := "10.0.141.1/24", "fd00:141::1/64"
	vi := newBecomeMasterGARPInstance12201(t, []string{v1, v2})
	vi.suppressGARP.Store(true)
	if !vi.becomeMaster() {
		t.Fatal("FIXTURE: a suppressed becomeMaster must still claim ownership")
	}
	vi.suppressGARP.Store(false)
	vi.sendGARP(true) // the unsuppress-edge sender

	mu.Lock()
	defer mu.Unlock()
	for _, vip := range []string{v1, v2} {
		ip, _, err := net.ParseCIDR(vip)
		if err != nil {
			t.Fatalf("FIXTURE: parse %s: %v", vip, err)
		}
		if counts[ip.String()] != 1 {
			t.Fatalf("unsuppress GARP/NA bursts for %s = %d, want exactly 1 (all bursts: %v)",
				ip, counts[ip.String()], counts)
		}
	}
	if len(counts) != 2 {
		t.Fatalf("unsuppress announced unexpected VIPs: %v", counts)
	}
}
