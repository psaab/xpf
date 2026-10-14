package vrrp

import (
	"runtime"
	"testing"
	"time"
)

// #12495 — the IPv6 lab half of #12201. The unit pins from PR #12416 cover a
// MIXED-family VIP set (one v4 + one v6), which is the shape of the default
// cluster RGs. The lab leg fails over an RG whose neighbors are IPv6 only,
// and the attribution argument ("an RA's SLLA cannot rewrite a global-VIP
// neighbor entry, only the NA burst can") needs the v6 announcement to be
// independent of the v4 path in two ways the mixed-family test cannot see:
//
//   - a v6-ONLY RG must still launch the burst: a regression that gates the
//     launch on any v4 work (an early return when no IPv4 VIP exists) leaves
//     the mixed test green and a v6-only RG permanently unannounced — new v6
//     flows blackhole until NUD re-resolves.
//   - EVERY v6 VIP gets its own NA: the receiving side repairs one neighbor
//     entry per target address, so announcing only the first v6 VIP leaves
//     the other VIP's peers stale. An RA cannot cover the gap (SLLA touches
//     only the router link-local entry).
//
// Both tests drive becomeMaster() itself (not sendGARP) and reuse the #12416
// capture seams, so they stay RED if the `go vi.sendGARP(false)` launch is
// removed.

// A v6-only RG claims mastership and announces every v6 VIP with an NA burst,
// with no IPv4 GARP in flight.
//
// RED-ON-REVERT:
//   - deleting the `go vi.sendGARP(false)` launch → no NA arrives, timeout;
//   - gating the launch on "has an IPv4 VIP" → no NA arrives, timeout, while
//     TestBecomeMaster_LaunchesOneBurstPerVIPFamily_12201 stays green;
//   - announcing only the first v6 VIP → the fd00:62::2 capture is missing.
func TestBecomeMaster_V6OnlyRGAnnouncesEveryV6VIP_12495(t *testing.T) {
	bursts := captureBursts12201(t)
	vi := newBecomeMasterGARPInstance12201(t, []string{"fd00:62::1/64", "fd00:62::2/64"})

	if !vi.becomeMaster() {
		t.Fatal("FIXTURE: a v6-only becomeMaster must claim ownership when VIP actuation succeeds")
	}
	if got := vi.garpEpoch.Load(); got != 1 {
		t.Fatalf("garpEpoch = %d, want 1 — the transition did not start a new burst tenure", got)
	}

	want := []string{"fd00:62::1", "fd00:62::2"}
	seen := make(map[string]bool, len(want))
	for len(seen) < len(want) {
		b := recvBurst12495(t, bursts)
		if b.family != "NA" {
			t.Fatalf("a v6-only RG emitted a %s burst for %s — no IPv4 VIP exists to announce", b.family, b.ip)
		}
		if seen[b.ip] {
			t.Fatalf("duplicate NA burst for %s", b.ip)
		}
		seen[b.ip] = true
	}
	for _, ip := range want {
		if !seen[ip] {
			t.Fatalf("missing NA burst for %s (got %v) — a v6-only RG announced only some of its VIPs (#12495)", ip, seen)
		}
	}
	// sendGARPReserved emits one seam call per VIP sequentially, so after
	// both arrivals the channel is deterministically drained.
	if n := len(bursts); n != 0 {
		t.Fatalf("unexpected extra bursts: %d still queued", n)
	}
	if got := vi.lastGARPEpoch.Load(); got != 1 {
		t.Fatalf("lastGARPEpoch = %d, want 1 — no burst was reserved for this tenure", got)
	}
}

// The lab leg's failover is followed by a MANUAL FAILBACK — a rapid
// MASTER→BACKUP→MASTER flap. The failback burst must not be eaten by the
// 500ms dampener: garpSendAllowedForOwner only dampens while
// lastGARPOwnerGen == ownerGen, and a tenure that ended bumps ownerGen, so a
// re-elected instance announces again even well inside 500ms of the previous
// burst. #12201's refutation notes name this exact hazard: once fw1's RA
// SLLA rewrites the host's router entry, a failback without an NA blackholes.
//
// RED-ON-REVERT: making the dampener unconditional (dropping the
// lastGARPOwnerGen guard in garpSendAllowedForOwner) silences the failback NA
// while every non-flap test stays green — the first burst already stored
// lastGARPTime.
func TestBecomeMaster_V6RapidFlapFailbackReannounces_12495(t *testing.T) {
	bursts := captureBursts12201(t)
	vi := newBecomeMasterGARPInstance12201(t, []string{"fd00:63::1/64"})

	if !vi.becomeMaster() {
		t.Fatal("FIXTURE: becomeMaster must claim ownership when VIP actuation succeeds")
	}
	first := recvBurst12495(t, bursts)
	if first.family != "NA" || first.ip != "fd00:63::1" {
		t.Fatalf("first burst = %s for %s, want NA for fd00:63::1", first.family, first.ip)
	}
	// Wait for the first sender to store lastGARPTime (sendGARPReserved's
	// final statement) so the flap lands demonstrably INSIDE the 500ms
	// dampening window rather than racing past it.
	deadline := time.Now().Add(5 * time.Second)
	for vi.lastGARPTime.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := vi.lastGARPTime.Load(); got == 0 {
		t.Fatal("FIXTURE: first burst never completed (lastGARPTime unset)")
	}

	// The flap: demote, then re-elect — the manual-failback shape, run well
	// inside the dampening window.
	vi.setState(StateBackup)
	if !vi.becomeMaster() {
		t.Fatal("FIXTURE: re-elected becomeMaster must claim ownership")
	}
	second := recvBurst12495(t, bursts)
	if second.family != "NA" || second.ip != "fd00:63::1" {
		t.Fatalf("failback burst = %s for %s, want NA for fd00:63::1 — the rapid flap was dampened and the re-election went unannounced (#12495)", second.family, second.ip)
	}
	if got := vi.garpEpoch.Load(); got != 2 {
		t.Fatalf("garpEpoch = %d, want 2 — the flap must start a new burst tenure", got)
	}
}

// recvBurst12495 waits for one captured burst with a timeout and a goroutine
// dump on failure, mirroring the #12201 collection loop for single events.
func recvBurst12495(t *testing.T, bursts <-chan burstCapture12201) burstCapture12201 {
	t.Helper()
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case b := <-bursts:
		return b
	case <-timer.C:
		stack := make([]byte, 1<<16)
		n := runtime.Stack(stack, true)
		t.Fatalf("timed out waiting for a captured burst (#12495)\n%s", stack[:n])
		return burstCapture12201{}
	}
}
