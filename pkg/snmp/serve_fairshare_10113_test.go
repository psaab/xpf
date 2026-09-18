package snmp

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// allowN10113 admits exactly n requests from ip, failing on any shed: the
// setup precondition for the fair-share cells below.
func allowN10113(t *testing.T, b *snmpServeBudget, ip net.IP, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if !b.allow(ip) {
			t.Fatalf("setup allow %d for %s denied (precondition)", i, ip)
		}
	}
}

func admitExpensive10113(t *testing.T, b *snmpServeBudget, ip net.IP, n int, elapsed time.Duration) {
	t.Helper()
	allowN10113(t, b, ip, n)
	b.account(ip, elapsed)
}

// drainAdmitCount10113 attempts tries requests from ip and returns how many
// admitted.
func drainAdmitCount10113(b *snmpServeBudget, ip net.IP, tries int) int {
	n := 0
	for i := 0; i < tries; i++ {
		if b.allow(ip) {
			n++
		}
	}
	return n
}

// TestServeBudgetFairShareScalesCharge10113 pins the #10113 fair-share charge:
// the per-source service factor scales with the contender count, so each of N
// contending sources converges to an equal 1/(2N) split of the global half
// instead of racing for it FIFO. The 100ms service cell leaves the global
// backstop enough debt to make the per-source remainder observable after a
// 900ms refill, without waiting or reading counters.
func TestServeBudgetFairShareScalesCharge10113(t *testing.T) {
	t.Run("ten contenders split the half", func(t *testing.T) {
		now := time.Unix(1_700_000_000, 0)
		b := newSNMPServeBudget()
		b.now = func() time.Time { return now }

		for i := 0; i < 10; i++ {
			ip := net.ParseIP(fmt.Sprintf("10.6.0.%d", i+1))
			admitExpensive10113(t, b, ip, 2, 100*time.Millisecond)
		}
		victim := net.ParseIP("10.6.0.10")
		now = now.Add(900 * time.Millisecond)
		// Victim has 198 - (100ms * 100 * 20) + 90 = 88 tokens.
		if got := drainAdmitCount10113(b, victim, snmpServeBurstPerSource); got != 88 {
			t.Fatalf("after a 100ms charge at N=10 + 900ms refill, %d admitted, want exactly 88", got)
		}
	})

	t.Run("six contenders scale below the old floor", func(t *testing.T) {
		now := time.Unix(1_700_000_000, 0)
		b := newSNMPServeBudget()
		b.now = func() time.Time { return now }

		for i := 0; i < 6; i++ {
			ip := net.ParseIP(fmt.Sprintf("10.6.1.%d", i+1))
			admitExpensive10113(t, b, ip, 2, 100*time.Millisecond)
		}
		victim := net.ParseIP("10.6.1.6")
		now = now.Add(900 * time.Millisecond)
		// N=6 uses factor 12: 198 - (100ms * 100 * 12) + 90 = 168.
		if got := drainAdmitCount10113(b, victim, snmpServeBurstPerSource); got != 168 {
			t.Fatalf("after a 100ms charge at N=6 + 900ms refill, %d admitted, want exactly 168", got)
		}
	})

	t.Run("four contenders preserve single-source floor", func(t *testing.T) {
		now := time.Unix(1_700_000_000, 0)
		b := newSNMPServeBudget()
		b.now = func() time.Time { return now }

		for i := 0; i < 4; i++ {
			ip := net.ParseIP(fmt.Sprintf("10.6.2.%d", i+1))
			admitExpensive10113(t, b, ip, 2, 100*time.Millisecond)
		}
		victim := net.ParseIP("10.6.2.4")
		now = now.Add(900 * time.Millisecond)
		// max(10, 2x4) remains 10: 198 - 100 + 90 = 188.
		if got := drainAdmitCount10113(b, victim, snmpServeBurstPerSource); got != 188 {
			t.Fatalf("after a 100ms charge at N=4 + 900ms refill, %d admitted, want exactly 188", got)
		}
	})
}

// TestServeBudgetFairShareExpiry10113 prevents historical contenders from
// permanently inflating a later lone source's charge. The idle contenders are
// never accessed after their expensive request; the bounded expiry sweep must
// release them, restoring the unchanged 10x single-source behavior.
func TestServeBudgetFairShareExpiry10113(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := newSNMPServeBudget()
	b.now = func() time.Time { return now }

	for i := 0; i < 10; i++ {
		admitExpensive10113(t, b, net.ParseIP(fmt.Sprintf("10.8.0.%d", i+1)), 1, 10*time.Millisecond)
	}
	now = now.Add(2 * time.Second)
	fresh := net.ParseIP("10.8.1.1")
	allowN10113(t, b, fresh, 1)
	b.account(fresh, 125*time.Millisecond)
	// Fresh bucket holds 199 tokens; after the restored factor-10 charge it
	// has exactly 74 admissions remaining.
	if got := drainAdmitCount10113(b, fresh, snmpServeBurstPerSource); got != 74 {
		t.Fatalf("after idle expiry + 125ms charge, %d admitted, want exactly 74 (199-125)", got)
	}
}

// TestServeBudgetFairShareCheapSybilExpires10113 prevents cheap keepalives
// from reserving an expensive contender slot. The legitimate expensive source
// stays active while six Sybils are refreshed below the classifier threshold;
// their scarce-global retries are only one-shot probes and the later source
// must still receive the ordinary 10x factor.
func TestServeBudgetFairShareCheapSybilExpires10113(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := newSNMPServeBudget()
	b.now = func() time.Time { return now }
	legit := net.ParseIP("10.9.0.1")
	sybil := make([]net.IP, 6)
	admitExpensive10113(t, b, legit, 1, 10*time.Millisecond)
	for i := range sybil {
		sybil[i] = net.ParseIP(fmt.Sprintf("10.9.0.%d", i+2))
		admitExpensive10113(t, b, sybil[i], 1, 10*time.Millisecond)
	}

	now = now.Add(900 * time.Millisecond)
	for _, ip := range sybil {
		allowN10113(t, b, ip, 1)
		b.account(ip, 999*time.Microsecond)
	}
	allowN10113(t, b, legit, 1)
	b.account(legit, 10*time.Millisecond)

	// This admitted cheap observer triggers expiry of the six Sybil slots.
	now = now.Add(200 * time.Millisecond)
	observer := net.ParseIP("10.9.0.8")
	allowN10113(t, b, observer, 1)
	b.mu.Lock()
	b.globalTokens = 0
	b.globalLast = now
	b.mu.Unlock()
	for _, ip := range sybil {
		if b.allow(ip) {
			t.Fatal("Sybil probe admitted with an empty global bucket")
		}
	}

	// Refill enough global credits for all six pending probes, but keep the
	// pending state younger than the one-second expiry sweep.
	now = now.Add(900 * time.Millisecond)
	for _, ip := range sybil {
		allowN10113(t, b, ip, 1)
		b.account(ip, 999*time.Microsecond)
	}
	// A second scarce-global retry must not re-enroll the cheap probe.
	b.mu.Lock()
	b.globalTokens = 0
	b.globalLast = now
	b.mu.Unlock()
	if b.allow(sybil[0]) {
		t.Fatal("second cheap Sybil retry admitted with an empty global bucket")
	}
	raw := sybil[0].To16()
	var key [16]byte
	copy(key[:], raw)
	b.mu.Lock()
	pendingCount := b.pendingSources
	eligible := b.perSource[key].everExpensive
	b.globalTokens = snmpServeGlobalBurst
	b.mu.Unlock()
	if pendingCount != 0 || eligible {
		t.Fatalf("cheap probe re-enrolled: pending=%d everExpensive=%t", pendingCount, eligible)
	}
	allowN10113(t, b, legit, 1)
	b.account(legit, 10*time.Millisecond)
	fresh := net.ParseIP("10.9.0.9")
	allowN10113(t, b, fresh, 1)
	b.account(fresh, 125*time.Millisecond)
	if got := drainAdmitCount10113(b, fresh, snmpServeBurstPerSource); got != 74 {
		t.Fatalf("cheap Sybils retained contender slots: admitted %d, want 74 (factor 10)", got)
	}
}

// TestServeBudgetFairShareSplitsGlobalHalf10113 is the #10113 enforcement cell:
// ten saturated expensive sources split the global half equally even when one
// offers 10x the arrival pressure. The scripted arrival pattern (aggressor
// attempts first every round) runs against the real budget with an advancing
// fake clock -- no sockets, no sleeping, deterministic. Sources are NOT
// pre-warmed: the pending-newcomer gate must onboard late sources that already
// reached Serve; datagrams lost in the socket buffer remain out of scope.
func TestServeBudgetFairShareSplitsGlobalHalf10113(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := newSNMPServeBudget()
	b.now = func() time.Time { return now }

	const sources = 10
	ips := make([]net.IP, sources)
	for i := range ips {
		ips[i] = net.ParseIP(fmt.Sprintf("10.7.0.%d", i+1))
	}
	const svcCost = 33 * time.Millisecond // in-tree max-size ifXTable worst case
	counts := make([]int, sources)
	round := func() {
		// Source zero offers 10x the pressure and is always first in the
		// userspace arrival order. The other sources still reach Serve.
		for k := 0; k < 40; k++ {
			if b.allow(ips[0]) {
				b.account(ips[0], svcCost)
				now = now.Add(svcCost)
				counts[0]++
			}
		}
		for s := 1; s < sources; s++ {
			for k := 0; k < 4; k++ {
				if b.allow(ips[s]) {
					b.account(ips[s], svcCost)
					now = now.Add(svcCost)
					counts[s]++
				}
			}
		}
		// Denied datagrams still consume a bounded amount of loop time; this
		// lets a depleted global bucket refill without sleeping.
		now = now.Add(time.Millisecond)
	}
	// Run a fixed number of rounds so the evidence is deterministic and fast;
	// successful requests advance fake time by their measured service cost.
	for i := 0; i < 1000; i++ {
		round()
	}
	for i := range counts {
		counts[i] = 0
	}
	measureStart := now
	for i := 0; i < 20000; i++ {
		round()
	}

	min, max, total := counts[0], counts[0], 0
	for _, c := range counts {
		if c < min {
			min = c
		}
		if c > max {
			max = c
		}
		total += c
	}
	measureElapsed := now.Sub(measureStart).Seconds()
	busyShare := float64(total) * svcCost.Seconds() / measureElapsed
	t.Logf("split over 20000 rounds: counts %v (late sources admitted), elapsed %.3fs, busy share %.3f",
		counts, measureElapsed, busyShare)
	if min < 1 {
		t.Fatalf("starved source in the split (min %d): fair-share must not lock anyone out", min)
	}
	if ratio := float64(max) / float64(min); ratio > 1.3 {
		t.Fatalf("unfair split: max %d / min %d = %.2fx, want <= 1.30x (equal shares of the half)", max, min, ratio)
	}
	if busyShare < 0.35 || busyShare > 0.65 {
		t.Fatalf("aggregate busy share %.3f, want approximately global half [0.35, 0.65]", busyShare)
	}
}

// TestServeBudgetFairSharePendingExpiry10113 ensures a quiet newcomer that
// loses a global credit cannot leave every existing source yielding forever.
func TestServeBudgetFairSharePendingExpiry10113(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := newSNMPServeBudget()
	b.now = func() time.Time { return now }

	existing := net.ParseIP("10.12.0.1")
	allowN10113(t, b, existing, 1)
	b.mu.Lock()
	b.globalTokens = 0
	b.mu.Unlock()
	pending := net.ParseIP("10.12.0.2")
	if b.allow(pending) {
		t.Fatal("pending newcomer admitted with empty global bucket")
	}
	now = now.Add(500 * time.Millisecond)
	if !b.allow(existing) {
		t.Fatal("existing source blocked despite surplus global credits")
	}
	now = now.Add(2 * time.Second)
	if !b.allow(existing) {
		t.Fatal("existing source remained blocked after pending newcomer went idle")
	}
}

// TestServeBudgetFairShareCheapPollingUnaffected10113 verifies that the
// contender factor is charged only to expensive buckets: a microsecond-scale
// manager still gets its ordinary polling budget while ten expensive sources
// are active.
func TestServeBudgetFairShareCheapPollingUnaffected10113(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := newSNMPServeBudget()
	b.now = func() time.Time { return now }

	for i := 0; i < 10; i++ {
		admitExpensive10113(t, b, net.ParseIP(fmt.Sprintf("10.13.0.%d", i+1)), 1, 10*time.Millisecond)
	}
	cheap := net.ParseIP("10.13.1.1")
	allowN10113(t, b, cheap, 1)
	b.account(cheap, 999*time.Microsecond)
	if got := drainAdmitCount10113(b, cheap, snmpServeBurstPerSource); got != 198 {
		t.Fatalf("cheap 999us poll charged with contender factor: admitted %d, want 198 (ordinary 10x remainder)", got)
	}
}
