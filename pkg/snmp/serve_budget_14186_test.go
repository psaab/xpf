package snmp

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// TestServeBudgetPendingReservationNoStarve14186 is the decisive regression
// check for #14186 (D9-05): with an admitted manager M, a drained global
// bucket, and >=64 (here: a full 1023-source) set of spoofed pending
// newcomers, M must be admitted within one refill cycle. The claim required
// pendingSources to reserve ~the whole 4000-token global burst; in fact
// pendingSources is bounded by the 1024-entry source table, pending expires
// after 1s of quiet, and the scarce-reservation gate only sheds admitted
// sources while globalTokens < pendingSources+1. After a 2s refill the
// bucket is capped at 4000 >= 1023+1, so M is admitted and the (now stale)
// pending set is swept. This pins that bound so a future change to the
// burst, table size, or pending accounting that breaks it fails here.
func TestServeBudgetPendingReservationNoStarve14186(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := newSNMPServeBudget()
	b.now = func() time.Time { return now }

	manager := net.ParseIP("10.20.0.1")
	if !b.allow(manager) {
		t.Fatal("manager initial admission failed")
	}
	b.account(manager, 100*time.Microsecond)

	// Drain the global bucket, then enroll spoofed pendings: each distinct
	// source arriving while globalTokens < 1 becomes pending.
	b.mu.Lock()
	b.globalTokens = 0
	b.globalLast = now
	b.mu.Unlock()
	for i := range 1023 {
		ip := net.ParseIP(fmt.Sprintf("10.%d.%d.%d", 30+(i/256)%200, i/256%256, i%256))
		if b.allow(ip) {
			t.Fatalf("spoofed source %d admitted with empty global bucket", i)
		}
	}
	b.mu.Lock()
	pending, tracked := b.pendingSources, len(b.perSource)
	b.mu.Unlock()
	if pending != 1023 || tracked != 1024 {
		t.Fatalf("enrollment = pending %d tracked %d, want 1023/1024 (table bound)", pending, tracked)
	}
	if pending+1 > snmpServeGlobalBurst {
		t.Fatalf("pendingSources %d + 1 exceeds global burst %d: reservation could lock out admitted sources", pending, snmpServeGlobalBurst)
	}

	// One refill cycle to the burst cap admits the admitted manager.
	now = now.Add(2 * time.Second)
	if !b.allow(manager) {
		t.Fatalf("admitted manager starved by %d pending reservations after refill to burst", pending)
	}
	// A pending newcomer is likewise admitted after refill, not locked out.
	if !b.allow(net.ParseIP("10.30.0.0")) {
		t.Fatal("pending newcomer not admitted after refill")
	}
}
