package snmp

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// TestServeBudgetBurstThenRefill9917 pins the F-139 token-bucket semantics with
// a frozen/advanceable fake clock (no sleeping): exactly the burst is admitted,
// the next is shed, advancing one second refills exactly the rate, and a second
// source is unaffected by the first's exhaustion.
func TestServeBudgetBurstThenRefill9917(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := newSNMPServeBudget()
	b.now = func() time.Time { return now }

	src := net.ParseIP("10.0.0.9")
	for i := 0; i < snmpServeBurstPerSource; i++ {
		if !b.allow(src) {
			t.Fatalf("request %d denied with a full bucket (burst %d)", i, snmpServeBurstPerSource)
		}
	}
	if b.allow(src) {
		t.Fatalf("request past burst %d admitted on a frozen clock", snmpServeBurstPerSource)
	}
	// Second source holds its own full bucket.
	other := net.ParseIP("10.0.0.10")
	if !b.allow(other) {
		t.Fatal("second source denied while the first is exhausted (buckets not per-source)")
	}
	// Advance one second: exactly the sustained rate refills.
	now = now.Add(time.Second)
	allowed := 0
	for i := 0; i < snmpServeRatePerSource+10; i++ {
		if b.allow(src) {
			allowed++
		}
	}
	if allowed != snmpServeRatePerSource {
		t.Fatalf("after 1s refilled %d, want exactly %d", allowed, snmpServeRatePerSource)
	}
}

// TestServeBudgetKeysOnNormalizedIP9917 pins that the budget keys on the
// normalized IP only: 4-byte and 16-byte forms of one address share a bucket
// (no double allowance), and distinct addresses do not.
func TestServeBudgetKeysOnNormalizedIP9917(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := newSNMPServeBudget()
	b.now = func() time.Time { return now }

	v4 := net.IP{10, 0, 0, 9} // 4-byte form
	v16 := net.ParseIP("10.0.0.9")
	if len(v16) != 16 {
		t.Fatalf("test precondition: ParseIP returned %d bytes, want 16", len(v16))
	}
	half := snmpServeBurstPerSource / 2
	for i := 0; i < half; i++ {
		if !b.allow(v4) {
			t.Fatalf("4-byte form denied at %d", i)
		}
	}
	for i := 0; i < half; i++ {
		if !b.allow(v16) {
			t.Fatalf("16-byte form denied at %d: same address must share one bucket", i)
		}
	}
	if b.allow(v4) || b.allow(v16) {
		t.Fatal("request past the shared burst admitted (4-byte/16-byte split buckets)")
	}
	if !b.allow(net.ParseIP("10.0.0.11")) {
		t.Fatal("distinct address denied (buckets not per-source)")
	}
}

// TestServeBudgetClockStepBackGrantsNothing9917 pins that a wall-clock jump
// backward refills nothing and a jump forward refills at most the burst cap.
func TestServeBudgetClockStepBackGrantsNothing9917(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := newSNMPServeBudget()
	b.now = func() time.Time { return now }

	src := net.ParseIP("10.0.0.9")
	for i := 0; i < snmpServeBurstPerSource; i++ {
		b.allow(src)
	}
	if b.allow(src) {
		t.Fatal("precondition: bucket not exhausted")
	}
	now = now.Add(-time.Hour) // step backward
	if b.allow(src) {
		t.Fatal("clock step backward granted a token")
	}
	now = now.Add(100 * 24 * time.Hour) // huge forward jump
	allowed := 0
	for i := 0; i < snmpServeBurstPerSource+10; i++ {
		if b.allow(src) {
			allowed++
		}
	}
	if allowed != snmpServeBurstPerSource {
		t.Fatalf("forward jump refilled %d, want the burst cap %d", allowed, snmpServeBurstPerSource)
	}
}

// TestServeBudgetFullTableShedsThenAdmitsAfterExpiry9917 pins the bounded-memory
// contract: past snmpServeMaxSources an unknown source sheds untracked, and an
// idle TTL later the sweep reclaims its slot so a newcomer is admitted.
func TestServeBudgetFullTableShedsThenAdmitsAfterExpiry9917(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := newSNMPServeBudget()
	b.now = func() time.Time { return now }

	for i := 0; i < snmpServeMaxSources; i++ {
		ip := net.ParseIP(fmt.Sprintf("10.1.%d.%d", i/256, i%256))
		if !b.allow(ip) {
			t.Fatalf("fill %d denied before the table is full", i)
		}
	}
	if b.allow(net.ParseIP("10.2.0.1")) {
		t.Fatal("unknown source admitted past the full table (memory unbounded)")
	}
	// Idle past the TTL and the sweep interval, then a newcomer displaces the
	// expired: admitted, not shed.
	now = now.Add(snmpServeSourceIdleTTL + snmpServeSweepInterval)
	if !b.allow(net.ParseIP("10.2.0.1")) {
		t.Fatal("newcomer shed after idle entries expired (sweep did not reclaim)")
	}
}

// TestServeBudgetNilAllow9917 pins the bypass rules: a nil budget (bare-struct
// agents), a nil IP, and an unparseable IP all allow.
func TestServeBudgetNilAllow9917(t *testing.T) {
	var nilBudget *snmpServeBudget
	if !nilBudget.allow(net.ParseIP("10.0.0.9")) {
		t.Fatal("nil budget denied (bare-struct agents must stay unbudgeted)")
	}
	b := newSNMPServeBudget()
	if !b.allow(nil) {
		t.Fatal("nil srcIP denied (non-IP transports bypass)")
	}
	if !b.allow(net.IP{1}) {
		t.Fatal("unparseable IP denied (must bypass, not index a garbage key)")
	}
	// A budget hand-built without the constructor (nil map) must not panic.
	bare := &snmpServeBudget{now: time.Now}
	if !bare.allow(net.ParseIP("10.0.0.9")) {
		t.Fatal("nil-map budget denied (lazy init must admit)")
	}
}
