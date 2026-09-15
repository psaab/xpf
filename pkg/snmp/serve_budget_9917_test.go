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
	// Shed call-site counter: 1 past-burst deny + 10 past-refill denies.
	if got := b.shed.Load(); got != 11 {
		t.Fatalf("shed = %d, want 11 (every deny observed at the call site)", got)
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

// TestServeBudgetServiceChargeThrottlesExpensive9917 pins the F-139 service
// charge: an admitted request debits its loop time at rate x factor, so the
// refill during handling cannot replenish the admission token of an expensive
// PDU. One 125ms request costs 1 admission + 125 service tokens (125ms is
// binary-exact, keeping the frozen-clock remainder exact).
func TestServeBudgetServiceChargeThrottlesExpensive9917(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := newSNMPServeBudget()
	b.now = func() time.Time { return now }

	src := net.ParseIP("10.0.0.9")
	if !b.allow(src) {
		t.Fatal("first request denied on a full bucket")
	}
	b.account(src, 125*time.Millisecond)

	const wantLeft = snmpServeBurstPerSource - 1 - 125
	allowed := 0
	for i := 0; i < snmpServeBurstPerSource; i++ {
		if b.allow(src) {
			allowed++
		}
	}
	if allowed != wantLeft {
		t.Fatalf("after a 125ms charge, %d admitted, want exactly %d", allowed, wantLeft)
	}
	// Debt repays by waiting: one second refills exactly the rate.
	now = now.Add(time.Second)
	allowed = 0
	for i := 0; i < snmpServeRatePerSource+10; i++ {
		if b.allow(src) {
			allowed++
		}
	}
	if allowed != snmpServeRatePerSource {
		t.Fatalf("after 1s refilled %d, want exactly %d", allowed, snmpServeRatePerSource)
	}
	// Sheds: (200-74) past-charge + 10 past-refill.
	if got, want := b.shed.Load(), uint64(126+10); got != want {
		t.Fatalf("shed = %d, want %d", got, want)
	}
}

// TestServeBudgetGlobalBackstop9917 pins the aggregate budget: distinct sources
// with full per-source buckets drain only the shared global bucket, which
// sheds past its burst and refills at its rate. Frozen clock, exact counts.
func TestServeBudgetGlobalBackstop9917(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := newSNMPServeBudget()
	b.now = func() time.Time { return now }

	for i := 0; i < snmpServeGlobalBurst; i++ {
		ip := net.ParseIP(fmt.Sprintf("10.3.%d.%d", i/256, i%256))
		if !b.allow(ip) {
			t.Fatalf("distinct source %d denied with global room left", i)
		}
	}
	if b.allow(net.ParseIP("10.4.0.1")) {
		t.Fatalf("request past global burst %d admitted", snmpServeGlobalBurst)
	}
	now = now.Add(time.Second)
	allowed := 0
	for i := 0; i < snmpServeGlobalRate+10; i++ {
		if b.allow(net.ParseIP(fmt.Sprintf("10.5.%d.%d", i/256, i%256))) {
			allowed++
		}
	}
	if allowed != snmpServeGlobalRate {
		t.Fatalf("after 1s globally refilled %d, want exactly %d", allowed, snmpServeGlobalRate)
	}
}

// TestServeBudgetFullTableAdmitsNewcomer9917 is the table-fill exclusion cell:
// 1024 spoofed sources fill the table and keep every entry refreshed, yet a
// legitimate newcomer is STILL admitted (displacing a random incumbent) -- no
// refreshed set can lock it out, and the table stays bounded.
func TestServeBudgetFullTableAdmitsNewcomer9917(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := newSNMPServeBudget()
	b.now = func() time.Time { return now }

	addrs := make([]net.IP, snmpServeMaxSources)
	for i := range addrs {
		addrs[i] = net.ParseIP(fmt.Sprintf("10.1.%d.%d", i/256, i%256))
		if !b.allow(addrs[i]) {
			t.Fatalf("fill %d denied before the table is full", i)
		}
	}
	// Attacker refresh round: every entry touched again (defeats any idle
	// scheme, and must not defeat displacement either).
	for _, ip := range addrs {
		if !b.allow(ip) {
			t.Fatal("refresh denied while the table holds (precondition)")
		}
	}
	if !b.allow(net.ParseIP("10.2.0.1")) {
		t.Fatal("legitimate newcomer shed past a refreshed-full table (lock-out)")
	}
	for _, ip := range addrs {
		b.allow(ip)
	}
	if !b.allow(net.ParseIP("10.2.0.2")) {
		t.Fatal("second newcomer shed after another refresh round (lock-out)")
	}
	b.mu.Lock()
	n := len(b.perSource)
	b.mu.Unlock()
	if n != snmpServeMaxSources {
		t.Fatalf("table holds %d entries, want exactly %d (bounded)", n, snmpServeMaxSources)
	}
}

// TestServeBudgetNilAllow9917 pins the bypass rules: a nil budget (bare-struct
// agents), a nil IP, and an unparseable IP all allow.
func TestServeBudgetNilAllow9917(t *testing.T) {
	var nilBudget *snmpServeBudget
	if !nilBudget.allow(net.ParseIP("10.0.0.9")) {
		t.Fatal("nil budget denied (bare-struct agents must stay unbudgeted)")
	}
	// Nil-budget clock/account are safe no-ops for the Serve call site.
	_ = nilBudget.clock()
	nilBudget.account(net.ParseIP("10.0.0.9"), time.Second)
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
