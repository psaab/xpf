package cluster

// #18752: an unpaid cold prime refuses every demotion of this node's RGs, and
// before this the refusal said only "cold prime owed without pending outbound
// bulk" — for three and a half minutes on udp, with no sign of how long it had
// been owed or why every re-drive failed. ColdPrimeDebtDetail names both. It is
// display only: none of these cells changes what the barrier admits.

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestColdPrimeDebtDetailNamesAgeAndLastBulkError18752(t *testing.T) {
	ss := dualSync9508(t)
	if got := ss.ColdPrimeDebtDetail(); got != "" {
		t.Fatalf("no debt owed, but detail = %q", got)
	}
	c := newHeldConn9508("fab0")
	if d := ss.installConn(0, c); !d.shouldColdPrime || !ss.needColdPrime.Load() {
		t.Fatalf("FIXTURE: the first install must arm the cold prime (%+v)", d)
	}
	armedAt := ss.coldPrimeOwedSince.Load()
	if armedAt == 0 {
		t.Fatal("arming the debt did not stamp when it became owed")
	}
	got := ss.ColdPrimeDebtDetail()
	if !strings.Contains(got, "owed for ") || !strings.Contains(got, "last bulk error: none recorded") ||
		!strings.Contains(got, "clears when a bulk re-drive") {
		t.Fatalf("detail before any bulk failure = %q", got)
	}

	ss.noteBulkResult(errors.New("owner-RG export busy (window 2 open); retry with backoff"))
	if got := ss.ColdPrimeDebtDetail(); !strings.Contains(got, "last bulk error: owner-RG export busy (window 2 open)") {
		t.Fatalf("detail after a failed re-drive = %q, want the failure named", got)
	}
	ss.noteBulkResult(nil)
	if got := ss.ColdPrimeDebtDetail(); !strings.Contains(got, "owner-RG export busy") {
		t.Fatalf("a successful send cleared the failure before the peer acked it: %q", got)
	}

	// A re-arm while the debt is already owed keeps the original stamp: the
	// operator is told how long failbacks have been refused, not how long
	// since the last arm.
	ss.coldPrimeOwedSince.Store(time.Now().Add(-90 * time.Second).UnixNano())
	ss.mu.Lock()
	ss.armColdPrimeLocked()
	gen := ss.coldPrimeGen.Load()
	ss.mu.Unlock()
	if got := ss.ColdPrimeDebtDetail(); !strings.Contains(got, "owed for 1m3") {
		t.Fatalf("a re-arm reset the owed-since stamp: %q", got)
	}

	ss.dischargeColdPrime(gen)
	if got := ss.ColdPrimeDebtDetail(); got != "" {
		t.Fatalf("discharged debt still described: %q", got)
	}
	if ss.coldPrimeOwedSince.Load() != 0 || ss.lastBulkFailure.Load() != nil {
		t.Fatal("discharge left the owed-since stamp or the last failure behind")
	}
}

// doBulkSync's own failure is what the detail reports: a table-truth source
// error (the #18752 shape) is recorded without any caller doing it.
func TestDoBulkSyncFailureIsRecordedForTheDebtDetail18752(t *testing.T) {
	ss := dualSync9508(t)
	c := newHeldConn9508("fab0")
	ss.installConn(0, c)
	ss.BulkSnapshotSource = func() (BulkSnapshot, error) {
		return BulkSnapshot{}, errors.New("export owner-RG sessions: owner-RG export busy (window 7 open); retry with backoff")
	}
	if err := ss.doBulkSync(); err == nil {
		t.Fatal("FIXTURE: a failing snapshot source must fail the bulk")
	}
	if got := ss.ColdPrimeDebtDetail(); !strings.Contains(got, "owner-RG export busy (window 7 open)") {
		t.Fatalf("detail after a failed doBulkSync = %q", got)
	}
}
