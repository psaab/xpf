package cluster

// #18752: an unpaid cold prime refuses every demotion of this node's RGs, and
// before this the refusal said only "cold prime owed without pending outbound
// bulk" — for three and a half minutes on udp, with no sign of how long it had
// been owed or why every re-drive failed. ColdPrimeDebtDetail names both. It is
// display only: none of these cells changes what the barrier admits.

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"sync"
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

// logSink18752 is a goroutine-safe slog sink: the sync fixtures run reader
// goroutines that may log while a cell inspects the buffer.
type logSink18752 struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logSink18752) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logSink18752) count(level, substr string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, l := range strings.Split(b.buf.String(), "\n") {
		if strings.Contains(l, "level="+level) && strings.Contains(l, substr) {
			n++
		}
	}
	return n
}

const longOwedMsg18752 = "cold prime owed to peer past the long-owed threshold"

// The long-owed Warn is the only unprompted sign that every failback and ISSU
// drain of this node's RGs is being refused. It must fire once per debt
// episode past the threshold — not before it, not on every sweep tick after
// it, not while a bulk that could pay the debt is still in flight — and fire
// again for a new episode.
func TestLongOwedColdPrimeWarnsOncePerEpisode18752(t *testing.T) {
	logs := &logSink18752{}
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))

	ss := dualSync9508(t)
	if ss.maybeWarnLongOwedColdPrime(time.Now().Add(time.Hour)) {
		t.Fatal("warned with no debt owed")
	}
	ss.installConn(0, newHeldConn9508("fab0"))
	armed := time.Unix(0, ss.coldPrimeOwedSince.Load())
	if armed.Unix() == 0 {
		t.Fatal("FIXTURE: the install did not arm the debt")
	}
	ss.noteBulkResult(errors.New("owner-RG export busy (window 3 open); retry with backoff"))

	if ss.maybeWarnLongOwedColdPrime(armed.Add(coldPrimeLongOwedAfter - time.Second)) {
		t.Fatal("warned before the long-owed threshold")
	}

	// A bulk that would pay this debt is in flight: the barrier is not
	// refusing for an unpaid prime, so neither is this Warn.
	ss.pendingBulkOwed.Store(ss.coldPrimeOwedGenAtomic())
	ss.pendingBulkAckEpoch.Store(5)
	ss.pendingBulkAckSince.Store(MonotonicNanos())
	if ss.maybeWarnLongOwedColdPrime(armed.Add(2 * coldPrimeLongOwedAfter)) {
		t.Fatal("warned while a bulk paying the debt was still pending")
	}
	ss.clearPendingBulkAck()

	if !ss.maybeWarnLongOwedColdPrime(armed.Add(coldPrimeLongOwedAfter + time.Second)) {
		t.Fatal("did not warn past the long-owed threshold with no bulk pending")
	}
	if ss.maybeWarnLongOwedColdPrime(armed.Add(3 * coldPrimeLongOwedAfter)) {
		t.Fatal("warned twice in one debt episode; the sweep calls this every tick")
	}
	if n := logs.count("WARN", longOwedMsg18752); n != 1 {
		t.Fatalf("episode 1 logged %d long-owed Warn(s), want 1", n)
	}
	if n := logs.count("WARN", "owner-RG export busy (window 3 open)"); n != 1 {
		t.Fatalf("the Warn did not carry the last bulk error that keeps the debt unpaid")
	}

	// Discharge, then a new episode: it earns its own Warn.
	ss.dischargeColdPrime(ss.coldPrimeGen.Load())
	ss.mu.Lock()
	ss.armColdPrimeLocked()
	ss.mu.Unlock()
	rearmed := time.Unix(0, ss.coldPrimeOwedSince.Load())
	if !ss.maybeWarnLongOwedColdPrime(rearmed.Add(coldPrimeLongOwedAfter + time.Second)) {
		t.Fatal("a new debt episode did not warn again")
	}
	if n := logs.count("WARN", longOwedMsg18752); n != 2 {
		t.Fatalf("two episodes logged %d long-owed Warn(s), want 2", n)
	}
}

// `show chassis cluster information` must name the debt and what it blocks
// while the barrier is refusing for it, and say nothing once it is paid or
// while a paying bulk is pending.
func TestClusterInformationShowsColdPrimeDebt18752(t *testing.T) {
	ss := dualSync9508(t)
	m := NewManager(0, 22)
	m.SetSyncStats(ss)
	const owedLine = "Cold prime owed to peer (no bulk pending): owed for "
	const blocksLine = "Blocks: manual failover/failback and ISSU drain of this node's RGs"
	if info := m.FormatInformation(); strings.Contains(info, owedLine) || strings.Contains(info, blocksLine) {
		t.Fatalf("no debt owed, but the information output reports one:\n%s", info)
	}

	ss.installConn(0, newHeldConn9508("fab0"))
	ss.noteBulkResult(errors.New("generation changed during export window"))
	info := m.FormatInformation()
	if !strings.Contains(info, owedLine) || !strings.Contains(info, blocksLine) ||
		!strings.Contains(info, "last bulk error: generation changed during export window") {
		t.Fatalf("an unpaid cold prime is not rendered with its cause and what it blocks:\n%s", info)
	}

	ss.pendingBulkOwed.Store(ss.coldPrimeOwedGenAtomic())
	ss.pendingBulkAckEpoch.Store(5)
	ss.pendingBulkAckSince.Store(MonotonicNanos())
	if info := m.FormatInformation(); strings.Contains(info, owedLine) {
		t.Fatalf("a debt with its paying bulk pending was rendered as refusing:\n%s", info)
	}
	ss.clearPendingBulkAck()

	ss.dischargeColdPrime(ss.coldPrimeGen.Load())
	if info := m.FormatInformation(); strings.Contains(info, owedLine) || strings.Contains(info, blocksLine) {
		t.Fatalf("a paid debt is still rendered:\n%s", info)
	}
}

// The Warn is only useful if something calls it: the session-sync sweep does,
// every tick, before anything that needs a session table.
func TestSyncSweepRaisesTheLongOwedWarn18752(t *testing.T) {
	logs := &logSink18752{}
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))

	ss := dualSync9508(t)
	// The sweep skips a node with no primary predicate at all (standalone);
	// the daemon always installs one.
	ss.IsPrimaryFn = func() bool { return true }
	ss.installConn(0, newHeldConn9508("fab0"))
	ss.coldPrimeOwedSince.Store(time.Now().Add(-2 * coldPrimeLongOwedAfter).UnixNano())
	ss.syncSweep()
	ss.syncSweep()
	if n := logs.count("WARN", longOwedMsg18752); n != 1 {
		t.Fatalf("two sweeps over a long-owed debt logged %d Warn(s), want 1", n)
	}
}
