package cluster

import (
	"bytes"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

func captureStaleConfigWarnLog18649(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

type staleConfigWarnUnlockWriter18649 struct {
	ss                     *SessionSync
	logs                   bytes.Buffer
	warnings               int
	warnedWhileApplyMuHeld bool
}

func (w *staleConfigWarnUnlockWriter18649) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(staleConfigRefusalWarnMessage)) {
		w.warnings++
		if w.ss.applyMu.TryLock() {
			w.ss.applyMu.Unlock()
		} else {
			w.warnedWhileApplyMuHeld = true
		}
	}
	return w.logs.Write(p)
}

func captureStaleConfigWarnUnlockLog18649(t *testing.T, ss *SessionSync) *staleConfigWarnUnlockWriter18649 {
	t.Helper()
	logs := &staleConfigWarnUnlockWriter18649{ss: ss}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return logs
}

func pinStaleConfigWarnClock18649(t *testing.T, ss *SessionSync, start int64) *atomic.Int64 {
	t.Helper()
	now := &atomic.Int64{}
	now.Store(start)
	previous := ss.nowMonoFn
	ss.nowMonoFn = func() int64 { return now.Load() }
	t.Cleanup(func() { ss.nowMonoFn = previous })
	return now
}

func refuseStaleV4ConfigEpoch18649(t *testing.T, ss *SessionSync, port uint16, epoch uint64) {
	t.Helper()
	key := configEpochKeyV4(port)
	val := dataplane.SessionValue{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2, ConfigEpoch: epoch}
	if ss.installClusterSyncedV4(key, val) {
		t.Fatal("stale-config v4 install unexpectedly succeeded")
	}
}

func refuseStaleV6ConfigEpoch18649(t *testing.T, ss *SessionSync, port uint16, epoch uint64) {
	t.Helper()
	key := configEpochKeyV6(port)
	val := dataplane.SessionValueV6{State: dataplane.SessStateEstablished, IngressZone: 1, EgressZone: 2, ConfigEpoch: epoch}
	if ss.installClusterSyncedV6(key, val) {
		t.Fatal("stale-config v6 install unexpectedly succeeded")
	}
}

// The real v4/v6 install paths must emit on the first current-config refusal,
// suppress all additional growth during the minute, and emit again at the
// interval boundary. The Warn names the decoded epoch, threshold source, and
// authority branch; refusing installs and their counters remain unchanged.
func TestStaleConfigRefusalWarnTracksGrowthAndRateLimits18649(t *testing.T) {
	const start = int64(10_000_000_000)
	ss, dp := newAuthority18636(t, 100)
	logs := captureStaleConfigWarnLog18649(t)
	now := pinStaleConfigWarnClock18649(t, ss, start)
	epoch := configEpochReverseTag | 5

	refuseStaleV4ConfigEpoch18649(t, ss, 61849, epoch)
	if got := ss.stats.SessionsStaleConfigIgnored.Load(); got != 1 {
		t.Fatalf("refusal counter = %d after first refusal, want 1", got)
	}
	if len(dp.v4sessions) != 0 {
		t.Fatal("stale-config v4 install was not refused")
	}
	if got := strings.Count(logs.String(), staleConfigRefusalWarnMessage); got != 1 {
		t.Fatalf("first refusal emitted %d growth warnings, want 1; logs: %s", got, logs.String())
	}
	for _, want := range []string{
		"session_config_epoch=5",
		"session_config_epoch_tagged=true",
		"threshold=100",
		"threshold_kind=config_gen_counter",
		"branch=rg0-authority",
		"rg0_authority=true",
	} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("first warning lacks %q: %s", want, logs.String())
		}
	}

	// Constantly growing refusal volume does not re-warn inside the minute,
	// including across address families.
	now.Store(start + int64(30*time.Second))
	refuseStaleV6ConfigEpoch18649(t, ss, 61850, epoch)
	now.Store(start + int64(staleConfigRefusalWarnInterval) - 1)
	refuseStaleV4ConfigEpoch18649(t, ss, 61851, epoch)
	if got := strings.Count(logs.String(), staleConfigRefusalWarnMessage); got != 1 {
		t.Fatalf("in-window v4/v6 refusals emitted %d warnings, want 1", got)
	}
	if len(dp.v6sessions) != 0 || len(dp.v4sessions) != 0 {
		t.Fatal("stale-config refusal unexpectedly installed a session")
	}

	now.Store(start + int64(staleConfigRefusalWarnInterval))
	refuseStaleV6ConfigEpoch18649(t, ss, 61852, epoch)
	if got := strings.Count(logs.String(), staleConfigRefusalWarnMessage); got != 2 {
		t.Fatalf("growth at the one-minute boundary emitted %d warnings, want 2 total; logs: %s", got, logs.String())
	}
	if !strings.Contains(logs.String(), "suppressed_since_last=2") {
		t.Fatalf("second warning did not report the two in-window refusals: %s", logs.String())
	}
	if got := ss.stats.SessionsStaleConfigIgnored.Load(); got != 4 {
		t.Fatalf("refusal counter = %d, want 4 (the Warn limiter must not change counting)", got)
	}
}

// Refusal growth observed while readiness says config-stale must not warn or
// later be mistaken for fresh growth; the next refusal after readiness catches
// up is new growth and does warn.
func TestStaleConfigRefusalWarnRequiresCurrentLocalConfig18649(t *testing.T) {
	ss, _ := newAuthority18636(t, 100)
	logs := captureStaleConfigWarnLog18649(t)
	pinStaleConfigWarnClock18649(t, ss, 20_000_000_000)
	ss.lastRecvConfigGen.Store(50)
	ss.lastAppliedConfigGen.Store(10)
	if !ss.TransferReadiness().ConfigStale() {
		t.Fatal("fixture: readiness must report stale config")
	}

	epoch := configEpochReverseTag | 5
	refuseStaleV4ConfigEpoch18649(t, ss, 61853, epoch)
	if got := strings.Count(logs.String(), staleConfigRefusalWarnMessage); got != 0 {
		t.Fatalf("config-stale refusal emitted %d warnings, want 0", got)
	}

	ss.rejectedAsAuthorityConfigGen.Store(50)
	if ss.TransferReadiness().ConfigStale() {
		t.Fatal("fixture: authority's rejected config generation must keep readiness current")
	}
	refuseStaleV6ConfigEpoch18649(t, ss, 61854, epoch)
	if got := strings.Count(logs.String(), staleConfigRefusalWarnMessage); got != 1 {
		t.Fatalf("first growth while config is current emitted %d warnings, want 1; logs: %s", got, logs.String())
	}
	if got := ss.stats.SessionsStaleConfigIgnored.Load(); got != 2 {
		t.Fatalf("refusal counter = %d, want 2", got)
	}
}

// The non-authority branch compares an untagged peer epoch against the local
// apply barrier and reports that exact source in the Warn.
func TestStaleConfigRefusalWarnReportsLocalBarrier18649(t *testing.T) {
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.lastRecvConfigGen.Store(100)
	ss.lastAppliedConfigGen.Store(100)
	capture := captureStaleConfigWarnLog18649(t)
	pinStaleConfigWarnClock18649(t, ss, 30_000_000_000)

	refuseStaleV4ConfigEpoch18649(t, ss, 61855, 5)
	if got := strings.Count(capture.String(), staleConfigRefusalWarnMessage); got != 1 {
		t.Fatalf("non-authority refusal emitted %d warnings, want 1; logs: %s", got, capture.String())
	}
	for _, want := range []string{
		"session_config_epoch=5",
		"session_config_epoch_tagged=false",
		"threshold=100",
		"threshold_kind=last_applied_config_gen",
		"branch=local-config-barrier",
		"rg0_authority=false",
	} {
		if !strings.Contains(capture.String(), want) {
			t.Errorf("non-authority warning lacks %q: %s", want, capture.String())
		}
	}
}

// A warning needs a counter increase as well as an elapsed interval; a quiet
// minute alone must not re-emit the same growth.
func TestStaleConfigRefusalWarnRequiresCounterGrowth18649(t *testing.T) {
	const start = int64(40_000_000_000)
	ss := &SessionSync{}
	now := pinStaleConfigWarnClock18649(t, ss, start)
	ss.applyMu.Lock()
	defer ss.applyMu.Unlock()
	limiter := &ss.staleConfigRefusalWarn

	if emit, _ := limiter.admit(0, false, now.Load()); emit {
		t.Fatal("zero counter unexpectedly admitted a warning")
	}
	if emit, _ := limiter.admit(1, false, now.Load()); !emit {
		t.Fatal("first counter growth did not admit a warning")
	}
	now.Store(start + int64(staleConfigRefusalWarnInterval))
	if emit, _ := limiter.admit(1, false, now.Load()); emit {
		t.Fatal("elapsed interval without counter growth re-emitted a warning")
	}
	if emit, _ := limiter.admit(2, false, now.Load()); !emit {
		t.Fatal("new counter growth after the interval did not admit a warning")
	}
}

func TestStaleConfigRefusalWarnReportsLastSentThreshold18649(t *testing.T) {
	ss, _ := newAuthority18636(t, 50)
	ss.recordLastSentConfigGen(100)
	logs := captureStaleConfigWarnLog18649(t)
	pinStaleConfigWarnClock18649(t, ss, 50_000_000_000)

	refuseStaleV6ConfigEpoch18649(t, ss, 61856, configEpochReverseTag|5)
	for _, want := range []string{
		"session_config_epoch=5",
		"session_config_epoch_tagged=true",
		"threshold=100",
		"threshold_kind=last_sent_config_gen",
		"branch=rg0-authority",
		"rg0_authority=true",
	} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("authority warning lacks %q: %s", want, logs.String())
		}
	}
}

func TestStaleConfigRefusalWarnIncludesPostWriteRollback18649(t *testing.T) {
	const start = int64(60_000_000_000)
	dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
	ss := NewSessionSync(":0", "10.0.0.2:4785", dp)
	ss.IsPrimaryFn = func() bool { return false }
	ss.lastRecvConfigGen.Store(10)
	ss.lastAppliedConfigGen.Store(10)
	logs := captureStaleConfigWarnUnlockLog18649(t, ss)
	now := pinStaleConfigWarnClock18649(t, ss, start)

	// A direct refusal emits first. Subsequent post-write config changes create
	// rollback refusals that share the same counter and one-minute limiter.
	refuseStaleV4ConfigEpoch18649(t, ss, 61857, 5)
	if logs.warnings != 1 {
		t.Fatalf("direct refusal warnings = %d, want 1; logs: %s", logs.warnings, logs.logs.String())
	}

	dp.onSetV4 = func() {
		ss.lastRecvConfigGen.Store(10)
		ss.lastAppliedConfigGen.Store(10)
	}
	ss.lastRecvConfigGen.Store(5)
	ss.lastAppliedConfigGen.Store(5)
	now.Store(start + int64(30*time.Second))
	refuseStaleV4ConfigEpoch18649(t, ss, 61858, 5)
	if logs.warnings != 1 {
		t.Fatalf("in-window rollback refusal re-warned: warnings=%d logs=%s", logs.warnings, logs.logs.String())
	}

	ss.lastRecvConfigGen.Store(5)
	ss.lastAppliedConfigGen.Store(5)
	now.Store(start + int64(staleConfigRefusalWarnInterval))
	refuseStaleV4ConfigEpoch18649(t, ss, 61859, 5)
	if logs.warnings != 2 {
		t.Fatalf("post-window rollback growth warnings = %d, want 2; logs: %s", logs.warnings, logs.logs.String())
	}
	if logs.warnedWhileApplyMuHeld {
		t.Fatal("a rate-limited Warn reached the log sink while applyMu was held")
	}
	if !strings.Contains(logs.logs.String(), "suppressed_since_last=1") {
		t.Fatalf("post-window Warn did not include the suppressed rollback refusal: %s", logs.logs.String())
	}
	if len(dp.v4sessions) != 0 {
		t.Fatalf("post-write stale permits survived rollback: %d sessions", len(dp.v4sessions))
	}
	if got := ss.stats.SessionsStaleConfigIgnored.Load(); got != 3 {
		t.Fatalf("stale-config refusal count = %d, want 3 including two rollbacks", got)
	}
}
