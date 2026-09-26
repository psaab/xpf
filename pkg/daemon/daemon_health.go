// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/bootstrapshow"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// Bootstrap-import outcome constants (#4184). Recorded once at boot by
// recordBootstrapImport and surfaced via /health, an event, and (#6496)
// `show system bootstrap-import` on the CLI + gRPC paths.
//
// These are ALIASES of the bootstrapshow vocabulary, not independent literals.
// The renderer maps each status to an operator-facing explanation and reports
// anything it does not recognise as unrecognised, so a status recorded here
// that the renderer was never taught would surface to the operator as
// "unrecognized status". Defining them as aliases makes that unreachable: the
// value written and the value rendered are the same constant.
const (
	// bootstrapImportOK: the text config and initial host credentials applied.
	bootstrapImportOK = bootstrapshow.StatusOK
	// bootstrapImportLoadedDB: an active config was already present in the DB;
	// no file import was attempted (normal steady-state boot).
	bootstrapImportLoadedDB = bootstrapshow.StatusLoadedDB
	// bootstrapImportNoConfig: no text config file present (factory/fresh
	// boot). Expected — NOT a failure and NOT health-degrading.
	bootstrapImportNoConfig = bootstrapshow.StatusNoConfig
	// bootstrapImportPending: text import succeeded; initial host-credential
	// reconciliation has not completed yet.
	bootstrapImportPending = bootstrapshow.StatusPending
	// bootstrapImportCredentialFailed: the text import succeeded, but
	// configured host credentials did not converge during the initial apply.
	bootstrapImportCredentialFailed = bootstrapshow.StatusCredentialFailed
	// bootstrapImportFailed: a text config file was present but could not be
	// read/parsed/committed (or was rejected by the device-map preflight).
	bootstrapImportFailed = bootstrapshow.StatusFailed
)

// BootstrapImport is a snapshot of the day-0 / bootstrap config-import
// outcome (#4184). Consumed by /health and `show system bootstrap-import`.
type BootstrapImport struct {
	Status  string // a bootstrapImport* constant ("" until recorded)
	Error   string // safe detail for a failed outcome
	UnixSec int64  // when the latest outcome transition was recorded
	// Failed is true for import or initial credential-apply failure. The
	// expected factory no-config state is NOT failed, so health stays healthy.
	Failed bool
}

// recordBootstrapImport stores the boot-time config-import outcome and, on a
// real failure, emits an event so the cause is observable beyond journald
// (#4184). Called exactly once during Run after the bootstrap decision.
func (d *Daemon) recordBootstrapImport(status, detail string) {
	d.bootstrapMu.Lock()
	d.bootstrapImportStatus = status
	d.bootstrapImportError = detail
	d.bootstrapImportUnixSec = time.Now().Unix()
	d.bootstrapMu.Unlock()

	if status != bootstrapImportFailed {
		return
	}
	// Emit a durable, in-band event so `monitor`/event-stream subscribers and
	// the ring buffer carry the cause — not just a one-shot journald WARN.
	if d.eventBuf != nil {
		d.eventBuf.Add(logging.EventRecord{
			Time:   time.Now(),
			Type:   "BOOTSTRAP_IMPORT_FAILED",
			Reason: detail,
		})
	}
}

// completeBootstrapCredentialApply finishes the day-0 status only while it is
// pending. The initial apply runs the same credential reconcilers used for
// later commits; retain a generic, secret-free error rather than copying their
// details (which can include submitted config text) into the status surface.
func (d *Daemon) completeBootstrapCredentialApply(err error) {
	d.bootstrapMu.Lock()
	defer d.bootstrapMu.Unlock()
	if d.bootstrapImportStatus != bootstrapImportPending {
		return
	}
	d.bootstrapImportUnixSec = time.Now().Unix()
	if err != nil {
		d.bootstrapImportStatus = bootstrapImportCredentialFailed
		d.bootstrapImportError = "host credential reconciliation failed; inspect the daemon journal"
		return
	}
	d.bootstrapImportStatus = bootstrapImportOK
	d.bootstrapImportError = ""
}

// BootstrapImportSnapshot returns the recorded day-0 / bootstrap import
// outcome for /health and operator-facing surfaces. Safe to call
// concurrently.
func (d *Daemon) BootstrapImportSnapshot() BootstrapImport {
	d.bootstrapMu.Lock()
	defer d.bootstrapMu.Unlock()
	return BootstrapImport{
		Status:  d.bootstrapImportStatus,
		Error:   d.bootstrapImportError,
		UnixSec: d.bootstrapImportUnixSec,
		Failed: d.bootstrapImportStatus == bootstrapImportFailed ||
			d.bootstrapImportStatus == bootstrapImportCredentialFailed,
	}
}

// bootstrapShowSnapshot converts the recorded outcome into the operator-facing
// shape (#6496). It exists as a named method rather than as a closure at each
// wiring site because there are TWO sites — the gRPC server config
// (daemon_run_servers.go) and the in-process CLI hook (daemon_run.go) — and a
// field silently dropped from one of two hand-copied conversions is exactly the
// divergence the shared renderer was introduced to prevent. One conversion,
// directly testable.
func (d *Daemon) bootstrapShowSnapshot() bootstrapshow.Snapshot {
	b := d.BootstrapImportSnapshot()
	return bootstrapshow.Snapshot{
		Status:  b.Status,
		Error:   b.Error,
		UnixSec: b.UnixSec,
		Failed:  b.Failed,
	}
}

// recordCompileFailure tracks a dataplane compile failure and emits an
// escalating log (#758). The first failure remains a single WARN;
// every Nth repeat re-emits at ERROR level so an operator tailing the
// journal sees the degraded state without needing to know the original
// failure text. A success clears the counter via recordCompileSuccess.
func (d *Daemon) recordCompileFailure(err error) {
	d.compileHealthMu.Lock()
	d.compileFailureCount++
	d.compileLastError = err.Error()
	d.compileLastErrorUnixSec = time.Now().Unix()
	count := d.compileFailureCount
	everOk := d.compileEverSucceeded
	d.compileHealthMu.Unlock()

	// First WARN fires on every failure — matches pre-#758 behaviour.
	// Escalate to ERROR on the 5th consecutive failure with no prior
	// success, and again every 10 failures thereafter, so a persistent
	// degraded state stays visible in the log without flooding.
	slog.Warn("failed to compile dataplane", "err", err, "attempt", count, "ever_ok", everOk)
	if !everOk && (count == 5 || (count > 5 && count%10 == 0)) {
		slog.Error("dataplane compile has failed repeatedly; forwarding path is degraded",
			"attempt", count, "err", err)
	}
}

// recordCompileSuccess clears compile failure state. The failure count
// is intentionally preserved as a monotonic "have we ever hit this"
// counter (exported via CompileHealthSnapshot), but the "ever ok" flag
// flips true so /health goes back to healthy.
func (d *Daemon) recordCompileSuccess() {
	d.compileHealthMu.Lock()
	d.compileEverSucceeded = true
	d.compileLastError = ""
	d.compileHealthMu.Unlock()
}

// CompileHealthSnapshot returns the current compile health for /health
// and operator-facing RPCs. Safe to call concurrently.
func (d *Daemon) CompileHealthSnapshot() CompileHealth {
	d.compileHealthMu.Lock()
	defer d.compileHealthMu.Unlock()
	return CompileHealth{
		EverSucceeded:    d.compileEverSucceeded,
		FailureCount:     d.compileFailureCount,
		LastError:        d.compileLastError,
		LastErrorUnixSec: d.compileLastErrorUnixSec,
	}
}

func (d *Daemon) shouldScheduleStandbyNeighborRefresh(now time.Time) bool {
	elapsed := now.Sub(d.startTime).Nanoseconds() + 1
	if elapsed < 1 {
		elapsed = 1
	}
	last := d.lastStandbyNeighborRefresh.Load()
	if last != 0 && elapsed >= last && elapsed-last < int64(standbyNeighborRefreshMinInterval) {
		return false
	}
	return d.lastStandbyNeighborRefresh.CompareAndSwap(last, elapsed)
}

func (d *Daemon) scheduleStandbyNeighborRefresh() {
	if d.cluster == nil || d.dataplane() == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	if !d.shouldScheduleStandbyNeighborRefresh(time.Now()) {
		return
	}
	go func(cfg *config.Config) {
		d.resolveNeighborsInner(cfg, false)
		d.maintainClusterNeighborReadiness()
	}(cfg)
}
