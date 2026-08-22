// Package daemon implements the xpf daemon lifecycle.
//
// This file implements D3 RSS indirection persistence (issue #785).
//
// For mlx5_core-driven interfaces that will be bound to userspace-dp with
// N workers, we reshape the hardware RSS indirection table so that hash
// outputs land only on queues 0..N-1. Queues N..RX_count-1 are weighted 0
// and never receive traffic. This avoids the wasted kernel-fallback path
// on queues that no userspace worker consumes.
//
// Why a sibling file to linksetup.go (not inline): the weight-vector
// computation is a pure function with several edge cases that deserve
// their own unit tests; keeping it here lets the tests live beside the
// logic without bloating linksetup.go, which already owns PCI enumeration
// and .link-file management.
//
// Applied strictly before any AF_XDP socket binding opens an RX ring on
// first boot — driven from enumerateAndRenameInterfaces() at daemon
// startup. The reviewer's #M4 concern (no mid-traffic re-hash) is
// addressed by call ordering: this runs from Run() before the dataplane
// is loaded, so RX rings do not yet exist.
//
// Re-applied from the daemon reconcile path (applyConfig) on every
// commit, so changes to `system dataplane workers` or the
// `rss-indirection enable|disable` knob take effect without a restart.
// Re-application is idempotent (matching tables skip the write) and
// strictly per-mlx5 (driver-guarded at both the top-level scan and the
// per-interface call site).
package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// mlx5Driver is the sysfs driver name we detect D3-eligible NICs by.
	// Non-mlx5 drivers are skipped silently — xpf must still bring up
	// virtio, i40e, etc. unchanged. D3 is an optimization, not a
	// correctness requirement.
	mlx5Driver = "mlx5_core"
)

// rssExecutor abstracts ethtool invocation and sysfs enumeration so unit
// tests can inject a fake without touching the real binary or real sysfs.
// Real callers use realRSSExecutor.
type rssExecutor interface {
	// runEthtool runs `ethtool <args...>` and returns combined output + err.
	// On ErrNotFound (binary missing), callers treat it as non-fatal.
	runEthtool(args ...string) ([]byte, error)
	// readDriver returns the sysfs driver name for iface (basename of
	// /sys/class/net/<iface>/device/driver), or "" if not a PCI NIC.
	readDriver(iface string) string
	// readQueueCount returns the number of RX queues for iface, as
	// enumerated from /sys/class/net/<iface>/queues/rx-*. A non-nil error
	// means the count is UNKNOWN — distinct from a successful read of zero
	// queues (#5250 A7-b2 F2); callers must not treat the two alike.
	readQueueCount(iface string) (int, error)
	// listInterfaces returns the set of netdev names to consider (real
	// sysfs: basenames of /sys/class/net). Injection point for tests so
	// the top-level scan path is exercised without touching real netdevs.
	listInterfaces() []string
}

// realRSSExecutor is the production implementation of rssExecutor.
type realRSSExecutor struct{}

func (realRSSExecutor) runEthtool(args ...string) ([]byte, error) {
	// Timeout-bounded (#1794/#1800 U3, AGY r2): reapplyRSSIndirection runs
	// on the config-apply path (daemon_apply.go) under applySem, so a
	// wedged ethtool (mlx5 indirection-table ioctl stall) would hang every
	// commit. Error-wrapping contract of this executor seam is unchanged.
	return runCommandTimeout("ethtool", args...)
}

func (realRSSExecutor) readDriver(iface string) string {
	link, err := os.Readlink(filepath.Join("/sys/class/net", iface, "device", "driver"))
	if err != nil {
		return ""
	}
	return filepath.Base(link)
}

func (realRSSExecutor) readQueueCount(iface string) (int, error) {
	entries, err := os.ReadDir(filepath.Join("/sys/class/net", iface, "queues"))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "rx-") {
			n++
		}
	}
	return n, nil
}

func (realRSSExecutor) listInterfaces() []string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// applyRSSIndirection reshapes the RSS indirection table on mlx5_core
// interfaces that are actually bound to the userspace dataplane so that
// only queues 0..workers-1 receive traffic.
//
// Invariants:
//   - Runs at daemon startup (and on reconcile for worker-count changes),
//     before the dataplane binds any AF_XDP socket on startup.
//   - `allowed` is the userspace-dp binding allowlist — the authoritative
//     set of Linux interface names that AF_XDP will bind. Only members
//     of that set are ever considered, and every member is still passed
//     through the mlx5 driver guard. An empty allowlist is treated as
//     "no interfaces to touch" (no-op) — never a fall-back to scanning
//     every netdev. Review finding Codex H1.
//   - Non-mlx5 interfaces in the allowlist are skipped — `ethtool` is
//     never invoked on virtio, iavf, i40e, etc. The driver-guard is
//     also repeated inside applyRSSIndirectionOne as defense in depth.
//   - enabled == false is a hard kill switch: restore the default
//     indirection table on every allowlisted mlx5 interface.
//   - workers == 1: no weight vector is applied (single worker benefits
//     from default RSS spreading across all HW queues / IRQ lines;
//     weight-pinning to a single queue would serialize the worker on one
//     IRQ — reviewer #L1). BUT the allowlist is still walked so the live
//     table is probed and reset to default if it carries a stale
//     concentrated layout left over from a prior workers < queue_count
//     apply — a day-2 workers→1 reduction must not leave RX hashed onto
//     the old subset of queues (#5124).
//   - workers >= queue_count: weight reshaping is skipped (default
//     table already delivers to every queue), BUT the live table is
//     probed and reset to default if it carries a stale concentrated
//     layout left over from a prior workers < queue_count apply (#805).
//   - Idempotent: if the live indirection table already matches the
//     computed layout, no write is issued.
//   - Never returns a non-nil error — D3 regressions must not break
//     interface bring-up.
func applyRSSIndirection(enabled bool, workers int, allowed []string, execer rssExecutor) {
	if !enabled {
		// Kill switch. Actively restore default (equal-weight) RSS on
		// every allowlisted mlx5 interface so toggling disable at
		// runtime reverts the table without a daemon restart.
		// Idempotent: restoring an already-default table is a no-op
		// ethtool call. The restore is scoped per-interface with the
		// same driver filter as the apply path, so non-mlx5 netdevs
		// and non-userspace-dp interfaces are never touched.
		restoreDefaultRSSIndirection(allowed, execer)
		slog.Info("linksetup: rss indirection disabled by config",
			"allowed_count", len(allowed))
		return
	}
	if workers <= 0 {
		// Non-userspace deploys (ebpf/dpdk) hit this path every boot —
		// keep at Debug to avoid info-level noise on the default path.
		slog.Debug("linksetup: rss indirection skipped (no workers configured)")
		return
	}
	if workers == 1 {
		// Single worker keeps default RSS: no weight vector is applied
		// (pinning to queue 0 would serialize the worker on one IRQ).
		// We do NOT return here — the allowlist loop below still runs so
		// a stale concentrated table left by a prior workers<queues apply
		// is probed and restored to the NIC default on a workers→1
		// reduction (#5124). computeWeightVector(1, queues) returns nil,
		// so applyRSSIndirectionOne issues at most one `ethtool -x` probe
		// plus, only when the live table is concentrated, one
		// `ethtool -X default` restore. A fresh default table is a no-op.
		slog.Debug("linksetup: rss single worker — keep default RSS, probe for stale concentrated table")
	}
	if len(allowed) == 0 {
		// No userspace-dp bindings derived from config — nothing to
		// reshape. This is distinct from "listInterfaces returned
		// nothing": an empty allowlist means the compiled config has
		// no userspace-dp-bound mlx5 interfaces (e.g. management-only
		// deploy), not a sysfs error.
		slog.Debug("linksetup: rss indirection skipped (no userspace-dp bound interfaces)",
			"workers", workers)
		return
	}

	for _, iface := range allowed {
		if iface == "lo" {
			continue
		}
		drv := execer.readDriver(iface)
		if drv != mlx5Driver {
			// Allowlist can legitimately include non-mlx5 interfaces
			// (virtio/iavf/i40e that userspace-dp binds on); skip
			// silently at the driver guard. Codex H1: never invoke
			// ethtool on a non-mlx5 netdev.
			slog.Debug("linksetup: rss indirection skipped (non-mlx5 driver)",
				"iface", iface, "driver", drv)
			continue
		}
		applyRSSIndirectionOne(iface, workers, execer)
	}
}

// restoreDefaultRSSIndirection is called when the kill switch is engaged.
// Runs `ethtool -X <iface> default` on every allowlisted mlx5 interface so
// the kernel reverts to equal-weight RSS across all HW queues. Idempotent
// (already-default is a no-op). Non-mlx5 interfaces are filtered out at
// the call site, mirroring applyRSSIndirection's guard. An empty allowlist
// is a no-op: the restore path must not escape the userspace-dp binding
// scope (Codex H1).
func restoreDefaultRSSIndirection(allowed []string, execer rssExecutor) {
	if len(allowed) == 0 {
		return
	}
	for _, iface := range allowed {
		if iface == "lo" {
			continue
		}
		if execer.readDriver(iface) != mlx5Driver {
			continue
		}
		out, err := execer.runEthtool("-X", iface, "default")
		if err != nil {
			if isExecNotFound(err) {
				slog.Warn("linksetup: ethtool binary not found, cannot restore default rss indirection",
					"iface", iface)
				return
			}
			slog.Warn("linksetup: ethtool -X default failed",
				"iface", iface, "err", err,
				"output", strings.TrimSpace(string(out)))
			continue
		}
		slog.Info("linksetup: restored default rss indirection", "iface", iface)
	}
}

// applyRSSIndirectionOne applies the weight-vector to a single mlx5 iface.
// Errors are logged and swallowed: D3 is best-effort.
//
// The caller (applyRSSIndirection) is responsible for driver filtering;
// this function additionally re-checks the driver as defense in depth so a
// future caller cannot accidentally invoke ethtool on a non-mlx5 netdev.
func applyRSSIndirectionOne(iface string, workers int, execer rssExecutor) {
	if drv := execer.readDriver(iface); drv != mlx5Driver {
		slog.Debug("linksetup: rss indirection skipped (non-mlx5 driver at per-iface check)",
			"iface", iface, "driver", drv)
		return
	}
	queues, err := execer.readQueueCount(iface)
	if err != nil {
		// #5250 (A7-b2 F2): a sysfs enumeration failure used to be laundered
		// into queues=0, which walks the "no weight vector" branch below and
		// then FAILS its `queues > 1` restore guard — so a concentrated
		// `[1,..,1,0,..,0]` table written by an earlier apply stayed live with
		// nothing logged above Info. The count is UNKNOWN here, not zero: we
		// cannot compute a weight vector and cannot compare against the
		// default layout either (indirectionTableIsDefault needs the count),
		// so restore the kernel default unconditionally for a real worker
		// configuration. `ethtool -X <iface> default` is idempotent and is
		// exactly what the kill switch already issues, so the fallback cannot
		// leave the NIC in a worse state than the stale table it replaces.
		slog.Warn("linksetup: rx queue count unreadable, restoring default rss indirection",
			"iface", iface, "workers", workers, "err", err)
		if workers >= 1 {
			if out, rerr := execer.runEthtool("-X", iface, "default"); rerr != nil {
				if isExecNotFound(rerr) {
					slog.Warn("linksetup: ethtool binary not found, cannot restore default rss indirection",
						"iface", iface)
					return
				}
				slog.Warn("linksetup: ethtool -X default failed",
					"iface", iface, "err", rerr,
					"output", strings.TrimSpace(string(out)))
			}
		}
		return
	}
	weights, reason := computeWeightVector(workers, queues)
	if weights == nil {
		slog.Info("linksetup: rss weight reshaping skipped", "iface", iface,
			"workers", workers, "queues", queues, "reason", reason)
		// #805/#5124: When no weight vector is applied — either
		// workers >= queues (#805) OR workers == 1 (#5124) — we
		// previously left the indirection table alone. That's correct on
		// a fresh install (kernel default is round-robin = what we want)
		// but wrong on any transition DOWN from a concentrated table: a
		// `[1,...,1,0,...,0]` table written by an earlier
		// applyRSSIndirectionOne for the prior worker count stays live
		// and starves queues that no worker consumes (workers→1: RX stays
		// hashed onto the old subset even though single-worker policy is
		// default RSS across all queues; workers>=queues: queues that now
		// host worker-bound AF_XDP sockets get no traffic). Inspect the
		// live table; if it isn't the round-robin default, restore it.
		//
		// Guard: queues > 1 (a single-queue NIC has no possible
		// concentration to undo — default and any "configured" layout
		// both have entry[i] == 0 for every i), and workers >= 1 (a real
		// worker configuration where default RSS is the desired state;
		// workers <= 0 is a non-userspace deploy filtered by the caller,
		// and restoring its table would be out of scope).
		if workers >= 1 && queues > 1 {
			maybeRestoreDefault(iface, queues, execer)
		}
		return
	}

	// Idempotency: read the live table; skip the write if it already
	// matches the target layout. Avoids kernel log noise on repeated
	// daemon restarts and avoids spurious NIC churn during reconcile.
	out, err := execer.runEthtool("-x", iface)
	if err != nil {
		// ethtool missing / unsupported → best-effort skip.
		if isExecNotFound(err) {
			slog.Warn("linksetup: ethtool binary not found, skipping rss indirection",
				"iface", iface)
			return
		}
		slog.Warn("linksetup: ethtool -x failed, skipping rss indirection",
			"iface", iface, "err", err,
			"output", strings.TrimSpace(string(out)))
		return
	}
	if indirectionTableMatches(out, weights) {
		slog.Debug("linksetup: rss indirection unchanged", "iface", iface)
		return
	}

	args := []string{"-X", iface, "weight"}
	for _, w := range weights {
		args = append(args, strconv.Itoa(w))
	}
	if out, err := execer.runEthtool(args...); err != nil {
		if isExecNotFound(err) {
			slog.Warn("linksetup: ethtool binary not found, rss indirection not applied",
				"iface", iface)
			return
		}
		slog.Warn("linksetup: ethtool -X failed",
			"iface", iface, "weights", weights, "err", err,
			"output", strings.TrimSpace(string(out)))
		return
	}
	slog.Info("linksetup: applied rss indirection",
		"iface", iface, "workers", workers, "queues", len(weights),
		"weights", weights)
}

// maybeRestoreDefault reads the live RSS indirection table and, if it
// is not the kernel's default round-robin shape, runs
// `ethtool -X <iface> default` to restore it. Used on the
// workers >= queues skip path (#805) to undo a concentrated table
// left behind by a prior workers < queues apply when the operator
// has since increased the worker count to match queue count.
//
// Best-effort: ethtool probe failures are logged and skipped without
// attempting a write, mirroring the apply path's error handling.
func maybeRestoreDefault(iface string, queues int, execer rssExecutor) {
	out, err := execer.runEthtool("-x", iface)
	if err != nil {
		if isExecNotFound(err) {
			slog.Warn("linksetup: ethtool binary not found, cannot probe for default rss indirection",
				"iface", iface)
			return
		}
		slog.Warn("linksetup: ethtool -x failed, cannot probe for default rss indirection",
			"iface", iface, "err", err,
			"output", strings.TrimSpace(string(out)))
		return
	}
	if indirectionTableIsDefault(out, queues) {
		slog.Debug("linksetup: rss indirection already default, no restore needed",
			"iface", iface)
		return
	}
	if out, err := execer.runEthtool("-X", iface, "default"); err != nil {
		if isExecNotFound(err) {
			slog.Warn("linksetup: ethtool binary not found, cannot restore default rss indirection",
				"iface", iface)
			return
		}
		slog.Warn("linksetup: ethtool -X default failed",
			"iface", iface, "err", err,
			"output", strings.TrimSpace(string(out)))
		return
	}
	slog.Info("linksetup: restored default round-robin rss indirection",
		"iface", iface,
		"reason", "workers>=queues with stale constrained table")
}

// indirectionRow is one parsed data row of the `ethtool -x` RSS
// indirection table: the printed row index (the value before the colon,
// e.g. 0, 8, 16 for an 8-column dump) and the queue indices that follow
// it, in column order.
type indirectionRow struct {
	idx     int
	entries []int
}

// parseIndirectionTable extracts the indirection-table data rows from
// `ethtool -x <iface>` output. Each row carries its printed index and the
// queue entries in column order.
//
// The scan is bounded to the indirection-table section and STOPS at the
// "RSS hash key:" (or "RSS hash function:") header. This bound is
// load-bearing (#3954): the hash-key line that follows the table is
// colon-separated hex, e.g.
//
//	RSS hash key:
//	09:5c:8e:3a:7f:...
//
// When the first key byte is a decimal-looking hex value — 0x00-0x09,
// 0x10-0x19, ..., 0x90-0x99, i.e. both nibbles in 0-9 (100 of 256 byte
// values, ~39% of randomly generated keys) — strconv.Atoi("09") succeeds,
// so without this bound the key line is misread as indirection row "9"
// whose remaining hex bytes ("5c", "8e", ...) then fail to parse. That
// produced a spurious "current != desired" verdict on ~39% of boots and an
// unnecessary `ethtool -X` rewrite mid-traffic, re-steering in-flight flows
// to different RX queues (and, on the AF_XDP path, forcing a queue rebind).
//
// A second, order-independent guard rejects any candidate row whose
// post-colon remainder still contains a colon: real indirection rows carry
// only whitespace-separated integers after the row index, whereas the
// hash-key line is ":"-separated hex. This defends the misparse even if a
// future ethtool reorders its output sections.
//
// ok is false when an in-section row carried a non-integer queue token (a
// genuinely unparseable table); callers treat that as "cannot confirm the
// desired layout" and fall through to a rewrite.
func parseIndirectionTable(output []byte) (rows []indirectionRow, ok bool) {
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		// Everything from the "RSS hash key" / "RSS hash function" header
		// onward is colon-separated hex or key:value pairs, not table
		// rows — stop here so the hash-key line is never parsed (#3954).
		if len(trimmed) >= 8 && bytes.EqualFold(trimmed[:8], []byte("RSS hash")) {
			break
		}
		colon := bytes.IndexByte(trimmed, ':')
		if colon <= 0 {
			continue
		}
		rowIdx, err := strconv.Atoi(string(trimmed[:colon]))
		if err != nil {
			continue
		}
		remainder := trimmed[colon+1:]
		// A real indirection row has only whitespace-separated integers
		// after the colon; the hash-key line has further colons. Reject
		// any remainder that still contains a colon (#3954, belt-and-braces
		// so the fix holds regardless of ethtool section ordering).
		if bytes.IndexByte(remainder, ':') >= 0 {
			continue
		}
		row := indirectionRow{idx: rowIdx}
		for _, tok := range bytes.Fields(remainder) {
			q, err := strconv.Atoi(string(tok))
			if err != nil {
				return rows, false
			}
			row.entries = append(row.entries, q)
		}
		rows = append(rows, row)
	}
	return rows, true
}

// indirectionTableIsDefault reports true iff the live `ethtool -x`
// output describes a round-robin indirection table where
// entry[i] == i mod queueCount. This is the exact shape mlx5
// produces on `ethtool -X iface default` (verified live on the
// loss:xpf-userspace-fw0 cluster, 6-queue ge-0-0-2).
//
// Stricter than indirectionTableMatches: rejects any custom table
// that uses every queue at least once but doesn't match the
// round-robin pattern.
//
// Returns false on empty/unparseable input, or on any row whose
// entries don't all match the expected (rowIdx + j) % queueCount
// position. Returns true only when at least one entry has been
// successfully parsed AND verified.
func indirectionTableIsDefault(output []byte, queueCount int) bool {
	if queueCount <= 0 {
		return false
	}
	rows, ok := parseIndirectionTable(output)
	if !ok {
		return false
	}
	sawAnyEntry := false
	for _, row := range rows {
		for j, q := range row.entries {
			expected := (row.idx + j) % queueCount
			if q != expected {
				return false
			}
			sawAnyEntry = true
		}
	}
	return sawAnyEntry
}

// computeWeightVector returns the weight vector for the given worker and
// queue counts, or nil if D3 should skip this interface. The second return
// value is a human-readable skip reason (empty if a vector was produced).
//
// Cases:
//   - workers <= 0 or queues <= 0: skip (misconfigured).
//   - workers == 1: skip (single worker — keep default RSS spreading load
//     across all HW queues / IRQ lines; pinning to queue 0 would serialize
//     the worker on one IRQ).
//   - workers >= queues: skip (default table already delivers to every
//     queue; no reshaping possible or useful).
//   - workers < queues: produce `[1]*workers + [0]*(queues - workers)`.
func computeWeightVector(workers, queues int) ([]int, string) {
	if workers <= 0 {
		return nil, "workers <= 0"
	}
	if queues <= 0 {
		return nil, "queue count unknown"
	}
	if workers == 1 {
		return nil, "workers == 1 (keep default RSS)"
	}
	if workers >= queues {
		return nil, fmt.Sprintf("workers (%d) >= queues (%d)", workers, queues)
	}
	v := make([]int, queues)
	for i := 0; i < workers; i++ {
		v[i] = 1
	}
	return v, ""
}

// indirectionTableMatches returns true if the live `ethtool -x` output
// already describes a table that only uses queues 0..(activeCount-1),
// where activeCount is the number of non-zero weights. The table layout
// for an mlx5 NIC with weight [1 1 1 1 0 0] looks like:
//
//	RX flow hash indirection table for eth0 with 6 RX ring(s):
//	    0:      0     1     2     3     0     1
//	    8:      2     3     0     1     2     3
//	...
//
// i.e. no queue index >= activeCount appears. We conservatively treat any
// appearance of a queue >= activeCount as a mismatch so the reapply goes
// through. Parsing is delegated to parseIndirectionTable, which bounds the
// scan to the indirection-table section so the trailing "RSS hash key:"
// line is never misread as a table row (#3954).
func indirectionTableMatches(output []byte, weights []int) bool {
	if len(weights) == 0 {
		return false
	}
	active := 0
	for _, w := range weights {
		if w > 0 {
			active++
		}
	}
	if active == 0 {
		return false
	}

	// Parse only the indirection-table rows (parseIndirectionTable stops
	// at the "RSS hash key:" section so a decimal-looking key byte cannot
	// be misread as a table row — #3954).
	rows, ok := parseIndirectionTable(output)
	if !ok {
		return false
	}
	if len(rows) == 0 {
		return false
	}
	// Track which of the active queues actually appear. A queue index >=
	// active (or negative) is an immediate mismatch (the table spreads onto
	// a queue no worker owns); everything else marks coverage.
	seen := make([]bool, active)
	for _, row := range rows {
		for _, q := range row.entries {
			if q < 0 || q >= active {
				return false
			}
			seen[q] = true
		}
	}
	// #5328 (A7-b2-F10): a table that uses only a SUBSET of the active
	// queues (e.g. a stale/driver-reset table pinned to queue 0 while N
	// workers are configured) must NOT be treated as converged. Every
	// active queue 0..active-1 must appear; otherwise applyRSSIndirectionOne
	// would skip the `ethtool -X ... weight` reprogram and leave the workers
	// bound to the absent queues idle (one queue/CPU overloaded).
	for _, covered := range seen {
		if !covered {
			return false
		}
	}
	return true
}

// isExecNotFound returns true if err indicates the ethtool binary is
// missing. `exec.Command("ethtool").CombinedOutput()` wraps the stable
// `exec.ErrNotFound` sentinel in an *exec.Error, so errors.Is is the
// correct mechanism — no substring matching required.
func isExecNotFound(err error) bool {
	return errors.Is(err, exec.ErrNotFound)
}
