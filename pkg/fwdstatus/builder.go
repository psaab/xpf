package fwdstatus

import (
	"time"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// userHZ is the kernel's scheduler tick frequency.  Every mainline
// kernel config we ship sets CONFIG_HZ_100=y, so this is 100 on
// every supported deployment.  golang.org/x/sys/unix does not expose
// `Sysconf`/`_SC_CLK_TCK` on Linux and we avoid cgo in this package,
// so the value is hardcoded.  There is no init-time validation; a
// pathological custom kernel with a different HZ would cause CPU
// percentages derived from /proc ticks to be inaccurate, but will
// not crash the daemon.
const userHZ = 100

// Well-known follow-up issue number printed in the rendered output
// when Buffer% cannot be read on userspace-dp.
const followupUMEMBuffer = 878

// UMEMBufferFollowup returns the issue number printed when Buffer%
// cannot be read on userspace-dp.  Callers may override to 0 if they
// want to suppress the reference.
func UMEMBufferFollowup() int { return followupUMEMBuffer }

// MapStats is the package-local BPF map utilization shape Build needs.
type MapStats struct {
	Type       string
	MaxEntries uint32
	UsedCount  uint32
}

// DataPlaneAccessor is the small surface Build needs from the dataplane.
// Callers adapt broader runtime or legacy dataplane implementations to this
// shape so this package does not depend on root dataplane telemetry types.
type DataPlaneAccessor interface {
	IsLoaded() bool
	GetMapStats() []MapStats
}

// Build gathers all fields of a ForwardingStatus.  Nil `dp` is
// tolerated (treated as "dataplane not loaded" → State=Unknown).
// `proc` must be non-nil; callers that want to bypass /proc should
// pass a stub implementation that returns os.ErrNotExist — Build
// maps that into State=Unknown with uptime falling back to
// `startTime`.  `snap` carries the 5s/1m/5m CPU history; an empty
// snapshot renders all window columns as invalid (`-`).
//
// (#879: dropped clusterMode parameter — peer rendering moved to the
// gRPC handler. fwdstatus now produces a pure single-block output;
// callers in cluster mode compose two blocks externally.)
func Build(
	dp DataPlaneAccessor,
	proc ProcReader,
	startTime time.Time,
	snap SamplerSnapshot,
) (*ForwardingStatus, error) {
	fs := &ForwardingStatus{
		State:             StateUnknown,
		WorkerCPUMode:     CPUModeEBPFNoWorkers,
		BufferKnown:       false,
		BufferFollowupRef: followupUMEMBuffer,
	}

	// --- Uptime: shared PID-start anchor ---------------------------
	selfStat, statErr := proc.ReadSelfStat()
	stat, btimeErr := proc.ReadStat()
	hasProcStat := statErr == nil && btimeErr == nil

	if hasProcStat {
		pidStart := time.Unix(int64(stat.BootTime)+int64(selfStat.StartTimeTicks)/userHZ, 0)
		fs.Uptime = time.Since(pidStart)
	} else {
		// Fallback: in-memory daemon start time.  Differs from true
		// PID-start by ms at most.  State stays Unknown below because
		// /proc/self/stat was unreadable.
		fs.Uptime = time.Since(startTime)
	}

	// --- CPU windows (5s / 1m / 5m) --------------------------------
	// Populated from the sampler's cumulative-counter ring.  An
	// empty snap (no sampler wired, or zero samples yet) leaves all
	// windows invalid — formatter renders `-`.
	fs.DaemonCPUWindows, fs.WorkerCPUWindows,
		fs.DaemonCPUWindowValid, fs.WorkerCPUWindowValid = computeCPUWindows(snap)

	// --- Heap % --------------------------------------------------
	selfStatm, statmErr := proc.ReadSelfStatm()
	hasStatm := statmErr == nil
	if hasStatm {
		rssBytes := uint64(selfStatm.ResidentPages) * uint64(pageSize())
		limitBytes := uint64(0)
		if cgroupMax, err := proc.ReadCgroupMemoryMax(); err == nil && cgroupMax > 0 {
			limitBytes = cgroupMax
		}
		if limitBytes == 0 {
			if mi, err := proc.ReadMemInfo(); err == nil && mi.MemTotalBytes > 0 {
				limitBytes = mi.MemTotalBytes
			}
		}
		if limitBytes > 0 {
			fs.HeapPercent = float64(rssBytes) * 100.0 / float64(limitBytes)
			fs.HeapPercentValid = true
		}
	}

	// --- Buffer % ------------------------------------------------
	// eBPF path: max BPF map utilization.
	// Userspace-dp path: derived from bounded AF_XDP helper status
	// below; BPF maps do not represent userspace ring fill.
	//
	// Note: GetMapStats() iterates every entry of every BPF map and
	// userspace.Manager.Status() takes Manager.mu.  That's acceptable
	// because `show chassis forwarding` is a rare CLI diagnostic, but
	// don't wire this into a high-frequency poller.
	isUserspace := false
	if dp != nil {
		if _, ok := dp.(interface {
			Status() (userspace.ProcessStatus, error)
		}); ok {
			isUserspace = true
		}
	}
	if dp != nil && !isUserspace {
		// Skip Array / PerCPUArray types — their "UsedCount" is the
		// iterator's slot count (always == MaxEntries, giving a
		// nonsense 100%).  `showSystemBuffers` skips them for the
		// same reason.  Only Hash / LPMTrie-style maps track
		// meaningful occupancy.
		maxPct := 0.0
		for _, ms := range dp.GetMapStats() {
			if ms.MaxEntries == 0 {
				continue
			}
			if ms.Type == "Array" || ms.Type == "PerCPUArray" {
				continue
			}
			pct := float64(ms.UsedCount) * 100.0 / float64(ms.MaxEntries)
			if pct > maxPct {
				maxPct = pct
			}
		}
		fs.BufferPercent = maxPct
		fs.BufferKnown = true
	}
	// #878: userspace-dp Buffer% is the max across bindings of
	// max(umem_inflight%, tx_ring%).  An idle binding with no
	// published capacities (UmemTotalFrames==0) is skipped, so a
	// fresh boot before the first per-binding publish keeps
	// BufferKnown=false and the legacy "unknown (#878)" rendering.
	// Userspace-dp status fetch happens below for State
	// classification — fold the buffer computation into that lookup
	// to avoid a second Status() call.

	// --- Worker path detection (for State + Mode) ----------------
	// Worker CPU values come from the sampler (above); here we only
	// need to know whether we're on the userspace path and whether
	// Status() currently returns an error, for State classification.
	var usStatus userspace.ProcessStatus
	var usErr error
	if dp != nil && isUserspace {
		if acc, ok := dp.(interface {
			Status() (userspace.ProcessStatus, error)
		}); ok {
			usStatus, usErr = acc.Status()
		}
	}
	if isUserspace && usErr == nil {
		fs.WorkerCPUMode = CPUModeWorkers
		// #878: derive Buffer% from per-binding UMEM in-flight and
		// TX-ring depth. Both inputs come from atomics published by
		// the worker thread itself in a single store per signal per
		// ~1s debug tick — no torn-load risk on the read side. For
		// each binding with published capacities, compute
		// max(umem%, tx_ring%) and aggregate as max across bindings.
		// Bindings whose UmemTotalFrames is zero (helper hasn't
		// published yet, or pre-#878 helper) are skipped entirely:
		// the Rust worker writes both capacities atomically at
		// startup, so a binding without UmemTotalFrames also has no
		// meaningful TxRingCapacity. Gating on UmemTotalFrames alone
		// keeps the "all unknown" backward-compat path clean.
		maxPct := 0.0
		anyKnown := false
		for _, b := range usStatus.Bindings {
			if b.UmemTotalFrames == 0 {
				continue
			}
			anyKnown = true
			umemPct := float64(b.UmemInflightFrames) * 100.0 / float64(b.UmemTotalFrames)
			var txPct float64
			if b.TxRingCapacity > 0 {
				txPct = float64(b.OutstandingTX) * 100.0 / float64(b.TxRingCapacity)
			}
			pct := umemPct
			if txPct > pct {
				pct = txPct
			}
			if pct > maxPct {
				maxPct = pct
			}
		}
		if anyKnown {
			if maxPct > 100.0 {
				maxPct = 100.0
			}
			fs.BufferPercent = maxPct
			fs.BufferKnown = true
			fs.BufferFollowupRef = 0
		}
	}

	// --- Helper crash/restart record (#7250) ---------------------
	//
	// Probed as an anonymous interface, matching the Status() probe above, so
	// DataPlaneAccessor stays the two-method surface every caller and test
	// already implements.
	//
	// This is deliberately NOT gated on `usErr == nil`. The crash record lives
	// on the Manager, not in the helper's published status, and a crash runs
	// `resetAfterHelperGoneLocked` -> `clearLastStatusLocked` so `Status()`
	// starts erroring — which is precisely the case this block exists to
	// explain. Gating it the way the Buffer% block above is gated would make
	// the crash surface go blank exactly when a helper crashed.
	//
	// `isUserspace` is a type assertion rather than a Status() outcome, so it
	// stays true across a crash; that is what keeps this reachable.
	if dp != nil && isUserspace {
		if acc, ok := dp.(interface {
			HelperCrashState() (userspace.HelperCrashRecord, bool)
		}); ok {
			if rec, known := acc.HelperCrashState(); known {
				fs.HelperCrashKnown = true
				fs.LastExitWasCrash = rec.LastExitWasCrash
				fs.RestartPending = rec.RestartPending
				fs.HelperCrashLooping = rec.CrashLooping()
				fs.HelperExitCode = rec.ExitCode
				fs.HelperSignal = rec.Signal
				fs.HelperExitDetail = rec.Detail
				fs.HelperPID = rec.PID
				fs.HelperLastExit = rec.At
				fs.HelperRestarts = rec.Restarts
				fs.HelperLastRestartAttempt = rec.LastRestartAttempt
				fs.HelperNextRestart = rec.NextRestart
			}
		}
		// #8397: crash HISTORY, a separate accessor because it has a separate
		// lifetime. Asserted independently of HelperCrashState so a build that
		// has one and not the other still renders what it has -- and, more to
		// the point, so this block is reachable when the CURRENT record is the
		// zero value, which is exactly the case history exists for: a helper
		// that crashed repeatedly and is healthy right now.
		if hist, ok := dp.(interface {
			HelperCrashHistory() ([]userspace.HelperCrashEpisode, int)
		}); ok {
			episodes, total := hist.HelperCrashHistory()
			fs.HelperCrashEpisodes = total
			if len(episodes) > 0 {
				fs.HelperCrashEpisodesOldest = episodes[0].At
			}
		}
	}

	// --- State ---------------------------------------------------
	switch {
	case dp == nil || !dp.IsLoaded():
		fs.State = StateUnknown
	case !hasProcStat || !hasStatm:
		fs.State = StateUnknown
	case isUserspace && usErr != nil:
		fs.State = StateUnknown
	case isUserspace && !heartbeatsHealthy(usStatus.WorkerHeartbeats, time.Now(), 2*time.Second):
		fs.State = StateDegraded
	default:
		fs.State = StateOnline
	}

	return fs, nil
}

func ticksToNanos(ticks uint64) uint64 {
	// Divide before multiply. The naive `ticks * 1e9 / userHZ` overflows
	// uint64 once `ticks * 1e9` exceeds 2^64 — at ~1.845e10 ticks (~33 days of
	// busy time summed across 64 cores at 100 Hz) the product wraps and the CPU
	// windows that diagnose saturation go invalid (#4909). Splitting into a
	// whole-second term plus a sub-second remainder keeps full precision (the
	// remainder is < userHZ so `rem * 1e9` cannot overflow) while pushing the
	// overflow point out by a factor of userHZ, far beyond any real uptime.
	return (ticks/userHZ)*1_000_000_000 + (ticks%userHZ)*1_000_000_000/userHZ
}

// heartbeatsHealthy returns true only on positive, in-window evidence
// that packet-processing workers are alive: the slice must be
// non-empty and EVERY heartbeat must fall in the closed age window
// [0, maxAge] relative to now.  Both endpoints are load-bearing
// (#4875):
//
//   - An empty slice returns false.  A userspace helper that has not
//     yet published any heartbeat (startup) or a wire-version mismatch
//     that omits the field must NOT read as Online — the old
//     "empty → trivially fresh" behavior let a firewall with no live
//     worker report a false-green forwarding state.
//   - A future-dated heartbeat (negative age) returns false.  Both the
//     heartbeat and `now` come from the same host clock, so a heartbeat
//     ahead of now is a malformed/torn conversion, not real evidence of
//     liveness; it must not satisfy the freshness check.
//   - A stale heartbeat (age > maxAge) returns false, as before.
func heartbeatsHealthy(hbs []time.Time, now time.Time, maxAge time.Duration) bool {
	if len(hbs) == 0 {
		return false
	}
	for _, hb := range hbs {
		age := now.Sub(hb)
		if age < 0 || age > maxAge {
			return false
		}
	}
	return true
}

// pageSize is runtime.Getpagesize wrapped so tests can't accidentally
// call it with a mock that doesn't match the real parser (the parser
// returns raw page counts).
func pageSize() int {
	return syscallPageSize
}

// syscallPageSize is the page size in bytes used to convert the
// `resident` field of /proc/self/statm (which is in pages) to
// bytes.  Hardcoded to 4096 — Linux x86_64/arm64 page size on every
// mainline kernel config we ship.  We intentionally do NOT call
// `unix.Getpagesize()` here to keep this package dependency-light;
// if we ever deploy on a kernel with a non-4K page size (HugeTLBFS
// main allocation, transparent-hugepage config), Heap% will be
// inaccurate by a constant factor until this is fetched at runtime.
var syscallPageSize = 4096

// (A library package must not panic on sensor unreliability.  A
// malformed /proc/self/stat is caught by Build returning State=Unknown
// — no init-time sanity check here.  If a user deploys on a kernel
// with a non-standard HZ, the operator will see wrong CPU percentages
// and investigate; that is strictly better than crashing xpfd.)
