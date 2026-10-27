package fwdstatus

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// Linux exposes the process clock-tick rate through getconf's
// CLK_TCK value. If getconf is unavailable (for example, in a minimal
// container), fall back to the Linux ABI default and explicitly mark
// daemon CPU as approximate.
var userHZ, userHZApprox = kernelUserHZ()

func kernelUserHZ() (int, bool) {
	out, err := exec.Command("getconf", "CLK_TCK").Output()
	if err == nil {
		hz, parseErr := strconv.Atoi(strings.TrimSpace(string(out)))
		if parseErr == nil && hz > 0 {
			return hz, false
		}
	}
	return 100, true
}

// Well-known follow-up issue number printed in the rendered output
// when Buffer% cannot be read on userspace-dp.
const followupUMEMBuffer = 878

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

// MapStatsSource is the minimal dataplane surface NewAccessor needs
// for the mandatory accessors, already in the package-local MapStats
// shape. Callers pass a value whose IsLoaded/GetMapStats forward to
// the provider stored on their surface (liveDataPlane forwards both).
type MapStatsSource interface {
	IsLoaded() bool
	GetMapStats() []MapStats
}

// CrashReporter is the named crash-capability surface (#17128).
// Build asserts CrashReporter instead of anonymous interfaces, so a
// missing HelperCrashState/HelperCrashHistory on the shared accessor
// is a compile error (see the var _ assertions below), not silence.
type CrashReporter interface {
	HelperCrashState() (userspace.HelperCrashRecord, bool)
	HelperCrashHistory() ([]userspace.HelperCrashEpisode, int)
}

// StatusProvider is the named userspace-status capability Build keys
// backend identity on.
type StatusProvider interface {
	Status() (userspace.ProcessStatus, error)
}

// accessor is the single shared forwarding-status adapter (#17128).
// It replaces the verbatim forwardingStatus*DataPlane twins formerly
// in pkg/cli and pkg/grpcapi.
//
// The userspace/non-userspace distinction is preserved by which
// concrete type NewAccessor returns (see below): only the userspace
// wrapper carries Status/CrashReporter, matching the old adapters
// where only forwardingStatus*UserspaceDataPlane carried them.
type accessor struct {
	src     MapStatsSource
	backend any
	status  func() (userspace.ProcessStatus, error)
}

func (a accessor) IsLoaded() bool {
	if a.src == nil {
		return false
	}
	return a.src.IsLoaded()
}

func (a accessor) GetMapStats() []MapStats {
	if a.src == nil {
		return nil
	}
	return a.src.GetMapStats()
}

// userspaceAccessor is the userspace flavour: it additionally carries
// Status and the crash reporters, so Build's named assertions succeed
// only for a published userspace backend.
type userspaceAccessor struct {
	accessor
}

func (a userspaceAccessor) Status() (userspace.ProcessStatus, error) {
	if a.status == nil {
		return userspace.ProcessStatus{}, errStatusUnavailable
	}
	return a.status()
}

// HelperCrashState resolves the backend directly (#7250): the crash
// record is Manager-owned and is NOT part of ProcessStatus — a crash
// clears the cached status, so routing through Status would blank
// the block in the one case it exists for.
func (a userspaceAccessor) HelperCrashState() (userspace.HelperCrashRecord, bool) {
	provider, ok := a.backend.(interface {
		HelperCrashState() (userspace.HelperCrashRecord, bool)
	})
	if !ok {
		return userspace.HelperCrashRecord{}, false
	}
	return provider.HelperCrashState()
}

// HelperCrashHistory feeds the #8397 completed-episode summary.
// Resolve the backend directly: completed history remains available
// after the live episode closes.
func (a userspaceAccessor) HelperCrashHistory() ([]userspace.HelperCrashEpisode, int) {
	provider, ok := a.backend.(interface {
		HelperCrashHistory() ([]userspace.HelperCrashEpisode, int)
	})
	if !ok {
		return nil, 0
	}
	return provider.HelperCrashHistory()
}

var (
	_ DataPlaneAccessor = accessor{}
	_ DataPlaneAccessor = userspaceAccessor{}
	_ StatusProvider    = userspaceAccessor{}
	_ CrashReporter     = userspaceAccessor{}
)

// errStatusUnavailable mirrors the per-surface "userspace status
// unavailable" error the old Status methods produced via their
// surface helpers when no provider was present.
var errStatusUnavailable = statusUnavailableError{}

type statusUnavailableError struct{}

func (statusUnavailableError) Error() string { return "userspace status unavailable" }

// NewAccessor builds the single shared forwarding-status accessor
// (#17128). dp supplies IsLoaded/GetMapStats (already in the
// package-local MapStats shape); backend is the single-resolved
// published backend (mgmtview.Probe result) used for capability
// detection and crash reporting; status, when non-nil, is the
// surface's userspace-status func. A nil backend yields a nil
// accessor (the #6743 publication check: an emptied cell must read
// as no dataplane, not as a trusted-zero BPF backend). A backend
// implementing StatusProvider yields the userspace accessor;
// otherwise the plain (map-stats) accessor.
func NewAccessor(dp MapStatsSource, backend any, status func() (userspace.ProcessStatus, error)) DataPlaneAccessor {
	if backend == nil {
		return nil
	}
	base := accessor{src: dp, backend: backend, status: status}
	if _, ok := backend.(StatusProvider); ok {
		return userspaceAccessor{accessor: base}
	}
	return base
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
		UserHZApprox:      userHZApprox,
		SamplerReadErrors: snap.ReadErrors,
	}

	// --- Uptime: shared PID-start anchor ---------------------------
	selfStat, statErr := proc.ReadSelfStat()
	stat, btimeErr := proc.ReadStat()
	hasProcStat := statErr == nil && btimeErr == nil

	if hasProcStat {
		pidStart := time.Unix(int64(stat.BootTime)+int64(selfStat.StartTimeTicks)/int64(userHZ), 0)
		fs.Uptime = time.Since(pidStart)
	} else {
		// Fallback: in-memory daemon start time.  Differs from true
		// PID-start by ms at most.  State stays Unknown below because
		// /proc/self/stat was unreadable.
		fs.Uptime = time.Since(startTime)
	}

	// --- CPU windows (5s / 1m / 5m) --------------------------------
	// A missing or stale sample leaves the affected window columns
	// invalid — the formatter renders them as `-`.
	fs.CPUDataStale = cpuSnapshotStale(snap)
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
		if _, ok := dp.(StatusProvider); ok {
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
		if acc, ok := dp.(StatusProvider); ok {
			usStatus, usErr = acc.Status()
		}
	}
	if isUserspace && usErr == nil {
		fs.LastSnapshotRejectReasons = append([]string(nil), usStatus.LastSnapshotRejectReasons...)
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
			// Buffer utilization tracks frames actually in flight, not
			// frames intentionally held idle in the userspace fill queue.
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
	// Probed via the named CrashReporter interface (#17128), so
	// DataPlaneAccessor stays the two-method surface every caller and
	// test already implements while the shared accessor's crash
	// methods are compile-checked (var _ CrashReporter above).
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
		if acc, ok := dp.(CrashReporter); ok {
			if rec, known := acc.HelperCrashState(); known {
				fs.HelperCrashKnown = true
				fs.LastExitWasCrash = rec.LastExitWasCrash
				fs.RestartPending = rec.RestartPending
				fs.HelperCrashLooping = rec.CrashLooping()
				fs.HelperRecovered = rec.RecoveredSinceCrash
				fs.HelperExitCode = rec.ExitCode
				fs.HelperSignal = rec.Signal
				fs.HelperExitDetail = rec.Detail
				fs.HelperPID = rec.PID
				fs.HelperLastExit = rec.At
				fs.HelperRestarts = rec.Restarts
				fs.HelperLastRestartAttempt = rec.LastRestartAttempt
				fs.HelperNextRestart = rec.NextRestart
			}
			// #8397: crash HISTORY, carried by the same CrashReporter
			// because it has a separate lifetime but the same reporter:
			// the completed-episode summary must be reachable when the
			// CURRENT record is the zero value, which is exactly the
			// case history exists for: a helper that crashed repeatedly
			// and is healthy right now.
			episodes, total := acc.HelperCrashHistory()
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
	return ticksToNanosAtHZ(ticks, uint64(userHZ))
}

// ticksToNanosAtHZ converts /proc scheduler ticks without assuming the
// host's USER_HZ value. Divide before multiply to avoid an overflowing
// ticks*1e9 intermediate.
func ticksToNanosAtHZ(ticks, hz uint64) uint64 {
	return (ticks/hz)*1_000_000_000 + (ticks%hz)*1_000_000_000/hz
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

// pageSize returns the running kernel's page size, the unit used by
// the `resident` field of /proc/self/statm. Captured from the runtime
// system call at initialization rather than assumed to be 4096.
var systemPageSize = os.Getpagesize()

func pageSize() int {
	return systemPageSize
}
