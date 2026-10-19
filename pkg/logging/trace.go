package logging

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// errFileUnavailable is the cause attributed to a dropped audit-log line when
// the writer's file handle is nil because a prior rotation reopen failed
// (#3478 item 1). Shared by TraceWriter and LocalLogWriter.
var errFileUnavailable = errors.New("audit log file unavailable (failed rotation)")

// traceLogDir is the directory persistent flow-trace files are written to. It
// is a package var (not a const) only so tests can redirect it to a temp dir;
// production always writes under /var/log. The persistent
// `security flow traceoptions file <name>` knob accepts a bare basename and the
// file always lives directly under this directory.
var traceLogDir = "/var/log"

// SetTraceLogDirForTest redirects the flow-trace output directory to dir and
// returns a function that restores the previous value. It exists only so tests
// in OTHER packages (the daemon #3932 single-callback reconcile test) can drive
// NewTraceWriter against a writable temp dir; production never calls it.
func SetTraceLogDirForTest(dir string) (restore func()) {
	old := traceLogDir
	traceLogDir = dir
	return func() { traceLogDir = old }
}

// sanitizeTraceFileName validates an operator-supplied flow-trace filename.
// The trace file always lives directly under traceLogDir, so only a bare
// basename is accepted: path separators, "." / "..", and absolute paths are
// rejected. Without this a committed `security flow traceoptions file
// ../../tmp/x` resolves to /tmp/x and the daemon appends root-written flow
// telemetry (internal addresses, ports, zones, actions, policy IDs) outside the
// log directory (#3420). This is the persistent-config sibling of the
// interactive monitor-path hardening (#3378). The commit-time gate
// (validateFlowTraceFileAST) rejects such a value loudly; this runtime check is
// defense-in-depth that fails safe (tracing disabled) on a leniently-loaded or
// peer-synced config.
func sanitizeTraceFileName(name string) error {
	if name == "" {
		return fmt.Errorf("trace filename must not be empty")
	}
	if name == "." || name == ".." {
		return fmt.Errorf("invalid trace filename: %q", name)
	}
	if strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("trace filename must be a bare name, not a path: %q", name)
	}
	if filepath.IsAbs(name) || name != filepath.Base(name) {
		return fmt.Errorf("trace filename must be a bare name, not a path: %q", name)
	}
	return nil
}

// openHardenedAuditLog opens an audit-grade log file at an absolute path with
// the symlink/permission hardening shared by the flow-trace writer and the
// event-mode security-log writer (#3420, #3477): O_NOFOLLOW so a pre-planted
// symlink at the path cannot redirect root-written telemetry to an arbitrary
// target, the opened descriptor verified to be a regular file, and mode 0600
// rather than world-readable 0644 — flow tuples/zones/policy/NAT metadata are
// audit-grade and must not leak to other local users. The caller supplies the
// open mode bits (O_APPEND for an existing/active file). O_TRUNC must NOT be
// passed: with O_NOFOLLOW a symlink open already fails, but truncation of a
// confirmed file is also undesirable on the rotation path — a fresh file is
// produced by renaming the old one aside before this open, so O_CREATE alone
// yields an empty file. This avoids the O_TRUNC-follows-symlink primitive
// (#3477 M02).
//
// The 0600 mode argument to OpenFile only applies when the file is *created*;
// an existing pre-hardening file (e.g. a 0644 trace/security log written by an
// older build) keeps its looser mode across upgrade. Since #3477 IS the
// mode-hardening contract, the descriptor — already confirmed a regular file
// opened O_NOFOLLOW, so fchmod is safe and cannot be redirected — is tightened
// to 0600 whenever its current group/other bits are non-zero.
func openHardenedAuditLog(path string, mode int) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|unix.O_NOFOLLOW|mode, 0o600)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("audit log target %s is not a regular file", path)
	}
	// Enforce 0600 on an existing file whose mode differs (create-time mode is
	// a no-op for an already-present file, so a pre-hardening 0644 log would
	// stay world-readable across upgrade). f.Chmod is an fchmod on the held
	// regular-file fd, so this cannot be steered to another path (#3477 item 3).
	if fi.Mode().Perm() != 0o600 {
		if err := f.Chmod(0o600); err != nil {
			f.Close()
			return nil, fmt.Errorf("tighten audit log mode %s: %w", path, err)
		}
	}
	return f, nil
}

// openTraceFile opens a flow-trace file (the active file or a rotated
// generation) inside traceLogDir with the shared hardened semantics
// (O_NOFOLLOW, regular-file verified, 0600 — see openHardenedAuditLog). The
// caller passes an already-sanitized basename (NewTraceWriter validates once up
// front).
func openTraceFile(name string) (*os.File, error) {
	return openHardenedAuditLog(filepath.Join(traceLogDir, name), os.O_APPEND)
}

// TraceWriter writes matching flow events to a trace file with rotation.
type TraceWriter struct {
	mu   sync.Mutex
	file *os.File
	// #9118 recovery bookkeeping for a writer wedged by a failed rotation
	// reopen. See locallog_reopen_9118.go.
	wedge    wedgeState9118
	name     string // sanitized basename, written under traceLogDir
	path     string // traceLogDir/name (rotation suffixes append to this)
	maxSize  int64  // bytes
	maxFiles int
	written  int64
	filters  []traceFilter
	flags    map[string]bool // which event types to trace

	// Failure observability (#3478). droppedWrites counts trace lines lost
	// because the file write failed or the file is nil (a prior rotation reopen
	// failed); failedRotations counts rotations that could not complete (a
	// generation shift, the active-file rename, or the post-rotation reopen
	// failed). Both are audit-grade signals: an operator who enabled
	// traceoptions must be able to tell that telemetry is being lost. The two
	// failure classes get SEPARATE ≤1/s warn clocks (lastDropWarn /
	// lastRotWarn) so a write-drop storm cannot suppress the rotation
	// warning, and vice versa. Both clocks are reached only under mu today;
	// they are guarded by warnMu as well so the invariant does not rest on
	// every present and future caller holding mu (#14191, same shape as
	// LocalLogWriter).
	// #9025: the bounded queue + writer goroutine that keeps the disk write
	// OFF the EventStream reader goroutine.
	async *asyncAuditWriter

	droppedWrites   atomic.Uint64
	failedRotations atomic.Uint64
	warnMu          sync.Mutex
	lastDropWarn    time.Time
	lastRotWarn     time.Time
}

// warnRateLimited emits a ≤1/s WARN carrying the current failure counters,
// gated by the supplied per-class clock. The clock itself is guarded by
// warnMu — a leaf lock taken only around the clock check/update and
// released before slog.Warn, so a re-entrant slog handler cannot wedge it
// and callers holding mu deadlock neither on it nor via it (#14191).
func (tw *TraceWriter) warnRateLimited(clock *time.Time, msg string, err error) {
	now := time.Now()
	tw.warnMu.Lock()
	if !clock.IsZero() && now.Sub(*clock) < time.Second {
		tw.warnMu.Unlock()
		return
	}
	*clock = now
	tw.warnMu.Unlock()
	slog.Warn(msg,
		"err", err,
		"path", tw.path,
		"dropped_writes", tw.droppedWrites.Load(),
		"failed_rotations", tw.failedRotations.Load())
}

// DroppedWrites reports the number of trace lines lost because the file write
// failed (#3478). Observability accessor for status/metrics surfaces.
func (tw *TraceWriter) DroppedWrites() uint64 { return tw.droppedWrites.Load() }

// SyncForTest blocks until every trace line queued before the call has reached
// the file (#9025). Test-only; production never needs it, because the writer
// goroutine is always draining and Close waits for it.
func (tw *TraceWriter) SyncForTest() {
	if tw.async != nil {
		tw.async.syncForTest()
	}
}

// FailedRotations reports the number of trace-file rotations that could not
// complete (#3478).
func (tw *TraceWriter) FailedRotations() uint64 { return tw.failedRotations.Load() }

type traceFilter struct {
	name     string
	srcNet   netip.Prefix
	dstNet   netip.Prefix
	protoNum uint8 // resolved protocol number; valid only when hasProto is true
	hasProto bool  // distinguishes "any protocol" from an explicit protocol 0 filter
	// invalid marks a filter whose configured prefix did not parse, was
	// present-but-empty, carried an unresolvable protocol, or had no selector
	// at all (flagged by the compiler as InvalidPrefix). Such a filter is kept
	// (so the writer still has a non-empty filter set) but never matches — a
	// typo'd/empty value must NARROW tracing to nothing, not be silently dropped
	// which would leave tw.filters empty and trace EVERYTHING (#3422 M01,
	// #15679). The commit-time gate rejects this loudly; this keeps a
	// leniently-loaded / peer-synced config fail-safe.
	invalid bool
}

// traceFlagImplemented reports whether a `security flow traceoptions flag`
// token is one the writer actually honours (matchFlags). Keep in sync with
// matchFlags and config.flowTraceImplementedFlags.
func traceFlagImplemented(flag string) bool {
	switch flag {
	case "basic-datapath", "session":
		return true
	default:
		return false
	}
}

// NewTraceWriter creates a trace writer from flow traceoptions config.
func NewTraceWriter(opts *config.FlowTraceoptions) (*TraceWriter, error) {
	if opts == nil || opts.File == "" {
		return nil, fmt.Errorf("no trace file specified")
	}

	// Reject a non-basename file value (absolute path, separator, or ".."
	// escape) so a committed config cannot steer root-written flow telemetry
	// outside /var/log (#3420). The commit-time gate rejects this loudly; here
	// we fail safe (no trace writer) for a leniently-loaded / peer-synced value.
	if err := sanitizeTraceFileName(opts.File); err != nil {
		return nil, err
	}
	name := opts.File
	path := filepath.Join(traceLogDir, name)

	maxSize := int64(opts.FileSize)
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024 // 10MB default
	}
	maxFiles := opts.FileCount
	if maxFiles <= 0 {
		maxFiles = 3
	}
	// Clamp size/files to the same bounds the commit-time gate enforces
	// (#3424). The strict gate rejects an out-of-range value, but a
	// leniently-loaded or peer-synced config (the #1960 / #3261
	// fail-closed-on-load class) can still carry one — e.g. the
	// `size 1 files 1000000000` that turns every trace line into a rotation
	// and each rotation into a ~1e9-iteration rename loop run synchronously
	// from the event callback under tw.mu (a per-event CPU storm). Clamping
	// here makes such a value fail-safe instead: a sub-minimum size cannot
	// rotate on every line and an absurd file count cannot stall the writer.
	// The unset defaults above (10MB / 3) already sit inside the bounds, so
	// this only ever narrows an explicitly out-of-range value.
	if maxSize < config.FlowTraceMinFileSize {
		maxSize = config.FlowTraceMinFileSize
	} else if maxSize > config.FlowTraceMaxFileSize {
		maxSize = config.FlowTraceMaxFileSize
	}
	if maxFiles < config.FlowTraceMinFileCount {
		maxFiles = config.FlowTraceMinFileCount
	} else if maxFiles > config.FlowTraceMaxFileCount {
		maxFiles = config.FlowTraceMaxFileCount
	}

	tw := &TraceWriter{
		name:     name,
		path:     path,
		maxSize:  maxSize,
		maxFiles: maxFiles,
		flags:    make(map[string]bool),
	}

	// Parse flags. Only flags the writer actually implements are installed.
	// An unimplemented flag (a typo like `sesson`) is dropped here rather than
	// inserted into the map: a non-empty map of unrecognized flags would
	// suppress the defaults below, and matchFlags would then never match, so
	// the daemon would report tracing enabled while writing an empty trace
	// file (#3422 M02). The commit-time gate
	// (validateFlowTraceFlagsAndFiltersAST) rejects an unknown flag loudly;
	// this keeps a leniently-loaded / peer-synced config tracing with the
	// defaults instead of silently tracing nothing.
	for _, f := range opts.Flags {
		if traceFlagImplemented(f) {
			tw.flags[f] = true
		} else {
			slog.Warn("ignoring unimplemented flow trace flag",
				"flag", f, "supported", "basic-datapath,session")
		}
	}
	// If no implemented flags specified, trace everything
	if len(tw.flags) == 0 {
		tw.flags["basic-datapath"] = true
		tw.flags["session"] = true
	}

	// Parse packet filters. A filter whose source or destination prefix does
	// not parse is marked invalid (never-match) but STILL appended, rather
	// than dropped: dropping every typo'd filter would leave tw.filters empty,
	// and HandleEvent skips filtering entirely when len(tw.filters)==0, so a
	// filter meant to narrow tracing would broaden it to every event (#3422
	// M01). Keeping an invalid filter in the set fails safe — it narrows
	// tracing to nothing. The commit-time gate rejects an unparseable prefix
	// loudly; this is the leniently-loaded / peer-synced backstop.
	for _, pf := range opts.PacketFilters {
		// A filter whose source/destination prefix node was present in the
		// config but empty (`source-prefix ""`) arrives here with an empty
		// string, indistinguishable from a legitimately-absent prefix (a
		// protocol-only filter). The compiler tells them apart and sets
		// InvalidPrefix for the present-but-empty case; seed f.invalid from it
		// so the filter fails closed (match-none) instead of matching every
		// event (#3422 M01). A protocol-only filter (InvalidPrefix false, no
		// prefixes, a protocol) stays valid and matches on its protocol.
		f := traceFilter{name: pf.Name, invalid: pf.InvalidPrefix}
		if pf.InvalidPrefix {
			slog.Warn("invalid trace filter; filter set to match-none",
				"filter", pf.Name)
		}
		if pf.SourcePrefix != "" {
			prefix, err := netip.ParsePrefix(pf.SourcePrefix)
			if err != nil {
				slog.Warn("invalid trace filter source prefix; filter set to match-none",
					"filter", pf.Name, "prefix", pf.SourcePrefix, "err", err)
				f.invalid = true
			} else {
				f.srcNet = prefix
			}
		}
		if pf.DestinationPrefix != "" {
			prefix, err := netip.ParsePrefix(pf.DestinationPrefix)
			if err != nil {
				slog.Warn("invalid trace filter destination prefix; filter set to match-none",
					"filter", pf.Name, "prefix", pf.DestinationPrefix, "err", err)
				f.invalid = true
			} else {
				f.dstNet = prefix
			}
		}
		if pf.Protocol != "" {
			// #15679: resolve via the appid SSOT so numeric (47) and named
			// (ospf/gre/...) filters match the record's raw ProtocolNum, not a
			// rendered-string comparison that only knew tcp/udp/icmp/icmpv6.
			// An unresolvable token (leniently-loaded bogus/empty-widened value)
			// fails closed instead of widening to any protocol.
			if n, ok := appid.ProtocolNumber(pf.Protocol); ok {
				f.protoNum, f.hasProto = n, true
			} else {
				slog.Warn("invalid trace filter protocol; filter set to match-none",
					"filter", pf.Name, "protocol", pf.Protocol)
				f.invalid = true
			}
		}
		tw.filters = append(tw.filters, f)
	}

	// Open trace file under traceLogDir (O_NOFOLLOW, regular-file checked, 0600).
	if err := os.MkdirAll(traceLogDir, 0755); err != nil {
		return nil, fmt.Errorf("create trace dir: %w", err)
	}
	f, err := openTraceFile(name)
	if err != nil {
		return nil, fmt.Errorf("open trace file: %w", err)
	}
	tw.file = f

	// Get current file size
	if info, err := f.Stat(); err == nil {
		tw.written = info.Size()
	}

	// #9025: start the writer goroutine last, once the handle and size are set,
	// so it can never observe a half-built writer.
	tw.async = newAsyncAuditWriter(func(it auditItem) { tw.writeLine(it.line) })

	return tw, nil
}

// Close closes the trace file.
func (tw *TraceWriter) Close() {
	// #9025: drain the queue BEFORE taking mu. The writer goroutine takes mu
	// itself, so stopping under the lock would deadlock — and dropping the
	// queued tail would lose exactly the audit records around whatever caused
	// the shutdown.
	if tw.async != nil {
		tw.async.stop()
	}
	tw.mu.Lock()
	defer tw.mu.Unlock()
	// #9118: mark the nil handle DELIBERATE, so WriteRecord's reopen cannot
	// resurrect a trace file after the writer was retired.
	tw.wedge.closed = true
	if tw.file != nil {
		tw.file.Close()
		tw.file = nil
	}
}

// HandleEvent is an EventCallback that writes matching events to the trace file.
func (tw *TraceWriter) HandleEvent(rec EventRecord, raw []byte) {
	// Check if event type matches trace flags
	if !tw.matchFlags(rec.Type) {
		return
	}

	// Check packet filters (if any configured)
	if len(tw.filters) > 0 && !tw.matchFilters(rec) {
		return
	}

	// Format trace line
	line := tw.formatTrace(rec)

	// #9025: HAND OFF, do not write. This runs on the EventStream reader
	// goroutine, which also carries HA session sync, the ISSU drain signal and
	// full-resync — a synchronous WriteString on a raw *os.File (plus an inline
	// rotate() when the cap trips) parks all of them under disk distress. A FULL
	// queue drops and counts into the same DroppedWrites signal #3478
	// established; blocking here would put the stall back one buffer later.
	if tw.async != nil {
		if !tw.async.enqueue(auditItem{line: line}) {
			tw.droppedWrites.Add(1)
		}
		return
	}
	tw.writeLine(line)
}

// writeLine performs the disk write and any rotation. It runs on the async
// writer's goroutine (#9025), never on the event reader.
func (tw *TraceWriter) writeLine(line string) {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	// #9118: try to recover a wedge first. rotate() is reached only from a
	// successful write, so once the handle is nil nothing else can ever reopen
	// it and every later event is lost.
	if !tw.ensureOpenLocked() {
		// #3478 item 1: a nil file means a prior rotation reopen failed and the
		// writer is wedged (or the retry is still backing off). Every such event
		// is lost — count and warn (rate-limited) instead of returning silently,
		// otherwise the operator sees a single FailedRotations bump and no
		// further signal.
		tw.droppedWrites.Add(1)
		tw.warnRateLimited(&tw.lastDropWarn, "flow-trace write dropped: file unavailable after failed rotation", errFileUnavailable)
		return
	}

	n, err := tw.file.WriteString(line)
	if err != nil {
		// #3478 H21: a swallowed write error means lost audit telemetry the
		// operator cannot detect. Count it and emit a rate-limited WARN.
		tw.droppedWrites.Add(1)
		tw.warnRateLimited(&tw.lastDropWarn, "flow-trace write failed (audit lines lost)", err)
		return
	}
	tw.written += int64(n)

	// Rotate if needed
	if tw.written >= tw.maxSize {
		if err := tw.rotate(); err != nil {
			tw.warnRateLimited(&tw.lastRotWarn, "flow-trace rotation failed", err)
		}
	}
}

func (tw *TraceWriter) matchFlags(eventType string) bool {
	if tw.flags["basic-datapath"] {
		return true // trace everything
	}
	switch eventType {
	case "SESSION_OPEN", "SESSION_CLOSE":
		return tw.flags["session"]
	case "POLICY_DENY":
		return tw.flags["session"] || tw.flags["basic-datapath"]
	default:
		return tw.flags["basic-datapath"]
	}
}

func (tw *TraceWriter) matchFilters(rec EventRecord) bool {
	srcAddr := extractAddr(rec.SrcAddr)
	dstAddr := extractAddr(rec.DstAddr)

	// #15679: compare raw protocol numbers. ProtocolNum is authoritative when
	// non-zero (including named protocols with no rendered trace name, e.g.
	// GRE/OSPF). Hand-built/legacy records may leave it 0: fall back to
	// resolving the rendered Protocol string. That fallback makes a proto-0
	// record indistinguishable from an unset number, but production records
	// always populate ProtocolNum (ringbuf.go), and proto 0 is rejected at
	// commit for trace filters, so the ambiguity is confined to hand-built
	// proto-0 test records.
	recProto, recHasProto := rec.ProtocolNum, rec.ProtocolNum != 0
	if !recHasProto {
		if n, ok := appid.ProtocolNumber(rec.Protocol); ok {
			recProto, recHasProto = n, true
		}
	}

	for _, f := range tw.filters {
		if f.invalid {
			// A filter with an unparseable prefix/protocol never matches.
			continue
		}
		srcMatch := !f.srcNet.IsValid() || (srcAddr.IsValid() && f.srcNet.Contains(srcAddr))
		dstMatch := !f.dstNet.IsValid() || (dstAddr.IsValid() && f.dstNet.Contains(dstAddr))
		protoMatch := !f.hasProto || (recHasProto && f.protoNum == recProto)
		if srcMatch && dstMatch && protoMatch {
			return true
		}
	}
	return false
}

// extractAddr parses an IP address from "IP:port" or "[IPv6]:port" format.
func extractAddr(addrPort string) netip.Addr {
	// Try "[ipv6]:port" format
	if strings.HasPrefix(addrPort, "[") {
		end := strings.Index(addrPort, "]")
		if end > 0 {
			if addr, err := netip.ParseAddr(addrPort[1:end]); err == nil {
				return addr
			}
		}
		return netip.Addr{}
	}
	// Try "ip:port" format
	host := addrPort
	if idx := strings.LastIndex(addrPort, ":"); idx >= 0 {
		host = addrPort[:idx]
	}
	addr, _ := netip.ParseAddr(host)
	return addr
}

func (tw *TraceWriter) formatTrace(rec EventRecord) string {
	ts := rec.Time.Format("2006-01-02 15:04:05.000")
	// #7531: OMIT `action=` when the event carries no forwarding decision,
	// rather than printing an empty one. EventRecord.Action is empty for a
	// lifecycle event (recordActionName), and this is the same treatment the
	// standard and structured syslog lines already give it under #2513 /
	// #2593 — the trace was the surface that never got its own issue and went
	// on printing `action=deny` for every normal session open and close.
	//
	// An empty `action=` would be an improvement over a false `deny` and still
	// wrong: a field with no value reads as a producer that failed to populate
	// it, which is a different (and alarming) claim from "this event type has
	// no action".
	act := ""
	if rec.Action != "" {
		act = " action=" + rec.Action
	}
	if rec.Type == "SESSION_CLOSE" {
		return fmt.Sprintf("%s %-14s %s -> %s proto=%s%s policy=%d zone=%d->%d pkts=%d bytes=%d\n",
			ts, rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, act,
			rec.PolicyID, rec.InZone, rec.OutZone, rec.SessionPkts, rec.SessionBytes)
	}
	if rec.Type == "SCREEN_DROP" {
		return fmt.Sprintf("%s %-14s %s -> %s proto=%s screen=%s zone=%d\n",
			ts, rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.ScreenCheck, rec.InZone)
	}
	return fmt.Sprintf("%s %-14s %s -> %s proto=%s%s policy=%d zone=%d->%d\n",
		ts, rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, act,
		rec.PolicyID, rec.InZone, rec.OutZone)
}

// rotate rolls the active trace file aside and reopens a fresh one. It returns
// a non-nil error if the rotation could not complete and bumps failedRotations
// (#3478 H22). Crucially, tw.written is reset to 0 ONLY when the active file was
// actually moved aside and a fresh empty file opened; on a failed primary
// rename the daemon keeps writing to the same (still-full) file, so written is
// re-synced to the real size to retry rotation on the next write rather than
// silently growing unbounded with a bogus 0 byte count.
func (tw *TraceWriter) rotate() error {
	tw.file.Close()
	tw.file = nil

	// Shift existing files: .2 -> .3, .1 -> .2. A missing generation is normal
	// (ENOENT); any other rename failure means a retained generation was lost,
	// so it is counted and surfaced (#3478 item 2) even though the active-file
	// rotation below can still succeed.
	var shiftErr error
	for i := tw.maxFiles - 1; i > 0; i-- {
		old := fmt.Sprintf("%s.%d", tw.path, i)
		next := fmt.Sprintf("%s.%d", tw.path, i+1)
		if err := os.Rename(old, next); err != nil && !os.IsNotExist(err) {
			slog.Debug("trace rotate generation shift failed", "from", old, "to", next, "err", err)
			tw.failedRotations.Add(1)
			if shiftErr == nil {
				shiftErr = fmt.Errorf("rotate shift %s->%s: %w", old, next, err)
			}
		}
	}
	renameErr := os.Rename(tw.path, tw.path+".1")

	// #9057: ONE directory fsync covering the whole generational shift, the
	// near-verbatim sibling of locallog.go's. The two writers were hardened
	// TOGETHER for symlink safety (#3477) and APART for durability, which is
	// how this one ended up in no review report — it was found by sweeping the
	// OPERATION rather than by reading the file a finding pointed at.
	//
	// Best-effort by design, matching the shift-failure policy above: a
	// rotation that shifted correctly must not fail because the directory
	// fsync did.
	if err := fsatomic.SyncDir(filepath.Dir(tw.path)); err != nil {
		slog.Debug("trace rotate directory fsync failed", "dir", filepath.Dir(tw.path), "err", err)
		tw.failedRotations.Add(1)
	}

	// Remove excess files (best-effort).
	excess := fmt.Sprintf("%s.%d", tw.path, tw.maxFiles+1)
	if err := os.Remove(excess); err != nil && !os.IsNotExist(err) {
		slog.Debug("trace rotate excess removal failed", "path", excess, "err", err)
	}

	// Open fresh file (O_NOFOLLOW, regular-file checked, 0600). When the
	// primary rename succeeded the active path no longer exists, so this
	// creates a new empty file.
	f, err := openTraceFile(tw.name)
	if err != nil {
		tw.failedRotations.Add(1)
		return fmt.Errorf("reopen after rotate: %w", err)
	}
	tw.file = f

	if renameErr != nil {
		// The active file was NOT rolled aside; we reopened the same full file.
		tw.failedRotations.Add(1)
		if info, statErr := f.Stat(); statErr == nil {
			tw.written = info.Size()
		}
		return fmt.Errorf("rotate rename %s: %w", tw.path, renameErr)
	}
	// The active file rotated cleanly (fresh empty file); reset the byte count.
	// shiftErr is non-nil only when a retained generation could not be shifted;
	// surface it so the caller warns, but the active rotation itself succeeded.
	tw.written = 0
	return shiftErr
}
