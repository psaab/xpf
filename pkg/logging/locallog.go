package logging

import (
	"fmt"
	"github.com/psaab/xpf/pkg/fsatomic"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// LocalLogWriter writes security log events to a local file with rotation.
// Used when security log mode is "event" instead of streaming to remote syslog.
type LocalLogWriter struct {
	mu       sync.Mutex
	file     *os.File
	path     string
	maxSize  int64
	maxFiles int
	written  int64

	// #9118 recovery bookkeeping for a writer wedged by a failed rotation
	// reopen. See locallog_reopen_9118.go.
	wedge wedgeState9118

	// #9025: bounded queue + writer goroutine for the EVENT-READER path only.
	async *asyncAuditWriter

	// Filtering (same as SyslogClient)
	MinSeverity int
	Categories  uint8
	Format      string // "binary" / "structured" / "sd-syslog" / "" (standard)

	// Facility is the syslog facility code used to compute the <PRI> value for
	// the RFC 5424 envelope when Format == "sd-syslog" (#3409). Defaults to
	// FacilityLocal0 in NewLocalLogWriter, matching SyslogClient. Ignored for
	// the standard / structured / binary paths.
	Facility int
	// hostname is captured at construction (os.Hostname, "xpf" fallback) for
	// the RFC 5424 HOSTNAME field, matching SyslogClient.
	hostname string

	// Failure observability (#3478). droppedWrites counts security-log lines
	// lost because the file write failed or the file handle is nil (closed, or
	// a prior rotation reopen failed); failedRotations counts rotations that
	// could not complete (a generation shift, the active-file rename, or the
	// post-rotation reopen failed). These are audit-grade signals — an operator
	// running `security log mode event` must be able to tell that audit lines
	// are being lost. The two failure classes get SEPARATE ≤1/s warn clocks
	// (lastDropWarn / lastRotWarn, mu-guarded) so a write-drop storm cannot
	// suppress the rotation warning and vice versa.
	droppedWrites   atomic.Uint64
	failedRotations atomic.Uint64
	lastDropWarn    time.Time
	lastRotWarn     time.Time
}

// warnRateLimited emits a ≤1/s WARN carrying the current failure counters,
// gated by the supplied per-class clock. Must be called with lw.mu held.
func (lw *LocalLogWriter) warnRateLimited(clock *time.Time, msg string, err error) {
	now := time.Now()
	if !clock.IsZero() && now.Sub(*clock) < time.Second {
		return
	}
	*clock = now
	slog.Warn(msg,
		"err", err,
		"path", lw.path,
		"dropped_writes", lw.droppedWrites.Load(),
		"failed_rotations", lw.failedRotations.Load())
}

// DroppedWrites reports the number of security-log lines lost because the file
// write failed (#3478). Observability accessor for status/metrics surfaces.
func (lw *LocalLogWriter) DroppedWrites() uint64 { return lw.droppedWrites.Load() }

// FailedRotations reports the number of security-log rotations that could not
// complete (#3478).
func (lw *LocalLogWriter) FailedRotations() uint64 { return lw.failedRotations.Load() }

// LocalLogConfig configures a LocalLogWriter.
type LocalLogConfig struct {
	Path     string // log file path (default: /var/log/xpf/security.log)
	MaxSize  int64  // max file size in bytes (default: 10MB)
	MaxFiles int    // number of rotated files to keep (default: 5)
}

// NewLocalLogWriter creates a local file log writer.
func NewLocalLogWriter(cfg LocalLogConfig) (*LocalLogWriter, error) {
	path := cfg.Path
	if path == "" {
		path = "/var/log/xpf/security.log"
	}
	maxSize := cfg.MaxSize
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024 // 10MB
	}
	maxFiles := cfg.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 5
	}

	// Directory 0750 (not 0755) — the security log dir should not be
	// world-traversable (#3477 M02).
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	// Open the active file with the shared audit-log hardening (#3477 M01):
	// O_NOFOLLOW (no symlink redirect), regular-file verified, mode 0600 (not
	// world-readable 0644 — the event-mode security log carries the same
	// policy/session/NAT forensics the flow-trace writer was hardened for).
	f, err := openHardenedAuditLog(path, os.O_APPEND)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "xpf"
	}
	lw := &LocalLogWriter{
		file:     f,
		path:     path,
		maxSize:  maxSize,
		maxFiles: maxFiles,
		Facility: FacilityLocal0,
		hostname: hostname,
	}
	if info, err := f.Stat(); err == nil {
		lw.written = info.Size()
	}
	// #9025: started last, once the handle and size are set, so the writer
	// goroutine can never observe a half-built writer.
	lw.async = newAsyncAuditWriter(func(it auditItem) { _ = lw.Send(it.severity, it.line) })
	return lw, nil
}

// Send writes a log message to the local file. It matches the SyslogClient.Send
// signature pattern so it can be used as a drop-in replacement.
func (lw *LocalLogWriter) Send(severity int, msg string) error {
	var line string
	if lw.Format == "sd-syslog" {
		// RFC 5424 envelope, byte-for-byte identical to SyslogClient.Send's
		// sd-syslog framing apart from the absence of transport octet-counting
		// (#3409): <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG.
		// The structured-data and msgid fields are NILVALUE ("-"), matching the
		// stream path. msg is the standard RT_FLOW body (formatSyslogMsg).
		priority := lw.Facility*8 + severity
		ts := time.Now().Format("2006-01-02T15:04:05.000Z07:00")
		line = fmt.Sprintf("<%d>1 %s %s xpf - - - %s\n", priority, ts, sanitizeSyslogHostname(lw.hostname), msg)
	} else {
		// Standard ("" / syslog) and structured (Junos RT_FLOW) bodies share the
		// local-file timestamp+severity-tag prefix; only the msg body differs
		// (chosen by the ringbuf fanout per Format).
		ts := time.Now().Format("2006-01-02T15:04:05.000")
		line = fmt.Sprintf("%s [%s] %s\n", ts, severityTag(severity), msg)
	}

	lw.mu.Lock()
	defer lw.mu.Unlock()

	// #9118: a nil handle may be a WEDGE (a prior rotation reopen failed) rather
	// than a deliberate close. Nothing else ever reopens it -- rotate() is
	// reached only from `written >= maxSize`, which needs a successful write --
	// so the recovery attempt has to live on the write path itself.
	if !lw.ensureOpenLocked() {
		// #3478 item 1/4: a nil file (closed, or a reopen that could not be
		// retried yet) drops the line. Count it on EVERY failure path — not just
		// a write error — so a wedged writer is observable, and return the error.
		lw.droppedWrites.Add(1)
		lw.warnRateLimited(&lw.lastDropWarn, "local security-log write dropped: file unavailable", errFileUnavailable)
		return fmt.Errorf("log file closed")
	}

	n, err := lw.file.WriteString(line)
	if err != nil {
		// #3478 M04: count the lost audit line and surface it (the error is
		// also returned to the caller; the counter makes the aggregate
		// observable even where callers discard it).
		lw.droppedWrites.Add(1)
		lw.warnRateLimited(&lw.lastDropWarn, "local security-log write failed (audit line lost)", err)
		return err
	}
	lw.written += int64(n)

	if lw.written >= lw.maxSize {
		if rerr := lw.rotate(); rerr != nil {
			lw.warnRateLimited(&lw.lastRotWarn, "local security-log rotation failed", rerr)
		}
	}
	return nil
}

// SendBinary writes a binary log record to the local file.
// The record is self-framing (contains its own length), so no additional
// framing is added.
func (lw *LocalLogWriter) SendBinary(data []byte) error {
	lw.mu.Lock()
	defer lw.mu.Unlock()

	if !lw.ensureOpenLocked() {
		// #3478 item 1/4: count the dropped binary record on the nil-file path
		// (#9118: after a reopen attempt, so a wedge is recovered rather than
		// merely counted).
		lw.droppedWrites.Add(1)
		lw.warnRateLimited(&lw.lastDropWarn, "local security-log binary write dropped: file unavailable", errFileUnavailable)
		return fmt.Errorf("log file closed")
	}

	n, err := lw.file.Write(data)
	if err != nil {
		lw.droppedWrites.Add(1)
		lw.warnRateLimited(&lw.lastDropWarn, "local security-log binary write failed (audit record lost)", err)
		return err
	}
	lw.written += int64(n)

	if lw.written >= lw.maxSize {
		if rerr := lw.rotate(); rerr != nil {
			lw.warnRateLimited(&lw.lastRotWarn, "local security-log rotation failed", rerr)
		}
	}
	return nil
}

// ShouldSendEvent returns true if both severity and category filters pass.
func (lw *LocalLogWriter) ShouldSendEvent(severity int, categoryBit uint8) bool {
	if lw.MinSeverity != 0 && severity > lw.MinSeverity {
		return false
	}
	return lw.Categories == 0 || lw.Categories&categoryBit != 0
}

// Close closes the log file.
// SendFromEventReader is the #9025 entry point for the EventStream reader
// goroutine. It hands the formatted line to a bounded queue and returns
// immediately; the disk write happens on a dedicated goroutine.
//
// WHY A SECOND ENTRY POINT rather than making Send itself async. Send's error
// REPORTS THE WRITE RESULT, and #3478 M04 made that deliberate ("the error is
// also returned to the caller"). That contract and "the write does not happen
// on your goroutine" cannot both hold — an async Send would return nil for a
// line that later fails, silently voiding a guarantee several callers and cells
// rely on. So the synchronous contract is left exactly as it was for every
// caller that can afford to wait, and only the one caller that CANNOT — the
// event reader, which also carries HA session sync, the ISSU drain signal and
// full-resync — is moved off it.
//
// The returned bool reports whether the line was ACCEPTED. False means it was
// dropped (queue full or writer retired) and counted, which is the signal
// #3478 established as the observable one.
func (lw *LocalLogWriter) SendFromEventReader(severity int, msg string) bool {
	if lw.async == nil {
		return lw.Send(severity, msg) == nil
	}
	// The line is formatted on the WRITER goroutine (Send does it), so the
	// reader goroutine pays only the channel send.
	if !lw.async.enqueue(auditItem{severity: severity, line: msg}) {
		lw.droppedWrites.Add(1)
		lw.warnRateLimited(&lw.lastDropWarn,
			"local security-log write dropped: writer queue full or retired", errFileUnavailable)
		return false
	}
	return true
}

// SyncForTest blocks until every line queued before the call has reached the
// file (#9025). Test-only.
func (lw *LocalLogWriter) SyncForTest() {
	if lw.async != nil {
		lw.async.syncForTest()
	}
}

func (lw *LocalLogWriter) Close() error {
	// #9025: drain BEFORE taking mu — the writer goroutine calls Send, which
	// takes mu, so stopping under the lock would deadlock; and dropping the
	// queued tail would lose the audit records around whatever caused the
	// shutdown.
	if lw.async != nil {
		lw.async.stop()
	}
	lw.mu.Lock()
	defer lw.mu.Unlock()
	// #9118: record that this nil handle is DELIBERATE. Send/SendBinary now
	// try to reopen a nil handle, and without this flag they could not tell a
	// wedged writer from a retired one and would recreate the audit file after
	// shutdown.
	lw.wedge.closed = true
	if lw.file != nil {
		err := lw.file.Close()
		lw.file = nil
		return err
	}
	return nil
}

// rotate rolls the active security-log file aside and reopens a fresh one. It
// returns a non-nil error if the rotation could not complete and bumps
// failedRotations (#3478 M03). The reopen uses the shared hardened open
// (O_NOFOLLOW, regular-file verified, 0600) instead of the old
// O_TRUNC|0644 — O_TRUNC followed a symlink planted between the rename and the
// reopen, turning rotation into a truncate-arbitrary-file primitive (#3477
// M02). lw.written is reset to 0 ONLY when the active file was actually moved
// aside; on a failed primary rename it is re-synced to the real size so the
// next write retries rotation rather than silently growing unbounded.
func (lw *LocalLogWriter) rotate() error {
	lw.file.Close()
	lw.file = nil

	// A missing generation is normal (ENOENT); any other shift failure means a
	// retained generation was lost — count and surface it (#3478 item 2).
	var shiftErr error
	for i := lw.maxFiles - 1; i > 0; i-- {
		old := fmt.Sprintf("%s.%d", lw.path, i)
		next := fmt.Sprintf("%s.%d", lw.path, i+1)
		if err := os.Rename(old, next); err != nil && !os.IsNotExist(err) {
			slog.Debug("local log rotate generation shift failed", "from", old, "to", next, "err", err)
			lw.failedRotations.Add(1)
			if shiftErr == nil {
				shiftErr = fmt.Errorf("rotate shift %s->%s: %w", old, next, err)
			}
		}
	}
	renameErr := os.Rename(lw.path, lw.path+".1")
	// #9057: ONE directory fsync covering the whole generational shift. Every
	// rename above lands in the same directory, so a per-rename
	// fsatomic.RenameDurable would issue N fsyncs where one suffices. Without
	// it the renames are atomic but the ENTRIES are not durable, and an
	// unclean shutdown can lose which generation a name points at. Rotation
	// fires once per maxSize (10 MB default), so the cost is negligible.
	//
	// Best-effort by design: a rotation that shifted correctly must not fail
	// because the directory fsync did — the log keeps working, and the failure
	// is counted and logged like the shift failures above.
	if err := fsatomic.SyncDir(filepath.Dir(lw.path)); err != nil {
		slog.Debug("local log rotate directory fsync failed", "dir", filepath.Dir(lw.path), "err", err)
		lw.failedRotations.Add(1)
	}
	excess := fmt.Sprintf("%s.%d", lw.path, lw.maxFiles+1)
	if err := os.Remove(excess); err != nil && !os.IsNotExist(err) {
		slog.Debug("local log rotate excess removal failed", "path", excess, "err", err)
	}

	// Reopen with the shared hardened semantics. The primary rename (when it
	// succeeds) removed the active path, so O_CREATE yields a fresh empty file;
	// O_TRUNC is deliberately NOT used (see openHardenedAuditLog).
	f, err := openHardenedAuditLog(lw.path, os.O_APPEND)
	if err != nil {
		lw.failedRotations.Add(1)
		return fmt.Errorf("reopen after rotate: %w", err)
	}
	lw.file = f

	if renameErr != nil {
		lw.failedRotations.Add(1)
		if info, statErr := f.Stat(); statErr == nil {
			lw.written = info.Size()
		}
		return fmt.Errorf("rotate rename %s: %w", lw.path, renameErr)
	}
	// Active file rotated cleanly; reset the byte count. shiftErr (if any) is a
	// retained-generation loss only — surface it so the caller warns.
	lw.written = 0
	return shiftErr
}

func severityTag(severity int) string {
	switch severity {
	case SyslogError:
		return "ERROR"
	case SyslogWarning:
		return "WARNING"
	case SyslogInfo:
		return "INFO"
	default:
		return "INFO"
	}
}
