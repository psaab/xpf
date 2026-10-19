package logging

import (
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
)

// TestNewTraceWriterRejectsPathTraversal verifies the #3420 runtime guard:
// NewTraceWriter refuses an absolute path, a "../" escape, or any
// separator-bearing file value so a leniently-loaded / peer-synced config
// cannot write root-owned flow telemetry outside /var/log. The accepted bare
// basename writes inside the configured trace directory.
func TestNewTraceWriterRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	bad := []string{
		"/tmp/rt-flow-leak",
		"../../tmp/rt-flow-leak",
		"sub/dir/x",
		"..",
		".",
		`a\b`,
	}
	for _, name := range bad {
		t.Run("reject/"+name, func(t *testing.T) {
			tw, err := NewTraceWriter(&config.FlowTraceoptions{File: name})
			if err == nil {
				if tw != nil {
					tw.Close()
				}
				t.Fatalf("NewTraceWriter(%q) = nil error, want rejection", name)
			}
			// Nothing must have been created outside the trace dir.
			if _, statErr := os.Stat("/tmp/rt-flow-leak"); statErr == nil {
				os.Remove("/tmp/rt-flow-leak")
				t.Fatalf("NewTraceWriter(%q) created /tmp/rt-flow-leak", name)
			}
		})
	}

	t.Run("accept-basename", func(t *testing.T) {
		tw, err := NewTraceWriter(&config.FlowTraceoptions{File: "rt-flow.log"})
		if err != nil {
			t.Fatalf("NewTraceWriter(basename) = %v, want nil", err)
		}
		defer tw.Close()
		want := filepath.Join(dir, "rt-flow.log")
		if _, err := os.Stat(want); err != nil {
			t.Fatalf("expected trace file %s: %v", want, err)
		}
		// Created mode 0600 (audit-grade telemetry), not world-readable 0644.
		fi, err := os.Stat(want)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("trace file mode = %o, want 0600", perm)
		}
	})
}

// TestOpenTraceFileRejectsNonRegular pins the fd fstat regular-file check in
// openTraceFile independently (#3420 Codex MINOR). A non-regular target (here a
// FIFO planted under traceLogDir) must be refused even though O_NOFOLLOW lets
// the open through — without the IsRegular() guard the daemon would append flow
// telemetry into a pipe/device an attacker pre-planted in /var/log.
//
// RED-on-revert: delete the !fi.Mode().IsRegular() check in openTraceFile and
// the open below succeeds (returns a non-nil fd, nil error), so this test goes
// green on the FIFO target — exactly the regression it guards.
func TestOpenTraceFileRejectsNonRegular(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	fifo := filepath.Join(dir, "flow.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	// Hold the read end open (non-blocking) so openTraceFile's O_WRONLY open on
	// the FIFO does not block waiting for a reader; the open then reaches the
	// fstat regular-file check, which is the guard under test.
	rf, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("open fifo read end: %v", err)
	}
	defer rf.Close()

	f, err := openTraceFile("flow.fifo")
	if err == nil {
		if f != nil {
			f.Close()
		}
		t.Fatalf("openTraceFile opened a FIFO target, want regular-file rejection")
	}
}

// TestRotateUsesHardenedOpen pins that rotate() reopens the fresh active file
// through the hardened openTraceFile path rather than a raw os.OpenFile (#3420
// Codex MINOR). It asserts two consequences of routing through openTraceFile:
// the reopened active file is mode 0600 (not the old raw-open 0644), and a
// symlink planted at the active path before the reopen is refused (O_NOFOLLOW),
// so a post-rotation symlink cannot redirect telemetry.
//
// RED-on-revert: change rotate() back to
// `os.OpenFile(tw.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)` and the
// mode-0600 assertion fails (perm becomes 0644) and the symlink sub-case fails
// (the raw open follows the symlink).
func TestRotateUsesHardenedOpen(t *testing.T) {
	t.Run("mode-0600", func(t *testing.T) {
		dir := t.TempDir()
		old := traceLogDir
		traceLogDir = dir
		defer func() { traceLogDir = old }()

		tw, err := NewTraceWriter(&config.FlowTraceoptions{File: "rot.log"})
		if err != nil {
			t.Fatal(err)
		}
		defer tw.Close()
		if _, err := tw.file.WriteString("seed\n"); err != nil {
			t.Fatal(err)
		}
		tw.rotate()
		active := filepath.Join(dir, "rot.log")
		fi, err := os.Stat(active)
		if err != nil {
			t.Fatalf("active trace file missing after rotate: %v", err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("rotated active file mode = %o, want 0600 (rotate must use openTraceFile)", perm)
		}
		if _, err := os.Stat(active + ".1"); err != nil {
			t.Fatalf("rotated archive rot.log.1 missing: %v", err)
		}
	})

	t.Run("nofollow-symlink", func(t *testing.T) {
		dir := t.TempDir()
		old := traceLogDir
		traceLogDir = dir
		defer func() { traceLogDir = old }()

		tw, err := NewTraceWriter(&config.FlowTraceoptions{File: "rot2.log"})
		if err != nil {
			t.Fatal(err)
		}
		defer tw.Close()

		// Simulate the active file having been rolled away (as rotate does) and a
		// symlink pre-planted at the active path before the fresh reopen. A
		// hardened reopen (openTraceFile, O_NOFOLLOW) must refuse it; a raw
		// os.OpenFile would follow it and create the target.
		active := filepath.Join(dir, "rot2.log")
		tw.file.Close()
		tw.file = nil
		os.Remove(active)
		target := filepath.Join(t.TempDir(), "victim")
		if err := os.Symlink(target, active); err != nil {
			t.Fatal(err)
		}
		f, err := openTraceFile(tw.name)
		if err == nil {
			if f != nil {
				f.Close()
			}
			t.Fatalf("rotate reopen followed a symlink at the active path, want O_NOFOLLOW rejection")
		}
		if _, statErr := os.Stat(target); statErr == nil {
			t.Fatalf("symlink target %s was created (followed)", target)
		}
	})
}

// TestNewTraceWriterNoFollowSymlink verifies O_NOFOLLOW: a symlink pre-planted
// at the trace path is not followed, so a writable-/var/log attacker cannot
// redirect telemetry to an arbitrary target (#3420).
func TestNewTraceWriterNoFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	target := filepath.Join(t.TempDir(), "victim")
	link := filepath.Join(dir, "flow.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	tw, err := NewTraceWriter(&config.FlowTraceoptions{File: "flow.log"})
	if err == nil {
		if tw != nil {
			tw.Close()
		}
		t.Fatalf("NewTraceWriter opened through a symlink, want O_NOFOLLOW rejection")
	}
	if _, statErr := os.Stat(target); statErr == nil {
		t.Fatalf("symlink target %s was created (followed)", target)
	}
}

// TestMatchFiltersProtocol verifies the M8 (#2008) traceoptions packet-filter
// `protocol` match: a filter with protocol set matches only records of that
// protocol, accepts both Junos protocol names and numbers, and an unset
// protocol matches any protocol.
func TestMatchFiltersProtocol(t *testing.T) {
	tests := []struct {
		name        string
		filterProto string // config value (name or number); "" = no protocol filter
		recProto    string // EventRecord.Protocol (as rendered by protoName)
		want        bool
	}{
		{"name-tcp-matches-tcp", "tcp", "TCP", true},
		{"name-tcp-rejects-udp", "tcp", "UDP", false},
		{"name-udp-matches-udp", "udp", "UDP", true},
		{"name-icmp-matches-icmp", "icmp", "ICMP", true},
		{"name-icmp6-matches-icmpv6", "icmp6", "ICMPv6", true},
		{"number-6-matches-tcp", "6", "TCP", true},
		{"number-17-matches-udp", "17", "UDP", true},
		{"number-1-matches-icmp", "1", "ICMP", true},
		{"number-58-matches-icmpv6", "58", "ICMPv6", true},
		{"number-6-rejects-udp", "6", "UDP", false},
		{"unconfigured-matches-tcp", "", "TCP", true},
		{"unconfigured-matches-udp", "", "UDP", true},
		{"uppercase-config-matches", "TCP", "TCP", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := traceFilter{name: "f"}
			if tt.filterProto != "" {
				n, ok := appid.ProtocolNumber(tt.filterProto)
				if !ok {
					t.Fatalf("filter proto %q unresolvable", tt.filterProto)
				}
				f.protoNum, f.hasProto = n, true
			}
			tw := &TraceWriter{filters: []traceFilter{f}}
			// Production records carry ProtocolNum; derive it from the rendered
			// name here the same way ringbuf does (protoName inverse for these).
			recNum, _ := appid.ProtocolNumber(tt.recProto)
			rec := EventRecord{
				SrcAddr:     "10.0.1.5:1000",
				DstAddr:     "10.0.2.5:80",
				Protocol:    tt.recProto,
				ProtocolNum: recNum,
			}
			if got := tw.matchFilters(rec); got != tt.want {
				t.Errorf("matchFilters(proto-filter=%q, rec=%q) = %v, want %v",
					tt.filterProto, tt.recProto, got, tt.want)
			}
		})
	}
}

// TestMatchFiltersProtocolWithPrefix verifies protocol is ANDed with the
// existing source/destination prefix match: a record matches only when it
// satisfies prefix AND protocol.
func TestMatchFiltersProtocolWithPrefix(t *testing.T) {
	tcpNum, _ := appid.ProtocolNumber("tcp")
	tw := &TraceWriter{
		filters: []traceFilter{{
			name:     "f",
			srcNet:   netip.MustParsePrefix("10.0.1.0/24"),
			protoNum: tcpNum, hasProto: true,
		}},
	}

	cases := []struct {
		src   string
		proto string
		want  bool
	}{
		{"10.0.1.5:1000", "TCP", true},  // prefix + proto both match
		{"10.0.1.5:1000", "UDP", false}, // prefix matches, proto does not
		{"10.0.9.5:1000", "TCP", false}, // proto matches, prefix does not
	}
	for _, c := range cases {
		rec := EventRecord{SrcAddr: c.src, DstAddr: "10.0.2.5:80", Protocol: c.proto}
		if got := tw.matchFilters(rec); got != c.want {
			t.Errorf("matchFilters(src=%s proto=%s) = %v, want %v", c.src, c.proto, got, c.want)
		}
	}
}

// TestTraceWriter_WriteFailureObservable pins #3478 H21: a swallowed trace
// write error is now counted in DroppedWrites so lost audit telemetry is
// detectable.
//
// RED-on-revert: remove the `tw.droppedWrites.Add(1)` in HandleEvent and the
// counter stays 0.
func TestTraceWriter_WriteFailureObservable(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	tw, err := NewTraceWriter(&config.FlowTraceoptions{File: "flow.log"})
	if err != nil {
		t.Fatal(err)
	}
	defer tw.Close()

	// Close the fd out from under the writer so the next write fails (EBADF)
	// while tw.file is still non-nil.
	if err := tw.file.Close(); err != nil {
		t.Fatal(err)
	}
	tw.HandleEvent(EventRecord{Type: "SESSION_OPEN"}, nil)
	// #9025: HandleEvent enqueues; drain before asserting on the file/counters.
	tw.SyncForTest()

	if got := tw.DroppedWrites(); got != 1 {
		t.Fatalf("DroppedWrites = %d, want 1 (trace write failure not observable)", got)
	}
}

// TestTraceWriter_RotationFailureObservable pins #3478 H22 + item 6: a rotation
// whose primary rename cannot complete (a) returns a non-nil error, (b) bumps
// FailedRotations, and (c) re-syncs `written` to the real file size rather than
// resetting to a bogus 0. Calling rotate() directly pins all three.
//
// RED-on-revert: make rotate() ignore the rename result and unconditionally set
// written=0 / return nil — the error-return, the written==realSize, and the
// FailedRotations assertions all fail.
func TestTraceWriter_RotationFailureObservable(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	// FileCount=1 / FileSize=40 so the generation-shift loop does not run and
	// cannot move our blocking directory aside before the primary rename. These
	// are below the #3424 commit bounds, so NewTraceWriter clamps them; set the
	// writer fields directly afterward to exercise rotate() mechanics with the
	// intended tiny size / single file (the clamp governs the config->writer
	// path, not this white-box rotate() unit test).
	tw, err := NewTraceWriter(&config.FlowTraceoptions{File: "flow.log"})
	if err != nil {
		t.Fatal(err)
	}
	defer tw.Close()
	tw.maxSize = 40
	tw.maxFiles = 1

	if _, err := tw.file.WriteString("0123456789012345678901234567890123456789\n"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(tw.path)
	if err != nil {
		t.Fatal(err)
	}
	realSize := fi.Size()
	tw.written = 999 // deliberately wrong to prove rotate() re-syncs to real size

	// Block the primary rename target with a non-empty directory so
	// os.Rename(path, path+".1") fails.
	archive := tw.path + ".1"
	if err := os.Mkdir(archive, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archive, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if rerr := tw.rotate(); rerr == nil {
		t.Fatal("rotate() returned nil on a failed primary rename, want a non-nil error")
	}
	if got := tw.FailedRotations(); got == 0 {
		t.Fatalf("FailedRotations = 0, want >=1 (failed rename not observable)")
	}
	if tw.written != realSize {
		t.Fatalf("written = %d after a failed rotation, want re-synced to real size %d (not a bogus 0/stale value)", tw.written, realSize)
	}
}

// TestTraceWriter_GenerationShiftFailureObservable pins #3478 item 2: a failed
// retained-generation shift (old->next) is counted and surfaced even when the
// active-file rotation itself succeeds.
//
// RED-on-revert: drop the failedRotations.Add(1)+shiftErr in the shift loop and
// both assertions fail.
func TestTraceWriter_GenerationShiftFailureObservable(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	// FileCount=2 so the shift loop runs once: rename .1 -> .2.
	tw, err := NewTraceWriter(&config.FlowTraceoptions{File: "flow.log", FileCount: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer tw.Close()

	if err := os.WriteFile(tw.path+".1", []byte("gen1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(tw.path+".2", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tw.path+".2", "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	rerr := tw.rotate()
	if rerr == nil {
		t.Fatal("rotate() returned nil despite a failed generation shift, want a non-nil error")
	}
	if got := tw.FailedRotations(); got == 0 {
		t.Fatalf("FailedRotations = 0, want >=1 (generation-shift failure not observable)")
	}
}

// TestTraceWriter_NilFileDropObservable pins #3478 item 1: a HandleEvent on a
// writer whose file is nil (here via Close, the state a failed rotation reopen
// leaves) increments DroppedWrites rather than returning silently.
//
// RED-on-revert: restore the bare `return` on the tw.file==nil branch without
// the droppedWrites.Add(1) and the counter stays 0.
func TestTraceWriter_NilFileDropObservable(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	tw, err := NewTraceWriter(&config.FlowTraceoptions{File: "flow.log"})
	if err != nil {
		t.Fatal(err)
	}
	tw.Close() // file = nil

	tw.HandleEvent(EventRecord{Type: "SESSION_OPEN"}, nil)
	// #9025: HandleEvent enqueues; drain before asserting on the file/counters.
	tw.SyncForTest()
	if got := tw.DroppedWrites(); got != 1 {
		t.Fatalf("DroppedWrites = %d, want 1 (nil-file drop not observable)", got)
	}
}

// TestTraceWriter_TightensExistingMode pins #3477 item 3: opening an existing
// 0644 trace file tightens it to 0600.
//
// RED-on-revert: remove the fchmod-on-existing block in openHardenedAuditLog
// and the mode stays 0644.
func TestTraceWriter_TightensExistingMode(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	path := filepath.Join(dir, "flow.log")
	if err := os.WriteFile(path, []byte("legacy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil { // defeat umask
		t.Fatal(err)
	}
	tw, err := NewTraceWriter(&config.FlowTraceoptions{File: "flow.log"})
	if err != nil {
		t.Fatal(err)
	}
	defer tw.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("existing trace-file mode = %o after open, want tightened to 0600", perm)
	}
}
