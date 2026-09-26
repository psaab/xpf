package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/logging"
)

// #3378: the flow-trace file was opened by raw "/var/log/"+name concatenation,
// with no path sanitization, mode 0644 (world-readable telemetry) and no
// symlink guard. These tests pin the hardened behavior.

func TestSanitizeTraceFilename_RejectsTraversal(t *testing.T) {
	bad := []string{
		"",
		".",
		"..",
		"../../etc/xpf-flow",
		"/etc/passwd",
		"sub/dir/trace",
		`sub\dir\trace`,
		"foo/..",
	}
	for _, name := range bad {
		if err := sanitizeTraceFilename(name); err == nil {
			t.Errorf("sanitizeTraceFilename(%q) = nil, want error (traversal must be rejected)", name)
		}
	}

	good := []string{"trace", "flow-trace.log", "trace_2026"}
	for _, name := range good {
		if err := sanitizeTraceFilename(name); err != nil {
			t.Errorf("sanitizeTraceFilename(%q) = %v, want nil (bare name)", name, err)
		}
	}
}

func TestHandleMonitorSecurityFlowFile_RejectsTraversalFilename(t *testing.T) {
	c := &CLI{}
	if err := c.handleMonitorSecurityFlowFile([]string{"../../etc/xpf-flow"}); err != nil {
		t.Fatalf("unexpected error return (should print + return nil): %v", err)
	}
	if c.monitorFlow == nil {
		t.Fatal("monitorFlow not initialized")
	}
	if c.monitorFlow.filename != "" {
		t.Fatalf("traversal filename was stored: %q (must be rejected)", c.monitorFlow.filename)
	}
}

func TestOpenTraceFile_Mode0600(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	// Force a permissive umask for the duration of the test. Without this a
	// reverted 0644 create mode would be masked down to 0600 under an inherited
	// umask of 077 and the assertion below would pass falsely. With umask 0 a
	// reverted 0644 actually lands on disk as 0644 and turns this test RED.
	oldMask := syscall.Umask(0)
	defer syscall.Umask(oldMask)

	f, path, err := openTraceFile("trace")
	if err != nil {
		t.Fatalf("openTraceFile error: %v", err)
	}
	defer f.Close()
	if path != filepath.Join(dir, "trace") {
		t.Fatalf("path = %q, want %q", path, filepath.Join(dir, "trace"))
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("trace file perm = %o, want 0600 (must not be world-readable)", perm)
	}
}

func TestOpenTraceFile_RefusesSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	// A pre-planted symlink under the log dir pointing at an attacker target.
	target := filepath.Join(dir, "secret-target")
	link := filepath.Join(dir, "trace")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	f, _, err := openTraceFile("trace")
	if err == nil {
		f.Close()
		t.Fatal("openTraceFile followed a symlink; O_NOFOLLOW must refuse it")
	}
	// The symlink target must NOT have been created/written.
	if _, statErr := os.Lstat(target); statErr == nil {
		t.Fatal("symlink target was created; the redirected write was not refused")
	}
}

// #3379: size/files rotation params were parsed but the writer never rotated,
// allowing unbounded log growth. This pins enforcement: writing past `size`
// rotates and the file count is capped at `files` generations.
func TestTraceWriter_RotatesAndCapsFiles(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	const name = "trace"
	const maxFiles = 3
	f, _, err := openTraceFile(name)
	if err != nil {
		t.Fatalf("openTraceFile: %v", err)
	}
	// Small cap so a handful of ~25-byte lines forces several rotations.
	w := newTraceWriter(name, f, 40, maxFiles)
	for i := 0; i < 50; i++ {
		if err := w.writeLine("flow-trace-line-padding-xx"); err != nil {
			t.Fatalf("writeLine[%d]: %v", i, err)
		}
	}
	w.close()

	base := filepath.Join(dir, name)
	// The active file plus exactly (maxFiles-1) archives must exist.
	if _, err := os.Stat(base); err != nil {
		t.Fatalf("active trace file missing: %v", err)
	}
	for i := 1; i <= maxFiles-1; i++ {
		if _, err := os.Stat(base + "." + itoa(i)); err != nil {
			t.Fatalf("expected archive %s.%d to exist: %v", base, i, err)
		}
	}
	// No generation beyond the cap may survive.
	if _, err := os.Stat(base + "." + itoa(maxFiles)); err == nil {
		t.Fatalf("generation %s.%d exists; files cap (%d) not enforced", base, maxFiles, maxFiles)
	}
	// The active file itself must respect the size cap.
	fi, err := os.Stat(base)
	if err != nil {
		t.Fatalf("stat active: %v", err)
	}
	if fi.Size() > 40 {
		t.Fatalf("active file size %d exceeds cap 40; rotation not triggered", fi.Size())
	}
}

func itoa(i int) string {
	return string(rune('0' + i))
}

// #3380: the flow file/filter parsers committed state incrementally and had no
// default case, so a failed option mutated the filename, an empty/invalid
// filter became match-all, and unknown/value-less tokens were silently dropped
// (widening forensic collection). These tests pin the atomic, fail-closed
// behavior.

func TestFlowFile_FailedOptionDoesNotMutateFilename(t *testing.T) {
	c := &CLI{}
	// Bad size must abort the whole command without storing the filename.
	if err := c.handleMonitorSecurityFlowFile([]string{"trace", "size", "1"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.monitorFlow.filename != "" {
		t.Fatalf("filename = %q, want empty (failed size must not commit filename)", c.monitorFlow.filename)
	}
}

func TestFlowFile_UnknownOptionRejected(t *testing.T) {
	c := &CLI{}
	if err := c.handleMonitorSecurityFlowFile([]string{"trace", "bogus", "x"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Unknown token must abort: nothing committed.
	if c.monitorFlow.filename != "" {
		t.Fatalf("filename = %q, want empty (unknown option must reject the command)", c.monitorFlow.filename)
	}
}

func TestFlowFile_MissingOptionValueRejected(t *testing.T) {
	c := &CLI{}
	if err := c.handleMonitorSecurityFlowFile([]string{"trace", "size"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.monitorFlow.filename != "" {
		t.Fatalf("filename = %q, want empty (value-less size must reject)", c.monitorFlow.filename)
	}
}

func TestFlowFilter_EmptyFilterRejected(t *testing.T) {
	c := &CLI{}
	// A filter name with no criteria must NOT be installed (empty == match-all).
	if err := c.handleMonitorSecurityFlowFilter([]string{"f1"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := c.monitorFlow.filters["f1"]; ok {
		t.Fatal("empty filter was installed; an empty filter matches everything (fail-open)")
	}
}

func TestFlowFilter_FailedOptionLeavesNoFilter(t *testing.T) {
	c := &CLI{}
	// Invalid source-port must abort and must NOT leave an empty match-all filter.
	if err := c.handleMonitorSecurityFlowFilter([]string{"f1", "source-port", "notaport"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := c.monitorFlow.filters["f1"]; ok {
		t.Fatal("failed filter command left an (empty, match-all) filter installed")
	}
}

func TestFlowFilter_UnknownTokenRejected(t *testing.T) {
	c := &CLI{}
	// 'from-zone' is a packet-drop token, not a valid flow-filter token.
	if err := c.handleMonitorSecurityFlowFilter([]string{"f1", "from-zone", "trust"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := c.monitorFlow.filters["f1"]; ok {
		t.Fatal("unknown filter token was silently dropped and the filter installed")
	}
}

func TestFlowFilter_ValidCriterionCommits(t *testing.T) {
	c := &CLI{}
	if err := c.handleMonitorSecurityFlowFilter([]string{"f1", "protocol", "tcp"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	f, ok := c.monitorFlow.filters["f1"]
	if !ok {
		t.Fatal("valid filter was not installed")
	}
	if f.Protocol != "tcp" {
		t.Fatalf("protocol = %q, want tcp", f.Protocol)
	}
}

// #3378 (open-time hardening): openTraceFile must independently reject
// traversal/separator names even if the parse-time sanitizeTraceFilename guard
// were bypassed. This pins the open-site sanitize call directly, not just the
// command-handler path covered above.
func TestOpenTraceFile_RejectsTraversalAtOpen(t *testing.T) {
	dir := t.TempDir()
	old := traceLogDir
	traceLogDir = dir
	defer func() { traceLogDir = old }()

	for _, name := range []string{"../escape", "a/b"} {
		f, _, err := openTraceFile(name)
		if err == nil {
			f.Close()
			t.Fatalf("openTraceFile(%q) = nil error, want rejection (open-time sanitize must block traversal/separators)", name)
		}
	}

	// RED-on-revert anchor: with the sanitize call removed from openTraceFile,
	// "../escape" resolves to a sibling of traceLogDir and the root-written
	// file is actually created there. Assert nothing escaped the log dir.
	escaped := filepath.Join(filepath.Dir(dir), "escape")
	if _, err := os.Stat(escaped); err == nil {
		os.Remove(escaped)
		t.Fatalf("a trace file escaped traceLogDir to %s; open-time sanitize did not block traversal", escaped)
	}
}

// #3380 (atomic parse default-reject): the packet-drop parser must reject an
// unknown token or a value-less option instead of silently skipping it (which
// would widen forensic collection). The handler reaches the event-subscription
// loop only on a fully accepted parse; with a nil eventBuf that manifests as a
// panic in Subscribe, while a parse-time rejection returns before touching the
// buffer. reachedEventLoop turns that distinction into a boolean.
func reachedEventLoop(t *testing.T, c *CLI, args []string) (reached bool) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			reached = true
		}
	}()
	_ = c.handleMonitorSecurityPacketDrop(args)
	return false
}

func TestPacketDrop_RejectsUnknownToken(t *testing.T) {
	c := &CLI{} // nil eventBuf: a rejected parse never reaches Subscribe.
	if reachedEventLoop(t, c, []string{"bogus", "x"}) {
		t.Fatal("unknown packet-drop token was not rejected (parser fell through to the event loop)")
	}
}

func TestPacketDrop_RejectsMissingOptionValue(t *testing.T) {
	c := &CLI{}
	if reachedEventLoop(t, c, []string{"count"}) {
		t.Fatal("value-less packet-drop option was not rejected (parser fell through to the event loop)")
	}
}
func TestMonitorPacketDropReportsSubscriberOverrun_10834(t *testing.T) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	os.Stdout = w

	eb := logging.NewEventBuffer(512)
	c := &CLI{eventBuf: eb}
	done := make(chan error, 1)
	go func() {
		done <- c.handleMonitorSecurityPacketDrop(nil)
	}()

	var cancelCmd func()
	defer func() {
		if cancelCmd != nil {
			cancelCmd()
		}
		_ = r.Close()
		_ = w.Close()
		os.Stdout = oldStdout
	}()
	deadline := time.Now().Add(2 * time.Second)
	for cancelCmd == nil && time.Now().Before(deadline) {
		c.cmdMu.Lock()
		cancelCmd = c.cmdCancel
		c.cmdMu.Unlock()
		time.Sleep(time.Millisecond)
	}
	if cancelCmd == nil {
		t.Fatal("packet-drop command did not subscribe")
	}

	const storm = 10000
	for range storm {
		eb.Add(logging.EventRecord{
			Time: time.Now(), Type: "POLICY_DENY", SrcAddr: "10.0.1.1:1000",
			DstAddr: "10.0.2.1:80", Protocol: "TCP", Action: "deny",
		})
	}
	dropped := eb.DroppedTotal()
	if dropped == 0 {
		t.Fatal("bounded event storm did not overrun the packet-drop subscriber")
	}

	lines := make(chan string, 20000)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		defer close(lines)
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()

	var reported uint64
	recordMarker := func(line string) {
		var lost uint64
		if n, err := fmt.Sscanf(line, "** %d records lost (overrun) **", &lost); n == 1 && err == nil {
			reported += lost
		}
	}
	deadline = time.Now().Add(2 * time.Second)
	for reported < dropped && time.Now().Before(deadline) {
		select {
		case line := <-lines:
			recordMarker(line)
		case <-time.After(time.Millisecond):
		}
	}
	cancelCmd()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("packet-drop command returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("packet-drop command did not stop after cancellation")
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close captured stdout: %v", err)
	}
	os.Stdout = oldStdout
	sawFinalCount := false
	for line := range lines {
		recordMarker(line)
		if line == fmt.Sprintf("dropped=%d", dropped) {
			sawFinalCount = true
		}
	}
	if reported != dropped {
		t.Fatalf("packet-drop gap markers report %d lost records, want %d", reported, dropped)
	}
	if !sawFinalCount {
		t.Errorf("packet-drop output omitted final dropped=%d count", dropped)
	}
}
