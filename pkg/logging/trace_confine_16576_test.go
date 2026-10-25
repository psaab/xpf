package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16576: the persistent TraceWriter was not confined like the #5038 CLI
// writer — traceLogDir was /var/log itself, so `file syslog` / `file auth.log`
// chmodded, appended to and rotated the live host log. These tests pin the
// dedicated-dir confinement with a seeded host-log tree as the control.

// hostLogNames are the bare names that must never be touched in the parent.
var hostLogNames16576 = []string{"syslog", "auth.log", "wtmp", "btmp", "kern.log"}

func seedHostLogs16576(t *testing.T, parent string) map[string]string {
	t.Helper()
	seeded := map[string]string{}
	for _, name := range hostLogNames16576 {
		body := "HOST-RECORD " + name + "\n"
		p := filepath.Join(parent, name)
		if err := os.WriteFile(p, []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
		seeded[name] = body
		for _, gen := range []string{".1", ".2"} {
			gbody := "HOST-GEN " + name + gen + "\n"
			if err := os.WriteFile(p+gen, []byte(gbody), 0o640); err != nil {
				t.Fatal(err)
			}
			seeded[name+gen] = gbody
		}
	}
	return seeded
}

func assertHostLogsUntouched16576(t *testing.T, parent string, seeded map[string]string) {
	t.Helper()
	for name, want := range seeded {
		p := filepath.Join(parent, name)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("host log %s missing after trace: %v", name, err)
		}
		if string(b) != want {
			t.Fatalf("host log %s content = %q, want byte-identical %q", name, b, want)
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o640 {
			t.Fatalf("host log %s mode = %o, want 0640 (writer must not chmod it)", name, perm)
		}
	}
}

// TestTraceWriterConfined16576HostLogsUntouched is the RED-on-revert guard:
// with traceLogDir = /var/log (pre-fix) the writer opens the seeded syslog
// directly, chmods it 0600 and rotates it, so the parent assertions fail.
func TestTraceWriterConfined16576HostLogsUntouched(t *testing.T) {
	// Shorten the wedge-recovery backoff (#9118) so a rotation-reopen race
	// cannot wedge this writer for the production 1s inside the test.
	oldBackoff := reopenBackoff9118
	reopenBackoff9118 = 0
	t.Cleanup(func() { reopenBackoff9118 = oldBackoff })
	for _, name := range hostLogNames16576 {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir() // stands in for /var/log
			seeded := seedHostLogs16576(t, parent)
			confined := filepath.Join(parent, "xpf-flow-trace")

			old := traceLogDir
			traceLogDir = confined
			defer func() { traceLogDir = old }()

			tw, err := NewTraceWriter(&config.FlowTraceoptions{
				File: name, FileSize: 10240, FileCount: 2,
				Flags: []string{"basic-datapath"},
			})
			if err != nil {
				t.Fatalf("NewTraceWriter(%q): %v", name, err)
			}
			// Drive events through the writer and force rotations.
			rec := EventRecord{Type: "SESSION_OPEN", Action: "PERMIT", Protocol: "tcp", SrcAddr: "10.0.0.1:1234", DstAddr: "10.0.0.2:80"}
			for range 600 {
				tw.HandleEvent(rec, nil)
			}
			tw.SyncForTest()
			tw.Close()
			assertHostLogsUntouched16576(t, parent, seeded)

			// Control: tracing still happened, inside the confined dir only.
			entries, err := os.ReadDir(confined)
			if err != nil {
				t.Fatalf("confined trace dir not created: %v", err)
			}
			found := false
			nonEmpty := false
			for _, e := range entries {
				if e.Name() == name || strings.HasPrefix(e.Name(), name+".") {
					found = true
					if b, err := os.ReadFile(filepath.Join(confined, e.Name())); err == nil && len(b) > 0 {
						nonEmpty = true
					}
				}
			}
			if !found {
				t.Fatalf("no trace file for %q inside confined dir %q (entries: %v)", name, confined, entries)
			}
			if !nonEmpty {
				t.Fatalf("confined trace files for %q are all empty", name)
			}
			fi, err := os.Stat(confined)
			if err != nil {
				t.Fatal(err)
			}
			if perm := fi.Mode().Perm(); perm != 0o700 {
				t.Fatalf("confined dir mode = %o, want 0700", perm)
			}
		})
	}
}

// TestTraceLogDirDefaultIsDedicated16576 pins the production default: a
// dedicated subdirectory under /var/log, never /var/log itself.
func TestTraceLogDirDefaultIsDedicated16576(t *testing.T) {
	if traceLogDir == "/var/log" || !strings.HasPrefix(traceLogDir, "/var/log/") {
		t.Fatalf("traceLogDir = %q, want a dedicated subdirectory under /var/log", traceLogDir)
	}
	if got := TraceLogDir(); got != traceLogDir {
		t.Fatalf("TraceLogDir() = %q, want %q", got, traceLogDir)
	}
}

// TestTraceWriterRefusesSymlinkedDir16576 pins the #8482 parent check on the
// persistent writer: a symlinked trace dir must be refused, not followed.
func TestTraceWriterRefusesSymlinkedDir16576(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "elsewhere")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "linkdir")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	old := traceLogDir
	traceLogDir = link
	defer func() { traceLogDir = old }()

	tw, err := NewTraceWriter(&config.FlowTraceoptions{File: "flow.log"})
	if err == nil {
		if tw != nil {
			tw.Close()
		}
		t.Fatal("NewTraceWriter followed a symlinked trace dir, want refusal")
	}
	if _, statErr := os.Stat(filepath.Join(target, "flow.log")); statErr == nil {
		t.Fatal("trace file was created through the symlinked dir")
	}

	// A non-directory at the trace path is also refused.
	file := filepath.Join(base, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	traceLogDir = file
	if tw, err := NewTraceWriter(&config.FlowTraceoptions{File: "flow.log"}); err == nil {
		if tw != nil {
			tw.Close()
		}
		t.Fatal("NewTraceWriter accepted a non-directory trace path, want refusal")
	}
}
