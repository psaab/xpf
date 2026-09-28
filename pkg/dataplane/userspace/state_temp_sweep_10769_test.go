package userspace

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseStateTempInstance(t *testing.T) {
	for _, tc := range []struct {
		middle string
		want   tempWriterInstance
		wantOK bool
	}{
		{"123_456.7", tempWriterInstance{pid: 123, startTime: 456}, true},
		{"1_2.0", tempWriterInstance{pid: 1, startTime: 2}, true},
		{"123_456", tempWriterInstance{}, false},        // no seq
		{"123.7", tempWriterInstance{}, false},          // no instance
		{"123_456.x", tempWriterInstance{}, false},      // non-numeric seq
		{"abc_456.7", tempWriterInstance{}, false},      // non-numeric pid
		{"123_abc.7", tempWriterInstance{}, false},      // non-numeric start
		{"_456.7", tempWriterInstance{}, false},         // empty pid
		{"123_.7", tempWriterInstance{}, false},         // empty start
		{"123_456.", tempWriterInstance{}, false},       // empty seq
		{"4294967296_1.1", tempWriterInstance{}, false}, // pid overflows u32
	} {
		got, ok := parseStateTempInstance(tc.middle)
		if ok != tc.wantOK || (ok && got != tc.want) {
			t.Errorf("parseStateTempInstance(%q) = %+v,%v; want %+v,%v",
				tc.middle, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestSweepStaleStateTemps(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "state.json")
	self := uint32(os.Getpid())
	selfStart, ok := procStartTime(self)
	if !ok {
		t.Skip("no /proc in test environment")
	}
	dead := fmt.Sprintf("state.json.%d_%d.1.tmp", self, selfStart+1000000)
	liveSelf := fmt.Sprintf("state.json.%d_%d.2.tmp", self, selfStart)
	noproc := "state.json.4250000000_1.3.tmp"
	otherDest := "other.json.1_1.1.tmp"
	nonTemp := "state.json.bak"
	for _, name := range []string{dead, liveSelf, noproc, otherDest, nonTemp} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	live, err := SweepStaleStateTemps(dest)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	// Dead instances (wrong start time, nonexistent pid) are swept.
	for _, name := range []string{dead, noproc} {
		if _, serr := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(serr) {
			t.Errorf("dead temp %s survived: %v", name, serr)
		}
	}
	// Our own in-flight temp is always preserved and reported.
	if len(live) != 1 || filepath.Base(live[0]) != liveSelf {
		t.Fatalf("live skipped = %v, want exactly [%s]", live, liveSelf)
	}
	if _, serr := os.Lstat(filepath.Join(dir, liveSelf)); serr != nil {
		t.Fatalf("live temp must survive: %v", serr)
	}
	// Non-matching names are untouched.
	for _, name := range []string{otherDest, nonTemp} {
		if _, serr := os.Lstat(filepath.Join(dir, name)); serr != nil {
			t.Errorf("out-of-scope %s must survive: %v", name, serr)
		}
	}
}

// TestTempSweepMatchesRustWriter pins the cross-language temp contract
// against the Rust source of truth (mirroring the DEFAULT_STATE_FILE
// agreement): the Go matcher must track state_writer.rs naming, instance
// parsing, and liveness rules, or the reset sweep and the helper sweep
// disagree about what an orphan is.
func TestTempSweepMatchesRustWriter(t *testing.T) {
	src, err := os.ReadFile("../../../userspace-dp/src/state_writer.rs")
	if err != nil {
		t.Fatalf("read state_writer.rs: %v", err)
	}
	body := string(src)
	for _, want := range []string{
		"<dest>.<pid>_<starttime>.<seq>.tmp",
		".tmp",
		"split_once('_')",
		"inst.start_time != 0",
		"sweep_stale_temps",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("state_writer.rs no longer contains %q — re-verify the Go sweep mirrors it", want)
		}
	}
}
