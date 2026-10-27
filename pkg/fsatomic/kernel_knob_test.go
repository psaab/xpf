package fsatomic

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeKnobFS is an in-memory knobFS for hermetic (class U) tests. It is
// safe for concurrent use (the race cells drive Assert/Release from
// several goroutines).
type fakeKnobFS struct {
	mu       sync.Mutex
	vals     map[string]string
	writeErr map[string]error
	readErr  map[string]error
	writes   []string
	// onWrite, when set, runs inside WriteFile while the fake's lock is
	// NOT held, after the value lands. The race cell uses it to land a
	// re-assert in the middle of a restore write.
	onWrite func(path string)
}

func newFakeKnobFS(seed map[string]string) *fakeKnobFS {
	m := make(map[string]string, len(seed))
	for k, v := range seed {
		m[k] = v
	}
	return &fakeKnobFS{vals: m, writeErr: map[string]error{}, readErr: map[string]error{}}
}

func (f *fakeKnobFS) ReadFile(path string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.readErr[path]; err != nil {
		return nil, err
	}
	v, ok := f.vals[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return []byte(v), nil
}

func (f *fakeKnobFS) WriteFile(path string, data []byte) error {
	f.mu.Lock()
	if err := f.writeErr[path]; err != nil {
		f.mu.Unlock()
		return err
	}
	f.vals[path] = string(data)
	f.writes = append(f.writes, path+"="+strings.TrimSpace(string(data)))
	hook := f.onWrite
	f.mu.Unlock()
	if hook != nil {
		hook(path)
	}
	return nil
}

// value returns the current fake value of path (locked read for race cells).
func (f *fakeKnobFS) value(path string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.TrimSpace(f.vals[path])
}

// writeCount returns how many writes have landed (locked read for race cells).
func (f *fakeKnobFS) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes)
}

func TestWriteKernelKnob17068(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "knob")
	if err := os.WriteFile(p, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := WriteKernelKnob(p, "1")
	if err != nil || !changed {
		t.Fatalf("WriteKernelKnob changed=%v err=%v, want true/nil", changed, err)
	}
	b, _ := os.ReadFile(p)
	if strings.TrimSpace(string(b)) != "1" {
		t.Fatalf("value=%q want 1", b)
	}
	// Read-compare-skip: second write is a no-op.
	changed, err = WriteKernelKnob(p, "1")
	if err != nil || changed {
		t.Fatalf("second WriteKernelKnob changed=%v err=%v, want false/nil", changed, err)
	}
	changed, err = WriteKernelKnobVerified(p, "0")
	if err != nil || !changed {
		t.Fatalf("WriteKernelKnobVerified changed=%v err=%v", changed, err)
	}
}

// Acceptance (2) at the primitive layer: assert then release returns the
// knob to its pre-assert value. This is the fib_multipath_hash_policy
// cell, exercised hermetically against a fake FS.
func TestKernelKnobsFibRestore17068(t *testing.T) {
	const path = "/proc/sys/net/ipv4/fib_multipath_hash_policy"
	fs := newFakeKnobFS(map[string]string{path: "0\n"})
	reg := newKernelKnobsFS(fs)
	if err := reg.Assert(path, "1", "fib", RestorePrior); err != nil {
		t.Fatalf("Assert: %v", err)
	}
	if got := strings.TrimSpace(fs.vals[path]); got != "1" {
		t.Fatalf("after assert value=%q want 1", got)
	}
	if failed := reg.Release("fib"); len(failed) != 0 {
		t.Fatalf("Release failed=%v", failed)
	}
	if got := strings.TrimSpace(fs.vals[path]); got != "0" {
		t.Fatalf("after release value=%q want restored 0", got)
	}
}

// Acceptance (3): a second owner asserting an owned path fails and
// writes nothing — the nf_conntrack_tcp_loose divergence guard.
func TestKernelKnobsSecondOwnerRejected17068(t *testing.T) {
	const path = "/proc/sys/net/netfilter/nf_conntrack_tcp_loose"
	fs := newFakeKnobFS(map[string]string{path: "1\n"})
	reg := newKernelKnobsFS(fs)
	if err := reg.Assert(path, "0", "posture", RestorePrior); err != nil {
		t.Fatalf("first Assert: %v", err)
	}
	writesBefore := len(fs.writes)
	if err := reg.Assert(path, "1", "other", RestorePrior); err == nil {
		t.Fatal("second owner Assert succeeded, want error")
	}
	if len(fs.writes) != writesBefore {
		t.Fatalf("second owner wrote: writes=%v", fs.writes)
	}
	if got := strings.TrimSpace(fs.vals[path]); got != "0" {
		t.Fatalf("value=%q want untouched 0", got)
	}
	if owner, ok := reg.Owner(path); !ok || owner != "posture" {
		t.Fatalf("Owner=%q,%v want posture,true", owner, ok)
	}
}

// Capture-failure cell: a first assert whose prior cannot be read must
// fail, register no capture, and write nothing — never poison the prior
// to "" for a later Release to "restore". This is the knob-absent-until-
// module-load shape (nf_conntrack_tcp_loose before conntrack loads).
func TestKernelKnobsCaptureFailureFails17068(t *testing.T) {
	const path = "/proc/sys/net/netfilter/nf_conntrack_tcp_loose"
	fs := newFakeKnobFS(map[string]string{})
	fs.readErr[path] = errors.New("ENOENT: conntrack not loaded")
	reg := newKernelKnobsFS(fs)
	if err := reg.Assert(path, "0", "posture", RestorePrior); err == nil {
		t.Fatal("Assert with unreadable prior succeeded, want error")
	}
	if _, ok := reg.Owner(path); ok {
		t.Fatal("capture registered despite failed capture read")
	}
	if n := fs.writeCount(); n != 0 {
		t.Fatalf("assert wrote %d times despite failed capture", n)
	}
	// Recovery: once the knob is readable the same assert succeeds and
	// the lifecycle is whole.
	delete(fs.readErr, path)
	fs.mu.Lock()
	fs.vals[path] = "1\n"
	fs.mu.Unlock()
	if err := reg.Assert(path, "0", "posture", RestorePrior); err != nil {
		t.Fatalf("Assert after knob appears: %v", err)
	}
	if failed := reg.Release("posture"); len(failed) != 0 {
		t.Fatalf("Release failed=%v", failed)
	}
	if got := fs.value(path); got != "1" {
		t.Fatalf("after release value=%q want restored 1", got)
	}
}

// Concurrency cell (run with -race): a same-owner re-assert landing in
// the middle of a Release restore write must not be wiped by that
// release. Either the release restores over the re-assert (knob at the
// captured prior, capture retained for the live assert) or the re-assert
// lands after (knob asserted, capture retained) — never asserted-with-
// no-capture, which strands the operator prior forever.
func TestKernelKnobsReleaseReassertRace17068(t *testing.T) {
	const path = "/proc/sys/net/ipv4/fib_multipath_hash_policy"
	fs := newFakeKnobFS(map[string]string{path: "0\n"})
	reg := newKernelKnobsFS(fs)
	if err := reg.Assert(path, "1", "fib", RestorePrior); err != nil {
		t.Fatalf("Assert: %v", err)
	}
	// On the restore write (value 0), signal so the test can race a
	// re-assert against the release's capture bookkeeping.
	restored := make(chan struct{})
	var once sync.Once
	fs.mu.Lock()
	fs.onWrite = func(p string) {
		if fs.value(p) != "0" {
			return
		}
		once.Do(func() { close(restored) })
	}
	fs.mu.Unlock()
	releaseDone := make(chan []string, 1)
	go func() { releaseDone <- reg.Release("fib") }()
	<-restored
	assertDone := make(chan error, 1)
	go func() { assertDone <- reg.Assert(path, "1", "fib", RestorePrior) }()
	if failed := <-releaseDone; len(failed) != 0 {
		t.Fatalf("Release failed=%v", failed)
	}
	if err := <-assertDone; err != nil {
		t.Fatalf("concurrent re-Assert: %v", err)
	}
	// Invariant, whichever interleaving won: the registry and the knob
	// agree. If a capture is held, the knob must be at the asserted
	// value and a later Release must restore the prior; if no capture
	// is held, the knob must already be at the prior.
	owner, owned := reg.Owner(path)
	got := fs.value(path)
	if owned {
		if owner != "fib" {
			t.Fatalf("Owner=%q want fib", owner)
		}
		if got != "1" {
			t.Fatalf("capture held but knob=%q, want asserted 1 (release clobbered a live re-assert)", got)
		}
		if failed := reg.Release("fib"); len(failed) != 0 {
			t.Fatalf("final Release failed=%v", failed)
		}
		if got := fs.value(path); got != "0" {
			t.Fatalf("after final release value=%q want restored prior 0", got)
		}
	} else if got != "0" {
		t.Fatalf("no capture held but knob=%q, want restored prior 0 (asserted with capture lost)", got)
	}
}

// Concurrent hammer (run with -race): many goroutines asserting and
// releasing the same path/owner must leave the registry and the knob in
// agreement, with the operator prior restored once the dust settles.
func TestKernelKnobsConcurrentAssertRelease17068(t *testing.T) {
	const path = "/proc/sys/net/ipv4/fib_multipath_hash_policy"
	fs := newFakeKnobFS(map[string]string{path: "0\n"})
	reg := newKernelKnobsFS(fs)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				_ = reg.Assert(path, "1", "fib", RestorePrior)
				_ = reg.Release("fib")
			}
		}()
	}
	wg.Wait()
	if failed := reg.Release("fib"); len(failed) != 0 {
		t.Fatalf("final Release failed=%v", failed)
	}
	if _, owned := reg.Owner(path); owned {
		t.Fatal("capture still held after final release")
	}
	if got := fs.value(path); got != "0" {
		t.Fatalf("after concurrent assert/release value=%q want prior 0", got)
	}
}

// Re-assert cell: a same-owner, same-policy re-assert keeps the original
// capture — the prior restored on Release is the first-captured value,
// never the asserted value written by the first assert.
func TestKernelKnobsReassertKeepsPrior17068(t *testing.T) {
	const path = "/proc/sys/net/ipv4/fib_multipath_hash_policy"
	fs := newFakeKnobFS(map[string]string{path: "0\n"})
	reg := newKernelKnobsFS(fs)
	if err := reg.Assert(path, "1", "fib", RestorePrior); err != nil {
		t.Fatalf("Assert: %v", err)
	}
	if err := reg.Assert(path, "1", "fib", RestorePrior); err != nil {
		t.Fatalf("same-policy re-Assert: %v", err)
	}
	if failed := reg.Release("fib"); len(failed) != 0 {
		t.Fatalf("Release failed=%v", failed)
	}
	if got := fs.value(path); got != "0" {
		t.Fatalf("after release value=%q want restored 0", got)
	}
}

// Retry debt (#5114 rule): a failed restore is retained and retried on
// the next Release; ownership is not dropped until the write succeeds.
func TestKernelKnobsReleaseRetryDebt17068(t *testing.T) {
	const path = "/proc/sys/net/ipv4/fib_multipath_hash_policy"
	fs := newFakeKnobFS(map[string]string{path: "0\n"})
	reg := newKernelKnobsFS(fs)
	if err := reg.Assert(path, "1", "fib", RestorePrior); err != nil {
		t.Fatalf("Assert: %v", err)
	}
	fs.writeErr[path] = errors.New("EROFS")
	if failed := reg.Release("fib"); len(failed) != 1 || failed[0] != path {
		t.Fatalf("Release failed=%v want [%s]", failed, path)
	}
	if _, ok := reg.Owner(path); !ok {
		t.Fatal("capture dropped despite failed restore — retry debt lost")
	}
	delete(fs.writeErr, path)
	if failed := reg.Release("fib"); len(failed) != 0 {
		t.Fatalf("retry Release failed=%v", failed)
	}
	if got := strings.TrimSpace(fs.vals[path]); got != "0" {
		t.Fatalf("after retry value=%q want 0", got)
	}
}
