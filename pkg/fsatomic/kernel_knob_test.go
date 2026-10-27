package fsatomic

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeKnobFS is an in-memory knobFS for hermetic (class U) tests.
type fakeKnobFS struct {
	vals     map[string]string
	writeErr map[string]error
	writes   []string
}

func newFakeKnobFS(seed map[string]string) *fakeKnobFS {
	m := make(map[string]string, len(seed))
	for k, v := range seed {
		m[k] = v
	}
	return &fakeKnobFS{vals: m, writeErr: map[string]error{}}
}

func (f *fakeKnobFS) ReadFile(path string) ([]byte, error) {
	v, ok := f.vals[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return []byte(v), nil
}

func (f *fakeKnobFS) WriteFile(path string, data []byte) error {
	if err := f.writeErr[path]; err != nil {
		return err
	}
	f.vals[path] = string(data)
	f.writes = append(f.writes, path+"="+strings.TrimSpace(string(data)))
	return nil
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

// KeepOnDisable: release drops the capture without writing.
func TestKernelKnobsKeepOnDisable17068(t *testing.T) {
	const path = "/proc/sys/net/ipv4/ip_forward"
	fs := newFakeKnobFS(map[string]string{path: "0\n"})
	reg := newKernelKnobsFS(fs)
	if err := reg.Assert(path, "1", "posture", KeepOnDisable); err != nil {
		t.Fatalf("Assert: %v", err)
	}
	if failed := reg.Release("posture"); len(failed) != 0 {
		t.Fatalf("Release failed=%v", failed)
	}
	if got := strings.TrimSpace(fs.vals[path]); got != "1" {
		t.Fatalf("value=%q want kept 1", got)
	}
	if _, ok := reg.Owner(path); ok {
		t.Fatal("capture not dropped after KeepOnDisable release")
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
