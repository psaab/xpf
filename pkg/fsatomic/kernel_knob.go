package fsatomic

// BestEffortKernelKnob lifecycle primitive (#17068). Before this file the
// class had a writer convention (direct os.WriteFile, allowlisted in the
// canary) but no capture/restore lifecycle: every daemon owner hand-rolled
// read-compare, error policy and restore, and "asserted on enable, never
// restored" leaked three times (#2475, #15707, #15710) plus once more in
// the bespoke restore that wrote a constant instead of the captured prior.
//
// WriteKernelKnob is the single low-level writer: read-compare-write with
// newline normalisation and optional read-back verify. KernelKnobs is the
// owner registry: Assert captures the prior value on the first assert of a
// path, and Release(owner) restores every captured prior that owner holds,
// retaining failed restores as retry debt (the #5114 rule: ownership is
// released only after the restore write succeeds).

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

// KnobRestorePolicy selects what Release does with a captured prior.
type KnobRestorePolicy int

const (
	// RestorePrior restores the value captured on the first Assert.
	RestorePrior KnobRestorePolicy = iota
	// KeepOnDisable leaves the asserted value in place on Release; the
	// capture is dropped without a write. For deliberately
	// daemon-lifetime posture (e.g. host forwarding posture).
	KeepOnDisable
)

// knobFS is the filesystem seam so tests (and the daemon's fake-FS tests)
// never touch real procfs. It is unexported: production uses the real
// procfs implementation, tests in this package substitute a fake.
type knobFS interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte) error
}

type realKnobFS struct{}

func (realKnobFS) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

func (realKnobFS) WriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}

// NormalizeKnobValue trims surrounding whitespace/newlines from a knob
// value as read from procfs, so comparisons are not defeated by the
// trailing newline the kernel appends.
func NormalizeKnobValue(s string) string { return strings.TrimSpace(s) }

// writeKernelKnobFS writes want to path if the current value differs.
// The written bytes are want+"\n" (procfs convention). When verify is
// true the value is read back and a mismatch is an error.
func writeKernelKnobFS(fs knobFS, path, want string, verify bool) (bool, error) {
	want = NormalizeKnobValue(want)
	current, _ := fs.ReadFile(path)
	if NormalizeKnobValue(string(current)) == want {
		return false, nil
	}
	if err := fs.WriteFile(path, []byte(want+"\n")); err != nil {
		return false, fmt.Errorf("write kernel knob %s=%s: %w", path, want, err)
	}
	if verify {
		back, err := fs.ReadFile(path)
		if err != nil {
			return true, fmt.Errorf("verify kernel knob %s: %w", path, err)
		}
		if NormalizeKnobValue(string(back)) != want {
			return true, fmt.Errorf("verify kernel knob %s: got %q want %q", path, NormalizeKnobValue(string(back)), want)
		}
	}
	return true, nil
}

// WriteKernelKnob writes want to the procfs/sysfs knob at path when the
// current value differs (read-compare-write, newline-normalised). It
// returns changed=true when a write (or attempted write that verified
// differently) occurred. Best-effort callers log and ignore the error;
// return-code callers (cleanup) propagate it.
func WriteKernelKnob(path, want string) (changed bool, err error) {
	return writeKernelKnobFS(realKnobFS{}, path, want, false)
}

// WriteKernelKnobVerified is WriteKernelKnob plus a read-back verify: a
// mismatch after the write is returned as an error with changed=true.
func WriteKernelKnobVerified(path, want string) (changed bool, err error) {
	return writeKernelKnobFS(realKnobFS{}, path, want, true)
}

// ReadKernelKnob returns the normalised current value of a knob.
func ReadKernelKnob(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return NormalizeKnobValue(string(b)), nil
}

type knobCapture struct {
	prior  string
	owner  string
	policy KnobRestorePolicy
}

// KernelKnobs is the daemon owner registry for BestEffortKernelKnob
// lifecycle. The zero value is not usable; construct with NewKernelKnobs
// (production) or newKernelKnobsFS (tests). It is safe for concurrent use.
//
// Invariants:
//   - The first Assert of a path captures its prior value; later asserts
//     by the same owner never overwrite the capture (first-assert wins,
//     mirroring priorHostTunables).
//   - A second, different owner asserting an already-owned path is an
//     error — two owners of one knob is exactly the nf_conntrack_tcp_loose
//     divergence this primitive exists to prevent. The failed assert
//     writes nothing and captures nothing.
//   - Release(owner) restores every RestorePrior capture that owner
//     holds. A failed restore write is retained as retry debt: the
//     capture stays, so the next Release retries it. KeepOnDisable
//     captures are dropped without a write.
//   - Assert never restores; Release never asserts.
type KernelKnobs struct {
	mu       sync.Mutex
	fs       knobFS
	captures map[string]knobCapture // path -> capture
}

// NewKernelKnobs returns a registry backed by real procfs writes.
func NewKernelKnobs() *KernelKnobs { return newKernelKnobsFS(realKnobFS{}) }

func newKernelKnobsFS(fs knobFS) *KernelKnobs {
	return &KernelKnobs{fs: fs, captures: make(map[string]knobCapture)}
}

// Assert drives path to want on behalf of owner. On the first assert of
// path the current value is captured for later restore. If another owner
// already holds path, Assert returns an error and writes nothing.
// A write failure returns an error and retains the capture (if this call
// created it) so a later Release can still restore the prior.
func (k *KernelKnobs) Assert(path, want, owner string, policy KnobRestorePolicy) error {
	want = NormalizeKnobValue(want)
	k.mu.Lock()
	cap0, owned := k.captures[path]
	if owned && cap0.owner != owner {
		k.mu.Unlock()
		return fmt.Errorf("kernel knob %s already owned by %q (asserted by %q)", path, cap0.owner, owner)
	}
	if !owned {
		prior := ""
		if b, err := k.fs.ReadFile(path); err == nil {
			prior = NormalizeKnobValue(string(b))
		}
		cap0 = knobCapture{prior: prior, owner: owner, policy: policy}
		k.captures[path] = cap0
	} else if cap0.policy != policy {
		cap0.policy = policy
		k.captures[path] = cap0
	}
	k.mu.Unlock()
	_, err := writeKernelKnobFS(k.fs, path, want, false)
	return err
}

// AssertVerified is Assert plus a read-back verify of the written value.
func (k *KernelKnobs) AssertVerified(path, want, owner string, policy KnobRestorePolicy) error {
	want = NormalizeKnobValue(want)
	k.mu.Lock()
	cap0, owned := k.captures[path]
	if owned && cap0.owner != owner {
		k.mu.Unlock()
		return fmt.Errorf("kernel knob %s already owned by %q (asserted by %q)", path, cap0.owner, owner)
	}
	if !owned {
		prior := ""
		if b, err := k.fs.ReadFile(path); err == nil {
			prior = NormalizeKnobValue(string(b))
		}
		cap0 = knobCapture{prior: prior, owner: owner, policy: policy}
		k.captures[path] = cap0
	} else if cap0.policy != policy {
		cap0.policy = policy
		k.captures[path] = cap0
	}
	k.mu.Unlock()
	_, err := writeKernelKnobFS(k.fs, path, want, true)
	return err
}

// Release restores every knob held by owner and drops the captures that
// restored successfully (or were KeepOnDisable). It returns the sorted
// list of paths whose restore write failed; those captures are retained
// as retry debt for the next Release. Releasing an unknown owner is a
// no-op.
func (k *KernelKnobs) Release(owner string) (failed []string) {
	k.mu.Lock()
	var paths []string
	for path, c := range k.captures {
		if c.owner == owner {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	type job struct {
		path  string
		prior string
		keep  bool
	}
	jobs := make([]job, 0, len(paths))
	for _, path := range paths {
		c := k.captures[path]
		jobs = append(jobs, job{path: path, prior: c.prior, keep: c.policy == KeepOnDisable})
	}
	k.mu.Unlock()

	for _, j := range jobs {
		if j.keep {
			k.mu.Lock()
			if c, ok := k.captures[j.path]; ok && c.owner == owner {
				delete(k.captures, j.path)
			}
			k.mu.Unlock()
			continue
		}
		if _, err := writeKernelKnobFS(k.fs, j.path, j.prior, false); err != nil {
			failed = append(failed, j.path)
			continue
		}
		k.mu.Lock()
		if c, ok := k.captures[j.path]; ok && c.owner == owner {
			delete(k.captures, j.path)
		}
		k.mu.Unlock()
	}
	return failed
}

// Owner returns the current owner of path, if any.
func (k *KernelKnobs) Owner(path string) (string, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	c, ok := k.captures[path]
	if !ok {
		return "", false
	}
	return c.owner, true
}

// CapturedPrior returns the prior value captured for path, if any.
func (k *KernelKnobs) CapturedPrior(path string) (string, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	c, ok := k.captures[path]
	if !ok {
		return "", false
	}
	return c.prior, true
}

// ReleaseAll releases every owner; it is the shutdown counterpart of
// Release and returns all failed restore paths (retained as debt).
func (k *KernelKnobs) ReleaseAll() (failed []string) {
	k.mu.Lock()
	owners := make(map[string]bool)
	for _, c := range k.captures {
		owners[c.owner] = true
	}
	k.mu.Unlock()
	for owner := range owners {
		failed = append(failed, k.Release(owner)...)
	}
	sort.Strings(failed)
	return failed
}
