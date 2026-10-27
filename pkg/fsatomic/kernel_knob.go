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
	// gen counts Assert calls for this capture. It lets Release tell a
	// capture the caller re-asserted during the restore write apart from
	// the one the snapshot was taken from (see releaseOne).
	gen uint64
}

// KernelKnobs is the daemon owner registry for BestEffortKernelKnob
// lifecycle. The zero value is not usable; construct with NewKernelKnobs
// (production) or newKernelKnobsFS (tests). It is safe for concurrent use.
//
// Invariants:
//   - The first Assert of a path captures its prior value; later asserts
//     by the same owner never overwrite the capture (first-assert wins,
//     mirroring priorHostTunables). A first assert whose capture read
//     fails registers nothing and writes nothing: there is no safe
//     prior to restore later, so the assert must fail rather than
//     poison the capture with an empty string.
//   - A second, different owner asserting an already-owned path is an
//     error — two owners of one knob is exactly the nf_conntrack_tcp_loose
//     divergence this primitive exists to prevent. The failed assert
//     writes nothing and captures nothing.
//   - A same-owner re-assert with a different policy is an error: the
//     policy is fixed at capture time and a later policy must never
//     silently rewrite what Release will do with a live capture.
//   - The per-path write (assert or restore) and the capture bookkeeping
//     are serialized per path (see pathMu), so a same-owner re-assert
//     landing during a Release restore can neither be deleted by that
//     release nor land after it leaving an asserted knob with no capture.
//   - Release(owner) restores every capture that owner holds. A failed
//     restore write is retained as retry debt: the capture stays, so
//     the next Release retries it.
//   - Assert never restores; Release never asserts.
//
// Restart scope: the registry is per-process and in-memory only. A
// daemon restart loses every capture, so a later first assert captures
// whatever value the previous process left in the knob. The daemon
// layers its restart contract on top of this (see
// Daemon.reconcileFibMultipathHashPolicy): this type makes no claim
// that a capture survives a restart.
type KernelKnobs struct {
	mu       sync.Mutex
	fs       knobFS
	captures map[string]knobCapture // path -> capture
	// locks serializes the write+bookkeeping critical section per path.
	// Entries are never removed: the map is bounded by the number of
	// distinct knob paths ever asserted, which for a daemon is a small
	// fixed set.
	locks map[string]*sync.Mutex
}

// NewKernelKnobs returns a registry backed by real procfs writes.
func NewKernelKnobs() *KernelKnobs { return newKernelKnobsFS(realKnobFS{}) }

func newKernelKnobsFS(fs knobFS) *KernelKnobs {
	return &KernelKnobs{fs: fs, captures: make(map[string]knobCapture), locks: make(map[string]*sync.Mutex)}
}

// pathMu returns the mutex serializing writes to path. Callers hold it
// across the write and the capture update/delete so the knob value and
// the registry entry can never disagree about which operation landed
// last. Lock ordering: pathMu is always taken before mu, never after.
func (k *KernelKnobs) pathMu(path string) *sync.Mutex {
	k.mu.Lock()
	defer k.mu.Unlock()
	m, ok := k.locks[path]
	if !ok {
		m = &sync.Mutex{}
		k.locks[path] = m
	}
	return m
}

// Assert drives path to want on behalf of owner. On the first assert of
// path the current value is captured for later restore; if that capture
// read fails, Assert returns the error, registers no capture, and writes
// nothing. If another owner already holds path, Assert returns an error
// and writes nothing. A write failure returns an error and retains the
// capture (if this call created it) so a later Release can still restore
// the prior.
func (k *KernelKnobs) Assert(path, want, owner string, policy KnobRestorePolicy) error {
	want = NormalizeKnobValue(want)
	pm := k.pathMu(path)
	pm.Lock()
	defer pm.Unlock()

	k.mu.Lock()
	cap0, owned := k.captures[path]
	if owned && cap0.owner != owner {
		k.mu.Unlock()
		return fmt.Errorf("kernel knob %s already owned by %q (asserted by %q)", path, cap0.owner, owner)
	}
	if owned && cap0.policy != policy {
		k.mu.Unlock()
		return fmt.Errorf("kernel knob %s already asserted by %q with a different restore policy", path, owner)
	}
	if !owned {
		b, err := k.fs.ReadFile(path)
		if err != nil {
			k.mu.Unlock()
			return fmt.Errorf("capture prior of kernel knob %s: %w", path, err)
		}
		cap0 = knobCapture{prior: NormalizeKnobValue(string(b)), owner: owner, policy: policy}
	}
	cap0.gen++
	k.captures[path] = cap0
	k.mu.Unlock()

	_, err := writeKernelKnobFS(k.fs, path, want, false)
	return err
}

// Release restores every knob held by owner and drops the captures that
// restored successfully. It returns the sorted list of paths whose
// restore write failed; those captures are retained as retry debt for
// the next Release. Releasing an unknown owner is a no-op.
func (k *KernelKnobs) Release(owner string) (failed []string) {
	k.mu.Lock()
	var paths []string
	for path, c := range k.captures {
		if c.owner == owner {
			paths = append(paths, path)
		}
	}
	k.mu.Unlock()
	sort.Strings(paths)
	for _, path := range paths {
		if !k.releaseOne(owner, path) {
			failed = append(failed, path)
		}
	}
	return failed
}

// releaseOne restores the capture owner holds for path and drops it once
// the restore write succeeds. It reports false when the restore failed
// (the capture is retained as retry debt). A capture the owner
// re-asserted while the restore was in flight is not this release's to
// drop: it is restored again so the knob ends at the captured prior and
// the live re-assert keeps its capture. A path the owner no longer holds
// at all is a quiet success (nothing to restore).
func (k *KernelKnobs) releaseOne(owner, path string) (restored bool) {
	pm := k.pathMu(path)
	pm.Lock()
	defer pm.Unlock()
	for {
		k.mu.Lock()
		c, ok := k.captures[path]
		if !ok || c.owner != owner {
			k.mu.Unlock()
			return true
		}
		gen := c.gen
		prior := c.prior
		k.mu.Unlock()

		if _, err := writeKernelKnobFS(k.fs, path, prior, false); err != nil {
			return false
		}

		k.mu.Lock()
		c, ok = k.captures[path]
		if !ok || c.owner != owner {
			// The capture is gone (a concurrent Release dropped it after
			// restoring the same prior): nothing left to do.
			k.mu.Unlock()
			return true
		}
		if c.gen == gen {
			delete(k.captures, path)
			k.mu.Unlock()
			return true
		}
		k.mu.Unlock()
		// A same-owner Assert landed during the restore write and bumped
		// the generation: loop and restore the re-asserted knob too
		// rather than deleting the live capture.
	}
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

// SeedPrior registers prior as the restore target for path under owner
// without writing the knob. It is the restart seam: a caller that knows
// the value currently in the knob is its own previous assert (not an
// operator prior) seeds the operator value so a later Release restores
// that instead of capturing the asserted value. Seeding is refused when
// a different owner already holds path; a same-owner seed overwrites the
// restore target (the caller is re-stating what Release should write)
// but never the owner. It reports whether the seed was registered.
func (k *KernelKnobs) SeedPrior(path, prior, owner string) bool {
	prior = NormalizeKnobValue(prior)
	pm := k.pathMu(path)
	pm.Lock()
	defer pm.Unlock()
	k.mu.Lock()
	defer k.mu.Unlock()
	if c, ok := k.captures[path]; ok {
		if c.owner != owner {
			return false
		}
		c.prior = prior
		k.captures[path] = c
		return true
	}
	k.captures[path] = knobCapture{prior: prior, owner: owner, policy: RestorePrior}
	return true
}
