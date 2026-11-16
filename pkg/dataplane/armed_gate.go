package dataplane

import (
	"errors"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/ebpf"
)

// ErrDataplaneNotArmed is returned by class-1 (fallible, map-required)
// Manager methods when the registry is in the FRESH-unarmed state —
// loaded == false AND no maps populated — where master previously returned
// the per-map "… not found" error (or, on the concurrent path the #2114
// research proved, a fatal concurrent-map read/write against the
// populating Start). Wrapped with %w at each gate site; match with
// errors.Is. It deliberately does NOT fire on the RETAINED-unarmed state
// (Close/Teardown keep the pinned-map registry live for hitless restart
// and bootstrap re-arm): retained reads report the retained state and
// retained mutations reach the retained maps, exactly as master.
var ErrDataplaneNotArmed = errors.New("dataplane not armed")

// registryState is the Manager's armedness classification, computed under
// m.mu (#2114 A3). The two-state unarmed split is load-bearing: FRESH is
// the only state the armed gate fires on.
type registryState int

const (
	// registryFresh: loaded == false AND the map registry is empty — the
	// manager was never armed (New()) or never completed a shim load. This
	// is exactly where master's fallible map accessors returned their
	// "… map not found" errors, so it is where the typed gate error
	// replaces them. (A nonempty m.programs alone does NOT make the
	// manager retained — the predicate reads m.maps emptiness.)
	registryFresh registryState = iota
	// registryRetained: loaded == false with a populated registry — an
	// armed manager's Close (hitless restart keeps the pinned-map handles
	// live), a Teardown-retained bootstrap manager, or a test fixture with
	// injected maps. Every class proceeds exactly as master here.
	registryRetained
	// registryArmed: loaded == true. Store(true) is the publication
	// batch's final in-hold step (publishShimRegistryLocked), so a reader
	// released from a lookup helper's hold observes a fully populated
	// registry.
	registryArmed
)

// String renders the registry state for gate diagnostics.
func (st registryState) String() string {
	switch st {
	case registryFresh:
		return "fresh"
	case registryRetained:
		return "retained"
	case registryArmed:
		return "armed"
	}
	return "unknown"
}

// classifyRegistry computes the armedness classification from the registry
// length. Callers hold m.mu (the loaded flag is atomic, but the
// maps-emptiness read must not race the publication batch's inserts) — the
// two lookup helpers pass their in-hold len(m.maps) reading so the
// classification and the handle selection stay one scoped operation and
// the registry canary's allowlist stays exactly the two helpers + the
// publisher.
func classifyRegistry(loaded *atomic.Bool, numMaps int) registryState {
	if loaded.Load() {
		return registryArmed
	}
	if numMaps == 0 {
		return registryFresh
	}
	return registryRetained
}

// registryLookupHook, when non-nil, runs INSIDE the lookup helpers' m.mu
// hold (#2114 A3 test seam, lock-ownership legs). Protocol: hooks are
// seam-scoped package vars, only ONE ownership hook is armed per test
// (two hooks on the same mutex cannot both be awaited — the second cannot
// execute while the first holds it), and the assertion is either
// TryLock()==false inside the actual access interval or a
// before-lock/after-acquire handshake. Production leaves it nil (one nil
// check per registry lookup, never on the packet path).
var registryLookupHook func()

// muAcquireProbeHook, when non-nil, runs at the ENTRY of the contended
// m.mu surfaces — BEFORE the m.mu.Lock call — in lookupMapLocked,
// lookupProgramLocked, publishShimRegistryLocked, XDPEntryProgram and
// xdpLinkFor (#2114 A3 test seam, Codex PR #6743 r3-8). The blocking legs
// signal arrival from here: a handshake closed BEFORE the goroutine's
// contended call leaves a preemption window in which the non-completion
// timeout can pass without the goroutine ever reaching the mutex (a
// false-green "it blocked" proof); the in-call pre-lock signal proves the
// goroutine arrived at the contended acquisition. The site argument names
// the function so a test can filter. Production leaves it nil (one nil
// check per call, control plane only).
//
// THE SET IS A CLAIM ABOUT THE CALLERS, not about these functions (#9337).
// A leg waiting on the probe is asserting that the path it drives reaches
// one of these surfaces FIRST. Move a plain m.mu acquisition ahead of a
// probed one — as 01409c1f did for DetachXDP by guarding the link maps —
// and the wait becomes an unbounded deadlock, not a failure. Every such
// wait is bounded for that reason; do not remove the bound.
var muAcquireProbeHook func(site string)

// lookupMapLocked performs the uniform #2114 A3 registry access for
// m.maps: under ONE scoped m.mu hold it classifies the manager's
// armedness and selects the named handle ATOMICALLY, so the gate outcome
// and the handle copy can never race the whole-batch publication.
// present is the comma-ok bit, distinguishing present-but-nil (test
// fixtures insert nil handles) from absent. The caller owns the OUTCOME
// per its class: the helper wraps the lookup, never the outcome.
func (m *Manager) lookupMapLocked(name string) (h *ebpf.Map, present bool, st registryState) {
	if muAcquireProbeHook != nil {
		muAcquireProbeHook("lookupMapLocked")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if registryLookupHook != nil {
		registryLookupHook()
	}
	h, present = m.maps[name]
	if present && m.registryObsoleteLocked() {
		// #6741 AC1: REFUSE rather than serve. See registryObsoleteLocked.
		m.obsoleteRegistryLocked("map", name)
		return nil, false, classifyRegistry(&m.loaded, len(m.maps))
	}
	return h, present, classifyRegistry(&m.loaded, len(m.maps))
}

// obsoleteRegistryLocked records that a lookup just served a handle from a
// SUPERSEDED registry generation (#6741). The caller must hold m.mu.
//
// WHAT THIS IS. Teardown's Cleanup destroys the pinned kernel objects but does
// not clear m.maps / m.programs, and the #2114 A3 rule deliberately lets a
// retained-state method PROCEED. So between a Teardown-retain and the next
// publish, a lookup hands back a handle to an obsolete forwarding generation and
// the caller mutates it: a mutation that succeeds and reaches nothing. Nothing
// measured that before this counter, on either recurrence path
// (bootstrap.go's enterBootstrapMode, and the standalone first-commit timeout in
// daemon_apply_commit.go).
//
// WHAT CHANGED (#6741 AC1). This used to count SERVED handles and change no
// behaviour. The lookup now REFUSES: it returns present=false so the caller
// takes its not-present path instead of mutating an orphan. The counter is the
// observability half of that guard, and counts refusals.
//
// The acceptance criterion offered "fails loudly OR is a verified no-op with a
// metric". The no-op branch was foreclosed by measurement: Close closes only
// the XDP/TC link handles and Cleanup unpins WITHOUT closing, so m.maps /
// m.programs FDs are never closed — the orphaned map stays alive and WRITABLE,
// and the mutation succeeds against a generation nothing forwards through.
//
// WHAT IT STILL DOES NOT COVER, and this must not be read as the hazard being
// closed:
//
//   - it remains a LOOKUP-TIME check. lookupMapLocked returns the *ebpf.Map by
//     reference and then RELEASES m.mu, so a handle obtained BEFORE the
//     Teardown and held across it is never re-checked and is neither refused
//     nor counted. AC1 is met for handles obtained after the boundary, not for
//     escaped ones.
//   - a mutation-time check, which would cover those, needs the generation read
//     at the syscall — and #6740 forbids holding m.mu across a BPF syscall.
//     That tension is why AC2 (a lease/refcount with drain discipline) is a
//     design item rather than an extension of this.
//
// A zero counter means "no lookup was refused", never "no obsolete mutation
// occurred".
// registryObsoleteLocked reports whether the registry is currently serving a
// generation that Teardown has superseded (#6741 AC1). The caller must hold
// m.mu.
//
// SCOPE — this is the whole safety argument for refusing. `registryObsoleteFrom`
// is set by `Teardown` and explicitly NOT by `Close`: Close keeps its pinned
// handles live for hitless restart, and the #2114 A3 proceed-on-retained rule
// is argued for exactly that case. So a Close-then-reuse sequence never sees
// this predicate true and proceeds precisely as before. What is refused is only
// the Teardown window, where `Cleanup` has already unpinned the objects and the
// retained handles are ORPHANS of a generation nothing forwards through.
//
// The rule is not weakened; a generation Teardown already superseded is
// declined.
func (m *Manager) registryObsoleteLocked() bool {
	return m.registryObsoleteFrom != 0 && m.registryGeneration <= m.registryObsoleteFrom
}

func (m *Manager) obsoleteRegistryLocked(kind, name string) {
	if !m.registryObsoleteLocked() {
		return
	}
	m.obsoleteRegistryAccesses++
	if m.obsoleteEpochLogged {
		return
	}
	// Once per obsolete epoch, not once per access: these helpers are on every
	// registry access, and a per-access log here would flood exactly when the
	// daemon is already in a degraded lifecycle state.
	m.obsoleteEpochLogged = true
	slog.Warn("dataplane: registry lookup served a handle from a superseded generation",
		"kind", kind, "name", name,
		"generation", m.registryGeneration, "obsolete_from", m.registryObsoleteFrom,
		"detail", "Teardown retained the registry and no publish has followed; "+
			"mutations through this handle reach an obsolete forwarding generation (#6741)")
}

// ObsoleteRegistryAccesses reports how many registry lookups have served a
// handle from a superseded generation (#6741). See obsoleteRegistryLocked for
// what a zero does and does not prove.
func (m *Manager) ObsoleteRegistryAccesses() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.obsoleteRegistryAccesses
}

// peekEntryProgramLocked is the loaded XDP entry program, read for IDENTITY
// only: nil when absent or when the registry is obsolete. Unlike
// lookupProgramLocked it has NO side effect: no lookup hook, no obsolete-access
// count and no log, so a caller holding its own mutex (the userspace takeover
// readiness, #19110) never reaches the obsolete-registry WARN. It makes no
// syscall.
func (m *Manager) peekEntryProgramLocked() *ebpf.Program {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.programs[m.xdpEntryProgramLocked()]
	if p == nil || m.registryObsoleteLocked() {
		return nil
	}
	return p
}

// EntryProgramIdentity returns the loaded XDP entry program for identity
// comparison and identification (#19110), or nil when none is loaded or the
// registry is obsolete. It never logs, counts or makes a syscall: see
// peekEntryProgramLocked.
func (m *Manager) EntryProgramIdentity() *ebpf.Program {
	return m.peekEntryProgramLocked()
}

// lookupProgramLocked is lookupMapLocked for the m.programs registry
// (different value type, same uniform rule).
func (m *Manager) lookupProgramLocked(name string) (p *ebpf.Program, present bool, st registryState) {
	if muAcquireProbeHook != nil {
		muAcquireProbeHook("lookupProgramLocked")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if registryLookupHook != nil {
		registryLookupHook()
	}
	p, present = m.programs[name]
	if present && m.registryObsoleteLocked() {
		// #6741 AC1: REFUSE rather than serve. See registryObsoleteLocked.
		m.obsoleteRegistryLocked("program", name)
		return nil, false, classifyRegistry(&m.loaded, len(m.maps))
	}
	return p, present, classifyRegistry(&m.loaded, len(m.maps))
}

// takeRegistryHandles returns the non-nil map and program handles
// currently in the registry, for a caller that must CLOSE their FDs.
//
// It ACQUIRES m.mu itself and returns with it released -- so it is NOT a
// "...Locked" helper and must not be called with the lock already held; a
// sync.Mutex is not reentrant and that would self-deadlock. The caller does
// the closing afterwards, with no lock held (#6740: a handle Close() is a
// syscall). Building the snapshot is not a syscall, so it is safe under m.mu;
// only the Close() loop must be outside.
//
// It exists so Teardown does not touch m.maps / m.programs directly (#7755).
// The registry canary permits raw access only in the scoped lookup helpers and
// the whole-batch publisher, and adding Teardown to that allowlist would widen
// exactly the surface the canary defends. Routing through a named helper keeps
// the invariant the canary states: every registry access lives in one of a
// small set of functions that can be reviewed together.
//
// It deliberately does NOT remove the entries. Closing is not clearing — the
// registry stays populated so classifyRegistry still reads registryRetained,
// registryObsoleteLocked can still refuse and count, and injected test fixtures
// are untouched. Only the FDs go.
func (m *Manager) takeRegistryHandles() ([]*ebpf.Map, []*ebpf.Program) {
	m.mu.Lock()
	defer m.mu.Unlock()
	maps := make([]*ebpf.Map, 0, len(m.maps))
	for _, h := range m.maps {
		if h != nil {
			maps = append(maps, h)
		}
	}
	programs := make([]*ebpf.Program, 0, len(m.programs))
	for _, p := range m.programs {
		if p != nil {
			programs = append(programs, p)
		}
	}
	return maps, programs
}

// shimRegistryPublishHook runs INSIDE the publisher's m.mu hold BEFORE
// the loaded.Store(true) step (#2114 A3 blocked-Start test seam: readers
// gated on the hold observe the pre-arm state and block; after release
// they observe armed). shimRegistryPublishPostStoreHook runs inside the
// hold AFTER Store(true) and before unlock — the pass-then-block seam
// for the loaded-check set (a method that passes its pre-registry
// IsLoaded check once Store(true) has landed and then blocks at registry
// selection). Same one-armed-hook-per-test protocol as
// registryLookupHook. Production leaves both nil.
var shimRegistryPublishHook func()
var shimRegistryPublishPostStoreHook func()

// publishShimRegistryLocked is the ONE whole-batch publication of the
// userspace shim registry (#2114 A3): the program assignment, both map
// insert loops, and the armed flag land as a single m.mu critical
// section. A reader released from a lookup helper's hold observes either
// the pre-arm state or the FULLY populated armed registry — never a
// partial one (the first insertion would otherwise flip fresh→retained
// while population was still partial). Acquisition (collection
// construction, program lookup, pinning) stays OUTSIDE the lock in
// loadUserspaceShimObjectsOnce.
func (m *Manager) publishShimRegistryLocked(prog *ebpf.Program, collMaps, sharedMaps map[string]*ebpf.Map) {
	if muAcquireProbeHook != nil {
		muAcquireProbeHook("publishShimRegistryLocked")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// #6741: a new registry generation. Bumped inside the SAME m.mu hold that
	// installs the handles, so the counter and the map contents can never be
	// read out of step. Publishing above registryObsoleteFrom is what ends an
	// obsolete epoch.
	m.registryGeneration++
	m.programs[userspaceShimEntryProg] = prog
	for name, umap := range collMaps {
		m.maps[name] = umap
	}
	for name, smap := range sharedMaps {
		m.maps[name] = smap
	}
	if shimRegistryPublishHook != nil {
		shimRegistryPublishHook()
	}
	// The armed flag is the batch's FINAL in-hold step: population is
	// sequenced-before the release-Store, so a post-release reader sees a
	// fully populated registry.
	m.loaded.Store(true)
	if shimRegistryPublishPostStoreHook != nil {
		shimRegistryPublishPostStoreHook()
	}
}

// closeWindowHook runs inside Close() immediately AFTER the entry
// loaded.Store(false) and BEFORE the link-handle closes (#2114 A3
// Close-window test seam: a concurrent IsLoaded() read observes false
// during the window where master reported true until the exit flip).
// Production leaves it nil.
var closeWindowHook func()

// swapXDPEntryProgHook runs INSIDE swapXDPEntryProg's m.mu section around
// the entry-program field write (#2114 A3 lock-ownership test seam).
// Production leaves it nil.
var swapXDPEntryProgHook func()

// xdpEntryProgSelectorHook runs INSIDE the m.mu section of the
// LoadUserspaceShim selector write (SelectUserspaceXDPShimEntryProgram)
// and the public getter (#2114 A3 two-sided selector seam). Production
// leaves it nil.
var xdpEntryProgSelectorHook func()
