package fwdstatus

import (
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// --- #17128: the single shared accessor -----------------------------------
//
// NewAccessor replaces the verbatim forwardingStatus*DataPlane twins in
// pkg/cli and pkg/grpcapi. These cells pin: crash state+history pass
// through from the backend, the userspace flavour is selected only for
// a Status-carrying backend, an empty cell yields nil, and deleting a
// crash method from userspaceAccessor fails to compile (the
// var _ CrashReporter assertion in builder.go).

type accessorMapSource17128 struct {
	loaded   bool
	mapStats []MapStats
}

func (s accessorMapSource17128) IsLoaded() bool          { return s.loaded }
func (s accessorMapSource17128) GetMapStats() []MapStats { return s.mapStats }

type accessorBackend17128 struct {
	status      userspace.ProcessStatus
	statusErr   error
	statusCalls int
	rec         userspace.HelperCrashRecord
	known       bool
	crashCalls  int
	episodes    []userspace.HelperCrashEpisode
	histTotal   int
	histCalls   int
}

func (b *accessorBackend17128) Status() (userspace.ProcessStatus, error) {
	b.statusCalls++
	return b.status, b.statusErr
}

func (b *accessorBackend17128) HelperCrashState() (userspace.HelperCrashRecord, bool) {
	b.crashCalls++
	return b.rec, b.known
}

func (b *accessorBackend17128) HelperCrashHistory() ([]userspace.HelperCrashEpisode, int) {
	b.histCalls++
	return b.episodes, b.histTotal
}

// accessorPlainBackend17128 has no Status: the eBPF flavour.
type accessorPlainBackend17128 struct{}

func TestNewAccessorExposesCrashStateAndHistory17128(t *testing.T) {
	oldest := time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC)
	backend := &accessorBackend17128{
		known: true,
		rec: userspace.HelperCrashRecord{
			LastExitWasCrash: true,
			RestartPending:   true,
			ExitCode:         101,
			PID:              4242,
			Restarts:         3,
		},
		episodes: []userspace.HelperCrashEpisode{
			{At: oldest, ExitCode: 101, PID: 4242, Restarts: 3},
		},
		histTotal: 4,
	}
	src := accessorMapSource17128{loaded: true, mapStats: []MapStats{{Type: "Hash", MaxEntries: 100, UsedCount: 30}}}
	statusFn := func() (userspace.ProcessStatus, error) { return backend.Status() }

	acc := NewAccessor(src, backend, statusFn)
	if acc == nil {
		t.Fatal("NewAccessor returned nil for a published userspace backend")
	}
	if !acc.IsLoaded() {
		t.Error("IsLoaded = false, want true from the map source")
	}
	if got := acc.GetMapStats(); len(got) != 1 || got[0].UsedCount != 30 {
		t.Errorf("GetMapStats = %+v, want the source stats passed through", got)
	}

	// Named interfaces, not anonymous: this is the assertion Build makes.
	reporter, ok := acc.(CrashReporter)
	if !ok {
		t.Fatalf("accessor %T does not implement CrashReporter; Build would silently skip the crash block", acc)
	}
	rec, known := reporter.HelperCrashState()
	if !known || rec.ExitCode != 101 || rec.PID != 4242 || rec.Restarts != 3 {
		t.Errorf("HelperCrashState = (%+v, %v), want the backend record vouched for", rec, known)
	}
	eps, total := reporter.HelperCrashHistory()
	if total != 4 || len(eps) != 1 || !eps[0].At.Equal(oldest) {
		t.Errorf("HelperCrashHistory = (%+v, %d), want 1 episode / total 4", eps, total)
	}
	if backend.crashCalls == 0 || backend.histCalls == 0 {
		t.Errorf("accessor never called through: crashCalls=%d histCalls=%d", backend.crashCalls, backend.histCalls)
	}

	sp, ok := acc.(StatusProvider)
	if !ok {
		t.Fatalf("userspace accessor %T does not implement StatusProvider", acc)
	}
	if _, err := sp.Status(); err != nil {
		t.Errorf("Status error = %v, want nil (status func delegates to backend)", err)
	}

	// End to end: Build must land both halves on the status even though
	// Status() errors (the post-crash shape).
	backend.statusErr = errors.New("userspace dataplane helper not running")
	fs, err := Build(acc, freshProcReader(), time.Now(), SamplerSnapshot{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !fs.HelperCrashKnown {
		t.Error("Build did not consult the crash accessor via NewAccessor")
	}
	if fs.HelperExitCode != 101 || fs.HelperRestarts != 3 {
		t.Errorf("Build dropped crash fields: %+v", fs)
	}
	if fs.HelperCrashEpisodes != 4 || !fs.HelperCrashEpisodesOldest.Equal(oldest) {
		t.Errorf("Build dropped history: episodes=%d oldest=%v", fs.HelperCrashEpisodes, fs.HelperCrashEpisodesOldest)
	}
}

func TestNewAccessorNonUserspaceAndEmptyCell17128(t *testing.T) {
	src := accessorMapSource17128{loaded: true}

	if got := NewAccessor(src, nil, nil); got != nil {
		t.Errorf("NewAccessor(empty cell) = %T, want nil (#6743 publication check)", got)
	}

	plain := NewAccessor(src, accessorPlainBackend17128{}, nil)
	if plain == nil {
		t.Fatal("NewAccessor(plain backend) = nil, want the map-stats accessor")
	}
	if _, ok := plain.(StatusProvider); ok {
		t.Error("plain accessor implements StatusProvider; Build would take the userspace arm for an eBPF backend")
	}
	if _, ok := plain.(CrashReporter); ok {
		t.Error("plain accessor implements CrashReporter; only the userspace flavour may report crashes")
	}
	if !plain.IsLoaded() {
		t.Error("plain accessor IsLoaded = false, want true")
	}
}

type accessorStatusOnlyBackend17128 struct {
	status userspace.ProcessStatus
}

func (b *accessorStatusOnlyBackend17128) Status() (userspace.ProcessStatus, error) {
	return b.status, nil
}

func TestNewAccessorCrashUnknownWhenBackendLacksCrash17128(t *testing.T) {
	backend := &accessorStatusOnlyBackend17128{}
	acc := NewAccessor(accessorMapSource17128{loaded: true}, backend, backend.Status)
	reporter, ok := acc.(CrashReporter)
	if !ok {
		t.Fatalf("userspace accessor %T does not implement CrashReporter", acc)
	}
	if _, known := reporter.HelperCrashState(); known {
		t.Error("HelperCrashState known=true for a backend with no crash method, want false (unknown, not healthy)")
	}
	if eps, total := reporter.HelperCrashHistory(); eps != nil || total != 0 {
		t.Errorf("HelperCrashHistory = (%v, %d), want (nil, 0)", eps, total)
	}
}
