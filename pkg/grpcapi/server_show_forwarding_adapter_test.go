package grpcapi

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/fwdstatus"
)

type forwardingStatusServerTestDP struct {
	dataplane.DataPlane

	loaded   bool
	mapStats []dataplane.MapStats
}

func (f *forwardingStatusServerTestDP) IsLoaded() bool {
	return f.loaded
}

func (f *forwardingStatusServerTestDP) GetMapStats() []dataplane.MapStats {
	return f.mapStats
}

type forwardingStatusServerUserspaceTestDP struct {
	*forwardingStatusServerTestDP

	status      dpuserspace.ProcessStatus
	statusCalls int
}

func (f *forwardingStatusServerUserspaceTestDP) Status() (dpuserspace.ProcessStatus, error) {
	f.statusCalls++
	return f.status, nil
}

func TestForwardingStatusDataplaneProjectsMapStats(t *testing.T) {
	dp := &forwardingStatusServerTestDP{
		loaded: true,
		mapStats: []dataplane.MapStats{
			{
				Name:       "sessions",
				Type:       "Hash",
				MaxEntries: 256,
				UsedCount:  64,
				KeySize:    16,
				ValueSize:  64,
			},
			{
				Name:       "lpm_trie",
				Type:       "LPMTrie",
				MaxEntries: 1024,
				UsedCount:  7,
				KeySize:    8,
				ValueSize:  8,
			},
		},
	}
	s := &Server{dp: dp}

	accessor := s.forwardingStatusDataplane()
	if accessor == nil {
		t.Fatal("forwardingStatusDataplane() returned nil")
	}
	if !accessor.IsLoaded() {
		t.Fatal("IsLoaded() = false, want true")
	}

	got := accessor.GetMapStats()
	want := []fwdstatus.MapStats{
		{Type: "Hash", MaxEntries: 256, UsedCount: 64},
		{Type: "LPMTrie", MaxEntries: 1024, UsedCount: 7},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GetMapStats() = %#v, want %#v", got, want)
	}
}

func TestForwardingStatusDataplaneUsesUserspaceStatusAdapter(t *testing.T) {
	dp := &forwardingStatusServerUserspaceTestDP{
		forwardingStatusServerTestDP: &forwardingStatusServerTestDP{loaded: true},
		status: dpuserspace.ProcessStatus{
			WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{{
				ThreadCPUNS: 321,
				WallNS:      654,
			}},
		},
	}
	s := &Server{dp: dp}

	accessor := s.forwardingStatusDataplane()
	statusAccessor, ok := accessor.(interface {
		Status() (dpuserspace.ProcessStatus, error)
	})
	if !ok {
		t.Fatalf("forwardingStatusDataplane() = %T, want userspace Status adapter", accessor)
	}

	got, err := statusAccessor.Status()
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if dp.statusCalls != 1 {
		t.Fatalf("Status() calls = %d, want 1", dp.statusCalls)
	}
	if len(got.WorkerRuntime) != 1 || got.WorkerRuntime[0].ThreadCPUNS != 321 {
		t.Fatalf("Status() = %#v, want injected userspace status", got)
	}
}

// --- #7250: the crash accessor must be WIRED on the gRPC side too ---------
//
// The remote `cli` binary lands here, not on pkg/cli. Two frontends render the
// same fact from one implementation (the pkg/bootstrapshow rule), so both
// adapters need the method and both need a cell — binding one would leave the
// other free to regress silently.

type forwardingStatusServerCrashTestDP struct {
	*forwardingStatusServerUserspaceTestDP

	rec        dpuserspace.HelperCrashRecord
	known      bool
	crashCalls int

	// #10007: the healthy-after-crash history half. The same backend carries
	// both accessors because production does: the daemon publishes ONE
	// *LegacyDataPlaneAdapter and fwdstatus.Build asserts the two lifetimes
	// independently.
	episodes  []dpuserspace.HelperCrashEpisode
	histTotal int
	histCalls int
}

func (f *forwardingStatusServerCrashTestDP) HelperCrashState() (dpuserspace.HelperCrashRecord, bool) {
	f.crashCalls++
	return f.rec, f.known
}

// HelperCrashHistory answers the #8397 accessor the #10007 adapter method
// probes for.
func (f *forwardingStatusServerCrashTestDP) HelperCrashHistory() ([]dpuserspace.HelperCrashEpisode, int) {
	f.histCalls++
	return f.episodes, f.histTotal
}

func TestForwardingStatusServerAdapterExposesTheCrashAccessor7250(t *testing.T) {
	base := &forwardingStatusServerTestDP{loaded: true}
	dp := &forwardingStatusServerCrashTestDP{
		forwardingStatusServerUserspaceTestDP: &forwardingStatusServerUserspaceTestDP{
			forwardingStatusServerTestDP: base,
		},
		known: true,
		rec: dpuserspace.HelperCrashRecord{
			LastExitWasCrash: true,
			RestartPending:   true,
			Signal:           "killed",
			ExitCode:         -1,
			Restarts:         7,
		},
	}

	s := &Server{dp: dp}
	acc := s.forwardingStatusDataplane()
	if acc == nil {
		t.Fatal("forwardingStatusDataplane returned nil for a userspace backend")
	}

	probe, ok := acc.(interface {
		HelperCrashState() (dpuserspace.HelperCrashRecord, bool)
	})
	if !ok {
		t.Fatal("the gRPC forwarding-status adapter does not expose HelperCrashState, so " +
			"the remote `cli` binary renders no crash block for `show chassis " +
			"forwarding` (#7250)")
	}

	got, known := probe.HelperCrashState()
	if !known {
		t.Fatal("adapter reported the crash state as unknown for a backend that answers it")
	}
	if got.Signal != "killed" || got.Restarts != 7 {
		t.Errorf("adapter did not pass the record through unchanged: %+v", got)
	}
	if dp.crashCalls == 0 {
		t.Error("adapter never called through to the backend")
	}
}

// --- #10007: the crash HISTORY accessor must be WIRED on the gRPC side ----
//
// Same gap as #7250 one layer down the lifetime stack: fwdstatus.Build probes
// for HelperCrashHistory independently of HelperCrashState, and the renderer
// prints the "Helper crash episodes" row once HelperCrashEpisodes > 0 — but
// the adapter never exposed the method, so the probe missed on the only
// backend production hands it and a helper that crashed repeatedly and is
// healthy now rendered a clean crash surface on the remote `cli`.
func TestForwardingStatusServerAdapterExposesTheCrashHistory10007(t *testing.T) {
	oldest := time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC)
	latest := time.Date(2026, 9, 16, 12, 30, 0, 0, time.UTC)
	base := &forwardingStatusServerTestDP{loaded: true}
	dp := &forwardingStatusServerCrashTestDP{
		forwardingStatusServerUserspaceTestDP: &forwardingStatusServerUserspaceTestDP{
			forwardingStatusServerTestDP: base,
		},
		// Healthy NOW: the recovery wipe zeroed the episode record, while the
		// manager stays reachable so the state is known.
		known: true,
		rec:   dpuserspace.HelperCrashRecord{},
		// ...meanwhile four episodes recovered in this daemon, of which the
		// ring still holds two. Total intentionally exceeds len(episodes):
		// the "2 crashes" vs "at least 2 crashes" distinction is the answer.
		episodes: []dpuserspace.HelperCrashEpisode{
			{At: oldest, ExitCode: 101, Detail: "exit status 101", PID: 4242, Restarts: 3, RecoveredAt: oldest.Add(2 * time.Second)},
			{At: latest, ExitCode: -1, Signal: "killed", Detail: "killed by signal killed", PID: 4311, Restarts: 1, RecoveredAt: latest.Add(time.Second)},
		},
		histTotal: 4,
	}

	s := &Server{dp: dp}
	acc := s.forwardingStatusDataplane()
	if acc == nil {
		t.Fatal("forwardingStatusDataplane returned nil for a userspace backend")
	}

	// The accessor fwdstatus.Build probes for. If the adapter does not
	// satisfy this, Build silently leaves HelperCrashEpisodes zero and the
	// history row never renders — with no compile error anywhere.
	probe, ok := acc.(interface {
		HelperCrashHistory() ([]dpuserspace.HelperCrashEpisode, int)
	})
	if !ok {
		t.Fatal("the gRPC forwarding-status adapter does not expose HelperCrashHistory, so " +
			"fwdstatus.Build's probe misses and the remote `cli` renders no crash " +
			"history for `show chassis forwarding` however healthy the renderer is (#10007)")
	}

	got, total := probe.HelperCrashHistory()
	if total != 4 {
		t.Errorf("history total = %d, want 4 — the monotonic count must survive the ring wrapping", total)
	}
	if len(got) != 2 || !got[0].At.Equal(oldest) || got[1].PID != 4311 {
		t.Errorf("adapter did not pass the episodes through unchanged: %+v", got)
	}
	if dp.histCalls == 0 {
		t.Error("adapter never called through to the backend")
	}

	// End to end through the REAL Build: history must land on the status
	// while the current-episode half stays a healthy zero.
	fs, out := buildForwarding6743(t, s)
	if fs.HelperCrashEpisodes != 4 {
		t.Errorf("HelperCrashEpisodes = %d, want 4", fs.HelperCrashEpisodes)
	}
	if !fs.HelperCrashEpisodesOldest.Equal(oldest) {
		t.Errorf("HelperCrashEpisodesOldest = %v, want %v", fs.HelperCrashEpisodesOldest, oldest)
	}
	// CONTROLS on the premise: known + healthy now. If the state half were
	// unknown the render gate would hide the row and this cell would pass
	// without the wiring doing anything.
	if !fs.HelperCrashKnown {
		t.Error("HelperCrashKnown = false for a backend that answers the state accessor")
	}
	if fs.LastExitWasCrash || fs.RestartPending {
		t.Errorf("current-episode half must be a healthy zero; got LastExitWasCrash=%v RestartPending=%v",
			fs.LastExitWasCrash, fs.RestartPending)
	}
	if !strings.Contains(out, "Helper crash episodes") {
		t.Errorf("rendered output lacks the history row:\n%s", out)
	}
	if !strings.Contains(out, "4 recovered in this daemon") {
		t.Errorf("rendered output lacks the recovered count:\n%s", out)
	}
}
