package cli

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/fwdstatus"
)

type forwardingStatusCLITestDP struct {
	dataplane.DataPlane

	loaded   bool
	mapStats []dataplane.MapStats
}

func (f *forwardingStatusCLITestDP) IsLoaded() bool {
	return f.loaded
}

func (f *forwardingStatusCLITestDP) GetMapStats() []dataplane.MapStats {
	return f.mapStats
}

type forwardingStatusCLIUserspaceTestDP struct {
	*forwardingStatusCLITestDP

	status      dpuserspace.ProcessStatus
	statusCalls int
}

func (f *forwardingStatusCLIUserspaceTestDP) Status() (dpuserspace.ProcessStatus, error) {
	f.statusCalls++
	return f.status, nil
}

func TestForwardingStatusDataplaneProjectsMapStats(t *testing.T) {
	dp := &forwardingStatusCLITestDP{
		loaded: true,
		mapStats: []dataplane.MapStats{
			{
				Name:       "sessions",
				Type:       "Hash",
				MaxEntries: 128,
				UsedCount:  32,
				KeySize:    16,
				ValueSize:  64,
			},
			{
				Name:       "zone_configs",
				Type:       "Array",
				MaxEntries: 4,
				UsedCount:  4,
				KeySize:    4,
				ValueSize:  32,
			},
		},
	}
	c := &CLI{dp: dp}

	accessor := c.forwardingStatusDataplane()
	if accessor == nil {
		t.Fatal("forwardingStatusDataplane() returned nil")
	}
	if !accessor.IsLoaded() {
		t.Fatal("IsLoaded() = false, want true")
	}

	got := accessor.GetMapStats()
	want := []fwdstatus.MapStats{
		{Type: "Hash", MaxEntries: 128, UsedCount: 32},
		{Type: "Array", MaxEntries: 4, UsedCount: 4},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GetMapStats() = %#v, want %#v", got, want)
	}
}

func TestForwardingStatusDataplaneUsesUserspaceStatusAdapter(t *testing.T) {
	dp := &forwardingStatusCLIUserspaceTestDP{
		forwardingStatusCLITestDP: &forwardingStatusCLITestDP{loaded: true},
		status: dpuserspace.ProcessStatus{
			WorkerRuntime: []dpuserspace.WorkerRuntimeStatus{{
				ThreadCPUNS: 123,
				WallNS:      456,
			}},
		},
	}
	c := &CLI{dp: dp}

	accessor := c.forwardingStatusDataplane()
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
	if len(got.WorkerRuntime) != 1 || got.WorkerRuntime[0].ThreadCPUNS != 123 {
		t.Fatalf("Status() = %#v, want injected userspace status", got)
	}
}

// --- #7250: the crash accessor must be WIRED, not merely implemented -------
//
// pkg/fwdstatus's own cells exercise Build + Format directly, so every one of
// them stays green if this adapter loses its HelperCrashState method — they
// assert a property of the renderer, not of the wiring. This is the cell that
// reds on that deletion.

type forwardingStatusCLICrashTestDP struct {
	*forwardingStatusCLIUserspaceTestDP

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

func (f *forwardingStatusCLICrashTestDP) HelperCrashState() (dpuserspace.HelperCrashRecord, bool) {
	f.crashCalls++
	return f.rec, f.known
}

// HelperCrashHistory answers the #8397 accessor the #10007 adapter method
// probes for.
func (f *forwardingStatusCLICrashTestDP) HelperCrashHistory() ([]dpuserspace.HelperCrashEpisode, int) {
	f.histCalls++
	return f.episodes, f.histTotal
}

func TestForwardingStatusCLIAdapterExposesTheCrashAccessor7250(t *testing.T) {
	base := &forwardingStatusCLITestDP{loaded: true}
	dp := &forwardingStatusCLICrashTestDP{
		forwardingStatusCLIUserspaceTestDP: &forwardingStatusCLIUserspaceTestDP{
			forwardingStatusCLITestDP: base,
		},
		known: true,
		rec: dpuserspace.HelperCrashRecord{
			LastExitWasCrash: true,
			RestartPending:   true,
			ExitCode:         101,
			PID:              4242,
			Restarts:         3,
		},
	}

	c := &CLI{dp: dp}
	acc := c.forwardingStatusDataplane()
	if acc == nil {
		t.Fatal("forwardingStatusDataplane returned nil for a userspace backend")
	}

	// The accessor fwdstatus.Build probes for. If the adapter does not satisfy
	// this, Build silently leaves HelperCrashKnown false and the crash block
	// never renders — with no compile error anywhere.
	probe, ok := acc.(interface {
		HelperCrashState() (dpuserspace.HelperCrashRecord, bool)
	})
	if !ok {
		t.Fatal("the CLI forwarding-status adapter does not expose HelperCrashState, so " +
			"fwdstatus.Build's probe misses and `show chassis forwarding` renders no " +
			"crash block however healthy the renderer is (#7250)")
	}

	got, known := probe.HelperCrashState()
	if !known {
		t.Fatal("adapter reported the crash state as unknown for a backend that answers it")
	}
	if got.ExitCode != 101 || got.PID != 4242 || got.Restarts != 3 {
		t.Errorf("adapter did not pass the record through unchanged: %+v", got)
	}
	if dp.crashCalls == 0 {
		t.Error("adapter never called through to the backend")
	}
}

// --- #10007: the crash HISTORY accessor must be WIRED on the CLI side -----
//
// pkg/fwdstatus's own cells exercise Build + Format directly, so every one of
// them stays green if this adapter loses its HelperCrashHistory method — they
// assert a property of the renderer, not of the wiring. This is the cell that
// reds on that deletion. (gRPC twin:
// TestForwardingStatusServerAdapterExposesTheCrashHistory10007.)
func TestForwardingStatusCLIAdapterExposesTheCrashHistory10007(t *testing.T) {
	oldest := time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC)
	latest := time.Date(2026, 9, 16, 12, 30, 0, 0, time.UTC)
	base := &forwardingStatusCLITestDP{loaded: true}
	dp := &forwardingStatusCLICrashTestDP{
		forwardingStatusCLIUserspaceTestDP: &forwardingStatusCLIUserspaceTestDP{
			forwardingStatusCLITestDP: base,
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

	c := &CLI{dp: dp}
	acc := c.forwardingStatusDataplane()
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
		t.Fatal("the CLI forwarding-status adapter does not expose HelperCrashHistory, so " +
			"fwdstatus.Build's probe misses and `show chassis forwarding` renders no " +
			"crash history however healthy the renderer is (#10007)")
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
	fs, out := buildForwardingCLI6743(t, c)
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
