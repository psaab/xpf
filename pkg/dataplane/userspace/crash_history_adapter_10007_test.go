package userspace

import (
	"testing"
	"time"
)

// #10007: the PUBLISHED adapter must forward crash history, not just crash state.
//
// Production dpProbe() resolves to *LegacyDataPlaneAdapter (Boot() returns
// NewLegacyDataPlaneAdapter(New())), never the bare *Manager — so a delegate
// missing here leaves fwdstatus.Build's history probe missing on the ONLY type
// it is ever handed, and fake-backed adapter tests above would pass while both
// real surfaces stay empty. This cell drives the ADAPTER, which is the gap a
// Manager-direct test misses (#9482 class).
func TestLegacyAdapterForwardsCrashHistory10007(t *testing.T) {
	first := time.Date(2026, 9, 16, 9, 0, 0, 0, time.UTC)
	second := time.Date(2026, 9, 16, 11, 0, 0, 0, time.UTC)
	m := crashedManagerFor8397(first, 4242, 101, 3, "exit status 101")
	m.recordRecoveredCrashEpisodeLocked(first.Add(2 * time.Second))
	m.helperCrash = HelperCrashRecord{}
	m.helperCrash = HelperCrashRecord{
		LastExitWasCrash: true,
		At:               second,
		PID:              4311,
		ExitCode:         -1,
		Signal:           "killed",
		Detail:           "killed by signal killed",
		Restarts:         1,
	}
	m.recordRecoveredCrashEpisodeLocked(second.Add(time.Second))
	// The wipe the production path performs immediately after each recovery.
	m.helperCrash = HelperCrashRecord{}

	// CONTROL on the premise: healthy now, so only history can speak.
	if m.helperCrash.LastExitWasCrash || m.helperCrash.Restarts != 0 {
		t.Fatal("fixture broken: the episode record must be wiped for a healthy-after-crash manager")
	}

	adapter := NewLegacyDataPlaneAdapter(m)
	src, ok := any(adapter).(interface {
		HelperCrashHistory() ([]HelperCrashEpisode, int)
	})
	if !ok {
		t.Fatalf("published adapter type %T does not satisfy the crash-history accessor, "+
			"so the CLI/gRPC adapters' probes miss in production and history renders "+
			"nowhere (#10007)", adapter)
	}

	eps, total := src.HelperCrashHistory()
	if total != 2 {
		t.Fatalf("history total = %d, want 2 — an episode did not survive the adapter", total)
	}
	if len(eps) != 2 {
		t.Fatalf("retained %d episodes, want 2", len(eps))
	}
	if !eps[0].At.Equal(first) || !eps[1].At.Equal(second) {
		t.Errorf("episodes not oldest-first: %v, %v", eps[0].At, eps[1].At)
	}
	if eps[0].PID != 4242 || eps[0].ExitCode != 101 || eps[0].Restarts != 3 {
		t.Errorf("first-episode disposition not carried: %+v", eps[0])
	}
	if eps[1].Signal != "killed" || eps[1].PID != 4311 {
		t.Errorf("second-episode disposition not carried: %+v", eps[1])
	}
}

// TestLegacyAdapterCrashHistoryWithoutManager10007 pins the fail-closed shape:
// no manager means no episodes and no total, never a panic and never a
// fabricated zero that a reader could mistake for "never crashed".
func TestLegacyAdapterCrashHistoryWithoutManager10007(t *testing.T) {
	adapters := map[string]*LegacyDataPlaneAdapter{
		"nil manager":  NewLegacyDataPlaneAdapter(nil),
		"zero adapter": {},
	}
	for name, adapter := range adapters {
		src, ok := any(adapter).(interface {
			HelperCrashHistory() ([]HelperCrashEpisode, int)
		})
		if !ok {
			t.Fatalf("%s: published adapter type %T does not satisfy the crash-history accessor (#10007)",
				name, adapter)
		}
		eps, total := src.HelperCrashHistory()
		if eps != nil || total != 0 {
			t.Errorf("%s: got %d episodes total %d, want nil 0", name, len(eps), total)
		}
	}

	var nilReceiver *LegacyDataPlaneAdapter
	src, ok := any(nilReceiver).(interface {
		HelperCrashHistory() ([]HelperCrashEpisode, int)
	})
	if !ok {
		t.Fatalf("nil *LegacyDataPlaneAdapter does not satisfy the crash-history accessor (#10007)")
	}
	if eps, total := src.HelperCrashHistory(); eps != nil || total != 0 {
		t.Errorf("nil receiver: got %d episodes total %d, want nil 0", len(eps), total)
	}
}
