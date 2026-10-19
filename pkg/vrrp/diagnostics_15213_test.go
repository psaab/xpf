package vrrp

import (
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// #15213 cohort: VRRP diagnostics / visibility.
//
// A25-03: a #14404-held RETH candidate that hears no peer retries
// becomeMaster on every master-down horizon (~125ms at the default
// interval) and logged "refusing MASTER" at INFO each time — roughly
// 8 lines/s/instance of journal flood that drowns real diagnostics.
// Only the first refusal of a hold episode may be INFO; repeats are
// Debug, and a new episode (hold cleared, then re-armed) logs INFO
// again.
//
// A25-04: Status() (and every surface reusing it) printed the
// CONFIGURED cfg.Priority, so a track-demoted MASTER still displayed
// e.g. 100 while advertising 50, and no surface named the track state
// at all. Status must show the EFFECTIVE (tracked) priority and the
// track state; InstanceStates must carry both so structured consumers
// (CLI/API/gRPC reuse these) stop repeating the lie.
//
// A25-06: ResignRG wrote cfg.Priority=0 synchronously, before the run
// loop consumed resignCh. If the MASTER advert timer won the run-loop
// select in that window, the routine advert carried priority 0 while
// this node still held its VIPs, and the peer took the 1ms priority-0
// takeover path — a probabilistic sub-advert-interval two-owner window
// during planned failover. The resigning priority must stay out of the
// routine send path until becomeBackup completes; the explicit
// priority-0 burst AFTER becomeBackup remains the takeover signal.

// --- A25-03 ---

func TestBecomeMaster_KernelHoldRefusalLogsInfoOncePerEpisode15213(t *testing.T) {
	vi := newGateTestInstance(t, 100, false)
	vi.setKernelUpgradeHold(true)
	buf := captureSlogMatching(t, "refusing MASTER while kernel-upgrade hold is armed")

	// Same episode: repeated dead-master retries must not repeat INFO.
	for range 5 {
		if vi.becomeMaster() {
			t.Fatal("held instance claimed MASTER")
		}
	}
	if got := strings.Count(buf.String(), "level=INFO"); got != 1 {
		t.Fatalf("INFO refusals in one hold episode = %d, want exactly 1; log:\n%s", got, buf.String())
	}

	// Control: clearing and re-arming the hold is a NEW episode — one
	// fresh INFO, not silence forever and not a second flood.
	vi.setKernelUpgradeHold(false)
	vi.setKernelUpgradeHold(true)
	if vi.becomeMaster() {
		t.Fatal("re-held instance claimed MASTER")
	}
	if got := strings.Count(buf.String(), "level=INFO"); got != 2 {
		t.Fatalf("INFO refusals after hold re-arm = %d, want 2 (one per episode); log:\n%s", got, buf.String())
	}
}

// --- A25-04 ---

func status15213Instance(t *testing.T, name string) (*Manager, *vrrpInstance) {
	t.Helper()
	m := NewManager()
	vi := newInstance(Instance{
		Interface:         name,
		GroupID:           101,
		Priority:          100,
		TrackInterface:    "wan0",
		TrackPriorityCost: 50,
		VirtualAddresses:  []string{"10.0.152.1/24"},
	}, nil, m.eventCh, nil)
	m.mu.Lock()
	m.instances = map[instanceKey]*vrrpInstance{{iface: name, groupID: 101}: vi}
	m.mu.Unlock()
	return m, vi
}

func TestStatus_ShowsEffectivePriorityAndTrackDown15213(t *testing.T) {
	m, vi := status15213Instance(t, "xpf-15213-a0")
	vi.setState(StateMaster)
	vi.setTrackDown(true)

	// Sanity: the track demotion really is in effect (100 - 50).
	if got := vi.getPriority(); got != 50 {
		t.Fatalf("getPriority() = %d, want 50 (track demotion fixture broken)", got)
	}
	status := m.Status()
	if !strings.Contains(status, "priority=50") {
		t.Fatalf("Status must show the EFFECTIVE priority 50 while track is down, got:\n%s", status)
	}
	if strings.Contains(status, "priority=100") {
		t.Fatalf("Status still prints the configured priority 100 (the A25-04 diagnostic lie):\n%s", status)
	}
	if !strings.Contains(status, "track down") {
		t.Fatalf("Status must name the track state (\"track down\") while the tracked interface is down, got:\n%s", status)
	}

	states := m.InstanceStates()
	if len(states) != 1 {
		t.Fatalf("InstanceStates len = %d, want 1", len(states))
	}
	if states[0].EffectivePriority != 50 {
		t.Fatalf("InstanceStates EffectivePriority = %d, want 50", states[0].EffectivePriority)
	}
	if !states[0].TrackDown {
		t.Fatal("InstanceStates TrackDown = false, want true while tracked interface is down")
	}
}

// TestStatus_TrackUpControl15213 is the adjacent legitimate case: with
// the tracked interface up, the effective priority equals the
// configured one and no track-down marker appears.
func TestStatus_TrackUpControl15213(t *testing.T) {
	m, vi := status15213Instance(t, "xpf-15213-b0")
	vi.setState(StateBackup)

	status := m.Status()
	if !strings.Contains(status, "priority=100") {
		t.Fatalf("Status with track up must show priority 100, got:\n%s", status)
	}
	if strings.Contains(status, "track down") {
		t.Fatalf("Status with track up must not claim track down:\n%s", status)
	}
	states := m.InstanceStates()
	if len(states) != 1 || states[0].EffectivePriority != 100 || states[0].TrackDown {
		t.Fatalf("InstanceStates with track up = %+v, want EffectivePriority=100 TrackDown=false", states)
	}
}

// --- A25-06 ---

// TestResignRG_RoutineAdvertKeepsPreResignPriority15213 pins the
// ordering: after ResignRG returns (resign token queued) but BEFORE
// the run loop consumes the token and becomeBackup completes, the
// priority a routine MASTER advert would carry — getPriority(),
// exactly what the advertTimer arm sends — must still be the
// pre-resign priority. Only the explicit post-becomeBackup burst may
// carry 0.
func TestResignRG_RoutineAdvertKeepsPreResignPriority15213(t *testing.T) {
	m, vi := resignBarrierInstance(t, "xpf-15213-c0", func(*netlink.Addr) error { return nil })
	vi.setState(StateMaster)

	barrier := m.ResignRG(1)
	if barrier == nil {
		t.Fatal("ResignRG returned a nil barrier")
	}
	// Positive control: the resignation really was signalled.
	if len(vi.resignCh) != 1 {
		t.Fatalf("resignCh depth = %d, want 1 — ResignRG did not signal the instance", len(vi.resignCh))
	}
	if got := vi.getPriority(); got != 200 {
		t.Fatalf("routine advert priority after ResignRG, before becomeBackup = %d, want 200 (pre-resign): "+
			"a priority-0 routine advert while MASTER still holds its VIPs triggers the peer's 1ms takeover", got)
	}

	// After the run loop consumes the resign and becomeBackup completes,
	// the resignation sentinel is what remains (peer takeover proceeds
	// via the explicit priority-0 burst; a re-election must not win).
	vi.becomeBackup(time.NewTimer(time.Hour), time.NewTimer(time.Hour))
	waitBarrier(t, barrier, "becomeBackup completed the resign")
	if got := vi.getPriority(); got != 0 {
		t.Fatalf("priority after becomeBackup = %d, want 0 (resignation sentinel must persist)", got)
	}
}
