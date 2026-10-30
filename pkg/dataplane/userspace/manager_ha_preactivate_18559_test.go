package userspace

import (
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// #18559: the make-before-break overlay. These cells pin what the helper is
// told while a transfer is in flight, against the cluster truth the manager
// keeps in haGroups. They are hermetic: controlRequestHook records every
// update_ha_state, haRGActiveMapWrite stands in for the BPF map, and there is
// no shim, so refreshHAWatchdogOnlyFromMapsLocked is a no-op.

type haSendRecorder18559 struct {
	mu    sync.Mutex
	sends [][]HAGroupStatus
}

func (r *haSendRecorder18559) last(t *testing.T) map[int]bool {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.sends) == 0 {
		t.Fatal("no update_ha_state reached the helper")
	}
	out := make(map[int]bool)
	for _, g := range r.sends[len(r.sends)-1] {
		out[g.RGID] = g.Active
	}
	return out
}

func (r *haSendRecorder18559) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sends)
}

func newPreActivateManager18559(t *testing.T) (*Manager, *haSendRecorder18559) {
	t.Helper()
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.clusterHA = true
	m.haGroups = map[int]HAGroupStatus{
		0: {RGID: 0, Active: false},
		1: {RGID: 1, Active: false},
		2: {RGID: 2, Active: true},
	}
	m.haRGActiveMapWrite = func(int, bool) error { return nil }
	rec := &haSendRecorder18559{}
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "update_ha_state" && req.HAState != nil {
			rec.mu.Lock()
			rec.sends = append(rec.sends, append([]HAGroupStatus(nil), req.HAState.Groups...))
			rec.mu.Unlock()
		}
		return nil
	}
	return m, rec
}

// The helper is told the pre-active RG is active; the cluster truth is not
// rewritten.
func TestPreActivationOpensHelperForwarding18559(t *testing.T) {
	m, rec := newPreActivateManager18559(t)
	m.BeginTransferPreActivation([]int{0, 1}, time.Now().Add(time.Minute))
	_ = m.PublishTransferPreActivation() // post-send status apply may fail unshimmed
	got := rec.last(t)
	if !got[1] {
		t.Fatalf("helper inventory %v: the pre-active RG1 was not sent active", got)
	}
	if got[0] {
		t.Fatalf("helper inventory %v: RG0 owns no forwarding and must never pre-activate", got)
	}
	if !got[2] {
		t.Fatalf("helper inventory %v: an unrelated active RG lost its state", got)
	}
	if m.haGroups[1].Active {
		t.Fatal("haGroups[1] was rewritten active: the overlay must not touch the cluster truth")
	}
}

// The daemon's reconcile keeps writing rg_active=false for an RG that is
// still cluster-secondary. That must not close the window.
func TestPreActivationSurvivesSecondaryRGActiveWrite18559(t *testing.T) {
	m, rec := newPreActivateManager18559(t)
	m.BeginTransferPreActivation([]int{1}, time.Now().Add(time.Minute))
	_ = m.UpdateRGActive(1, false)
	if got := rec.last(t); !got[1] {
		t.Fatalf("helper inventory %v: a still-secondary rg_active=false write closed the pre-activation", got)
	}
	if rgs := m.TransferPreActiveRGs(); len(rgs) != 1 || rgs[0] != 1 {
		t.Fatalf("pre-active RGs = %v, want [1]", rgs)
	}
}

// The promotion landing supersedes the overlay, so a LATER demotion of the
// same RG reaches the helper. Without this the next transfer away from this
// node would ack its #5640 fence while the helper still forwarded.
func TestPromotionSupersedesPreActivationSoDemotionLands18559(t *testing.T) {
	m, rec := newPreActivateManager18559(t)
	m.BeginTransferPreActivation([]int{1}, time.Now().Add(time.Minute))
	_ = m.UpdateRGActive(1, true)
	if rgs := m.TransferPreActiveRGs(); len(rgs) != 0 {
		t.Fatalf("pre-active RGs = %v after the promotion landed, want none", rgs)
	}
	_ = m.UpdateRGActive(1, false)
	if got := rec.last(t); got[1] {
		t.Fatalf("helper inventory %v: a real demotion after promotion did not reach the helper", got)
	}
}

// A real demotion (active -> inactive in the cluster truth) supersedes a live
// overlay too, even if no promotion was observed in between.
func TestRealDemotionSupersedesPreActivation18559(t *testing.T) {
	m, rec := newPreActivateManager18559(t)
	m.BeginTransferPreActivation([]int{2}, time.Now().Add(time.Minute))
	_ = m.UpdateRGActive(2, false)
	if got := rec.last(t); got[2] {
		t.Fatalf("helper inventory %v: RG2 demoted in the cluster truth but the helper kept it active", got)
	}
	if rgs := m.TransferPreActiveRGs(); len(rgs) != 0 {
		t.Fatalf("pre-active RGs = %v after a real demotion, want none", rgs)
	}
}

// A failed transfer releases the overlay and the helper is told the truth.
func TestEndPreActivationRevertsUnpromotedRG18559(t *testing.T) {
	m, rec := newPreActivateManager18559(t)
	m.BeginTransferPreActivation([]int{1}, time.Now().Add(time.Minute))
	_ = m.PublishTransferPreActivation()
	reverted, _ := m.EndTransferPreActivation([]int{1})
	if !reverted {
		t.Fatal("EndTransferPreActivation did not report the revert; the caller would not withdraw the connected prefixes")
	}
	if got := rec.last(t); got[1] {
		t.Fatalf("helper inventory %v: the released, unpromoted RG1 stayed active", got)
	}
}

// After a successful transfer the release is free: no extra publish, no
// revert to withdraw.
func TestEndPreActivationAfterPromotionIsFree18559(t *testing.T) {
	m, rec := newPreActivateManager18559(t)
	m.BeginTransferPreActivation([]int{1}, time.Now().Add(time.Minute))
	_ = m.UpdateRGActive(1, true)
	before := rec.count()
	reverted, err := m.EndTransferPreActivation([]int{1})
	if reverted || err != nil {
		t.Fatalf("EndTransferPreActivation after promotion = (%v, %v), want (false, nil)", reverted, err)
	}
	if rec.count() != before {
		t.Fatal("EndTransferPreActivation after promotion sent another update_ha_state")
	}
}

// The deadline is a backstop: an expired entry no longer counts.
func TestExpiredPreActivationDoesNotCount18559(t *testing.T) {
	m, rec := newPreActivateManager18559(t)
	m.BeginTransferPreActivation([]int{1}, time.Now().Add(-time.Millisecond))
	_ = m.PublishTransferPreActivation()
	if got := rec.last(t); got[1] {
		t.Fatalf("helper inventory %v: an expired pre-activation was sent active", got)
	}
}

// The route builders see the pre-active RG as locally owned (its connected
// prefixes must be in the helper FIB before its forwarding opens); the raw
// provider, which proxy-NDP uses, is untouched.
func TestPreActivationRouteProviderOnly18559(t *testing.T) {
	m, _ := newPreActivateManager18559(t)
	m.rgPrimaryProvider = func(int) (bool, bool) { return false, true }
	m.BeginTransferPreActivation([]int{1}, time.Now().Add(time.Minute))
	m.mu.Lock()
	routes := m.rgPrimaryNowLocked()
	raw := m.rgPrimaryProvider
	m.mu.Unlock()
	if p, k := routes(1); !p || !k {
		t.Fatalf("route provider(1) = (%v, %v), want (true, true) for a pre-active RG", p, k)
	}
	if p, _ := routes(2); p {
		t.Fatal("route provider(2) reported primary for an RG that is not pre-active")
	}
	if p, _ := raw(1); p {
		t.Fatal("the raw provider reports the pre-active RG primary; proxy-NDP would answer for an address the peer still owns")
	}
}

// The watchdog refresh paths (session socket, degraded path) build from the
// acknowledged inventory overlaid with Go-side intent. A pre-activation is
// intent; reading it as a demotion would make every lease refresh fight the
// main publish.
func TestPreActivationKeptByWatchdogInventory18559(t *testing.T) {
	m, _ := newPreActivateManager18559(t)
	m.BeginTransferPreActivation([]int{1}, time.Now().Add(time.Minute))
	_ = m.PublishTransferPreActivation()
	m.mu.Lock()
	groups := m.haWatchdogGroupsLocked()
	m.mu.Unlock()
	found := false
	for _, g := range groups {
		if g.RGID == 1 {
			found = true
			if !g.Active {
				t.Fatal("watchdog inventory demotes the pre-active RG1")
			}
		}
	}
	if !found {
		t.Fatal("watchdog inventory lost RG1")
	}
}

// A request that fails after the deadline: the entry no longer counts for
// the helper, but the connected routes Begin published still mark the RG
// local, so the release must still report the revert (Seat G finding 1).
func TestEndPreActivationAfterExpiryStillReportsRevert18559(t *testing.T) {
	m, _ := newPreActivateManager18559(t)
	m.BeginTransferPreActivation([]int{1}, time.Now().Add(-time.Millisecond))
	reverted, _ := m.EndTransferPreActivation([]int{1})
	if !reverted {
		t.Fatal("an expired-then-released pre-activation reported no revert; its connected routes would stay published")
	}
	if rgs := m.TransferPreActiveRGs(); len(rgs) != 0 {
		t.Fatalf("pre-active RGs = %v after release, want none", rgs)
	}
}
