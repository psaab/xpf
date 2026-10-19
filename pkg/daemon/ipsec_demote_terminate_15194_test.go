// #15194 (D04-02): on RG demotion xpf removes the VIP but never terminates
// the IKE/CHILD SAs anchored on it. The stale SAs survive in charon (MOBIKE
// defers teardown, and a non-MOBIKE peer generates no IKE traffic), so when
// the RG fails back the returning owner's `swanctl --initiate --child` is
// refused with "not establishing CHILD_SA ... due to existing duplicate",
// and the returning owner keeps encrypting with SPIs the peer has already
// deleted. The black hole is bounded only by DPD (if configured), the next
// rekey, or peer initiation.
//
// These cells drive the real demotion edges (clearRethServicesForRG and the
// RG0 secondary arm of applyRG0OwnershipTransition) plus the takeover belt
// (reinitiateIPsecSAs) and assert that a terminate is issued for the
// DEMOTED RG's connections only, and that the belt clears a stale local
// duplicate before initiating.

package daemon

import (
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/configstore"
)

type ipsecTerminateRecorder15194 struct {
	mu         sync.Mutex
	terminated []string
	initiated  []string
	activeErr  error
	termErr    error
	initErr    error
}

func (r *ipsecTerminateRecorder15194) recordTerminated(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.terminated = append(r.terminated, name)
	return r.termErr
}

func (r *ipsecTerminateRecorder15194) recordInitiated(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.initiated = append(r.initiated, name)
	return r.initErr
}

func (r *ipsecTerminateRecorder15194) terminatedNames() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]string(nil), r.terminated...)
	sort.Strings(out)
	return out
}

func (r *ipsecTerminateRecorder15194) initiatedNames() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.initiated...)
}

// demotionFixture15194 builds the two-RG store/cluster used by the 9139
// cells and returns it with every RG primary, so a test can demote one.
func demotionFixture15194(t *testing.T) (*configstore.Store, *cluster.Manager) {
	t.Helper()
	store := twoRGIPsecStore(t)
	cfg := store.ActiveConfig()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cfg.Chassis.Cluster)
	for _, rg := range []int{0, 1, 2} {
		cm.SetGroupStateForTesting(rg, cluster.StatePrimary)
	}
	return store, cm
}

func waitFor15194(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// RED core: losing RG1 must terminate the RG1-anchored IKE SA only. The
// RG2 and RG0/plain connections this node still owns must survive.
func TestClearRethServicesTerminatesDemotedRGIPsec15194(t *testing.T) {
	store, cm := demotionFixture15194(t)
	rec := &ipsecTerminateRecorder15194{}
	var active []string
	d := &Daemon{
		cluster: cm,
		store:   store,
		ipsecActiveNamesFn: func() ([]string, error) {
			return append([]string(nil), active...), nil
		},
		ipsecTerminateFn: rec.recordTerminated,
	}
	// This node holds live SAs for all three connections, then loses RG1.
	active = []string{"vpn-rg1", "vpn-rg2", "vpn-plain"}
	cm.SetGroupStateForTesting(1, cluster.StateSecondary)

	d.clearRethServicesForRG(1)

	waitFor15194(t, "terminate of vpn-rg1", func() bool {
		return len(rec.terminatedNames()) > 0
	})
	got := rec.terminatedNames()
	if len(got) != 1 || got[0] != "vpn-rg1" {
		t.Fatalf("#15194: demoting RG1 must terminate exactly [vpn-rg1], got %v "+
			"(vpn-rg2 is still owned by this node; vpn-plain follows RG0, still owned)", got)
	}
}

// CONTROL: demoting an RG must NOT terminate when no live SA names are
// readable — the terminate set is derived from the live set, and a read
// failure must not become a blind terminate of every configured name.
func TestClearRethServicesIPsecReadFailureTerminatesNothing15194(t *testing.T) {
	store, cm := demotionFixture15194(t)
	rec := &ipsecTerminateRecorder15194{}
	d := &Daemon{
		cluster: cm,
		store:   store,
		ipsecActiveNamesFn: func() ([]string, error) {
			return nil, errors.New("charon down")
		},
		ipsecTerminateFn: rec.recordTerminated,
	}
	cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	d.clearRethServicesForRG(1)
	// The sweep is async; give it a bounded window to (not) fire.
	time.Sleep(300 * time.Millisecond)
	if got := rec.terminatedNames(); len(got) != 0 {
		t.Fatalf("#15194: a failed live-SA read must terminate nothing, got %v", got)
	}
}

// RG0 arm: the secondary edge of applyRG0OwnershipTransition must terminate
// the RG0/plain (and any RG0-anchored) SAs, leaving data-RG SAs it still
// owns untouched.
func TestRG0DemotionTerminatesRG0IPsec15194(t *testing.T) {
	store, cm := demotionFixture15194(t)
	rec := &ipsecTerminateRecorder15194{}
	d := &Daemon{
		cluster: cm,
		store:   store,
		ipsecActiveNamesFn: func() ([]string, error) {
			return []string{"vpn-rg1", "vpn-plain"}, nil
		},
		ipsecTerminateFn: rec.recordTerminated,
	}
	// Node loses RG0 but keeps RG1.
	cm.SetGroupStateForTesting(0, cluster.StateSecondary)
	d.rg0WasPrimary.Store(true)
	d.applyRG0OwnershipTransition(cluster.StateSecondary, true)

	waitFor15194(t, "terminate of vpn-plain", func() bool {
		return len(rec.terminatedNames()) > 0
	})
	got := rec.terminatedNames()
	if len(got) != 1 || got[0] != "vpn-plain" {
		t.Fatalf("#15194: RG0 demotion must terminate exactly [vpn-plain] (RG0-anchored), got %v; "+
			"vpn-rg1 belongs to RG1 which this node still owns", got)
	}
}

// Initial secondary seating is NOT a demotion (#12171 shape): a node that
// never held RG0 in this incarnation and whose peer does not hold it must
// not tear down SAs on the strength of the reconcile arm alone.
func TestRG0InitialSecondaryDoesNotTerminateIPsec15194(t *testing.T) {
	store, cm := demotionFixture15194(t)
	rec := &ipsecTerminateRecorder15194{}
	d := &Daemon{
		cluster: cm,
		store:   store,
		ipsecActiveNamesFn: func() ([]string, error) {
			return []string{"vpn-plain"}, nil
		},
		ipsecTerminateFn: rec.recordTerminated,
	}
	cm.SetGroupStateForTesting(0, cluster.StateSecondary)
	// rg0WasPrimary is false and demotionProven is false: initial seating.
	d.applyRG0OwnershipTransition(cluster.StateSecondary, false)
	time.Sleep(300 * time.Millisecond)
	if got := rec.terminatedNames(); len(got) != 0 {
		t.Fatalf("#15194: initial-secondary seating must terminate nothing, got %v", got)
	}
}

// Belt: even if a stale local duplicate survived demotion (terminate raced
// or failed), the takeover initiate must terminate it first so charon does
// not refuse with "existing duplicate".
func TestReinitiateTerminatesStaleLocalDuplicate15194(t *testing.T) {
	store, cm := demotionFixture15194(t)
	rec := &ipsecTerminateRecorder15194{}
	ss := cluster.NewSessionSync(":0", "", nil)
	ss.SetPeerIPsecSAsForTesting([]string{"vpn-rg1"})
	// This node (taking RG1) still holds a stale local SA for vpn-rg1.
	var mu sync.Mutex
	var events []string
	d := &Daemon{
		cluster:     cm,
		store:       store,
		sessionSync: ss,
		ipsecActiveNamesFn: func() ([]string, error) {
			return []string{"vpn-rg1"}, nil
		},
		ipsecTerminateFn: func(name string) error {
			mu.Lock()
			events = append(events, "terminate:"+name)
			mu.Unlock()
			return rec.recordTerminated(name)
		},
		ipsecInitiateFn: func(name string) error {
			mu.Lock()
			events = append(events, "initiate:"+name)
			mu.Unlock()
			return rec.recordInitiated(name)
		},
	}
	d.reinitiateIPsecSAs()
	mu.Lock()
	defer mu.Unlock()
	want := []string{"terminate:vpn-rg1", "initiate:vpn-rg1"}
	if len(events) != len(want) {
		t.Fatalf("#15194: takeover must terminate the stale local duplicate BEFORE initiating; events=%v want %v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("#15194: takeover event order = %v, want %v", events, want)
		}
	}
}

// Belt CONTROL: with no stale local SA, takeover initiates directly and
// terminates nothing — the belt must not tear down a healthy fresh SA.
func TestReinitiateWithoutLocalDuplicateDoesNotTerminate15194(t *testing.T) {
	store, cm := demotionFixture15194(t)
	rec := &ipsecTerminateRecorder15194{}
	ss := cluster.NewSessionSync(":0", "", nil)
	ss.SetPeerIPsecSAsForTesting([]string{"vpn-rg1"})
	d := &Daemon{
		cluster:     cm,
		store:       store,
		sessionSync: ss,
		ipsecActiveNamesFn: func() ([]string, error) {
			return nil, nil
		},
		ipsecTerminateFn: rec.recordTerminated,
		ipsecInitiateFn:  rec.recordInitiated,
	}
	d.reinitiateIPsecSAs()
	if got := rec.terminatedNames(); len(got) != 0 {
		t.Fatalf("#15194: no local duplicate, so takeover must terminate nothing, got %v", got)
	}
	if got := rec.initiatedNames(); len(got) != 1 || got[0] != "vpn-rg1" {
		t.Fatalf("#15194: takeover must still initiate vpn-rg1, got %v", got)
	}
}
