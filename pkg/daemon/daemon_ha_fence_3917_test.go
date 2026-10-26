package daemon

import (
	"context"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// fenceRecorderHA records the SetRGActive / SetHAWatchdog calls the fence
// path makes so a test can assert exactly which redundancy-groups were
// deactivated on a peer fence.
type fenceRecorderHA struct {
	mu          sync.Mutex
	deactivated []int // RG IDs passed to SetRGActive(ctx, id, false)
	activated   []int // RG IDs passed to SetRGActive(ctx, id, true) — none on fence
}

func (h *fenceRecorderHA) SetRGActive(_ context.Context, rgID int, active bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if active {
		h.activated = append(h.activated, rgID)
	} else {
		h.deactivated = append(h.deactivated, rgID)
	}
	return nil
}

func (h *fenceRecorderHA) SetHAWatchdog(_ context.Context, _ int, _ uint64) error {
	return nil
}

func (h *fenceRecorderHA) SetFabricForwarding(_ context.Context, _ dataplane.FabricID, _ dataplane.FabricFwdInfo) error {
	return nil
}

func (h *fenceRecorderHA) SyncFabricState(_ context.Context) error { return nil }

func (h *fenceRecorderHA) sortedDeactivated() []int {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := append([]int(nil), h.deactivated...)
	sort.Ints(out)
	return out
}

// fenceRecorderDP is a RuntimeDataPlane whose only live surface is HA().
// The nil embed panics if any other method is called, which keeps the fake
// honest: the fence path must touch nothing but HA().SetRGActive.
type fenceRecorderDP struct {
	dataplane.RuntimeDataPlane
	ha *fenceRecorderHA
}

func (d *fenceRecorderDP) HA() dataplane.HAController { return d.ha }

// fenceTestStore builds a committed configstore.Store from flat-set lines.
func fenceTestStore(t *testing.T, setCmds string) *configstore.Store {
	t.Helper()
	s, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := s.LoadSet(setCmds); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	s.ExitConfigureSession("")
	return s
}

// commitDay2 re-enters configure and applies additional set lines, promoting
// them to the active config — the day-2 commit that a fence must observe.
func commitDay2(t *testing.T, s *configstore.Store, setCmds string) {
	t.Helper()
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure (day-2): %v", err)
	}
	if _, err := s.LoadSet(setCmds); err != nil {
		t.Fatalf("LoadSet (day-2): %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit (day-2): %v", err)
	}
	s.ExitConfigureSession("")
}

const fenceStartupClusterSet = "" +
	"set chassis cluster cluster-id 1\n" +
	"set chassis cluster node 0\n" +
	"set chassis cluster reth-count 2\n" +
	"set chassis cluster redundancy-group 0 node 0 priority 200\n" +
	"set chassis cluster redundancy-group 0 node 1 priority 100\n" +
	"set chassis cluster redundancy-group 1 node 0 priority 200\n" +
	"set chassis cluster redundancy-group 1 node 1 priority 100\n" +
	"set chassis cluster authentication-key test-cluster-psk-6611\n" +
	"set chassis cluster control-interface em0\n" +
	"set chassis cluster peer-address 10.99.0.2\n" +
	"set interfaces em0 unit 0 family inet address 10.99.0.1/24\n"

// TestFenceAllRedundancyGroups_ReadsCurrentConfig is the #3917 regression
// guard. A redundancy-group added by a day-2 commit (after startClusterComms
// captured its `cfg` closure) MUST be fenced on a peer fence — otherwise the
// day-2 RG stays active on this node while the peer also becomes active for
// it, i.e. split-brain dual-active. The pre-fix closure iterated the startup
// snapshot (RG0, RG1 only), so RG2 went unfenced; this test goes RED on that
// revert.
func TestFenceAllRedundancyGroups_ReadsCurrentConfig(t *testing.T) {
	s := fenceTestStore(t, fenceStartupClusterSet)

	// Snapshot the startup RG set the buggy closure would have captured.
	startup := s.ActiveConfig()
	if startup == nil || startup.Chassis.Cluster == nil {
		t.Fatal("startup config missing cluster")
	}
	if got := len(startup.Chassis.Cluster.RedundancyGroups); got != 2 {
		t.Fatalf("startup RG count = %d, want 2 (RG0, RG1)", got)
	}

	// Day-2 commit: add redundancy-group 2. Comms are NOT restarted for a
	// non-transport change, so a startup-snapshot closure would never see it.
	commitDay2(t, s, fenceStartupClusterSet+
		"set chassis cluster redundancy-group 2 node 0 priority 200\n"+
		"set chassis cluster redundancy-group 2 node 1 priority 100\n")

	rec := &fenceRecorderHA{}
	d := &Daemon{store: s}
	d.setDataplane(&fenceRecorderDP{ha: rec}) // #2114: publish through the cell

	d.fenceAllRedundancyGroups(context.Background())

	if got, want := rec.sortedDeactivated(), []int{0, 1, 2}; !equalInts(got, want) {
		t.Fatalf("fenced RGs = %v, want %v (day-2 RG2 must be fenced)", got, want)
	}
	if len(rec.activated) != 0 {
		t.Fatalf("fence must never activate any RG, got %v", rec.activated)
	}
}

// TestFenceAllRedundancyGroups_StartupRGsFenced confirms the fix does not
// regress the base case: RGs present at startup are still fenced.
func TestFenceAllRedundancyGroups_StartupRGsFenced(t *testing.T) {
	s := fenceTestStore(t, fenceStartupClusterSet)
	rec := &fenceRecorderHA{}
	d := &Daemon{store: s}
	d.setDataplane(&fenceRecorderDP{ha: rec}) // #2114: publish through the cell

	d.fenceAllRedundancyGroups(context.Background())

	if got, want := rec.sortedDeactivated(), []int{0, 1}; !equalInts(got, want) {
		t.Fatalf("fenced RGs = %v, want %v", got, want)
	}
}

// TestFenceAllRedundancyGroups_ConfigOnlyModeSafe: with a nil dataplane
// (config-only mode) a fence must not panic and must make no HA calls.
func TestFenceAllRedundancyGroups_ConfigOnlyModeSafe(t *testing.T) {
	s := fenceTestStore(t, fenceStartupClusterSet)
	d := &Daemon{store: s}
	// Must not panic.
	d.fenceAllRedundancyGroups(context.Background())
}

// TestFenceAllRedundancyGroups_NoClusterSafe: a non-cluster (or nil) config
// yields no RGs and no HA calls, without panicking.
func TestFenceAllRedundancyGroups_NoClusterSafe(t *testing.T) {
	// nil store.
	rec := &fenceRecorderHA{}
	d := &Daemon{store: nil}
	d.setDataplane(&fenceRecorderDP{ha: rec}) // #2114: publish through the cell
	d.fenceAllRedundancyGroups(context.Background())
	if len(rec.deactivated) != 0 {
		t.Fatalf("nil store must fence nothing, got %v", rec.deactivated)
	}

	// Committed config with no chassis cluster stanza.
	s := fenceTestStore(t, "set interfaces ge-0/0/3 unit 0 family inet address 10.0.30.1/24\n")
	rec2 := &fenceRecorderHA{}
	d2 := &Daemon{store: s}
	d2.setDataplane(&fenceRecorderDP{ha: rec2}) // #2114: publish through the cell
	d2.fenceAllRedundancyGroups(context.Background())
	if len(rec2.deactivated) != 0 {
		t.Fatalf("non-cluster config must fence nothing, got %v", rec2.deactivated)
	}
}

// TestCurrentRedundancyGroups covers the shared live-config reader directly.
func TestCurrentRedundancyGroups(t *testing.T) {
	// nil store → nil.
	d := &Daemon{}
	if rgs := d.currentRedundancyGroups(); rgs != nil {
		t.Fatalf("nil store: got %v, want nil", rgs)
	}

	s := fenceTestStore(t, fenceStartupClusterSet)
	d.store = s
	if got := len(d.currentRedundancyGroups()); got != 2 {
		t.Fatalf("current RG count = %d, want 2", got)
	}

	commitDay2(t, s, fenceStartupClusterSet+
		"set chassis cluster redundancy-group 2 node 0 priority 200\n"+
		"set chassis cluster redundancy-group 2 node 1 priority 100\n")
	if got := len(d.currentRedundancyGroups()); got != 3 {
		t.Fatalf("post day-2 RG count = %d, want 3", got)
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
