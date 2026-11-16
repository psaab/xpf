package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #19140: the daemon's member-shim debt producer. RG1 is served by reth0
// (local member ge-0-0-0), RG2 by reth1 (ge-0-0-1). The verdict source is a
// fake; the clock is memberShimNow.

const memberShimSet19140 = "" +
	"set chassis cluster cluster-id 1\n" +
	"set chassis cluster authentication-key test-cluster-psk-19140\n" +
	"set chassis cluster control-interface em0\n" +
	"set chassis cluster peer-address 10.99.0.2\n" +
	"set interfaces em0 unit 0 family inet address 10.99.0.1/24\n" +
	"set chassis cluster redundancy-group 1 node 0 priority 200\n" +
	"set chassis cluster redundancy-group 1 node 1 priority 100\n" +
	"set chassis cluster redundancy-group 2 node 0 priority 200\n" +
	"set chassis cluster redundancy-group 2 node 1 priority 100\n" +
	"set interfaces reth0 redundant-ether-options redundancy-group 1\n" +
	"set interfaces ge-0/0/0 gigether-options redundant-parent reth0\n" +
	"set interfaces ge-7/0/0 gigether-options redundant-parent reth0\n" +
	"set interfaces reth0 unit 0 family inet address 10.0.0.1/24\n" +
	"set interfaces reth1 redundant-ether-options redundancy-group 2\n" +
	"set interfaces ge-0/0/1 gigether-options redundant-parent reth1\n" +
	"set interfaces ge-7/0/1 gigether-options redundant-parent reth1\n" +
	"set interfaces reth1 unit 0 family inet address 10.0.1.1/24\n"

type verdictDP19140 struct {
	dataplane.RuntimeDataPlane
	mu sync.Mutex
	v  dpuserspace.DataMemberShimVerdict
	ok bool
}

func (f *verdictDP19140) DataMemberShimVerdict() (dpuserspace.DataMemberShimVerdict, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.v
	out.Members = append([]dpuserspace.DataMemberShimState(nil), f.v.Members...)
	return out, f.ok
}

type shimFixture19140 struct {
	d   *Daemon
	dp  *verdictDP19140
	cfg *config.Config
	now time.Time
}

func newShimFixture19140(t *testing.T) *shimFixture19140 {
	t.Helper()
	cfg := fenceTestStore(t, memberShimSet19140).ActiveConfig()
	if got := memberShimRGs(cfg); !slices.Equal(got["ge-0-0-0"], []int{1}) || !slices.Equal(got["ge-0-0-1"], []int{2}) {
		t.Fatalf("setup: member to RG map = %v, want ge-0-0-0:[1] ge-0-0-1:[2]", got)
	}
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(&config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{
		{ID: 0, NodePriorities: map[int]int{0: 200}},
		{ID: 1, NodePriorities: map[int]int{0: 200}},
		{ID: 2, NodePriorities: map[int]int{0: 200}},
	}})
	t.Cleanup(cm.Stop)
	f := &shimFixture19140{d: &Daemon{cluster: cm}, dp: &verdictDP19140{}, cfg: cfg, now: time.Unix(1_800_000_000, 0)}
	f.d.setDataplane(f.dp)
	old := memberShimNow
	memberShimNow = func() time.Time { return f.now }
	t.Cleanup(func() { memberShimNow = old })
	return f
}

// tick publishes a FRESH verdict (At = now) with the given member states, then
// runs one producer pass.
func (f *shimFixture19140) tick(states map[string]dpuserspace.DataMemberShimStatus) {
	f.publish(f.now, states)
	f.d.applyMemberShimDebt()
}

func (f *shimFixture19140) publish(at time.Time, states map[string]dpuserspace.DataMemberShimStatus) {
	v := dpuserspace.DataMemberShimVerdict{Config: f.cfg, At: at, Checked: true}
	for _, name := range []string{"ge-0-0-0", "ge-0-0-1"} {
		st, ok := states[name]
		if !ok {
			st = dpuserspace.DataMemberShimAttached
		}
		v.Members = append(v.Members, dpuserspace.DataMemberShimState{LinuxName: name, Status: st, Detail: st.String()})
	}
	f.dp.mu.Lock()
	f.dp.v, f.dp.ok = v, true
	f.dp.mu.Unlock()
}

// run ticks every second for d with the same states.
func (f *shimFixture19140) run(d time.Duration, states map[string]dpuserspace.DataMemberShimStatus) {
	for end := f.now.Add(d); f.now.Before(end); {
		f.now = f.now.Add(time.Second)
		f.tick(states)
	}
}

func (f *shimFixture19140) charged(t *testing.T, rg int) bool {
	t.Helper()
	for _, g := range f.d.cluster.GroupStates() { // no readiness callback in this fixture
		if g.GroupID == rg {
			return slices.Contains(g.MonitorFails, cluster.RethMemberShimMonitorIface)
		}
	}
	t.Fatalf("RG%d not found", rg)
	return false
}

var (
	missing19140    = dpuserspace.DataMemberShimMissing
	unverified19140 = dpuserspace.DataMemberShimUnverified
	excluded19140   = dpuserspace.DataMemberShimNotRequired
)

// D1: positively missing for less than the grace charges nothing; at the grace
// it charges exactly the member's RG, never RG0 or the other RG.
func TestMemberShimDebtAfterGraceOnTheMembersRGOnly19140(t *testing.T) {
	f := newShimFixture19140(t)
	f.run(memberShimDebtGrace-2*time.Second, map[string]dpuserspace.DataMemberShimStatus{"ge-0-0-0": missing19140})
	if f.charged(t, 1) {
		t.Fatal("RG1 charged before the grace")
	}
	f.run(3*time.Second, map[string]dpuserspace.DataMemberShimStatus{"ge-0-0-0": missing19140})
	if !f.charged(t, 1) {
		t.Fatal("RG1 not charged after the grace of positive missing evidence")
	}
	if f.charged(t, 0) || f.charged(t, 2) {
		t.Fatal("the debt reached RG0 or RG2, which the member does not serve")
	}
}

// D2: unverified never installs or clears, and a stale snapshot is unverified
// for every member.
func TestMemberShimDebtUnverifiedChangesNothing19140(t *testing.T) {
	t.Run("missing-then-unverified-installs-nothing", func(t *testing.T) {
		f := newShimFixture19140(t)
		f.run(5*time.Second, map[string]dpuserspace.DataMemberShimStatus{"ge-0-0-0": missing19140})
		f.run(30*time.Second, map[string]dpuserspace.DataMemberShimStatus{"ge-0-0-0": unverified19140})
		if f.charged(t, 1) {
			t.Fatal("debt installed while the member was unverified")
		}
	})
	t.Run("charged-then-unverified-clears-nothing", func(t *testing.T) {
		f := newShimFixture19140(t)
		f.run(memberShimDebtGrace+2*time.Second, map[string]dpuserspace.DataMemberShimStatus{"ge-0-0-0": missing19140})
		f.run(30*time.Second, map[string]dpuserspace.DataMemberShimStatus{"ge-0-0-0": unverified19140})
		if !f.charged(t, 1) {
			t.Fatal("debt cleared on unverified evidence")
		}
	})
	t.Run("stale-snapshot", func(t *testing.T) {
		f := newShimFixture19140(t)
		published := f.now
		for range 30 {
			f.now = f.now.Add(time.Second)
			f.publish(published, map[string]dpuserspace.DataMemberShimStatus{"ge-0-0-0": missing19140})
			f.d.applyMemberShimDebt()
		}
		if f.charged(t, 1) {
			t.Fatal("debt installed from a snapshot older than its freshness bound")
		}
	})
}

// D3: the debt clears only after the clear-hold of continuous positive
// evidence; a flutter inside the hold keeps it.
func TestMemberShimDebtClearHold19140(t *testing.T) {
	f := newShimFixture19140(t)
	f.run(memberShimDebtGrace+2*time.Second, map[string]dpuserspace.DataMemberShimStatus{"ge-0-0-0": missing19140})
	f.run(memberShimClearHold-3*time.Second, nil)
	f.run(time.Second, map[string]dpuserspace.DataMemberShimStatus{"ge-0-0-0": missing19140}) // flutter
	f.run(memberShimClearHold-2*time.Second, nil)
	if !f.charged(t, 1) {
		t.Fatal("debt cleared inside the clear-hold after a flutter")
	}
	f.run(3*time.Second, nil)
	if f.charged(t, 1) {
		t.Fatal("debt not cleared after a full clear-hold of positive evidence")
	}
}

// D4: a member that leaves the configuration takes its RG's debt with it.
func TestMemberShimDebtClearsWhenTheMemberLeavesTheConfig19140(t *testing.T) {
	f := newShimFixture19140(t)
	f.run(memberShimDebtGrace+2*time.Second, map[string]dpuserspace.DataMemberShimStatus{"ge-0-0-0": missing19140})
	if !f.charged(t, 1) {
		t.Fatal("setup: RG1 charged")
	}
	f.cfg = fenceTestStore(t, ""+
		"set chassis cluster cluster-id 1\n"+
		"set chassis cluster authentication-key test-cluster-psk-19140\n"+
		"set chassis cluster control-interface em0\n"+
		"set chassis cluster peer-address 10.99.0.2\n"+
		"set interfaces em0 unit 0 family inet address 10.99.0.1/24\n"+
		"set chassis cluster redundancy-group 2 node 0 priority 200\n"+
		"set chassis cluster redundancy-group 2 node 1 priority 100\n"+
		"set interfaces reth1 redundant-ether-options redundancy-group 2\n"+
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth1\n"+
		"set interfaces ge-7/0/1 gigether-options redundant-parent reth1\n"+
		"set interfaces reth1 unit 0 family inet address 10.0.1.1/24\n").ActiveConfig()
	f.run(time.Second, nil)
	if f.charged(t, 1) {
		t.Fatal("RG1's debt survived its RETH member leaving the configuration")
	}
}

// D5 (lane T's rule): a NOT-REQUIRED member never accrues debt, and does not
// block a clear.
func TestMemberShimDebtNeverForANotRequiredMember19140(t *testing.T) {
	f := newShimFixture19140(t)
	f.run(3*memberShimDebtGrace, map[string]dpuserspace.DataMemberShimStatus{"ge-0-0-0": excluded19140})
	if f.charged(t, 1) {
		t.Fatal("a not-required member charged its RG")
	}
	f.run(memberShimDebtGrace+2*time.Second, map[string]dpuserspace.DataMemberShimStatus{"ge-0-0-0": missing19140})
	f.run(memberShimClearHold+2*time.Second, map[string]dpuserspace.DataMemberShimStatus{"ge-0-0-0": excluded19140})
	if f.charged(t, 1) {
		t.Fatal("a member that became not-required kept its RG charged past the clear-hold")
	}
}

// D6: unverified HOLDS an episode, it does not reset it. Missing 6 s,
// unverified 3 s, missing again: the debt is due 10 s after the FIRST missing
// tick, not 10 s after the unverified run.
func TestMemberShimDebtUnverifiedHoldsTheEpisode19140(t *testing.T) {
	f := newShimFixture19140(t)
	f.run(6*time.Second, map[string]dpuserspace.DataMemberShimStatus{"ge-0-0-0": missing19140})
	f.run(3*time.Second, map[string]dpuserspace.DataMemberShimStatus{"ge-0-0-0": unverified19140})
	f.run(2*time.Second, map[string]dpuserspace.DataMemberShimStatus{"ge-0-0-0": missing19140})
	if !f.charged(t, 1) {
		t.Fatal("an unverified run reset the episode: no debt 11 s after the member first went missing")
	}
}

// The producer is wired into the transit-gate tick (reassertTransitGate),
// which runs every second and on every XDP link event.
func TestTransitGateTickRunsTheMemberShimProducer19140(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "transit_gate_tick_9725.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "reassertTransitGate" {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "applyMemberShimDebt" {
					found = true
				}
			}
			return true
		})
		return false
	})
	if !found {
		t.Fatal("reassertTransitGate does not run applyMemberShimDebt: the producer never ticks")
	}
}
