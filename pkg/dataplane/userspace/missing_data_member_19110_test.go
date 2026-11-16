package userspace

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #19110: a configured RETH data member with NO shim XDP is a takeover-
// readiness reason, from a live verdict the status tick publishes
// (missing_data_member_19110.go). Nothing retries the attach automatically.
// The kernel is a fake behind memberXDPStateFn; the loaded program is a fake
// pointer behind entryProgramHook, whose ID still goes through the REAL
// identification cache (only programIDFn, the syscall, is replaced).

const shimProg19110 = 7

type fakeDev19110 struct {
	ifindex       int
	prog          uint32
	notAttachable bool
}

type fakeKernel19110 struct {
	mu      sync.Mutex
	devs    map[string]*fakeDev19110
	lookups int
	byName  map[string]int
	onLook  map[string]func() // runs inside the lookup of that name
	idCalls int
	ids     map[*ebpf.Program]uint32
	idErr   error
	now     time.Time
	attach  int // attach attempts seen by the #18740 seam
}

func (k *fakeKernel19110) state(name string) (memberXDPState, error) {
	k.mu.Lock()
	k.lookups++
	if k.byName == nil {
		k.byName = map[string]int{}
	}
	k.byName[name]++
	hook := k.onLook[name]
	k.mu.Unlock()
	if hook != nil {
		hook()
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	d, ok := k.devs[name]
	if !ok {
		return memberXDPState{}, errMemberAbsent
	}
	return memberXDPState{Ifindex: d.ifindex, Attached: d.prog != 0, ProgID: d.prog, NotAttachable: d.notAttachable}, nil
}

func (k *fakeKernel19110) programID(p *ebpf.Program) (uint32, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.idCalls++
	if k.idErr != nil {
		return 0, k.idErr
	}
	return k.ids[p], nil
}

func (k *fakeKernel19110) clock() time.Time {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.now
}

func (k *fakeKernel19110) advance(d time.Duration) {
	k.mu.Lock()
	k.now = k.now.Add(d)
	k.mu.Unlock()
}

func (k *fakeKernel19110) set(name string, ifindex int, prog uint32) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.devs[name] = &fakeDev19110{ifindex: ifindex, prog: prog}
}

func (k *fakeKernel19110) counts() (lookups, idCalls, attach int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.lookups, k.idCalls, k.attach
}

type memberFixture19110 struct {
	m     *Manager
	k     *fakeKernel19110
	cfg   *config.Config
	progA *ebpf.Program
	prog  *ebpf.Program // what entryProgramHook returns
	pmu   sync.Mutex
}

func (f *memberFixture19110) setProgram(p *ebpf.Program) {
	f.pmu.Lock()
	f.prog = p
	f.pmu.Unlock()
}

// newMemberFixture19110 is a HEALTHY standby whose local RETH data members are
// ge-0-0-1 (ifindex 29) and, with two=true, ge-0-0-2 (ifindex 30), each with
// the shim attached. ge-0-0-0 is the fabric parent and ge-7-0-1 is node1's
// member; neither is a local member.
func newMemberFixture19110(t *testing.T, two bool) *memberFixture19110 {
	t.Helper()
	progA := &ebpf.Program{}
	k := &fakeKernel19110{
		devs:   map[string]*fakeDev19110{"ge-0-0-1": {ifindex: 29, prog: shimProg19110}},
		onLook: map[string]func(){},
		ids:    map[*ebpf.Program]uint32{progA: shimProg19110},
		now:    time.Unix(1_800_000_000, 0),
	}
	oldState, oldID, oldNow := memberXDPStateFn, programIDFn, memberNow
	memberXDPStateFn, programIDFn, memberNow = k.state, k.programID, k.clock
	t.Cleanup(func() { memberXDPStateFn, programIDFn, memberNow = oldState, oldID, oldNow })
	oldIdx := ifindexByNameFn
	ifindexByNameFn = func(name string) (int, error) {
		st, err := k.state(name)
		return st.Ifindex, err
	}
	t.Cleanup(func() { ifindexByNameFn = oldIdx })
	t.Cleanup(dataplane.SetXDPTransitionSeamForTest(func(op string, ifindex int, generic bool) (bool, error) {
		if op == "attach" {
			k.mu.Lock()
			k.attach++
			k.mu.Unlock()
		}
		return true, nil
	}))

	f := &memberFixture19110{k: k, progA: progA, prog: progA}
	m := New()
	m.clusterHA = true
	m.bpfShim = dataplane.New()
	m.entryProgramHook = func() *ebpf.Program {
		f.pmu.Lock()
		defer f.pmu.Unlock()
		return f.prog
	}
	cfg := f4Config19110(true)
	if two {
		k.set("ge-0-0-2", 30, shimProg19110)
		cfg.Interfaces.Interfaces["ge-0/0/2"] = &config.InterfaceConfig{Name: "ge-0/0/2", RedundantParent: "reth0"}
	}
	m.refreshGenericDataMembers(cfg) // the compile that sets the membership authority
	m.mu.Lock()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: 1}}
	m.lastStatus = ProcessStatus{
		Enabled:         true,
		ForwardingArmed: true,
		Capabilities:    UserspaceCapabilities{ForwardingSupported: true},
	}
	m.mode = ModeUserspaceCompat
	m.xskLivenessProven = true
	m.eventStream = boundEventStream(t)
	m.mu.Unlock()
	f.m, f.cfg = m, cfg
	return f
}

func ready19110(m *Manager, peerAlive bool) (bool, []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.takeoverReadyLocked(peerAlive)
}

func missingReasonIn19110(reasons []string) (string, bool) {
	for _, r := range reasons {
		if strings.Contains(r, missingDataMemberReasonMarker) {
			return r, true
		}
	}
	return "", false
}

func wantReady19110(t *testing.T, m *Manager, what string) {
	t.Helper()
	if ready, reasons := ready19110(m, true); !ready {
		t.Fatalf("%s: not ready: %v", what, reasons)
	}
}

func wantNotReady19110(t *testing.T, m *Manager, what string, needles ...string) string {
	t.Helper()
	ready, reasons := ready19110(m, true)
	r, ok := missingReasonIn19110(reasons)
	if ready || !ok {
		t.Fatalf("%s: ready=%v reasons %v, want NOT ready with a missing-member reason", what, ready, reasons)
	}
	for _, n := range needles {
		if !strings.Contains(r, n) {
			t.Errorf("%s: reason %q does not contain %q", what, r, n)
		}
	}
	return r
}

// The TRUE twin, on the readiness BOOLEAN: a healthy standby with its member
// attached is ready; unattached or carrying a foreign program, it is NOT. A
// lone owner stays ready, but the metric shows the blocker.
func TestMissingDataMemberTrueTwinReadiness19110(t *testing.T) {
	f := newMemberFixture19110(t, false)
	f.m.observeDataMembers()
	wantReady19110(t, f.m, "fixture: the healthy standby with its member attached")
	for _, tc := range []struct {
		prog uint32
		kind string
	}{{0, "not-attached"}, {99, "foreign-program"}} {
		f.k.set("ge-0-0-1", 29, tc.prog)
		f.m.observeDataMembers()
		if ready, _ := ready19110(f.m, true); ready {
			t.Errorf("prog %d: a standby whose RETH member has no shim XDP reports takeover-READY", tc.prog)
		}
		r := wantNotReady19110(t, f.m, fmt.Sprintf("prog %d", tc.prog), "ge-0-0-1", tc.kind, "ifindex 29")
		if got := MapHATakeoverBlocker(r); got != HATakeoverBlockerXDPMissingDataMember {
			t.Errorf("blocker = %q, want %q", got, HATakeoverBlockerXDPMissingDataMember)
		}
		if !slices.Contains(f.m.HATakeoverReadiness().Blockers, HATakeoverBlockerXDPMissingDataMember) {
			t.Error("the takeover-blocker metric does not carry xdp_missing_data_member")
		}
		if ready, reasons := ready19110(f.m, false); !ready {
			t.Errorf("prog %d: a LONE owner was made not-ready (%v); it has no better node", tc.prog, reasons)
		}
	}
}

// A SLOW pass with DISTINCT observation times: A's lookup is slow, so A is
// observed at T0 and B at T0+4s; A loses its attachment during B's lookup. At
// T0+4s the EARLIEST observation (A's) has expired and the latest (B's) is
// fresh. The verdict is aged from the earliest, so it reads not-ready instead
// of serving A's old positive evidence as fresh.
func TestMissingDataMemberSlowPassReadsNotReady19110(t *testing.T) {
	f := newMemberFixture19110(t, true)
	f.m.observeDataMembers()
	wantReady19110(t, f.m, "fixture")
	f.k.onLook["ge-0-0-1"] = func() { f.k.advance(memberVerdictMaxAge + time.Second) } // A's lookup is slow
	f.k.onLook["ge-0-0-2"] = func() {
		f.k.mu.Lock()
		f.k.devs["ge-0-0-1"].prog = 0 // A loses its attachment while B is looked up
		f.k.mu.Unlock()
	}
	f.m.observeDataMembers()
	f.m.mu.Lock()
	a, b := f.m.memberVerdict.obs["ge-0-0-1"].at, f.m.memberVerdict.obs["ge-0-0-2"].at
	f.m.mu.Unlock()
	if !b.After(a) || f.k.clock().Sub(b) > memberVerdictMaxAge || f.k.clock().Sub(a) <= memberVerdictMaxAge {
		t.Fatalf("fixture: want A expired and B fresh (A at %v, B at %v, now %v)", a, b, f.k.clock())
	}
	wantNotReady19110(t, f.m, "A's positive evidence is older than the verdict window", "unverified")
}

// A FAILED lookup is not-ready, recomputed every tick: never the previous tick's
// answer carried forward, in either direction.
func TestMissingDataMemberFailedLookupMeansNotReady19110(t *testing.T) {
	f := newMemberFixture19110(t, false)
	f.m.observeDataMembers()
	wantReady19110(t, f.m, "fixture")
	var mu sync.Mutex
	fail := true
	inner := memberXDPStateFn
	memberXDPStateFn = func(name string) (memberXDPState, error) {
		mu.Lock()
		failing := fail
		mu.Unlock()
		if failing {
			return memberXDPState{}, errors.New("netlink: receive timeout")
		}
		return inner(name)
	}
	f.m.observeDataMembers()
	wantNotReady19110(t, f.m, "a failed lookup must not carry the previous positive answer", "unverified")
	mu.Lock()
	fail = false
	mu.Unlock()
	f.m.observeDataMembers()
	wantReady19110(t, f.m, "the next tick's successful lookup")
}

// The loaded program cannot be identified (the info query fails): its members
// are UNVERIFIED, never skipped as if no program were loaded.
func TestMissingDataMemberUnidentifiedProgramMeansNotReady19110(t *testing.T) {
	f := newMemberFixture19110(t, false)
	f.k.mu.Lock()
	f.k.idErr = errors.New("bpf obj info: permission denied")
	f.k.mu.Unlock()
	f.m.observeDataMembers()
	wantNotReady19110(t, f.m, "an unidentifiable loaded program", "could not be identified")
	// A failed identification is not cached: the next tick asks again.
	f.k.mu.Lock()
	f.k.idErr = nil
	f.k.mu.Unlock()
	f.m.observeDataMembers()
	wantReady19110(t, f.m, "the next tick identified the program")
}

// The program ID comes from the tick's REAL identification cache: one info query
// per loaded program, none from readiness. A reloaded program invalidates the
// verdict until the next tick identifies it.
func TestMissingDataMemberProgramIDIsCachedOnTheTick19110(t *testing.T) {
	f := newMemberFixture19110(t, false)
	f.m.observeDataMembers()
	f.m.observeDataMembers()
	if _, ids, _ := f.k.counts(); ids != 1 {
		t.Errorf("%d program info queries over two ticks with one loaded program, want 1 (cached)", ids)
	}
	wantReady19110(t, f.m, "fixture")
	progB := &ebpf.Program{}
	f.k.mu.Lock()
	f.k.ids[progB] = 8
	f.k.mu.Unlock()
	f.setProgram(progB) // the shim reloaded its program
	wantNotReady19110(t, f.m, "a verdict made against the previous program", "loaded shim program")
	f.k.set("ge-0-0-1", 29, 8) // the reload re-attached the member with the new program
	f.m.observeDataMembers()
	if _, ids, _ := f.k.counts(); ids != 2 {
		t.Errorf("%d info queries after the reload, want 2", ids)
	}
	wantReady19110(t, f.m, "after the tick identified the reloaded program")
}

// NO shim program loaded is its own state: the check is skipped (other reasons
// block such a node), even with the member unattached.
func TestMissingDataMemberNoProgramLoadedIsADistinctState19110(t *testing.T) {
	f := newMemberFixture19110(t, false)
	f.k.set("ge-0-0-1", 29, 0)
	f.setProgram(nil)
	f.m.observeDataMembers()
	if r, ok := missingReasonIn19110(reasonsOnly19110(f.m)); ok {
		t.Errorf("with no shim program loaded the check blocked readiness: %q", r)
	}
}

// A new configuration invalidates the verdict until the next tick observes it.
func TestMissingDataMemberConfigChangeIsUnverifiedUntilObserved19110(t *testing.T) {
	f := newMemberFixture19110(t, false)
	f.m.observeDataMembers()
	wantReady19110(t, f.m, "fixture")
	f.m.refreshGenericDataMembers(f4Config19110(true)) // a commit
	wantNotReady19110(t, f.m, "a verdict made against the previous configuration", "current configuration")
	f.m.observeDataMembers()
	wantReady19110(t, f.m, "after the tick observed the new configuration")
}

// A verdict whose earliest observation is older than memberVerdictMaxAge (a
// stalled loop) is not served.
func TestMissingDataMemberStaleVerdictMeansNotReady19110(t *testing.T) {
	f := newMemberFixture19110(t, false)
	f.m.observeDataMembers()
	wantReady19110(t, f.m, "fixture")
	f.k.advance(memberVerdictMaxAge + time.Second)
	wantNotReady19110(t, f.m, "a stale verdict", "no observation in the last")
}

// An absent configured member is not ready.
func TestMissingDataMemberAbsentNetdevMeansNotReady19110(t *testing.T) {
	f := newMemberFixture19110(t, false)
	f.k.mu.Lock()
	delete(f.k.devs, "ge-0-0-1")
	f.k.mu.Unlock()
	f.m.observeDataMembers()
	wantNotReady19110(t, f.m, "an absent configured member", "absent")
}

// An administratively DISABLED member is not a required attachment: never a
// blocker, even when absent and even when the verdict is stale, and the tick
// does not even look it up.
func TestMissingDataMemberDisabledMemberIsNotABlocker19110(t *testing.T) {
	f := newMemberFixture19110(t, false)
	cfg := f4Config19110(true)
	cfg.Interfaces.Interfaces["ge-0/0/1"] = &config.InterfaceConfig{Name: "ge-0/0/1", RedundantParent: "reth1", Disable: true}
	f.m.refreshGenericDataMembers(cfg)
	f.k.mu.Lock()
	delete(f.k.devs, "ge-0-0-1")
	before := f.k.byName["ge-0-0-1"]
	f.k.mu.Unlock()
	f.m.observeDataMembers()
	f.k.mu.Lock()
	looked := f.k.byName["ge-0-0-1"] - before
	f.k.mu.Unlock()
	if looked != 0 {
		t.Errorf("the tick looked up a disabled member %d time(s); it is not a required attachment", looked)
	}
	wantReady19110(t, f.m, "a disabled member")
	f.k.advance(memberVerdictMaxAge + time.Second)
	wantReady19110(t, f.m, "a disabled member under a stale verdict")
}

// A member with known non-Ethernet framing is never attached by the shim: not
// a blocker.
func TestMissingDataMemberNonEthernetMemberIsNotABlocker19110(t *testing.T) {
	f := newMemberFixture19110(t, false)
	f.k.mu.Lock()
	f.k.devs["ge-0-0-1"] = &fakeDev19110{ifindex: 29, notAttachable: true}
	f.k.mu.Unlock()
	f.m.observeDataMembers()
	wantReady19110(t, f.m, "a non-Ethernet member")
}

// Readiness does no lookup and no program info query: it is called under m.mu
// by the RG reconcile loop and the metrics scrape, and serves the tick's
// verdict.
func TestMissingDataMemberReadinessDoesNoLookup19110(t *testing.T) {
	f := newMemberFixture19110(t, false)
	f.m.observeDataMembers()
	l0, i0, _ := f.k.counts()
	ready19110(f.m, true)
	f.m.HATakeoverReadiness()
	if l1, i1, _ := f.k.counts(); l1 != l0 || i1 != i0 {
		t.Errorf("readiness made %d member lookup(s) and %d program info query(ies) itself; it must serve the "+
			"tick's verdict", l1-l0, i1-i0)
	}
}

// Nothing retries the attach automatically: ticks only observe.
func TestMissingDataMemberTicksNeverAttach19110(t *testing.T) {
	f := newMemberFixture19110(t, false)
	f.k.set("ge-0-0-1", 29, 0)
	for i := 0; i < 5; i++ {
		f.m.observeDataMembers()
		f.k.advance(time.Minute)
	}
	if _, _, attach := f.k.counts(); attach != 0 {
		t.Errorf("the status tick attempted %d attach(es); recovery is the next compile or a link-refresh event", attach)
	}
}

func captureSlog19110(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func countLines19110(buf *bytes.Buffer, level, substr string) int {
	n := 0
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "level="+level) && strings.Contains(line, substr) {
			n++
		}
	}
	return n
}

// Logs are on change, keyed on the STABLE kind: the same kind at a new ifindex
// is not a new ERROR. The ERROR says recovery is not automatic.
func TestMissingDataMemberLogsOnAStableKind19110(t *testing.T) {
	f := newMemberFixture19110(t, false)
	logs := captureSlog19110(t)
	f.k.set("ge-0-0-1", 29, 0)
	f.m.observeDataMembers()
	f.m.observeDataMembers()
	f.k.set("ge-0-0-1", 41, 0) // recreated, still unattached
	f.m.observeDataMembers()
	if n := countLines19110(logs, "ERROR", "no XDP shim attached"); n != 1 {
		t.Errorf("%d ERROR lines for one not-attached member over three ticks, want 1", n)
	}
	if !strings.Contains(logs.String(), "NOT retried automatically") {
		t.Error("the ERROR line does not tell the operator that recovery is not automatic")
	}
	f.k.set("ge-0-0-1", 41, shimProg19110)
	f.m.observeDataMembers()
	if n := countLines19110(logs, "INFO", "has its XDP shim again"); n != 1 {
		t.Errorf("%d recovery INFO lines, want 1", n)
	}
}

func reasonsOnly19110(m *Manager) []string {
	_, r := ready19110(m, true)
	return r
}

// The status loop observes right AFTER a tick releases m.mu, so the lookups and
// the program info query never run under the lock.
func TestStatusLoopObservesAfterUnlock19110(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "process_status.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	isCall := func(s ast.Stmt, recv, sel string) bool {
		es, ok := s.(*ast.ExprStmt)
		if !ok {
			return false
		}
		ce, ok := es.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		se, ok := ce.Fun.(*ast.SelectorExpr)
		if !ok || se.Sel.Name != sel {
			return false
		}
		if recv == "" {
			return true
		}
		inner, ok := se.X.(*ast.SelectorExpr)
		return ok && inner.Sel.Name == recv
	}
	found := false
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "statusLoop" || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			var list []ast.Stmt
			switch x := n.(type) {
			case *ast.BlockStmt:
				list = x.List
			case *ast.CommClause:
				list = x.Body
			case *ast.CaseClause:
				list = x.Body
			default:
				return true
			}
			for i := 1; i < len(list); i++ {
				if isCall(list[i], "", "observeDataMembers") && isCall(list[i-1], "mu", "Unlock") {
					found = true
				}
			}
			return true
		})
	}
	if !found {
		t.Error("statusLoop does not call observeDataMembers immediately after m.mu.Unlock()")
	}
}

// Before the first observation there is no verdict for this configuration:
// every required member is unverified.
func TestMissingDataMemberBeforeTheFirstObservation19110(t *testing.T) {
	f := newMemberFixture19110(t, false)
	wantNotReady19110(t, f.m, "readiness before any tick", "unverified")
}

// A COLD cache: readiness before any tick makes no lookup and no program info
// query; identification happens only on the tick.
func TestMissingDataMemberColdCacheReadinessMakesNoQuery19110(t *testing.T) {
	f := newMemberFixture19110(t, false)
	l0, i0, _ := f.k.counts()
	ready19110(f.m, true)
	f.m.HATakeoverReadiness()
	if l1, i1, _ := f.k.counts(); l1 != l0 || i1 != i0 {
		t.Errorf("readiness on a cold cache made %d lookup(s) and %d program info query(ies)", l1-l0, i1-i0)
	}
}

// A disabled untagged unit 0 collapses onto the base netdev, so the base row is
// administratively disabled (baseRowAdminDisabled) and structural admission
// refuses it: not a blocker. The control is a VLAN-tagged unit 0, which has
// its own netdev, so the base row stays required.
func TestMissingDataMemberDisabledUnitZeroOnTheSameDevice19110(t *testing.T) {
	for _, tc := range []struct {
		name    string
		vlan    int
		blocker bool
	}{{"untagged unit 0 (same netdev)", 0, false}, {"VLAN unit 0 (own netdev)", 50, true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMemberFixture19110(t, false)
			cfg := f4Config19110(true)
			cfg.Interfaces.Interfaces["ge-0/0/1"] = &config.InterfaceConfig{
				Name: "ge-0/0/1", RedundantParent: "reth1",
				Units: map[int]*config.InterfaceUnit{0: {Number: 0, Disable: true, VlanID: tc.vlan}},
			}
			f.m.refreshGenericDataMembers(cfg)
			f.k.set("ge-0-0-1", 29, 0) // the attach paths left it unattached
			f.m.observeDataMembers()
			ready, reasons := ready19110(f.m, true)
			if tc.blocker && ready {
				t.Errorf("%s: the base row is required and unattached, yet ready (%v)", tc.name, reasons)
			}
			if !tc.blocker && !ready {
				t.Errorf("%s: the base row is administratively disabled, yet not ready: %v", tc.name, reasons)
			}
		})
	}
}

// A known non-Ethernet member stays excluded when the verdict goes stale (no new
// tick) and when the loaded program cannot be identified: "required?" is
// decided by framing, independent of attachment freshness and of the program.
func TestMissingDataMemberNonEthernetExclusionSurvivesStalenessAndIdentification19110(t *testing.T) {
	f := newMemberFixture19110(t, false)
	f.k.mu.Lock()
	f.k.devs["ge-0-0-1"] = &fakeDev19110{ifindex: 29, notAttachable: true}
	f.k.mu.Unlock()
	f.m.observeDataMembers()
	wantReady19110(t, f.m, "a non-Ethernet member")
	f.k.advance(memberVerdictMaxAge + time.Second)
	wantReady19110(t, f.m, "a non-Ethernet member under a stale verdict")

	g := newMemberFixture19110(t, false)
	g.k.mu.Lock()
	g.k.devs["ge-0-0-1"] = &fakeDev19110{ifindex: 29, notAttachable: true}
	g.k.idErr = errors.New("bpf obj info: permission denied")
	g.k.mu.Unlock()
	g.m.observeDataMembers()
	wantReady19110(t, g.m, "a non-Ethernet member while the program is unidentified")
}
