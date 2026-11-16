package userspace

import (
	"bytes"
	"context"
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
	"syscall"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #19110: a configured RETH data member with NO shim XDP is a readiness reason
// from LIVE kernel state, and is retried by NAME on later ticks
// (missing_data_member_19110.go). The kernel is a fake, read through the
// memberXDPStateFn seam and written by the #18740 attach seam, so every
// attach goes through the production AttachShimXDPInterfaces path.

const shimProg19110 = 7

type fakeDev19110 struct {
	ifindex int
	prog    uint32
}

type fakeKernel19110 struct {
	mu      sync.Mutex
	devs    map[string]*fakeDev19110
	refuse  map[int]error // ifindex -> the attach's error (native and generic)
	ops     []string
	queried []string
	nth     int
}

func (k *fakeKernel19110) state(name string) (memberXDPState, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.queried = append(k.queried, name)
	d, ok := k.devs[name]
	if !ok {
		return memberXDPState{}, errMemberAbsent
	}
	return memberXDPState{Ifindex: d.ifindex, Attached: d.prog != 0, ProgID: d.prog}, nil
}

func (k *fakeKernel19110) seam(op string, ifindex int, generic bool) (bool, error) {
	if op != "attach" {
		return true, nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.ops = append(k.ops, fmt.Sprintf("attach/%d", ifindex))
	if err := k.refuse[ifindex]; err != nil {
		k.nth++
		// The text changes on every attempt (as the shim's elapsed time does);
		// the errno does not.
		return true, fmt.Errorf("attach XDP to ifindex %d (attempt %d): %w", ifindex, k.nth, err)
	}
	for _, d := range k.devs {
		if d.ifindex == ifindex {
			d.prog = shimProg19110
		}
	}
	return true, nil
}

func (k *fakeKernel19110) set(name string, ifindex int, prog uint32) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.devs[name] = &fakeDev19110{ifindex: ifindex, prog: prog}
}

func (k *fakeKernel19110) remove(name string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.devs, name)
}

func (k *fakeKernel19110) refuseWith(ifindex int, err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err == nil {
		delete(k.refuse, ifindex)
		return
	}
	k.refuse[ifindex] = err
}

func (k *fakeKernel19110) prog(name string) uint32 {
	k.mu.Lock()
	defer k.mu.Unlock()
	if d, ok := k.devs[name]; ok {
		return d.prog
	}
	return 0
}

func (k *fakeKernel19110) opsSnapshot() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.ops)
}

// newMemberFixture19110 is a HEALTHY standby whose only configured local RETH
// data member is ge-0-0-1 (ifindex 29, the shim attached). ge-0-0-0 is the
// fabric parent and ge-7-0-1 is node1's member; neither is a local member.
func newMemberFixture19110(t *testing.T) (*Manager, *fakeKernel19110, *config.Config) {
	t.Helper()
	k := &fakeKernel19110{
		devs:   map[string]*fakeDev19110{"ge-0-0-1": {ifindex: 29, prog: shimProg19110}},
		refuse: map[int]error{},
	}
	oldState := memberXDPStateFn
	memberXDPStateFn = k.state
	t.Cleanup(func() { memberXDPStateFn = oldState })
	oldIdx := ifindexByNameFn
	ifindexByNameFn = func(name string) (int, error) {
		st, err := k.state(name)
		return st.Ifindex, err
	}
	t.Cleanup(func() { ifindexByNameFn = oldIdx })
	t.Cleanup(dataplane.SetXDPTransitionSeamForTest(k.seam))

	m := New()
	m.clusterHA = true
	m.bpfShim = dataplane.New()
	m.shimProgIDHook = func() (uint32, bool) { return shimProg19110, true }
	m.rxVlanPreconditionCheck = func(string) (error, error) { return nil, nil }
	cfg := f4Config19110(true)
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
	return m, k, cfg
}

func ready19110(m *Manager, peerAlive bool) (bool, []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.takeoverReadyLocked(peerAlive)
}

func tick19110(m *Manager, now time.Time) {
	m.retryMissingDataMembersOnce(context.Background(), now)
}

func retryState19110(m *Manager, name string) (memberAttachRetry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.memberAttachRetry[name]
	if !ok {
		return memberAttachRetry{}, false
	}
	return *r, true
}

func countAttach19110(k *fakeKernel19110, ifindex int) int {
	n := 0
	for _, op := range k.opsSnapshot() {
		if op == fmt.Sprintf("attach/%d", ifindex) {
			n++
		}
	}
	return n
}

func missingReasonIn19110(reasons []string) (string, bool) {
	for _, r := range reasons {
		if strings.Contains(r, missingDataMemberReasonMarker) {
			return r, true
		}
	}
	return "", false
}

// The TRUE twin, on the readiness BOOLEAN: a healthy standby with the member
// attached is ready; the same standby with the member unattached, or carrying a
// foreign program, is NOT. A lone owner stays ready but the metric shows it.
// Readiness serves the last tick's verdict, so each state is read through a
// tick; the attach stays refused so the tick cannot repair it.
func TestMissingDataMemberTrueTwinReadiness19110(t *testing.T) {
	m, k, _ := newMemberFixture19110(t)
	tick19110(m, time.Now())
	if ready, reasons := ready19110(m, true); !ready {
		t.Fatalf("fixture: the healthy standby with its member attached is not ready: %v", reasons)
	}
	k.refuseWith(29, syscall.EBUSY)
	for _, tc := range []struct {
		prog uint32
		kind string
	}{{0, "not-attached"}, {99, "foreign-program"}} {
		k.set("ge-0-0-1", 29, tc.prog)
		tick19110(m, time.Now().Add(time.Hour))
		ready, reasons := ready19110(m, true)
		if ready {
			t.Errorf("prog %d: a standby whose RETH member has no shim XDP reports takeover-READY", tc.prog)
		}
		r, ok := missingReasonIn19110(reasons)
		if !ok {
			t.Fatalf("prog %d: no missing-member reason in %v", tc.prog, reasons)
		}
		for _, want := range []string{"ge-0-0-1", tc.kind, "ifindex 29"} {
			if !strings.Contains(r, want) {
				t.Errorf("reason %q does not name %q", r, want)
			}
		}
		if got := MapHATakeoverBlocker(r); got != HATakeoverBlockerXDPMissingDataMember {
			t.Errorf("blocker = %q, want %q", got, HATakeoverBlockerXDPMissingDataMember)
		}
		if !slices.Contains(m.HATakeoverReadiness().Blockers, HATakeoverBlockerXDPMissingDataMember) {
			t.Error("the takeover-blocker metric does not carry xdp_missing_data_member")
		}
		if ready, reasons := ready19110(m, false); !ready {
			t.Errorf("prog %d: a LONE owner was made not-ready (%v); it has no better node", tc.prog, reasons)
		}
	}
	if slices.Contains(k.queried, "ge-7-0-1") || slices.Contains(k.queried, "ge-0-0-0") {
		t.Errorf("readiness looked up a non-member (queried %v): only local RETH data members count", k.queried)
	}
}

// Admission refusal keeps the obligation; recovery comes through ticks only.
func TestMissingDataMemberAdmissionRefusalRecoversThroughTicks19110(t *testing.T) {
	m, k, _ := newMemberFixture19110(t)
	k.set("ge-0-0-1", 29, 0)
	var admit sync.Mutex
	stag := errors.New("s-tag offload stuck")
	m.rxVlanPreconditionCheck = func(string) (error, error) {
		admit.Lock()
		defer admit.Unlock()
		return nil, stag
	}
	t0 := time.Now()
	tick19110(m, t0)
	if n := len(k.opsSnapshot()); n != 0 {
		t.Fatalf("an attach was attempted (%v) while admission refused", k.opsSnapshot())
	}
	r, owed := retryState19110(m, "ge-0-0-1")
	if !owed || r.kind != "admission:s-tag-precondition" {
		t.Fatalf("admission refusal did not keep the obligation (state %+v, owed %v)", r, owed)
	}
	if ready, _ := ready19110(m, true); ready {
		t.Fatal("ready while the member is unattached")
	}
	admit.Lock()
	stag = nil
	admit.Unlock()
	tick19110(m, t0.Add(500*time.Millisecond))
	if n := len(k.opsSnapshot()); n != 0 {
		t.Fatalf("retried before due: %v", k.opsSnapshot())
	}
	tick19110(m, t0.Add(memberRetryMin))
	if got := k.opsSnapshot(); !slices.Equal(got, []string{"attach/29"}) {
		t.Fatalf("ops %v, want one attach of the live ifindex 29", got)
	}
	if _, owed := retryState19110(m, "ge-0-0-1"); owed {
		t.Error("the obligation survived a successful attach")
	}
	if ready, reasons := ready19110(m, true); !ready {
		t.Errorf("not ready after recovery: %v", reasons)
	}
}

// A second recreate moves the member to a NEW ifindex: the retry follows the
// name through ticks only, and never attaches the old index again.
func TestMissingDataMemberSecondRecreateRecoversThroughTicks19110(t *testing.T) {
	m, k, _ := newMemberFixture19110(t)
	k.set("ge-0-0-1", 29, 0)
	k.refuseWith(29, syscall.EBUSY)
	t0 := time.Now()
	tick19110(m, t0)
	if countAttach19110(k, 29) != 1 {
		t.Fatalf("fixture: ops %v, want one refused attach of 29", k.opsSnapshot())
	}
	k.set("ge-0-0-1", 41, 0) // the second recreate; 29 is gone
	tick19110(m, t0.Add(memberRetryMin))
	if countAttach19110(k, 29) != 1 {
		t.Errorf("the retry attached the OLD ifindex 29 again (ops %v): a remembered index", k.opsSnapshot())
	}
	if countAttach19110(k, 41) != 1 {
		t.Fatalf("the retry did not attach the member's new ifindex 41 (ops %v)", k.opsSnapshot())
	}
	if ready, reasons := ready19110(m, true); !ready {
		t.Errorf("not ready after the retry attached 41: %v", reasons)
	}
}

// The old ifindex is REUSED by another device: it must never be attached.
func TestMissingDataMemberNeverAttachesAReusedOldIndex19110(t *testing.T) {
	m, k, _ := newMemberFixture19110(t)
	k.set("ge-0-0-1", 29, 0)
	k.refuseWith(29, syscall.EBUSY)
	t0 := time.Now()
	tick19110(m, t0)
	k.refuseWith(29, nil)
	k.set("ge-0-0-1", 41, 0)
	k.refuseWith(41, syscall.EBUSY) // keep the member failing
	k.set("other0", 29, 0)          // an unrelated device reuses 29
	tick19110(m, t0.Add(memberRetryMin))
	if k.prog("other0") != 0 || countAttach19110(k, 29) != 1 {
		t.Errorf("the retry attached the reused ifindex 29, now another device (ops %v)", k.opsSnapshot())
	}
	if countAttach19110(k, 41) != 1 {
		t.Errorf("ops %v, want one attempt on the member's live ifindex 41", k.opsSnapshot())
	}
}

// A stale published snapshot (the member at an old ifindex) is irrelevant: the
// retry attaches the index the kernel resolves for the name now.
func TestMissingDataMemberIgnoresAStaleSnapshot19110(t *testing.T) {
	m, k, _ := newMemberFixture19110(t)
	k.set("ge-0-0-1", 29, 0)
	m.mu.Lock()
	m.lastSnapshot = &ConfigSnapshot{Interfaces: []InterfaceSnapshot{{Name: "ge-0/0/1", LinuxName: "ge-0-0-1", Ifindex: 17}}}
	m.mu.Unlock()
	tick19110(m, time.Now())
	if got := k.opsSnapshot(); !slices.Equal(got, []string{"attach/29"}) {
		t.Errorf("ops %v, want the live ifindex 29 only (the snapshot says 17)", got)
	}
}

// An absent netdev keeps the obligation and advances the backoff; when it
// appears, a tick attaches it.
func TestMissingDataMemberAbsentNetdevKeepsTheObligation19110(t *testing.T) {
	m, k, _ := newMemberFixture19110(t)
	k.remove("ge-0-0-1")
	t0 := time.Now()
	tick19110(m, t0)
	ready, reasons := ready19110(m, true)
	if r, ok := missingReasonIn19110(reasons); ready || !ok || !strings.Contains(r, "absent") {
		t.Fatalf("a configured member that is absent: ready=%v reasons %v, want not ready with an absent reason",
			ready, reasons)
	}
	tick19110(m, t0.Add(memberRetryMin))
	r, owed := retryState19110(m, "ge-0-0-1")
	if !owed || r.kind != "absent" || r.backoff != 2*memberRetryMin {
		t.Fatalf("absent member: state %+v owed %v, want kind absent with the backoff advanced to 2s", r, owed)
	}
	if n := len(k.opsSnapshot()); n != 0 {
		t.Fatalf("attached something for an absent member: %v", k.opsSnapshot())
	}
	k.set("ge-0-0-1", 52, 0)
	tick19110(m, t0.Add(memberRetryMin+2*memberRetryMin))
	if got := k.opsSnapshot(); !slices.Equal(got, []string{"attach/52"}) {
		t.Fatalf("ops %v, want one attach of the reappeared member at 52", got)
	}
	if ready, reasons := ready19110(m, true); !ready {
		t.Errorf("not ready after the member reappeared and was attached: %v", reasons)
	}
}

// Another path attaches the member: the next tick (before the retry is due)
// clears readiness and drops the retry, with no attach of its own.
func TestMissingDataMemberAttachedByAnotherPathClears19110(t *testing.T) {
	m, k, _ := newMemberFixture19110(t)
	k.set("ge-0-0-1", 29, 0)
	k.refuseWith(29, syscall.EBUSY)
	t0 := time.Now()
	tick19110(m, t0)
	if ready, _ := ready19110(m, true); ready {
		t.Fatal("fixture: ready while the member is unattached")
	}
	k.set("ge-0-0-1", 29, shimProg19110) // a compile attached it
	tick19110(m, t0.Add(100*time.Millisecond))
	if ready, reasons := ready19110(m, true); !ready {
		t.Errorf("readiness still blocks after another path attached the member: %v", reasons)
	}
	if _, owed := retryState19110(m, "ge-0-0-1"); owed {
		t.Error("the retry state survived positive attachment evidence")
	}
	if countAttach19110(k, 29) != 1 {
		t.Errorf("the retry attached again after another path did (ops %v)", k.opsSnapshot())
	}
}

// An attach that "succeeds" but leaves no evidence on the member keeps the
// obligation: the kernel, not the call's return, is the evidence.
func TestMissingDataMemberAttachWithoutEvidenceKeepsTheObligation19110(t *testing.T) {
	m, k, _ := newMemberFixture19110(t)
	k.set("ge-0-0-1", 29, 0)
	// The seam reports success but changes nothing the kernel shows.
	t.Cleanup(dataplane.SetXDPTransitionSeamForTest(func(op string, ifindex int, generic bool) (bool, error) {
		return true, nil
	}))
	tick19110(m, time.Now())
	if r, owed := retryState19110(m, "ge-0-0-1"); !owed || !strings.HasPrefix(r.kind, "unverified-after-attach") {
		t.Errorf("an attach with no kernel evidence cleared or mislabelled the obligation (state %+v owed %v)", r, owed)
	}
}

// The exact deadline: 1 s after the first failure, then 2 s, 4 s, ... 30 s.
func TestMissingDataMemberRetryDeadlineBoundary19110(t *testing.T) {
	m, k, _ := newMemberFixture19110(t)
	k.set("ge-0-0-1", 29, 0)
	k.refuseWith(29, syscall.EBUSY)
	now := time.Now()
	tick19110(m, now)
	var backoffs []time.Duration
	for i := 0; i < 7; i++ {
		r, _ := retryState19110(m, "ge-0-0-1")
		backoffs = append(backoffs, r.backoff)
		before := countAttach19110(k, 29)
		tick19110(m, now.Add(r.backoff-time.Millisecond))
		if countAttach19110(k, 29) != before {
			t.Fatalf("retry %d ran 1 ms before its %s deadline", i+1, r.backoff)
		}
		if r.backoff > memberRetryMin {
			tick19110(m, now.Add(memberRetryMin))
			if countAttach19110(k, 29) != before {
				t.Fatalf("retry %d ran 1 s after the failure, before its %s deadline", i+1, r.backoff)
			}
		}
		now = now.Add(r.backoff)
		tick19110(m, now)
		if countAttach19110(k, 29) != before+1 {
			t.Fatalf("retry %d did not run at its %s deadline", i+1, r.backoff)
		}
	}
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30}
	for i := range want {
		want[i] *= time.Second
	}
	if !slices.Equal(backoffs, want) {
		t.Errorf("backoffs %v, want %v", backoffs, want)
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

// Logs are on a STABLE kind: the same errno with different error text is one
// ERROR; a new errno is another. The retry's attach is Quiet, so the shim's
// fallback line is never a WARN on a retry.
func TestMissingDataMemberLogsOnAStableKind19110(t *testing.T) {
	m, k, _ := newMemberFixture19110(t)
	k.set("ge-0-0-1", 29, 0)
	k.refuseWith(29, syscall.EBUSY)
	logs := captureSlog19110(t)
	now := time.Now()
	tick19110(m, now)
	now = now.Add(memberRetryMin)
	tick19110(m, now)
	if n := countLines19110(logs, "ERROR", "no XDP shim attached"); n != 1 {
		t.Errorf("%d ERROR lines for two refusals of one kind (the error text differed each time), want 1", n)
	}
	k.refuseWith(29, syscall.EINVAL) // native and generic both fail: a different kind
	now = now.Add(2 * memberRetryMin)
	tick19110(m, now)
	if n := countLines19110(logs, "ERROR", "no XDP shim attached"); n != 2 {
		t.Errorf("%d ERROR lines after the kind changed to EINVAL, want 2", n)
	}
	if n := countLines19110(logs, "WARN", "native XDP unavailable"); n != 0 {
		t.Errorf("the retry's attach logged the generic fallback at WARN %d time(s); a retry attach is Quiet", n)
	}
}

// Removing the member from the configuration drops its retry.
func TestMissingDataMemberConfigRemovalDropsTheRetry19110(t *testing.T) {
	m, k, _ := newMemberFixture19110(t)
	k.set("ge-0-0-1", 29, 0)
	k.refuseWith(29, syscall.EBUSY)
	t0 := time.Now()
	tick19110(m, t0)
	if _, owed := retryState19110(m, "ge-0-0-1"); !owed {
		t.Fatal("fixture: no retry state")
	}
	cfg := f4Config19110(true)
	cfg.Interfaces.Interfaces["ge-0/0/1"] = &config.InterfaceConfig{Name: "ge-0/0/1"} // no longer a RETH member
	m.refreshGenericDataMembers(cfg)
	tick19110(m, t0.Add(time.Hour))
	if _, owed := retryState19110(m, "ge-0-0-1"); owed {
		t.Error("a member removed from the configuration kept its retry")
	}
	if countAttach19110(k, 29) != 1 {
		t.Errorf("a removed member was attached again (ops %v)", k.opsSnapshot())
	}
}

// One retry pass at a time: a second start while one runs does nothing.
func TestMissingDataMemberRetryIsSingleFlight19110(t *testing.T) {
	m, k, _ := newMemberFixture19110(t)
	k.set("ge-0-0-1", 29, 0)
	entered, release := make(chan struct{}, 4), make(chan struct{})
	var calls sync.WaitGroup
	calls.Add(1)
	var mu sync.Mutex
	n := 0
	oldState := memberXDPStateFn
	memberXDPStateFn = func(name string) (memberXDPState, error) {
		mu.Lock()
		n++
		first := n == 1
		mu.Unlock()
		if first {
			entered <- struct{}{}
			<-release
			defer calls.Done()
		}
		return k.state(name)
	}
	t.Cleanup(func() { memberXDPStateFn = oldState })
	if !m.startMissingDataMemberRetry(context.Background(), time.Now()) {
		t.Fatal("fixture: the first retry pass did not start")
	}
	<-entered
	if m.startMissingDataMemberRetry(context.Background(), time.Now()) {
		t.Error("a second retry pass started while the first was running: the retry is not single-flight")
	}
	close(release)
	calls.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for m.memberRetryInFlight.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if m.memberRetryInFlight.Load() {
		t.Fatal("the retry pass never finished")
	}
}

// With no shim program loaded, the check is skipped: other reasons block a node
// whose shim is not loaded, and hermetic fixtures never load one.
func TestMissingDataMemberSkippedWithoutAShimProgram19110(t *testing.T) {
	m, k, _ := newMemberFixture19110(t)
	k.set("ge-0-0-1", 29, 0)
	m.shimProgIDHook = func() (uint32, bool) { return 0, false }
	if r, ok := missingReasonIn19110(reasonsOnly19110(m)); ok {
		t.Errorf("a missing-member reason with no shim program to compare against: %q", r)
	}
}

func reasonsOnly19110(m *Manager) []string {
	_, r := ready19110(m, true)
	return r
}

// The status loop starts the retry right AFTER a tick releases m.mu, so the
// retry's netlink, ethtool and attach work never runs under the lock.
func TestStatusLoopStartsTheMemberRetryAfterUnlock19110(t *testing.T) {
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
			// A statement list is a block's, or a select/switch case's body (the
			// tick body is a `case <-tick:` of the loop's select).
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
				if isCall(list[i], "", "startMissingDataMemberRetry") && isCall(list[i-1], "mu", "Unlock") {
					found = true
				}
			}
			return true
		})
	}
	if !found {
		t.Error("statusLoop does not call startMissingDataMemberRetry immediately after m.mu.Unlock()")
	}
}

// A FAILED lookup is not-ready, recomputed every tick: it is never the previous
// tick's answer carried forward, in either direction.
func TestMissingDataMemberFailedLookupMeansNotReady19110(t *testing.T) {
	m, k, _ := newMemberFixture19110(t)
	tick19110(m, time.Now())
	if ready, reasons := ready19110(m, true); !ready {
		t.Fatalf("fixture: not ready with the member attached: %v", reasons)
	}
	var mu sync.Mutex
	fail := true
	oldState := memberXDPStateFn
	memberXDPStateFn = func(name string) (memberXDPState, error) {
		mu.Lock()
		f := fail
		mu.Unlock()
		if f {
			return memberXDPState{}, errors.New("netlink: receive timeout")
		}
		return k.state(name)
	}
	t.Cleanup(func() { memberXDPStateFn = oldState })
	tick19110(m, time.Now())
	ready, reasons := ready19110(m, true)
	if r, ok := missingReasonIn19110(reasons); ready || !ok || !strings.Contains(r, "unverified") {
		t.Fatalf("a failed lookup: ready=%v reasons %v, want NOT ready with an unverified reason; a failed "+
			"lookup must not carry the previous tick's positive answer forward", ready, reasons)
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	tick19110(m, time.Now())
	if ready, reasons := ready19110(m, true); !ready {
		t.Errorf("the next tick's successful lookup did not restore readiness: %v", reasons)
	}
}

// A verdict older than memberVerdictMaxAge (a stalled loop) is not served.
func TestMissingDataMemberStaleVerdictMeansNotReady19110(t *testing.T) {
	m, _, _ := newMemberFixture19110(t)
	tick19110(m, time.Now())
	if ready, reasons := ready19110(m, true); !ready {
		t.Fatalf("fixture: not ready: %v", reasons)
	}
	m.mu.Lock()
	m.memberVerdict.at = time.Now().Add(-memberVerdictMaxAge - time.Second)
	m.mu.Unlock()
	ready, reasons := ready19110(m, true)
	if r, ok := missingReasonIn19110(reasons); ready || !ok || !strings.Contains(r, "no live verdict") {
		t.Errorf("a stale verdict: ready=%v reasons %v, want NOT ready", ready, reasons)
	}
}

// A member configured after the last tick is not covered by its verdict: it is
// unverified until a tick checks it.
func TestMissingDataMemberUncheckedMemberIsUnverified19110(t *testing.T) {
	m, k, _ := newMemberFixture19110(t)
	tick19110(m, time.Now())
	k.set("ge-0-0-2", 30, shimProg19110)
	cfg2 := f4Config19110(true)
	cfg2.Interfaces.Interfaces["ge-0/0/2"] = &config.InterfaceConfig{Name: "ge-0/0/2", RedundantParent: "reth0"}
	m.refreshGenericDataMembers(cfg2)
	ready, reasons := ready19110(m, true)
	if r, ok := missingReasonIn19110(reasons); ready || !ok || !strings.Contains(r, "ge-0-0-2") ||
		!strings.Contains(r, "not checked yet") {
		t.Fatalf("a member no tick has checked yet: ready=%v reasons %v, want NOT ready", ready, reasons)
	}
	tick19110(m, time.Now())
	if ready, reasons := ready19110(m, true); !ready {
		t.Errorf("not ready after a tick checked the new, attached member: %v", reasons)
	}
}

// Readiness itself does no lookup: it is called under m.mu by the RG reconcile
// loop and the metrics scrape, and serves the tick's verdict.
func TestMissingDataMemberReadinessDoesNoLookup19110(t *testing.T) {
	m, k, _ := newMemberFixture19110(t)
	tick19110(m, time.Now())
	k.mu.Lock()
	before := len(k.queried)
	k.mu.Unlock()
	ready19110(m, true)
	m.HATakeoverReadiness()
	k.mu.Lock()
	after := len(k.queried)
	k.mu.Unlock()
	if after != before {
		t.Errorf("readiness looked up %d member(s) itself; it must serve the tick's verdict, with no syscall "+
			"under m.mu", after-before)
	}
}
