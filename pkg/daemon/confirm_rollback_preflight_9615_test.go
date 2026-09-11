package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #9615: the timed-out rollback of a commit-confirmed window applied its target
// unconditionally, on the grounds that it was pre-flighted when the window was
// armed. A window Store.Load re-armed at boot was never pre-flighted.

const abandoned9615 = "system { host-name abandoned; }"

// refusedTarget9615 is a tolerant-only config the helper refuses as a whole
// snapshot (#9410: a zone pair naming an undefined zone).
const refusedTarget9615 = `system { host-name refused-target; }
security { zones { security-zone trust; security-zone untrust; }
  policies { from-zone trust to-zone gone { policy bad1 { match { source-address any; destination-address any; application any; } then { permit; } } } } }
`

const healthyTarget9615 = `system { host-name healthy-target; }
security { zones { security-zone trust; security-zone untrust; }
  policies { from-zone trust to-zone untrust { policy p1 { match { source-address any; destination-address any; application any; } then { permit; } } } } }
`

// feedTarget9615 is a strict-valid target whose only policy matches a
// dynamic-address binding: with no installed feed snapshot the helper refuses
// it (#5645), and with one it is appliable.
func feedTarget9615(t *testing.T) string {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, line := range []string{
		"set system host-name feed-target",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
		"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
		"set security dynamic-address address-name dyn1 profile feed-name malware",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address dyn1",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then deny",
	} {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree.Format()
}

// armWindowOver9615 makes target the active config through the tolerant sync
// ingress (a refused target cannot be strictly committed), then arms `commit
// confirmed` over it with the abandoned config.
func armWindowOver9615(t *testing.T, s *configstore.Store, target string) {
	t.Helper()
	if _, err := s.SyncApply(target, nil); err != nil {
		t.Fatalf("SyncApply(target): %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride(abandoned9615); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	s.ExitConfigure()
}

type daemon9615 struct {
	d       *Daemon
	s       *configstore.Store
	applied []string
}

func newDaemon9615(t *testing.T) *daemon9615 {
	t.Helper()
	s := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	h := &daemon9615{s: s}
	h.d = &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	h.d.applyBodyForTest = func(cfg *config.Config) {
		if cfg != nil {
			h.applied = append(h.applied, cfg.System.HostName)
		}
	}
	s.SetRollbackExecutor(h.d.executeConfirmedRollback)
	prev := confirmRollbackFeedRetryInterval
	confirmRollbackFeedRetryInterval = time.Hour
	t.Cleanup(func() {
		confirmRollbackFeedRetryInterval = prev
		_ = s.ConfirmCommit()
	})
	return h
}

func hostName9615(s *configstore.Store) string {
	if cfg := s.ActiveConfig(); cfg != nil {
		return cfg.System.HostName
	}
	return ""
}

// TestHealthyRollbackTargetIsAppliedAtFire_9615 is the control: an appliable
// target rolls back and is applied exactly as before.
func TestHealthyRollbackTargetIsAppliedAtFire_9615(t *testing.T) {
	h := newDaemon9615(t)
	armWindowOver9615(t, h.s, healthyTarget9615)
	h.s.InvokeRollbackTimerForTesting(h.s.ConfirmGenForTesting())
	if got := hostName9615(h.s); got != "healthy-target" {
		t.Fatalf("store not rolled back to the target: host-name %q", got)
	}
	if len(h.applied) != 1 || h.applied[0] != "healthy-target" {
		t.Fatalf("a healthy target must be applied once, got %v", h.applied)
	}
	if h.d.inBootstrap() {
		t.Fatal("a healthy target must not enter the bootstrap safe state")
	}
}

// TestRefusedRollbackTargetIsNotAppliedAtFire_9615: a target the helper refuses
// is never applied. The store is still reverted to it (the unconfirmed commit
// must not stand) and the daemon takes the bootstrap/lifeline safe state.
func TestRefusedRollbackTargetIsNotAppliedAtFire_9615(t *testing.T) {
	h := newDaemon9615(t)
	armWindowOver9615(t, h.s, refusedTarget9615)
	buf, restore := captureSlog(t)
	defer restore()
	h.s.InvokeRollbackTimerForTesting(h.s.ConfirmGenForTesting())
	if len(h.applied) != 0 {
		t.Fatalf("a refused rollback target was applied: %v", h.applied)
	}
	if got := hostName9615(h.s); got != "refused-target" {
		t.Fatalf("the store must still revert to the target (the abandoned commit must not stand), got %q", got)
	}
	if h.s.IsConfirmPending() {
		t.Fatal("the window must be resolved after the refused-target rollback")
	}
	if !h.d.inBootstrap() {
		t.Fatal("a refused rollback target must leave the daemon in the bootstrap/lifeline safe state")
	}
	if !strings.Contains(buf.String(), "bad1") || !strings.Contains(buf.String(), "#9615") {
		t.Errorf("the refusal must be logged with its reason:\n%s", buf.String())
	}
}

// TestFeedBoundRollbackTargetIsDeferredThenBounded_9615: a target whose only
// problem is a feed with no installed snapshot is deferred without promoting,
// and after the retry cap it takes the safe state rather than waiting forever.
func TestFeedBoundRollbackTargetIsDeferredThenBounded_9615(t *testing.T) {
	h := newDaemon9615(t)
	armWindowOver9615(t, h.s, feedTarget9615(t))
	gen := h.s.ConfirmGenForTesting()
	for i := 1; i <= confirmRollbackFeedRetryMax; i++ {
		h.s.InvokeRollbackTimerForTesting(gen)
		if got := hostName9615(h.s); got != "abandoned" {
			t.Fatalf("attempt %d: a feed-bound target must be deferred without promoting, store holds %q", i, got)
		}
		if !h.s.IsConfirmPending() || len(h.applied) != 0 || h.d.inBootstrap() {
			t.Fatalf("attempt %d: deferral must keep the window pending with nothing applied (pending=%v applied=%v bootstrap=%v)",
				i, h.s.IsConfirmPending(), h.applied, h.d.inBootstrap())
		}
	}
	h.s.InvokeRollbackTimerForTesting(gen)
	if got := hostName9615(h.s); got != "feed-target" || len(h.applied) != 0 || !h.d.inBootstrap() {
		t.Fatalf("past the cap the rollback must promote and take the safe state without applying: host=%q applied=%v bootstrap=%v",
			got, h.applied, h.d.inBootstrap())
	}
}

// recoveredStore9615 arms a window over target in one store, then loads a second
// store from the same files, which re-arms the window the way a restart does.
func recoveredStore9615(t *testing.T, target string) *configstore.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xpf.conf")
	a := newConfigStore(t, path)
	armWindowOver9615(t, a, target)
	b := newConfigStore(t, path)
	if err := b.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !b.IsConfirmPending() {
		t.Fatal("precondition: Load must re-arm the still-live window")
	}
	t.Cleanup(func() { _ = b.ConfirmCommit() })
	a.CancelConfirmTimerForTesting()
	return b
}

// TestRecoveredWindowWithRefusedTargetRaisesAlarm_9615 is the boot half: the
// operator is told, with the reason and the deadline, while the window is still
// armed.
func TestRecoveredWindowWithRefusedTargetRaisesAlarm_9615(t *testing.T) {
	s := recoveredStore9615(t, refusedTarget9615)
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.checkRecoveredConfirmTarget()
	alarm := s.ConfirmAlarm()
	for _, want := range []string{"recovered commit-confirmed window", "refused", "bad1", "deadline"} {
		if !strings.Contains(alarm, want) {
			t.Errorf("alarm missing %q: %q", want, alarm)
		}
	}
	if !s.IsConfirmPending() {
		t.Error("the alarm must never un-arm the window")
	}
}

// TestRecoveredWindowWithHealthyTargetRaisesNoAlarm_9615 is the control.
func TestRecoveredWindowWithHealthyTargetRaisesNoAlarm_9615(t *testing.T) {
	s := recoveredStore9615(t, healthyTarget9615)
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.checkRecoveredConfirmTarget()
	if alarm := s.ConfirmAlarm(); alarm != "" {
		t.Errorf("a healthy recovered target must raise no alarm: %q", alarm)
	}
}

// TestRecoveredConfirmPreflightIsWired_9615 binds the wiring the cells above
// call directly: startup runs the boot check after manager-init, and the fire
// path checks before PromoteRollback.
func TestRecoveredConfirmPreflightIsWired_9615(t *testing.T) {
	fset := token.NewFileSet()
	run, err := parser.ParseFile(fset, "daemon_run.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var phases []string
	ast.Inspect(run, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			phases = append(phases, strings.Trim(lit.Value, `"`))
		}
		return true
	})
	iInit, iCheck := -1, -1
	for i, p := range phases {
		if p == "manager-init" {
			iInit = i
		}
		if p == "recovered-confirm-preflight" {
			iCheck = i
		}
	}
	if iInit < 0 || iCheck < iInit {
		t.Errorf("startup must run the recovered-confirm-preflight phase after manager-init (manager-init@%d, preflight@%d)", iInit, iCheck)
	}
	// The phase must also CALL the check; a phase that exists by name with an
	// empty body satisfies the ordering assertion above and checks nothing.
	wiredCall := false
	ast.Inspect(run, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok || len(cl.Elts) != 2 {
			return true
		}
		name, ok := cl.Elts[0].(*ast.BasicLit)
		if !ok || name.Value != `"recovered-confirm-preflight"` {
			return true
		}
		ast.Inspect(cl.Elts[1], func(m ast.Node) bool {
			if sel, ok := m.(*ast.SelectorExpr); ok && sel.Sel.Name == "checkRecoveredConfirmTarget" {
				wiredCall = true
			}
			return true
		})
		return false
	})
	if !wiredCall {
		t.Error("the recovered-confirm-preflight phase must call checkRecoveredConfirmTarget, not only exist by name")
	}
	src, err := parser.ParseFile(fset, "daemon_apply_commit.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	var checkPos, promotePos token.Pos
	ast.Inspect(src, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "executeConfirmedRollback" {
			return true
		}
		ast.Inspect(fd, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "confirmRollbackTargetHandledAtFire":
				if checkPos == 0 {
					checkPos = sel.Pos()
				}
			case "PromoteRollback":
				if promotePos == 0 {
					promotePos = sel.Pos()
				}
			}
			return true
		})
		return false
	})
	if checkPos == 0 || promotePos == 0 || checkPos > promotePos {
		t.Errorf("executeConfirmedRollback must call confirmRollbackTargetHandledAtFire before PromoteRollback (check@%v promote@%v)", checkPos, promotePos)
	}
}

// TestDeferredConfirmTimerFiresTheSameGeneration_9615: a feed deferral is only a
// deferral if the re-armed timer really fires again, for the same window. The
// cells above invoke the timer directly, so they cannot see a re-arm that never
// fires.
func TestDeferredConfirmTimerFiresTheSameGeneration_9615(t *testing.T) {
	s := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	armWindowOver9615(t, s, healthyTarget9615)
	gen := s.ConfirmGenForTesting()
	fired := make(chan uint64, 4)
	s.SetRollbackExecutor(func(g uint64) {
		select {
		case fired <- g:
		default:
		}
	})
	t.Cleanup(func() { _ = s.ConfirmCommit() })
	if s.DeferConfirmTimer(gen+1, time.Millisecond) {
		t.Fatal("a stale generation must not re-arm the window")
	}
	if !s.DeferConfirmTimer(gen, 20*time.Millisecond) {
		t.Fatal("DeferConfirmTimer refused the live window")
	}
	select {
	case g := <-fired:
		if g != gen {
			t.Fatalf("the deferred timer fired generation %d, want %d", g, gen)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the deferred timer never fired")
	}
}

// TestInProcessWindowIsNotReportedAsRecovered_9615: a window armed in this
// process was pre-flighted before arming, so the boot check must not treat it
// as recovered, including a window re-armed over one Load recovered.
func TestInProcessWindowIsNotReportedAsRecovered_9615(t *testing.T) {
	h := newDaemon9615(t)
	armWindowOver9615(t, h.s, refusedTarget9615)
	if _, _, _, ok := h.s.RecoveredConfirmWindow(); ok {
		t.Fatal("a window armed in this process must not be reported as recovered")
	}
	h.d.checkRecoveredConfirmTarget()
	if alarm := h.s.ConfirmAlarm(); alarm != "" {
		t.Errorf("an in-process window must raise no recovered-window alarm: %q", alarm)
	}

	r := recoveredStore9615(t, refusedTarget9615)
	if _, _, _, ok := r.RecoveredConfirmWindow(); !ok {
		t.Fatal("precondition: Load must mark the re-armed window as recovered")
	}
	if err := r.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := r.LoadOverride(healthyTarget9615); err != nil {
		t.Fatal(err)
	}
	if _, err := r.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed over the recovered window: %v", err)
	}
	r.ExitConfigure()
	if _, _, _, ok := r.RecoveredConfirmWindow(); ok {
		t.Error("re-arming in this process must clear the recovered mark")
	}
}
