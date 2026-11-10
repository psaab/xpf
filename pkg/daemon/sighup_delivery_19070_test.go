package daemon

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// #19070: TestIgnoreSIGHUPSurvivesDelivery15084 signalled its own process
// twice and released the ignoreSIGHUP capture straight after. kill(2) returns
// before the signal is handled: for a process-directed signal the kernel may
// pick another thread (a parked main thread, typically) and the handler runs
// when that thread is next scheduled. When the release won that race, the
// late HUP met the default action and killed the test binary with
// "signal: hangup", truncating every pkg/daemon run it hit (10 of 23 full
// runs on loaded runners; 0 of 14 when the binary started with SIGHUP
// ignored, which keeps an inherited SIG_IGN through signal.Stop).

// sighupWarnings19070 counts the capture's "SIGHUP received and ignored"
// records: ignoreSIGHUP logs one per HUP its channel receives, so the count is
// the number of HUPs the capture has consumed.
type sighupWarnings19070 struct{ n atomic.Int64 }

func (h *sighupWarnings19070) Enabled(context.Context, slog.Level) bool { return true }
func (h *sighupWarnings19070) Handle(_ context.Context, r slog.Record) error {
	if r.Message == sighupIgnoredWarning {
		h.n.Add(1)
	}
	return nil
}
func (h *sighupWarnings19070) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *sighupWarnings19070) WithGroup(string) slog.Handler      { return h }

func countSIGHUPWarnings19070(t *testing.T) *sighupWarnings19070 {
	t.Helper()
	h := &sighupWarnings19070{}
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return h
}

// deliverSIGHUPsUnderCapture19070 installs the ignoreSIGHUP capture, sends n
// real SIGHUPs to this process one at a time, waiting after each until the
// capture has logged it, then releases the capture. It returns how many HUPs
// the capture had observed when it was released. Waiting per kill (not once
// for the burst) matters: two HUPs sent back to back can coalesce into one
// delivery, or the second can arrive while the first is being handled, so a
// count observed after a burst does not prove nothing is still pending.
//
// On a timeout the capture is deliberately left installed: releasing it with
// a HUP possibly still pending is the very hazard this guards against.
func deliverSIGHUPsUnderCapture19070(t *testing.T, seen *sighupWarnings19070, n int) int64 {
	t.Helper()
	stop := ignoreSIGHUP()
	base := seen.n.Load()
	for i := int64(1); i <= int64(n); i++ {
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
			t.Fatalf("deliver SIGHUP %d to self: %v", i, err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for seen.n.Load()-base < i {
			if time.Now().After(deadline) {
				t.Fatalf("the capture never observed SIGHUP %d of %d (observed %d); leaving it installed",
					i, n, seen.n.Load()-base)
			}
			time.Sleep(50 * time.Microsecond)
		}
	}
	observed := seen.n.Load() - base
	stop()
	return observed
}

const sighupDeliveryChild19070Env = "XPF_19070_SIGHUP_DELIVERY_CHILD"
const sighupDeliveryRounds19070 = 200

// TestSIGHUPCaptureReleasedOnlyAfterDelivery19070 pins the HELPER: it runs
// deliverSIGHUPsUnderCapture19070 sighupDeliveryRounds19070 times in a
// re-executed child, and each round must release the capture with every HUP it
// sent observed. A helper that releases before observing fails here
// deterministically ("observed 0 of 2"), and a late HUP kills only the child.
// It does not pin that a CALLER uses the helper; TestNoInProcessSelfSignal19070
// does that from the source (R8 F1 on #19070).
func TestSIGHUPCaptureReleasedOnlyAfterDelivery19070(t *testing.T) {
	if os.Getenv(sighupDeliveryChild19070Env) == "1" {
		seen := countSIGHUPWarnings19070(t)
		for round := 1; round <= sighupDeliveryRounds19070; round++ {
			// < not !=: a capture leaked from another test can log too.
			if got := deliverSIGHUPsUnderCapture19070(t, seen, 2); got < 2 {
				t.Fatalf("round %d: the capture was released having observed %d of 2 SIGHUPs; "+
					"a HUP still in flight then meets the default action (#19070)", round, got)
			}
		}
		return
	}
	runSIGHUPChild19070(t, "TestSIGHUPCaptureReleasedOnlyAfterDelivery19070", sighupDeliveryChild19070Env)
}

// runSIGHUPChild19070 re-executes this test binary for one test with env=1
// and judges the child: killed by a signal is a named FAIL (a SIGHUP outlived
// a capture), and only the child's own "--- PASS: <name> (" line with a zero
// exit is a pass.
func runSIGHUPChild19070(t *testing.T, name, env string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run", "^"+name+"$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), env+"=1")
	out, runErr := cmd.CombinedOutput()
	if ee, ok := runErr.(*exec.ExitError); ok {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			t.Fatalf("the child was killed by %v: a SIGHUP outlived the capture (#19070)\n--- child output ---\n%s", ws.Signal(), out)
		}
	}
	if runErr != nil || !regexp.MustCompile(`(?m)^--- PASS: `+regexp.QuoteMeta(name)+` \(`).Match(out) {
		t.Fatalf("the child did not pass (exit: %v)\n--- child output ---\n%s", runErr, out)
	}
}

// TestNoInProcessSelfSignal19070 is the source pin R8 asked for (F1 on
// #19070). In pkg/daemon's tests a signal sent to the test process itself
// (syscall/unix.Kill with syscall.Getpid() or os.Getpid()) may appear only
// where a late delivery cannot take the test binary down: inside
// deliverSIGHUPsUnderCapture19070, inside a function whose name says it is a
// child body (…Child…), or inside an `if` gated on os.Getenv (a re-executed
// child's branch). Every call of the helper must itself be in such a branch,
// and the #15084 delivery cell must still call it.
func TestNoInProcessSelfSignal19070(t *testing.T) {
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	helperCalls, selfKills, uses15084 := 0, 0, false
	for _, f := range files {
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			gated := map[ast.Node]bool{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if ifs, ok := n.(*ast.IfStmt); ok && readsGetenv19070(ifs.Cond) {
					ast.Inspect(ifs.Body, func(m ast.Node) bool {
						gated[m] = true
						return true
					})
				}
				return true
			})
			childFn := strings.Contains(fn.Name.Name, "Child")
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "deliverSIGHUPsUnderCapture19070" {
					helperCalls++
					if fn.Name.Name == "TestIgnoreSIGHUPSurvivesDelivery15084" {
						uses15084 = true
					}
					if !gated[call] {
						t.Errorf("%s: %s calls deliverSIGHUPsUnderCapture19070 outside a re-executed child's branch (#19070)",
							fset.Position(call.Pos()), fn.Name.Name)
					}
					return true
				}
				if isSelfKill19070(call) {
					selfKills++
					if fn.Name.Name != "deliverSIGHUPsUnderCapture19070" && !childFn && !gated[call] {
						t.Errorf("%s: %s signals the test process itself in-process; a delivery that lands after its capture is released kills the whole test binary (#19070). Do it in a re-executed child, through deliverSIGHUPsUnderCapture19070",
							fset.Position(call.Pos()), fn.Name.Name)
					}
				}
				return true
			})
		}
	}
	if !uses15084 {
		t.Errorf("TestIgnoreSIGHUPSurvivesDelivery15084 no longer calls deliverSIGHUPsUnderCapture19070: a kill-then-release body there is the #19070 defect")
	}
	// Positive control: the scan must see the helper's own kill and its calls.
	if selfKills == 0 || helperCalls < 2 {
		t.Fatalf("scan saw %d self-signal calls and %d helper calls; the scan rotted", selfKills, helperCalls)
	}
}

func readsGetenv19070(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Getenv" {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "os" {
				found = true
			}
		}
		return !found
	})
	return found
}

// isSelfKill19070 matches syscall.Kill / unix.Kill whose pid argument is
// syscall.Getpid() or os.Getpid().
func isSelfKill19070(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Kill" || len(call.Args) != 2 {
		return false
	}
	if pkg, ok := sel.X.(*ast.Ident); !ok || (pkg.Name != "syscall" && pkg.Name != "unix") {
		return false
	}
	pc, ok := call.Args[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	ps, ok := pc.Fun.(*ast.SelectorExpr)
	return ok && ps.Sel.Name == "Getpid"
}
