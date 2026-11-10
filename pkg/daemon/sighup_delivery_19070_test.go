package daemon

import (
	"context"
	"fmt"
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

// TestNoInProcessSelfSignal19070 is a source pin (R8 F1/N1, Codex F3/F4 on
// #19070). The REAL protection is the re-exec: the #15084 delivery runs in a
// child, so a late HUP kills the child and fails that cell by name. This pin
// catches the common ways a pkg/daemon test could signal the test binary
// itself OUTSIDE such a child:
//   - syscall/unix .Kill or .Tgkill whose pid is syscall/os.Getpid(), a local
//     variable assigned from one, or 0 (the process group, the test binary
//     included);
//   - os.FindProcess(<that pid>) followed by .Signal on the result;
//   - those functions, or the helper, taken as a VALUE (an alias).
//
// Such a call is allowed only inside deliverSIGHUPsUnderCapture19070, inside
// a known child body (childBodies19070, each of whose call sites must itself
// be gated), or inside an `if os.Getenv(<env>) == "1"` branch. An inverted
// gate (!= "1"), another comparison, or a function's NAME does not count.
// The helper must be called only in such a gated branch, and the #15084 cell
// must still call it. Not covered: import aliases of syscall/unix/os and
// signals sent by a child process the test spawns.
func TestNoInProcessSelfSignal19070(t *testing.T) {
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var parsed []*ast.File
	for _, f := range files {
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		parsed = append(parsed, file)
	}
	for _, v := range selfSignalViolations19070(fset, parsed) {
		t.Error(v)
	}
}

// childBodies19070 are functions that run only in a re-executed child. Each
// call site must be inside an `os.Getenv(X) == "1"` branch, which the pin
// verifies.
var childBodies19070 = map[string]bool{"runSecondSignalChild16801": true}

const selfSignalHelper19070 = "deliverSIGHUPsUnderCapture19070"

// selfSignalViolations19070 is the pin's engine, separated so the parser
// fixtures in TestSelfSignalPinCatchesTheEscapes19070 can drive it.
func selfSignalViolations19070(fset *token.FileSet, files []*ast.File) []string {
	var out []string
	helperCalls, selfKills, uses15084 := 0, 0, false
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			gated := map[ast.Node]bool{}
			pidVars := map[string]bool{}
			procVars := map[string]bool{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.IfStmt:
					if isChildGate19070(x.Cond) {
						ast.Inspect(x.Body, func(m ast.Node) bool {
							gated[m] = true
							return true
						})
					}
				case *ast.AssignStmt:
					for i, rhs := range x.Rhs {
						if i >= len(x.Lhs) && len(x.Rhs) != 1 {
							break
						}
						id, ok := x.Lhs[0].(*ast.Ident)
						if len(x.Rhs) > 1 {
							id, ok = x.Lhs[i].(*ast.Ident)
						}
						if !ok {
							continue
						}
						if isGetpid19070(rhs) {
							pidVars[id.Name] = true
						}
						if c, ok := rhs.(*ast.CallExpr); ok && selName19070(c.Fun, "os", "FindProcess") && len(c.Args) == 1 && selfPid19070(c.Args[0], pidVars) {
							procVars[id.Name] = true
						}
					}
				}
				return true
			})
			allowedHere := fn.Name.Name == selfSignalHelper19070 || childBodies19070[fn.Name.Name]
			report := func(n ast.Node, what string) {
				if !allowedHere && !gated[n] {
					out = append(out, fmt.Sprintf("%s: %s %s outside a re-executed child's branch; a delivery that lands after its capture is released kills the whole test binary (#19070). Do it in a re-executed child, through %s",
						fset.Position(n.Pos()), fn.Name.Name, what, selfSignalHelper19070))
				}
			}
			calls := map[*ast.Ident]bool{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok {
					calls[id] = true
					if id.Name == selfSignalHelper19070 {
						helperCalls++
						if fn.Name.Name == "TestIgnoreSIGHUPSurvivesDelivery15084" {
							uses15084 = true
						}
						if !gated[call] {
							out = append(out, fmt.Sprintf("%s: %s calls %s outside an os.Getenv(...) == \"1\" child branch (#19070)",
								fset.Position(call.Pos()), fn.Name.Name, selfSignalHelper19070))
						}
					}
					if childBodies19070[id.Name] && !gated[call] {
						out = append(out, fmt.Sprintf("%s: %s calls the child body %s outside an os.Getenv(...) == \"1\" branch (#19070)",
							fset.Position(call.Pos()), fn.Name.Name, id.Name))
					}
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					calls[sel.Sel] = true
					switch {
					case (selName19070(call.Fun, "syscall", "Kill") || selName19070(call.Fun, "unix", "Kill") ||
						selName19070(call.Fun, "syscall", "Tgkill") || selName19070(call.Fun, "unix", "Tgkill")) &&
						len(call.Args) >= 2 && selfPid19070(call.Args[0], pidVars):
						selfKills++
						report(call, "signals the test process itself")
					case sel.Sel.Name == "Signal" && len(call.Args) == 1:
						if id, ok := sel.X.(*ast.Ident); ok && procVars[id.Name] {
							selfKills++
							report(call, "signals the test process itself through os.FindProcess")
						}
						if c, ok := sel.X.(*ast.CallExpr); ok && selName19070(c.Fun, "os", "FindProcess") && len(c.Args) == 1 && selfPid19070(c.Args[0], pidVars) {
							selfKills++
							report(call, "signals the test process itself through os.FindProcess")
						}
					}
				}
				return true
			})
			// A signal function or the helper taken as a value is an alias the
			// call checks cannot follow.
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.SelectorExpr:
					if calls[x.Sel] {
						return true
					}
					if selName19070(x, "syscall", "Kill") || selName19070(x, "unix", "Kill") || selName19070(x, "syscall", "Tgkill") || selName19070(x, "unix", "Tgkill") {
						out = append(out, fmt.Sprintf("%s: %s takes %s.%s as a value; call it directly so the self-signal pin can see it (#19070)",
							fset.Position(x.Pos()), fn.Name.Name, x.X.(*ast.Ident).Name, x.Sel.Name))
					}
				case *ast.Ident:
					if x.Name == selfSignalHelper19070 && !calls[x] {
						out = append(out, fmt.Sprintf("%s: %s takes %s as a value; call it directly in a child branch (#19070)",
							fset.Position(x.Pos()), fn.Name.Name, selfSignalHelper19070))
					}
				}
				return true
			})
		}
	}
	if !uses15084 {
		out = append(out, "TestIgnoreSIGHUPSurvivesDelivery15084 no longer calls "+selfSignalHelper19070+": a kill-then-release body there is the #19070 defect")
	}
	// Positive control: the scan must see the helper's own kill and its calls.
	if selfKills == 0 || helperCalls < 2 {
		out = append(out, fmt.Sprintf("scan saw %d self-signal calls and %d helper calls; the scan rotted", selfKills, helperCalls))
	}
	return out
}

// isChildGate19070 accepts only `os.Getenv(X) == "1"` (either operand order),
// the gate every re-exec child here sets. An inverted (!=) or other
// comparison is not a child gate.
func isChildGate19070(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		be, ok := n.(*ast.BinaryExpr)
		if !ok || be.Op != token.EQL {
			return true
		}
		isGetenv := func(x ast.Expr) bool {
			c, ok := x.(*ast.CallExpr)
			return ok && selName19070(c.Fun, "os", "Getenv")
		}
		isOne := func(x ast.Expr) bool {
			l, ok := x.(*ast.BasicLit)
			return ok && l.Value == `"1"`
		}
		if (isGetenv(be.X) && isOne(be.Y)) || (isGetenv(be.Y) && isOne(be.X)) {
			found = true
		}
		return !found
	})
	return found
}

func selName19070(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}

func isGetpid19070(e ast.Expr) bool {
	c, ok := e.(*ast.CallExpr)
	return ok && (selName19070(c.Fun, "syscall", "Getpid") || selName19070(c.Fun, "os", "Getpid") || selName19070(c.Fun, "unix", "Getpid"))
}

// selfPid19070: a Getpid() call, a local assigned from one, or 0 (the
// caller's process group, the test binary included).
func selfPid19070(e ast.Expr, pidVars map[string]bool) bool {
	if isGetpid19070(e) {
		return true
	}
	if id, ok := e.(*ast.Ident); ok && pidVars[id.Name] {
		return true
	}
	l, ok := e.(*ast.BasicLit)
	return ok && l.Value == "0"
}

// TestSelfSignalPinCatchesTheEscapes19070 drives the pin over parser
// fixtures: each escape Codex and R8 named (F3/F4, N1) must produce exactly
// one violation naming its function, and the gated forms none.
func TestSelfSignalPinCatchesTheEscapes19070(t *testing.T) {
	const base = `package daemon
import ("os"; "syscall"; "testing")
func deliverSIGHUPsUnderCapture19070(t *testing.T, s any, n int) int64 { _ = syscall.Kill(syscall.Getpid(), syscall.SIGHUP); return 0 }
func TestIgnoreSIGHUPSurvivesDelivery15084(t *testing.T) {
	if os.Getenv("X15084") == "1" { deliverSIGHUPsUnderCapture19070(t, nil, 2) }
}
func TestHelperCell(t *testing.T) {
	if "1" == os.Getenv("X19070") { deliverSIGHUPsUnderCapture19070(t, nil, 2) }
}
func runSecondSignalChild16801(t *testing.T) { _ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM) }
func TestGatedChildBody(t *testing.T) {
	if os.Getenv("X16801") == "1" { runSecondSignalChild16801(t) }
}
`
	for _, tc := range []struct{ name, src, want string }{
		{"clean base", "", ""},
		{"unix.Kill", `func E(t *testing.T) { _ = unix.Kill(os.Getpid(), syscall.SIGHUP) }`, "E signals the test process itself"},
		{"Tgkill", `func E(t *testing.T) { _ = syscall.Tgkill(syscall.Getpid(), syscall.Gettid(), syscall.SIGHUP) }`, "E signals the test process itself"},
		{"pid in a local", `func E(t *testing.T) { pid := os.Getpid(); _ = syscall.Kill(pid, syscall.SIGHUP) }`, "E signals the test process itself"},
		{"process group 0", `func E(t *testing.T) { _ = syscall.Kill(0, syscall.SIGHUP) }`, "E signals the test process itself"},
		{"FindProcess then Signal", `func E(t *testing.T) { p, _ := os.FindProcess(os.Getpid()); _ = p.Signal(syscall.SIGHUP) }`, "E signals the test process itself through os.FindProcess"},
		{"FindProcess chained", `func E(t *testing.T) { pr, _ := os.FindProcess(os.Getpid()); _ = pr; _ = mustProc(os.FindProcess(os.Getpid())) }
func mustProc(p *os.Process, err error) *os.Process { return p }
func F(t *testing.T) { q, _ := os.FindProcess(syscall.Getpid()); q.Signal(syscall.SIGHUP) }`, "F signals the test process itself through os.FindProcess"},
		{"inverted gate", `func E(t *testing.T) { if os.Getenv("X") != "1" { _ = syscall.Kill(syscall.Getpid(), syscall.SIGHUP) } }`, "E signals the test process itself"},
		{"other env comparison", `func E(t *testing.T) { if os.Getenv("PATH") != "" { _ = syscall.Kill(syscall.Getpid(), syscall.SIGHUP) } }`, "E signals the test process itself"},
		{"Child in the name only", `func TestChildSignal(t *testing.T) { _ = syscall.Kill(syscall.Getpid(), syscall.SIGHUP) }`, "TestChildSignal signals the test process itself"},
		{"Kill as a value", `func E(t *testing.T) { kill := syscall.Kill; _ = kill }`, "E takes syscall.Kill as a value"},
		{"helper as a value", `func E(t *testing.T) { d := deliverSIGHUPsUnderCapture19070; _ = d }`, "E takes deliverSIGHUPsUnderCapture19070 as a value"},
		{"helper ungated", `func E(t *testing.T) { deliverSIGHUPsUnderCapture19070(t, nil, 2) }`, "E calls deliverSIGHUPsUnderCapture19070 outside"},
		{"child body ungated", `func E(t *testing.T) { runSecondSignalChild16801(t) }`, "E calls the child body runSecondSignalChild16801 outside"},
		{"gated kill is fine", `func E(t *testing.T) { if os.Getenv("X") == "1" { _ = syscall.Kill(syscall.Getpid(), syscall.SIGHUP) } }`, ""},
		{"signal to another pid is fine", `func E(t *testing.T, pid int) { _ = syscall.Kill(pid, syscall.SIGHUP) }`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "fixture_test.go", base+"\n"+tc.src, 0)
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			got := selfSignalViolations19070(fset, []*ast.File{f})
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("want no violation, got:\n%s", strings.Join(got, "\n"))
				}
				return
			}
			if len(got) != 1 || !strings.Contains(got[0], tc.want) {
				t.Fatalf("want exactly one violation containing %q, got:\n%s", tc.want, strings.Join(got, "\n"))
			}
		})
	}
}
