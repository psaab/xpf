// #6552: gRPC ShowText and GetSystemInfo forked host binaries with NO
// diagcmd.DefaultLimiter acquisition — the process-wide
// MaxConcurrentDiagnostics semaphore (#5057) that BOTH surfaces'
// ping/traceroute paths do acquire.
//
// The anchor site was unconditional. `ShowText{topic:"log"}` forked
// `journalctl -u xpfd -n 50 --no-pager` on nothing but a decodable request:
// no config precondition, no dataplane check. ShowText is on
// fabricAllowedUnaryMethods and neither grpc.NewServer set
// MaxConcurrentStreams, so the amplification was not loopback-bounded either.
//
// SECURITY SCOPE, stated because "forks journalctl" reads like an injection
// finding and is not one. Every argv element at the nine constant sites is a
// compile-time Go string literal handed to exec.CommandContext — no shell, no
// `sh -c`. The tenth (`tail -n <N> <logPath>`) IS request-derived on both
// arguments and is constrained on both: N goes through strconv.Atoi +
// clampTailLines to [1,10000] and is re-emitted with strconv.Itoa, so it can
// never become an option; logPath goes through config.SyslogLogFilePath, which
// refuses any name that is not filepath.Base(name) and then requires it in the
// operator-configured `system syslog file` allowlist, yielding
// /var/log/<allowlisted-base>. This is a resource-exhaustion defect, not
// command injection.
//
// FAIL-ON-REVERT: drop the acquireDiagSlot() call from outputTimeout or
// combinedOutputTimeout in exec_timeout.go and the two bound tests below go
// RED (an over-cap call forks anyway and answers Internal, or succeeds,
// instead of ResourceExhausted). Switch a bounded site back to the
// *Unlimited helper and the source tripwire names it.
package grpcapi

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/diagcmd"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func newDiagForkServer(t *testing.T) *Server {
	t.Helper()
	return &Server{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
}

// withSaturatedDiagLimiter swaps in a single-slot limiter and holds its only
// slot, returning a release. Every caller must release before asserting the
// post-release behaviour, so the two halves of the contract (refuse while
// full, admit once free) are both exercised.
func withSaturatedDiagLimiter(t *testing.T) func() {
	t.Helper()
	orig := diagLimiter
	t.Cleanup(func() { diagLimiter = orig })
	diagLimiter = diagcmd.NewLimiter(1)
	release, err := diagLimiter.Acquire()
	if err != nil {
		t.Fatalf("failed to pre-acquire the only diagnostic slot: %v", err)
	}
	return release
}

// TestShowTextLogIsDiagnosticConcurrencyBounded6552 is the issue's anchor site:
// the unconditional `journalctl` fork on a fabric-reachable RPC.
func TestShowTextLogIsDiagnosticConcurrencyBounded6552(t *testing.T) {
	release := withSaturatedDiagLimiter(t)
	s := newDiagForkServer(t)

	_, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "log"})
	if !isResourceExhausted(err) {
		release()
		t.Fatalf("ShowText{log} with a saturated diagnostic limiter: err = %v, "+
			"want codes.ResourceExhausted — the fork ran with no admission gate", err)
	}

	// Once a slot frees the call must be admitted. It may still fail (journalctl
	// can be absent in a build container), but NOT with ResourceExhausted —
	// that would mean the slot was never returned.
	release()
	if _, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "log"}); isResourceExhausted(err) {
		t.Fatalf("ShowText{log} still ResourceExhausted after the slot was released: %v "+
			"(the limiter is leaking slots — release must run on every path)", err)
	}
}

// TestGetSystemInfoIsDiagnosticConcurrencyBounded6552 covers the other
// forking RPC. The issue notes GetSystemInfo had ZERO tests anywhere in
// pkg/grpcapi despite forking four host binaries; this is the first.
func TestGetSystemInfoIsDiagnosticConcurrencyBounded6552(t *testing.T) {
	// Every forking type, so a future edit that bounds one arm and not another
	// is caught. "users" is deliberately excluded — it reads config, forks
	// nothing, and must NOT be gated.
	for _, typ := range []string{"processes", "storage", "boot-messages", "connections"} {
		t.Run(typ, func(t *testing.T) {
			release := withSaturatedDiagLimiter(t)
			s := newDiagForkServer(t)

			_, err := s.GetSystemInfo(context.Background(), &pb.GetSystemInfoRequest{Type: typ})
			if !isResourceExhausted(err) {
				release()
				t.Fatalf("GetSystemInfo{%s} with a saturated diagnostic limiter: err = %v, "+
					"want codes.ResourceExhausted", typ, err)
			}
			release()
			if _, err := s.GetSystemInfo(context.Background(), &pb.GetSystemInfoRequest{Type: typ}); isResourceExhausted(err) {
				t.Fatalf("GetSystemInfo{%s} still ResourceExhausted after release: %v", typ, err)
			}
		})
	}
}

// TestNonForkingSystemInfoTypeIsNotGated6552 is the negative control, and it
// is the assertion that keeps the fix honest. Acquiring the semaphore at the
// top of the HANDLER instead of at the fork would satisfy both tests above
// while throttling every config-only topic behind the diagnostic budget — a
// bound in the wrong place. "users" reads config and forks nothing, so a
// saturated limiter must not affect it at all.
func TestNonForkingSystemInfoTypeIsNotGated6552(t *testing.T) {
	release := withSaturatedDiagLimiter(t)
	defer release()
	s := newDiagForkServer(t)

	if _, err := s.GetSystemInfo(context.Background(), &pb.GetSystemInfoRequest{Type: "users"}); isResourceExhausted(err) {
		t.Fatalf("GetSystemInfo{users} was refused by the diagnostic limiter: %v — "+
			"it forks nothing, so the bound is being taken at the handler rather "+
			"than at the fork", err)
	}
}

// unboundedForkExemption names one deliberate use of an unbounded exec helper,
// keyed by the pair that survives line drift: the file and the enclosing
// top-level declaration.
type unboundedForkExemption struct {
	file   string
	fn     string // enclosing FuncDecl name, or "<package-scope>" for a var initializer
	callee string
	why    string
}

// declaredUnboundedForks is the complete allowlist. Anything else that reaches
// an unbounded exec helper in pkg/grpcapi is a bug, not a choice.
var declaredUnboundedForks = []unboundedForkExemption{
	{"exec_timeout.go", "outputTimeout", "outputTimeoutUnlimited",
		"the limited wrapper — it holds a slot across this call"},
	{"exec_timeout.go", "combinedOutputTimeout", "combinedOutputTimeoutUnlimited",
		"the limited wrapper — it holds a slot across this call"},
	{"exec_timeout.go", "outputTimeoutUnlimited", "exec.CommandContext",
		"the raw implementation"},
	{"exec_timeout.go", "combinedOutputTimeoutUnlimited", "exec.CommandContext",
		"the raw implementation"},
	{"exec_timeout.go", "runTimeout", "exec.CommandContext",
		"the raw implementation"},
	{"server_diag_ping.go", "streamDiagCmd", "exec.CommandContext",
		"Ping/Traceroute acquire diagLimiter themselves before reaching this (#5057)"},
	{"server_diag_system_action.go", "<package-scope>", "runTimeout",
		"schedulePowerAction / scheduleStopDaemon: a CONFIRMED reboot/halt/poweroff " +
			"or zeroize daemon-stop must not be refused because the diagnostic " +
			"budget is busy; both are behind the maintenance authz tier"},
	{"server_diag_system_action.go", "SystemAction", "combinedOutputTimeoutUnlimited",
		"ip -4/-6 neigh flush: state-changing operator actions behind PermControl, " +
			"not diagnostics — cheap, and refusing them under diagnostic load is a regression"},
	{"server_diag_zeroize.go", "<package-scope>", "combinedOutputTimeoutUnlimited",
		"zeroizeUserdel / zeroizeLockRootPassword: a factory reset must run to " +
			"completion; a half-zeroized box that left root unlocked because the " +
			"semaphore was busy is strictly worse than a slow one"},
	{"server_diag_zeroize_seal_10769.go", "stopKeaUnits", "combinedOutputTimeoutUnlimited",
		"factory reset must stop Kea before erasing tenant lease data and cannot be refused by diagnostic backpressure"},
}

// unboundedForkCallees are the helpers that fork WITHOUT drawing a diagnostic
// slot. exec.Command is included even though pkg/grpcapi does not currently
// use it: the point is that a new fork site written any of these ways is
// caught, not just one written the way today's code happens to be.
var unboundedForkCallees = map[string]bool{
	"outputTimeoutUnlimited":         true,
	"combinedOutputTimeoutUnlimited": true,
	"runTimeout":                     true,
	"exec.Command":                   true,
	"exec.CommandContext":            true,
}

// TestNoUnboundedForkOutsideTheDeclaredExemptions6552 is the armed tripwire,
// and it is the part of this change that survives the change.
//
// The issue asked for the bound to live "inside exec_timeout.go so it cannot
// be forgotten by a future caller". Placing it there is necessary but not
// sufficient: a future caller can still reach past the limited helpers. So the
// plainly-named helpers acquire by default, the unbounded forms carry
// "Unlimited" in the name, and this walks every non-test file in the package
// and requires each remaining unbounded fork to be one someone wrote down.
//
// It is deliberately NOT a count. A count goes vacuous the moment a counted
// call is deleted, and reads as "audited" when the population changed
// underneath it. This is a set difference in both directions: an undeclared
// use is a failure, and a declared exemption whose site no longer exists is
// also a failure, so the list cannot rot into a list of things that used to be
// true. The keying is (file, enclosing decl) rather than file:line precisely so
// an unrelated edit above a site does not red it.
//
// RED-on-revert: point any bounded site at a *Unlimited helper and it is named
// here with its file and enclosing function.
func TestNoUnboundedForkOutsideTheDeclaredExemptions6552(t *testing.T) {
	t.Parallel()

	allowed := map[string]string{}
	for _, e := range declaredUnboundedForks {
		allowed[e.file+"\x00"+e.fn+"\x00"+e.callee] = e.why
	}

	found := map[string]bool{}
	var undeclared []string

	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	scanned := 0
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++

		var decls []*ast.FuncDecl
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				decls = append(decls, fd)
			}
		}
		enclosing := func(pos token.Pos) string {
			for _, fd := range decls {
				if fd.Pos() <= pos && pos <= fd.End() {
					return fd.Name.Name
				}
			}
			return "<package-scope>"
		}

		ast.Inspect(f, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var callee string
			switch fn := ce.Fun.(type) {
			case *ast.Ident:
				callee = fn.Name
			case *ast.SelectorExpr:
				if x, ok := fn.X.(*ast.Ident); ok {
					callee = x.Name + "." + fn.Sel.Name
				}
			}
			if !unboundedForkCallees[callee] {
				return true
			}
			key := name + "\x00" + enclosing(ce.Pos()) + "\x00" + callee
			if _, ok := allowed[key]; ok {
				found[key] = true
				return true
			}
			undeclared = append(undeclared, name+" "+enclosing(ce.Pos())+"() calls "+
				callee+" at line "+fset.Position(ce.Pos()).String())
			return true
		})
	}

	if scanned == 0 {
		t.Fatal("scanned no non-test .go files — the walk is vacuous, so a green " +
			"here proves nothing. Check the test's working directory.")
	}

	sort.Strings(undeclared)
	for _, u := range undeclared {
		t.Errorf("unbounded fork with no declared exemption: %s\n"+
			"  Use outputTimeout / combinedOutputTimeout (they acquire the shared\n"+
			"  MaxConcurrentDiagnostics slot), or add an entry to\n"+
			"  declaredUnboundedForks with the reason this one must not be bounded.", u)
	}

	// The other direction: a stale exemption is also a failure, so this list
	// cannot decay into a record of sites that no longer exist.
	for _, e := range declaredUnboundedForks {
		if !found[e.file+"\x00"+e.fn+"\x00"+e.callee] {
			t.Errorf("declared exemption no longer matches any call site: %s %s() -> %s (%s).\n"+
				"  Remove it — a stale allowlist entry silently widens the next real one.",
				e.file, e.fn, e.callee, e.why)
		}
	}
}

// TestBothGRPCServersCapConcurrentStreams6552 pins the transport half of the
// bound. grpc-go's server default is unlimited concurrent streams per
// connection, so without this one connection supplies the multiplier that
// turns a per-request cost into an amplification. There is no exported
// accessor for the option, so this asserts on the source of the two builders
// — which is also the mutation that matters: deleting the option line.
func TestBothGRPCServersCapConcurrentStreams6552(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "server.go", src, 0)
	if err != nil {
		t.Fatalf("parse server.go: %v", err)
	}

	// Every grpc.NewServer in the package must pass grpc.MaxConcurrentStreams.
	builders := 0
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fd, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := ce.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			x, ok := sel.X.(*ast.Ident)
			if !ok || x.Name != "grpc" || sel.Sel.Name != "NewServer" {
				return true
			}
			builders++
			for _, arg := range ce.Args {
				inner, ok := arg.(*ast.CallExpr)
				if !ok {
					continue
				}
				isel, ok := inner.Fun.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				ix, ok := isel.X.(*ast.Ident)
				if ok && ix.Name == "grpc" && isel.Sel.Name == "MaxConcurrentStreams" {
					return true
				}
			}
			t.Errorf("%s() builds a grpc.Server with no grpc.MaxConcurrentStreams — "+
				"grpc-go defaults to unlimited streams per connection, so the "+
				"per-request bounds above can be multiplied without limit (#6552)",
				fd.Name.Name)
			return true
		})
	}
	if builders != 2 {
		t.Fatalf("found %d grpc.NewServer builders in server.go, want 2 (loopback + fabric); "+
			"a new server that this check did not see would be unbounded", builders)
	}
	if maxConcurrentStreams == 0 {
		t.Fatal("maxConcurrentStreams is 0 — grpc.MaxConcurrentStreams(0) is not a bound")
	}
}
