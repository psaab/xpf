// #6584: raw external-command output reaching an operator terminal unescaped.
//
// #6468 established the class — device-originated text printed to a terminal
// can carry OSC 52 (clipboard write), OSC 8 (hyperlink) and CSI (cursor/erase)
// sequences the terminal ACTS ON. #6579 covered the vtysh and DDNS surfaces.
//
// The two sites the issue names are the largest remaining members, and the log
// one is the most directly connected to #6468's own threat model: the syslog
// stream carries the very DHCP lease hostnames #6468 was filed about, so a
// device that sets its hostname to an escape payload gets it logged and then
// re-emitted verbatim the moment an operator runs `show log` — the sanitized
// lease table is bypassed by reading the log instead.
//
// THIS FILE'S DURABLE PART IS THE TRIPWIRE, not the two fixes.
//
// The research for this issue established that NOTHING in the tree fails when
// a display site forgets the guard: there is no enumerating table and no
// source-scanning canary for termsafe, only per-site behavioural binders. That
// is the same gap #6579's own review recorded from the other side — "reverting
// all 14 call-site edits left the suite green, because the only test file
// exercised the primitive" — and the miss it actually shipped was an entire
// renderer.
//
// So every function that forks an external command must either reference
// termsafe or be written down here with a reason. That is a set difference in
// BOTH directions: an unguarded fork fails, and a stale exemption whose site no
// longer exists also fails, so the list cannot rot into a record of things that
// used to be true.
package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// forkExemption names one function that forks an external command and does NOT
// route its output through termsafe.
type forkExemption struct {
	pkgDir string
	file   string
	fn     string
	why    string
}

// declaredUnsanitizedForks is the complete allowlist across the three packages
// that fork on a display path.
var declaredUnsanitizedForks = []forkExemption{
	// ---- no output is consumed at all ----
	{"../cli", "cli_request_system.go", "handleRequestSystem",
		"systemctl reboot/halt/poweroff — no output is read"},
	{"../cli", "cli_request_system.go", "<package-scope>",
		"deferred power-action goroutine — no output is read"},
	{"../grpcapi", "server_diag_system_action.go", "<package-scope>",
		"reset stop/unit probes (systemctl stop xpfd; is-active --quiet) — exit status only, no output is read"},

	// ---- output is consumed but never reaches a terminal as raw text ----
	{"../ipsec", "manager.go", "runSwanctl",
		"generic swanctl runner; its SA-listing caller sanitizes at ingest " +
			"(sanitizeSAStatus) and its error path escapes the captured output"},
	{"../ipsec", "manager.go", "runSwanctlSplit",
		"#9068 stdout-only swanctl runner for the one call whose output is " +
			"PARSED. Same exposure as runSwanctl above and for the same reasons: " +
			"GetSAStatus sanitizes its rows at ingest (sanitizeSAStatus), and both " +
			"callers escape stderr into their error path " +
			"(termsafe.SanitizeForDisplay). Splitting the streams changed WHICH " +
			"buffer the parser reads, not whether raw output reaches a terminal"},

	// ---- STREAMING sites ----
	//
	// #7389: the three LOCAL CLI streaming sites are no longer exempt.
	// termsafe.NewSanitizingWriter is the shape change #6584 said was needed:
	// a line-wise io.Writer interposed between the command and the terminal,
	// which preserves the streaming UX (Ctrl-C, incremental output) that made
	// buffered capture unacceptable for tcpdump. handleMonitorTraffic,
	// handlePing and handleTraceroute all use it now, so their entries are
	// deleted rather than reworded — an allowlist entry is a claim, and this
	// census checks its entries for staleness in BOTH directions.
	//
	// The gRPC twin below is a DIFFERENT shape (per-line protobuf sends, not
	// an io.Writer) and stays exempt.
	{"../grpcapi", "server_diag_ping.go", "streamDiagCmd",
		"the gRPC ping/traceroute streamer — per-line sends, same shape change " +
			"as the local CLI twins above. Tracked separately"},

	// ---- low-taint, root-controlled text, LOCAL CLI ONLY ----
	// Each of these is a SINGLE-fork function, so function granularity is exact
	// for them. Their gRPC mirrors ARE guarded: those functions fork several
	// binaries each, and leaving any raw would let the guarded sibling vouch
	// for the rest under this check.
	{"../cli", "cli_show_system.go", "showSystemConnections",
		"ss -tnp — numeric; the process column is root-controlled. Tracked separately"},
	{"../cli", "cli_show_system.go", "showSystemProcesses",
		"ps aux — argv of root-controlled processes. Tracked separately"},
	{"../cli", "cli_show_system.go", "showSystemNTP",
		"FOUR forks, and the reason differs per fork (#8597). `chronyc -n sources`, " +
			"`ntpq -pn` and `timedatectl show --property=NTPSynchronized --value` are " +
			"numeric-mode or fixed-property status and stay raw. The fourth, " +
			"`chronyc tracking`, carries NO `-n`: its Reference-ID parenthetical is a " +
			"REVERSE-DNS-RESOLVED hostname, so printChronyTracking now sanitizes every " +
			"field it prints. The pre-#8597 reason said \"chronyc -n / ntpq -pn / " +
			"timedatectl — numeric-mode NTP status\", which was true of three forks and " +
			"silent about the fourth. Tracked separately"},
	{"../cli", "cli_clear.go", "handleClearArp",
		"ip -4 neigh flush — output only in an error string. Tracked separately"},
	{"../cli", "cli_clear.go", "handleClearIPv6",
		"ip -6 neigh flush — as above. Tracked separately"},

	// ---- the exec plumbing itself ----
	{"../grpcapi", "exec_timeout.go", "combinedOutputTimeout", "exec helper, not a display site"},
	{"../grpcapi", "exec_timeout.go", "combinedOutputTimeoutUnlimited", "exec helper"},
	{"../grpcapi", "exec_timeout.go", "outputTimeout", "exec helper"},
	{"../grpcapi", "exec_timeout.go", "outputTimeoutUnlimited", "exec helper"},
	{"../grpcapi", "exec_timeout.go", "runTimeout", "exec helper; discards output"},

	// ---- destructive admin actions, output only in errors ----
	{"../grpcapi", "server_diag_system_action.go", "SystemAction",
		"ip neigh flush; output only in an error string. Tracked separately"},
	{"../grpcapi", "server_diag_zeroize.go", "<package-scope>",
		"zeroize userdel / passwd -l root. Tracked separately"},
}

var forkCallees = map[string]bool{
	"exec.Command": true, "exec.CommandContext": true,
	"combinedOutputTimeout": true, "outputTimeout": true,
	"combinedOutputTimeoutUnlimited": true, "outputTimeoutUnlimited": true,
}

// TestEveryCommandOutputDisplaySiteIsSanitizedOrDeclared6584 is the tripwire.
//
// RED-on-revert: drop the termsafe call from showDaemonLog (or its gRPC
// mirror) and that function is named here, because it forks and no longer
// references termsafe and is not on the list.
func TestEveryCommandOutputDisplaySiteIsSanitizedOrDeclared6584(t *testing.T) {
	t.Parallel()

	allowed := map[string]string{}
	for _, e := range declaredUnsanitizedForks {
		allowed[e.pkgDir+"\x00"+e.file+"\x00"+e.fn] = e.why
	}
	found := map[string]bool{}
	var undeclared []string
	scanned := 0

	for _, dir := range []string{"../cli", "../grpcapi", "../ipsec"} {
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		fset := token.NewFileSet()
		for _, e := range ents {
			name := e.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			f, err := parser.ParseFile(fset, path, src, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			scanned++

			// A function is "guarded" when its FILE references termsafe and
			// the function body itself mentions it. File-level alone would
			// let one guarded function in a file vouch for an unguarded
			// sibling — which is exactly how a half-applied sweep hides.
			var decls []*ast.FuncDecl
			for _, d := range f.Decls {
				if fd, ok := d.(*ast.FuncDecl); ok {
					decls = append(decls, fd)
				}
			}
			encl := func(p token.Pos) *ast.FuncDecl {
				for _, fd := range decls {
					if fd.Pos() <= p && p <= fd.End() {
						return fd
					}
				}
				return nil
			}

			ast.Inspect(f, func(nd ast.Node) bool {
				ce, ok := nd.(*ast.CallExpr)
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
				if !forkCallees[callee] {
					return true
				}
				fnName := "<package-scope>"
				body := ""
				haveBody := false
				if fd := encl(ce.Pos()); fd != nil {
					fnName = fd.Name.Name
					body = string(src[fd.Pos()-f.FileStart : fd.End()-f.FileStart])
					haveBody = true
				}
				// Guarded when the function applies AT LEAST AS MANY termsafe
				// calls as it makes forks.
				//
				// "references termsafe at all" was the first version and it was
				// too coarse: GetSystemInfo forks four binaries and ShowText
				// two, so one guarded arm vouched for its unguarded siblings —
				// the exact half-applied-sweep shape this file exists to catch,
				// reproduced inside the guard. The mutation matrix found it:
				// four cells that removed a real guard stayed GREEN.
				//
				// A RELATIVE count is safe where an absolute one would rot:
				// deleting a fork also lowers the requirement, so the guard
				// cannot go vacuous by the counted call disappearing — which is
				// the usual failure of count-based checks. Deleting a SANITIZE
				// while keeping the fork is what reds.
				// A fork inside a package-level var initializer has no
				// enclosing FuncDecl, so there is no body to count. Unknown
				// must mean UNGUARDED and fall through to the allowlist: with
				// an empty body both counts are 0, and `0 >= 0` would have
				// waved every package-scope fork through silently. The control
				// run caught exactly that.
				//
				// #7389: `wireSanitizedOutput(` counts as a sanitize. It is the
				// named in-package wrapper that points a command's stdout AND
				// stderr at termsafe.SanitizingWriter, for the streaming sites
				// that wire an io.Writer instead of capturing a string.
				//
				// It has to be recognised HERE rather than left to the
				// allowlist, because the alternative measured worse. With the
				// two streams wired inline and separately, reverting only
				// `cmd.Stdout` left the function still mentioning "termsafe."
				// via `cmd.Stderr`, the relative count still passed, and the
				// mutation ESCAPED. Routing both through one call makes the
				// partial revert inexpressible — but then the body no longer
				// says "termsafe." at all, so the count must know the wrapper's
				// name. Deleting the call still reds, which is the property
				// that matters.
				sanitizes := strings.Count(body, "termsafe.") +
					strings.Count(body, "wireSanitizedOutput(")
				if haveBody && sanitizes >= strings.Count(body, callee+"(") {
					return true
				}
				key := dir + "\x00" + name + "\x00" + fnName
				if _, ok := allowed[key]; ok {
					found[key] = true
					return true
				}
				undeclared = append(undeclared,
					dir+"/"+name+" "+fnName+"() forks "+callee+" and does not sanitize")
				return true
			})
		}
	}

	if scanned < 30 {
		t.Fatalf("scanned only %d production files — the walk is vacuous", scanned)
	}
	sort.Strings(undeclared)
	for _, u := range undeclared {
		t.Errorf("unsanitized command-output site: %s\n"+
			"  Route the output through termsafe.SanitizeBlockForDisplay (multi-line\n"+
			"  command stdout) or termsafe.SanitizeForDisplay (a single-line field),\n"+
			"  on BOTH renderers — or add it to declaredUnsanitizedForks with the\n"+
			"  reason it cannot be guarded (#6584).", u)
	}
	for _, e := range declaredUnsanitizedForks {
		if !found[e.pkgDir+"\x00"+e.file+"\x00"+e.fn] {
			t.Errorf("stale exemption: %s/%s %s() no longer forks, or is now guarded (%s).\n"+
				"  Remove it — a stale allowlist entry silently widens the next real one.",
				e.pkgDir, e.file, e.fn, e.why)
		}
	}
}

// TestGetSAStatusWiresTheIngestGuard6584 binds the WIRING for site B.
//
// The behavioural tests in pkg/ipsec drive parseSAOutput and sanitizeSAStatus
// directly, because GetSAStatus forks a real swanctl and cannot be driven from
// a unit test. That means they test the FUNCTION and say nothing about whether
// anything calls it — and the mutation that matters is deleting the call.
func TestGetSAStatusWiresTheIngestGuard6584(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile("../ipsec/ike.go")
	if err != nil {
		t.Fatalf("read ike.go: %v", err)
	}
	flat := strings.Join(strings.Fields(string(src)), "")
	if !strings.Contains(flat, "sanitizeSAStatus(&sas[i])") {
		t.Fatal("GetSAStatus does not call sanitizeSAStatus on the parsed records. " +
			"Every renderer of SAStatus — two local CLI views, two gRPC mirrors — then " +
			"prints peer-influenced swanctl text raw, and the pkg/ipsec tests stay green " +
			"throughout because they exercise the sanitizer directly (#6584).")
	}
}

// TestMultiLineCommandOutputUsesTheBlockVariant6584 pins the VARIANT at the
// sites whose output is multi-line command stdout.
//
// Picking the wrong one is not a security regression but it is a real defect
// in the other direction: SanitizeForDisplay escapes LF, so a whole journalctl
// dump would collapse into one line of \x0a. pkg/cli/README.md states the rule
// as "pick the variant by the SHAPE of the value" and says the tests assert
// both directions; for these forked sites there is no seam to assert it
// behaviourally, so it is asserted structurally.
func TestMultiLineCommandOutputUsesTheBlockVariant6584(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ file, fn string }{
		{"../cli/cli_show_system.go", "showDaemonLog"},
		{"../cli/cli_show_system.go", "showSystemBootMessages"},
		// #8629 renamed the body: `ShowText` is now a two-line boundary that
		// converts bare errors to gRPC status codes and delegates to `showText`,
		// which is where the forks live. The exported wrapper forks nothing, so
		// pointing at it made this guard report itself VACUOUS — correctly, and
		// that self-report is why the rename could not silently disarm it.
		{"../grpcapi/server_show.go", "showText"},
		{"../grpcapi/server_show_status.go", "GetSystemInfo"},
	} {
		src, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, tc.file, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", tc.file, err)
		}
		var body string
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == tc.fn {
				body = string(src[fd.Pos()-f.FileStart : fd.End()-f.FileStart])
			}
		}
		if body == "" {
			t.Fatalf("%s: function %s not found — this guard is stale", tc.file, tc.fn)
		}
		// COUNT-relative, for the same reason the tripwire above is: these
		// functions fork more than once (GetSystemInfo four times, ShowText and
		// showDaemonLog twice), so `contains Block` lets one correct arm vouch
		// for a sibling that was switched to the single-line variant. The
		// mutation matrix caught exactly that.
		forks := strings.Count(body, "outputTimeout(ctx,") +
			strings.Count(body, "combinedOutputTimeout(ctx,") +
			strings.Count(body, "exec.Command(")
		if got := strings.Count(body, "SanitizeBlockForDisplay"); got < forks {
			t.Errorf("%s %s() applies SanitizeBlockForDisplay %d time(s) to %d forked "+
				"command output(s). The shortfall is sanitized with the SINGLE-LINE "+
				"variant, which escapes LF — so a multi-line log dump collapses into "+
				"one line of \\x0a. Multi-line command output takes "+
				"SanitizeBlockForDisplay, which preserves LF/TAB and neutralizes "+
				"CR/ESC/C0/C1 (#6584).", tc.file, tc.fn, got, forks)
		}
		if forks == 0 {
			t.Errorf("%s %s(): the fork-counting patterns matched nothing, so this "+
				"guard is vacuous — the call spelling changed", tc.file, tc.fn)
		}
	}
}
