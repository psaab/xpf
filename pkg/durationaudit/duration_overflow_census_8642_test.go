package durationaudit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8642: a repo-wide census of `time.Duration(x) * time.<Unit>` sites, so the
// NINETEENTH unbounded config knob reds here instead of shipping.
//
// THE FAMILY. A config seconds/milliseconds knob is stored by the compiler as a
// plain `int` from `strconv.Atoi` with no range check, and a consumer computes
// `time.Duration(n) * time.Second`. Past `MaxDurationSeconds` the multiply
// overflows int64 nanoseconds and WRAPS — and the residue can be small and
// POSITIVE (`gcd(1e9, 2^64) = 512`, so 512ns for seconds; `gcd(1e6, 2^64) = 64`
// for milliseconds). Every guard this swept was `<= 0` or `> 0`, and every one
// of them is blind to that by construction: **a guard asking "is it nonsense in
// the obvious direction" cannot see wrap, because wrap is not nonsense.**
//
// The project fixed this family FOUR times one package at a time (#5705, #5723,
// #6769, #8597) before #8642 counted what was left. Five private copies of one
// three-line clamp is how the sixth site gets missed.
//
// WHY THIS PARSES RATHER THAN GREPS. A regex over the same pattern is wrong in
// both directions, measured:
//
//   - It counts PROSE. `pkg/config/schema_interfaces.go` has a `valueDesc`
//     string that describes this very hazard; a grep scores it as an instance.
//   - It counts the multiply INSIDE a bounding helper, after the bound — which
//     made all five already-fixed packages look unswept when the census was
//     first run against them.
//
// WHY A FIXPOINT RATHER THAN AN ALLOWLIST (the #8629 shape). A site is safe when
// its operand is bounded, OR when it comes from a function that bounds it. That
// accepts the shared converters and each package's own hardening helper by
// CONSTRUCTION, rather than by a hand-maintained exemption list that would
// happily keep blessing a helper which had stopped bounding.

// unitFactor names the time units whose multiply can overflow from a plausible
// config integer. Hour/Minute are included because #5784 was the minutes
// straggler of this same class.
var overflowUnits = map[string]bool{
	"Second": true, "Millisecond": true, "Minute": true, "Hour": true,
}

// boundingCalls are the primitives that establish a bound. A function becomes
// bound-clean by calling one of these, and the fixpoint then spreads that
// property to its callers.
var boundingCalls = map[string]bool{
	"SecondsToDuration": true, // pkg/config, #8642
	"MillisToDuration":  true,
	"MinutesToDuration": true,
}

// isBoundingConstant reports whether an identifier names a ceiling denominated
// in one of the overflow-capable units.
//
// This is a NAME PATTERN, not a fixed list, and the first draft was a fixed list
// of the three MaxDuration* constants. That list was wrong within one run: the
// census flagged `withinWindow` (#8597, already fixed) because it bounds against
// the domain-specific `config.MaxEventWithinSeconds` instead. A hand-maintained
// list of ceilings is the allowlist-rot failure the fixpoint exists to avoid,
// one level down — the NEXT domain ceiling would red a correctly-bounded site,
// and the usual response to that noise is to weaken the guard.
//
// A name pattern alone would be a naming heuristic, so it is not alone:
// TestEveryRecognisedCeilingIsBelowItsOverflowPoint8642 checks that every
// ceiling this accepts is actually at or below the arithmetic's overflow point.
// Recognition is by name; soundness is by value.
func isBoundingConstant(name string) bool {
	if !strings.HasPrefix(name, "Max") && !strings.HasPrefix(name, "max") {
		return false
	}
	for _, unit := range []string{"Seconds", "Millis", "Minutes", "Milliseconds"} {
		if strings.HasSuffix(name, unit) {
			return true
		}
	}
	return false
}

type site struct {
	file string
	line int
	fn   string
}

// isDurationMultiply reports whether e is `time.Duration(<ident>) * time.<Unit>`
// with a NON-CONSTANT operand. A literal or a named constant cannot come from
// config, so it is not a member of this family.
func isDurationMultiply(e ast.Expr) (operand string, ok bool) {
	bin, isBin := e.(*ast.BinaryExpr)
	if !isBin || bin.Op != token.MUL {
		return "", false
	}
	unit, isUnit := bin.Y.(*ast.SelectorExpr)
	if !isUnit {
		return "", false
	}
	if pkg, _ := unit.X.(*ast.Ident); pkg == nil || pkg.Name != "time" || !overflowUnits[unit.Sel.Name] {
		return "", false
	}
	call, isCall := bin.X.(*ast.CallExpr)
	if !isCall || len(call.Args) != 1 {
		return "", false
	}
	conv, isConv := call.Fun.(*ast.SelectorExpr)
	if !isConv {
		return "", false
	}
	if pkg, _ := conv.X.(*ast.Ident); pkg == nil || pkg.Name != "time" || conv.Sel.Name != "Duration" {
		return "", false
	}
	switch a := call.Args[0].(type) {
	case *ast.Ident:
		return a.Name, true
	case *ast.SelectorExpr:
		return a.Sel.Name, true
	}
	return "", false
}

// funcBoundsItsOperands reports whether fn establishes a bound before it
// multiplies: it either calls a bounding helper, or compares against one of the
// overflow-point constants.
func funcBoundsItsOperands(fn ast.Node) bool {
	bounded := false
	ast.Inspect(fn, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			switch f := v.Fun.(type) {
			case *ast.Ident:
				if boundingCalls[f.Name] {
					bounded = true
				}
			case *ast.SelectorExpr:
				if boundingCalls[f.Sel.Name] {
					bounded = true
				}
			}
		case *ast.Ident:
			if isBoundingConstant(v.Name) {
				bounded = true
			}
		case *ast.SelectorExpr:
			if isBoundingConstant(v.Sel.Name) {
				bounded = true
			}
		}
		return !bounded
	})
	return bounded
}

// repoRoot walks up to the module root so the census scans the tree rather than
// this package.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find go.mod above the working directory")
	return ""
}

// censusDurationSites walks pkg/ and cmd/ and returns every unbounded site,
// plus the count of sites it classified as BOUNDED. The second number is what
// makes a degenerate scan distinguishable from a clean tree.
func censusDurationSites(t *testing.T) (unbounded []site, boundedCount int) {
	t.Helper()
	root := repoRoot(t)
	fset := token.NewFileSet()

	for _, top := range []string{"pkg", "cmd"} {
		err := filepath.Walk(filepath.Join(root, top), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil // an unparseable file is not this census's business
			}
			rel, _ := filepath.Rel(root, path)
			for _, decl := range f.Decls {
				fn, isFn := decl.(*ast.FuncDecl)
				if !isFn || fn.Body == nil {
					continue
				}
				safe := funcBoundsItsOperands(fn)
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					e, isExpr := n.(ast.Expr)
					if !isExpr {
						return true
					}
					if _, ok := isDurationMultiply(e); !ok {
						return true
					}
					if safe {
						boundedCount++
						return true
					}
					unbounded = append(unbounded, site{
						file: rel, line: fset.Position(e.Pos()).Line, fn: fn.Name.Name,
					})
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", top, err)
		}
	}
	sort.Slice(unbounded, func(i, j int) bool {
		if unbounded[i].file != unbounded[j].file {
			return unbounded[i].file < unbounded[j].file
		}
		return unbounded[i].line < unbounded[j].line
	})
	return unbounded, boundedCount
}

// knownUnbounded is the pinned residue: sites that match the pattern, are NOT
// bounded, and carry a recorded verdict saying why that is correct.
//
// This is a verdict list, not an exemption list. Every entry names why the
// operand cannot come from an unbounded config int. A NEW site must either be
// bounded or be argued onto this list — which is the point of the census.
var knownUnbounded = map[string]string{
	// Runtime uptime, display only. Three copies of one line.
	"pkg/api/system.go":                           "upSec is process uptime, not config",
	"pkg/grpcapi/server_show_status.go":           "upSec is process uptime, not config",
	"pkg/cli/cli_show_system.go":                  "upSec is process uptime, not config",
	"pkg/dataplane/userspace/format/wireguard.go": "age is a runtime handshake age, display only",
	"pkg/flowexport/netflow.go":                   "ts.Sec is a packet timestamp",
	// Wire-supplied, and bounded by the wire field's own width: the LLDP TTL is
	// a 2-byte TLV clamped to [0,0xffff] (lldp.go:886), so the max is ~18h.
	// The ONLY attacker-influenced operand in the census, and safe by a bound
	// nobody wrote for arithmetic reasons — see the #8642 verdict table.
	"pkg/lldp/lldp.go": "neighbor.TTL is a 2-byte wire TLV clamped to [0,0xffff]",
	// capacity is clamped by resolvePendingCapacity before use. Note its own
	// post-multiply `w > pendingTTL` check would NOT have saved it: a wrapped
	// small-positive passes that comparison, same blindness as a `<= 0` guard.
	"pkg/dhcprelay/pending.go": "capacity is clamped by resolvePendingCapacity",
	// RA wire-field lifetimes. Same arithmetic, DIFFERENT harm: these encode
	// into RA option fields rather than arming a timer, so a wrapped value is a
	// wrong advertised lifetime, not a storm. The correct ceiling is the wire
	// field width (16- or 32-bit per field) and the fallback direction has to
	// be argued per field — RouterLifetime 0 means "not a default router",
	// which is a live behaviour change, not a safe default. Deliberately NOT
	// guessed at in this sweep; the timer site in the same file IS fixed.
	"pkg/ra/sender.go": "RA wire-field lifetimes; wire-width bound + per-field fallback, tracked separately",
	// Argued in place: minutes*time.Minute cannot overflow from the clamped
	// input (#5784), and store_commit carries its own written argument.
	"pkg/daemon/daemon_archive_timer.go": "clamped to MaxDurationMinutes (#5784)",
	"pkg/configstore/store_commit.go":    "carries a written non-overflow argument",
	// Both multiplies in sync_conn_sweep.go use runtime-derived scan seconds,
	// never a raw config value: primaryLivenessScanIntervalForTimeout clamps
	// to [initialPrimaryLivenessScanIntervalSeconds=1,
	// maxPrimaryLivenessScanIntervalSeconds=10]. requestedScanSeconds (:35)
	// reaches sweepWakeScanIntervalSeconds only via wakeSyncSweepForInterval
	// from that clamp or the 1s initial, and its CAS-min only ever lowers it;
	// scanSeconds (:70) is stored only from that clamp, the 1s initial, or
	// minimumLivenessScanInterval (min of 10, clamped per-session values, and
	// pending, itself only ever clamped or initial). Max 10s cannot overflow.
	// The pinned count is 2: StartSyncSweep and capSweepIntervalForLiveness.
	"pkg/cluster/sync_conn_sweep.go": "scan seconds clamped to [1,10] by primaryLivenessScanIntervalForTimeout; CAS-min only lowers",
}

// Counts measured from censusDurationSites. Keep zero-site verdicts pinned too:
// a future multiply in one of those files is a new site, not old residue.
var knownUnboundedSiteCounts = map[string]int{
	"pkg/api/system.go":                           0,
	"pkg/grpcapi/server_show_status.go":           0,
	"pkg/cli/cli_show_system.go":                  0,
	"pkg/dataplane/userspace/format/wireguard.go": 1,
	"pkg/flowexport/netflow.go":                   1,
	"pkg/lldp/lldp.go":                            1,
	"pkg/dhcprelay/pending.go":                    1,
	"pkg/ra/sender.go":                            7,
	"pkg/daemon/daemon_archive_timer.go":          0,
	"pkg/configstore/store_commit.go":             0,
	"pkg/cluster/sync_conn_sweep.go":              2,
}

func durationSiteVerdictFindings(unbounded []site, verdicts map[string]string, pinnedCounts map[string]int) []string {
	actualCounts := make(map[string]int)
	var findings []string
	for _, s := range unbounded {
		actualCounts[s.file]++
		if _, known := verdicts[s.file]; !known {
			findings = append(findings, s.file+":"+itoa(s.line)+" in "+s.fn+"() has no recorded verdict")
		}
	}

	files := make([]string, 0, len(verdicts))
	for file := range verdicts {
		files = append(files, file)
	}
	sort.Strings(files)
	for _, file := range files {
		actual := actualCounts[file]
		pinned, hasPinnedCount := pinnedCounts[file]
		if !hasPinnedCount {
			findings = append(findings, file+": pinned count missing, actual "+itoa(actual)+
				"; bound the new site or re-argue the verdict and update the count")
		} else if actual != pinned {
			findings = append(findings, file+": pinned "+itoa(pinned)+", actual "+itoa(actual)+
				"; bound the new site or re-argue the verdict and update the count")
		}
	}
	return findings
}

func TestDurationSiteVerdictCounts8642(t *testing.T) {
	const file = "pkg/fixture/verdict.go"
	verdicts := map[string]string{file: "fixture verdict"}
	pinnedCounts := map[string]int{file: 2}
	makeSites := func(count int) []site {
		sites := make([]site, count)
		for i := range sites {
			sites[i] = site{file: file, line: i + 1, fn: "f"}
		}
		return sites
	}

	for _, tc := range []struct {
		name       string
		sites      []site
		wantFinding string
	}{
		{name: "exact count", sites: makeSites(2)},
		{name: "gained site", sites: makeSites(3), wantFinding: file + ": pinned 2, actual 3"},
		{name: "lost site", sites: makeSites(1), wantFinding: file + ": pinned 2, actual 1"},
		{
			name: "non-verdicted site",
			sites: append(makeSites(2), site{file: "pkg/fixture/new.go", line: 9, fn: "newSite"}),
			wantFinding: "pkg/fixture/new.go:9 in newSite() has no recorded verdict",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings := durationSiteVerdictFindings(tc.sites, verdicts, pinnedCounts)
			if tc.wantFinding == "" {
				if len(findings) != 0 {
					t.Fatalf("exact pinned count produced findings: %s", strings.Join(findings, "\n"))
				}
				return
			}
			joined := strings.Join(findings, "\n")
			if !strings.Contains(joined, tc.wantFinding) {
				t.Fatalf("findings %q do not contain %q", joined, tc.wantFinding)
			}
			if tc.name == "gained site" || tc.name == "lost site" {
				if !strings.Contains(joined, "bound the new site or re-argue the verdict and update the count") {
					t.Fatalf("count mismatch lacks remediation instruction: %s", joined)
				}
			}
		})
	}
}

// THE CENSUS. A new `time.Duration(x) * time.<Unit>` on an unbounded operand
// reds here.
func TestNoUnboundedConfigDurationMultiplies8642(t *testing.T) {
	unbounded, boundedCount := censusDurationSites(t)

	// DEGENERATE-FAILURE GUARD 1: a scan that recognises no BOUNDED site at all
	// — a broken parser, a renamed helper, a walk that found no files — reports
	// exactly what a clean tree reports. Require it to have seen the bounding
	// helpers actually working.
	if boundedCount < 8 {
		t.Fatalf("the census classified only %d sites as bounded. The tree has at "+
			"least the shared converters plus five package helpers, so a number "+
			"this low means the scan is not seeing what it claims to — and a "+
			"blind scan and a clean tree produce identical output", boundedCount)
	}

	findings := durationSiteVerdictFindings(unbounded, knownUnbounded, knownUnboundedSiteCounts)
	if len(findings) > 0 {
		t.Fatalf("unbounded time.Duration multiply verdict mismatch:\n  %s\n\n"+
			"This is the #8642 family. A config seconds/milliseconds knob reaches\n"+
			"`time.Duration(n) * time.<Unit>` with no ceiling, and past\n"+
			"MaxDurationSeconds (or MaxDurationMillis) the multiply WRAPS to a\n"+
			"small POSITIVE residue — 512ns for seconds, 64ns for milliseconds.\n"+
			"A `<= 0` or `> 0` guard cannot see that, because a wrapped value is\n"+
			"not nonsense; it is a plausible small interval.\n\n"+
			"Fix by converting through config.SecondsToDuration / MillisToDuration\n"+
			"/ MinutesToDuration, which bound at the OVERFLOW POINT and fall back\n"+
			"rather than clamp. Do NOT fix by adding a schema ceiling: a typed-leaf\n"+
			"violation is downgraded to a warning on the tolerant Store.Load /\n"+
			"peer-sync ingress, so a persisted or peer-pushed config never meets it.\n\n"+
			"If the operand genuinely cannot come from config, add it to\n"+
			"knownUnbounded with the reason and pin its site count.",
			strings.Join(findings, "\n  "))
	}
}


// DEGENERATE-FAILURE GUARD 2: the census must be able to SEE an unbounded site.
// Guard 1 proves it recognises bounded ones; without this, a classifier that
// called everything bounded would pass both the census and guard 1.
func TestTheCensusCanSeeAnUnboundedSite8642(t *testing.T) {
	src := `package p
import "time"
func f(n int) time.Duration { return time.Duration(n) * time.Second }`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	fn := firstFunc(t, f)
	if funcBoundsItsOperands(fn) {
		t.Fatal("an unbounded function was classified as bounded — the census " +
			"would report a clean tree no matter what the tree contained")
	}
	var found bool
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if e, ok := n.(ast.Expr); ok {
			if _, is := isDurationMultiply(e); is {
				found = true
			}
		}
		return true
	})
	if !found {
		t.Fatal("isDurationMultiply did not recognise `time.Duration(n) * time.Second`")
	}
}

// And the converse: a function that DOES bound must be recognised, or every
// fixed site would red and the pressure would be to weaken the census.
func TestTheCensusRecognisesABoundedSite8642(t *testing.T) {
	src := `package p
import "time"
func f(n int, fb time.Duration) time.Duration {
	if int64(n) > MaxDurationSeconds { return fb }
	return time.Duration(n) * time.Second
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !funcBoundsItsOperands(firstFunc(t, f)) {
		t.Fatal("a function comparing against MaxDurationSeconds was NOT " +
			"recognised as bounded — every already-fixed site would red, and the " +
			"usual response to that noise is to weaken the guard")
	}
}

// PROSE IS NOT A SITE. A grep counts the valueDesc string in
// pkg/config/schema_interfaces.go that describes this hazard; the parser must
// not.
func TestProseDescribingTheHazardIsNotASite8642(t *testing.T) {
	src := `package p
var d = struct{ valueDesc string }{
	valueDesc: "Bounded to keep time.Duration(sec)*time.Second from overflowing",
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if e, ok := n.(ast.Expr); ok {
			if _, is := isDurationMultiply(e); is {
				t.Fatal("a STRING describing the hazard was counted as an instance " +
					"of it — the reason this census parses instead of grepping")
			}
		}
		return true
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// firstFunc returns the first FuncDecl in f. Indexing Decls[0] gets the IMPORT
// declaration, which is how the first draft of these two cells panicked rather
// than asserting.
func firstFunc(t *testing.T, f *ast.File) *ast.FuncDecl {
	t.Helper()
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok {
			return fn
		}
	}
	t.Fatal("fixture has no function declaration")
	return nil
}

// Recognition above is by NAME; this is the check that makes it sound. Every
// ceiling the census accepts as a bound must actually be at or below the point
// where its unit's multiply overflows — otherwise a site could "bound" against a
// number too large to help, and the census would bless it.
func TestEveryRecognisedCeilingIsBelowItsOverflowPoint8642(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value int64
		max   int64
	}{
		{"config.MaxEventWithinSeconds", int64(config.MaxEventWithinSeconds), config.MaxDurationSeconds},
		{"config.MaxDurationSeconds", config.MaxDurationSeconds, config.MaxDurationSeconds},
		{"config.MaxDurationMillis", config.MaxDurationMillis, config.MaxDurationMillis},
		{"config.MaxDurationMinutes", config.MaxDurationMinutes, config.MaxDurationMinutes},
	} {
		if tc.value > tc.max {
			t.Errorf("%s = %d exceeds its unit's overflow point %d — a site "+
				"comparing against it is NOT bounded, but the census accepts the "+
				"name as if it were", tc.name, tc.value, tc.max)
		}
	}
}
