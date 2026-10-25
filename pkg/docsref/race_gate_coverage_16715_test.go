package docsref

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// #16715: the only `go test -race` runs in any gate were the three
// name-filtered test-race-dp legs (pkg/daemon, pkg/dataplane,
// pkg/cluster). At the source base 111 of 118 Test*Race*/*Concurrent*
// cells in pkg/ and cmd/ matched no leg, so reintroducing the #13127
// SNMP or #9916 syslog race passed `make test-go`. This census is the
// binder for the property leg added to test-race-dp: it derives the
// race-named population from the tree (never a hand list) and fails
// when any such test is outside every -race leg in the Makefile.
//
// A leg covers a (package, test) pair iff, inside the test-race-dp
// recipe, a `test -race` line names that package — `./pkg/<dir>/`,
// `./pkg/<dir>/...`, `./cmd/<dir>/...`, or a `./pkg/...`/`./cmd/...`
// wildcard — and that line's single-quoted -run pattern matches the
// test name. A line with `test -race` and no -run at all races the
// whole package. The #15241 `go test -list` pre-check lines are not
// race legs and never count.

// raceLeg16715 is one parsed `test -race` invocation in test-race-dp.
type raceLeg16715 struct {
	pkgArg  string // e.g. ./pkg/daemon/, ./pkg/..., or $(GO) list expansion marker
	pattern string // -run pattern; "" with hasRun=false means whole package
	hasRun  bool
}

var raceRunRe16715 = regexp.MustCompile(`-run\s+'([^']*)'`)

// raceNameRe16715 mirrors the issue census: a top-level Test func whose
// name contains Race or Concurrent.
var raceNameRe16715 = regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]*(?:Race|Concurrent)[A-Za-z0-9_]*)\s*\(`)

// parseRaceLegs16715 extracts the race legs from the test-race-dp
// recipe of a Makefile text. It is a pure function so the stale-shape
// tests below can feed it fixtures.
func parseRaceLegs16715(mk string) []raceLeg16715 {
	var legs []raceLeg16715
	inRecipe := false
	for _, line := range strings.Split(mk, "\n") {
		if strings.HasPrefix(line, "test-race-dp:") {
			inRecipe = true
			continue
		}
		if !inRecipe {
			continue
		}
		if line != "" && !strings.HasPrefix(line, "\t") {
			break
		}
		if !strings.Contains(line, "test -race") {
			continue
		}
		leg := raceLeg16715{}
		if m := raceRunRe16715.FindStringSubmatch(line); m != nil {
			leg.pattern, leg.hasRun = m[1], true
		}
		// Package argument: the token after -race/-run selection.
		// Prefer an explicit ./pkg/... or ./cmd/... token; the
		// property leg expands `$(GO) list ./pkg/... ./cmd/...`
		// in shell, so record that expansion as wildcard legs.
		if strings.Contains(line, "$(GO) list ./pkg/... ./cmd/...") ||
			strings.Contains(line, "$(GO) list ./pkg/...") {
			legs = append(legs, raceLeg16715{pkgArg: "./pkg/...", pattern: leg.pattern, hasRun: leg.hasRun})
			if strings.Contains(line, "./cmd/...") {
				legs = append(legs, raceLeg16715{pkgArg: "./cmd/...", pattern: leg.pattern, hasRun: leg.hasRun})
			}
			continue
		}
		for _, tok := range strings.Fields(line) {
			tok = strings.Trim(tok, `"'`)
			if strings.HasPrefix(tok, "./pkg/") || strings.HasPrefix(tok, "./cmd/") {
				leg.pkgArg = tok
				break
			}
		}
		if leg.pkgArg == "" {
			continue
		}
		legs = append(legs, leg)
	}
	return legs
}

// raceLegCovers16715 reports whether any leg selects test name in
// package dir pkgRel (repo-relative, slash form, e.g. pkg/snmp).
func raceLegCovers16715(legs []raceLeg16715, pkgRel, name string) (bool, error) {
	for _, leg := range legs {
		matched := false
		switch {
		case leg.pkgArg == "./pkg/..." && strings.HasPrefix(pkgRel, "pkg/"):
			matched = true
		case leg.pkgArg == "./cmd/..." && strings.HasPrefix(pkgRel, "cmd/"):
			matched = true
		default:
			want := strings.TrimSuffix(strings.TrimPrefix(leg.pkgArg, "./"), "/")
			if strings.HasSuffix(want, "/...") {
				base := strings.TrimSuffix(want, "/...")
				matched = pkgRel == base || strings.HasPrefix(pkgRel, base+"/")
			} else {
				matched = pkgRel == want
			}
		}
		if !matched {
			continue
		}
		if !leg.hasRun {
			return true, nil
		}
		re, err := regexp.Compile(leg.pattern)
		if err != nil {
			return false, fmt.Errorf("race leg pattern %q does not compile: %w", leg.pattern, err)
		}
		if re.MatchString(name) {
			return true, nil
		}
	}
	return false, nil
}

// raceNamedTests16715 walks pkg/ and cmd/ under root and returns
// pkgRel -> sorted race-named test names.
func raceNamedTests16715(root string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, top := range []string{"pkg", "cmd"} {
		base := filepath.Join(root, top)
		err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				switch info.Name() {
				case "vendor", "testdata":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, "_test.go") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			names := raceNameRe16715.FindAllStringSubmatch(string(raw), -1)
			if len(names) == 0 {
				return nil
			}
			rel, err := filepath.Rel(root, filepath.Dir(path))
			if err != nil {
				return err
			}
			pkgRel := filepath.ToSlash(rel)
			for _, m := range names {
				out[pkgRel] = append(out[pkgRel], m[1])
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out, nil
}

// uncoveredRaceTests16715 returns "pkg/name" for every race-named test
// no leg covers.
func uncoveredRaceTests16715(legs []raceLeg16715, census map[string][]string) ([]string, error) {
	var uncovered []string
	for pkgRel, names := range census {
		for _, name := range names {
			ok, err := raceLegCovers16715(legs, pkgRel, name)
			if err != nil {
				return nil, err
			}
			if !ok {
				uncovered = append(uncovered, pkgRel+":"+name)
			}
		}
	}
	sort.Strings(uncovered)
	return uncovered, nil
}

// TestRaceGateCoversAllRaceNamedTests16715 binds the #16715 property
// leg to the tree: every Test*Race*/*Concurrent* cell in pkg/ and
// cmd/ must be selected by some test-race-dp -race leg.
//
// FAIL-ON-REVERT: drop the property leg from test-race-dp, narrow
// its -run pattern, or add a race-named test in a package the legs
// do not race — this fails naming the cell. Pre-fix (property leg
// absent) it fails with the 100+ ungated cells.
func TestRaceGateCoversAllRaceNamedTests16715(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	legs := parseRaceLegs16715(string(b))
	if len(legs) == 0 {
		t.Fatal("test-race-dp has no `go test -race` legs at all")
	}
	census, err := raceNamedTests16715(root)
	if err != nil {
		t.Fatalf("census race-named tests: %v", err)
	}
	total := 0
	for _, names := range census {
		total += len(names)
	}
	// Positive controls: a vacuous census or a census that lost the
	// two cells the issue names must not read as full coverage.
	if total < 100 {
		t.Fatalf("census found only %d race-named tests in pkg/+cmd/ — the walk is broken, not the gate complete", total)
	}
	for _, want := range []string{"pkg/snmp", "pkg/logging"} {
		if len(census[want]) == 0 {
			t.Fatalf("census found no race-named tests in %s — the #16715 acceptance cells are invisible to this guard", want)
		}
	}
	uncovered, err := uncoveredRaceTests16715(legs, census)
	if err != nil {
		t.Fatal(err)
	}
	if len(uncovered) > 0 {
		t.Fatalf("%d of %d race-named tests are outside every test-race-dp -race leg:\n  %s\n\n"+
			"They pass `make test-go` without the race detector, so reintroducing their race ships silently. "+
			"Widen a leg or the property leg's -run pattern in the Makefile.",
			len(uncovered), total, strings.Join(uncovered, "\n  "))
	}
	t.Logf("#16715: %d race-named tests across %d packages, all inside a -race leg", total, len(census))
}

// TestRaceGateCensusRejectsStaleShapes16715 pins the guard itself:
// the pre-fix Makefile shape (three name-filtered legs only) and a
// property leg whose pattern is narrowed must both report the
// SNMP/syslog cells uncovered, or the census above could green on a
// reverted gate.
func TestRaceGateCensusRejectsStaleShapes16715(t *testing.T) {
	t.Parallel()
	census := map[string][]string{
		"pkg/snmp":    {"TestSetVRFDeviceConcurrentAccess13127"},
		"pkg/logging": {"TestSyslogConcurrentReconfigureRaceFree9916"},
		"pkg/daemon":  {"TestDataplaneCell_ConcurrentReadersVsWriter"},
	}
	preFix := "test-race-dp:\n" +
		"\t$(GO) test -race ./pkg/daemon/ -run 'DataplaneCell' -count=2\n" +
		"\t$(GO) test -race ./pkg/dataplane/ -run 'ArmedGate' -count=2\n"
	legs := parseRaceLegs16715(preFix)
	// The -list pre-check shape must not count as a race leg.
	withList := "test-race-dp:\n" +
		"\t$(GO) test -list \"^Test.*(Race)\" ./pkg/snmp/ | grep -q '^Test'\n" +
		"\t$(GO) test -race ./pkg/daemon/ -run 'DataplaneCell' -count=2\n"
	if got := parseRaceLegs16715(withList); len(got) != 1 {
		t.Fatalf("-list pre-check counted as a race leg: got %d legs, want 1", len(got))
	}
	uncovered, err := uncoveredRaceTests16715(legs, census)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(uncovered, " ")
	for _, want := range []string{"pkg/snmp:TestSetVRFDeviceConcurrentAccess13127", "pkg/logging:TestSyslogConcurrentReconfigureRaceFree9916"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("pre-fix shape did not report %s uncovered (uncovered: %v) — the census cannot fail on revert", want, uncovered)
		}
	}
	if strings.Contains(joined, "pkg/daemon:") {
		t.Fatalf("pre-fix shape wrongly reported the daemon cell uncovered: %v", uncovered)
	}
	// Narrowed property pattern: Race dropped, only Concurrent kept.
	narrowed := "test-race-dp:\n" +
		"\t$(GO) test -race -run 'Concurrent' -count=1 $$($(GO) list ./pkg/... ./cmd/...)\n"
	uncovered, err = uncoveredRaceTests16715(parseRaceLegs16715(narrowed), map[string][]string{
		"pkg/vrrp": {"TestAdvertIntervalNoRace6230"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(uncovered) != 1 {
		t.Fatalf("narrowed property pattern reported %v, want the NoRace cell uncovered", uncovered)
	}
	// Whole-package leg (no -run) covers its package.
	whole := "test-race-dp:\n\t$(GO) test -race ./pkg/snmp/ -count=1\n"
	uncovered, err = uncoveredRaceTests16715(parseRaceLegs16715(whole), census)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(uncovered, " "), "pkg/snmp:") {
		t.Fatalf("whole-package race leg did not cover pkg/snmp: %v", uncovered)
	}
}
