package refactoraudit

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// applied_marker_registry_7343_test.go — #7343 item 2, the driver registry.
//
// #6533 PLAN-KILLED the proposed `analysistest` rule on measured evidence: the
// applied/published/converged vocabulary is the REMEDY each historical fix
// introduced, not the defect's signature, so the rule missed 3 of 3 sampled
// defects and flagged the mechanisms held up as correct.
//
// #7343 then proposed two mechanisms. This file is the second, and the triage
// on that issue is why only the second was built:
//
//   - ITEM 1, a typed marker whose `Advance(gen, err)` takes the error, is not
//     built. All 42 population sites were classified and all 23 real markers
//     are already correct — by FOUR different mechanisms (early return, caller
//     contract, explicit guard, status readback). Exactly ONE has a live
//     unreturned error in scope at the stamp, and it advances on failure
//     deliberately (#6535). So `Advance` would take a literal nil at 22 of 23
//     sites, and a parameter that is nil at every call site encodes no
//     contract — it is a no-op wearing the shape of a guarantee.
//
//   - ITEM 2, this registry, is the half #7343 says "actually made the twelve
//     prior fixes work — storage without a driver is the bug."
//
// WHY THE INVENTORY IS KEYED ON (file, statement, count) AND NOT ON file:line.
// A line-keyed registry goes stale on any edit ABOVE a site and would red
// constantly for reasons that have nothing to do with convergence. Counting
// identical statements per file is stable under line drift and still fails when
// a NEW assignment appears — which is the property that matters, because the
// recurring defect is a marker added without a driver.

type markerStmt struct {
	stmt  string
	count int
}

// notMarkerFiles hold assignments that MATCH the population grep but are not
// convergence markers at all. Each carries its reason: an unexplained entry
// here is indistinguishable from an unnoticed marker.
var notMarkerFiles7343 = map[string][]markerStmt{
	// Accumulators — appending to a result slice.
	"pkg/vrrp/instance_vip.go": {{`res.applied = append(res.applied, vip)`, 2}},
	// #8000: BatchFailoverResult is a local `var res` that is only ever
	// RETURNED (never assigned into m.*), so these two record what one call
	// did for its caller. Nothing stores them and nothing re-reads them to
	// decide whether to converge, which is what a marker would need a driver
	// for. The two statements are the commit loop and the one-member
	// delegation arm.
	"pkg/cluster/failover.go": {
		{`res.Applied = append(res.Applied, ids[0])`, 1},
		{`res.Applied = append(res.Applied, rgID)`, 1},
	},
	// Read-outs into a display view or a snapshot returned to a caller.
	"pkg/cli/cli_show_security_filters.go": {{`v.appliedGen = cr.Generation`, 1}},
	"pkg/cluster/sync_bulk.go":             {{`snap.AppliedConfigGen = s.lastAppliedConfigGen.Load()`, 1}},
	// Remembers what was last LOGGED, not what was applied.
	"pkg/dataplane/userspace/tunnels.go": {{`m.lastPublishedWgEndpoints = set`, 1}},
	// Zero-resets: clearing a marker is the SAFE direction — it forces a
	// re-converge and can never claim a convergence that did not happen.
	"pkg/routing/tunnel.go": {
		{`t.appliedAddrs = map[string]map[string]bool{}`, 1},
		{`t.appliedAddrs = nil`, 1},
		{`t.appliedRI = map[string]string{}`, 1},
		{`t.appliedRI = nil`, 1},
	},
	"pkg/dataplane/userspace/process.go": {
		{`m.appliedSnapshot = appliedSnapshot{}`, 1},
		{`m.publishedPlanKey = ""`, 1},
		{`m.publishedSnapshot = 0`, 1},
	},
}

// markerFiles7343 hold REAL convergence markers. Driver is the symbol that
// periodically re-drives the marker when desired != applied; DriverPkg is the
// directory holding it. Both are asserted to exist.
type markerFile struct {
	Driver    string
	DriverPkg string
	Why       string
	Stmts     []markerStmt
}

var markerFiles7343 = map[string]markerFile{
	"pkg/dataplane/userspace/manager_compile.go": {
		Driver: "statusLoop", DriverPkg: "pkg/dataplane/userspace",
		Why: "early return: the apply_snapshot error returns above every stamp",
		Stmts: []markerStmt{
			{`m.publishedPlanKey = newPlanKey`, 1},
			{`m.publishedPlanKey = snapshotBindingPlanKey(&next)`, 1},
			{`m.publishedSnapshot = next.Generation`, 1},
			{`m.publishedSnapshot = snap.Generation`, 1},
		},
	},
	"pkg/dataplane/userspace/manager_overlay.go": {
		Driver: "statusLoop", DriverPkg: "pkg/dataplane/userspace",
		Why: "early return at both publish sites: the route-overlay publish and #10485's " +
			"RepublishCurrentCaptureAuthority rollback-heal return the publish error above " +
			"the stamp",
		Stmts: []markerStmt{
			{`m.publishedPlanKey = snapshotBindingPlanKey(&next)`, 2},
			{`m.publishedSnapshot = next.Generation`, 2},
		},
	},
	"pkg/dataplane/userspace/manager_worker_arm_5134.go": {
		Driver: "statusLoop", DriverPkg: "pkg/dataplane/userspace",
		Why: "early return: the arm error returns above the stamp and the debt stays set",
		Stmts: []markerStmt{
			{`m.publishedPlanKey = snapshotBindingPlanKey(&next)`, 1},
			{`m.publishedSnapshot = next.Generation`, 1},
		},
	},
	"pkg/dataplane/userspace/process_status.go": {
		Driver: "statusLoop", DriverPkg: "pkg/dataplane/userspace",
		Why: "three shapes in one file: one early return, one status READBACK where the " +
			"helper already reports the generation, and one dedup-skip where nothing was " +
			"published because nothing changed. None has an error in scope.",
		Stmts: []markerStmt{
			{`m.publishedPlanKey = planKey`, 2},
			{`m.publishedSnapshot = m.lastSnapshot.Generation`, 3},
		},
	},
	"pkg/dataplane/userspace/manager_generation.go": {
		Driver: "statusLoop", DriverPkg: "pkg/dataplane/userspace",
		Why:   "guard: skipped entirely unless fullSnapshotWasPublished",
		Stmts: []markerStmt{{`m.publishedSnapshot = m.lastSnapshot.Generation`, 1}},
	},
	"pkg/dataplane/userspace/applied_nat_view.go": {
		Driver: "statusLoop", DriverPkg: "pkg/dataplane/userspace",
		Why:   "guard: skipped while deferWorkers is set; the rebind reconcile captures it later",
		Stmts: []markerStmt{{`m.appliedSnapshot = appliedSnapshot{`, 1}},
	},
	"pkg/feeds/feeds.go": {
		Driver: "refreshLoop", DriverPkg: "pkg/feeds",
		Why: "early return: an apply REJECTION returns above the stamp, deliberately leaving " +
			"publishedHash stale so the next identical refetch retries (#5646 publication debt)",
		Stmts: []markerStmt{
			{`dst.publishedHash = src.publishedHash`, 1},
			{`fs.publishedHash = [32]byte{}`, 1},
			{`fs.publishedHash = res.hash`, 1},
		},
	},
	"pkg/ddns/surface_a.go": {
		Driver: "reconcileScopeLocked", DriverPkg: "pkg/ddns",
		Why: "early return: the publish error returns above the stamp and records backoff",
		Stmts: []markerStmt{
			{`rt.lastPublished = now`, 1},
			{`v.LastPublished = rt.lastPublished`, 2},
			{`v.Published = owned.AddrText`, 1},
			// #7423 row 5: the pending-window override. Same read-out into the
			// status view as the line above, and it narrows what the view
			// claims rather than widening it -- while PublishPending is set the
			// view reports the last CONFIRMED address instead of the desired
			// one, which is the safe direction for a convergence marker.
			{`v.Published = owned.PriorAddrText`, 1},
		},
	},
	"pkg/daemon/rg_state.go": {
		Driver: "reconcileLocked", DriverPkg: "pkg/daemon",
		Why: "caller contract: markAppliedLocked takes the OBSERVED state and contains no " +
			"error at all (#6799); InvalidateApplied sets NOT-converged, the safe direction",
		Stmts: []markerStmt{
			{`s.applied = !s.active`, 1},
			{`s.applied = active`, 1},
		},
	},
	"pkg/configstore/store.go": {
		Driver: "ActiveApplied", DriverPkg: "pkg/configstore",
		Why: "caller contract: MarkAppliedDigest is called only on full success and an empty " +
			"digest is a no-op that deliberately does not clear a prior one. #9175 adds the " +
			"SECOND zero-reset: InvalidateAppliedDigest, called from applyConfigLocked's " +
			"error path. A zero-reset is the safe direction — it forces a re-converge and " +
			"can never claim a convergence that did not happen — and it is what makes the " +
			"caller contract above sufficient: before it, a FAILED apply left the previous " +
			"success standing, so a re-promotion of a text applied earlier in the process " +
			"read as converged for a dataplane that never took it",
		Stmts: []markerStmt{
			{`s.appliedDigest = ""`, 2},
			{`s.appliedDigest = configTextDigest(s.active.Format())`, 1},
			{`s.appliedDigest = digest`, 1},
		},
	},
	"pkg/ipmon/ipmon.go": {
		Driver: "run", DriverPkg: "pkg/ipmon",
		Why: "guard: inside the converged-and-not-re-dirtied branch; a failed actuation or a " +
			"concurrent re-dirty keeps dirtySince set so the next wake re-actuates (#3757/#3761)",
		Stmts: []markerStmt{{`e.appliedOverlay = e.activeOverlayLocked()`, 1}},
	},
	// THE DECLARED ESCAPE. #7343 requires this be a first-class, registry-visible
	// declaration naming the driver rather than a suppression — a `//nolint` here
	// is the failure mode #6533 was killed for.
	"pkg/dhcpserver/dhcpserver.go": {
		Driver: "apply", DriverPkg: "pkg/dhcpserver",
		Why: "the shared apply body drives every Apply path: clearFamilyLocked resets both " +
			"family stamps when config removes a family, and a later configured apply reaches " +
			"reconcileFamilyRestart with a nil applied config, so it enforces the new rendered " +
			"bytes. Apply failures still advance lastAppliedGen; ClaimApplyRetry lets the " +
			"converger enter the same apply body again (#6535).",
		Stmts: []markerStmt{
			{`m.appliedConfig4 = nil`, 1},
			{`m.appliedConfig6 = nil`, 1},
			{`m.lastAppliedGen = gen`, 1},
		},
	},
}

var markerAssignRE7343 = regexp.MustCompile(
	`^\s*[A-Za-z_][A-Za-z0-9_.]*\.(last|prev|Last|Prev)?([Aa]pplied|[Pp]ublished|[Cc]onverged)[A-Za-z0-9_]*\s*(=|:=)`)

// scanPopulation7343 reproduces docs/applied-marker-invariant.md Measurement 1
// over the tree, returning file -> statement -> count.
func scanPopulation7343(t *testing.T, root string) map[string]map[string]int {
	t.Helper()
	out := map[string]map[string]int{}
	for _, top := range []string{"pkg", "cmd"} {
		err := filepath.Walk(filepath.Join(root, top), func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			rel, _ := filepath.Rel(root, p)
			for _, line := range strings.Split(string(b), "\n") {
				if markerAssignRE7343.MatchString(line) {
					if out[rel] == nil {
						out[rel] = map[string]int{}
					}
					out[rel][strings.TrimSpace(line)]++
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", top, err)
		}
	}
	return out
}

// Every assignment matching the population grep must be classified — as a real
// marker with a driver, or as a non-marker with a stated reason.
//
// This is the property that makes the registry load-bearing rather than
// decorative: a NEW marker added anywhere in the tree lands here as an
// unclassified statement and reds, which is exactly the "storage without a
// driver" defect that recurred twelve times.
func TestEveryAppliedMarkerSiteIsClassified7343(t *testing.T) {
	root := repoRoot(t)
	pop := scanPopulation7343(t, root)

	total := 0
	for _, stmts := range pop {
		for _, n := range stmts {
			total += n
		}
	}
	// ANTI-VACUITY FLOOR. The scan is regex-driven over a directory walk and
	// can silently come back short — a moved tree, a changed suffix check, a
	// regex that stops matching. Every comparison below would then pass over
	// almost nothing. 35 is comfortably under the current population and
	// comfortably over anything a broken scan produces.
	if total < 35 {
		t.Fatalf("the population scan found only %d assignments (floor 35); the scan is "+
			"broken, so a clean result here would certify nothing", total)
	}

	registered := map[string]map[string]int{}
	for f, stmts := range notMarkerFiles7343 {
		registered[f] = map[string]int{}
		for _, s := range stmts {
			registered[f][s.stmt] = s.count
		}
	}
	for f, mf := range markerFiles7343 {
		if registered[f] == nil {
			registered[f] = map[string]int{}
		}
		for _, s := range mf.Stmts {
			registered[f][s.stmt] = s.count
		}
	}

	for f, stmts := range pop {
		for stmt, n := range stmts {
			want, ok := registered[f][stmt]
			if !ok {
				t.Errorf("UNCLASSIFIED applied-marker assignment:\n  %s\n    %s\n"+
					"Add it to markerFiles7343 with the driver that re-drives it, or to "+
					"notMarkerFiles7343 with the reason it is not a marker. A marker with "+
					"no driver is the defect this registry exists to catch — storage "+
					"without a driver is the bug (#7343)", f, stmt)
				continue
			}
			if n != want {
				t.Errorf("%s: %q occurs %d times, registry says %d. If an assignment was "+
					"added, classify it; if one was removed, update the count — an "+
					"unreconciled count means a marker is in the tree with nothing "+
					"checking it (#7343)", f, stmt, n, want)
			}
		}
	}

	for f, stmts := range registered {
		for stmt := range stmts {
			if _, ok := pop[f][stmt]; !ok {
				t.Errorf("%s: registry lists %q but the tree no longer contains it. A stale "+
					"registry entry is an allowlist that hides the next regression (#7343)", f, stmt)
			}
		}
	}
}

// STORAGE WITHOUT A DRIVER IS THE BUG. Every real marker must name a periodic
// re-driver, and that symbol must exist.
func TestEveryAppliedMarkerHasALiveDriver7343(t *testing.T) {
	root := repoRoot(t)
	if len(markerFiles7343) < 8 {
		t.Fatalf("only %d marker files registered; the table is not reaching this test",
			len(markerFiles7343))
	}
	for f, mf := range markerFiles7343 {
		if mf.Driver == "" || mf.DriverPkg == "" {
			t.Errorf("%s registers a marker with no driver. #7343: storage without a "+
				"driver is the bug", f)
			continue
		}
		if mf.Why == "" {
			t.Errorf("%s registers a marker with no stated reason its stamp is correct; an "+
				"unexplained entry is indistinguishable from an unnoticed defect", f)
		}
		if !symbolExistsInPkg7343(t, root, mf.DriverPkg, mf.Driver) {
			t.Errorf("%s names driver %q in %s, and no such func exists there. Either the "+
				"driver was renamed or removed — and a marker whose re-driver is gone is "+
				"exactly the twelve-times-recurring defect (#7343)", f, mf.Driver, mf.DriverPkg)
		}
	}
}

// A file may not be registered as both a marker and a non-marker.
func TestNoFileIsBothMarkerAndNotMarker7343(t *testing.T) {
	for f := range markerFiles7343 {
		if _, dup := notMarkerFiles7343[f]; dup {
			// Legal only if the STATEMENTS are disjoint — a file can hold both a
			// real marker and a zero-reset. Assert that explicitly rather than
			// letting the overlap merge silently in the classification map.
			seen := map[string]bool{}
			for _, s := range markerFiles7343[f].Stmts {
				seen[s.stmt] = true
			}
			for _, s := range notMarkerFiles7343[f] {
				if seen[s.stmt] {
					t.Errorf("%s classifies %q as BOTH a marker and a non-marker", f, s.stmt)
				}
			}
		}
	}
}

func symbolExistsInPkg7343(t *testing.T, root, pkgDir, symbol string) bool {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, pkgDir))
	if err != nil {
		t.Fatalf("read %s: %v", pkgDir, err)
	}
	needle := regexp.MustCompile(`^func\s+(\([^)]*\)\s*)?` + regexp.QuoteMeta(symbol) + `\b`)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, pkgDir, e.Name()))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if needle.MatchString(line) {
				return true
			}
		}
	}
	return false
}
