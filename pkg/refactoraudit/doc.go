// Package refactoraudit hosts the enforcement canary for the committed
// modularity heatmap (docs/refactoring-audit-current.txt).
//
// It contains no xpf runtime code — nothing here is linked into xpfd or
// the CLI. Its primary purpose is to give `go test ./...` — the required
// pre-commit aggregate (`make test`) — a home for the modularity gate.
//
// #6937 added the one piece of non-test code: structs.go / structs_rust.go
// measure struct heterogeneity for the sibling artifact
// docs/refactoring-audit-structs.txt, driven by the `structaudit`
// command in this package's subdirectory. That measurement needs go/ast
// (a regex counter descends into anonymous nested structs and inflates
// the count), so it cannot live in the shell generator the way the LOC
// measurement does. An earlier revision of this paragraph said the
// package "contains no runtime code" full stop, which stopped being true
// the moment the counter landed.
//
// # Two properties, two surfaces (#7253)
//
// The gate used to be one test, TestHeatmapNotStale, and it fused two
// different properties:
//
//	modularity — "this file is growing past the point where it should be
//	split". Aimed at the author of the growth, actionable by them, worth
//	interrupting them for.
//
//	freshness — "the committed global snapshot disagrees with the tree".
//	Aimed at whoever merges next, not actionable by them, and not worth
//	interrupting anyone for.
//
// Only the first is a gate, and the second could not stay true long
// enough to be one: the heatmap is a snapshot of a repo-GLOBAL property,
// so any file crossing 1500 or 2000 LOC anywhere in the tree flipped it
// for every author. #7235, #7252 and #7254 each regenerated it inside one
// hour for different files, and #7252 was ALREADY STALE when it merged.
// #6617 had narrowed the same class once before (byte-compare ->
// content-compare, after master measured byte-stale in 26 of 40
// first-parent commits) without changing its shape.
//
// So the two properties now have two surfaces:
//
//   - TestTouchedFileCrossedModularityThreshold is the HARD gate. It reds
//     when a file THE BRANCH TOUCHES crossed 1500 or 2000 LOC, measured
//     from the branch's own diff against its merge base with
//     origin/master (scripts/refactoring-audit-touched.sh). It never reads
//     the committed artifact, so no unrelated file can invalidate it and
//     regenerating the artifact cannot silence it. On master the changed
//     set is empty and it is structurally silent. The one escape is a
//     written acknowledgement in docs/refactoring-audit-accepted.txt.
//
//   - TestGlobalHeatmapFreshnessAdvisory REPORTS global drift and does
//     not fail on it. scripts/refactoring-audit-refresh.sh (make
//     audit-refresh) regenerates and commits the artifact, so freshness
//     converges through a job rather than through a human.
//
// TestTouchedGateIsNotASnapshotCompare is the test that keeps the split
// from decaying back into one property: it shows the two mechanisms
// disagreeing in BOTH directions on the same input, so the hard gate
// cannot be re-implemented as a restricted snapshot compare.
//
// The companion tests pin the artifact's internal coherence
// (TestHeatmapArtifactWellFormed), generator determinism
// (TestGeneratorDeterministic), the Rust test-only filename classifier
// (#6232), the audited-path predicate the touched probe shares with the
// generator, and the raw-LOC measurement so the gate cannot silently
// start counting test warehouses as production again.
//
// # The package is also the home for unrelated mechanical canaries
//
// The framing above — "its primary purpose is to give `go test ./...` a
// home for the modularity gate" — describes how the package started, not
// what it now holds. Guards that have nothing to do with the heatmap have
// accumulated here because this is where a repo-WIDE structural check can
// run inside the required aggregate without inventing a package for one
// test: the `_Log.md` closure (#6874), conflict-marker residue, the
// commit-check dataplane ban (#7297), the iperf3 port (#6897) and the
// duplicate `#[test]` scanner (#8393).
//
// What they share is shape, not subject: each answers a question about the
// TREE that no single package's own tests can see, and each fails to a
// value an author would otherwise mistake for healthy. A canary belongs
// here when it is mechanical, repo-wide and cheap; it does not belong here
// merely because it is a test with nowhere obvious to live.
//
// See audit_touched_test.go, audit_jobs_test.go, audit_canary_test.go,
// docs/refactoring-audit.md, scripts/refactoring-audit.sh,
// scripts/refactoring-audit-touched.sh,
// scripts/refactoring-audit-refresh.sh, and
// scripts/refactoring-audit-lib.sh.
package refactoraudit
