package manifest

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// repoRoot walks up from this test file's directory until it finds go.mod,
// so the canary reads the tracked shell sites regardless of the test's cwd.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed; cannot locate repo root")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("walked to filesystem root from %s without finding go.mod", filepath.Dir(thisFile))
		}
		dir = parent
	}
}

// readFile reads a repo-relative file and fails the test if it is missing —
// the canary must fail closed: a moved/renamed site is a divergence, not a
// skip.
func readFile(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read %s: %v (the drift canary expects this file to exist; "+
			"if it moved, update the canary)", rel, err)
	}
	return string(b)
}

// binsLine matches a `BINS="word word ..."` assignment, tolerating leading
// whitespace (the test fixtures indent the assignment inside a function).
var binsLine = regexp.MustCompile(`(?m)^[[:space:]]*BINS="([^"]*)"`)

// extractBINS pulls the single BINS="..." word list out of a shell source and
// returns the space-separated fields. It FAILS the test (fail-closed) if no
// BINS= literal is present or if more than one is present (a script that drops
// the literal, or grows a second divergent one, must trip the canary rather
// than be silently skipped — Codex caution against a vacuous regex match).
func extractBINS(t *testing.T, rel, src string) []string {
	t.Helper()
	m := binsLine.FindAllStringSubmatch(src, -1)
	if len(m) == 0 {
		t.Fatalf("%s: no `BINS=\"...\"` literal found — the managed-binary "+
			"drift canary requires every shell site to carry the BINS literal "+
			"(if the mechanism changed, update pkg/upgrade/manifest and this "+
			"canary together)", rel)
	}
	if len(m) > 1 {
		t.Fatalf("%s: found %d `BINS=\"...\"` literals; expected exactly one "+
			"(a second, possibly divergent, list defeats the canary)", rel, len(m))
	}
	return strings.Fields(m[0][1])
}

// rulesInstall matches the `install -m 0755 <src> ... debian/xpf$(STAGED)/<name>`
// lines in debian/rules. The install command may wrap across two physical
// lines (xpf-day0-config does), so we match on the staged destination path
// which is what defines the installed basename.
var rulesInstallDest = regexp.MustCompile(`debian/xpf\$\(STAGED\)/([A-Za-z0-9._-]+)`)

// extractRulesInstall pulls the set of basenames debian/rules installs into
// the staging dir. It scans only the override_dh_auto_install recipe so that
// unrelated debian/xpf$(STAGED) mentions elsewhere do not pollute the set.
func extractRulesInstall(t *testing.T, src string) []string {
	t.Helper()
	const startMarker = "override_dh_auto_install:"
	start := strings.Index(src, startMarker)
	if start < 0 {
		t.Fatalf("debian/rules: %q recipe not found", startMarker)
	}
	body := src[start+len(startMarker):]
	// The recipe ends at the next top-level target/override (a line starting
	// at column 0 that is not blank and not a comment). Recipe lines are
	// TAB-indented.
	if end := nextTopLevel(body); end >= 0 {
		body = body[:end]
	}
	var names []string
	for _, m := range rulesInstallDest.FindAllStringSubmatch(body, -1) {
		names = append(names, m[1])
	}
	if len(names) == 0 {
		t.Fatal("debian/rules: no `debian/xpf$(STAGED)/<name>` install lines " +
			"found in override_dh_auto_install (the canary expects the managed " +
			"binaries to be installed there)")
	}
	return names
}

// rulesInstallPair matches a single `install -m 0755 <src> debian/xpf$(STAGED)/<dest>`
// command, capturing BOTH the build-output SOURCE and the staged DEST basename.
// The install command may wrap across two physical lines (xpf-day0-config does),
// so callers join `\`-continuations before matching.
var rulesInstallPair = regexp.MustCompile(`install\s+-m\s+0755\s+(\S+)\s+debian/xpf\$\(STAGED\)/([A-Za-z0-9._-]+)`)

// extractRulesInstallPairs returns the dest->src map debian/rules installs into
// the staging dir. Unlike extractRulesInstall (dest basenames only) it keeps the
// SOURCE path so the canary can catch a wrong artifact shipped under the correct
// staged basename — StagedSrc was previously dead manifest metadata (#1999).
func extractRulesInstallPairs(t *testing.T, src string) map[string]string {
	t.Helper()
	const startMarker = "override_dh_auto_install:"
	start := strings.Index(src, startMarker)
	if start < 0 {
		t.Fatalf("debian/rules: %q recipe not found", startMarker)
	}
	body := src[start+len(startMarker):]
	if end := nextTopLevel(body); end >= 0 {
		body = body[:end]
	}
	// Join line continuations so a wrapped install command matches as one.
	joined := strings.ReplaceAll(body, "\\\n", " ")
	pairs := map[string]string{}
	for _, m := range rulesInstallPair.FindAllStringSubmatch(joined, -1) {
		pairs[m[2]] = m[1] // dest basename -> source path
	}
	if len(pairs) == 0 {
		t.Fatal("debian/rules: no `install -m 0755 <src> debian/xpf$(STAGED)/<name>` " +
			"pairs found in override_dh_auto_install")
	}
	return pairs
}

// stagedSrcMismatches compares debian/rules' dest->src install pairs against the
// manifest's Name->StagedSrc mapping, returning one message per divergence. A
// wrong source under the correct basename (the #1999 hazard) is caught here even
// though the destination-basename set still equals manifest.Names().
func stagedSrcMismatches(pairs map[string]string) []string {
	var msgs []string
	for _, b := range All() {
		got, ok := pairs[b.Name]
		if !ok {
			msgs = append(msgs, b.Name+": no `install ... debian/xpf$(STAGED)/"+
				b.Name+"` line in debian/rules")
			continue
		}
		if got != b.StagedSrc {
			msgs = append(msgs, b.Name+": debian/rules installs source "+got+
				" but manifest StagedSrc is "+b.StagedSrc+
				" (a wrong artifact under the correct basename ships silently)")
		}
	}
	return msgs
}

// nextTopLevel returns the offset of the first line in body that begins a new
// top-level make construct (column-0, non-blank, non-comment, non-recipe), or
// -1 if none. Recipe lines are TAB-indented; a directory `install -d` that is
// not a managed binary is harmless because it does not match rulesInstallDest.
func nextTopLevel(body string) int {
	lines := strings.SplitAfter(body, "\n")
	off := 0
	for _, ln := range lines {
		trimmedNL := strings.TrimRight(ln, "\n")
		if trimmedNL != "" && !strings.HasPrefix(ln, "\t") &&
			!strings.HasPrefix(strings.TrimSpace(ln), "#") {
			return off
		}
		off += len(ln)
	}
	return -1
}

// besteffortForLoop matches the literal managed-binary `for b in ...` loop in
// test/debian/preinst-besteffort-test.sh. That fixture hardcodes the binary
// list in a for loop rather than a BINS= literal, so it is a drift site the
// canary must cover too (the plan's eight-site list missed it; we cover it
// here). We assert the full-set loop (the one that includes xpfd) matches.
var besteffortFullLoop = regexp.MustCompile(`for b in (xpfd[^;]*); do`)

func extractBesteffortLoop(t *testing.T, src string) []string {
	t.Helper()
	m := besteffortFullLoop.FindStringSubmatch(src)
	if m == nil {
		t.Fatal("preinst-besteffort-test.sh: no `for b in xpfd ...; do` " +
			"managed-binary loop found (the canary expects this fixture to " +
			"iterate the full managed set)")
	}
	return strings.Fields(m[1])
}

// sortedEqual reports whether a and b contain the same elements (order- and
// duplicate-sensitive after sorting). The shell loops are order-free, so the
// canary compares as sets-with-multiplicity.
func sortedEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string(nil), a...)
	bs := append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

// censusToken matches one word token for the census scanner.
var censusToken = regexp.MustCompile(`[A-Za-z0-9._-]+`)

type censusHit struct {
	file  string
	line  int
	names []string
}

// censusRuns returns every maximal run of >=3 adjacent manifest.Names()
// tokens in src, attributed to its starting line. Tokens are
// [A-Za-z0-9._-]+ words; any other byte (whitespace, punctuation,
// quotes, comment markers) is a separator, so runs may span line
// breaks. Occurrences of the generated list in gen_bins.go and this
// test's own literals are inventoried by the allowance below, never
// silently skipped.
func censusRuns(src string, nameSet map[string]bool) []censusHit {
	var hits []censusHit
	var run []string
	runLine := 0
	flush := func() {
		if len(run) >= 3 {
			hits = append(hits, censusHit{line: runLine, names: append([]string(nil), run...)})
		}
		run = nil
	}
	for _, loc := range censusToken.FindAllStringIndex(src, -1) {
		tok := src[loc[0]:loc[1]]
		if nameSet[tok] {
			if len(run) == 0 {
				runLine = strings.Count(src[:loc[0]], "\n") + 1
			}
			run = append(run, tok)
		} else {
			flush()
		}
	}
	flush()
	return hits
}

// censusAllowlist records, per file, every census run that is neither
// a covered site compared against the SSOT nor the generated file.
// Entries are positional: the walk rejects a run with no remaining
// entry, and the final check rejects a stale entry with no run.
// Counts were inventoried from the census at #17101.
var censusAllowlist = map[string][]string{
	// Derives BINS from seed_layout._BINS (bins.txt), so it contains
	// no >=3 run; kept with zero runs so a retyped list would need a
	// new allowlist reason AND would fail the no-literal scan.
	"scripts/image/test_seed_layout_10771.py": {},
	// Prose info line naming the deb payload (all four, updated by
	// #17101 to match Names()), not a list definition.
	"scripts/image/bake.py": {"prose-not-a-list"},
	// Captured tcpdump fixture text (xpfd xpfd cli), not a list.
	"test/incus/harness-result-selftest.sh": {"fixture-not-a-list"},
	// Incidental fixture loops over a subset (missing xpfd): setup
	// scaffolding that iterates BINS-adjacent fixtures, not the
	// managed set definition.
	"test/debian/postinst-test.sh": {
		"fixture-loop-missing-xpfd", "fixture-loop-missing-xpfd",
		"fixture-loop-missing-xpfd", "fixture-loop-missing-xpfd",
		"fixture-loop-missing-xpfd", "fixture-loop-missing-xpfd",
	},
	"test/debian/postrm-test.sh": {
		"fixture-loop-missing-xpfd", "fixture-loop-missing-xpfd",
	},
	// The full-set loop is the covered besteffort site; this subset
	// run is fixture scaffolding in the same file.
	"test/debian/preinst-besteffort-test.sh": {"fixture-loop-missing-xpfd"},
	"test/debian/preinst-migrate-test.sh":    {"fixture-loop-missing-xpfd"},
	// Dual-covered: the staged-path comment run is pinned by the
	// debian/rules install-set and StagedSrc checks in this test.
	"debian/rules": {"covered-rules"},
	// Prose naming the pushed/verified binaries: not a list
	// definition, and the push set is separately pinned below.
	"test/incus/deploy-lib.sh": {
		"prose-not-a-list", "prose-not-a-list",
		"prose-not-a-list", "prose-not-a-list",
	},
	// Prose comment describing the deb payload, not a list.
	"Makefile": {"prose-not-a-list"},
	// This test's own literals: comparator fixtures (drifted, extra,
	// renamed), the StagedSrc counterfactual, and the push-set
	// xpf-day0-config filter — inputs to the code under test.
	"pkg/upgrade/manifest/manifest_drift_test.go": {
		"test-fixture", "test-fixture", "test-fixture", "test-fixture",
	},
	// Generator's Names() mirror literal: pinned transitively (its
	// output must equal bins.txt; bins.txt is pinned to Names()).
	"pkg/upgrade/manifest/gen_bins.go": {"generated-mirror-pinned-by-canary"},
}

// censusCoveredRuns are the covered managed-binary sites whose raw
// census runs the dedicated extractors above already compare against
// the SSOT. bins.txt is the generated copy, compared directly.
var censusCoveredRuns = map[string]bool{
	"debian/xpf.preinst":                     true,
	"debian/xpf.postinst":                    true,
	"debian/xpf.postrm":                      true,
	"test/debian/preinst-migrate-test.sh":    true,
	"test/debian/postrm-test.sh":             true,
	"test/debian/postinst-test.sh":           true,
	"test/debian/preinst-besteffort-test.sh": true,
	"scripts/image/seed_layout_10771.py":     true,
	"pkg/upgrade/manifest/bins.txt":          true,
	"pkg/upgrade/manifest/manifest.go":       true,
}

// TestManagedBinaryDriftCanary is the #1982 drift guard, extended to a
// census by #17101. It FAILS the suite if any covered site's
// managed-binary list diverges from the Go SSOT (manifest.Names), if
// the generated bins.txt diverges, if the deploy push set is not
// exactly Names() minus xpf-day0-config, or if a tracked shell,
// Python, Makefile or systemd-unit file contains a run of >=3
// adjacent Names() tokens that is neither a covered site nor an
// allowlisted run with a reason. The census is the coverage claim:
// a new duplicated list anywhere in scope reds this test until it is
// covered or allowlisted with a reason.
func TestManagedBinaryDriftCanary(t *testing.T) {
	root := repoRoot(t)
	want := Names()

	// Shell sites carrying a BINS="..." literal.
	binsSites := []string{
		"debian/xpf.preinst",
		"debian/xpf.postinst",
		"debian/xpf.postrm",
		"test/debian/preinst-migrate-test.sh",
		"test/debian/postrm-test.sh",
		"test/debian/postinst-test.sh",
	}
	for _, rel := range binsSites {
		got := extractBINS(t, rel, readFile(t, root, rel))
		if !sortedEqual(got, want) {
			t.Errorf("%s: BINS=%q diverges from manifest.Names()=%q — update "+
				"pkg/upgrade/manifest/manifest.go and every site together", rel, got, want)
		}
	}

	// debian/rules install set.
	rulesSrc := readFile(t, root, "debian/rules")
	gotRules := extractRulesInstall(t, rulesSrc)
	if !sortedEqual(gotRules, want) {
		t.Errorf("debian/rules: install set %q diverges from manifest.Names()=%q",
			gotRules, want)
	}
	// Install SOURCE must also match manifest StagedSrc (#1999), not just the
	// destination basename — otherwise a wrong artifact under the correct
	// staged name ships silently (the StagedSrc field used to be unchecked).
	for _, msg := range stagedSrcMismatches(extractRulesInstallPairs(t, rulesSrc)) {
		t.Error("debian/rules: " + msg)
	}

	// preinst-besteffort-test.sh literal for-loop.
	gotBE := extractBesteffortLoop(t, readFile(t, root, "test/debian/preinst-besteffort-test.sh"))
	if !sortedEqual(gotBE, want) {
		t.Errorf("test/debian/preinst-besteffort-test.sh: for-loop set %q "+
			"diverges from manifest.Names()=%q", gotBE, want)
	}

	// Generated bins.txt must equal Names() exactly, in order (#17101):
	// seed_layout_10771.py and its test derive their lists from it, so
	// adding a fifth managed binary reds here until bins.txt is
	// regenerated (go generate ./pkg/upgrade/manifest/).
	binsTxt := readFile(t, root, "pkg/upgrade/manifest/bins.txt")
	var binsNames []string
	for _, line := range strings.Split(binsTxt, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			binsNames = append(binsNames, strings.Fields(line)...)
		}
	}
	if strings.Join(binsNames, " ") != strings.Join(want, " ") {
		t.Errorf("pkg/upgrade/manifest/bins.txt=%q diverges from "+
			"manifest.Names()=%q — regenerate with "+
			"`go generate ./pkg/upgrade/manifest/`", binsNames, want)
	}

	// seed_layout_10771.py (ACCEPTANCE) and its test oracle contain no
	// literal binary list: the subject must read bins.txt and name no
	// managed binary at all; the oracle derives from the subject, but
	// keeps individual binary names in assertions (fine — those are
	// assertions, not a list), so it is checked only for a >=3 run
	// via the census.
	{
		src := readFile(t, root, "scripts/image/seed_layout_10771.py")
		if !strings.Contains(src, "bins.txt") {
			t.Error("scripts/image/seed_layout_10771.py: does not read " +
				"pkg/upgrade/manifest/bins.txt — the image layout gate " +
				"must derive from the SSOT (#17101)")
		}
		for _, tok := range censusToken.FindAllString(src, -1) {
			for _, name := range want {
				if tok == name {
					t.Errorf("scripts/image/seed_layout_10771.py: contains "+
						"literal managed-binary name %q — derive from "+
						"bins.txt instead (#17101)", tok)
				}
			}
		}
	}
	if !strings.Contains(readFile(t, root, "scripts/image/test_seed_layout_10771.py"), "seed_layout._BINS") {
		t.Error("scripts/image/test_seed_layout_10771.py: oracle does not " +
			"derive from seed_layout._BINS (#17101)")
	}

	// Deploy push set: deploy_managed_bins must be exactly Names()
	// minus xpf-day0-config (the one binary raw deploy never pushes).
	deploySrc := readFile(t, root, "test/incus/deploy-lib.sh")
	m := regexp.MustCompile(`(?m)^deploy_managed_bins=\(([^)]*)\)`).FindStringSubmatch(deploySrc)
	if m == nil {
		t.Fatal("test/incus/deploy-lib.sh: no deploy_managed_bins=(...) " +
			"push-set literal found (the canary expects the push set here)")
	}
	pushWant := make([]string, 0, len(want))
	for _, name := range want {
		if name != "xpf-day0-config" {
			pushWant = append(pushWant, name)
		}
	}
	if got := strings.Fields(m[1]); !sortedEqual(got, pushWant) {
		t.Errorf("test/incus/deploy-lib.sh: deploy_managed_bins=%q, want "+
			"push set %q (manifest.Names() minus xpf-day0-config)", got, pushWant)
	}

	// Census (#17101): every run of >=3 adjacent Names() tokens in a
	// tracked shell, Python, Makefile or unit file must be covered or
	// allowlisted with a reason.
	nameSet := map[string]bool{}
	for _, name := range want {
		nameSet[name] = true
	}
	out, err := exec.Command("git", "-C", root, "ls-files").Output()
	if err != nil {
		t.Fatalf("git ls-files: %v (the census needs a git checkout)", err)
	}
	exts := map[string]bool{
		".sh": true, ".py": true, ".bash": true, ".service": true,
		".timer": true, ".socket": true, ".path": true, ".target": true,
		".mk": true,
	}
	allowUsed := map[string]int{}
	files := []string{"debian/rules", "debian/xpf.preinst",
		"debian/xpf.postinst", "debian/xpf.postrm",
		"pkg/upgrade/manifest/manifest_drift_test.go",
		"pkg/upgrade/manifest/gen_bins.go",
		"pkg/upgrade/manifest/manifest.go",
		"pkg/upgrade/manifest/bins.txt"}
	seenFile := map[string]bool{}
	for _, rel := range strings.Fields(string(out)) {
		if exts[filepath.Ext(rel)] || filepath.Base(rel) == "Makefile" ||
			strings.HasSuffix(rel, "/Makefile") {
			files = append(files, rel)
		}
	}
	for _, rel := range files {
		if seenFile[rel] {
			continue
		}
		seenFile[rel] = true
		if strings.HasPrefix(rel, "docs/") {
			continue
		}
		src := readFile(t, root, rel)
		for _, hit := range censusRuns(src, nameSet) {
			hit.file = rel
			if censusCoveredRuns[rel] {
				continue
			}
			idx := allowUsed[rel]
			reasons := censusAllowlist[rel]
			if idx < len(reasons) {
				allowUsed[rel]++
				continue
			}
			t.Errorf("census: %s:%d: uncovered run of managed-binary "+
				"names %q — cover it against manifest.Names(), derive "+
				"it from bins.txt, or allowlist it in "+
				"manifest_drift_test.go with a reason (#17101)",
				hit.file, hit.line, hit.names)
		}
	}
	// Stale-entry check: covered files skip the per-run allowlist
	// accounting above, so only non-covered allowlisted files must
	// fully consume their entries.
	for rel, reasons := range censusAllowlist {
		if censusCoveredRuns[rel] {
			continue
		}
		if allowUsed[rel] != len(reasons) {
			t.Errorf("census: allowlist for %s has %d reason(s) but %d "+
				"run(s) found — stale allowlist entries must be removed "+
				"(#17101)", rel, len(reasons), allowUsed[rel])
		}
	}
}

// TestDriftCanaryComparatorCatchesDivergence is the counter-factual: it proves
// the canary's comparator (extractBINS + sortedEqual) actually REPORTS a
// divergence rather than passing vacuously. If this test ever passes while a
// real script drifts, the guard is worthless — so we feed the parser a drifted
// snippet and assert it does NOT match the SSOT.
func TestDriftCanaryComparatorCatchesDivergence(t *testing.T) {
	want := Names()

	cases := []struct {
		name string
		src  string
	}{
		{"missing-binary", `set -e
BINS="xpfd cli xpf-userspace-dp"
case "$1" in`},
		{"extra-binary", `set -e
BINS="xpfd cli xpf-userspace-dp xpf-day0-config xpf-new-helper"
case "$1" in`},
		{"renamed-binary", `set -e
BINS="xpfd cli xpf-userspace-dp xpf-day0"
case "$1" in`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := binsLine.FindStringSubmatch(tc.src)
			if m == nil {
				t.Fatalf("comparator test setup: BINS not found in %q", tc.src)
			}
			got := strings.Fields(m[1])
			if sortedEqual(got, want) {
				t.Fatalf("comparator FAILED to catch divergence: drifted "+
					"BINS=%q compared equal to manifest %q — the drift canary "+
					"would pass vacuously", got, want)
			}
		})
	}

	// And the inverse: the in-sync literal MUST compare equal (so the canary
	// is not a constant-fail).
	inSync := `set -e
BINS="` + ShellBINS() + `"
case "$1" in`
	m := binsLine.FindStringSubmatch(inSync)
	if m == nil {
		t.Fatal("comparator test: BINS not found in in-sync snippet")
	}
	if !sortedEqual(strings.Fields(m[1]), want) {
		t.Fatalf("comparator rejected an IN-SYNC BINS literal %q vs manifest %q "+
			"— the canary would false-positive", strings.Fields(m[1]), want)
	}
}

// TestStagedSrcCounterfactual proves the StagedSrc check is not vacuous: a
// debian/rules that installs the WRONG source under the correct staged basename
// (the #1999 hazard) must be flagged, even though the destination-basename set
// still equals manifest.Names().
func TestStagedSrcCounterfactual(t *testing.T) {
	// Pairs derived faithfully from the manifest must pass.
	good := map[string]string{}
	for _, b := range All() {
		good[b.Name] = b.StagedSrc
	}
	if msgs := stagedSrcMismatches(good); len(msgs) != 0 {
		t.Fatalf("manifest-derived install pairs should pass, got: %v", msgs)
	}

	// Swap one source to a wrong path while keeping the destination basename —
	// exactly the failure mode #1999 guards against.
	bad := map[string]string{}
	for k, v := range good {
		bad[k] = v
	}
	const victim = "xpf-day0-config"
	if _, ok := bad[victim]; !ok {
		t.Fatalf("manifest missing %q; update this counterfactual", victim)
	}
	bad[victim] = "scripts/image/old-" + victim
	msgs := stagedSrcMismatches(bad)
	if len(msgs) == 0 {
		t.Fatal("a wrong source under the correct basename must be flagged")
	}
	found := false
	for _, m := range msgs {
		if strings.Contains(m, victim) && strings.Contains(m, "old-"+victim) {
			found = true
		}
	}
	if !found {
		t.Fatalf("mismatch message should name the wrong source, got: %v", msgs)
	}

	// A missing install line for a managed binary is also flagged.
	delete(bad, victim)
	if msgs := stagedSrcMismatches(bad); len(msgs) == 0 {
		t.Fatal("a managed binary with no debian/rules install line must be flagged")
	}

	// Parse-path counterfactual (AGY review): exercise the actual text parser
	// (extractRulesInstallPairs) on a synthetic debian/rules whose recipe
	// installs a WRONG source under a correct managed basename, so the full
	// parse->compare path is covered — the map-only checks above don't run the
	// regex / line-continuation join.
	const wrongRules = "override_dh_auto_install:\n" +
		"\tinstall -d debian/xpf$(STAGED)\n" +
		"\tinstall -m 0755 wrong/path/xpfd debian/xpf$(STAGED)/xpfd\n" +
		"\tinstall -m 0755 cli              debian/xpf$(STAGED)/cli\n" +
		"\tinstall -m 0755 xpf-userspace-dp debian/xpf$(STAGED)/xpf-userspace-dp\n" +
		"\tinstall -m 0755 scripts/image/xpf-day0-config \\\n" +
		"\t                                 debian/xpf$(STAGED)/xpf-day0-config\n" +
		"\n" +
		"override_dh_auto_test:\n"
	parsed := extractRulesInstallPairs(t, wrongRules)
	if parsed["xpfd"] != "wrong/path/xpfd" {
		t.Fatalf("parser should capture the wrong source, got %q", parsed["xpfd"])
	}
	// The wrapped (line-continued) xpf-day0-config install must still parse to
	// its source — confirms the `\`-join handles the real recipe shape.
	if parsed["xpf-day0-config"] != "scripts/image/xpf-day0-config" {
		t.Fatalf("wrapped install should parse to its source, got %q", parsed["xpf-day0-config"])
	}
	foundWrong := false
	for _, m := range stagedSrcMismatches(parsed) {
		if strings.Contains(m, "xpfd") && strings.Contains(m, "wrong/path/xpfd") {
			foundWrong = true
		}
	}
	if !foundWrong {
		t.Fatal("the parse->compare path must flag the wrong xpfd source in debian/rules text")
	}
}

// TestManifestShape locks the manifest's basic invariants so a careless edit
// (empty list, duplicate name, blank field) is caught at the SSOT itself.
func TestManifestShape(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("manifest is empty")
	}
	seen := map[string]bool{}
	for i, b := range all {
		if b.Name == "" {
			t.Errorf("managed[%d] has empty Name", i)
		}
		if b.StagedSrc == "" {
			t.Errorf("managed[%d] (%s) has empty StagedSrc", i, b.Name)
		}
		if seen[b.Name] {
			t.Errorf("managed[%d] duplicate Name %q", i, b.Name)
		}
		seen[b.Name] = true
	}
	if all[0].Name != "xpfd" {
		t.Errorf("manifest[0].Name=%q, want \"xpfd\" (callers rely on the daemon "+
			"being first)", all[0].Name)
	}
	// All() must return a defensive copy: mutating it must not change the SSOT.
	all[0].Name = "MUTATED"
	if All()[0].Name != "xpfd" {
		t.Error("All() does not return a defensive copy — mutating the result " +
			"changed the source of truth")
	}
	if got, want := ShellBINS(), strings.Join(Names(), " "); got != want {
		t.Errorf("ShellBINS()=%q, want %q", got, want)
	}
}

// TestLockstepNames locks the lockstep subset the cut's pre-start
// completeness check (pkg/upgrade.versionDirComplete) derives from the
// manifest. The set must be exactly the daemon + the dataplane helper; a
// regression that flips a LockstepCut flag would change which binaries the
// cut requires present before StartUnit.
func TestLockstepNames(t *testing.T) {
	got := LockstepNames()
	want := []string{"xpfd", "xpf-userspace-dp"}
	if !sortedEqual(got, want) {
		t.Errorf("LockstepNames()=%q, want %q (xpfd + xpf-userspace-dp are the "+
			"version-locked dataplane set)", got, want)
	}
	// Every lockstep name must also be a managed name (a lockstep binary that
	// is not in the managed set would never be staged/copied).
	managed := map[string]bool{}
	for _, n := range Names() {
		managed[n] = true
	}
	for _, n := range got {
		if !managed[n] {
			t.Errorf("LockstepNames() returned %q which is not in Names()", n)
		}
	}
}
