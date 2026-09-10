package refactoraudit

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// #9506: #8276 ("price the bounded kernel->userspace capture bridge for
// XFRM-decrypted IPsec plaintext (B2)") closed COMPLETED on the pricing alone —
// PR #8604 "lands no production code" — and its umbrella #7167 closed
// NOT_PLANNED. Three in-source statements kept naming #8276 as the owner of the
// route-based IPsec ingress gap in the present tense ("#8276 owns that half",
// "tracked as #8274 / #8276", "Closing the gap itself is ... #8276"). A reader
// who followed one landed on a closed issue and could conclude someone was on
// it. #9506 is the open owner.
//
// Whether an issue is OPEN is tracker state a test cannot read, so this does not
// police owner references in general. It pins the one measured instance: #8276
// may appear only where it is HISTORY, and the sites that name the owner name
// #9506.

var (
	// Built from pieces so this file's own code does not match itself; the
	// doc comments above do, which is why the census skips this file by path.
	closedOwnerRef8276 = regexp.MustCompile(`#` + `8276(?:\D|$)`)
	liveOwnerRef9506   = regexp.MustCompile(`#` + `9506(?:\D|$)`)
)

const closedOwnerCensusSelf9506 = "pkg/refactoraudit/closed_owner_8276_9506_test.go"

// closedOwnerHistorical8276 lists the files where #8276 is provenance, not a
// claim that it owns anything, with the reason.
var closedOwnerHistorical8276 = map[string]string{
	"docs/research/7167-tunnel-ingress/adjudication.md": "records #8276's B2 pricing as the source of a hardware-gated item",
	"userspace-dp/benches/b2_capture_bridge.rs":         "is the pricing microbench #8276 produced",
}

// liveOwnerSites9506 are the statements of who owns closing the IPsec ingress
// gap. Each must name #9506.
var liveOwnerSites9506 = []string{
	"docs/userspace-dataplane-gaps.md",
	"pkg/config/compiler_ipsec_plaintext_warn.go",
	"pkg/dataplane/README.md",
	"pkg/dataplane/compiler_iface.go",
}

type censusFile9506 struct {
	path    string
	content []byte
}

// censusCovered9506 is the population: source and prose, minus the history
// directories, whose job is to remember what used to be true.
func censusCovered9506(path string) bool {
	for _, prefix := range []string{"docs/log/", "docs/issues/", "docs/reviews/"} {
		if strings.HasPrefix(path, prefix) {
			return false
		}
	}
	if path == "_Log.md" {
		return false
	}
	switch filepath.Ext(path) {
	case ".go", ".rs", ".md", ".sh", ".py":
		return true
	}
	return false
}

// closedOwnerCensus8276 returns one violation per line naming #8276 outside the
// historical allowlist, and how many #8276 lines each allowlisted file carries —
// the positive control's input, so a census that sees nothing cannot pass.
func closedOwnerCensus8276(files []censusFile9506, self string) (violations []string, historicalHits map[string]int) {
	historicalHits = map[string]int{}
	for _, f := range files {
		if f.path == self || !censusCovered9506(f.path) || !closedOwnerRef8276.Match(f.content) {
			continue
		}
		for i, line := range strings.Split(string(f.content), "\n") {
			if !closedOwnerRef8276.MatchString(line) {
				continue
			}
			if _, historical := closedOwnerHistorical8276[f.path]; historical {
				historicalHits[f.path]++
				continue
			}
			violations = append(violations, f.path+":"+itoa(i+1)+": "+truncate(strings.TrimSpace(line), 160))
		}
	}
	sort.Strings(violations)
	return violations, historicalHits
}

// TestClosedOwnerCensusFlagsAStaleOwnerClaim9506 drives the census function on
// a fixture, so the check itself is exercisable: with the repository clean, a
// census whose check had been disabled would pass the repository cell below.
func TestClosedOwnerCensusFlagsAStaleOwnerClaim9506(t *testing.T) {
	ref := "#" + "8276"
	files := []censusFile9506{
		{"pkg/x/stale.go", []byte("package x\n// the IPsec half is owned by " + ref + "\n")},
		{"docs/research/7167-tunnel-ingress/adjudication.md", []byte("from " + ref + "'s B2 pricing\n")},
		{"docs/log/8276.md", []byte(ref + " history\n")},
		{"docs/pr/x/evidence.json", []byte(`"issue": "` + ref + `"` + "\n")},
		{"pkg/y/near_miss.go", []byte("// " + ref + "0 is a different issue\n")},
		{"self_test.go", []byte("// " + ref + "\n")},
	}
	violations, hits := closedOwnerCensus8276(files, "self_test.go")
	want := []string{"pkg/x/stale.go:2: // the IPsec half is owned by " + ref}
	if strings.Join(violations, "\n") != strings.Join(want, "\n") {
		t.Errorf("census violations = %q, want %q. It must flag a present-tense owner "+
			"claim in source, and ignore the allowlisted history, docs/log, a non-covered "+
			"extension, a longer issue number and itself", violations, want)
	}
	if hits["docs/research/7167-tunnel-ingress/adjudication.md"] != 1 {
		t.Errorf("the allowlisted historical site must be COUNTED, not just skipped (got %d)",
			hits["docs/research/7167-tunnel-ingress/adjudication.md"])
	}
}

// TestClosedIssue8276IsNotNamedAsTheIPsecOwner9506 runs the census over the
// repository.
func TestClosedIssue8276IsNotNamedAsTheIPsecOwner9506(t *testing.T) {
	root := repoRoot(t)
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Skipf("git ls-files unavailable (%v); the census needs a git checkout", err)
	}
	seen := map[string]bool{}
	var files []censusFile9506
	for _, raw := range bytes.Split(out, []byte{0}) {
		path := string(raw)
		if path == "" || seen[path] || !censusCovered9506(path) {
			continue
		}
		seen[path] = true
		content, readErr := os.ReadFile(filepath.Join(root, path))
		if readErr != nil {
			if os.IsNotExist(readErr) {
				continue // deleted in the working tree, still in the index
			}
			t.Fatalf("read %s: %v", path, readErr)
		}
		files = append(files, censusFile9506{path: path, content: content})
	}
	if len(files) < 1000 {
		t.Fatalf("the census read only %d covered files; it did not run over the repository", len(files))
	}

	violations, hits := closedOwnerCensus8276(files, closedOwnerCensusSelf9506)
	for _, v := range violations {
		t.Errorf("%s\n\tnames #8276, which closed COMPLETED on the B2 pricing alone and owns "+
			"nothing. The route-based IPsec ingress gap's open owner is #9506; if this line "+
			"is history rather than an owner claim, move it to a history directory or add "+
			"the file to closedOwnerHistorical8276 with the reason.", v)
	}
	for path, why := range closedOwnerHistorical8276 {
		if hits[path] == 0 {
			t.Errorf("positive control: %s %s, and the census did not find #8276 there. "+
				"Either it was reworded (update the allowlist) or the census is blind to it — "+
				"and then a zero-violation result above means nothing.", path, why)
		}
	}
	byPath := map[string][]byte{}
	for _, f := range files {
		byPath[f.path] = f.content
	}
	for _, site := range liveOwnerSites9506 {
		content, ok := byPath[site]
		if !ok {
			t.Errorf("owner site %s was not read by the census", site)
			continue
		}
		if !liveOwnerRef9506.Match(content) {
			t.Errorf("%s states who owns closing the route-based IPsec ingress gap and does "+
				"not name #9506, the open owner", site)
		}
	}
}
