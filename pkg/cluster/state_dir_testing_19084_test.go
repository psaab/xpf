package cluster

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestStateDirForTestingCoversEveryStatePath19084 pins SetStateDirForTesting
// to the package's real set of /var/lib/xpf paths: every non-test source file
// is scanned for a "/var/lib/xpf/..." string literal assigned at package level,
// and each such path must be one the hook redirects. A new state file added
// without extending the hook would otherwise land in the host's /var/lib/xpf
// from another package's root-leg tests (#19084).
func TestStateDirForTestingCoversEveryStatePath19084(t *testing.T) {
	dir := t.TempDir()
	restore := SetStateDirForTesting(dir)
	redirected := map[string]bool{}
	for _, p := range []string{bootEpochPath, peerEpochStatePath, fabricAuthGraceStatePath, unkeyedAuthorityGraceStatePath} {
		if !strings.HasPrefix(p, dir+string(os.PathSeparator)) {
			t.Errorf("state path %q is not under the test state dir %q", p, dir)
		}
		redirected[filepath.Base(p)] = true
	}
	restore()
	if bootEpochPath != "/var/lib/xpf/ha-boot-epoch" {
		t.Errorf("restore left bootEpochPath = %q", bootEpochPath)
	}

	lit := regexp.MustCompile(`(?m)^(?:var\s+)?\s*\w+\s*=\s*"(/var/lib/xpf/[^"]+)"`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range lit.FindAllStringSubmatch(string(src), -1) {
			found++
			if !redirected[filepath.Base(m[1])] {
				t.Errorf("%s: state path %s is not redirected by SetStateDirForTesting", f, m[1])
			}
		}
	}
	// Positive control: the scan must see the four paths the hook covers.
	if found < len(redirected) {
		t.Fatalf("scan found %d /var/lib/xpf path literals, want at least %d; the scan rotted", found, len(redirected))
	}
}
