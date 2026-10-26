package refactoraudit

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var afxdpReadmeFileRow = regexp.MustCompile("^\\s*\\|\\s*`([^`]+\\.rs)`\\s*\\|")

func TestAfxdpReadmeFileTableParity17019(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range []string{
		"userspace-dp/src/afxdp/worker",
		"userspace-dp/src/afxdp/types",
	} {
		t.Run(filepath.Base(rel), func(t *testing.T) {
			checkAfxdpReadmeFileTableParity(t, root, rel)
		})
	}
}

func checkAfxdpReadmeFileTableParity(t *testing.T, root, rel string) {
	t.Helper()
	base := filepath.Join(root, rel)
	readme, err := os.ReadFile(filepath.Join(base, "README.md"))
	if err != nil {
		t.Fatalf("read %s/README.md: %v", rel, err)
	}

	inFilesSection := false
	sawFilesSection := false
	rows := make(map[string]int)
	for _, line := range strings.Split(string(readme), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "## Files" {
			inFilesSection = true
			sawFilesSection = true
			continue
		}
		if inFilesSection && strings.HasPrefix(trimmed, "## ") {
			break
		}
		if !inFilesSection {
			continue
		}
		match := afxdpReadmeFileRow.FindStringSubmatch(line)
		if len(match) == 2 {
			rows[filepath.ToSlash(match[1])]++
		}
	}
	if !sawFilesSection {
		t.Fatalf("%s/README.md has no ## Files section", rel)
	}

	production := make(map[string]struct{})
	err = filepath.WalkDir(base, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !entry.Type().IsRegular() || filepath.Ext(entry.Name()) != ".rs" || isAfxdpRustTestFile(entry.Name()) {
			return nil
		}
		relPath, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		production[filepath.ToSlash(relPath)] = struct{}{}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", rel, err)
	}

	var missing, stale, duplicates []string
	for path := range production {
		if rows[path] == 0 {
			missing = append(missing, path)
		}
	}
	for path, count := range rows {
		if _, ok := production[path]; !ok {
			stale = append(stale, path)
		}
		if count > 1 {
			duplicates = append(duplicates, path)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	sort.Strings(duplicates)
	if len(missing) != 0 || len(stale) != 0 || len(duplicates) != 0 {
		t.Errorf("%s README file-table parity: missing rows=%v, stale rows=%v, duplicate rows=%v", rel, missing, stale, duplicates)
		return
	}
	t.Logf("README file-table parity: %d production files matched exactly once", len(production))
}

func isAfxdpRustTestFile(name string) bool {
	return name == "tests.rs" || strings.HasSuffix(name, "_tests.rs") || strings.HasPrefix(name, "tests_") || strings.HasPrefix(name, "test_")
}
