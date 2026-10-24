package docsref

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// #16466: CLAUDE.md (agent contract) and docs/feature-coverage.md (operator
// matrix) cited pkg/config/compiler_system.go:3132-3137 and
// pkg/cluster/heartbeat.go:61-65,1916-1960 for the HA-timing claims, but
// compiler_system.go now ends before 3132 (the logic moved to compileChassis
// in compiler_chassis.go) and heartbeat.go ends before 1916. The stale ranges
// were replaced with symbol citations. This gate resolves every
// `path:N[-M(,N-M)*]` citation to a .go file in those two live docs and
// fails if the file is missing or any range runs past its end, so the next
// file split cannot silently re-rot the evidence. Scoped to the two docs the
// finding names: the repo at large carries many historical citations
// (docs/log/*, docs/issues/*-history.md, archived reviews) that quote what
// was true at the time and are not live pointers.
//
// FAIL-ON-REVERT: restore `pkg/cluster/heartbeat.go:1916-1960` (or any
// out-of-range / missing-file .go citation) in CLAUDE.md or
// docs/feature-coverage.md and this test fails.
var sourceLineCitationRe16466 = regexp.MustCompile("`((?:pkg|docs)/[^`\\s:]+\\.go):([0-9][0-9, \\-]*)`")

var sourceLineDocs16466 = []string{"CLAUDE.md", "docs/feature-coverage.md"}

func TestSourceLineCitationsResolve16466(t *testing.T) {
	root := repoRoot(t)
	total := 0
	lineCounts := map[string]int{}
	for _, doc := range sourceLineDocs16466 {
		b, err := os.ReadFile(filepath.Join(root, doc))
		if err != nil {
			t.Fatalf("read %s: %v", doc, err)
		}
		for _, m := range sourceLineCitationRe16466.FindAllStringSubmatch(string(b), -1) {
			file, ranges := m[1], m[2]
			n, ok := lineCounts[file]
			if !ok {
				cb, err := os.ReadFile(filepath.Join(root, file))
				if err != nil {
					t.Errorf("#16466: %s cites missing file %s", doc, file)
					continue
				}
				n = strings.Count(string(cb), "\n")
				lineCounts[file] = n
			}
			for _, part := range strings.Split(ranges, ",") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				hi := part
				if i := strings.Index(part, "-"); i >= 0 {
					hi = part[i+1:]
				}
				end, err := strconv.Atoi(strings.TrimSpace(hi))
				if err != nil {
					t.Errorf("#16466: %s: unparseable citation %s:%s", doc, file, part)
					continue
				}
				total++
				if end > n {
					t.Errorf("#16466: %s cites %s:%s but %s has only %d lines — cite the symbol instead of a line range, or re-point the range", doc, file, part, file, n)
				}
			}
		}
	}
	if total == 0 {
		t.Fatal("#16466: no .go line citations found in CLAUDE.md / docs/feature-coverage.md — the sweep has rotted and this gate is vacuous")
	}
	// The docs must also carry the symbol citations this fix landed, and
	// none of the stale paths the finding named.
	for _, doc := range sourceLineDocs16466 {
		b, err := os.ReadFile(filepath.Join(root, doc))
		if err != nil {
			t.Fatalf("read %s: %v", doc, err)
		}
		s := string(b)
		for _, stale := range []string{"compiler_system.go:3132", "compiler_system.go:3119", "heartbeat.go:1916"} {
			if strings.Contains(s, stale) {
				t.Errorf("#16466: %s still contains stale citation %q", doc, stale)
			}
		}
		for _, sym := range []string{"compileChassis", "compiler_chassis.go", "DefaultHeartbeatInterval", "checkTimeout"} {
			if !strings.Contains(s, sym) {
				t.Errorf("#16466: %s lost symbol citation %q — the HA-timing evidence must name the symbol, not a bare line range", doc, sym)
			}
		}
	}
}
