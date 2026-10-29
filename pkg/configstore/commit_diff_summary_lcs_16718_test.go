package configstore

import (
	"fmt"
	"math/rand/v2"
	"runtime"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// referenceLCSCounts16718 is the naive full-table LCS used only as a
// test oracle on small inputs.
func referenceLCSCounts16718(oldLines, newLines []string) (added, removed int) {
	lo, ln := len(oldLines), len(newLines)
	if lo == 0 {
		return ln, 0
	}
	if ln == 0 {
		return 0, lo
	}
	dp := make([][]int, lo+1)
	for i := range dp {
		dp[i] = make([]int, ln+1)
	}
	for i := lo - 1; i >= 0; i-- {
		for j := ln - 1; j >= 0; j-- {
			if oldLines[i] == newLines[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	lcs := dp[0][0]
	return ln - lcs, lo - lcs
}

func TestSequenceLineDiffCounts16718MatchesReference(t *testing.T) {
	cases := []struct {
		name string
		old  []string
		new  []string
	}{
		{"empty both", nil, nil},
		{"empty old", nil, []string{"a", "b"}},
		{"empty new", []string{"a"}, nil},
		{"identical", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"one edit middle", []string{"a", "b", "c"}, []string{"a", "x", "c"}},
		{"prefix only", []string{"a", "b"}, []string{"x", "a", "b"}},
		{"suffix only", []string{"a", "b"}, []string{"a", "b", "x"}},
		{"reorder", []string{"deny", "allow"}, []string{"allow", "deny"}},
		{"duplicates add", []string{"a"}, []string{"a", "a"}},
		{"duplicates remove", []string{"a", "a", "a"}, []string{"a"}},
		{"duplicates reorder", []string{"a", "b", "a"}, []string{"a", "a", "b"}},
		{"all replaced", []string{"a", "b"}, []string{"x", "y", "z"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantA, wantR := referenceLCSCounts16718(tc.old, tc.new)
			gotA, gotR := sequenceLineDiffCounts(tc.old, tc.new)
			if gotA != wantA || gotR != wantR {
				t.Fatalf("sequenceLineDiffCounts(%v,%v) = (%d,%d), want (%d,%d)",
					tc.old, tc.new, gotA, gotR, wantA, wantR)
			}
		})
	}

	// Deterministic random small cases over a tiny alphabet (heavy
	// duplicates) must match the full-table oracle exactly.
	rng := rand.New(rand.NewPCG(16718, 1))
	alphabet := []string{"a", "b", "c", "d"}
	for iter := range 200 {
		mk := func() []string {
			n := rng.IntN(13)
			out := make([]string, n)
			for i := range out {
				out[i] = alphabet[rng.IntN(len(alphabet))]
			}
			return out
		}
		oldLines, newLines := mk(), mk()
		wantA, wantR := referenceLCSCounts16718(oldLines, newLines)
		gotA, gotR := sequenceLineDiffCounts(oldLines, newLines)
		if gotA != wantA || gotR != wantR {
			t.Fatalf("iter %d: (%v,%v) = (%d,%d), want (%d,%d)",
				iter, oldLines, newLines, gotA, gotR, wantA, wantR)
		}
	}
}

func makeLines16718(n int) []string {
	lines := make([]string, n)
	for i := range lines {
		lines[i] = fmt.Sprintf("set security address-book global address addr-%d 10.0.%d.%d", i, i/256%256, i%256)
	}
	return lines
}

func allocFor16718(t *testing.T, fn func()) uint64 {
	t.Helper()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// TestSequenceLineDiffCounts16718LargeOneLineEdit is the #16718
// acceptance: a 50k-line config with a one-line edit must compute in
// under 10 MiB. The old full-table implementation needed
// (50001)^2*8 ~= 20 GB here.
func TestSequenceLineDiffCounts16718LargeOneLineEdit(t *testing.T) {
	oldLines := makeLines16718(50000)
	newLines := make([]string, len(oldLines))
	copy(newLines, oldLines)
	newLines[25000] = "set system host-name changed"

	var added, removed int
	alloc := allocFor16718(t, func() {
		added, removed = sequenceLineDiffCounts(oldLines, newLines)
	})
	if added != 1 || removed != 1 {
		t.Fatalf("50k one-line edit = (%d added, %d removed), want (1,1)", added, removed)
	}
	const limit = 10 << 20
	if alloc >= limit {
		t.Fatalf("50k one-line edit allocated %d bytes, want < %d", alloc, limit)
	}
	t.Logf("50k one-line edit alloc = %d bytes", alloc)
}

// A large identical input must be free (common prefix consumes it).
func TestSequenceLineDiffCounts16718IdenticalLarge(t *testing.T) {
	lines := makeLines16718(50000)
	alloc := allocFor16718(t, func() {
		added, removed := sequenceLineDiffCounts(lines, lines)
		if added != 0 || removed != 0 {
			t.Fatalf("identical = (%d,%d), want (0,0)", added, removed)
		}
	})
	if alloc >= 1<<20 {
		t.Fatalf("identical 50k allocated %d bytes, want < 1MiB", alloc)
	}
}

// Above maxExactLCSCells the documented fallback is multiset counts:
// multiplicities are preserved, order sensitivity is not.
func TestSequenceLineDiffCounts16718OversizedFallback(t *testing.T) {
	n := 3000 // 3000*3000 > maxExactLCSCells
	oldLines := makeLines16718(n)
	// Pure reorder of the whole (oversized) middle.
	newLines := make([]string, n)
	for i, line := range oldLines {
		newLines[n-1-i] = line
	}
	if added, removed := sequenceLineDiffCounts(oldLines, newLines); added != 0 || removed != 0 {
		t.Fatalf("oversized pure reorder fallback = (%d,%d), want (0,0) multiset", added, removed)
	}
	// One line changed in the oversized middle still counts 1/1.
	newLines[1500] = "set system host-name changed"
	if added, removed := sequenceLineDiffCounts(oldLines, newLines); added != 1 || removed != 1 {
		t.Fatalf("oversized one-line edit fallback = (%d,%d), want (1,1)", added, removed)
	}
	// Direct multiset duplicate check.
	if added, removed := multisetLineDiffCounts(
		[]string{"a", "a", "b"}, []string{"a", "b", "b", "c"}); added != 2 || removed != 1 {
		t.Fatalf("multiset = (%d,%d), want (2,1)", added, removed)
	}
}

// End-to-end: CommitDiffSummary on a large config with a one-line edit.
func TestCommitDiffSummary16718LargeConfig(t *testing.T) {
	const n = 12000
	build := func(changed bool) *config.ConfigTree {
		children := make([]*config.Node, 0, n)
		for i := range n {
			name := fmt.Sprintf("addr-%d", i)
			if changed && i == n/2 {
				name = "addr-changed"
			}
			children = append(children, &config.Node{
				Keys:   []string{"address", name},
				IsLeaf: true,
			})
		}
		return &config.ConfigTree{Children: []*config.Node{
			{Keys: []string{"security"}, Children: children},
		}}
	}
	s := newTestStore(t)
	s.active = build(false)
	s.candidate = build(true)
	var got string
	alloc := allocFor16718(t, func() {
		got = s.CommitDiffSummary()
	})
	if want := "2 statement(s) changed (1 added, 1 removed)"; got != want {
		t.Fatalf("CommitDiffSummary large = %q, want %q", got, want)
	}
	// #16718's historical end-to-end 12k bound remains unchanged; #17773
	// adds the stricter 50k <10 MiB acceptance below.
	if alloc >= 64<<20 {
		t.Fatalf("CommitDiffSummary 12k allocated %d bytes, want < 64MiB", alloc)
	}
	t.Logf("CommitDiffSummary 12k alloc = %d bytes", alloc)
}

// TestCommitDiffSummary17773EndToEnd50K is the #17773 acceptance: the
// REAL CommitDiffSummary over a 50k-line config with a one-line edit
// (not just the sequenceLineDiffCounts helper over pre-made strings)
// must stay under 10 MiB and return (1,1). The 12k control keeps the
// old pre-LCS table scale visible; identical trees must be (0,0).
func TestCommitDiffSummary17773EndToEnd50K(t *testing.T) {
	build := func(n int, changed bool) *config.ConfigTree {
		children := make([]*config.Node, 0, n)
		for i := range n {
			name := fmt.Sprintf("addr-%d", i)
			if changed && i == n/2 {
				name = "addr-changed"
			}
			children = append(children, &config.Node{
				Keys:   []string{"address", name, fmt.Sprintf("10.0.%d.%d", i/256%256, i%256)},
				IsLeaf: true,
			})
		}
		return &config.ConfigTree{Children: []*config.Node{
			{Keys: []string{"security", "address-book", "global"}, Children: children},
		}}
	}

	s := newTestStore(t)
	s.active = build(50000, false)
	s.candidate = build(50000, true)
	var got string
	alloc := allocFor16718(t, func() {
		got = s.CommitDiffSummary()
	})
	if want := "2 statement(s) changed (1 added, 1 removed)"; got != want {
		t.Fatalf("CommitDiffSummary 50k = %q, want %q", got, want)
	}
	const limit = 10 << 20
	if alloc >= limit {
		t.Fatalf("CommitDiffSummary 50k allocated %d bytes, want < %d", alloc, limit)
	}
	t.Logf("CommitDiffSummary 50k alloc = %d bytes", alloc)

	// Identical control: same trees, no edit.
	s.candidate = build(50000, false)
	allocIdent := allocFor16718(t, func() {
		got = s.CommitDiffSummary()
	})
	if got != "" {
		t.Fatalf("CommitDiffSummary identical 50k = %q, want empty", got)
	}
	if allocIdent >= limit {
		t.Fatalf("CommitDiffSummary identical 50k allocated %d bytes, want < %d", allocIdent, limit)
	}
	t.Logf("CommitDiffSummary identical 50k alloc = %d bytes", allocIdent)

	// 12k control at the same bound (not the old 64 MiB).
	s.active = build(12000, false)
	s.candidate = build(12000, true)
	alloc12k := allocFor16718(t, func() {
		got = s.CommitDiffSummary()
	})
	if want := "2 statement(s) changed (1 added, 1 removed)"; got != want {
		t.Fatalf("CommitDiffSummary 12k = %q, want %q", got, want)
	}
	if alloc12k >= limit {
		t.Fatalf("CommitDiffSummary 12k allocated %d bytes, want < %d", alloc12k, limit)
	}
	t.Logf("CommitDiffSummary 12k alloc = %d bytes", alloc12k)
}

func TestFormatSetLines17773MatchesFormatSet(t *testing.T) {
	tree := &config.ConfigTree{Children: []*config.Node{
		{Keys: []string{"policy-options"}, Children: []*config.Node{
			{Keys: []string{"policy-statement", "P"}, Children: []*config.Node{
				{Keys: []string{"then", "reject"}, IsLeaf: true},
				{Keys: []string{"from", "protocol", "bgp"}, IsLeaf: true},
			}},
		}},
		{Keys: []string{"system"}, Children: []*config.Node{
			{Keys: []string{"host-name", `café "router`}, KeysQuoted: []bool{false, true}, IsLeaf: true},
		}, Annotation: `owner "ops" café\nbackup`, Inactive: true},
		{Keys: []string{"security-zone", "trusted"}, KeysBracketed: []bool{true, true}, Children: []*config.Node{
			{Keys: []string{"interfaces"}, Children: []*config.Node{
				{Keys: []string{"ge-0/0/0.0"}, IsLeaf: true},
			}},
		}},
	}}
	want := splitLines(tree.FormatSet())
	got := tree.FormatSetLines(nil)
	if len(got) != len(want) {
		t.Fatalf("FormatSetLines returned %d lines, FormatSet has %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("FormatSetLines line %d = %q, want %q", i, got[i], want[i])
		}
	}
	reused := tree.FormatSetLines(got)
	for i := range got {
		if reused[i] != got[i] {
			t.Fatalf("FormatSetLines reuse line %d = %q, want %q", i, reused[i], got[i])
		}
	}
}
