package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestStripSurroundingQuotes pins the matched-pair rule now shared by the pcap
// filter, the commit comment and the annotate comment (#7171).
//
// The commit and annotate paths used strings.Trim with a quote CUTSET, which
// matches every leading and trailing byte in the set whether or not it is
// balanced. The consequence landed in the AUDIT JOURNAL: a comment ending in a
// legitimate apostrophe was recorded without it. A journal that silently
// mutates what the operator typed is weaker evidence than one that does not.
// The #4005 cases below moved here with the helper (from
// monitor_traffic_filter_4005_test.go) and are preserved verbatim: a helper
// that moves must take its regression test with it, or the test keeps passing
// while guarding nothing the code still uses.
func TestStripSurroundingQuotes(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// The real need: peel syntactic quotes the tokenizer left behind.
		{`"quoted"`, `quoted`},
		{`'quoted'`, `quoted`},

		// THE DEFECT. A trailing apostrophe is content, not syntax. Under the
		// old cutset Trim this returned `users`.
		{`users'`, `users'`},
		{`fix for users'`, `fix for users'`},
		{`it's`, `it's`},

		// A mismatched pair is not a pair. This is the case that stops a
		// "strip one from each end whenever both look like quotes"
		// implementation from passing the two above.
		{`'mixed"`, `'mixed"`},
		{`"mixed'`, `"mixed'`},

		// Exactly ONE layer. The cutset form collapsed all of them.
		{`""text""`, `"text"`},
		{`''text''`, `'text'`},

		// Unterminated: kept verbatim, deliberately. Guessing the operator
		// meant to close the quote is the behaviour being removed.
		{`"unterminated`, `"unterminated`},
		{`unterminated"`, `unterminated"`},

		// Leading/trailing quotes that are not surrounding must survive.
		{`say "hi" now`, `say "hi" now`},

		// Preserved verbatim from the #4005 pcap-filter cases.
		{`"tcp port 80"`, `tcp port 80`},
		{`'udp or tcp'`, `udp or tcp`},
		{`icmp`, `icmp`},
		{`tcp port 80`, `tcp port 80`},
		{`"unbalanced`, `"unbalanced`},
		{`mismatched"`, `mismatched"`},

		// Degenerate inputs.
		{``, ``},
		{`"`, `"`},
		{`'`, `'`},
		{`""`, ``},
		{`no quotes here`, `no quotes here`},
	} {
		t.Run(tc.in, func(t *testing.T) {
			if got := stripSurroundingQuotes(tc.in); got != tc.want {
				t.Errorf("stripSurroundingQuotes(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestCommentSitesStripMatchedPairsOnly binds the CALL SITES, not the helper.
//
// The first version of this change asserted the helper twice and called it an
// anti-drift cell. It was not: reverting BOTH call sites to strings.Trim with a
// quote cutset produced zero failures across 968 tests, because a test that
// calls stripSurroundingQuotes directly never reaches the site that calls it.
// Both sites are now named units so a revert is visible, and these are the
// inputs that discriminate the cutset from the matched pair.
func TestCommentSitesStripMatchedPairsOnly(t *testing.T) {
	t.Run("commit comment keeps a trailing apostrophe", func(t *testing.T) {
		// argv as the CLI tokenizer hands it over, i.e. already split.
		got := commitCommentFromArgs([]string{"fix", "for", "users'"})
		if got != "fix for users'" {
			t.Errorf("commit comment = %q, want %q -- this value is persisted to the audit journal", got, "fix for users'")
		}
	})
	t.Run("commit comment still peels syntactic quotes", func(t *testing.T) {
		if got := commitCommentFromArgs([]string{`"tidy`, `up"`}); got != "tidy up" {
			t.Errorf("commit comment = %q, want %q", got, "tidy up")
		}
	})
	t.Run("commit comment keeps a mismatched pair", func(t *testing.T) {
		if got := commitCommentFromArgs([]string{`'mixed"`}); got != `'mixed"` {
			t.Errorf("commit comment = %q, want it unchanged", got)
		}
	})

	t.Run("annotate keeps a trailing apostrophe inside the quotes", func(t *testing.T) {
		path, comment, ok := annotateCommentFromLine(`system host-name "belongs to users'"`)
		if !ok {
			t.Fatal("annotateCommentFromLine reported no comment")
		}
		if path != "system host-name" {
			t.Errorf("path = %q, want %q", path, "system host-name")
		}
		if comment != "belongs to users'" {
			t.Errorf("comment = %q, want %q -- this value is persisted into the config", comment, "belongs to users'")
		}
	})
	t.Run("annotate keeps an unterminated leading quote", func(t *testing.T) {
		_, comment, ok := annotateCommentFromLine(`system host-name "unterminated`)
		if !ok {
			t.Fatal("annotateCommentFromLine reported no comment")
		}
		if comment != `"unterminated` {
			t.Errorf("comment = %q, want it unchanged", comment)
		}
	})
	t.Run("annotate reports absence of a quoted comment", func(t *testing.T) {
		if _, _, ok := annotateCommentFromLine("system host-name no-quotes"); ok {
			t.Error("annotateCommentFromLine accepted a line with no quoted comment")
		}
	})
}

// TestCommitCommentReachesJournalVerbatim binds the whole chain through the
// REAL entry point and asserts the property that actually matters: what lands
// in the audit journal.
//
// Two earlier attempts at this guard escaped their own mutation. The first
// asserted stripSurroundingQuotes twice and called it an anti-drift cell;
// reverting both call sites to strings.Trim produced zero failures across 968
// tests. The second extracted commitCommentFromArgs and asserted THAT --
// and reverting the call site to bypass it still produced zero failures,
// because a test of the extracted function does not bind the site's USE of it.
// Only entering through handleCommit and reading the persisted JournalEntry
// closes that gap.
func TestCommitCommentReachesJournalVerbatim(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
		want string
	}{
		// THE DEFECT: a trailing apostrophe is content. Under the old cutset
		// Trim the journal recorded "fix for users".
		{"trailing apostrophe", []string{"comment", "fix", "for", "users'"}, "fix for users'"},
		// The real need this serves: syntactic quotes are still peeled.
		{"syntactic quotes peeled", []string{"comment", `"tidy`, `up"`}, "tidy up"},
		// A mismatched pair is not a pair.
		{"mismatched pair kept", []string{"comment", `'mixed"`}, `'mixed"`},
		// Exactly one layer, not all of them.
		{"one layer only", []string{"comment", `""quoted""`}, `"quoted"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
			if err := store.EnterConfigure(); err != nil {
				t.Fatal(err)
			}
			c := &CLI{store: store}
			if _, err := store.LoadSet("set system host-name Probe"); err != nil {
				t.Fatal(err)
			}
			if err := c.handleCommit(tc.argv); err != nil {
				t.Fatalf("handleCommit(%q): %v", tc.argv, err)
			}
			entries, err := store.ListCommitHistory(10)
			if err != nil {
				t.Fatalf("ListCommitHistory: %v", err)
			}
			var got string
			var found bool
			for _, e := range entries {
				if e.Action == "commit" {
					got, found = e.Detail, true
					break
				}
			}
			if !found {
				t.Fatalf("no commit entry in the journal; entries=%d", len(entries))
			}
			if got != tc.want {
				t.Errorf("journal recorded %q, want %q -- the audit journal must be verbatim", got, tc.want)
			}
		})
	}
}

// TestAnnotateCommentReachesConfigVerbatim is the annotate-path counterpart,
// entering through dispatchConfig -- the real command path -- and reading the
// comment back out of the rendered candidate configuration, where it is
// persisted. Same reason as the commit test: asserting the extracted helper
// does not bind the call site's use of it.
func TestAnnotateCommentReachesConfigVerbatim(t *testing.T) {
	for _, tc := range []struct {
		name, line, want string
	}{
		// THE DEFECT, inside the quoted comment.
		{"trailing apostrophe", `annotate system host-name "belongs to users'"`, "belongs to users'"},
		// Syntactic quotes still peeled.
		{"syntactic quotes peeled", `annotate system host-name "plain comment"`, "plain comment"},
		// #14717: an unterminated trailing string is not a quoted comment
		// token under the canonical lexer split the gate uses, so the line
		// is rejected as usage and nothing is annotated. Before the
		// canonical split, the first-quote parser preserved the raw
		// `"unterminated` text as the comment.
		{"unterminated rejected", `annotate system host-name "unterminated`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
			if err := store.EnterConfigure(); err != nil {
				t.Fatal(err)
			}
			if _, err := store.LoadSet("set system host-name Probe"); err != nil {
				t.Fatal(err)
			}
			c := &CLI{store: store}
			if err := c.dispatchConfig(tc.line); err != nil {
				t.Fatalf("dispatchConfig(%q): %v", tc.line, err)
			}
			rendered := store.ShowCandidate()
			if tc.want == "" {
				if strings.Contains(rendered, "/*") {
					t.Errorf("unterminated annotate must not annotate anything.\n%s", rendered)
				}
				return
			}
			if !strings.Contains(rendered, tc.want) {
				t.Errorf("rendered candidate does not contain %q; the annotation is persisted, so it must be verbatim.\n%s", tc.want, rendered)
			}
		})
	}
}
