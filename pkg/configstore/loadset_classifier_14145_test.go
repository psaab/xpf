package configstore

import (
	"strings"
	"testing"
)

// #14145: LoadSetAsPlantClass replayed the RAW lines while the
// authorization gate adjudicated its own comment-stripped view of the
// same body. A mid-token '[/*' opened a fictitious block comment in the
// gate's scanner (the real config lexer keeps '[', '/' and '*' inside an
// identifier once a token has begun), so the gate saw zero mutations
// while this raw replay applied every line. The store now routes through
// the same shared classifier as the gate (config.ClassifyLoadContent),
// so it applies exactly the representation that was adjudicated — and
// refuses what the classifier refuses.

// The admitted prefix of the attack body must land, and every line the
// classifier keeps must land with it: the store's view and the gate's
// view are the same bytes, so there is no second, hidden line left for
// the raw replay to apply beyond what was adjudicated.
func TestLoadSetAppliesClassifierView14145(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	body := "set system host-name a[/*\n" +
		"set system domain-name example14145.net\n"
	count, err := s.LoadSet(body)
	if err != nil {
		t.Fatalf("LoadSet of a body whose first value carries a mid-token '[/*': %v", err)
	}
	if count != 2 {
		t.Errorf("LoadSet applied %d commands, want 2 (both classifier-visible lines)", count)
	}
	got := s.ShowCandidateSet()
	if !strings.Contains(got, "host-name") || !strings.Contains(got, "a[/*") {
		t.Errorf("candidate lost the mid-token bracket value the real lexer keeps:\n%s", got)
	}
	if !strings.Contains(got, "domain-name example14145.net") {
		t.Errorf("candidate missing the second line; the store did not apply the "+
			"classifier-visible body:\n%s", got)
	}
}

// A genuine unterminated block comment is refused by the store itself,
// atomically — not partially applied line by line. Before the fix the
// raw replay applied the first line and then failed (or worse, applied
// lines the gate had blanked); either way the candidate advanced on a
// body no adjudicator could classify.
func TestLoadSetRejectsUnterminatedCommentAtomically14145(t *testing.T) {
	s, before, beforeDirty, beforeLease := seedForAtomicLoad(t)
	body := "set system host-name changed14145\n/* unterminated\n" +
		"set system domain-name example14145.net\n"
	if _, err := s.LoadSet(body); err == nil {
		t.Fatal("LoadSet accepted a body with an unterminated block comment (#14145)")
	}
	assertCandidateUnchanged(t, s, before, beforeDirty, beforeLease)
}

// A genuine block comment's prose is comment text to the store as it is
// to the gate: it neither applies nor errors. This is the narrowness
// control — routing through the classifier must not turn valid
// commented scripts into failures.
func TestLoadSetSkipsGenuineBlockComment14145(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	body := "/* delete system host-name is prose, not a command */\n" +
		"set system host-name kept14145\n" +
		"# set system host-name also-prose\n"
	count, err := s.LoadSet(body)
	if err != nil {
		t.Fatalf("LoadSet of a commented script: %v", err)
	}
	if count != 1 {
		t.Errorf("LoadSet applied %d commands, want 1 (comment prose is not a command)", count)
	}
	if got := s.ShowCandidateSet(); !strings.Contains(got, "host-name kept14145") {
		t.Errorf("candidate missing the one real command:\n%s", got)
	}
}
