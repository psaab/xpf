package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16530: the HA config-sync payload is ShowActive() -> Format() text, which
// the peer re-parses in SyncApply, and rollback slots are the same Format
// text re-parsed on load. Leaf bracket provenance did not survive that
// text, so a grandfathered unquoted-bracket as-path (JSON DB written
// between #6668 and #9881) strict-rejected on the primary's next strict
// commit but strict-accepted — and rendered — on the peer / after rollback.
//
// These tests drive the production surfaces end to end: a primary store
// whose active tree carries the provenance (built exactly as a pre-#9881
// DB load builds it, by parsing the authored text), the peer's SyncApply
// of ShowActive(), and a rollback-file round trip.

// syncPrimary16530 returns a store whose candidate carries the flagged
// as-path, installed through the tolerant sync path (the only path that
// admits a grandfathered flagged tree, per the #1960 no-brick rule).
func syncPrimary16530(t *testing.T) *Store {
	t.Helper()
	s := newTestStore(t)
	if _, err := s.SyncApply("policy-options {\n    as-path AP1 [0-9]+;\n}\n", nil); err != nil {
		t.Fatalf("SyncApply flagged config: %v", err)
	}
	return s
}

func activeASPath16530(t *testing.T, s *Store) *config.ASPathDef {
	t.Helper()
	cfg := s.ActiveConfig()
	if cfg == nil {
		t.Fatal("store has no active config")
	}
	ap := cfg.PolicyOptions.ASPaths["AP1"]
	if ap == nil {
		t.Fatalf("active config lost AP1:\n%s", s.ShowActive())
	}
	return ap
}

// TestSyncApplyFormatPreservesBracketFlag16530: the peer receives
// ShowActive() text; after SyncApply its compiled as-path must still carry
// RegexUnquotedBracket, so a strict compile on the peer rejects with the
// same diagnostic as on the primary instead of rendering the mangled regex.
func TestSyncApplyFormatPreservesBracketFlag16530(t *testing.T) {
	primary := syncPrimary16530(t)
	if ap := activeASPath16530(t, primary); !ap.RegexUnquotedBracket {
		t.Fatalf("premise: primary active flag=false (Regex=%q)", ap.Regex)
	}
	payload := primary.ShowActive()
	if !strings.Contains(payload, "[ 0-9 ]") {
		t.Fatalf("premise: HA payload does not carry the bracket:\n%s", payload)
	}

	peer := newTestStore(t)
	cfg, err := peer.SyncApply(payload, nil)
	if err != nil {
		t.Fatalf("peer SyncApply: %v", err)
	}
	ap := cfg.PolicyOptions.ASPaths["AP1"]
	if ap == nil {
		t.Fatalf("peer compiled config lost AP1:\n%s", payload)
	}
	if !ap.RegexUnquotedBracket {
		t.Fatalf("peer lost RegexUnquotedBracket across ShowActive->SyncApply (Regex=%q) — peer would render the mangled regex (#16530)", ap.Regex)
	}
	if got := peer.ShowActive(); got != payload {
		t.Fatalf("peer active text differs from primary payload:\nprimary:\n%s\npeer:\n%s", payload, got)
	}

	// Strict verdict parity: both sides reject with the identical error.
	_, perr := config.CompileConfig(primary.ActiveTree())
	peerTree, errs := config.NewParser(peer.ShowActive()).Parse()
	if len(errs) > 0 {
		t.Fatalf("reparse peer active: %v", errs)
	}
	_, qerr := config.CompileConfig(peerTree)
	if perr == nil || qerr == nil || perr.Error() != qerr.Error() {
		t.Fatalf("strict verdict diverged:\nprimary: %v\npeer:    %v", perr, qerr)
	}
}

// TestRollbackFormatPreservesBracketFlag16530: a rollback slot is Format
// text on disk; loading it back (fresh store over the same file) must keep
// the flag so `rollback N` reproduces the primary's verdict. The slot is
// produced through the production commit path, the same path that writes
// xpf.conf.N on a real box.
func TestRollbackFormatPreservesBracketFlag16530(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/xpf.db"
	s := newTestStoreAt(t, path)
	if _, err := s.SyncApply("policy-options {\n    as-path AP1 [0-9]+;\n}\n", nil); err != nil {
		t.Fatalf("SyncApply flagged config: %v", err)
	}
	if _, err := s.SyncApply("system {\n    host-name after;\n}\npolicy-options {\n    as-path AP1 [0-9]+;\n}\n", nil); err != nil {
		t.Fatalf("SyncApply second config: %v", err)
	}
	// A third SyncApply with a changed host-name pushes the flagged tree
	// into the history; ListHistory on a reopened store reloads the
	// numbered slots from their Format text on disk. A strict Commit of
	// the flagged tree is deliberately NOT used: it correctly refuses,
	// which is the primary-side verdict this test preserves.
	if _, err := s.SyncApply("system {\n    host-name third;\n}\npolicy-options {\n    as-path AP1 [0-9]+;\n}\n", nil); err != nil {
		t.Fatalf("SyncApply third config: %v", err)
	}
	reopened := newTestStoreAt(t, path)
	if err := reopened.Load(); err != nil {
		t.Fatalf("reopen Load: %v", err)
	}
	if ap := activeASPath16530(t, reopened); !ap.RegexUnquotedBracket {
		t.Fatalf("premise: reopened active flag=false (Regex=%q)", ap.Regex)
	}
	entries := reopened.ListHistory()
	found := false
	for _, e := range entries {
		if e == nil || e.Config == nil {
			continue
		}
		cfg, err := config.CompileConfigLenient(e.Config)
		if err != nil {
			continue
		}
		if ap := cfg.PolicyOptions.ASPaths["AP1"]; ap != nil {
			found = true
			if !ap.RegexUnquotedBracket {
				t.Fatalf("rollback slot lost RegexUnquotedBracket (Regex=%q) — rollback would strict-accept the mangled regex (#16530)\nslot text:\n%s", ap.Regex, e.Config.Format())
			}
		}
	}
	if !found {
		var texts []string
		for _, e := range entries {
			if e != nil && e.Config != nil {
				texts = append(texts, e.Config.Format())
			}
		}
		t.Fatalf("no rollback slot carries AP1; slots:\n%s", strings.Join(texts, "\n---\n"))
	}
}
