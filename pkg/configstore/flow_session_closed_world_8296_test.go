package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8296: a fumbled keyword under `security flow {tcp,udp,icmp}-session`
// committed CLEAN, rendered back through `show configuration` verbatim, and
// reached no consumer.
//
// # Why this is not cosmetic, and why the fail direction is not uniform
//
// The render-back is the trap: it is how an operator confirms a commit took,
// and it confirms the TEXT was stored, not that anything consumes it. What a
// typo then does depends on which keyword it was:
//
//   - `rst-invalidate-sesion` — a HARDENING flag. The typo silently drops a
//     protection the operator explicitly asked for. Fail-OPEN.
//   - `timout` / `inital-timeout` — the session falls back to the DEFAULT,
//     which is usually LONGER than the value being tightened.
//   - `no-syn-check`, `no-sequence-check` — relaxations, so a typo fails SAFE.
//     Those are the wrong examples to reason from; they make the class look
//     benign.
//
// `security flow aging` has rejected its unknown options since #4313. These
// three siblings are the same shape and were left open — a partial hardening
// that stopped, not a deliberate compatibility posture.
//
// # The accept side carries the weight here
//
// `schemaNode.closedWorld`'s own contract says a flip is safe only once the
// subtree is LEAF-COMPLETE, "otherwise it false-rejects a valid-but-not-yet-
// modeled config", and it names the #2078/#4231 accept-with-advisory knobs as
// what a blanket flip would break. `tcp-session strict-syn-check` is exactly
// such a knob — documented in docs/feature-gaps.md, and until #8296 modelled by
// NOTHING: absent from setSchema, absent from the compiler, and (contrary to
// what that doc claimed) carrying no advisory either. Flipping tcp-session
// without modelling it first would have rejected a documented configuration.
//
// So the rejection cells below are worth exactly as much as
// TestFlowSessionClosedWorldAcceptsEveryDocumentedKeyword8296, which is the one
// that would have caught that mistake.

// everyDocumentedFlowSessionKeyword is the full authored set for the three
// closed subtrees: every keyword modelled in setSchema plus every one
// docs/feature-gaps.md documents as accepted. If a future Junos keyword is
// added to the schema it belongs here too — that is the point of a
// leaf-completeness cell.
var everyDocumentedFlowSessionKeyword = []string{
	"tcp-session { established-timeout 1800; }",
	"tcp-session { initial-timeout 20; }",
	"tcp-session { closing-timeout 4; }",
	"tcp-session { time-wait-timeout 150; }",
	"tcp-session { no-syn-check; }",
	"tcp-session { no-syn-check-in-tunnel; }",
	"tcp-session { rst-invalidate-session; }",
	"tcp-session { no-sequence-check; }",
	"tcp-session { strict-syn-check; }",
	"udp-session { timeout 60; }",
	"icmp-session { timeout 60; }",
}

func flowText8296(body string) string {
	return "security {\n    flow {\n        " + body + "\n    }\n}\n"
}

// ACCEPT SIDE. A closed-world subtree that refused everything would pass every
// rejection cell below; this is what makes those cells mean something.
func TestFlowSessionClosedWorldAcceptsEveryDocumentedKeyword8296(t *testing.T) {
	for _, body := range everyDocumentedFlowSessionKeyword {
		if _, err := CheckText(flowText8296(body), 0); err != nil {
			t.Errorf("closed-world REJECTED a documented keyword — this is the "+
				"false-rejection schemaNode.closedWorld's contract warns about, "+
				"and for an accept-with-advisory knob (#2078/#4231) it refuses a "+
				"configuration the tree documents as supported.\n  authored: %s\n  error: %v",
				body, err)
		}
	}
}

// THE HARM. Each typo used to commit clean and reach no consumer.
func TestFlowSessionClosedWorldRejectsATypo8296(t *testing.T) {
	for _, tc := range []struct{ body, want, why string }{
		{
			"tcp-session { rst-invalidate-sesion; }", "rst-invalidate-sesion",
			"a fumbled HARDENING flag silently drops a protection the operator asked for",
		},
		{
			"tcp-session { inital-timeout 10; }", "inital-timeout",
			"the session falls back to the default instead of the authored value",
		},
		{"udp-session { timout 30; }", "timout", "same, on a longer default"},
		{"icmp-session { timout 30; }", "timout", "same, on a longer default"},
	} {
		_, err := CheckText(flowText8296(tc.body), 0)
		if err == nil {
			t.Errorf("a typo committed CLEAN: %s\n  it would render back through "+
				"`show configuration` verbatim and reach no consumer — %s",
				tc.body, tc.why)
			continue
		}
		// The message must NAME the offending keyword; "invalid config" sends an
		// operator hunting through a stanza they just typed correctly except for
		// one character.
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("the rejection does not name %q, so it does not tell the "+
				"operator which keyword to fix.\n  got: %v", tc.want, err)
		}
	}
}

// #8296 also made `strict-syn-check` reach a consumer for the first time: the
// accepted-only advisory docs/feature-gaps.md already claimed existed.
func TestStrictSynCheckNowCarriesItsAdvisory8296(t *testing.T) {
	tree, perrs := config.NewParser(flowText8296("tcp-session { strict-syn-check; }")).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, cerr := config.CompileConfig(tree)
	if cerr != nil {
		t.Fatalf("compile: %v", cerr)
	}
	if cfg.Security.Flow.TCPSession == nil || !cfg.Security.Flow.TCPSession.StrictSynCheck {
		t.Fatal("strict-syn-check did not reach the typed config — it is modelled " +
			"in the schema but read by nothing, which is the #8296 defect again")
	}
	var found bool
	for _, w := range config.ValidateConfig(cfg) {
		if strings.Contains(w, "strict-syn-check") {
			found = true
		}
	}
	if !found {
		t.Error("no advisory names strict-syn-check. docs/feature-gaps.md states " +
			"`Commit emits an accepted-only advisory`; before #8296 that claim was " +
			"false and the keyword reached nothing at all")
	}
}

// BOOT SAFETY. A strict gate bounds what an operator may TYPE, not what the
// daemon must be able to LOAD. `Store.Load` (persisted config at boot) and
// `SyncApply` (HA peer sync during a rolling upgrade) take the tolerant path,
// and a hard rejection there would refuse to boot a config already on disk.
func TestFlowSessionClosedWorldDoesNotBrickABoot8296(t *testing.T) {
	text := flowText8296("tcp-session { rst-invalidate-sesion; }")

	tree, perrs := config.NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if _, err := config.CompileConfigLenient(tree); err != nil {
		t.Errorf("the tolerant compile REFUSED a typo'd config: %v\n  that path "+
			"backs Store.Load and SyncApply, so this would refuse to boot a node "+
			"whose on-disk config already carries the typo", err)
	}

	// The real boot path, not a proxy for it.
	path := filepath.Join(t.TempDir(), "xpf.conf")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Load(); err != nil {
		t.Errorf("Store.Load REFUSED a typo'd on-disk config: %v", err)
	}
}

// SCOPE BOUNDARY, re-decided by #10078 (#10337 cohort). When #8296 landed,
// an unknown stanza directly under `security {}` was STILL accepted on every
// path, and closing that was deliberately left open as the wider #8296 design
// question. #10078 (PR #10327) has since armed closedWorld at the `security`
// root, which IS that decision on the strict side: an operator typo at this
// level now rejects at commit, naming the token. This cell therefore no
// longer asserts strict acceptance — it pins the LENIENT half of the new
// contract: the tolerant load path (Store.Load at boot, SyncApply on peer
// sync) must still ACCEPT the stanza, with a warning, so a node whose
// on-disk config already carries it boots instead of bricking (#1960).
// The strict half is pinned by TestUnknownSecurityStanzaStrictRejects10337
// below: strict rejects, lenient warns-and-loads.
func TestUnknownSecurityStanzaIsStillAccepted8296(t *testing.T) {
	text := "security {\n    flow { allow-dns-reply; }\n    flooby { wibble 42; }\n}\n"
	tree, perrs := config.NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if _, err := config.CompileConfigLenient(tree); err != nil {
		t.Errorf("the tolerant compile REFUSED an unknown security stanza: %v\n  that path "+
			"backs Store.Load and SyncApply, so this would refuse to boot a node "+
			"whose on-disk config already carries it", err)
	}
	// The store leg, with the downgrade warning captured: the stanza must be
	// visible, not silently swallowed.
	buf := captureWarnLogs(t)
	s := newTestStore(t)
	if _, err := s.compileTreeLenient(tree); err != nil {
		t.Fatalf("the tolerant store path REFUSED an unknown security stanza: %v", err)
	}
	if !strings.Contains(buf.String(), "flooby") {
		t.Errorf("expected the lenient downgrade warning to name %q, log = %q", "flooby", buf.String())
	}
	// The real boot path, not a proxy for it.
	path := filepath.Join(t.TempDir(), "xpf.conf")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	boot, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := boot.Load(); err != nil {
		t.Errorf("Store.Load REFUSED an on-disk config with an unknown security stanza: %v", err)
	}
}

// STRICT HALF of the rescoped #8296 boundary (#10337 cohort). #10078 armed
// closedWorld at the `security` root, deciding the wider #8296 question on
// the operator path: an unknown stanza directly under `security {}` is a
// typo-class shape (the `policie`/`frum-zone` family #10078 exists to catch)
// and must REJECT at commit-check, naming the token. The lenient half —
// warn-and-load — is pinned by TestUnknownSecurityStanzaIsStillAccepted8296
// above. RED-on-revert: disarm the security root and this commits clean.
func TestUnknownSecurityStanzaStrictRejects10337(t *testing.T) {
	_, err := CheckText("security {\n    flow { allow-dns-reply; }\n    flooby { wibble 42; }\n}\n", 0)
	if err == nil {
		t.Fatal("an unknown stanza under security{} committed CLEAN — the #10078 " +
			"closedWorld arm is not rejecting at the security root")
	}
	if !strings.Contains(err.Error(), "flooby") {
		t.Errorf("the rejection does not name %q, so it does not tell the "+
			"operator which keyword to fix.\n  got: %v", "flooby", err)
	}
}

// INHERITANCE DIRECTION. `closedWorld` inherits DOWN every level
// (`childClosed := closed || childSchema.closedWorld` in schema_walk.go), so a
// cell that only exercises a subtree's direct children cannot see an
// inheritance bug. Every leaf under these three subtrees is `children: nil`, so
// nothing deeper is MODELLED — which means an authored nested block under a
// leaf is unmodelled at a level BELOW the flip, and closed-world must still
// reject it. If the inheritance were dropped, this would silently accept.
func TestFlowSessionClosedWorldInheritsDownward8296(t *testing.T) {
	for _, body := range []string{
		"tcp-session { rst-invalidate-session { bogus-child; } }",
		"udp-session { timeout { bogus-child; } }",
		"icmp-session { timeout { bogus-child; } }",
	} {
		if _, err := CheckText(flowText8296(body), 0); err == nil {
			t.Errorf("closed-world did not reach a level BELOW the subtree it was "+
				"flipped on — an unmodelled keyword nested under a leaf committed "+
				"clean: %s", body)
		}
	}
}
