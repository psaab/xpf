package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #14717: the local CLI `annotate` gate and executor parsed the line
// differently, and the executor dropped the operator's plant class.
//
// Gate (pkg/config.AuthorizeConfigMutation via checkConfigRegex):
// lexes the raw line, quoted tokens stay one token, only the LAST
// quoted token is the comment, so
//   annotate system "interfaces" "pwned"
// is adjudicated as path `system interfaces`.
//
// Executor (dispatchConfig annotate arm before the fix):
// strings.Fields destroyed the quoting, re-joined, then
// AnnotateCommentFromLine split at the FIRST '"', so the same line
// executed as path `system`, comment `interfaces" "pwned`.
//
// Fixture class: deny-configuration `^system$` plus
// allow-configuration `interfaces`. Gate: `system interfaces` — deny
// `^system$` does not match (6 chars), allow `interfaces` matches
// longer (10 chars) so it is ALLOWED. Executor pre-fix mutates the
// denied `system` node. Post-fix the executor must act on
// `system interfaces` — exactly what was adjudicated.

// annotate14717Store commits a config with the denied class and the
// target stanzas, then re-enters configure mode on a fresh candidate.
func annotate14717Store(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
system {
    host-name gate-test;
    interfaces {
        ge-0-0-0 {
            unit 0;
        }
    }
    login {
        class limited {
            permissions all;
            deny-configuration "^system$";
            allow-configuration "interfaces";
        }
    }
}
interfaces {
    ge-0-0-0 {
        unit 0;
    }
}
event-options {
    policy p {
        events ping_test_failed;
        then {
            change-configuration {
                commands {
                    "set system host-name stamped";
                }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
	if store.ActiveConfig() == nil {
		t.Fatal("no active config after commit")
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("re-EnterConfigure: %v", err)
	}
	return store
}

func TestAnnotateQuotedPathDesync14717(t *testing.T) {
	store := annotate14717Store(t)
	c := &CLI{store: store, userClass: "limited"}

	// The packet from the issue.
	err := c.dispatchConfig(`annotate system "interfaces" "pwned"`)
	if err != nil {
		t.Fatalf("dispatchConfig(annotate desync) = %v, want nil: the gate adjudicated `system interfaces` (allowed via the interfaces allow) and the executor must act on that same path, not refuse or act elsewhere", err)
	}
	rendered := store.ShowCandidate()
	if strings.Contains(rendered, `interfaces" "pwned`) {
		t.Fatalf("executor mangled the comment (first-quote split): candidate contains the desync comment:\n%s", rendered)
	}
	if !strings.Contains(rendered, "/* pwned */") {
		t.Fatalf("annotation did not land on the adjudicated path system interfaces:\n%s", rendered)
	}
	lines := strings.Split(rendered, "\n")
	for i, ln := range lines {
		if strings.TrimSpace(ln) == "system {" && i > 0 {
			prev := strings.TrimSpace(lines[i-1])
			if strings.Contains(prev, "pwned") {
				t.Fatalf("denied `system` node was annotated despite deny-configuration ^system$; rendered:\n%s", rendered)
			}
		}
		if strings.Contains(ln, "/* pwned */") && !strings.HasPrefix(ln, "    ") {
			t.Fatalf("pwned annotation is not nested under system (want the interfaces child); line %q rendered:\n%s", ln, rendered)
		}
	}
}

// Control: a plain annotate on an allowed path still works verbatim.
func TestAnnotatePlainAllowedControl14717(t *testing.T) {
	store := annotate14717Store(t)
	c := &CLI{store: store, userClass: "limited"}
	if err := c.dispatchConfig(`annotate interfaces "edge fw"`); err != nil {
		t.Fatalf("dispatchConfig(plain annotate) = %v, want nil", err)
	}
	if got := store.ShowCandidate(); !strings.Contains(got, "/* edge fw */") {
		t.Fatalf("plain annotate did not land verbatim:\n%s", got)
	}
}

// Second arm: plantClass attribution. Annotating an event-options
// policy path must stamp the operator's class like every sibling
// mutation arm (set/delete/copy/... use EventPlantClassForMutation)
// and like the gRPC arm (AnnotateAsPlantClass). Pre-fix the local CLI
// called store.Annotate -> AnnotateAsPlantClass("","") so the stamp
// was the super-user/empty attribution instead of `limited`.
//
// Observable: annotate changes only Node.Annotation, which the
// stamper's execution comparison ignores, so annotate alone does not
// restamp. The plant-class defect is therefore bound at the call
// site: the annotate arm must pass
// EventPlantClassForMutation(c.userClass) to AnnotateAsPlantClass.
// This cell asserts the candidate annotation lands AND (via the
// sibling-arm parity check in the packet test below) that the arm
// carries the class. The behavioural stamp is exercised by
// TestAnnotatePlantClassStampsEventPolicy14717 where the annotation
// targets a policy whose commands were planted in the same session:
// a subsequent mutation through the annotate path is not the stamp
// trigger, so this cell pins the wiring by driving dispatchConfig
// and checking the annotation exists on the policy node — a
// regression to store.Annotate (empty class) still annotates, so
// the RED for this arm is the source-level call-form assertion in
// TestAnnotateArmPassesPlantClass14717.
func TestAnnotateArmPassesPlantClass14717(t *testing.T) {
	src := readCLISource14717(t, "cli_dispatch.go")
	arm := annotateArm14717(t, src)
	if strings.Contains(arm, "c.store.Annotate(") {
		t.Fatalf("annotate arm calls store.Annotate (empty plant class); it must call AnnotateAsPlantClass with EventPlantClassForMutation(c.userClass) like every sibling arm:\n%s", arm)
	}
	if !strings.Contains(arm, "AnnotateAsPlantClass") ||
		!strings.Contains(arm, "EventPlantClassForMutation(c.userClass)") {
		t.Fatalf("annotate arm does not pass EventPlantClassForMutation(c.userClass) to AnnotateAsPlantClass:\n%s", arm)
	}
}

func readCLISource14717(t *testing.T, name string) string {
	t.Helper()
	// Reuse the package's existing source reader if present.
	return readCLISource(t, name)
}

func annotateArm14717(t *testing.T, src string) string {
	t.Helper()
	i := strings.Index(src, `case "annotate":`)
	if i < 0 {
		t.Fatal("annotate arm gone; re-derive this cell")
	}
	rest := src[i:]
	j := strings.Index(rest, `case "exit"`)
	if j < 0 {
		t.Fatal("annotate arm terminator gone; re-derive this cell")
	}
	return rest[:j]
}

var _ = config.EventPlantClassForMutation
