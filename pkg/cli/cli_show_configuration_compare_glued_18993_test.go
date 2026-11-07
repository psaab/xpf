package cli

// #18993: a compare pipe glued on its LEFT side (`show configuration|
// compare rollback 1`, `show configuration system| compare rollback 1`)
// was recognized by neither the dispatch carve-out (which enumerated
// spaced, `|compare` and `x|compare` shapes) nor the operational handler
// (which only matched a token ending in `|compare`). Under a foreign
// holder or an ownerless store the line therefore fell into config-mode
// show, printed `configuration path not found` and returned nil.
//
// The fix shares one adjacency-aware classifier
// (cmdtree.ClassifyComparePipe) between dispatch routing and the
// handler: any `|` touching non-space text on either side is glued.
// Spaced compare (found && !glued) must keep rendering the ACTIVE
// baseline exactly as #18669 landed it.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

func gluedCompareFixtures18993() []struct {
	name      string
	store     func(*testing.T) *configstore.Store
	userClass string
} {
	return []struct {
		name      string
		store     func(*testing.T) *configstore.Store
		userClass string
	}{
		{"foreign-holder", foreignShowCompareStore18669, "super-user"},
		{"ownerless-no-rbac", showCompareStore18669, ""},
	}
}

func TestCLIShowConfigurationLeftGluedCompareRefused18993(t *testing.T) {
	lines := []string{
		// Left-glued: the defect rows (RED at base).
		"show configuration| compare rollback 1",
		"show configuration system| compare rollback 1",
		// Already-refused glued shapes staying refused.
		"show configuration |compare rollback 1",
		// The config lexer skips the block comment after the pipe, but
		// the pipe remains raw-byte adjacent to that comment.
		"show configuration |/*x*/compare rollback 1",
		"show configuration system |/*x*/compare rollback 1",
	}
	for _, fixture := range gluedCompareFixtures18993() {
		for _, line := range lines {
			t.Run(fixture.name+"/"+line, func(t *testing.T) {
				c := &CLI{store: fixture.store(t), userClass: fixture.userClass}
				if got, want := c.promptForCurrentMode(), c.operationalPrompt(); got != want {
					t.Fatalf("promptForCurrentMode() = %q, want operational prompt %q", got, want)
				}
				var err error
				out := captureStdout(t, func() { err = c.dispatch(line) })
				if err == nil {
					t.Fatalf("dispatch(%q) returned nil, output %q; want glued-pipe refusal", line, out)
				}
				if strings.Contains(out, "configuration path not found") {
					t.Errorf("dispatch(%q) printed candidate path-not-found output: %q", line, out)
				}
				if out != "" {
					t.Errorf("dispatch(%q) printed %q before refusing", line, out)
				}
			})
		}
	}
}

// TestCLIShowConfigurationSpacedCompareControls18993 pins that the
// landed spaced compare keeps rendering the ACTIVE baseline under both
// holder fixtures after the classifier rewiring (the glued-always-false
// mutant must leave these GREEN).
func TestCLIShowConfigurationSpacedCompareControls18993(t *testing.T) {
	fixtures := []struct {
		name      string
		store     func(*testing.T) *configstore.Store
		userClass string
	}{
		{"foreign-holder", foreignShowCompareStore18669, "compare-view-18669"},
		{"ownerless-no-rbac", showCompareStore18669, ""},
	}
	for _, fixture := range fixtures {
		for _, tc := range []struct {
			line    string
			wantIn  []string
			wantOut []string
		}{
			{
				line:    "show configuration | compare rollback 1",
				wantIn:  []string{activeDomain18669, activeInterface18669},
				wantOut: []string{candidateCanary18669, "candidate-18669.invalid"},
			},
			{
				line:    "show configuration system | compare rollback 1",
				wantIn:  []string{activeDomain18669},
				wantOut: []string{activeInterface18669, candidateCanary18669, "candidate-18669.invalid"},
			},
			{
				line:    "show configuration | /*x*/compare rollback 1",
				wantIn:  []string{activeDomain18669, activeInterface18669},
				wantOut: []string{candidateCanary18669, "candidate-18669.invalid"},
			},
			{
				line:    "show configuration | /*x*/ compare rollback 1",
				wantIn:  []string{activeDomain18669, activeInterface18669},
				wantOut: []string{candidateCanary18669, "candidate-18669.invalid"},
			},
			{
				line:    "show configuration system | /*x*/compare rollback 1",
				wantIn:  []string{activeDomain18669},
				wantOut: []string{activeInterface18669, candidateCanary18669, "candidate-18669.invalid"},
			},
			{
				line:    "show configuration system | /*x*/ compare rollback 1",
				wantIn:  []string{activeDomain18669},
				wantOut: []string{activeInterface18669, candidateCanary18669, "candidate-18669.invalid"},
			},
		} {
			t.Run(fixture.name+"/"+tc.line, func(t *testing.T) {
				c := &CLI{store: fixture.store(t), userClass: fixture.userClass}
				var err error
				out := captureStdout(t, func() { err = c.dispatch(tc.line) })
				if err != nil {
					t.Fatalf("dispatch(%q): %v", tc.line, err)
				}
				for _, value := range tc.wantIn {
					if !strings.Contains(out, value) {
						t.Errorf("dispatch(%q) output missing active-baseline value %q:\n%s", tc.line, value, out)
					}
				}
				for _, value := range tc.wantOut {
					if strings.Contains(out, value) {
						t.Errorf("dispatch(%q) output contains candidate value %q:\n%s", tc.line, value, out)
					}
				}
			})
		}
	}
}

func TestCLIShowConfigurationGluedCompareHandlerRefused18993(t *testing.T) {
	for _, args := range [][]string{
		{"configuration", "system|", "compare", "rollback", "1"},
		{"configuration", "system|compare", "rollback", "1"},
		{"configuration", "|compare", "rollback", "1"},
		{"configuration", "/*x*/|", "compare", "rollback", "1"},
		{"configuration", "|/*x*/compare", "rollback", "1"},
		{"configuration", "system", "|/*x*/compare", "rollback", "1"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			c := &CLI{store: showCompareStore18669(t)}
			var err error
			out := captureStdout(t, func() { err = c.handleShow(args) })
			if err == nil {
				t.Fatalf("handleShow(%q) returned nil, output %q; want glued-pipe refusal", args, out)
			}
			if out != "" {
				t.Fatalf("handleShow(%q) printed %q before refusing", args, out)
			}
		})
	}
}
