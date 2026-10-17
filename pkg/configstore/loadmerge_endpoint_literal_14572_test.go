package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14572: the store's hierarchical LoadMerge branch re-parsed the RAW body
// while the authorization gate adjudicated ClassifyLoadContent's
// comment-stripped view. A token-initial `[/*x]:1` endpoint literal is one
// identifier to the real lexer (#5182), but the classifier opened a
// fictitious comment at its `/*` and blanked every following statement —
// so the gate saw only the first leaf while this branch applied the whole
// body, including denied subtrees. Both hierarchical ingresses (LoadMerge
// and LoadOverride's shared parser) must now parse exactly the
// classifier's uncommented text.

// Property: every set line the hierarchical merge branch APPLIES is a line
// the gate ADJUDICATED (LoadMutationLines of the same body). Exercised
// over the `[`/`]`/`/*`/`//`/`#` placement space, with a description leaf
// as the carrier so nothing depends on host-name validation.
func TestLoadMergeAppliesOnlyGateAdjudicatedLines14572(t *testing.T) {
	deniedLeaf := "set system root-authentication plain-text-password-value hunter2"
	bodies := map[string]string{
		"token-initial block endpoint": "system { host-name [/*x]:1; " +
			"root-authentication { plain-text-password-value hunter2; } } # */\n",
		"token-initial line endpoint": "system { host-name [//x]:1; " +
			"root-authentication { plain-text-password-value hunter2; } }\n",
		"endpoint on allowed description": "interfaces { ge-0/0/0 { description [/*x]:1; } } " +
			"system { root-authentication { plain-text-password-value hunter2; } } # */\n",
		"mid-token fake comment": "interfaces { ge-0/0/0 { description a[/*x]:1; } } " +
			"system { root-authentication { plain-text-password-value hunter2; } } # */\n",
		"stray close bracket endpoint": "interfaces { ge-0/0/0 { description ][/*x]:1; } } " +
			"system { root-authentication { plain-text-password-value hunter2; } } # */\n",
		"quoted fake comment": `interfaces { ge-0/0/0 { description "[/*x]:1"; } } ` +
			"system { root-authentication { plain-text-password-value hunter2; } }\n",
		"plain endpoint literal": "interfaces { ge-0/0/0 { description [2001:db8::1]:51820; } } " +
			"system { host-name fw14572; }\n",
		"genuine comment hides prose": "interfaces { ge-0/0/0 { description kept14572; } } " +
			"/* root-authentication { plain-text-password-value hunter2; } */\n",
		"genuine list then comment": "interfaces { ge-0/0/0 { description [ /* prose */ x; } } " +
			"system { host-name fw14572; }\n",
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			adjudicated, err := config.LoadMutationLines(body)
			if err != nil {
				t.Fatalf("LoadMutationLines error = %v (#14572)", err)
			}
			adjudicatedSet := make(map[string]bool, len(adjudicated))
			for _, line := range adjudicated {
				adjudicatedSet[line] = true
			}

			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			if err := s.LoadMerge(body); err != nil {
				t.Fatalf("LoadMerge: %v", err)
			}
			for _, line := range strings.Split(s.ShowCandidateSet(), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				if !adjudicatedSet[line] {
					t.Errorf("store applied a line the gate never adjudicated (#14572):\n"+
						"applied:     %q\nadjudicated: %q", line, adjudicated)
				}
			}
			// The denied leaf must never materialize unless the gate saw
			// it: bodies carrying it for real must have it adjudicated.
			applied := s.ShowCandidateSet()
			if strings.Contains(applied, deniedLeaf) && !adjudicatedSet[deniedLeaf] {
				t.Errorf("denied leaf applied without adjudication (#14572):\n%s", applied)
			}
		})
	}
}

// The same gate⊆store property through LoadOverride's shared hierarchical
// parser: it replaces the candidate wholesale, so an unadjudicated line
// there is a complete unadjudicated configuration.
func TestLoadOverrideAppliesOnlyGateAdjudicatedLines14572(t *testing.T) {
	body := "system { host-name [/*x]:1; " +
		"root-authentication { plain-text-password-value hunter2; } } # */\n"
	adjudicated, err := config.LoadMutationLines(body)
	if err != nil {
		t.Fatalf("LoadMutationLines error = %v (#14572)", err)
	}
	adjudicatedSet := make(map[string]bool, len(adjudicated))
	for _, line := range adjudicated {
		adjudicatedSet[line] = true
	}

	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.LoadOverride(body); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	for _, line := range strings.Split(s.ShowCandidateSet(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !adjudicatedSet[line] {
			t.Errorf("store applied a line the gate never adjudicated (#14572):\n"+
				"applied:     %q\nadjudicated: %q", line, adjudicated)
		}
	}
}
