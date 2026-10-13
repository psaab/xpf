package configstore

import (
	"strings"
	"testing"
)

func TestCommitCheckRejectsNestedNameCompactTail12092(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	input := `firewall {
    family inet {
        filter F {
            term { T from destination-port 22 { then { accept; } } }
            term deny { then discard; }
        }
    }
}`
	if err := s.LoadOverride(input); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("LoadOverride + CommitCheck accepted P05; the nameless nested term must be rejected")
	}
	if !strings.Contains(err.Error(), "nameless") ||
		!strings.Contains(err.Error(), "#10294") ||
		!strings.Contains(err.Error(), "#12092") ||
		!strings.Contains(err.Error(), `"T"`) {
		t.Fatalf("CommitCheck error = %q, want nameless #10294/#12092 rejection naming T", err)
	}
}

// Hierarchical LoadMerge must inspect literal term bodies before
// FormatSetForLoadMerge normalizes nameless bodies into named paths.
func TestLoadMergeRejectsNamelessFirewallTermsBeforeFlattening12526(t *testing.T) {
	cases := []struct{ name, input string }{
		{"bare foo", `firewall { family inet { filter F { term { foo; } } } }`},
		{"then discard", `firewall { family inet { filter F { term { T then discard { } } } } }`},
		{"then accept", `firewall { family inet { filter F { term { T then accept { } } } } }`},
		{"P05 destination port", `firewall { family inet { filter F { term { T from destination-port 22 { then { accept; } } } } } }`},
		{"protocol and action", `firewall { family inet { filter F { term { T from protocol tcp { then { accept; } } } } } }`},
		// #12528 separately covers the named is-fragment tail loss. This
		// nameless variant is rejected here at the earlier naming boundary.
		{"is-fragment fused tail", `firewall { family inet { filter F { term { T from is-fragment { then { discard; } } } } } }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			err := s.LoadMerge(tc.input)
			if err == nil {
				t.Fatal("LoadMerge accepted nameless firewall term")
			}
			for _, want := range []string{"nameless", "#10294", "#12092", "#12526"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("LoadMerge error = %q, want %q", err, want)
				}
			}
			if got := s.ShowCandidateSet(); got != "" {
				t.Fatalf("rejected LoadMerge mutated candidate: %q", got)
			}
		})
	}
}
