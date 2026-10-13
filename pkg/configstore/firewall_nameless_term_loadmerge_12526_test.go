package configstore

import (
	"strings"
	"testing"
)

func TestLoadMergeRejectsNamelessFirewallTermsBeforeFlatten12526(t *testing.T) {
	rows := []struct{ name, input string }{
		{"bare foo", `firewall { family inet { filter F { term { foo; } } } }`},
		{"then discard", `firewall { family inet { filter F { term { T then discard { } } } } }`},
		{"then accept", `firewall { family inet { filter F { term { T then accept { } } } } }`},
		{"nested destination-port", `firewall { family inet { filter F { term { T from destination-port 22 { then { accept; } } } } } }`},
		{"is-fragment fused tail", `firewall { family inet { filter F { term { T from is-fragment { then { discard; } } } } } }`},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			if err := s.LoadMerge(tc.input); err == nil {
				t.Fatal("LoadMerge accepted nameless firewall term before flattening")
			} else {
				for _, want := range []string{"nameless", "#10294", "#12092", "#12526"} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("LoadMerge error = %q, want %q", err, want)
					}
				}
			}
			if got := s.ShowCandidateSet(); got != "" {
				t.Fatalf("failed LoadMerge mutated candidate: %q", got)
			}
		})
	}
}

func TestLoadMergeNamelessFirewallTermsControls12526(t *testing.T) {
	rows := []struct{ name, input, want string }{
		{"hierarchical", `firewall { family inet { filter F { term allow { then accept; } } } }`, "set firewall family inet filter F term allow then accept\n"},
		{"nested named", `firewall { family inet { filter F { term { allow { then accept; } } } } }`, "set firewall family inet filter F term allow then accept\n"},
		{"existing named candidate", `firewall { family inet { filter F { term allow { then accept; } } } }`, "set firewall family inet filter F term allow then accept\n"},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			if err := s.LoadMerge(tc.input); err != nil {
				t.Fatalf("LoadMerge named control: %v", err)
			}
			if got := s.ShowCandidateSet(); got != tc.want {
				t.Fatalf("candidate set = %q, want %q", got, tc.want)
			}
			if _, err := s.CommitCheck(); err != nil {
				t.Fatalf("CommitCheck named control: %v", err)
			}
		})
	}
}
