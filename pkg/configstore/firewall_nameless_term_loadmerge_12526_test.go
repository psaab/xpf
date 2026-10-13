package configstore

import (
	"strings"
	"testing"
)

// Hierarchical LoadMerge must inspect literal term bodies before
// FormatSetForLoadMerge normalizes nameless bodies into named paths. These
// shapes replace the #12092 flattening pin; the P05 and is-fragment inputs keep
// that pin's named sibling term, so a mixed request must reject as a whole.
func TestLoadMergeRejectsNamelessFirewallTermsBeforeFlattening12526(t *testing.T) {
	cases := []struct{ name, input string }{
		{"bare foo", `firewall { family inet { filter F { term { foo; } } } }`},
		{"then discard", `firewall { family inet { filter F { term { T then discard { } } } } }`},
		{"then accept", `firewall { family inet { filter F { term { T then accept { } } } } }`},
		{"P05 destination port", `firewall { family inet { filter F { term { T from destination-port 22 { then { accept; } } } term deny { then discard; } } } }`},
		{"protocol and action", `firewall { family inet { filter F { term { T from protocol tcp { then { accept; } } } } } }`},
		// #12528 separately covers the named is-fragment tail loss. This
		// nameless variant is rejected here at the earlier naming boundary.
		{"is-fragment fused tail", `firewall { family inet { filter F { term { T from is-fragment { then { discard; } } } term allow { then accept; } } } }`},
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

func TestLoadMergeNamelessFirewallTermsControls12526(t *testing.T) {
	rows := []struct{ name, candidate, input, want string }{
		{
			name:  "hierarchical",
			input: `firewall { family inet { filter F { term allow { then accept; } } } }`,
			want:  "set firewall family inet filter F term allow then accept\n",
		},
		{
			name:  "nested named",
			input: `firewall { family inet { filter F { term { allow { then accept; } } } } }`,
			want:  "set firewall family inet filter F term allow then accept\n",
		},
		{
			name:      "existing named candidate",
			candidate: `firewall { family inet { filter F { term ssh { from { protocol tcp; } then accept; } } } }`,
			input:     `firewall { family inet { filter F { term deny { then discard; } } } }`,
			want: "set firewall family inet filter F term ssh from protocol tcp\n" +
				"set firewall family inet filter F term ssh then accept\n" +
				"set firewall family inet filter F term deny then discard\n",
		},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			if tc.candidate != "" {
				if err := s.LoadOverride(tc.candidate); err != nil {
					t.Fatalf("LoadOverride candidate: %v", err)
				}
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
