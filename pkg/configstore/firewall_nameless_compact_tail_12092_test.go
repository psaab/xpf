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

// Pin the current hierarchical LoadMerge contract: FormatSetForLoadMerge
// turns these nameless AST shapes into ordinary named set paths before the
// strict CommitCheck gate sees them. The behavior is tracked for redesign in
// #12526; this test deliberately does not assert a pre-flatten rejection.
func TestLoadMergeNamelessTermFlatteningIsPinned12092(t *testing.T) {
	accepted := []struct {
		name, input, wantSet string
	}{
		{
			name: "bare foo",
			input: `firewall {
    family inet {
        filter F {
            term { foo; }
        }
    }
}`,
			wantSet: "set firewall family inet filter F term foo\n",
		},
		{
			name: "then discard",
			input: `firewall {
    family inet {
        filter F {
            term { T then discard { } }
        }
    }
}`,
			wantSet: "set firewall family inet filter F term T then discard\n",
		},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			if err := s.LoadMerge(tc.input); err != nil {
				t.Fatalf("LoadMerge: %v", err)
			}
			if got := s.ShowCandidateSet(); got != tc.wantSet {
				t.Fatalf("LoadMerge candidate set = %q, want flattened named set %q", got, tc.wantSet)
			}
			if _, err := s.CommitCheck(); err != nil {
				t.Fatalf("LoadMerge + CommitCheck rejected the pinned current behavior: %v", err)
			}
		})
	}

	// Populated dangerous nested-name forms remain refused after replay; these
	// controls make the accepted nameless-shape pin precise rather than
	// weakening the existing commit gate.
	rejected := []struct {
		name, input, wantErr string
	}{
		{
			name:    "P05 destination port",
			input:   `firewall {
    family inet {
        filter F {
            term { T from destination-port 22 { then { accept; } } }
            term deny { then discard; }
        }
    }
}`,
			wantErr: `unknown port "then"`,
		},
		{
			name:  "protocol and action",
			input: `firewall {
    family inet {
        filter F {
            term { T from protocol tcp { then { accept; } } }
        }
    }
}`,
			wantErr: `unknown protocol "then"`,
		},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			if err := s.LoadMerge(tc.input); err != nil {
				t.Fatalf("LoadMerge: %v", err)
			}
			_, err := s.CommitCheck()
			if err == nil {
				t.Fatal("LoadMerge + CommitCheck accepted populated dangerous shape")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("CommitCheck error = %q, want %q", err, tc.wantErr)
			}
		})
	}
}
