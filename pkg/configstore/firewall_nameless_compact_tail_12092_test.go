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

	// These two value-bearing controls reject because their validators see
	// `then` as a port/protocol value. The no-argument is-fragment and
	// flexible-match-range leaves instead swallow the fused tail; the pin
	// below records the is-fragment fail-open (#12528).
	rejected := []struct {
		name, input, wantErr string
	}{
		{
			name: "P05 destination port",
			input: `firewall {
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
			name: "protocol and action",
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
	t.Run("is-fragment fused tail fail-open #12528", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		input := `firewall {
    family inet {
        filter F {
            term { T from is-fragment { then { discard; } } }
            term allow { then accept; }
        }
    }
}`
		if err := s.LoadMerge(input); err != nil {
			t.Fatalf("LoadMerge: %v", err)
		}
		wantSet := "set firewall family inet filter F term T from is-fragment then discard\n" +
			"set firewall family inet filter F term allow then accept\n"
		if got := s.ShowCandidateSet(); got != wantSet {
			t.Fatalf("LoadMerge candidate set = %q, want %q", got, wantSet)
		}
		cfg, err := s.CommitCheck()
		if err != nil {
			t.Fatalf("LoadMerge + CommitCheck rejected known current behavior: %v", err)
		}
		terms := cfg.Firewall.FiltersInet["F"].Terms
		if len(terms) != 2 {
			t.Fatalf("committed firewall term count = %d, want 2", len(terms))
		}
		if terms[0].Name != "T" || !terms[0].IsFragment || terms[0].Action != "" {
			t.Fatalf("committed is-fragment term = {Name:%q IsFragment:%t Action:%q}, want T with IsFragment and empty Action",
				terms[0].Name, terms[0].IsFragment, terms[0].Action)
		}
		if terms[1].Name != "allow" || terms[1].Action != "accept" {
			t.Fatalf("committed allow term = %+v, want allow/accept", terms[1])
		}
	})
}
