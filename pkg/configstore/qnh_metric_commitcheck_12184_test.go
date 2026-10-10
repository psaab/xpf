package configstore

import (
	"strings"
	"testing"
)

// #12184: the actual operator CommitCheck path must reject bad qualified-next-
// hop metrics in every accepted AST spelling, while preserving zero and u32
// controls. The QNH flat-run cases are consumed by the compiler's #9235 hoist.
func TestCommitCheckQualifiedNextHopMetric12184(t *testing.T) {
	spellings := []struct {
		name  string
		input func(string) string
	}{
		{
			name: "flat leaf",
			input: func(v string) string {
				return "set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1 metric " + v
			},
		},
		{
			name: "flat interface chain",
			input: func(v string) string {
				return "set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1 interface ge-0/0/1.0 metric " + v
			},
		},
		{
			name: "flat preference chain",
			input: func(v string) string {
				return "set routing-options static route 0.0.0.0/0 qualified-next-hop 192.168.1.1 preference 5 metric " + v
			},
		},
		{
			name: "hierarchical braced",
			input: func(v string) string {
				return "routing-options { static { route 0.0.0.0/0 { qualified-next-hop 192.168.1.1 { interface ge-0/0/1.0; metric " + v + "; } } } }"
			},
		},
		{
			name: "hierarchical packed",
			input: func(v string) string {
				return "routing-options { static { route 0.0.0.0/0 { qualified-next-hop 192.168.1.1 metric " + v + "; } } }"
			},
		},
	}

	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, value := range []string{"-1", "4294967296", "abc"} {
		for _, spelling := range spellings {
			t.Run("reject/"+spelling.name+"/"+value, func(t *testing.T) {
				if err := s.LoadOverride(spelling.input(value)); err != nil {
					t.Fatalf("LoadOverride rejected candidate before CommitCheck: %v", err)
				}
				_, err := s.CommitCheck()
				if err == nil {
					t.Fatalf("CommitCheck accepted metric %q in %s spelling", value, spelling.name)
				}
				if !strings.Contains(err.Error(), "metric") || !strings.Contains(err.Error(), value) {
					t.Fatalf("CommitCheck error %q must name metric and offending value %q", err, value)
				}
			})
		}
	}
	for _, value := range []string{"0", "100", "4294967295"} {
		for _, spelling := range spellings {
			t.Run("accept/"+spelling.name+"/"+value, func(t *testing.T) {
				if err := s.LoadOverride(spelling.input(value)); err != nil {
					t.Fatalf("LoadOverride rejected valid candidate: %v", err)
				}
				if _, err := s.CommitCheck(); err != nil {
					t.Fatalf("CommitCheck rejected metric %q in %s spelling: %v", value, spelling.name, err)
				}
			})
		}
	}
}
