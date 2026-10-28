package configstore

import (
	"strings"
	"testing"
)

// #16672 acceptance at the operator boundary: both fused orders are
// rejected at Store.Commit, and the separate-statement control still
// commits. LoadOverride feeds the raw parsed tree to Commit, which is
// the channel a hand-edited or migrated config takes.

const rgFused16672Store = `chassis {
    cluster {
        cluster-id 1;
        node 0;
        authentication-key test-cluster-psk-16672;
        no-private-rg-election;
        redundancy-group 1 {
            %s
        }
    }
}`

func TestRGFusedNodePriorityStoreCommit16672(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"node1 then node0", `node 1 priority 100 node 0 priority 200;`},
		{"node0 then node1", `node 0 priority 200 node 1 priority 100;`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			defer s.ExitConfigure()
			text := strings.Replace(rgFused16672Store, "%s", tc.body, 1)
			if err := s.LoadOverride(text); err != nil {
				t.Fatalf("LoadOverride: %v", err)
			}
			if _, err := s.Commit(); err == nil || !strings.Contains(err.Error(), "#16672") {
				t.Fatalf("Store.Commit must reject fused %q with #16672, got: %v", tc.body, err)
			}
		})
	}
	t.Run("separate statements commit", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		defer s.ExitConfigure()
		text := strings.Replace(rgFused16672Store, "%s", `node 1 priority 100; node 0 priority 200;`, 1)
		if err := s.LoadOverride(text); err != nil {
			t.Fatalf("LoadOverride: %v", err)
		}
		if _, err := s.Commit(); err != nil {
			t.Fatalf("separate-statement control must commit: %v", err)
		}
	})
}

// #17820 acceptance at the operator boundary: every RG node statement must
// carry its own explicit priority. The #16672 control above proves that
// separate statements with priorities still commit through Store.Commit.
func TestRGBareNodePriorityStoreCommit17820(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"bare node 0", `node 0;`},
		{"bare node 1", `node 1;`},
		{"bare beside explicit node", `node 1; node 0 priority 200;`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			defer s.ExitConfigure()
			text := strings.Replace(rgFused16672Store, "%s", tc.body, 1)
			if err := s.LoadOverride(text); err != nil {
				t.Fatalf("LoadOverride: %v", err)
			}
			if _, err := s.Commit(); err == nil ||
				!strings.Contains(err.Error(), "#17820") ||
				!strings.Contains(err.Error(), "missing required `priority`") {
				t.Fatalf("Store.Commit must reject bare RG node %q for missing priority (#17820), got: %v", tc.body, err)
			}
		})
	}
}
