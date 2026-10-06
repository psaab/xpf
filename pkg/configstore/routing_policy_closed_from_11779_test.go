package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func assertClosedPolicyList11779(t *testing.T, s *Store) {
	t.Helper()
	cfg, err := config.CompileConfig(s.candidate)
	if err != nil {
		t.Fatalf("strict compile rejected a closed routing-policy list: %v", err)
	}
	term := cfg.PolicyOptions.PolicyStatements["P"].Terms[0]
	if got, want := strings.Join(term.PrefixList, ","), "PL1,then"; got != want {
		t.Fatalf("from prefix-list = %q, want %q", got, want)
	}
}

func TestClosedRoutingPolicyFromListSurvivesStoreIngress11779(t *testing.T) {
	commands := []string{
		"policy-options prefix-list PL1 10.0.0.0/8",
		"policy-options prefix-list then 192.0.2.0/24",
		"policy-options policy-statement P term T from prefix-list [ PL1 then ]",
	}

	t.Run("SetFromInput", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		for _, command := range commands {
			if err := s.SetFromInput(command); err != nil {
				t.Fatalf("SetFromInput(%q): %v", command, err)
			}
		}
		assertClosedPolicyList11779(t, s)
	})

	t.Run("LoadSet", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		lines := make([]string, len(commands))
		for i, command := range commands {
			lines[i] = "set " + command
		}
		if _, err := s.LoadSet(strings.Join(lines, "\n") + "\n"); err != nil {
			t.Fatalf("LoadSet: %v", err)
		}
		assertClosedPolicyList11779(t, s)
	})
}
