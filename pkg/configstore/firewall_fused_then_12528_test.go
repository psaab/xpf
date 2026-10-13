package configstore

import (
	"strings"
	"testing"
)

func TestFirewallFusedThenRejectedAtStoreBoundary12528(t *testing.T) {
	rows := []struct {
		name string
		load func(*testing.T, *Store) error
	}{
		{"LoadSet", func(t *testing.T, s *Store) error {
			_, err := s.LoadSet("set firewall family inet filter F term T from is-fragment then discard\n" +
				"set firewall family inet filter F term allow then accept\n")
			return err
		}},
		{"LoadOverride", func(t *testing.T, s *Store) error {
			return s.LoadOverride(`firewall { family inet { filter F { term T { from { is-fragment then discard; } } term allow { then accept; } } } }`)
		}},
		{"LoadMerge", func(t *testing.T, s *Store) error {
			return s.LoadMerge(`firewall { family inet { filter F { term T { from { is-fragment { then { discard; } } } } term allow { then accept; } } } }`)
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			loadErr := row.load(t, s)
			if loadErr == nil {
				_, loadErr = s.CommitCheck()
			}
			if loadErr == nil || !strings.Contains(loadErr.Error(), "#12528") {
				t.Fatalf("%s + CommitCheck error = %v, want #12528 refusal", row.name, loadErr)
			}
		})
	}
}
