package configstore

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12528 at the store boundary: every operator ingress that can author a
// fused is-fragment / flexible-match-range tail must be refused at commit
// with the #12528 diagnostic naming the right term, the position-aware
// controls (Review12678 B2) must still commit, and tolerant boot / peer sync
// must keep booting with one warning per offending term while the typed-leaf
// warning on the same config survives (Review12678 minor 2).

const (
	fusedThenFlag12528   = "`then` follows `from is-fragment`"
	fusedThenFlex12528   = "`then` is written inside `from flexible-match-range`"
	fusedThenPacked12528 = "the packed spelling `from is-fragment ... then ...` compiles"
)

func TestFirewallFusedThenRejectedAtStoreBoundary12528(t *testing.T) {
	rows := []struct {
		name string
		seed string // committed first through LoadOverride + Commit
		load func(*Store) error
		want string
	}{
		{name: "LoadSet flat", want: fusedThenFlag12528, load: func(s *Store) error {
			_, err := s.LoadSet("set firewall family inet filter F term T from is-fragment then discard\n" +
				"set firewall family inet filter F term allow then accept\n")
			return err
		}},
		{name: "interactive set", want: fusedThenFlag12528, load: func(s *Store) error {
			return s.SetFromInput("firewall family inet filter F term T from is-fragment then discard")
		}},
		{name: "LoadOverride braced", want: fusedThenFlag12528, load: func(s *Store) error {
			return s.LoadOverride(`firewall { family inet { filter F { term T { from { is-fragment then discard; } } term allow { then accept; } } } }`)
		}},
		{name: "LoadMerge nested", want: fusedThenFlag12528, load: func(s *Store) error {
			return s.LoadMerge(`firewall { family inet { filter F { term T { from { is-fragment { then { discard; } } } } term allow { then accept; } } } }`)
		}},
		{name: "LoadOverride packed term", want: fusedThenPacked12528, load: func(s *Store) error {
			return s.LoadOverride(`firewall { family inet { filter F { term T from is-fragment then discard; term allow { then accept; } } } }`)
		}},
		{name: "LoadMerge packed term replays fused", want: fusedThenFlag12528, load: func(s *Store) error {
			return s.LoadMerge(`firewall { family inet { filter F { term T from is-fragment then discard; term allow { then accept; } } } }`)
		}},
		{name: "LoadMerge compact from replays fused", want: fusedThenFlag12528, load: func(s *Store) error {
			return s.LoadMerge(`firewall { family inet { filter F { term T { from is-fragment then discard; } term allow { then accept; } } } }`)
		}},
		{name: "LoadOverride flex", want: fusedThenFlex12528, load: func(s *Store) error {
			return s.LoadOverride(`firewall { family inet { filter F { term T { from { flexible-match-range { range R { byte-offset 9; then discard; } } } } term allow { then accept; } } } }`)
		}},
		{name: "LoadSet flex", want: fusedThenFlex12528, load: func(s *Store) error {
			_, err := s.LoadSet("set firewall family inet filter F term T from flexible-match-range range R byte-offset 9\n" +
				"set firewall family inet filter F term T from flexible-match-range range R then discard\n")
			return err
		}},
		{name: "LoadOverride apply-groups", want: fusedThenFlag12528, load: func(s *Store) error {
			return s.LoadOverride(`groups { G { firewall { family inet { filter F { term T { from { is-fragment then discard; } } } } } } } apply-groups G;`)
		}},
		{name: "LoadMerge onto a committed flag", want: fusedThenFlag12528,
			seed: `firewall { family inet { filter F { term T { from { is-fragment; } } term allow { then accept; } } } }`,
			load: func(s *Store) error {
				return s.LoadMerge(`firewall { family inet { filter F { term T { from { is-fragment { then discard; } } } } } }`)
			}},
		{name: "set onto a committed flag", want: fusedThenFlag12528,
			seed: `firewall { family inet { filter F { term T { from { is-fragment; } } term allow { then accept; } } } }`,
			load: func(s *Store) error {
				return s.SetFromInput("firewall family inet filter F term T from is-fragment then discard")
			}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			if row.seed != "" {
				if err := s.LoadOverride(row.seed); err != nil {
					t.Fatalf("seed LoadOverride: %v", err)
				}
				if _, err := s.Commit(); err != nil {
					t.Fatalf("seed Commit: %v", err)
				}
			}
			if err := row.load(s); err != nil {
				t.Fatalf("load: %v", err)
			}
			const where = `firewall family inet filter "F" term "T": `
			_, err := s.CommitCheck()
			if err == nil || !strings.HasPrefix(err.Error(), where+row.want) ||
				!strings.HasSuffix(err.Error(), "(#12528)") {
				t.Fatalf("CommitCheck error = %v, want %q... (#12528)", err, where+row.want)
			}
			if _, err := s.Commit(); err == nil || !strings.Contains(err.Error(), where+row.want) {
				t.Fatalf("Commit error = %v, want the #12528 refusal", err)
			}
		})
	}
}

func TestFirewallFusedThenControlsCommitAtStoreBoundary12528(t *testing.T) {
	rows := []struct {
		name string
		load func(*Store) error
	}{
		{"term named is-fragment", func(s *Store) error {
			return s.LoadOverride(`firewall { family inet { filter F { term is-fragment { from { is-fragment; } then { discard; } } term allow { then accept; } } } }`)
		}},
		{"term named is-fragment quoted", func(s *Store) error {
			return s.LoadOverride(`firewall { family inet6 { filter F { term "is-fragment" { from { is-fragment; } then { discard; } } } } }`)
		}},
		{"term named is-fragment flat", func(s *Store) error {
			_, err := s.LoadSet("set firewall family inet filter F term is-fragment from is-fragment\n" +
				"set firewall family inet filter F term is-fragment then discard\n")
			return err
		}},
		{"filter named is-fragment", func(s *Store) error {
			_, err := s.LoadSet("set firewall family inet filter is-fragment term T from protocol udp\n" +
				"set firewall family inet filter is-fragment term T then discard\n")
			return err
		}},
		{"filter named flexible-match-range quoted", func(s *Store) error {
			return s.LoadOverride(`firewall { family inet { filter "flexible-match-range" { term T { from { protocol udp; } then discard; } } } }`)
		}},
		{"prefix-list named is-fragment", func(s *Store) error {
			return s.LoadOverride(`policy-options { prefix-list is-fragment { 10.0.0.0/8; } } firewall { family inet { filter F { term T { from { source-prefix-list { is-fragment except; } } then { discard; } } } } }`)
		}},
		{"range named then", func(s *Store) error {
			_, err := s.LoadSet("set firewall family inet filter F term T from flexible-match-range range then byte-offset 9\n" +
				"set firewall family inet filter F term T then discard\n")
			return err
		}},
		{"then-first flex", func(s *Store) error {
			return s.LoadOverride(`firewall { family inet { filter F { term T then discard from flexible-match-range range R byte-offset 9; } } }`)
		}},
		{"from is-fragment protocol udp", func(s *Store) error {
			return s.LoadOverride(`firewall { family inet { filter F { term T { from is-fragment protocol udp; then discard; } } } }`)
		}},
		{"from is-fragment destination-port 53", func(s *Store) error {
			return s.LoadOverride(`firewall { family inet { filter F { term T { from is-fragment destination-port 53; then accept; } } } }`)
		}},
		{"bare flag merged", func(s *Store) error {
			return s.LoadMerge(`firewall { family inet { filter F { term T { from { is-fragment; } then { discard; } } } } }`)
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			if err := row.load(s); err != nil {
				t.Fatalf("load: %v", err)
			}
			if _, err := s.CommitCheck(); err != nil {
				t.Fatalf("CommitCheck rejected a valid control: %v", err)
			}
			if _, err := s.Commit(); err != nil {
				t.Fatalf("Commit rejected a valid control: %v", err)
			}
		})
	}

	t.Run("rename a committed term to is-fragment", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		if err := s.LoadOverride(`firewall { family inet { filter F { term ok { from { protocol udp; } then { accept; } } } } }`); err != nil {
			t.Fatalf("LoadOverride: %v", err)
		}
		if _, err := s.Commit(); err != nil {
			t.Fatalf("seed Commit: %v", err)
		}
		term := []string{"firewall", "family", "inet", "filter", "F", "term"}
		if err := s.Rename(append(append([]string(nil), term...), "ok"), append(append([]string(nil), term...), "is-fragment")); err != nil {
			t.Fatalf("Rename: %v", err)
		}
		if _, err := s.CommitCheck(); err != nil {
			t.Fatalf("CommitCheck after rename: %v", err)
		}
	})
}

// A persisted config with a fused tail must still boot (#1960), warn once per
// offending term, and keep the typed-leaf warning the schema walk records for
// the same config: the #12528 check runs in the compiler, after the walk.
func TestFirewallFusedThenTolerantPathsWarn12528(t *testing.T) {
	text := `class-of-service { schedulers { be { transmit-rate asd; } } }
firewall {
    family inet {
        filter F { term T { from { is-fragment then discard; } } term allow { then accept; } }
        filter G { term U { from { flexible-match-range { range R { byte-offset 9; then discard; } } } } }
    }
}`
	count := func(warnings []string) (typed, fused int) {
		for _, w := range warnings {
			if strings.HasPrefix(w, config.ToleratedTypedLeafWarningPrefix) && strings.Contains(w, "transmit-rate") {
				typed++
			}
			if strings.Contains(w, "(#12528)") {
				fused++
			}
		}
		return typed, fused
	}

	tree, errs := config.NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	s := newTestStore(t)
	if err := s.db.WriteActive(tree); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}
	if err := s.Load(); err != nil {
		t.Fatalf("Load must boot a persisted fused tail: %v", err)
	}
	if typed, fused := count(s.ActiveConfig().Warnings); typed != 1 || fused != 2 {
		t.Fatalf("Load warnings: typed-leaf=%d #12528=%d, want 1 and 2: %q",
			typed, fused, s.ActiveConfig().Warnings)
	}

	cfg, err := newTestStore(t).SyncApply(text, nil)
	if err != nil {
		t.Fatalf("SyncApply must accept a peer config with a fused tail: %v", err)
	}
	if typed, fused := count(cfg.Warnings); typed != 1 || fused != 2 {
		t.Fatalf("SyncApply warnings: typed-leaf=%d #12528=%d, want 1 and 2: %q", typed, fused, cfg.Warnings)
	}
}
