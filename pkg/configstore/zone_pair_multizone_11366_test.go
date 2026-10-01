package configstore

import (
	"strings"
	"testing"
)

const groupedZonePairSetScript11366 = `set security zones security-zone A
set security zones security-zone B
set security zones security-zone C
set security policies from-zone A to-zone [ B C ] policy p1 match source-address any
set security policies from-zone A to-zone [ B C ] policy p1 match destination-address any
set security policies from-zone A to-zone [ B C ] policy p1 match application any
set security policies from-zone A to-zone [ B C ] policy p1 then permit
`

const groupedZonePairHierarchical11366 = `security {
    zones {
        security-zone A;
        security-zone B;
        security-zone C;
    }
    policies {
        from-zone A to-zone [ B C ] {
            policy p1 {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { permit; }
            }
        }
    }
}
`

func assertZonePairListRejected11366(t *testing.T, s *Store, channel string) {
	t.Helper()
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"CommitCheck", func() error { _, err := s.CommitCheck(); return err }},
		{"Commit", func() error { _, err := s.Commit(); return err }},
	} {
		if err := tc.call(); err == nil ||
			!strings.Contains(err.Error(), "to-zone") ||
			!strings.Contains(err.Error(), "bracketed") {
			t.Errorf("%s %s must reject grouped to-zone lists with a clear cause, got %v", channel, tc.name, err)
		}
	}
}

func TestGroupedZonePairListStrictStoreChannels11366(t *testing.T) {
	for _, channel := range []struct {
		name   string
		ingest func(*Store) error
	}{
		{"SetFromInput", func(s *Store) error {
			for _, command := range strings.Split(strings.TrimSpace(groupedZonePairSetScript11366), "\n") {
				if err := s.SetFromInput(strings.TrimPrefix(command, "set ")); err != nil {
					return err
				}
			}
			return nil
		}},
		{"LoadSet", func(s *Store) error {
			_, err := s.LoadSet(groupedZonePairSetScript11366)
			return err
		}},
		{"LoadOverride-flat", func(s *Store) error {
			return s.LoadOverride(groupedZonePairSetScript11366)
		}},
		{"LoadOverride-hierarchical", func(s *Store) error {
			return s.LoadOverride(groupedZonePairHierarchical11366)
		}},
	} {
		t.Run(channel.name, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			if err := channel.ingest(s); err != nil {
				t.Fatalf("%s ingest: %v", channel.name, err)
			}
			assertZonePairListRejected11366(t, s, channel.name)
		})
	}
}

func TestGroupedZonePairListPeerSyncWarnsAndQuarantines11366(t *testing.T) {
	s := newTestStore(t)
	cfg, err := s.SyncApply(groupedZonePairHierarchical11366, nil)
	if err != nil {
		t.Fatalf("peer-sync must remain bootable on the tolerant path: %v", err)
	}
	var warned bool
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "to-zone") && strings.Contains(warning, "bracketed") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("peer-sync must warn about the rejected zone list, got %v", cfg.Warnings)
	}
	if len(cfg.Security.Policies) != 0 {
		t.Fatalf("peer-sync must not partially compile one zone from the rejected list: %+v", cfg.Security.Policies)
	}
}
