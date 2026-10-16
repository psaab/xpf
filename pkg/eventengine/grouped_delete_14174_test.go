package eventengine

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14174: classifyPlan parsed a delete with ParseSetCommand (which discards
// bracket grouping) and applyOnce passed nil grouping to
// DeleteAsGroupedPlantClass. A delete naming an ENTIRE bracketed container
// group — the exact line the interactive CLI accepts via
// DeleteFromInputAsPlantClass (ParseSetCommandGrouped) — therefore
// re-split the wide node at schema arity, reported ErrPathNotFound, and was
// swallowed by the tolerated-missing-delete carve-out: the batch committed
// and counted as success while the configured node survived.
//
// The decisive check builds the grouped-key AST through the normal
// SetFromInputAsPlantClass path, fires an event whose delete text matches
// the interactive CLI delete, and asserts the nodes disappear. The
// ordinary absent-path tolerated rule is preserved by the second test.
func TestGroupedDeleteRemovesBracketedZoneGroup14174(t *testing.T) {
	s := newStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure (seed): %v", err)
	}
	// Build the grouped-key AST via the normal grouped set entry point:
	// one wide node Keys=[security-zone trust dmz] with a host-inbound body.
	if err := s.SetFromInputAsPlantClass("", "", "security zones security-zone [ trust dmz ] host-inbound-traffic system-services ssh"); err != nil {
		t.Fatalf("seed grouped set: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("seed commit: %v", err)
	}
	s.ExitConfigure()

	if zones := s.ActiveConfig().Security.Zones; len(zones) != 2 {
		t.Fatalf("seed zones = %v; want trust+dmz from the bracketed group", zoneNames14174(zones))
	}

	pol := &config.EventPolicy{
		Name:   "p",
		Events: []string{"ping_test_failed"},
		ThenCommands: []string{
			"delete security zones security-zone [ trust dmz ]",
			"set system domain-name applied",
		},
	}
	e := New(s, nil)
	defer e.Close()
	applyPolicies9984(e, []*config.EventPolicy{pol})

	e.HandleEvent(eventFor("ping_test_failed"))

	waitFor(t, "committed counter", func() bool { return e.Stats().Committed >= 1 })

	active := s.ActiveConfig()
	if len(active.Security.Zones) != 0 {
		t.Fatalf("zones survive grouped delete: %v; the bracketed delete "+
			"was missed (nil grouping) and swallowed as a tolerated "+
			"missing delete (#14174)", zoneNames14174(active.Security.Zones))
	}
	if active.System.DomainName != "applied" {
		t.Fatalf("domain-name=%q; trailing set must commit with the delete", active.System.DomainName)
	}
	if got := e.Stats().Rejected; got != 0 {
		t.Fatalf("Rejected=%d; grouped delete of an existing node must not reject", got)
	}
}

// #14174: the ordinary absent-path tolerated rule must survive the fix —
// a grouped delete of a bracketed group that was never configured is still
// a tolerated missing delete, not a batch abort.
func TestGroupedDeleteAbsentGroupStillTolerated14174(t *testing.T) {
	s := newStore(t)
	pol := &config.EventPolicy{
		Name:   "p",
		Events: []string{"ping_test_failed"},
		ThenCommands: []string{
			"delete security zones security-zone [ trust dmz ]",
			"set system host-name still-commits",
		},
	}
	e := New(s, nil)
	defer e.Close()
	applyPolicies9984(e, []*config.EventPolicy{pol})

	e.HandleEvent(eventFor("ping_test_failed"))

	waitFor(t, "committed counter", func() bool { return e.Stats().Committed >= 1 })

	if got := s.ActiveConfig().System.HostName; got != "still-commits" {
		t.Fatalf("host-name=%q; absent grouped delete must be tolerated and the batch commit", got)
	}
	if got := e.Stats().Rejected; got != 0 {
		t.Fatalf("Rejected=%d; absent grouped delete must not reject the batch", got)
	}
}

func zoneNames14174(zones map[string]*config.ZoneConfig) []string {
	names := make([]string, 0, len(zones))
	for name := range zones {
		names = append(names, name)
	}
	return names
}
