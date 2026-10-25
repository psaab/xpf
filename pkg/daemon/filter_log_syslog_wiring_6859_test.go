package daemon

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/logging"
)

// filter_log_syslog_wiring_6859_test.go — #6859, the WIRING.
//
// The routing gate in pkg/logging and the projection in pkg/dataplane/userspace
// are both inert until applySyslogConfig actually installs the map on the event
// reader. Deleting that ONE assignment leaves every cell in those two packages
// green while `then log` goes back to being forwarded off-box — the map stays
// nil, and nil is (deliberately) the legacy fan-out.
//
// So the assignment is bound behaviourally here: drive the production apply and
// read back what the event reader ended up holding.

// filterCfg6859 builds a config with a syslog stream and two filter terms in one
// filter: term 0 `then log` (must NOT reach syslog) and term 1 `then syslog`
// (must). Two terms in one filter is the smallest shape that can distinguish a
// correct projection from one that answers the same for every term.
func filterCfg6859() *config.Config {
	cfg := &config.Config{}
	cfg.Security.Log.Mode = "stream"
	cfg.Security.Log.Streams = map[string]*config.SyslogStream{
		"s1": {Name: "s1", Host: "127.0.0.1", Port: 514},
	}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"WATCH": {
			Name: "WATCH",
			Terms: []*config.FirewallFilterTerm{
				{Name: "log-only", Log: true},
				{Name: "syslog-too", Log: true, Syslog: true},
			},
		},
	}
	return cfg
}

// TestApplySyslogConfigWiresTheFilterTermSyslogMap6859 is the wiring cell.
//
// FAIL-ON-REVERT: delete the er.SetFilterTermSyslog(...) line in
// daemon_system.go and this reds — the map stays nil.
func TestApplySyslogConfigWiresTheFilterTermSyslogMap6859(t *testing.T) {
	er := logging.NewEventReader(nil, logging.NewEventBuffer(4))
	if er.FilterTermSyslog() != nil {
		t.Fatal("precondition: a fresh event reader must hold NO map (nil = legacy fan-out)")
	}

	d := &Daemon{}
	d.applySyslogConfig(er, filterCfg6859())

	got := er.FilterTermSyslog()
	if got == nil {
		t.Fatal("applySyslogConfig did not install the #6859 filter-term syslog map — " +
			"the map stays nil, which is the LEGACY fan-out, so `then log` hits keep " +
			"going off-box with every routing test still green")
	}
	// Term 1 (`then syslog`) may forward; term 0 (`then log`) may not. Asserting
	// both directions is what makes this a projection check and not just a
	// not-nil check.
	if !got[logging.FilterTermSyslogKey(0, 1)] {
		t.Fatalf("the `then syslog` term (filter 0, term 1) is absent from the "+
			"installed map, so its hits would be suppressed: %v", got)
	}
	if got[logging.FilterTermSyslogKey(0, 0)] {
		t.Fatalf("the `then log` term (filter 0, term 0) is marked syslog-eligible, "+
			"so its hits would still go off-box: %v", got)
	}
}

// TestApplySyslogConfigBindsFilterTermSyslogGeneration16775 pins #16775:
// when an apply result with a generation is present, applySyslogConfig
// installs the projection generation-bound; a deferred publish keeps the
// previous generation's map until the publish lands.
func TestApplySyslogConfigBindsFilterTermSyslogGeneration16775(t *testing.T) {
	er := logging.NewEventReader(nil, logging.NewEventBuffer(4))
	dp := &runtimeOnlyApplyTestDP{applyResult: &dataplane.ApplyResult{}}
	d := &Daemon{}
	d.setDataplane(dp)
	if _, err := dp.ApplyConfig(context.Background(), filterCfg6859()); err != nil {
		t.Fatal(err)
	}
	publishedGen := dp.LastApplyResult().Generation
	if publishedGen == 0 {
		t.Fatal("fake did not publish a generation")
	}
	d.applySyslogConfig(er, filterCfg6859())
	gen, set := er.FilterTermSyslogGeneration()
	if !set || gen != publishedGen {
		t.Fatalf("FilterTermSyslogGeneration = %d,%v; want %d,true (map not generation-bound at publish)", gen, set, publishedGen)
	}
	if !er.FilterTermSyslog()[logging.FilterTermSyslogKey(0, 1)] {
		t.Fatal("generation-bound map lost the `then syslog` term")
	}
	// Deferred completion with no store is a no-op (previous map retained).
	d.eventReader = er
	d.installDeferredFilterTermSyslog(publishedGen + 1)
	gen, set = er.FilterTermSyslogGeneration()
	if !set || gen != publishedGen {
		t.Fatalf("deferred completion without store changed generation to %d,%v; want retained %d,true", gen, set, publishedGen)
	}
}

// TestApplySyslogConfigInstallsAnEmptyMapNotNil6859 pins the case that a naive
// "only wire it when there is something to wire" guard would get wrong.
//
// A config whose filters were all REMOVED must install an empty NON-nil map. If
// it installed nil instead, the reader would fall back to the legacy fan-out and
// resume forwarding under the removed terms' ids — the exact stale-routing bug
// the nil/empty distinction exists to prevent.
func TestApplySyslogConfigInstallsAnEmptyMapNotNil6859(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Log.Mode = "stream"
	cfg.Security.Log.Streams = map[string]*config.SyslogStream{
		"s1": {Name: "s1", Host: "127.0.0.1", Port: 514},
	}
	// No filters at all.

	er := logging.NewEventReader(nil, logging.NewEventBuffer(4))
	d := &Daemon{}
	d.applySyslogConfig(er, cfg)

	got := er.FilterTermSyslog()
	if got == nil {
		t.Fatal("a config with no filters installed a NIL map, which restores the " +
			"pre-#6859 fan-out; it must install an empty non-nil map so the gate " +
			"stays active")
	}
	if len(got) != 0 {
		t.Fatalf("a config with no filters produced a non-empty map: %v", got)
	}
}

// TestFilterTermSyslogMapAgreesWithTheSnapshot6859 binds the projection to the
// snapshot ORDERING rather than to a hand-written literal.
//
// The ids in a filter-log event are positional indices into the snapshot the
// dataplane received. Pinning "WATCH term 1 == key(0,1)" as a literal would
// encode which side of that pairing I trust, and would keep passing if the
// snapshot ordering changed underneath. This walks the snapshot itself and
// asserts the map agrees with it at every position — so a reordering reds here
// instead of silently mis-routing one term's hits under another's spelling.
func TestFilterTermSyslogMapAgreesWithTheSnapshot6859(t *testing.T) {
	cfg := filterCfg6859()
	// A second filter, so the FILTER index is exercised too and not just term 0.
	cfg.Firewall.FiltersInet["AAA-FIRST"] = &config.FirewallFilter{
		Name: "AAA-FIRST",
		Terms: []*config.FirewallFilterTerm{
			{Name: "a1", Log: true, Syslog: true},
		},
	}

	snaps := dpuserspace.BuildFirewallFilterSnapshots(cfg)
	if len(snaps) < 2 {
		t.Fatalf("fixture degenerated: expected >= 2 filters in the snapshot, got %d", len(snaps))
	}
	got := dpuserspace.FilterTermSyslogMap(cfg)

	var syslogTerms int
	for fi, f := range snaps {
		for ti, term := range f.Terms {
			key := logging.FilterTermSyslogKey(uint32(fi), uint32(ti))
			if term.Syslog {
				syslogTerms++
				if !got[key] {
					t.Fatalf("snapshot filter %d (%s) term %d (%s) carries syslog, but the "+
						"map does not — its hits would be wrongly suppressed",
						fi, f.Name, ti, term.Name)
				}
				continue
			}
			if got[key] {
				t.Fatalf("snapshot filter %d (%s) term %d (%s) does NOT carry syslog, but "+
					"the map says it may forward — its hits would still go off-box",
					fi, f.Name, ti, term.Name)
			}
		}
	}
	// Guard the guard: if the fixture ever compiled to zero syslog terms, every
	// assertion above would be vacuously satisfied by an all-false map.
	if syslogTerms == 0 {
		t.Fatal("fixture degenerated: no `then syslog` terms in the snapshot, so the " +
			"agreement above proved nothing")
	}
	if len(got) != syslogTerms {
		t.Fatalf("map holds %d entries for %d syslog terms — it carries keys for "+
			"terms the snapshot does not have: %v", len(got), syslogTerms, got)
	}
}
