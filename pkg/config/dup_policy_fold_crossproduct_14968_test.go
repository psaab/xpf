package config

import (
	"strings"
	"testing"
)

// #14968 (D30-02) — the tolerant #8752 duplicate-policy fold must not only
// refuse a restrictive statement turned into a permit (#9571); it must also
// refuse folds whose merged MATCH or SCHEDULER semantics are not the union
// of the statements:
//
//   - cross-product permit widening: two permit statements that differ in
//     two or more match dimensions fold into source-union x dest-union x
//     application-union, permitting source/destination combinations no
//     statement permitted;
//   - excluded-set deny disarming: an excluded-address flag/list authored
//     on one statement is OR-ed/unioned onto the merged policy, so a deny
//     that survives the fold matches the complement of the union and no
//     longer covers traffic its own statement denied;
//   - scheduler narrowing: a scheduler-name authored on one statement is
//     inherited by the merged policy, so an unconditional deny that
//     survives the fold is only active inside another statement's window.
//
// All three compile today to one unpoisoned policy on the tolerant path.

const sched14968 = `schedulers { scheduler narrow { daily { start-time 09:00; stop-time 17:00; } } } `

func TestFoldCrossProductPermitIsRefused14968(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"zone-pair cross product", zonePairText9571(
			`policy p1 { match { source-address 10.0.1.0/25; destination-address 192.0.2.0/25; application any; } then { permit; } } ` +
				`policy p1 { match { source-address 10.0.2.0/25; destination-address 198.51.100.0/25; application any; } then { permit; } }`)},
		{"global cross product", globalText9571(
			`policy p1 { match { source-address 10.0.1.0/25; destination-address 192.0.2.0/25; application any; } then { permit; } } ` +
				`policy p1 { match { source-address 10.0.2.0/25; destination-address 198.51.100.0/25; application any; } then { permit; } }`)},
		{"cross product in source and application", zonePairText9571(
			`policy p1 { match { source-address 10.0.1.0/25; destination-address any; application junos-http; } then { permit; } } ` +
				`policy p1 { match { source-address 10.0.2.0/25; destination-address any; application junos-https; } then { permit; } }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, entry := range lenientEntries9571 {
				cfg, err := entry.compile(parse9571(t, tc.text))
				if err != nil {
					t.Fatalf("%s must accept the persisted duplicate (#1960): %v", entry.label, err)
				}
				pols := policies9571(cfg)
				if len(pols) != 1 {
					t.Fatalf("%s: want duplicate folded into one policy, got %d", entry.label, len(pols))
				}
				if pols[0].Action != PolicyPermit {
					t.Fatalf("%s: fixture premise broken: merged action = %v, want permit", entry.label, pols[0].Action)
				}
				if !pols[0].LenientContentDropped {
					t.Errorf("%s: #14968: fold permits source/destination combinations no statement "+
						"permitted (cross product of the statements' match dimensions) and nothing poisons it", entry.label)
				}
				if LenientDroppedPolicyLocator(cfg) == "" {
					t.Errorf("%s: poisoned cross-product fold is invisible to the fail-closed locator", entry.label)
				}
			}
		})
	}
}

func TestFoldExcludedSetDenyDisarmingIsRefused14968(t *testing.T) {
	text := zonePairText9571(
		`policy p1 { match { source-address 10.0.99.0/24; source-address-excluded; destination-address any; application any; } then { permit; } } ` +
			`policy p1 { match { source-address any; destination-address any; application any; } then { deny; } }`)
	for _, entry := range lenientEntries9571 {
		cfg, err := entry.compile(parse9571(t, text))
		if err != nil {
			t.Fatalf("%s must accept the persisted duplicate (#1960): %v", entry.label, err)
		}
		pols := policies9571(cfg)
		if len(pols) != 1 {
			t.Fatalf("%s: want duplicate folded into one policy, got %d", entry.label, len(pols))
		}
		if pols[0].Action != PolicyDeny {
			t.Fatalf("%s: fixture premise broken: merged action = %v, want deny", entry.label, pols[0].Action)
		}
		if !pols[0].Match.SourceAddressExcluded {
			t.Fatalf("%s: fixture premise broken: merged deny did not inherit the excluded flag: %+v", entry.label, pols[0].Match)
		}
		if !pols[0].LenientContentDropped {
			t.Errorf("%s: #14968: merged deny inherited another statement's excluded set, so it no "+
				"longer covers the traffic its own statement denied, and nothing poisons it", entry.label)
		}
	}
}

func TestFoldSchedulerNarrowedDenyIsRefused14968(t *testing.T) {
	text := sched14968 + zonePairText9571(
		`policy p1 { `+anyMatch9571+` then { permit; } scheduler-name narrow; } `+
			`policy p1 { `+anyMatch9571+` then { deny; } }`)
	for _, entry := range lenientEntries9571 {
		cfg, err := entry.compile(parse9571(t, text))
		if err != nil {
			t.Fatalf("%s must accept the persisted duplicate (#1960): %v", entry.label, err)
		}
		pols := policies9571(cfg)
		if len(pols) != 1 {
			t.Fatalf("%s: want duplicate folded into one policy, got %d", entry.label, len(pols))
		}
		if pols[0].Action != PolicyDeny || pols[0].SchedulerName != "narrow" {
			t.Fatalf("%s: fixture premise broken: merged action=%v scheduler=%q, want deny gated by narrow",
				entry.label, pols[0].Action, pols[0].SchedulerName)
		}
		if !pols[0].LenientContentDropped {
			t.Errorf("%s: #14968: unconditional deny inherited another statement's scheduler-name, "+
				"so it is inactive outside that window, and nothing poisons it", entry.label)
		}
	}
}

// Controls: folds whose merged match/scheduler semantics ARE the union of
// the statements stay merged and unpoisoned (#8752/#9571 behaviour).
func TestFoldCrossProductControlsStayUnpoisoned14968(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"permit pair differing only in source", zonePairText9571(
			`policy p1 { match { source-address 10.0.1.0/25; destination-address any; application any; } then { permit; } } ` +
				`policy p1 { match { source-address 10.0.1.128/25; destination-address any; application any; } then { permit; } }`)},
		{"permit pair differing only in destination", zonePairText9571(
			`policy p1 { match { source-address any; destination-address 192.0.2.0/25; application any; } then { permit; } } ` +
				`policy p1 { match { source-address any; destination-address 198.51.100.0/25; application any; } then { permit; } }`)},
		{"permit subset of an any permit", zonePairText9571(
			`policy p1 { ` + anyMatch9571 + ` then { permit; } } ` +
				`policy p1 { match { source-address 10.0.1.0/25; destination-address 192.0.2.0/25; application any; } then { permit; } }`)},
		{"identical excluded deny pair", zonePairText9571(
			`policy p1 { match { source-address 10.0.99.0/24; source-address-excluded; destination-address any; application any; } then { deny; } } ` +
				`policy p1 { match { source-address 10.0.99.0/24; source-address-excluded; destination-address any; application any; } then { deny; } }`)},
		{"same-scheduler permit then deny", sched14968 + zonePairText9571(
			`policy p1 { `+anyMatch9571+` then { permit; } scheduler-name narrow; } `+
				`policy p1 { `+anyMatch9571+` then { deny; } scheduler-name narrow; }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, entry := range lenientEntries9571 {
				cfg, err := entry.compile(parse9571(t, tc.text))
				if err != nil {
					t.Fatalf("%s: %v", entry.label, err)
				}
				pols := policies9571(cfg)
				if len(pols) != 1 {
					t.Fatalf("%s: want one folded policy, got %d", entry.label, len(pols))
				}
				if pols[0].LenientContentDropped {
					t.Errorf("%s: #14968 over-rejection: semantics-preserving fold poisoned policy %q", entry.label, pols[0].Name)
				}
				if strings.Contains(strings.Join(cfg.Warnings, "\n"), "#14968") {
					t.Errorf("%s: semantics-preserving fold warned #14968: %v", entry.label, cfg.Warnings)
				}
			}
		})
	}
}
