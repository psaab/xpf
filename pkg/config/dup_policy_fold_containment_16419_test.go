package config

import (
	"strings"
	"testing"
)

// #16419 (R3-F03-04) — the #14968 cross-product predicate exempted any
// dimension in which one statement's value set contains the other's,
// claiming the wider statement already permits every merged tuple. That
// holds per dimension but not for the tuple: when the statements trade
// narrow and wide dimensions, the merged permit covers the cross product.
//
// Defect rows (must be poisoned): p1 permits ssh from 10.0.1.0/25 and http
// from any; the fold permits ssh from any, a tuple neither statement
// permitted. The same trade in any pair of dimensions (including a global
// policy's zone scope) must poison, as must a scheduler-gated permit
// folded with an unconditional one and a permit whose excluded-address
// sense differs from another permit statement.
//
// Controls (stay unpoisoned): a permit pair differing in at most one
// dimension, and a pair where one statement dominates the other in every
// dimension (its permitted set already contains the other's).

func TestFoldContainedCrossProductPermitIsRefused16419(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"zone-pair source-contained x application-disjoint (issue example)", zonePairText9571(
			`policy p1 { match { source-address 10.0.1.0/25; destination-address any; application junos-ssh; } then { permit; } } ` +
				`policy p1 { match { source-address any; destination-address any; application junos-http; } then { permit; } }`)},
		{"zone-pair source-superset x destination-disjoint", zonePairText9571(
			`policy p1 { match { source-address any; destination-address 192.0.2.0/25; application any; } then { permit; } } ` +
				`policy p1 { match { source-address 10.0.1.0/25; destination-address 198.51.100.0/25; application any; } then { permit; } }`)},
		{"zone-pair destination-contained x application-disjoint", zonePairText9571(
			`policy p1 { match { source-address any; destination-address 192.0.2.0/25; application junos-ssh; } then { permit; } } ` +
				`policy p1 { match { source-address any; destination-address any; application junos-http; } then { permit; } }`)},
		{"global source-contained x application-disjoint", globalText9571(
			`policy p1 { match { source-address 10.0.1.0/25; destination-address any; application junos-ssh; } then { permit; } } ` +
				`policy p1 { match { source-address any; destination-address any; application junos-http; } then { permit; } }`)},
		{"global from-zone-contained x source-disjoint", globalText9571(
			`policy p1 { match { from-zone trust; source-address 10.0.1.0/25; destination-address any; application any; } then { permit; } } ` +
				`policy p1 { match { from-zone any; source-address 10.0.2.0/25; destination-address any; application any; } then { permit; } }`)},
		{"global to-zone-contained x application-disjoint", globalText9571(
			`policy p1 { match { to-zone trust; source-address any; destination-address any; application junos-ssh; } then { permit; } } ` +
				`policy p1 { match { to-zone any; source-address any; destination-address any; application junos-http; } then { permit; } }`)},
		{"global wider-zone permit x disjoint source", globalText9571(
			`policy p1 { match { from-zone [ trust untrust ]; source-address 10.0.1.0/25; destination-address any; application any; } then { permit; } } ` +
				`policy p1 { match { from-zone trust; source-address 10.0.2.0/25; destination-address any; application any; } then { permit; } }`)},
		{"zone-pair application-contained x source-disjoint (set form)", zonePairText9571(
			`policy p1 { match { source-address 10.0.1.0/25; destination-address any; application [ junos-ssh junos-http ]; } then { permit; } } ` +
				`policy p1 { match { source-address 10.0.2.0/25; destination-address any; application junos-https; } then { permit; } }`)},
		{"zone-pair empty source (universal) x application-disjoint", zonePairText9571(
			`policy p1 { match { destination-address any; application junos-ssh; } then { permit; } } ` +
				`policy p1 { match { source-address 10.0.1.0/25; destination-address any; application junos-http; } then { permit; } }`)},
		{"zone-pair scheduler-gated permit x unconditional permit", sched14968 + zonePairText9571(
			`policy p1 { match { source-address 10.0.1.0/25; destination-address any; application any; } then { permit; } scheduler-name narrow; } `+
				`policy p1 { match { source-address 10.0.2.0/25; destination-address any; application any; } then { permit; } }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, entry := range lenientEntries9571 {
				cfg, err := entry.compile(parseHierText(t, tc.text))
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
					t.Errorf("%s: #16419: fold permits tuples no statement permitted "+
						"(statements trade narrow/wide dimensions, so the dimension-wise union is a strict cross product) "+
						"and nothing poisons it; merged=%+v scheduler=%q", entry.label, pols[0].Match, pols[0].SchedulerName)
				}
				if LenientDroppedPolicyLocator(cfg) == "" {
					t.Errorf("%s: poisoned containment cross-product fold is invisible to the fail-closed locator", entry.label)
				}
			}
		})
	}
}

func TestFoldPermitExcludedSenseMismatchIsRefused16419(t *testing.T) {
	text := zonePairText9571(
		`policy p1 { match { source-address 10.0.99.0/24; source-address-excluded; destination-address any; application any; } then { permit; } } ` +
			`policy p1 { match { source-address 10.0.1.0/25; destination-address any; application any; } then { permit; } }`)
	for _, entry := range lenientEntries9571 {
		cfg, err := entry.compile(parseHierText(t, text))
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
		if !pols[0].Match.SourceAddressExcluded {
			t.Fatalf("%s: fixture premise broken: merged permit did not inherit the excluded flag: %+v", entry.label, pols[0].Match)
		}
		if !pols[0].LenientContentDropped {
			t.Errorf("%s: #16419: merged permit inherited another statement's excluded sense, so it permits "+
				"sources that statement carved out, and nothing poisons it; merged=%+v", entry.label, pols[0].Match)
		}
	}
}

func TestFoldContainmentControlsStayUnpoisoned16419(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"src-equal app-differ (exact union)", zonePairText9571(
			`policy p1 { match { source-address 10.0.1.0/25; destination-address any; application junos-ssh; } then { permit; } } ` +
				`policy p1 { match { source-address 10.0.1.0/25; destination-address any; application junos-http; } then { permit; } }`)},
		{"dominating any permit plus narrow permit", zonePairText9571(
			`policy p1 { ` + anyMatch9571 + ` then { permit; } } ` +
				`policy p1 { match { source-address 10.0.1.0/25; destination-address 192.0.2.0/25; application junos-ssh; } then { permit; } }`)},
		{"dominating permit with superset dimensions", zonePairText9571(
			`policy p1 { match { source-address [ 10.0.1.0/25 10.0.2.0/25 ]; destination-address any; application [ junos-ssh junos-http ]; } then { permit; } } ` +
				`policy p1 { match { source-address 10.0.1.0/25; destination-address any; application junos-ssh; } then { permit; } }`)},
		{"containment in one dimension only, equal elsewhere", zonePairText9571(
			`policy p1 { match { source-address any; destination-address any; application junos-ssh; } then { permit; } } ` +
				`policy p1 { match { source-address 10.0.1.0/25; destination-address any; application junos-ssh; } then { permit; } }`)},
		{"global dominating zone-scoped permit", globalText9571(
			`policy p1 { match { from-zone any; source-address any; destination-address any; application any; } then { permit; } } ` +
				`policy p1 { match { from-zone trust; source-address 10.0.1.0/25; destination-address any; application junos-ssh; } then { permit; } }`)},
		{"same-scheduler contained permit pair", sched14968 + zonePairText9571(
			`policy p1 { match { source-address any; destination-address any; application junos-ssh; } then { permit; } scheduler-name narrow; } `+
				`policy p1 { match { source-address 10.0.1.0/25; destination-address any; application junos-ssh; } then { permit; } scheduler-name narrow; }`)},
		{"identical excluded permit pair", zonePairText9571(
			`policy p1 { match { source-address 10.0.99.0/24; source-address-excluded; destination-address any; application any; } then { permit; } } ` +
				`policy p1 { match { source-address 10.0.99.0/24; source-address-excluded; destination-address any; application any; } then { permit; } }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, entry := range lenientEntries9571 {
				cfg, err := entry.compile(parseHierText(t, tc.text))
				if err != nil {
					t.Fatalf("%s: %v", entry.label, err)
				}
				pols := policies9571(cfg)
				if len(pols) != 1 {
					t.Fatalf("%s: want one folded policy, got %d", entry.label, len(pols))
				}
				if pols[0].LenientContentDropped {
					t.Errorf("%s: #16419 over-rejection: semantics-preserving fold poisoned policy %q", entry.label, pols[0].Name)
				}
				if strings.Contains(strings.Join(cfg.Warnings, "\n"), "#14968") {
					t.Errorf("%s: semantics-preserving fold warned #14968: %v", entry.label, cfg.Warnings)
				}
			}
		})
	}
}
