package config

import (
	"strings"
	"testing"
)

// #16418 (R3-F03-03) — the #14968 fold-semantics guard ignores a global
// policy's from-zone/to-zone match dimensions. FromZones/ToZones are match
// predicates of a global policy (empty or "any" = all zones), so:
//   - cross-zone permit widening: two permit statements differing in
//     from-zone AND source fold into from=[trust untrust] src=[a b],
//     permitting (trust,b) and (untrust,a) no statement permitted;
//   - scoped+unscoped deny narrowing: a deny scoped to from=[trust]
//     folded with an unscoped (all-zones) deny compiles zone slices by
//     union, so the surviving deny keeps only [trust] and traffic the
//     unscoped statement denied from other zones is no longer denied.
//
// Controls (stay unpoisoned): permit pair differing only in from-zone
// (one dimension), a permit pair whose wider zone scope contains the
// other's differing only in source, and deny pairs whose merged scope
// contains every restrictive statement's scope.

func globalPolicies16418(cfg *Config) []*Policy { return cfg.Security.GlobalPolicies }

func TestFoldGlobalZonePermitCrossProductIsRefused16418(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"from-zone x source", globalText9571(
			`policy p1 { match { from-zone trust; source-address 10.0.1.0/25; destination-address any; application any; } then { permit; } } ` +
				`policy p1 { match { from-zone untrust; source-address 10.0.2.0/25; destination-address any; application any; } then { permit; } }`)},
		{"to-zone x source", globalText9571(
			`policy p1 { match { to-zone trust; source-address 10.0.1.0/25; destination-address any; application any; } then { permit; } } ` +
				`policy p1 { match { to-zone untrust; source-address 10.0.2.0/25; destination-address any; application any; } then { permit; } }`)},
		{"from-zone x destination", globalText9571(
			`policy p1 { match { from-zone trust; source-address any; destination-address 192.0.2.0/25; application any; } then { permit; } } ` +
				`policy p1 { match { from-zone untrust; source-address any; destination-address 198.51.100.0/25; application any; } then { permit; } }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, entry := range lenientEntries9571 {
				cfg, err := entry.compile(parseHierText(t, tc.text))
				if err != nil {
					t.Fatalf("%s must accept the persisted duplicate (#1960): %v", entry.label, err)
				}
				pols := globalPolicies16418(cfg)
				if len(pols) != 1 {
					t.Fatalf("%s: want duplicate folded into one policy, got %d", entry.label, len(pols))
				}
				if pols[0].Action != PolicyPermit {
					t.Fatalf("%s: fixture premise broken: merged action = %v, want permit", entry.label, pols[0].Action)
				}
				if !pols[0].LenientContentDropped {
					t.Errorf("%s: #16418: fold permits (zone,address) combinations no statement permitted "+
						"(cross product of zone scope and address dimensions) and nothing poisons it; merged=%+v", entry.label, pols[0].Match)
				}
				if LenientDroppedPolicyLocator(cfg) == "" {
					t.Errorf("%s: poisoned zone cross-product fold is invisible to the fail-closed locator", entry.label)
				}
			}
		})
	}
}

func TestFoldGlobalZoneScopedDenyNarrowingIsRefused16418(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"scoped deny then unscoped deny", globalText9571(
			`policy p1 { match { from-zone trust; source-address 10.0.1.0/25; destination-address any; application any; } then { deny; } } ` +
				`policy p1 { match { source-address 10.0.2.0/25; destination-address any; application any; } then { deny; } }`)},
		{"unscoped deny then scoped deny", globalText9571(
			`policy p1 { match { source-address 10.0.2.0/25; destination-address any; application any; } then { deny; } } ` +
				`policy p1 { match { from-zone trust; source-address 10.0.1.0/25; destination-address any; application any; } then { deny; } }`)},
		{"to-zone scoped plus unscoped deny", globalText9571(
			`policy p1 { match { to-zone trust; source-address 10.0.1.0/25; destination-address any; application any; } then { deny; } } ` +
				`policy p1 { match { source-address 10.0.2.0/25; destination-address any; application any; } then { deny; } }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, entry := range lenientEntries9571 {
				cfg, err := entry.compile(parseHierText(t, tc.text))
				if err != nil {
					t.Fatalf("%s must accept the persisted duplicate (#1960): %v", entry.label, err)
				}
				pols := globalPolicies16418(cfg)
				if len(pols) != 1 {
					t.Fatalf("%s: want duplicate folded into one policy, got %d", entry.label, len(pols))
				}
				if pols[0].Action != PolicyDeny {
					t.Fatalf("%s: fixture premise broken: merged action = %v, want deny", entry.label, pols[0].Action)
				}
				if !pols[0].LenientContentDropped {
					t.Errorf("%s: #16418: surviving deny's zone scope is narrower than a restrictive "+
						"statement's scope, so it no longer denies what that statement denied, and nothing poisons it; merged=%+v", entry.label, pols[0].Match)
				}
			}
		})
	}
}

func TestFoldGlobalZoneControlsStayUnpoisoned16418(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"permit pair differing only in from-zone", globalText9571(
			`policy p1 { match { from-zone trust; source-address 10.0.1.0/25; destination-address any; application any; } then { permit; } } ` +
				`policy p1 { match { from-zone untrust; source-address 10.0.1.0/25; destination-address any; application any; } then { permit; } }`)},
		{"permit pair differing only in to-zone", globalText9571(
			`policy p1 { match { to-zone trust; source-address 10.0.1.0/25; destination-address any; application any; } then { permit; } } ` +
				`policy p1 { match { to-zone untrust; source-address 10.0.1.0/25; destination-address any; application any; } then { permit; } }`)},
		{"wider zone permit differs only in source", globalText9571(
			`policy p1 { match { from-zone [ trust untrust ]; source-address 10.0.1.0/25; destination-address any; application any; } then { permit; } } ` +
				`policy p1 { match { from-zone trust; source-address 10.0.2.0/25; destination-address any; application any; } then { permit; } }`)},
		{"identical scoped deny pair", globalText9571(
			`policy p1 { match { from-zone trust; source-address 10.0.1.0/25; destination-address any; application any; } then { deny; } } ` +
				`policy p1 { match { from-zone trust; source-address 10.0.1.0/25; destination-address any; application any; } then { deny; } }`)},
		{"scoped deny folded into wider scoped deny", globalText9571(
			`policy p1 { match { from-zone trust; source-address 10.0.1.0/25; destination-address any; application any; } then { deny; } } ` +
				`policy p1 { match { from-zone [ trust untrust ]; source-address 10.0.1.0/25; destination-address any; application any; } then { deny; } }`)},
		{"unscoped deny pair differing only in source", globalText9571(
			`policy p1 { match { source-address 10.0.1.0/25; destination-address any; application any; } then { deny; } } ` +
				`policy p1 { match { source-address 10.0.2.0/25; destination-address any; application any; } then { deny; } }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, entry := range lenientEntries9571 {
				cfg, err := entry.compile(parseHierText(t, tc.text))
				if err != nil {
					t.Fatalf("%s: %v", entry.label, err)
				}
				pols := globalPolicies16418(cfg)
				if len(pols) != 1 {
					t.Fatalf("%s: want one folded policy, got %d", entry.label, len(pols))
				}
				if pols[0].LenientContentDropped {
					t.Errorf("%s: #16418 over-rejection: semantics-preserving fold poisoned policy %q", entry.label, pols[0].Name)
				}
				if strings.Contains(strings.Join(cfg.Warnings, "\n"), "#14968") {
					t.Errorf("%s: semantics-preserving fold warned #14968: %v", entry.label, cfg.Warnings)
				}
			}
		})
	}
}
