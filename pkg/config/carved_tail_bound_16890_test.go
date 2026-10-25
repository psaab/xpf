package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestCarvedBGPExportTailSequenceBound_16890(t *testing.T) {
	cases := []struct {
		name            string
		termSequences   int
		nextPolicy      bool
		explicitDefault bool
		wantReject      bool
	}{
		{
			name:          "no-default no-next exact ceiling is rejected",
			termSequences: MaxRouteMapSequences,
			wantReject:    true,
		},
		{
			name:          "no-default next-policy one below is rejected",
			termSequences: MaxRouteMapSequences - 1,
			nextPolicy:    true,
			wantReject:    true,
		},
		{
			name:          "no-default no-next one below remains valid",
			termSequences: MaxRouteMapSequences - 1,
		},
		{
			name:            "explicit-default next-policy count remains valid",
			termSequences:   MaxRouteMapSequences - 2,
			nextPolicy:      true,
			explicitDefault: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := carvedTailBoundaryTree16890(t, tc.termSequences, tc.nextPolicy, tc.explicitDefault)
			_, err := CompileConfig(tree)
			if tc.wantReject {
				if err == nil {
					t.Fatal("CompileConfig accepted a carved BGP export whose rendered tail exceeds the FRR sequence ceiling")
				}
				if !strings.Contains(err.Error(), "carved") || !strings.Contains(err.Error(), "BIG") {
					t.Fatalf("reject error must identify the carved export and policy BIG, got %q", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("CompileConfig rejected an in-range carved export: %v", err)
			}
		})
	}
}

func TestCarvedBGPComposedTailSequenceBound_16890(t *testing.T) {
	cases := []struct {
		name           string
		totalSequences int
		wantReject     bool
	}{
		{name: "composed no-default exact ceiling is rejected", totalSequences: MaxRouteMapSequences, wantReject: true},
		{name: "composed no-default one below remains valid", totalSequences: MaxRouteMapSequences - 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := carvedComposedTailBoundaryTree16890(t, tc.totalSequences)
			_, err := CompileConfig(tree)
			if tc.wantReject {
				if err == nil {
					t.Fatal("CompileConfig accepted a carved composed BGP export whose rendered tail exceeds the FRR sequence ceiling")
				}
				if !strings.Contains(err.Error(), "carved") || !strings.Contains(err.Error(), "A B") {
					t.Fatalf("reject error must identify the carved composed chain A B, got %q", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("CompileConfig rejected an in-range carved composed export: %v", err)
			}
		})
	}
}

func carvedComposedTailBoundaryTree16890(t *testing.T, totalSequences int) *ConfigTree {
	t.Helper()
	first := (totalSequences + 1) / 2
	second := totalSequences - first
	sets := []string{
		"set protocols bgp group g neighbor 192.0.2.1 peer-as 65001",
		"set protocols bgp group g neighbor 192.0.2.1 export [ A B ]",
		"set protocols bgp group g neighbor 192.0.2.2 peer-as 65002",
		"set protocols bgp group g neighbor 192.0.2.2 export ORIGIN",
		"set policy-options policy-statement ORIGIN term originate from protocol static",
		"set policy-options policy-statement ORIGIN term originate then accept",
		"set policy-options policy-statement A term t from protocol bgp",
		"set policy-options policy-statement B term t from protocol bgp",
	}
	for i := 0; i < first; i++ {
		sets = append(sets, fmt.Sprintf("set policy-options policy-statement A term t from prefix-list a%d", i))
	}
	for i := 0; i < second; i++ {
		sets = append(sets, fmt.Sprintf("set policy-options policy-statement B term t from prefix-list b%d", i))
	}
	return treeFromSets(t, sets)
}

func carvedTailBoundaryTree16890(t *testing.T, termSequences int, nextPolicy, explicitDefault bool) *ConfigTree {
	t.Helper()
	sets := []string{
		"set protocols bgp group g neighbor 192.0.2.1 peer-as 65001",
		"set protocols bgp group g neighbor 192.0.2.1 export BIG",
		"set protocols bgp group g neighbor 192.0.2.2 peer-as 65002",
		"set protocols bgp group g neighbor 192.0.2.2 export ORIGIN",
		"set policy-options policy-statement ORIGIN term originate from protocol static",
		"set policy-options policy-statement ORIGIN term originate then accept",
		"set policy-options policy-statement BIG term t from protocol bgp",
	}
	for i := 0; i < termSequences; i++ {
		sets = append(sets, fmt.Sprintf("set policy-options policy-statement BIG term t from prefix-list pl%d", i))
	}
	if nextPolicy {
		sets = append(sets, "set policy-options policy-statement BIG term t then next policy")
	}
	if explicitDefault {
		sets = append(sets, "set policy-options policy-statement BIG then accept")
	}
	return treeFromSets(t, sets)
}
