package userspace

// #13547: a mixed valid/empty (or failed-expansion) application list under
// `then ... off` must not narrow the #12631 over-exemption to only the valid
// members. ExpandApplicationSet returns ([], nil) for a defined-but-empty
// set and (nil, err) when a member cannot be resolved; both NAT snapshot
// builders ignored that signal, so [junos-http empty-appset] under off
// exempted only TCP/80 and let every other flow fall through to later
// translation. An off exemption with an empty/failed expansion must widen
// to the match-all over-exemption term (bounded by the rule's other
// dimensions); translate rules keep failing closed on the same input.

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func dnatCfg13547(appNames []string, sets map[string]*config.ApplicationSet, off bool) *config.Config {
	cfg := dnatCfg12631(appNames, off)
	cfg.Applications.ApplicationSets = sets
	return cfg
}

func snatCfg13547(appNames []string, sets map[string]*config.ApplicationSet, off bool) *config.Config {
	cfg := snatOffCfg12631(map[string]*config.Application{
		"web": {Name: "web", Protocol: "tcp", DestinationPort: "80"},
	}, appNames, off)
	cfg.Applications.ApplicationSets = sets
	return cfg
}

var natAppsets13547 = map[string]*config.ApplicationSet{
	"empty-appset": {Name: "empty-appset"},
	// Member does not resolve -> ExpandApplicationSet returns an error.
	"broken-appset": {Name: "broken-appset", Applications: []string{"no-such-member"}},
}

func TestDNATOffMixedEmptyOrBrokenAppSetOverExempts13547(t *testing.T) {
	for _, tc := range []struct {
		name string
		apps []string
	}{
		{"mixed valid and empty set", []string{"junos-http", "empty-appset"}},
		{"mixed valid and broken set", []string{"junos-http", "broken-appset"}},
		{"empty set only", []string{"empty-appset"}},
		{"broken set only", []string{"broken-appset"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snaps := buildDestinationNATSnapshots(dnatCfg13547(tc.apps, natAppsets13547, true), nil)
			if len(snaps) == 0 {
				t.Fatalf("no off snapshots")
			}
			found := false
			for _, s := range snaps {
				if !s.Off {
					t.Fatalf("snap not off: %+v", s)
				}
				if isNeverRow12631(s) {
					t.Fatalf("off exemption emitted never-match row: %+v", snaps)
				}
				if s.DestinationAddress != "203.0.113.10" {
					t.Fatalf("destination bound lost: %+v", s)
				}
				if isMatchAllRow12631(s) {
					found = true
				}
			}
			if !found {
				t.Fatalf("off snaps=%+v want a match-all row beside/beyond the valid members", snaps)
			}
		})
	}
}

func TestSNATOffMixedEmptyOrBrokenAppSetOverExempts13547(t *testing.T) {
	for _, tc := range []struct {
		name string
		apps []string
	}{
		{"mixed valid and empty set", []string{"junos-http", "empty-appset"}},
		{"mixed valid and broken set", []string{"junos-http", "broken-appset"}},
		{"empty set only", []string{"empty-appset"}},
		{"broken set only", []string{"broken-appset"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snaps := buildSourceNATSnapshots(snatCfg13547(tc.apps, natAppsets13547, true), nil)
			if len(snaps) != 1 || !snaps[0].Off {
				t.Fatalf("snaps = %+v, want one off snapshot", snaps)
			}
			foundAny := false
			for _, term := range snaps[0].MatchApplications {
				if term.Protocol == natProtoNever {
					t.Fatalf("off exemption emitted never-match sentinel: %+v", snaps[0].MatchApplications)
				}
				if term.Protocol == natProtoAny && len(term.Ports) == 0 && len(term.SrcPorts) == 0 {
					foundAny = true
				}
			}
			if !foundAny {
				t.Fatalf("off exemption terms = %+v, want a match-all (proto-any, no ports) term", snaps[0].MatchApplications)
			}
			if len(snaps[0].SourceAddresses) != 1 || snaps[0].SourceAddresses[0] != "10.0.0.0/8" {
				t.Fatalf("source scope lost: %+v", snaps[0])
			}
		})
	}
}

// Translate controls: the same empty/failed expansions must NOT widen a
// translating rule — it keeps the never-match sentinel when nothing valid
// resolves, and keeps only the valid member when mixed.
func TestNATTranslateEmptyOrBrokenAppSetStaysNarrow13547(t *testing.T) {
	for _, apps := range [][]string{{"empty-appset"}, {"broken-appset"}} {
		snaps := buildDestinationNATSnapshots(dnatCfg13547(apps, natAppsets13547, false), nil)
		if len(snaps) != 1 || !isNeverRow12631(snaps[0]) || isMatchAllRow12631(snaps[0]) {
			t.Fatalf("DNAT translate apps=%v snaps=%+v want one never-match row", apps, snaps)
		}
		ssnaps := buildSourceNATSnapshots(snatCfg13547(apps, natAppsets13547, false), nil)
		if len(ssnaps) != 1 {
			t.Fatalf("SNAT translate apps=%v snaps=%+v", apps, ssnaps)
		}
		foundNever := false
		for _, term := range ssnaps[0].MatchApplications {
			if term.Protocol == natProtoNever {
				foundNever = true
			}
			if term.Protocol == natProtoAny {
				t.Fatalf("SNAT translate apps=%v emitted match-all: %+v", apps, ssnaps[0].MatchApplications)
			}
		}
		if !foundNever {
			t.Fatalf("SNAT translate apps=%v terms=%+v want natProtoNever", apps, ssnaps[0].MatchApplications)
		}
	}
	// Mixed translate keeps exactly the valid member's term, no match-all.
	snaps := buildDestinationNATSnapshots(dnatCfg13547([]string{"junos-http", "empty-appset"}, natAppsets13547, false), nil)
	for _, s := range snaps {
		if isMatchAllRow12631(s) {
			t.Fatalf("DNAT mixed translate widened to match-all: %+v", snaps)
		}
	}
	ssnaps := buildSourceNATSnapshots(snatCfg13547([]string{"junos-http", "empty-appset"}, natAppsets13547, false), nil)
	if len(ssnaps) != 1 {
		t.Fatalf("SNAT mixed translate snaps=%+v", ssnaps)
	}
	for _, term := range ssnaps[0].MatchApplications {
		if term.Protocol == natProtoAny || term.Protocol == natProtoNever {
			t.Fatalf("SNAT mixed translate terms=%+v want only the junos-http term", ssnaps[0].MatchApplications)
		}
	}
}
