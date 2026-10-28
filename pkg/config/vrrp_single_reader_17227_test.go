package config

import (
	"reflect"
	"strings"
	"testing"
)

// #17227 — parseVRRPGroups read every vrrp-group property TWICE (a
// Keys-packed switch and a child switch) and the copies diverged:
//
//   - packed hierarchical one-liner: nested `priority-cost 30` +
//     legacy sibling `track-priority-cost 20` compiled delta=20 in
//     BOTH source orders (sibling overwrote / won by source order),
//     while the braced and flat-set spellings compiled 30 (nested
//     wins regardless of order, #1814).
//   - lenient packed: nested 30 + BAD sibling (`track-priority-cost
//     999`) compiled delta=0 — the Keys arm's swallowed
//     `vg.TrackPriorityDelta, _ = parseTrackCost(...)` erased the
//     good nested cost, and the follow-on warning claimed only the
//     sibling was ignored — while the braced spelling kept 30.
//
// The fix normalizes first (vrrpGroupStatements) and reads once, so
// these divergences cannot recur: there is exactly one
// `case "track-priority-cost"` in compiler_interfaces.go (acceptance
// grep == 1 outside gate code — the gate copy in
// checkVRRPGroupTrackShape counts raw Keys, it does not compile).
//
// FAIL-ON-REVERT: restoring the Keys arm (or pointing the packed
// shape back at a second reader) makes the packed rows below compile
// 20 / 0 again while braced stays 30.

// vrrp17227Group compiles one spelling and returns its single group.
func vrrp17227Group(t *testing.T, cfg *Config) *VRRPGroup {
	t.Helper()
	for _, ifc := range cfg.Interfaces.Interfaces {
		for _, u := range ifc.Units {
			for _, g := range u.VRRPGroups {
				return g
			}
		}
	}
	t.Fatalf("no VRRP group compiled")
	return nil
}

// The three spellings of ONE group body. Braced = hierarchical block,
// packed = hierarchical one-liner (properties on the instance Keys),
// flat = separate `set` lines (schema-structured flat-set / flat run).
func vrrp17227Braced(body string) string {
	return `interfaces {
    ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } }
    reth1 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.3/24;
` + body + `
                    }
                }
            }
        }
    }
}`
}

func vrrp17227Packed(body string) string {
	return `interfaces {
    ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } }
    reth1 {
        unit 0 {
            family inet {
                address 10.0.61.1/24 {
                    vrrp-group 1 virtual-address 10.0.61.3/24 ` + body + `;
                }
            }
        }
    }
}`
}

const vrrp17227Base = "set interfaces reth1 unit 0 family inet address 10.0.61.1/24 vrrp-group 1 "
const vrrp17227TrackDecl = "set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24"

func vrrp17227Flat(lines ...string) []string {
	out := []string{vrrp17227TrackDecl, vrrp17227Base + "virtual-address 10.0.61.3/24"}
	return append(out, lines...)
}

// TestVRRPSingleReaderParity17227 asserts every vrrp-group property
// compiles IDENTICALLY (reflect.DeepEqual on the whole VRRPGroup)
// across braced / packed one-liner / flat-set spellings, including
// the two measured divergences from the issue.
func TestVRRPSingleReaderParity17227(t *testing.T) {
	rows := []struct {
		name   string
		braced string
		packed string
		flat   []string
	}{
		{
			name:   "priority",
			braced: "priority 200;",
			packed: "priority 200",
			flat:   vrrp17227Flat(vrrp17227Base + "priority 200"),
		},
		{
			name:   "preempt hold-time packed pair",
			braced: "preempt { hold-time 30; }",
			packed: "preempt hold-time 30",
			flat:   vrrp17227Flat(vrrp17227Base + "preempt hold-time 30"),
		},
		{
			name:   "no-preempt",
			braced: "no-preempt;",
			packed: "no-preempt",
			flat:   vrrp17227Flat(vrrp17227Base + "no-preempt"),
		},
		{
			name:   "accept-data",
			braced: "accept-data;",
			packed: "accept-data",
			flat:   vrrp17227Flat(vrrp17227Base + "accept-data"),
		},
		{
			name:   "advertise-interval",
			braced: "advertise-interval 5;",
			packed: "advertise-interval 5",
			flat:   vrrp17227Flat(vrrp17227Base + "advertise-interval 5"),
		},
		{
			name:   "virtual-address multi bracket",
			braced: "virtual-address [ 10.0.61.4/24 10.0.61.5/24 ];",
			packed: "virtual-address [ 10.0.61.4/24 10.0.61.5/24 ]",
			flat: vrrp17227Flat(
				vrrp17227Base+"virtual-address 10.0.61.4/24",
				vrrp17227Base+"virtual-address 10.0.61.5/24"),
		},
		{
			name:   "nested track wins over sibling, nested first",
			braced: "track-interface ge-0/0/1 { priority-cost 30; } track-priority-cost 20;",
			packed: "track-interface ge-0/0/1 priority-cost 30 track-priority-cost 20",
			flat: vrrp17227Flat(
				vrrp17227Base+"track-interface ge-0/0/1 priority-cost 30",
				vrrp17227Base+"track-priority-cost 20"),
		},
		{
			name:   "nested track wins over sibling, sibling first",
			braced: "track-priority-cost 20; track-interface ge-0/0/1 { priority-cost 30; }",
			packed: "track-priority-cost 20 track-interface ge-0/0/1 priority-cost 30",
			flat: vrrp17227Flat(
				vrrp17227Base+"track-priority-cost 20",
				vrrp17227Base+"track-interface ge-0/0/1 priority-cost 30"),
		},
		{
			name:   "junos track container",
			braced: "track { interface ge-0/0/1 { priority-cost 30; } }",
			packed: "track interface ge-0/0/1 priority-cost 30",
			flat:   vrrp17227Flat(vrrp17227Base + "track interface ge-0/0/1 priority-cost 30"),
		},
		{
			name:   "legacy sibling only",
			braced: "track-interface ge-0/0/1; track-priority-cost 20;",
			packed: "track-interface ge-0/0/1 track-priority-cost 20",
			flat: vrrp17227Flat(
				vrrp17227Base+"track-interface ge-0/0/1",
				vrrp17227Base+"track-priority-cost 20"),
		},
		{
			name:   "all properties together",
			braced: "priority 200; accept-data; advertise-interval 5; preempt { hold-time 30; } track-interface ge-0/0/1 { priority-cost 30; } track-priority-cost 20;",
			packed: "priority 200 accept-data advertise-interval 5 preempt hold-time 30 track-interface ge-0/0/1 priority-cost 30 track-priority-cost 20",
			flat: vrrp17227Flat(
				vrrp17227Base+"priority 200",
				vrrp17227Base+"accept-data",
				vrrp17227Base+"advertise-interval 5",
				vrrp17227Base+"preempt hold-time 30",
				vrrp17227Base+"track-interface ge-0/0/1 priority-cost 30",
				vrrp17227Base+"track-priority-cost 20"),
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			bcfg, err := CompileConfig(parseHierText(t, vrrp17227Braced(row.braced)))
			if err != nil {
				t.Fatalf("braced compile: %v", err)
			}
			pcfg, err := CompileConfig(parseHierText(t, vrrp17227Packed(row.packed)))
			if err != nil {
				t.Fatalf("packed compile: %v", err)
			}
			fcfg, err := CompileConfig(replaySetLines(t, row.flat))
			if err != nil {
				t.Fatalf("flat compile: %v", err)
			}
			bg, pg, fg := vrrp17227Group(t, bcfg), vrrp17227Group(t, pcfg), vrrp17227Group(t, fcfg)
			if !reflect.DeepEqual(bg, pg) {
				t.Fatalf("braced != packed:\nbraced=%+v\npacked=%+v", bg, pg)
			}
			if !reflect.DeepEqual(bg, fg) {
				t.Fatalf("braced != flat:\nbraced=%+v\nflat=%+v", bg, fg)
			}
		})
	}
}

// TestVRRPSingleReaderTrackPrecedence17227 pins the headline measured
// divergence directly: packed-nested+sib20 (and the reverse order)
// must be 30 — nested wins regardless of spelling or source order.
func TestVRRPSingleReaderTrackPrecedence17227(t *testing.T) {
	for _, packed := range []string{
		"track-interface ge-0/0/1 priority-cost 30 track-priority-cost 20",
		"track-priority-cost 20 track-interface ge-0/0/1 priority-cost 30",
		"track interface ge-0/0/1 priority-cost 30 track-priority-cost 20",
		"track-priority-cost 20 track interface ge-0/0/1 priority-cost 30",
	} {
		cfg, err := CompileConfig(parseHierText(t, vrrp17227Packed(packed)))
		if err != nil {
			t.Fatalf("packed %q: %v", packed, err)
		}
		vg := vrrp17227Group(t, cfg)
		if vg.TrackInterface != "ge-0/0/1" || vg.TrackPriorityDelta != 30 {
			t.Fatalf("packed %q: track=%q delta=%d, want ge-0/0/1/30 (nested wins)", packed, vg.TrackInterface, vg.TrackPriorityDelta)
		}
	}
}

// TestVRRPSingleReaderLenientBadSibling17227 pins the #4573 divergence:
// lenient packed nested 30 + bad sibling (999) keeps 30; the bad
// sibling is ignored, not applied as 0 over the good nested cost.
func TestVRRPSingleReaderLenientBadSibling17227(t *testing.T) {
	packed := vrrp17227Packed("track-interface ge-0/0/1 priority-cost 30 track-priority-cost 999")
	// Strict rejects the 999 in both shapes (unchanged gate behaviour).
	if _, err := CompileConfig(parseHierText(t, packed)); err == nil {
		t.Fatal("strict must reject track-priority-cost 999")
	}
	cfg, err := CompileConfigLenient(parseHierText(t, packed))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	vg := vrrp17227Group(t, cfg)
	if vg.TrackPriorityDelta != 30 {
		t.Fatalf("lenient packed-nested+badsib delta=%d, want 30 (bad sibling ignored, nested kept)", vg.TrackPriorityDelta)
	}
	if vg.TrackInterface != "ge-0/0/1" {
		t.Fatalf("lenient track interface = %q, want ge-0/0/1", vg.TrackInterface)
	}
	// The misleading pre-fix warning ("track-interface without
	// priority-cost has no effect" while a cost WAS in effect) is gone.
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "without priority-cost has no effect") {
			t.Fatalf("misleading no-effect warning survives: %v", cfg.Warnings)
		}
	}
	// Braced control: same value through the child spelling.
	bcfg, err := CompileConfigLenient(parseHierText(t, vrrp17227Braced(
		"track-interface ge-0/0/1 { priority-cost 30; } track-priority-cost 999;")))
	if err != nil {
		t.Fatalf("lenient braced compile: %v", err)
	}
	if got := vrrp17227Group(t, bcfg).TrackPriorityDelta; got != 30 {
		t.Fatalf("lenient braced-nested+badsib delta=%d, want 30", got)
	}
}

// TestVRRPSingleReaderPackedShortTrack17227 pins that a short packed
// track (`track interface <if>` with no priority-cost) does not
// swallow the following property keyword.
func TestVRRPSingleReaderPackedShortTrack17227(t *testing.T) {
	cfg, err := CompileConfig(parseHierText(t, vrrp17227Packed(
		"track interface ge-0/0/1 priority 200")))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	vg := vrrp17227Group(t, cfg)
	if vg.TrackInterface != "ge-0/0/1" {
		t.Fatalf("track interface = %q, want ge-0/0/1", vg.TrackInterface)
	}
	if vg.Priority != 200 {
		t.Fatalf("priority after short track = %d, want 200 (keyword swallowed by track)", vg.Priority)
	}
}
