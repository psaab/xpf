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
		{
			name:   "bare preempt then priority",
			braced: "preempt; priority 200;",
			packed: "preempt priority 200",
			flat: vrrp17227Flat(
				vrrp17227Base+"preempt",
				vrrp17227Base+"priority 200"),
		},
		{
			name:   "bare preempt then accept-data",
			braced: "preempt; accept-data;",
			packed: "preempt accept-data",
			flat: vrrp17227Flat(
				vrrp17227Base+"preempt",
				vrrp17227Base+"accept-data"),
		},
		{
			name:   "bare preempt then no-preempt",
			braced: "preempt; no-preempt;",
			packed: "preempt no-preempt",
			flat: vrrp17227Flat(
				vrrp17227Base+"preempt",
				vrrp17227Base+"no-preempt"),
		},
		{
			name:   "bare preempt then virtual-address",
			braced: "preempt; virtual-address 10.0.61.4/24;",
			packed: "preempt virtual-address 10.0.61.4/24",
			flat: vrrp17227Flat(
				vrrp17227Base+"preempt",
				vrrp17227Base+"virtual-address 10.0.61.4/24"),
		},
		{
			name:   "bare preempt then track-interface",
			braced: "preempt; track-interface ge-0/0/1;",
			packed: "preempt track-interface ge-0/0/1",
			flat: vrrp17227Flat(
				vrrp17227Base+"preempt",
				vrrp17227Base+"track-interface ge-0/0/1"),
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

// TestVRRPSingleReaderPackedAuth17227 pins the packed spellings of the
// authentication pair to the same outcome as the braced and flat-set
// spellings: the strict gate rejects the dead-security config naming
// the leaf (never echoing the key), and the lenient path drops the
// group with that warning while the base address survives (#4288 /
// #5834). It exercises the packed token run through the single reader
// so `authentication-type` / `authentication-key` cannot be swallowed
// or re-split by the splitter.
func TestVRRPSingleReaderPackedAuth17227(t *testing.T) {
	const secret = "s3cr3t-17227"
	for _, row := range []struct {
		name   string
		braced string
		packed string
		flat   []string
	}{
		{
			name:   "type and key",
			braced: "authentication-type md5; authentication-key " + secret + ";",
			packed: "authentication-type md5 authentication-key " + secret,
			flat: vrrp17227Flat(
				vrrp17227Base+"authentication-type md5",
				vrrp17227Base+"authentication-key "+secret),
		},
		{
			name:   "type only",
			braced: "authentication-type md5;",
			packed: "authentication-type md5",
			flat:   vrrp17227Flat(vrrp17227Base + "authentication-type md5"),
		},
		{
			name:   "key only",
			braced: "authentication-key " + secret + ";",
			packed: "authentication-key " + secret,
			flat:   vrrp17227Flat(vrrp17227Base + "authentication-key " + secret),
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			trees := map[string]*ConfigTree{
				"braced": parseHierText(t, vrrp17227Braced(row.braced)),
				"packed": parseHierText(t, vrrp17227Packed(row.packed)),
				"flat":   replaySetLines(t, row.flat),
			}
			for spelling, tree := range trees {
				_, err := CompileConfig(tree)
				if err == nil || !strings.Contains(err.Error(), "authentication") {
					t.Fatalf("%s strict: must reject naming the auth leaf, got %v", spelling, err)
				}
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("%s strict: error leaks the authentication key: %v", spelling, err)
				}
				lcfg, err := CompileConfigLenient(tree)
				if err != nil {
					t.Fatalf("%s lenient: %v", spelling, err)
				}
				if !hasWarningContaining(lcfg.Warnings, "authentication") {
					t.Fatalf("%s lenient: must warn naming the auth leaf, got %v", spelling, lcfg.Warnings)
				}
				for _, w := range lcfg.Warnings {
					if strings.Contains(w, secret) {
						t.Fatalf("%s lenient: warning leaks the authentication key: %q", spelling, w)
					}
				}
				// The group is dropped, so no VRRP group survives on
				// the unit at all (firstVRRPGroupWithVIP keys on reth0,
				// but this fixture's group lives on reth1 — scan every
				// interface so the drop is actually observed).
				for ifName, ifc := range lcfg.Interfaces.Interfaces {
					for un, u := range ifc.Units {
						if len(u.VRRPGroups) != 0 {
							t.Fatalf("%s lenient: auth group must be dropped, got %d group(s) on %s unit %d", spelling, len(u.VRRPGroups), ifName, un)
						}
					}
				}
			}
		})
	}
}

// vrrp17227Inet6 helpers for the v6-only leaves. Strict gates refuse
// `virtual-link-local-address` and range-check
// `inet6-advertise-interval`, so those rows assert the gate outcome;
// `virtual-inet6-address` compiles and is read off the group.
const vrrp17227Inet6Base = "set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64 vrrp-inet6-group 1 "

func vrrp17227Inet6Braced(body string) string {
	return `interfaces {
    reth0 {
        unit 0 {
            family inet6 {
                address 2001:db8::10/64 {
                    vrrp-inet6-group 1 {
                        virtual-inet6-address 2001:db8::1/64;
` + body + `
                    }
                }
            }
        }
    }
}`
}

func vrrp17227Inet6Packed(body string) string {
	return `interfaces {
    reth0 {
        unit 0 {
            family inet6 {
                address 2001:db8::10/64 {
                    vrrp-inet6-group 1 virtual-inet6-address 2001:db8::1/64 ` + body + `;
                }
            }
        }
    }
}`
}

func vrrp17227Inet6Flat(lines ...string) []string {
	out := []string{"set interfaces reth0 unit 0 family inet6 address 2001:db8::10/64",
		vrrp17227Inet6Base + "virtual-inet6-address 2001:db8::1/64"}
	return append(out, lines...)
}

func vrrp17227Inet6Group(t *testing.T, cfg *Config) *VRRPGroup {
	t.Helper()
	vg := firstVRRPGroupWithVIP(t, cfg, "2001:db8::1/64")
	if vg == nil {
		t.Fatal("no inet6 VRRP group compiled")
	}
	return vg
}

// TestVRRPSingleReaderInet6Packed17227 pins the v6-only leaves in the
// packed spelling to their braced / flat-set outcomes.
func TestVRRPSingleReaderInet6Packed17227(t *testing.T) {
	t.Run("virtual-inet6-address packed extra VIP", func(t *testing.T) {
		bcfg, err := CompileConfig(parseHierText(t, vrrp17227Inet6Braced(
			"virtual-inet6-address 2001:db8::2/64;")))
		if err != nil {
			t.Fatalf("braced compile: %v", err)
		}
		pcfg, err := CompileConfig(parseHierText(t, vrrp17227Inet6Packed(
			"virtual-inet6-address 2001:db8::2/64")))
		if err != nil {
			t.Fatalf("packed compile: %v", err)
		}
		fcfg, err := CompileConfig(replaySetLines(t, vrrp17227Inet6Flat(
			vrrp17227Inet6Base+"virtual-inet6-address 2001:db8::2/64")))
		if err != nil {
			t.Fatalf("flat compile: %v", err)
		}
		bg, pg, fg := vrrp17227Inet6Group(t, bcfg), vrrp17227Inet6Group(t, pcfg), vrrp17227Inet6Group(t, fcfg)
		if !reflect.DeepEqual(bg, pg) || !reflect.DeepEqual(bg, fg) {
			t.Fatalf("spellings diverge:\nbraced=%+v\npacked=%+v\nflat=%+v", bg, pg, fg)
		}
		if len(pg.VirtualAddresses) != 2 {
			t.Fatalf("packed virtual-inet6-address values = %v, want 2 VIPs", pg.VirtualAddresses)
		}
	})
	t.Run("inet6-advertise-interval", func(t *testing.T) {
		bcfg, err := CompileConfig(parseHierText(t, vrrp17227Inet6Braced(
			"inet6-advertise-interval 500;")))
		if err != nil {
			t.Fatalf("braced compile: %v", err)
		}
		pcfg, err := CompileConfig(parseHierText(t, vrrp17227Inet6Packed(
			"inet6-advertise-interval 500")))
		if err != nil {
			t.Fatalf("packed compile: %v", err)
		}
		fcfg, err := CompileConfig(replaySetLines(t, vrrp17227Inet6Flat(
			vrrp17227Inet6Base+"inet6-advertise-interval 500")))
		if err != nil {
			t.Fatalf("flat compile: %v", err)
		}
		for spelling, cfg := range map[string]*Config{"braced": bcfg, "packed": pcfg, "flat": fcfg} {
			if got := vrrp17227Inet6Group(t, cfg).Inet6AdvertiseIntervalMS; got != 500 {
				t.Fatalf("%s inet6-advertise-interval = %d, want 500", spelling, got)
			}
		}
	})
	t.Run("virtual-link-local-address gate", func(t *testing.T) {
		trees := map[string]*ConfigTree{
			"braced": parseHierText(t, vrrp17227Inet6Braced("virtual-link-local-address fe80::1;")),
			"packed": parseHierText(t, vrrp17227Inet6Packed("virtual-link-local-address fe80::1")),
			"flat": replaySetLines(t, vrrp17227Inet6Flat(
				vrrp17227Inet6Base+"virtual-link-local-address fe80::1")),
		}
		for spelling, tree := range trees {
			_, err := CompileConfig(tree)
			if err == nil || !strings.Contains(err.Error(), "virtual-link-local-address") {
				t.Fatalf("%s strict: must name-refuse virtual-link-local-address, got %v", spelling, err)
			}
			lcfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("%s lenient: %v", spelling, err)
			}
			if !hasWarningContaining(lcfg.Warnings, "virtual-link-local-address") {
				t.Fatalf("%s lenient: must warn naming virtual-link-local-address, got %v", spelling, lcfg.Warnings)
			}
			if got := vrrp17227Inet6Group(t, lcfg).VirtualLinkLocalAddress; got != "fe80::1" {
				t.Fatalf("%s lenient: VirtualLinkLocalAddress = %q, want fe80::1 recorded", spelling, got)
			}
		}
	})
}
