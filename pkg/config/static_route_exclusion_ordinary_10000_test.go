package config

import (
	"strings"
	"testing"
)

// #10000: an ORDINARY static route (next-hop / discard / reject) whose
// destination the builder cannot put on the wire must carry an exclusion
// reason instead of vanishing with only a daemon-log Warn.
//
// StaticRouteExcludedReason returned early when NextTable == "", so the
// destination-parse arm existed only in the next-table path. An unusable
// ordinary destination was dropped from the helper FIB by addSnapshot
// (pkg/dataplane/userspace/routes.go) with only slog.Warn, while the show
// surfaces rendered it as installed. Measured: `route default discard`
// commits and vanishes; for a discard route that is a FAIL-OPEN onto a
// less-specific route (#6568).
//
// FAIL-ON-REVERT: restore the blanket `if sr.NextTable == "" { return "" }`
// and every "excluded" row below reports "".
func TestStaticRouteExcludedReasonOrdinaryDestination_10000(t *testing.T) {
	defined := map[string]struct{}{"vrf-a": {}}

	for _, tc := range []struct {
		name        string
		sr          *StaticRoute
		perInstance bool
		wantSubstr  string // "" means MUST NOT be excluded
	}{
		{
			name:       "default-keyword discard is excluded",
			sr:         &StaticRoute{Destination: "default", Discard: true},
			wantSubstr: "neither a CIDR prefix nor a bare IP",
		},
		{
			name:       "malformed ordinary next-hop is excluded",
			sr:         &StaticRoute{Destination: "not-a-cidr", NextHops: []NextHopEntry{{Address: "10.0.0.1"}}},
			wantSubstr: "neither a CIDR prefix nor a bare IP",
		},
		{
			name:       "empty destination is excluded",
			sr:         &StaticRoute{Destination: "", Discard: true},
			wantSubstr: "neither a CIDR prefix nor a bare IP",
		},
		{
			name:       "out-of-range octet is excluded",
			sr:         &StaticRoute{Destination: "10.0.0.300/24", Discard: true},
			wantSubstr: "neither a CIDR prefix nor a bare IP",
		},
		{
			name:        "per-instance default-keyword discard is excluded",
			sr:          &StaticRoute{Destination: "default", Discard: true},
			perInstance: true,
			wantSubstr:  "neither a CIDR prefix nor a bare IP",
		},
		{
			name:       "valid CIDR discard is NOT excluded",
			sr:         &StaticRoute{Destination: "10.9.0.0/16", Discard: true},
			wantSubstr: "",
		},
		{
			name:       "default-route CIDR is NOT excluded",
			sr:         &StaticRoute{Destination: "0.0.0.0/0", Discard: true},
			wantSubstr: "",
		},
		{
			name:       "bare v4 host is NOT excluded — the builder normalises it to /32 (#6568)",
			sr:         &StaticRoute{Destination: "10.0.0.1", Discard: true},
			wantSubstr: "",
		},
		{
			name:       "bare v6 host is NOT excluded — the builder normalises it to /128 (#6568)",
			sr:         &StaticRoute{Destination: "2001:db8::1", Discard: true},
			wantSubstr: "",
		},
		{
			name:       "IPv4-mapped IPv6 is NOT excluded — colon text means v6 on the wire (#6568)",
			sr:         &StaticRoute{Destination: "::ffff:10.0.0.1", Discard: true},
			wantSubstr: "",
		},
		{
			name:       "host-bearing prefix is NOT excluded — ParseCIDR accepts it and the wire keeps it verbatim",
			sr:         &StaticRoute{Destination: "10.0.0.5/24", Discard: true},
			wantSubstr: "",
		},
		{
			name:       "next-table bare host stays excluded — the next-table arm is strict CIDR and this fix does not widen it",
			sr:         &StaticRoute{Destination: "10.0.0.1", NextTable: "vrf-a"},
			wantSubstr: "does not parse as a CIDR prefix",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := StaticRouteExcludedReason(tc.sr, tc.perInstance, defined)
			if tc.wantSubstr == "" {
				if got != "" {
					t.Fatalf("StaticRouteExcludedReason = %q, want \"\" — this route IS installed, "+
						"and annotating it would tell the operator a live route is dead", got)
				}
				return
			}
			if !strings.Contains(got, tc.wantSubstr) {
				t.Fatalf("StaticRouteExcludedReason = %q, want a reason containing %q", got, tc.wantSubstr)
			}
		})
	}
}

// TestStaticRouteExclusionsOrdinaryUnusable_10000 is the whole-config half:
// unusable ordinary destinations must appear in the shared verdict map the
// builder and the show surfaces both consult — global and per-instance —
// while usable ordinary destinations stay out of it.
func TestStaticRouteExclusionsOrdinaryUnusable_10000(t *testing.T) {
	globalDefault := &StaticRoute{Destination: "default", Discard: true}
	globalGarbage := &StaticRoute{Destination: "not-a-prefix", NextHops: []NextHopEntry{{Address: "10.0.0.1"}}}
	globalValid := &StaticRoute{Destination: "10.9.0.0/16", Discard: true}
	globalBare := &StaticRoute{Destination: "10.0.0.1", Discard: true}
	instanceDefault := &StaticRoute{Destination: "default", Discard: true}

	cfg := srExclCfg7357(
		[]*StaticRoute{globalDefault, globalGarbage, globalValid, globalBare},
		nil,
		[]*RoutingInstanceConfig{{Name: "vrf-a", StaticRoutes: []*StaticRoute{instanceDefault}}},
	)

	excl := StaticRouteExclusions(cfg)

	for _, sr := range []*StaticRoute{globalDefault, globalGarbage, instanceDefault} {
		if reason := excl[sr]; !strings.Contains(reason, "neither a CIDR prefix nor a bare IP") {
			t.Errorf("StaticRouteExclusions[%q] = %q, want a reason naming the unusable destination",
				sr.Destination, reason)
		}
	}
	for _, sr := range []*StaticRoute{globalValid, globalBare} {
		if reason := excl[sr]; reason != "" {
			t.Errorf("StaticRouteExclusions[%q] = %q, want \"\" — this route IS installed",
				sr.Destination, reason)
		}
	}
}
