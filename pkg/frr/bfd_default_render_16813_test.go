package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16813: the #15203 benign-reload re-check certifies convergence only
// when `frr-reload.py --test` shows an empty diff. Two renders made
// that impossible:
//
//   - bfdd is northbound/YANG-backed (frr-bfdd.yang defaults:
//     detection-multiplier 3, intervals 300000us): a leaf set to its
//     default is elided from `show running-config`, so the rendered
//     `detect-multiplier 3` / `receive-interval 300` /
//     `transmit-interval 300` lines were a perpetual "Lines To Add".
//   - ospf6d's ospf6_bfd_write_config always prints the bare
//     ` ipv6 ospf6 bfd` line and only then the profile line, so
//     rendering only ` ipv6 ospf6 bfd profile P` made every --test
//     delete the running bare line.
//
// Live-verified on FRR 10.7.1 (isolated netns+pathspace, daemons
// loaded with the pre-fix render): running-config held
// `profile xpf-300-3` with NO timer lines, the OSPFv3 interface held
// both ospf6 bfd lines, and --test against the identical file listed
// all six default timer lines as additions plus
// `no ipv6 ospf6 bfd` as a deletion. With the post-fix render the
// bfd/interface sections diff empty (only the probe's unrelated
// hostname line remained). Non-default and mixed profiles (500/4,
// 500/3, peer 100/3) keep exactly their non-default lines.
//
// FAIL-ON-REVERT: restoring unconditional timer emission or dropping
// the ospf6 bare line makes the assertions below RED.
func TestBFDDefaultRender16813(t *testing.T) {
	m := New()

	// (a) IS-IS interface at the exact acceptance profile xpf-300-3:
	// the profile stanza must be bare (no timer lines at all), while
	// the interface enable+profile pair is unchanged (#15015).
	isis := &config.ISISConfig{
		NET:   "49.0001.0100.0000.0001.00",
		Level: "level-1-2",
		Interfaces: []*config.ISISInterface{
			{Name: "ge-0-0-0", BFD: true, BFDInterval: 300, BFDMultiplier: 3},
		},
	}
	gotISIS := m.generateProtocols(nil, nil, nil, nil, isis, "", 1, nil, nil)
	if !strings.Contains(gotISIS, " isis bfd\n isis bfd profile xpf-300-3\n") {
		t.Errorf("IS-IS default profile must keep enable+profile pair, got:\n%s", gotISIS)
	}
	if !strings.Contains(gotISIS, " profile xpf-300-3\n exit\n") {
		t.Errorf("all-default profile xpf-300-3 must render bare (no timer lines), got:\n%s", gotISIS)
	}
	for _, line := range []string{"detect-multiplier", "receive-interval", "transmit-interval"} {
		if strings.Contains(gotISIS, line) {
			t.Errorf("default-valued %s line must not render (#16813), got:\n%s", line, gotISIS)
		}
	}

	// (b) OSPFv3 timed interface: FRR holds BOTH the bare enable and
	// the profile line; render both, in that order.
	ospfv3 := &config.OSPFv3Config{
		RouterID: "10.0.0.1",
		Areas: []*config.OSPFv3Area{
			{ID: "0.0.0.0", Interfaces: []*config.OSPFv3Interface{
				{Name: "trust0", BFD: true, BFDInterval: 300, BFDMultiplier: 3},
			}},
		},
	}
	gotV3 := m.generateProtocols(nil, ospfv3, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(gotV3, " ipv6 ospf6 bfd\n ipv6 ospf6 bfd profile xpf-300-3\n") {
		t.Errorf("OSPFv3 profile interface must render bare `ipv6 ospf6 bfd` before the profile line (#16813), got:\n%s", gotV3)
	}
	if !strings.Contains(gotV3, " profile xpf-300-3\n exit\n") {
		t.Errorf("OSPFv3 default profile must render bare, got:\n%s", gotV3)
	}

	// (c) Mixed profile: non-default interval, default multiplier —
	// only the interval lines render; the session still gets 500ms
	// (multiplier falls back to bfdd's default 3, same value).
	ospfMixed := &config.OSPFConfig{
		RouterID: "10.0.0.1",
		Areas: []*config.OSPFArea{
			{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
				{Name: "trust0", BFD: true, BFDInterval: 500, BFDMultiplier: 3},
			}},
		},
	}
	gotMixed := m.generateProtocols(ospfMixed, nil, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(gotMixed, " profile xpf-500-3\n  receive-interval 500\n  transmit-interval 500\n exit\n") {
		t.Errorf("mixed profile must render only non-default interval lines, got:\n%s", gotMixed)
	}
	if strings.Contains(gotMixed, "detect-multiplier") {
		t.Errorf("default multiplier must not render in mixed profile, got:\n%s", gotMixed)
	}

	// (d) Fully non-default profile: all three lines render.
	ospfCustom := &config.OSPFConfig{
		RouterID: "10.0.0.1",
		Areas: []*config.OSPFArea{
			{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
				{Name: "trust0", BFD: true, BFDInterval: 500, BFDMultiplier: 4},
			}},
		},
	}
	gotCustom := m.generateProtocols(ospfCustom, nil, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(gotCustom, " profile xpf-500-4\n  detect-multiplier 4\n  receive-interval 500\n  transmit-interval 500\n exit\n") {
		t.Errorf("non-default profile must render all timer lines, got:\n%s", gotCustom)
	}

	// (e) BGP peer at defaults (bare BFD, no timers authored): the
	// peer stanza renders bare; the neighbor binding is unchanged.
	bgp := &config.BGPConfig{
		LocalAS:   65000,
		Neighbors: []*config.BGPNeighbor{{Address: "192.0.2.1", PeerAS: 65001, BFD: true}},
	}
	gotBGP := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	if !strings.Contains(gotBGP, " peer 192.0.2.1\n exit\n") {
		t.Errorf("all-default BGP peer must render bare, got:\n%s", gotBGP)
	}
	if strings.Contains(gotBGP, "detect-multiplier") || strings.Contains(gotBGP, "receive-interval") {
		t.Errorf("default BGP peer must not render timer lines, got:\n%s", gotBGP)
	}

	// (f) Unset timers (0/0) resolve to the defaults, hence bare too:
	// an OSPF interface with only multiplier authored at default via
	// interval-only path still binds xpf-500-3-style naming; here a
	// direct accumulator cell pins 0/0.
	s := newBFDSection()
	s.addProfile("xpf-300-3", bfdProfile{interval: 0, multiplier: 0})
	if got := s.render(); !strings.Contains(got, " profile xpf-300-3\n exit\n") {
		t.Errorf("unset (0/0) profile must render bare, got:\n%s", got)
	}
}
