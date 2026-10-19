package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14587: BGP BFD timers were ignored for multihop peers. The renderer
// emitted a plain `neighbor X bfd` and a single-hop `peer X` stanza with
// the configured timers, so bfdd kept the orphan single-hop session at
// 900/7 while bgpd created its own dynamic multihop session at FRR
// defaults (300ms x3). The fix binds the configured timers to the session
// bgpd actually uses via `neighbor X bfd profile <p>` and keys the static
// peer as `peer X multihop local-address L` (no orphan).
//
// FAIL-ON-REVERT: reverting to plain `neighbor X bfd` + single-hop peer
// makes the multihop/profile assertions below RED.
func TestBGPBFDMultihopProfile14587(t *testing.T) {
	m := New()

	// Multihop iBGP over loopbacks: same AS, update-source set, timers 900/7.
	mh := &config.BGPConfig{
		LocalAS: 65000,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.255.0.2", PeerAS: 65000, LocalAddress: "10.255.0.1", BFD: true, BFDInterval: 900, BFDMultiplier: 7},
		},
	}
	got := m.generateProtocols(nil, nil, mh, nil, nil, "", 0, nil, nil)

	profile := bfdProfileName(900, 7) // xpf-900-7
	if !strings.Contains(got, " neighbor 10.255.0.2 bfd profile "+profile+"\n") {
		t.Errorf("multihop neighbor must bind BFD profile %s, got:\n%s", profile, got)
	}
	if strings.Contains(got, " neighbor 10.255.0.2 bfd\n") {
		t.Errorf("multihop neighbor must not render plain `neighbor bfd` (timers lost), got:\n%s", got)
	}
	if !strings.Contains(got, " peer 10.255.0.2 multihop local-address 10.255.0.1\n") {
		t.Errorf("multihop BFD peer must be keyed multihop+local-address, got:\n%s", got)
	}
	if strings.Contains(got, " peer 10.255.0.2\n") {
		t.Errorf("multihop peer must not also render an orphan single-hop peer, got:\n%s", got)
	}
	// Exactly one peer line for this neighbor.
	if n := strings.Count(got, " peer 10.255.0.2"); n != 1 {
		t.Errorf("expected exactly 1 BFD peer line for multihop neighbor, got %d in:\n%s", n, got)
	}
	// The peer stanza and the profile both carry the configured timers.
	for _, want := range []string{
		" profile " + profile + "\n",
		"  detect-multiplier 7\n",
		"  receive-interval 900\n",
		"  transmit-interval 900\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}

	// Control: single-hop eBGP neighbor unchanged — plain bfd, bare peer,
	// no profile binding, no multihop keying.
	sh := &config.BGPConfig{
		LocalAS: 65000,
		Neighbors: []*config.BGPNeighbor{
			{Address: "192.0.2.2", PeerAS: 65001, BFD: true, BFDInterval: 900, BFDMultiplier: 7},
		},
	}
	gotSH := m.generateProtocols(nil, nil, sh, nil, nil, "", 0, nil, nil)
	if !strings.Contains(gotSH, " neighbor 192.0.2.2 bfd\n") {
		t.Errorf("single-hop control must keep plain `neighbor bfd`, got:\n%s", gotSH)
	}
	if strings.Contains(gotSH, "bfd profile") {
		t.Errorf("single-hop control must not bind a profile, got:\n%s", gotSH)
	}
	if !strings.Contains(gotSH, " peer 192.0.2.2\n") {
		t.Errorf("single-hop control must keep bare peer line, got:\n%s", gotSH)
	}
	if strings.Contains(gotSH, "multihop") {
		t.Errorf("single-hop control must not render multihop, got:\n%s", gotSH)
	}

	// Control: eBGP multihop via explicit MultihopTTL also gets profile+keying.
	ebgpMH := &config.BGPConfig{
		LocalAS: 65000,
		Neighbors: []*config.BGPNeighbor{
			{Address: "192.0.2.6", PeerAS: 65001, MultihopTTL: 5, LocalAddress: "192.0.2.5", BFD: true, BFDInterval: 500, BFDMultiplier: 4},
		},
	}
	gotEBGP := m.generateProtocols(nil, nil, ebgpMH, nil, nil, "", 0, nil, nil)
	p2 := bfdProfileName(500, 4)
	if !strings.Contains(gotEBGP, " neighbor 192.0.2.6 bfd profile "+p2+"\n") {
		t.Errorf("ebgp-multihop neighbor must bind profile %s, got:\n%s", p2, gotEBGP)
	}
	if !strings.Contains(gotEBGP, " peer 192.0.2.6 multihop local-address 192.0.2.5\n") {
		t.Errorf("ebgp-multihop peer must be keyed multihop+local-address, got:\n%s", gotEBGP)
	}
	if strings.Contains(gotEBGP, " peer 192.0.2.6\n") {
		t.Errorf("ebgp-multihop must not render orphan single-hop peer, got:\n%s", gotEBGP)
	}

	// Control (flipped by #15135/A89-03): iBGP neighbor WITHOUT
	// update-source is multihop-classified, so the profile is still
	// bound (timers reach bgpd's dynamic session) — but NO static peer
	// line is rendered: the bare `peer X multihop` the pre-#15135 code
	// emitted is rejected by bfdd 10.7.1 and fails every frr-reload.
	ibgpNoSrc := &config.BGPConfig{
		LocalAS: 65000,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.255.0.9", PeerAS: 65000, BFD: true, BFDInterval: 400, BFDMultiplier: 5},
		},
	}
	gotNoSrc := m.generateProtocols(nil, nil, ibgpNoSrc, nil, nil, "", 0, nil, nil)
	if !strings.Contains(gotNoSrc, " neighbor 10.255.0.9 bfd profile "+bfdProfileName(400, 5)+"\n") {
		t.Errorf("iBGP without update-source must still bind profile, got:\n%s", gotNoSrc)
	}
	if strings.Contains(gotNoSrc, " peer 10.255.0.9") {
		t.Errorf("iBGP without update-source must not render a static peer (#15135), got:\n%s", gotNoSrc)
	}

	// Control: multihop neighbor with NO explicit timers still binds the
	// default profile (300x3) so bgpd's session inherits the static peer's
	// timers instead of diverging.
	mhDefault := &config.BGPConfig{
		LocalAS: 65000,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.255.0.12", PeerAS: 65000, LocalAddress: "10.255.0.1", BFD: true},
		},
	}
	gotDef := m.generateProtocols(nil, nil, mhDefault, nil, nil, "", 0, nil, nil)
	if !strings.Contains(gotDef, " neighbor 10.255.0.12 bfd profile "+bfdProfileName(300, 3)+"\n") {
		t.Errorf("multihop neighbor with default timers must bind default profile, got:\n%s", gotDef)
	}
	if !strings.Contains(gotDef, " peer 10.255.0.12 multihop local-address 10.255.0.1\n") {
		t.Errorf("multihop default-timer peer must be keyed multihop, got:\n%s", gotDef)
	}
}

// #15135 (A89-03): a multihop peer keyed without a valid local-address
// renders the bare line `peer X multihop`, which bfdd 10.7.1 rejects —
// frr-reload.py exits 1 and every commit fails to converge. The static
// peer must be omitted entirely (bgpd's own dynamic session keeps the
// timers through the bound profile); a directly-connected peer must
// never see the invalid line.
//
// FAIL-ON-REVERT: restoring the unconditional multihop peer emission
// makes the bare-`multihop` assertions below RED.
func TestBGPBFDMultihopNoLocalAddress15135(t *testing.T) {
	m := New()

	// (a) iBGP without local-address: profile still bound (timers reach
	// bgpd's dynamic session), but NO static peer line at all — neither
	// the invalid bare `peer X multihop` nor an orphan single-hop peer.
	ibgpNoSrc := &config.BGPConfig{
		LocalAS: 65000,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.255.0.9", PeerAS: 65000, BFD: true, BFDInterval: 400, BFDMultiplier: 5},
		},
	}
	got := m.generateProtocols(nil, nil, ibgpNoSrc, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, " neighbor 10.255.0.9 bfd profile "+bfdProfileName(400, 5)+"\n") {
		t.Errorf("iBGP without local-address must still bind profile, got:\n%s", got)
	}
	if strings.Contains(got, " peer 10.255.0.9") {
		t.Errorf("iBGP without local-address must not render any static peer line, got:\n%s", got)
	}
	if strings.Contains(got, "multihop\n") {
		t.Errorf("render must never contain a bare `peer X multihop` line, got:\n%s", got)
	}

	// (b) eBGP-multihop without local-address: same rule.
	ebgpNoSrc := &config.BGPConfig{
		LocalAS: 65000,
		Neighbors: []*config.BGPNeighbor{
			{Address: "192.0.2.10", PeerAS: 65001, MultihopTTL: 5, BFD: true, BFDInterval: 500, BFDMultiplier: 4},
		},
	}
	gotEBGP := m.generateProtocols(nil, nil, ebgpNoSrc, nil, nil, "", 0, nil, nil)
	if !strings.Contains(gotEBGP, " neighbor 192.0.2.10 bfd profile "+bfdProfileName(500, 4)+"\n") {
		t.Errorf("ebgp-multihop without local-address must still bind profile, got:\n%s", gotEBGP)
	}
	if strings.Contains(gotEBGP, " peer 192.0.2.10") {
		t.Errorf("ebgp-multihop without local-address must not render any static peer line, got:\n%s", gotEBGP)
	}

	// (c) iBGP with an INVALID (whitespace-bearing, persisted pre-gate)
	// local-address: the single-token belt drops the update-source line,
	// so the peer has no valid local-address either — same omission.
	ibgpBadSrc := &config.BGPConfig{
		LocalAS: 65000,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.255.0.11", PeerAS: 65000, LocalAddress: "10.255.0.1 POISON", BFD: true, BFDInterval: 400, BFDMultiplier: 5},
		},
	}
	gotBad := m.generateProtocols(nil, nil, ibgpBadSrc, nil, nil, "", 0, nil, nil)
	if strings.Contains(gotBad, " peer 10.255.0.11") {
		t.Errorf("iBGP with invalid local-address must not render any static peer line, got:\n%s", gotBad)
	}

	// (d) VRF-scoped iBGP without local-address: no `peer X vrf ... multihop`
	// either — the accumulator is shared across instances.
	vrfPeer := bfdPeer{address: "10.255.0.20", vrfName: "vrf-blue", interval: 400, multiplier: 5, multihop: true}
	s := newBFDSection()
	s.addPeer(vrfPeer)
	if strings.Contains(s.render(), " peer 10.255.0.20") {
		t.Errorf("VRF multihop peer without local-address must be omitted, got:\n%s", s.render())
	}

	// Control: VRF multihop WITH a valid local-address still renders
	// the full keyed line.
	s2 := newBFDSection()
	s2.addPeer(bfdPeer{address: "10.255.0.21", vrfName: "vrf-blue", interval: 400, multiplier: 5, multihop: true, localAddress: "10.255.0.1"})
	wantLine := " peer 10.255.0.21 vrf vrf-blue multihop local-address 10.255.0.1\n"
	if !strings.Contains(s2.render(), wantLine) {
		t.Errorf("VRF multihop peer with local-address must render %q, got:\n%s", wantLine, s2.render())
	}

	// Control: single-hop (non-multihop) bare peer is untouched.
	s3 := newBFDSection()
	s3.addPeer(bfdPeer{address: "192.0.2.30", interval: 300, multiplier: 3})
	if !strings.Contains(s3.render(), " peer 192.0.2.30\n") {
		t.Errorf("single-hop control must keep bare peer line, got:\n%s", s3.render())
	}
}
