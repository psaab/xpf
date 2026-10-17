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

	// Control: iBGP neighbor WITHOUT update-source is still multihop
	// (bgpd keys iBGP non-shared-network as multihop) — profile bound,
	// peer keyed multihop without a local-address clause.
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
	if !strings.Contains(gotNoSrc, " peer 10.255.0.9 multihop\n") {
		t.Errorf("iBGP without update-source peer must be keyed multihop, got:\n%s", gotNoSrc)
	}
	if strings.Contains(gotNoSrc, " peer 10.255.0.9\n") {
		t.Errorf("iBGP without update-source must not render orphan peer, got:\n%s", gotNoSrc)
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
