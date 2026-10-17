package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14377 render pin: a padded cluster-id must never again be silently
// omitted. validClusterID validates the RAW string (net.ParseIP /
// ParseUint reject padding), so a leniently-loaded ` 10.0.0.1 ` / ` 42 `
// cannot render — and since this fix the omission warns
// (logOmittedBGPClusterID) instead of disappearing silently. The strict
// commit gate (config.ValidateBGPClusterID) rejects the padded spelling
// outright; this test pins the render belt so the two can never diverge
// back to "commits green, renders nothing, says nothing".
//
// FAIL-ON-REVERT: trimming inside validClusterID (which would render the
// padded value) or dropping the validClusterID gate makes the padded
// assertions below render a cluster-id line -> RED. Dropping the warn
// call is caught by review of logOmittedBGPClusterID wiring in
// protocols_render.go.

func TestGenerateProtocols_PaddedClusterIDNeverRendered_14377(t *testing.T) {
	m := New()

	for _, padded := range []string{" 10.0.0.1 ", " 42 ", " 10.0.0.1", "42 "} {
		bgp := &config.BGPConfig{LocalAS: 65001, ClusterID: padded}
		out := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
		if strings.Contains(out, "cluster-id") {
			t.Errorf("padded cluster-id %q must not render (FRR would reject the token); output:\n%s", padded, out)
		}
		if !strings.Contains(out, "router bgp 65001") {
			t.Errorf("padded cluster-id %q: router bgp stanza itself must still render; output:\n%s", padded, out)
		}
	}

	// Controls: bare valid cluster-ids still render exactly.
	for _, good := range []string{"10.0.0.1", "42"} {
		bgp := &config.BGPConfig{LocalAS: 65001, ClusterID: good}
		out := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
		if !strings.Contains(out, "bgp cluster-id "+good+"\n") {
			t.Errorf("control: valid cluster-id %q must render; output:\n%s", good, out)
		}
	}

	// Control: padded BGP local-address (update-source) is omitted by the
	// existing frrOperandOrOmit belt, while a bare one renders.
	bgp := &config.BGPConfig{LocalAS: 65001, Neighbors: []*config.BGPNeighbor{
		{Address: "10.0.0.1", PeerAS: 65001, LocalAddress: " 10.0.0.1 "},
	}}
	out := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	if strings.Contains(out, "update-source") {
		t.Errorf("padded local-address must not render update-source; output:\n%s", out)
	}
	bgp.Neighbors[0].LocalAddress = "10.0.0.2"
	out = m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	if !strings.Contains(out, "neighbor 10.0.0.1 update-source 10.0.0.2\n") {
		t.Errorf("control: bare local-address must render update-source; output:\n%s", out)
	}
}

func TestValidClusterIDRejectsPadding_14377(t *testing.T) {
	for _, v := range []string{" 10.0.0.1 ", " 42 ", "42 ", " 1"} {
		if validClusterID(v) {
			t.Errorf("validClusterID(%q) = true, want false (render belt must agree with strict gate)", v)
		}
	}
	for _, v := range []string{"10.0.0.1", "42", "1", "4294967295"} {
		if !validClusterID(v) {
			t.Errorf("validClusterID(%q) = false, want true", v)
		}
	}
}
