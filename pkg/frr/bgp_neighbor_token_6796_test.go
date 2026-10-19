package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// injectedNeighbor6796 is the shape the defect permits: a first statement FRR
// accepts, then a newline, then a second statement the operator never wrote.
const injectedNeighbor6796 = "1.1.1.1 remote-as 65000\n neighbor 2.2.2.2"

func bgpWithNeighbors6796(addrs ...string) *config.BGPConfig {
	bgp := &config.BGPConfig{LocalAS: 65001, RouterID: "10.0.0.1"}
	for _, a := range addrs {
		bgp.Neighbors = append(bgp.Neighbors, &config.BGPNeighbor{
			Address:    a,
			PeerAS:     65000,
			BFD:        true,
			FamilyInet: true,
		})
	}
	return bgp
}

// renderProtocols6796 renders the BGP block the way production does.
func renderProtocols6796(t *testing.T, bgp *config.BGPConfig) string {
	t.Helper()
	m := &Manager{}
	return m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
}

// TestMultiTokenNeighborNeverReachesFRRConf6796 is the render-side belt.
//
// n.Address is emitted RAW at 24 sites, and FRR's lexer splits on whitespace
// with no quoted-string token — so an identity carrying a newline renders a
// valid first statement plus an attacker-chosen second one. This asserts what
// the render BECAME, not merely that the raw needle is absent: an absence check
// alone passes against a renderer that emits nothing at all.
func TestMultiTokenNeighborNeverReachesFRRConf6796(t *testing.T) {
	good := "10.0.0.2"
	out := renderProtocols6796(t, bgpWithNeighbors6796(good, injectedNeighbor6796))

	// The legitimate neighbor must still be fully rendered — otherwise a
	// renderer that dropped the whole BGP block would pass the absence check
	// below for the wrong reason.
	if !strings.Contains(out, "neighbor "+good+" remote-as 65000") {
		t.Fatalf("the VALID neighbor was not rendered; the belt is dropping "+
			"more than the bad one:\n%s", out)
	}
	if !strings.Contains(out, "neighbor "+good+" bfd") {
		t.Fatalf("the valid neighbor lost its bfd line:\n%s", out)
	}

	// The injected second statement must not appear anywhere.
	if strings.Contains(out, "neighbor 2.2.2.2") {
		t.Fatalf("a multi-token neighbor identity injected a SECOND frr.conf "+
			"statement the operator never wrote (#6796):\n%s", out)
	}
	// Nor the first half of it, which would still be a peering to a host the
	// operator did not configure.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "neighbor 1.1.1.1") {
			t.Fatalf("the injected identity's first token still rendered as a "+
				"real peering: %q\n%s", line, out)
		}
	}
}

// TestMultiTokenNeighborIsExcludedFromBFDToo6796 pins the OTHER consumer.
//
// The identity is reused by the BFD peer accumulator as well as the neighbor
// statements, which is the "reused raw by BGP and BFD" half of the issue.
// Excluding it from validNeighbors covers both — but only because that set is
// the shared exclusion point; a per-site guard on the neighbor lines alone
// would leave the BFD peer behind, and a `bfd` peer for a neighbor that was
// never declared makes vtysh reject the WHOLE managed section.
func TestMultiTokenNeighborIsExcludedFromBFDToo6796(t *testing.T) {
	out := renderProtocols6796(t, bgpWithNeighbors6796("10.0.0.2", injectedNeighbor6796))

	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "peer 1.1.1.1") || strings.HasPrefix(trimmed, "peer 2.2.2.2") {
			t.Fatalf("a multi-token neighbor still produced a BFD peer: %q\n%s",
				line, out)
		}
	}
	// Control: the valid neighbor's BFD peer IS present, so the assertion above
	// is not passing because BFD rendering is off entirely.
	if !strings.Contains(out, "peer 10.0.0.2") {
		t.Fatalf("the valid neighbor produced no BFD peer, so the exclusion "+
			"assertion above proves nothing:\n%s", out)
	}
}

// TestNeighborTokenBeltAcceptsAHostname6796 is now the #15184 bare-IP belt
// test: hostnames / peer-group names are REJECTED (bgpd refuses them in
// this rendering), bare IPs accepted, multi-token still rejected.
func TestNeighborTokenBeltAcceptsAHostname6796(t *testing.T) {
	for _, addr := range []string{
		"10.0.0.2",
		"2001:db8::2",
	} {
		if !validBGPNeighborAddress(addr) {
			t.Errorf("validBGPNeighborAddress(%q) = false — bare IP must render", addr)
		}
	}
	for _, addr := range []string{
		"",
		"peer.example.com",
		"UPSTREAM-GROUP",
		"10.0.0.256",
		"192.0.2.0/24",
		"fe80::1%ge-0-0-1",
		"1.1.1.1 remote-as 65000",
		"1.1.1.1\nneighbor 2.2.2.2",
		"1.1.1.1\tremote-as 65000",
		"1.1.1.1\rneighbor 2.2.2.2",
	} {
		if validBGPNeighborAddress(addr) {
			t.Errorf("validBGPNeighborAddress(%q) = true — must be omitted (#15184/#6796)", addr)
		}
	}
}
