package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15184: lenient load must omit non-IP neighbors instead of rendering them
// verbatim and breaking frr-reload.

func TestBGPNeighborAddressRenderOmitsBad15184(t *testing.T) {
	bad := []string{"10.0.0.256", "192.0.2.0/24", "peer-a", "peer.example.com", "fe80::1%ge-0-0-1", "2001:db8::1/64"}
	good := "192.0.2.1"
	addrs := append([]string{good}, bad...)
	out := renderProtocols6796(t, bgpWithNeighbors6796(addrs...))
	if !strings.Contains(out, "neighbor "+good+" remote-as 65000") {
		t.Fatalf("good neighbor not rendered:\n%s", out)
	}
	for _, b := range bad {
		if strings.Contains(out, "neighbor "+b) {
			t.Errorf("bad neighbor %q rendered:\n%s", b, out)
		}
		if strings.Contains(out, "peer "+b) {
			t.Errorf("bad neighbor %q rendered as BFD peer:\n%s", b, out)
		}
	}
	// valid v6 control
	out2 := renderProtocols6796(t, bgpWithNeighbors6796("2001:db8::1"))
	if !strings.Contains(out2, "neighbor 2001:db8::1 remote-as 65000") {
		t.Fatalf("good v6 neighbor not rendered:\n%s", out2)
	}
	for _, b := range bad {
		if validBGPNeighborAddress(b) {
			t.Errorf("validBGPNeighborAddress(%q)=true, want false", b)
		}
	}
	for _, g := range []string{"192.0.2.1", "2001:db8::1"} {
		if !validBGPNeighborAddress(g) {
			t.Errorf("validBGPNeighborAddress(%q)=false, want true", g)
		}
	}
}

// TestBGPNeighborAddressMatchesCommitGate17035 is the #17035 (R4-Q42-06)
// parity cell: the render belt must be the exported SSOT
// config.ValidBGPNeighborAddress, not a retyped netip.ParseAddr copy.
// The witnesses include the cases where the SSOT could diverge from a
// plain ParseAddr+zone copy (empty, surrounding whitespace/tab/newline,
// prefix and zone forms); any future gate change mirrored nowhere else
// surfaces here instead of silently reopening the tolerant-path seam.
func TestBGPNeighborAddressMatchesCommitGate17035(t *testing.T) {
	for _, s := range []string{
		"", " ", "192.0.2.1", "2001:db8::1", " 192.0.2.1", "192.0.2.1 ",
		"\t192.0.2.1", "192.0.2.1\n", "10.0.0.256", "192.0.2.0/24",
		"2001:db8::1/64", "fe80::1%ge-0-0-1", "fe80::1%eth0", "peer-a",
		"peer.example.com", "::", "::1", "0.0.0.0", "256.256.256.256",
	} {
		if got, want := validBGPNeighborAddress(s), config.ValidBGPNeighborAddress(s); got != want {
			t.Errorf("validBGPNeighborAddress(%q) = %v, want %v (config.ValidBGPNeighborAddress); belt and gate disagree", s, got, want)
		}
	}
}
