package frr

import (
	"strings"
	"testing"
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
