package daemon

import (
	"strings"
	"testing"
)

// #9016 (re-scoped by #11076): EVERY configured listen-port is admitted, not
// just the steered one — but admission is per-zone, not global. The former
// test pinned a single coarse `udp dport { 51820, 51821 } accept`; that bare
// rule reached every local address including lifeline/mgmt and no-stanza
// zones (#11076). Now each zone's ports render as a daddr-scoped accept
// inside that zone's own section.
func TestHostInboundAdmitsEveryWireGuardPort9016(t *testing.T) {
	var rules []string
	emitHostInboundZoneWireGuardAccept(&rules, "ip daddr { 10.0.1.1, 10.0.1.2 }", []uint16{51820, 51821})
	joined := strings.Join(rules, "\n")

	for _, port := range []string{"51820", "51821"} {
		if !strings.Contains(joined, port) {
			t.Fatalf("host-inbound accept omits configured WireGuard port %s; if only the "+
				"steered port were admitted, the unsteered tunnel really would be dead "+
				"and the advisory's old wording would have been right:\n%s", port, joined)
		}
	}
	if !strings.Contains(joined, "ip daddr") {
		t.Fatalf("zone WG accept must be daddr-scoped, got:\n%s", joined)
	}

	// CONTROL: no ports configured emits nothing. Without this, a renderer that
	// emitted a blanket accept would pass the assertions above while opening
	// every UDP port on the box.
	var none []string
	emitHostInboundZoneWireGuardAccept(&none, "ip daddr { 10.0.1.1 }", nil)
	if len(none) != 0 {
		t.Fatalf("no configured WireGuard ports must emit no accept rule, got: %v", none)
	}

	// CONTROL: a single port emits that port and not the other.
	var one []string
	emitHostInboundZoneWireGuardAccept(&one, "ip daddr { 10.0.1.1 }", []uint16{51820})
	got := strings.Join(one, "\n")
	if !strings.Contains(got, "51820") || strings.Contains(got, "51821") {
		t.Fatalf("single-port accept should mention only 51820:\n%s", got)
	}
}
