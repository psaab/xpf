package daemon

import (
	"strings"
	"testing"
)

// #9016: the comment on emitHostInboundWireGuardAccept called the second port's
// rule "a no-op at the kernel (nothing steers that port up)". It is not a
// no-op — it is precisely what ADMITS that port's traffic to the host, where
// the second tunnel's own bound socket receives it. That misreading is what
// made a live path look inert, and it fed the pkg/config advisory's false
// "dead tunnel" claim.
//
// #9521 changed what that socket does with a TRANSPORT record — the helper now
// drops it rather than writing its plaintext to the wgN TUN — but not the need
// for this rule: the unsteered tunnel's handshakes still arrive here, and a
// passive handshake to a restricted zone would be dropped without the admit.
//
// This cell pins the behaviour the corrected comment asserts: EVERY configured
// listen-port is admitted, not just the steered one.
func TestHostInboundAdmitsEveryWireGuardPort9016(t *testing.T) {
	var rules []string
	emitHostInboundWireGuardAccept(&rules, []uint16{51820, 51821})
	joined := strings.Join(rules, "\n")

	for _, port := range []string{"51820", "51821"} {
		if !strings.Contains(joined, port) {
			t.Fatalf("host-inbound accept omits configured WireGuard port %s; if only the "+
				"steered port were admitted, the unsteered tunnel really would be dead "+
				"and the advisory's old wording would have been right:\n%s", port, joined)
		}
	}

	// CONTROL: no ports configured emits nothing. Without this, a renderer that
	// emitted a blanket accept would pass the assertions above while opening
	// every UDP port on the box.
	var none []string
	emitHostInboundWireGuardAccept(&none, nil)
	if len(none) != 0 {
		t.Fatalf("no configured WireGuard ports must emit no accept rule, got: %v", none)
	}

	// CONTROL: a single port emits that port and not the other.
	var one []string
	emitHostInboundWireGuardAccept(&one, []uint16{51820})
	got := strings.Join(one, "\n")
	if !strings.Contains(got, "51820") || strings.Contains(got, "51821") {
		t.Fatalf("single-port accept should mention only 51820:\n%s", got)
	}
}
