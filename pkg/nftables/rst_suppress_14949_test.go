package nftables

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// TestRSTDropExprsScopedToConntrackless14949 pins the #14949 (D12-05)
// conntrack scoping and the family-specific socket treatment corrected by
// #15727, #16839, and #17868.
//
// At raw OUTPUT, conntrack has not run yet. A live socket's RST also reads
// INVALID, so IPv4 requires the wildcard-bound tcp_rst_sock mini-socket
// predicate to spare full sockets. IPv6 socketless kernel RST skbs have no
// skb->sk, so nft_socket_eval BREAKs before the wildcard value can be tested.
// IPv6 instead returns full address-bound live-socket RSTs in an earlier
// rule, then drops socketless RSTs with no socket expression.
//
// The ct predicate is exactly INVALID (0x01): nft_ct_get_eval always writes
// INVALID, UNTRACKED, or a tracked ctinfo bit. The former `ct state & 0x4f == 0`
// predicate was unsatisfiable. UNTRACKED requires a NOTRACK ingress decision
// that locally generated RSTs do not carry, so it is deliberately excluded.
//
// Fail-on-revert: restoring the unsatisfiable ct predicate, removing the
// family-specific live-socket handling, or restoring a shared wildcard==1
// predicate makes these assertions fail.
func TestRSTDropExprsScopedToConntrackless14949(t *testing.T) {
	for _, addr := range []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
	} {
		exprs := rstDropExprs(addr)

		// Locate the ct-state predicate: Ct{STATE} + Bitwise + Cmp.
		ctIdx := -1
		for i, e := range exprs {
			if ct, ok := e.(*expr.Ct); ok && ct.Key == expr.CtKeySTATE {
				ctIdx = i
				break
			}
		}
		if ctIdx < 0 {
			t.Fatalf("%s: no ct-state expression in %d exprs — the drop is not scoped to conntrack-less RSTs (#14949)", addr, len(exprs))
		}
		if ctIdx+2 >= len(exprs) {
			t.Fatalf("%s: ct-state expression at %d not followed by bitwise+cmp", addr, ctIdx)
		}
		bw, ok := exprs[ctIdx+1].(*expr.Bitwise)
		if !ok {
			t.Fatalf("%s: expr[%d] = %#v, want *expr.Bitwise after Ct", addr, ctIdx+1, exprs[ctIdx+1])
		}
		// The mask/value pair must be exactly INVALID (0x01): that is
		// the sole state nft_ct_get_eval reports for a packet with no
		// conntrack entry, and the only conntrack-less signature a
		// locally generated RST presents at OUTPUT (#15727). The old
		// mask 0x4f compared against zero is unsatisfiable kernel-wide.
		want := binaryutil.NativeEndian.PutUint32(expr.CtStateBitINVALID)
		if bw.Len != 4 || !bytes.Equal(bw.Mask, want) || !bytes.Equal(bw.Xor, []byte{0, 0, 0, 0}) {
			t.Errorf("%s: ct bitwise = len %d mask %x xor %x, want len 4 mask %x xor 00000000 "+
				"(match INVALID only)", addr, bw.Len, bw.Mask, bw.Xor, want)
		}
		cmp, ok := exprs[ctIdx+2].(*expr.Cmp)
		if !ok {
			t.Fatalf("%s: expr[%d] = %#v, want *expr.Cmp after ct bitwise", addr, ctIdx+2, exprs[ctIdx+2])
		}
		// Equality against INVALID itself, not zero: state & 1 == 1.
		if cmp.Op != expr.CmpOpEq || !bytes.Equal(cmp.Data, want) {
			t.Errorf("%s: ct cmp = op %v data %x, want Eq %x (ct state invalid)", addr, cmp.Op, cmp.Data, want)
		}

		// IPv4 uses wildcard==1 to identify the control mini-socket. IPv6
		// drops socketless RSTs without a Socket expression and has a
		// separate wildcard==0 live-socket exception rule.
		if addr.Is4() {
			sockIdx := ctIdx + 3
			if sockIdx+1 >= len(exprs) {
				t.Fatalf("%s: socket expression at %d not followed by cmp", addr, sockIdx)
			}
			sock, ok := exprs[sockIdx].(*expr.Socket)
			if !ok || sock.Key != expr.SocketKeyWildcard {
				t.Fatalf("%s: expr[%d] = %#v, want *expr.Socket{WILDCARD}", addr, sockIdx, exprs[sockIdx])
			}
			scmp, ok := exprs[sockIdx+1].(*expr.Cmp)
			if !ok || scmp.Op != expr.CmpOpEq || !bytes.Equal(scmp.Data, []byte{1}) {
				t.Fatalf("%s: expr[%d] = %#v, want Cmp{Eq, 1} for IPv4 control mini-socket", addr, sockIdx+1, exprs[sockIdx+1])
			}
		} else {
			for i, e := range exprs {
				if _, ok := e.(*expr.Socket); ok {
					t.Fatalf("%s: socketless IPv6 drop expression %d unexpectedly has Socket predicate", addr, i)
				}
			}
			liveExprs := rstLiveSocketReturnExprs(addr)
			sockIdx := ctIdx + 3
			if len(liveExprs) <= sockIdx+1 {
				t.Fatalf("%s: live-socket exception has no wildcard comparison", addr)
			}
			sock, ok := liveExprs[sockIdx].(*expr.Socket)
			if !ok || sock.Key != expr.SocketKeyWildcard {
				t.Fatalf("%s: live exception expr[%d] = %#v, want *expr.Socket{WILDCARD}", addr, sockIdx, liveExprs[sockIdx])
			}
			scmp, ok := liveExprs[sockIdx+1].(*expr.Cmp)
			if !ok || scmp.Op != expr.CmpOpEq || !bytes.Equal(scmp.Data, []byte{0}) {
				t.Fatalf("%s: live exception expr[%d] = %#v, want Cmp{Eq, 0}", addr, sockIdx+1, liveExprs[sockIdx+1])
			}
			if v, ok := liveExprs[len(liveExprs)-1].(*expr.Verdict); !ok || v.Kind != expr.VerdictReturn {
				t.Fatalf("%s: live exception final expression = %#v, want Verdict{Return}", addr, liveExprs[len(liveExprs)-1])
			}
		}

		// The rule must still terminate in counter+drop (the scoped
		// suppression itself must not be weakened), and the ct
		// predicate must precede the verdict so tracked RSTs are not
		// counted/dropped.
		n := len(exprs)
		if _, ok := exprs[n-2].(*expr.Counter); !ok {
			t.Errorf("%s: expr[%d] = %#v, want Counter before verdict", addr, n-2, exprs[n-2])
		}
		if v, ok := exprs[n-1].(*expr.Verdict); !ok || v.Kind != expr.VerdictDrop {
			t.Errorf("%s: expr[%d] = %#v, want Verdict{Drop}", addr, n-1, exprs[n-1])
		}
		if ctIdx > n-3 {
			t.Errorf("%s: ct predicate at %d must precede counter/drop", addr, ctIdx)
		}
	}
}
