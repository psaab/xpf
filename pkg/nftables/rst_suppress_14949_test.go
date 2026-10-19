package nftables

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// TestRSTDropExprsScopedToConntrackless14949 pins the #14949 (D12-05) fix:
// every RST-drop rule must carry a conntrack-state predicate that matches
// ONLY packets with no conntrack entry (ct state == 0), so that
// conntrack-tracked RSTs survive the xpf_dp_rst output chain:
//
//   - nft `reject with tcp reset` (policy reject / ident-reset) creates a
//     conntrack entry for the rejected connection before the synthesized
//     RST traverses OUTPUT, so its ct state is non-zero (new).
//   - Local control-plane socket RSTs (e.g. a refused local connection)
//     belong to a tracked connection, also non-zero ct state.
//
// The only RSTs this table exists to suppress are the kernel's spurious
// no-socket RSTs for userspace-owned interface-NAT flows (#450): those
// arrive with no conntrack entry at all (ct state 0), because the
// userspace dataplane owns the flow and the kernel never tracked it.
//
// Fail-on-revert: deleting the ct predicate (the pre-fix shape) leaves a
// bare saddr+RST drop that also kills the tracked RSTs above, and this
// test fails because no *expr.Ct / state-zero comparison exists. Widening
// the predicate to also match a tracked state (e.g. mask covering `new`)
// fails the exact mask/zero assertions below.
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
		// The mask must cover every known ct-state bit (invalid,
		// established, related, new, untracked) so that ANY tracked
		// packet — whatever single state it carries — is excluded.
		// A narrower mask (e.g. only established|related) would let a
		// `new`-state reject RST fall through to the drop.
		wantMask := binaryutil.NativeEndian.PutUint32(
			expr.CtStateBitINVALID | expr.CtStateBitESTABLISHED |
				expr.CtStateBitRELATED | expr.CtStateBitNEW |
				expr.CtStateBitUNTRACKED)
		if bw.Len != 4 || !bytes.Equal(bw.Mask, wantMask) || !bytes.Equal(bw.Xor, []byte{0, 0, 0, 0}) {
			t.Errorf("%s: ct bitwise = len %d mask %x xor %x, want len 4 mask %x xor 00000000 "+
				"(any tracked state must be excluded)", addr, bw.Len, bw.Mask, bw.Xor, wantMask)
		}
		cmp, ok := exprs[ctIdx+2].(*expr.Cmp)
		if !ok {
			t.Fatalf("%s: expr[%d] = %#v, want *expr.Cmp after ct bitwise", addr, ctIdx+2, exprs[ctIdx+2])
		}
		// Equality against zero: match only when NO state bit is set,
		// i.e. no conntrack entry exists for the packet.
		if cmp.Op != expr.CmpOpEq || !bytes.Equal(cmp.Data, []byte{0, 0, 0, 0}) {
			t.Errorf("%s: ct cmp = op %v data %x, want Eq 00000000 (conntrack-less only)", addr, cmp.Op, cmp.Data)
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
