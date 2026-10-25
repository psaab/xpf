package nftables

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// TestRSTDropExprsScopedToConntrackless14949 pins the #14949 (D12-05)
// scoping as corrected by #15727 and #16839: every RST-drop rule must
// carry BOTH a conntrack-state predicate and a socket predicate that
// together match ONLY the kernel's no-socket RSTs, so that legitimate
// RSTs survive the xpf_dp_rst output chain:
//
//   - nft `reject with tcp reset` (policy reject / ident-reset) creates a
//     conntrack entry for the rejected connection before the synthesized
//     RST traverses OUTPUT, so its ct state is a tracked bit (new).
//   - Local control-plane socket RSTs (e.g. a refused local connection)
//     belong to a tracked connection, also a tracked bit -- but at the
//     raw priority (-300) this chain uses, conntrack (-200) has not run
//     yet, so a live socket's RST ALSO reads INVALID there (#16839).
//     The ct predicate alone therefore cannot spare it; the socket
//     predicate (socket wildcard == 1, below) is what does.
//
// The only RSTs this table exists to suppress are the kernel's spurious
// no-socket RSTs for userspace-owned interface-NAT flows (#450). The
// pre-#15727 shape matched `ct state & 0x4f == 0` ("ct state 0"), which
// can never fire: Linux nft_ct_get_eval (net/netfilter/nft_ct.c,
// NFT_CT_STATE) always writes a non-zero state -- NF_CT_STATE_BIT(ctinfo)
// for a tracked packet, NF_CT_STATE_UNTRACKED_BIT (0x40) when ctinfo is
// IP_CT_UNTRACKED, NF_CT_STATE_INVALID_BIT (0x01) otherwise. A locally
// generated RST (tcp_v4_send_reset via the per-cpu tcp_rst_sock control
// mini-socket, with any ingress-created entry detached by nf_reset_ct)
// has no entry when it reaches OUTPUT, so conntrack either attaches no
// entry (loose=0: the non-SYN fails tcp_new) or drops an invalid one (a
// lone RST in state NONE maps to TCP_CONNTRACK_MAX); OUTPUT then reads
// INVALID. INVALID is therefore a necessary conntrack-less signature at
// OUTPUT, which is what the ct half of the rule matches
// (mask==value==INVALID). Tracked packets never read INVALID once
// conntrack has run: a confirmed entry reports its ctinfo bit.
// UNTRACKED (0x40) never appears on locally generated output either --
// NOTRACK is an ingress raw-table decision the kernel's own RST never
// carries, and ctinfo==IP_CT_UNTRACKED requires it -- so it is
// deliberately not matched: widening to it would spend the drop budget
// on a class that cannot occur here without evidence it should drop.
//
// The socket half (#16839): nft_socket_eval (NFT_SOCKET_WILDCARD) stores
// 1 only for a full socket bound to a wildcard address, 0 for a full
// socket bound to a specific address, and BREAKs (no match) when there
// is no full socket at all. tcp_rst_sock is a wildcard-bound
// mini-socket, so the spurious RST reads wildcard 1 (measured live:
// 3/3 spurious vs 0/3 for wildcard 0); a live socket bound to the
// protected address reads wildcard 0 (measured live: 1/1), so its
// abortive RST is spared even though it reads INVALID at raw.
//
// Residual (#15727): with the host default nf_conntrack_tcp_loose=1 a
// bare non-RST segment may be picked up mid-stream on ingress; it still
// cannot attach to the locally generated RST (nf_reset_ct detaches any
// entry, and a lone RST creates none), so the INVALID signature holds.
//
// Fail-on-revert: reverting to the & 0x4f == 0 predicate (or deleting
// either predicate) fails the exact assertions below; widening the ct
// match to any tracked bit (e.g. also matching `new`) fails them too,
// as does inverting the socket value to 0.
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

		// The socket-wildcard predicate (#16839) must follow the ct
		// predicate: socket wildcard == 1 exactly. A live full socket
		// bound to the protected address reads 0 and is spared; the
		// wildcard-bound control mini-socket behind the spurious RST
		// reads 1; no socket at all BREAKs before the compare.
		sockIdx := ctIdx + 3
		if sockIdx+1 >= len(exprs) {
			t.Fatalf("%s: socket expression at %d not followed by cmp", addr, sockIdx)
		}
		sock, ok := exprs[sockIdx].(*expr.Socket)
		if !ok || sock.Key != expr.SocketKeyWildcard {
			t.Fatalf("%s: expr[%d] = %#v, want *expr.Socket{WILDCARD} after ct predicate (#16839)", addr, sockIdx, exprs[sockIdx])
		}
		scmp, ok := exprs[sockIdx+1].(*expr.Cmp)
		if !ok {
			t.Fatalf("%s: expr[%d] = %#v, want *expr.Cmp after Socket", addr, sockIdx+1, exprs[sockIdx+1])
		}
		if scmp.Op != expr.CmpOpEq || !bytes.Equal(scmp.Data, []byte{1}) {
			t.Errorf("%s: socket cmp = op %v data %x, want Eq [1] (socket wildcard == 1)", addr, scmp.Op, scmp.Data)
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
