package nftables

import (
	"bytes"
	"net"
	"net/netip"
	"testing"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// TestRSTDropExprsShape pins the wire shape of one RST-drop rule (#7171).
//
// The package had two tests, both about delete-plan logic, and none about what
// the rule actually matches. That is the gap that matters here: every field
// below is silently wrong rather than loudly wrong. A transposed saddr offset
// reads the wrong bytes of the IP header, a wrong family byte matches the wrong
// protocol, a wrong flags mask matches the wrong TCP flag -- and in every case
// nftables accepts the rule, the install reports success, and the only symptom
// is that the RST it exists to suppress is not suppressed.
func TestRSTDropExprsShape(t *testing.T) {
	for _, tc := range []struct {
		name        string
		addr        netip.Addr
		wantBytes   net.IP
		addrLen     uint32
		saddrOffset uint32
		family      byte
	}{
		{"ipv4", netip.MustParseAddr("192.0.2.1"), net.IP{192, 0, 2, 1}, 4, 12, unix.NFPROTO_IPV4},
		{"ipv6", netip.MustParseAddr("2001:db8::1"), net.ParseIP("2001:db8::1").To16(), 16, 8, unix.NFPROTO_IPV6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exprs := rstDropExprs(tc.addr)

			// meta nfproto <family>
			if m, ok := exprs[0].(*expr.Meta); !ok || m.Key != expr.MetaKeyNFPROTO {
				t.Fatalf("expr[0] = %#v, want Meta{NFPROTO}", exprs[0])
			}
			if c, ok := exprs[1].(*expr.Cmp); !ok || c.Op != expr.CmpOpEq || !bytes.Equal(c.Data, []byte{tc.family}) {
				t.Fatalf("expr[1] = %#v, want Cmp{Eq, family=%d}", exprs[1], tc.family)
			}

			// ip/ip6 saddr == addr -- the transposition-sensitive pair
			p, ok := exprs[2].(*expr.Payload)
			if !ok || p.Base != expr.PayloadBaseNetworkHeader {
				t.Fatalf("expr[2] = %#v, want Payload{NetworkHeader}", exprs[2])
			}
			if p.Offset != tc.saddrOffset {
				t.Errorf("saddr offset = %d, want %d", p.Offset, tc.saddrOffset)
			}
			if p.Len != tc.addrLen {
				t.Errorf("saddr len = %d, want %d", p.Len, tc.addrLen)
			}
			if c, ok := exprs[3].(*expr.Cmp); !ok || !bytes.Equal(c.Data, tc.wantBytes) {
				t.Fatalf("expr[3] = %#v, want Cmp{Eq, %v}", exprs[3], tc.wantBytes)
			}

			// ct state predicate at [4..6] is pinned separately by
			// TestRSTDropExprsScopedToConntrackless14949 (#14949); here
			// we only require it to be present so the indices below stay
			// honest about the rule's full shape.
			if ct, ok := exprs[4].(*expr.Ct); !ok || ct.Key != expr.CtKeySTATE {
				t.Fatalf("expr[4] = %#v, want Ct{STATE} (#14949 conntrack-less scoping)", exprs[4])
			}

			// meta l4proto tcp
			if m, ok := exprs[7].(*expr.Meta); !ok || m.Key != expr.MetaKeyL4PROTO {
				t.Fatalf("expr[7] = %#v, want Meta{L4PROTO}", exprs[7])
			}
			if c, ok := exprs[8].(*expr.Cmp); !ok || !bytes.Equal(c.Data, []byte{unix.IPPROTO_TCP}) {
				t.Fatalf("expr[8] = %#v, want Cmp{Eq, IPPROTO_TCP}", exprs[8])
			}

			// tcp flags & RST != 0. Offset 13 is the TCP flags byte and the
			// mask is RST (0x04) -- 0x02 would match SYN, 0x01 FIN, and any
			// of those installs cleanly while suppressing the wrong packet.
			fp, ok := exprs[9].(*expr.Payload)
			if !ok || fp.Base != expr.PayloadBaseTransportHeader {
				t.Fatalf("expr[9] = %#v, want Payload{TransportHeader}", exprs[9])
			}
			if fp.Offset != 13 || fp.Len != 1 {
				t.Errorf("tcp flags payload = offset %d len %d, want offset 13 len 1", fp.Offset, fp.Len)
			}
			b, ok := exprs[10].(*expr.Bitwise)
			if !ok || !bytes.Equal(b.Mask, []byte{0x04}) || !bytes.Equal(b.Xor, []byte{0x00}) {
				t.Fatalf("expr[10] = %#v, want Bitwise{mask 0x04, xor 0x00}", exprs[10])
			}
			if c, ok := exprs[11].(*expr.Cmp); !ok || c.Op != expr.CmpOpNeq || !bytes.Equal(c.Data, []byte{0x00}) {
				t.Fatalf("expr[11] = %#v, want Cmp{Neq, 0x00}", exprs[11])
			}

			// counter then drop -- a rule that matches but does not drop is
			// the same silent failure as one that never matches.
			if _, ok := exprs[12].(*expr.Counter); !ok {
				t.Fatalf("expr[12] = %#v, want Counter", exprs[12])
			}
			if v, ok := exprs[13].(*expr.Verdict); !ok || v.Kind != expr.VerdictDrop {
				t.Fatalf("expr[13] = %#v, want Verdict{Drop}", exprs[13])
			}
			if len(exprs) != 14 {
				t.Errorf("len(exprs) = %d, want 14", len(exprs))
			}
		})
	}
}

// TestRSTDropExprsFamiliesDiffer guards the transposition directly. The
// per-family test above passes if BOTH families are given the same wrong
// offset by a future edit that "fixes" one to match the other, because each
// case only checks itself against its own expectation. This asserts the two
// families disagree, which no single-family assertion can express.
func TestRSTDropExprsFamiliesDiffer(t *testing.T) {
	v4 := rstDropExprs(netip.MustParseAddr("192.0.2.1"))
	v6 := rstDropExprs(netip.MustParseAddr("2001:db8::1"))

	p4 := v4[2].(*expr.Payload)
	p6 := v6[2].(*expr.Payload)
	if p4.Offset == p6.Offset {
		t.Errorf("v4 and v6 saddr offsets both %d; IPv4 saddr is at 12, IPv6 at 8", p4.Offset)
	}
	if p4.Len == p6.Len {
		t.Errorf("v4 and v6 saddr lengths both %d; want 4 and 16", p4.Len)
	}
	c4 := v4[1].(*expr.Cmp)
	c6 := v6[1].(*expr.Cmp)
	if bytes.Equal(c4.Data, c6.Data) {
		t.Errorf("v4 and v6 nfproto both %v", c4.Data)
	}
}
