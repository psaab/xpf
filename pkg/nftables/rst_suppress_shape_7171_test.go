package nftables

import (
	"bytes"
	"net"
	"net/netip"
	"testing"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// TestRSTDropExprsShape pins the wire shape of the family-specific RST rules.
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

			if m, ok := exprs[0].(*expr.Meta); !ok || m.Key != expr.MetaKeyNFPROTO {
				t.Fatalf("expr[0] = %#v, want Meta{NFPROTO}", exprs[0])
			}
			if c, ok := exprs[1].(*expr.Cmp); !ok || c.Op != expr.CmpOpEq || !bytes.Equal(c.Data, []byte{tc.family}) {
				t.Fatalf("expr[1] = %#v, want Cmp{Eq, family=%d}", exprs[1], tc.family)
			}
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
			if ct, ok := exprs[4].(*expr.Ct); !ok || ct.Key != expr.CtKeySTATE {
				t.Fatalf("expr[4] = %#v, want Ct{STATE}", exprs[4])
			}

			l4Idx := 7
			if tc.addr.Is4() {
				if s, ok := exprs[7].(*expr.Socket); !ok || s.Key != expr.SocketKeyWildcard {
					t.Fatalf("expr[7] = %#v, want Socket{WILDCARD}", exprs[7])
				}
				if c, ok := exprs[8].(*expr.Cmp); !ok || c.Op != expr.CmpOpEq || !bytes.Equal(c.Data, []byte{1}) {
					t.Fatalf("expr[8] = %#v, want Cmp{Eq, socket wildcard 1}", exprs[8])
				}
				l4Idx = 9
			} else {
				for i, e := range exprs {
					if _, ok := e.(*expr.Socket); ok {
						t.Fatalf("IPv6 socketless drop rule unexpectedly has socket expression at %d", i)
					}
				}
			}
			if m, ok := exprs[l4Idx].(*expr.Meta); !ok || m.Key != expr.MetaKeyL4PROTO {
				t.Fatalf("expr[%d] = %#v, want Meta{L4PROTO}", l4Idx, exprs[l4Idx])
			}
			if c, ok := exprs[l4Idx+1].(*expr.Cmp); !ok || !bytes.Equal(c.Data, []byte{unix.IPPROTO_TCP}) {
				t.Fatalf("expr[%d] = %#v, want Cmp{Eq, IPPROTO_TCP}", l4Idx+1, exprs[l4Idx+1])
			}
			fp, ok := exprs[l4Idx+2].(*expr.Payload)
			if !ok || fp.Base != expr.PayloadBaseTransportHeader || fp.Offset != 13 || fp.Len != 1 {
				t.Fatalf("expr[%d] = %#v, want TCP flags byte at offset 13", l4Idx+2, exprs[l4Idx+2])
			}
			b, ok := exprs[l4Idx+3].(*expr.Bitwise)
			if !ok || !bytes.Equal(b.Mask, []byte{0x04}) || !bytes.Equal(b.Xor, []byte{0x00}) {
				t.Fatalf("expr[%d] = %#v, want RST mask 0x04", l4Idx+3, exprs[l4Idx+3])
			}
			if c, ok := exprs[l4Idx+4].(*expr.Cmp); !ok || c.Op != expr.CmpOpNeq || !bytes.Equal(c.Data, []byte{0}) {
				t.Fatalf("expr[%d] = %#v, want Cmp{Neq, 0}", l4Idx+4, exprs[l4Idx+4])
			}
			if _, ok := exprs[l4Idx+5].(*expr.Counter); !ok {
				t.Fatalf("expr[%d] = %#v, want Counter", l4Idx+5, exprs[l4Idx+5])
			}
			if v, ok := exprs[l4Idx+6].(*expr.Verdict); !ok || v.Kind != expr.VerdictDrop {
				t.Fatalf("expr[%d] = %#v, want Verdict{Drop}", l4Idx+6, exprs[l4Idx+6])
			}
			if len(exprs) != l4Idx+7 {
				t.Errorf("len(exprs) = %d, want %d", len(exprs), l4Idx+7)
			}
		})
	}
}

// TestRSTLiveSocketReturnExprsV6 pins the IPv6 live-socket exception. The
// no-socket IPv6 RST BREAKs at Socket, falls through, and is matched by the
// socketless drop rule checked above.
func TestRSTLiveSocketReturnExprsV6(t *testing.T) {
	exprs := rstLiveSocketReturnExprs(netip.MustParseAddr("2001:db8::1"))
	if s, ok := exprs[7].(*expr.Socket); !ok || s.Key != expr.SocketKeyWildcard {
		t.Fatalf("expr[7] = %#v, want Socket{WILDCARD}", exprs[7])
	}
	if c, ok := exprs[8].(*expr.Cmp); !ok || c.Op != expr.CmpOpEq || !bytes.Equal(c.Data, []byte{0}) {
		t.Fatalf("expr[8] = %#v, want Cmp{Eq, socket wildcard 0}", exprs[8])
	}
	if _, ok := exprs[len(exprs)-2].(*expr.Cmp); !ok {
		t.Fatalf("penultimate expression = %#v, want RST comparison", exprs[len(exprs)-2])
	}
	if v, ok := exprs[len(exprs)-1].(*expr.Verdict); !ok || v.Kind != expr.VerdictReturn {
		t.Fatalf("last expression = %#v, want Verdict{Return}", exprs[len(exprs)-1])
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
