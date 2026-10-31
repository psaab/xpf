package vipstamp

import (
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// #18573: the stamp's encode and decode halves agree, and the decoder fails
// closed. The kernel half (that the kernel keeps and reports IFA_PROTO, and
// that REPLACE rewrites it in place) is pinned by the pkg/daemon kernel cells
// TestDirectVIPStampRoundTripsThroughTheKernel18573 and
// TestDirectVIPRenumberOnKernel18573.

func serialize(data []nl.NetlinkRequestData) []byte {
	var out []byte
	for _, d := range data {
		out = append(out, d.Serialize()...)
	}
	return out
}

func TestRequestDataRoundTripsThroughParseRow18573(t *testing.T) {
	for _, s := range []string{"172.16.50.42/24", "2001:db8:50::42/64", "fe80::1/64", "10.0.0.1/31", "10.0.0.1/32"} {
		p := netip.MustParsePrefix(s)
		raw := serialize(RequestData(9, p))
		row, ok, err := ParseRow(raw)
		if err != nil || !ok {
			t.Fatalf("%s: ParseRow ok=%v err=%v", s, ok, err)
		}
		if row.LinkIndex != 9 || row.Prefix != p || row.Proto != Proto || !row.Stamped() {
			t.Fatalf("%s: round trip = %+v", s, row)
		}
		msg := nl.DeserializeIfAddrmsg(raw)
		if p.Addr().Is6() && msg.Flags&unix.IFA_F_NODAD == 0 {
			t.Fatalf("%s: IPv6 VIP must carry IFA_F_NODAD", s)
		}
		if p.Addr().Is4() && msg.Flags != 0 {
			t.Fatalf("%s: IPv4 VIP flags = %#x, want 0", s, msg.Flags)
		}
	}
}

// IPv4 below /31 carries the broadcast netlink v1.3.1's AddrAdd computed, so
// a stamped VIP is the address the library used to install plus IFA_PROTO.
func TestRequestDataMirrorsLibraryBroadcast18573(t *testing.T) {
	brd := func(s string) []byte {
		raw := serialize(RequestData(9, netip.MustParsePrefix(s)))
		attrs, err := nl.ParseRouteAttr(raw[unix.SizeofIfAddrmsg:])
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range attrs {
			if a.Attr.Type == unix.IFA_BROADCAST {
				return a.Value
			}
		}
		return nil
	}
	if got := brd("172.16.50.42/24"); netip.AddrFrom4([4]byte(got)) != netip.MustParseAddr("172.16.50.255") {
		t.Fatalf("/24 broadcast = %v", got)
	}
	if got := brd("10.0.0.1/31"); got != nil {
		t.Fatalf("/31 must carry no broadcast, got %v", got)
	}
}

func TestParseRowFailsClosed18573(t *testing.T) {
	good := serialize(RequestData(9, netip.MustParsePrefix("10.0.0.1/24")))
	if _, _, err := ParseRow(good[:4]); err == nil {
		t.Fatal("short row must error")
	}
	msg := nl.NewIfAddrmsg(unix.AF_INET)
	msg.Prefixlen = 24
	cases := map[string][]nl.NetlinkRequestData{
		"proto width":   {msg, nl.NewRtAttr(unix.IFA_LOCAL, []byte{10, 0, 0, 1}), nl.NewRtAttr(IFAProto, []byte{Proto, 0})},
		"local width":   {msg, nl.NewRtAttr(unix.IFA_LOCAL, []byte{10, 0, 0})},
		"address width": {msg, nl.NewRtAttr(unix.IFA_ADDRESS, make([]byte, 16))},
		"no address":    {msg, nl.NewRtAttr(IFAProto, []byte{Proto})},
	}
	for name, data := range cases {
		if _, _, err := ParseRow(serialize(data)); err == nil {
			t.Fatalf("%s: malformed row decoded without error", name)
		}
	}
	wide := nl.NewIfAddrmsg(unix.AF_INET)
	wide.Prefixlen = 33
	if _, _, err := ParseRow(serialize([]nl.NetlinkRequestData{wide, nl.NewRtAttr(unix.IFA_LOCAL, []byte{10, 0, 0, 1})})); err == nil {
		t.Fatal("prefixlen beyond the family width must error")
	}
	other := nl.NewIfAddrmsg(unix.AF_PACKET)
	if _, ok, err := ParseRow(serialize([]nl.NetlinkRequestData{other})); ok || err != nil {
		t.Fatalf("non-IP family: ok=%v err=%v, want skipped", ok, err)
	}
	// No IFA_PROTO at all (a kernel that omits it for proto 0): unstamped.
	row, ok, err := ParseRow(serialize([]nl.NetlinkRequestData{msg, nl.NewRtAttr(unix.IFA_LOCAL, []byte{10, 0, 0, 1})}))
	if err != nil || !ok || row.Stamped() {
		t.Fatalf("proto-less row: %+v ok=%v err=%v", row, ok, err)
	}
	// IPv4: IFA_LOCAL wins over a differing IFA_ADDRESS (peer).
	row, _, _ = ParseRow(serialize([]nl.NetlinkRequestData{msg,
		nl.NewRtAttr(unix.IFA_ADDRESS, []byte{10, 0, 0, 2}), nl.NewRtAttr(unix.IFA_LOCAL, []byte{10, 0, 0, 1})}))
	if row.Prefix != netip.MustParsePrefix("10.0.0.1/24") {
		t.Fatalf("IFA_LOCAL must win: %v", row.Prefix)
	}
}

func TestLeftoverPredicate18573(t *testing.T) {
	p := netip.MustParsePrefix("172.16.50.10/24")
	configured := map[string]map[string]bool{"ge-0-0-2.50": {"172.16.50.42/24": true}, "ge-0-0-1": {"172.16.50.10/24": true}}
	cases := []struct {
		name   string
		row    Row
		netdev string
		want   bool
	}{
		{"stamped, not configured on its netdev", Row{Prefix: p, Proto: Proto}, "ge-0-0-2.50", true},
		{"unstamped, not configured", Row{Prefix: p}, "ge-0-0-2.50", false},
		{"other proto (kernel_ll)", Row{Prefix: p, Proto: 3}, "ge-0-0-2.50", false},
		{"stamped, configured on THIS netdev", Row{Prefix: p, Proto: Proto}, "ge-0-0-1", false},
		{"stamped, netdev unresolved", Row{Prefix: p, Proto: Proto}, "", false},
		{"stamped, same host other prefix", Row{Prefix: netip.MustParsePrefix("172.16.50.42/25"), Proto: Proto}, "ge-0-0-2.50", true},
	}
	for _, c := range cases {
		if got := Leftover(c.row, c.netdev, configured); got != c.want {
			t.Errorf("%s: Leftover = %v, want %v", c.name, got, c.want)
		}
	}
}
