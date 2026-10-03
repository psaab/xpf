package routing

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

func ruleRowWithDSCPSelector11685(t *testing.T, priority, table int, dst string, dscp *uint8) []byte {
	t.Helper()
	msg := nl.NewRtMsg()
	msg.Family = unix.AF_INET
	msg.Dst_len = 24
	row := msg.Serialize()
	_, prefix, err := net.ParseCIDR(dst)
	if err != nil {
		t.Fatal(err)
	}
	attrs := []*nl.RtAttr{
		nl.NewRtAttr(nl.FRA_PRIORITY, nl.Uint32Attr(uint32(priority))),
		nl.NewRtAttr(unix.RTA_TABLE, nl.Uint32Attr(uint32(table))),
		nl.NewRtAttr(nl.FRA_DST, []byte(prefix.IP.To4())),
	}
	if dscp != nil {
		attrs = append(attrs, nl.NewRtAttr(FRA_DSCP, nl.Uint8Attr(*dscp)))
	}
	for _, attr := range attrs {
		row = append(row, attr.Serialize()...)
	}
	return row
}

func TestDSCPSelectorFromRuleRow11685(t *testing.T) {
	for _, tc := range []struct {
		name       string
		dscp       *uint8
		wantDSCP   uint8
		wantScoped bool
	}{
		{name: "zero is present and scoped", dscp: dscpValue11685(0), wantDSCP: 0, wantScoped: true},
		{name: "nonzero selector", dscp: dscpValue11685(46), wantDSCP: 46, wantScoped: true},
		{name: "no FRA_DSCP is not scoped", dscp: nil, wantScoped: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := ruleRowWithDSCPSelector11685(t, 30016, 100, "198.51.100.0/24", tc.dscp)
			got, scoped, err := dscpSelectorFromRuleRow(row)
			if err != nil {
				t.Fatalf("dscpSelectorFromRuleRow: %v", err)
			}
			if scoped != tc.wantScoped {
				t.Fatalf("scoped=%t, want %t", scoped, tc.wantScoped)
			}
			if !scoped {
				return
			}
			if got.Priority != 30016 || got.Table != 100 || got.Dst != "198.51.100.0/24" || got.DSCP != tc.wantDSCP {
				t.Fatalf("selector = %+v, want priority/table/dst/dscp = 30016/100/198.51.100.0/24/%d", got, tc.wantDSCP)
			}
		})
	}
}

func dscpValue11685(value uint8) *uint8 { return &value }
