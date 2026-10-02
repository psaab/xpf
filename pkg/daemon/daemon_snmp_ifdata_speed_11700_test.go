package daemon

import (
	"net"
	"testing"

	nl "github.com/mdlayher/netlink"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #11700 red-before: a queued interface without a reported physical link rate
// must not acquire an invented 1Gbps ifSpeed/ifHighSpeed value.
func TestBuildSNMPIfDataDoesNotInferSpeedFromTxQLen11700(t *testing.T) {
	previous := snmpLinkLister
	previousSpeedReader := snmpLinkSpeedReader
	t.Cleanup(func() {
		snmpLinkLister = previous
		snmpLinkSpeedReader = previousSpeedReader
	})
	snmpLinkSpeedReader = func([]netlink.Link) map[int]uint32 { return nil }
	snmpLinkLister = func() ([]netlink.Link, error) {
		return []netlink.Link{&testLink{attrs: netlink.LinkAttrs{
			Index: 11700, Name: "queued11700", TxQLen: 1000,
			Flags: net.FlagUp, OperState: netlink.OperUp,
		}}}, nil
	}

	got := buildSNMPIfData()
	if len(got) != 1 {
		t.Fatalf("buildSNMPIfData returned %d interfaces, want one", len(got))
	}
	if got[0].IfSpeed != 0 || got[0].IfHighSpeed != 0 {
		t.Fatalf("unknown link rate was fabricated from TxQLen: ifSpeed=%d ifHighSpeed=%d, want 0/0",
			got[0].IfSpeed, got[0].IfHighSpeed)
	}
}

func TestBuildSNMPIfDataUsesEthtoolMbpsForBothSpeedColumns11700(t *testing.T) {
	previous := snmpLinkLister
	previousSpeedReader := snmpLinkSpeedReader
	t.Cleanup(func() {
		snmpLinkLister = previous
		snmpLinkSpeedReader = previousSpeedReader
	})
	snmpLinkLister = func() ([]netlink.Link, error) {
		return []netlink.Link{
			&testLink{attrs: netlink.LinkAttrs{Index: 11701, Name: "fast2500", OperState: netlink.OperUp}},
			&testLink{attrs: netlink.LinkAttrs{Index: 11702, Name: "unknown11700", TxQLen: 1000, OperState: netlink.OperUp}},
			&testLink{attrs: netlink.LinkAttrs{Index: 11703, Name: "fast25000", TxQLen: 1000, OperState: netlink.OperUp}},
		}, nil
	}
	snmpLinkSpeedReader = func(links []netlink.Link) map[int]uint32 {
		if len(links) != 3 {
			t.Fatalf("speed reader got %d links, want 3", len(links))
		}
		return map[int]uint32{
			11701: 2500,
			11702: ^uint32(0),
			11703: 25000,
		}
	}

	got := buildSNMPIfData()
	if len(got) != 3 {
		t.Fatalf("buildSNMPIfData returned %d interfaces, want three", len(got))
	}
	want := map[int]struct {
		ifSpeed     uint32
		ifHighSpeed uint32
	}{
		11701: {ifSpeed: 2_500_000_000, ifHighSpeed: 2500},
		11702: {ifSpeed: 0, ifHighSpeed: 0},
		11703: {ifSpeed: ^uint32(0), ifHighSpeed: 25000},
	}
	for _, entry := range got {
		expected, ok := want[entry.IfIndex]
		if !ok {
			t.Fatalf("unexpected interface index %d", entry.IfIndex)
		}
		if entry.IfSpeed != expected.ifSpeed || entry.IfHighSpeed != expected.ifHighSpeed {
			t.Errorf("ifIndex %d speed = %d bps/%d Mbps, want %d/%d",
				entry.IfIndex, entry.IfSpeed, entry.IfHighSpeed, expected.ifSpeed, expected.ifHighSpeed)
		}
	}
}

func TestParseEthtoolLinkSpeedNormalizesUnknown11700(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   uint32
		want uint32
	}{
		{name: "unknown", in: ^uint32(0), want: 0},
		{name: "known", in: 25000, want: 25000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := nl.NewAttributeEncoder()
			attrs.Uint32(uint16(unix.ETHTOOL_A_LINKMODES_SPEED), tc.in)
			data, err := attrs.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			got, found, err := parseEthtoolLinkSpeed(data)
			if err != nil {
				t.Fatalf("parseEthtoolLinkSpeed: %v", err)
			}
			if !found || got != tc.want {
				t.Fatalf("parseEthtoolLinkSpeed = %d, found=%v; want %d,true", got, found, tc.want)
			}
		})
	}
}
