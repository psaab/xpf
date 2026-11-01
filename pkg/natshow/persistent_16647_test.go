package natshow

import (
	"context"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #16647: the detail renderer must show protocol, routing scope and the
// granted remotes, not only the (previously always any-remote-host) permit.

func TestRenderPersistentDetailShowsProtocolScopeAndGrants16647(t *testing.T) {
	pnat := dataplane.NewPersistentNATTable()
	pnat.Save(&dataplane.PersistentNATBinding{
		SrcIP:        netip.MustParseAddr("10.0.1.5"),
		SrcPort:      1111,
		NatIP:        netip.MustParseAddr("203.0.113.1"),
		NatPort:      40000,
		PoolName:     "p-src",
		LastSeen:     time.Now(),
		Timeout:      600 * time.Second,
		Permit:       config.PersistentNATPermitTargetHost,
		Protocol:     17,
		RoutingScope: 7,
		PermittedRemotes: []dataplane.PersistentNATRemote{
			{IP: netip.MustParseAddr("8.8.8.8"), Port: 0},
		},
	})
	var b strings.Builder
	RenderPersistentDetail(context.Background(), &b, &fakeReader{pnat: pnat})
	out := b.String()
	for _, want := range []string{
		"  Protocol:           udp\n",
		"  Routing scope:      7\n",
		"  Permit:             target-host\n",
		"  Permitted remote:   8.8.8.8 (any port)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("detail missing %q:\n%s", want, out)
		}
	}
}

// Control: a legacy binding with no protocol still renders (protocol line
// omitted, scope 0 shown) so pre-#16647 rows do not break the golden shape.
func TestRenderPersistentDetailLegacyBindingStillRenders16647(t *testing.T) {
	pnat := dataplane.NewPersistentNATTable()
	pnat.Save(&dataplane.PersistentNATBinding{
		SrcIP:    netip.MustParseAddr("10.0.1.5"),
		SrcPort:  1111,
		NatIP:    netip.MustParseAddr("203.0.113.1"),
		NatPort:  40000,
		PoolName: "p-src",
		LastSeen: time.Now(),
		Timeout:  600 * time.Second,
		Permit:   config.PersistentNATPermitAnyRemoteHost,
	})
	var b strings.Builder
	RenderPersistentDetail(context.Background(), &b, &fakeReader{pnat: pnat})
	out := b.String()
	if !strings.Contains(out, "  Routing scope:      0\n") {
		t.Errorf("legacy detail missing scope line:\n%s", out)
	}
	if strings.Contains(out, "  Protocol:") {
		t.Errorf("legacy binding must not invent a protocol:\n%s", out)
	}
}

type scopedPersistentReader17737 struct {
	fakeReader
	v4Keys []dataplane.SessionKey
	v6Keys []dataplane.SessionKeyV6
}

func (r *scopedPersistentReader17737) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for i, v := range r.v4 {
		if !fn(r.v4Keys[i], v) {
			break
		}
	}
	return nil
}

func (r *scopedPersistentReader17737) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for i, v := range r.v6 {
		if !fn(r.v6Keys[i], v) {
			break
		}
	}
	return nil
}

func persistentBinding17737(srcPort uint16, protocol uint8, scope uint32, natIP netip.Addr) *dataplane.PersistentNATBinding {
	return &dataplane.PersistentNATBinding{
		SrcIP:        netip.MustParseAddr("10.0.1.5"),
		SrcPort:      srcPort,
		NatIP:        natIP,
		NatPort:      40000,
		PoolName:     "p-src",
		LastSeen:     time.Now(),
		Timeout:      600 * time.Second,
		Permit:       config.PersistentNATPermitAnyRemoteHost,
		Protocol:     protocol,
		RoutingScope: scope,
	}
}

func snatSession17737(natIP netip.Addr, natPort uint16, routingDomain uint32) dataplane.SessionValue {
	var ip4 [4]byte
	copy(ip4[:], natIP.AsSlice())
	return dataplane.SessionValue{
		Flags:         dataplane.SessFlagSNAT,
		NATSrcIP:      binary.NativeEndian.Uint32(ip4[:]),
		NATSrcPort:    natPort,
		RoutingDomain: routingDomain,
	}
}

func snatSessionV617737(natIP netip.Addr, natPort uint16, routingDomain uint32) dataplane.SessionValueV6 {
	return dataplane.SessionValueV6{
		Flags:         dataplane.SessFlagSNAT,
		NATSrcIP:      natIP.As16(),
		NATSrcPort:    natPort,
		RoutingDomain: routingDomain,
	}
}

func TestRenderPersistentDetailSessionCountsScopedToLeaseIdentity17737(t *testing.T) {
	natIP := netip.MustParseAddr("203.0.113.1")
	natIPV6 := netip.MustParseAddr("2001:db8::1")
	cases := []struct {
		name     string
		bindings []*dataplane.PersistentNATBinding
		v4       []dataplane.SessionValue
		v4Keys   []dataplane.SessionKey
		v6       []dataplane.SessionValueV6
		v6Keys   []dataplane.SessionKeyV6
		want     []int
	}{
		{
			name: "protocol distinct v4",
			bindings: []*dataplane.PersistentNATBinding{
				persistentBinding17737(1111, 6, 0, natIP),
				persistentBinding17737(2222, 17, 0, natIP),
			},
			v4: []dataplane.SessionValue{snatSession17737(natIP, 40000, 1), snatSession17737(natIP, 40000, 1)},
			v4Keys: []dataplane.SessionKey{
				{Protocol: 6},
				{Protocol: 17},
			},
			want: []int{1, 1},
		},
		{
			name: "scope distinct same protocol",
			bindings: []*dataplane.PersistentNATBinding{
				persistentBinding17737(1111, 6, 100007, natIP),
				persistentBinding17737(2222, 6, 100008, natIP),
			},
			v4: []dataplane.SessionValue{snatSession17737(natIP, 40000, 100007), snatSession17737(natIP, 40000, 100008)},
			v4Keys: []dataplane.SessionKey{
				{Protocol: 6},
				{Protocol: 6},
			},
			want: []int{1, 1},
		},
		{
			name:     "single lease raw-default scope control",
			bindings: []*dataplane.PersistentNATBinding{persistentBinding17737(1111, 6, 0, natIP)},
			v4:       []dataplane.SessionValue{snatSession17737(natIP, 40000, 0), snatSession17737(natIP, 40000, 0)},
			v4Keys: []dataplane.SessionKey{
				{Protocol: 6},
				{Protocol: 6},
			},
			want: []int{2},
		},
		{
			name: "protocol distinct v6",
			bindings: []*dataplane.PersistentNATBinding{
				persistentBinding17737(1111, 6, 0, natIPV6),
				persistentBinding17737(2222, 17, 0, natIPV6),
			},
			v6: []dataplane.SessionValueV6{
				snatSessionV617737(natIPV6, 40000, 0),
				snatSessionV617737(natIPV6, 40000, 0),
			},
			v6Keys: []dataplane.SessionKeyV6{
				{Protocol: 6},
				{Protocol: 17},
			},
			want: []int{1, 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pnat := dataplane.NewPersistentNATTable()
			for _, b := range tc.bindings {
				pnat.Save(b)
			}
			dp := &scopedPersistentReader17737{
				fakeReader: fakeReader{pnat: pnat, v4: tc.v4, v6: tc.v6},
				v4Keys:     tc.v4Keys,
				v6Keys:     tc.v6Keys,
			}
			var out strings.Builder
			RenderPersistentDetail(context.Background(), &out, dp)
			got := out.String()
			if strings.Count(got, "Current sessions:   1\n") != countOf(tc.want, 1) {
				t.Fatalf("%s: want counts %v, got:\n%s", tc.name, tc.want, got)
			}
			if strings.Count(got, "Current sessions:   2\n") != countOf(tc.want, 2) {
				t.Fatalf("%s: want counts %v, got:\n%s", tc.name, tc.want, got)
			}
			if strings.Count(got, "Current sessions:") != len(tc.want) {
				t.Fatalf("%s: unexpected session count rows, want %v, got:\n%s", tc.name, tc.want, got)
			}
		})
	}
}

func countOf(vals []int, target int) int {
	n := 0
	for _, v := range vals {
		if v == target {
			n++
		}
	}
	return n
}
