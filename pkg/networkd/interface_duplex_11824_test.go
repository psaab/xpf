package networkd

import (
	"strings"
	"testing"
)

func TestGenerateLinkDuplexEnumGate11824(t *testing.T) {
	m := New()
	for _, tc := range []struct {
		mode   string
		want   string
		forbid string
	}{
		{mode: "full", want: "Duplex=full\n", forbid: "AutoNegotiation="},
		{mode: "half", want: "Duplex=half\n", forbid: "AutoNegotiation="},
		{mode: "auto", want: "AutoNegotiation=yes\n", forbid: "Duplex="},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			got := m.generateLink(InterfaceConfig{
				Name:       "ge-0-0-0",
				MACAddress: "52:54:00:aa:bb:cc",
				Duplex:     tc.mode,
			})
			if !strings.Contains(got, tc.want) || strings.Contains(got, tc.forbid) {
				t.Fatalf("duplex %q rendered invalid link config (need %q; forbid %q):\n%s",
					tc.mode, tc.want, tc.forbid, got)
			}
		})
	}
	for _, value := range []string{"garbage", "FULL", "full\nDHCP=yes"} {
		t.Run(value, func(t *testing.T) {
			got := m.generateLink(InterfaceConfig{
				Name:       "ge-0-0-0",
				MACAddress: "52:54:00:aa:bb:cc",
				Duplex:     value,
			})
			if strings.Contains(got, "Duplex=") || strings.Contains(got, "AutoNegotiation=") {
				t.Fatalf("invalid duplex %q passed through to networkd:\n%s", value, got)
			}
		})
	}
}
