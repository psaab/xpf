package networkd

import (
	"strings"
	"testing"
)

func TestGenerateLinkDuplexEnumGate11824(t *testing.T) {
	m := New()
	for _, mode := range []string{"full", "half", "auto"} {
		t.Run(mode, func(t *testing.T) {
			got := m.generateLink(InterfaceConfig{
				Name:       "ge-0-0-0",
				MACAddress: "52:54:00:aa:bb:cc",
				Duplex:     mode,
			})
			if !strings.Contains(got, "Duplex="+mode+"\n") {
				t.Fatalf("valid duplex %q was not rendered:\n%s", mode, got)
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
			if strings.Contains(got, "Duplex=") {
				t.Fatalf("invalid duplex %q passed through to networkd:\n%s", value, got)
			}
		})
	}
}
