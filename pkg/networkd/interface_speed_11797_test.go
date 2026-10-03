package networkd

import (
	"fmt"
	"strings"
	"testing"
)

func TestGenerateLinkTypedSpeedConversion11797(t *testing.T) {
	for _, tc := range []struct {
		speed string
		bps   string
	}{
		{"10m", "10000000"},
		{"100m", "100000000"},
		{"1g", "1000000000"},
		{"2.5g", "2500000000"},
		{"5g", "5000000000"},
		{"10g", "10000000000"},
		{"25g", "25000000000"},
		{"40g", "40000000000"},
		{"100g", "100000000000"},
		{"1G", "1000000000"},
	} {
		t.Run(tc.speed, func(t *testing.T) {
			if got := junosSpeedToNetworkd(tc.speed); got != tc.bps {
				t.Fatalf("junosSpeedToNetworkd(%q) = %q, want %q", tc.speed, got, tc.bps)
			}
			link := New().generateLink(InterfaceConfig{
				Name:       "ge-0-0-0",
				MACAddress: "52:54:00:aa:bb:cc",
				Speed:      tc.speed,
			})
			want := fmt.Sprintf("BitsPerSecond=%s\n", tc.bps)
			if !strings.Contains(link, want) {
				t.Fatalf("generated link lacks %q:\n%s", want, link)
			}
		})
	}
}

func TestGenerateLinkOmitsAutoAndUnrecognizedSpeed11797(t *testing.T) {
	for _, speed := range []string{"", "auto", "bogus", "1000"} {
		t.Run(fmt.Sprintf("%q", speed), func(t *testing.T) {
			if got := junosSpeedToNetworkd(speed); got != "" {
				t.Fatalf("junosSpeedToNetworkd(%q) = %q, want omission", speed, got)
			}
			ifc := InterfaceConfig{
				Name:       "ge-0-0-0",
				MACAddress: "52:54:00:aa:bb:cc",
				Speed:      speed,
			}
			if err := renderedUnitTokenError(ifc); err != nil {
				t.Fatalf("unrendered speed %q should not fail preflight: %v", speed, err)
			}
			link := New().generateLink(ifc)
			if strings.Contains(link, "BitsPerSecond=") || strings.Contains(link, "DHCP=yes") {
				t.Fatalf("unrecognized speed %q leaked into generated link:\n%s", speed, link)
			}
		})
	}
}

func TestRenderedUnitTokenErrorRejectsUnsafeUnrecognizedSpeed11797(t *testing.T) {
	for _, speed := range []string{"1g 999999999999", "1g\nDHCP=yes"} {
		t.Run(fmt.Sprintf("%q", speed), func(t *testing.T) {
			if got := junosSpeedToNetworkd(speed); got != "" {
				t.Fatalf("junosSpeedToNetworkd(%q) = %q, want omission", speed, got)
			}
			if err := renderedUnitTokenError(InterfaceConfig{
				Name:       "ge-0-0-0",
				MACAddress: "52:54:00:aa:bb:cc",
				Speed:      speed,
			}); err == nil {
				t.Fatalf("unsafe speed %q passed preflight", speed)
			}
		})
	}
}
