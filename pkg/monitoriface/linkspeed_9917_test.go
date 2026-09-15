package monitoriface

import (
	"testing"
)

// TestFormatLinkSpeed9917 is the F-138 cell. COMPILE-RED on base: formatLinkSpeed
// does not exist there (ReadLinkSpeed reads sysfs directly, which tests cannot
// drive — no base seam). Revert-sensitive: restoring mbps/1000 truncation fails
// every fractional row.
func TestFormatLinkSpeed9917(t *testing.T) {
	cases := []struct {
		mbps int
		want string
	}{
		{0, "unknown"},
		{-5, "unknown"},
		{10, "10mbps"},
		{100, "100mbps"},
		{999, "999mbps"},
		{1000, "1gbps"},
		{1001, "1.0gbps"},
		{1049, "1.0gbps"},
		{1050, "1.0gbps"},
		{1100, "1.1gbps"},
		{1150, "1.1gbps"},
		{1250, "1.2gbps"},
		{1500, "1.5gbps"},
		{2000, "2gbps"},
		{2500, "2.5gbps"},
		{5000, "5gbps"},
		{10000, "10gbps"},
		{10500, "10.5gbps"},
		{25000, "25gbps"},
		{100000, "100gbps"},
	}
	for _, tc := range cases {
		if got := formatLinkSpeed(tc.mbps); got != tc.want {
			t.Errorf("F-138: formatLinkSpeed(%d) = %q, want %q", tc.mbps, got, tc.want)
		}
	}
}

// TestReadLinkSpeedUnknownInterface9917 pins the thin-wrapper contract:
// an unreadable speed file stays "unknown". GREEN on base and after.
func TestReadLinkSpeedUnknownInterface9917(t *testing.T) {
	if got := ReadLinkSpeed("definitely-no-such-iface-9917"); got != "unknown" {
		t.Errorf("ReadLinkSpeed(missing) = %q, want %q", got, "unknown")
	}
}
