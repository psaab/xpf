package cli

import (
	"testing"
)

// TestFormatSpeed10112 is the #10112 cell: pkg/cli/link.go formatSpeed
// carried the identical mbps/1000 integer-division truncation that #9917
// F-138 fixed in pkg/monitoriface (2500 Mbps rendered "2Gbps").
//
// Template is formatLinkSpeed's uniform rule — exact multiples of 1000
// render integer, any other gigabit-plus speed renders one truncated
// decimal via integer math, never float-rounded — with this surface's own
// Gbps/Mbps casing (see issue notes). Revert-sensitive: restoring the
// mbps/1000 truncation fails every fractional row; using %.1f float
// formatting fails the truncation rows (1999, 1150, 1250, 2599).
//
// Callers (cli_show_interfaces.go, cli_show_interfaces_detail.go,
// cli_show_interfaces_extensive.go) guard speed > 0 before calling, so
// only positive inputs are pinned; the sub-1000 branch is preserved
// verbatim from base.
func TestFormatSpeed10112(t *testing.T) {
	cases := []struct {
		mbps int
		want string
	}{
		{10, "10Mbps"},
		{100, "100Mbps"},
		{999, "999Mbps"},
		{1000, "1Gbps"},
		{1001, "1.0Gbps"},
		{1049, "1.0Gbps"},
		{1050, "1.0Gbps"},
		{1100, "1.1Gbps"},
		{1150, "1.1Gbps"},
		{1250, "1.2Gbps"},
		{1500, "1.5Gbps"},
		{1999, "1.9Gbps"},
		{2000, "2Gbps"},
		{2500, "2.5Gbps"},
		{2599, "2.5Gbps"},
		{5000, "5Gbps"},
		{10000, "10Gbps"},
		{10500, "10.5Gbps"},
		{25000, "25Gbps"},
		{100000, "100Gbps"},
	}
	for _, tc := range cases {
		if got := formatSpeed(tc.mbps); got != tc.want {
			t.Errorf("10112: formatSpeed(%d) = %q, want %q", tc.mbps, got, tc.want)
		}
	}
}
