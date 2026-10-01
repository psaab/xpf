package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #11341: predefined Junos multi-term bundles must expand into every exact
// application term carried to the userspace dataplane snapshot. This pins the
// issue's version-bounded dumps, not current-release vSRX parity.
func TestPredefinedJunosApplicationsExpandToUserspaceTerms_11341(t *testing.T) {
	cases := []struct {
		set  string
		want []PolicyApplicationSnapshot
	}{
		{
			set: "junos-smb",
			want: []PolicyApplicationSnapshot{
				{Name: "junos-netbios-session", Protocol: "tcp", DestinationPort: "139"},
				{Name: "junos-smb-session", Protocol: "tcp", DestinationPort: "445"},
			},
		},
		{
			set: "junos-h323",
			want: []PolicyApplicationSnapshot{
				{Name: "junos-h323-q931", Protocol: "tcp", DestinationPort: "1720"},
				{Name: "junos-h323-ras", Protocol: "udp", DestinationPort: "1719"},
				{Name: "junos-h323-tcp-1503", Protocol: "tcp", DestinationPort: "1503"},
				{Name: "junos-h323-tcp-389", Protocol: "tcp", DestinationPort: "389"},
				{Name: "junos-h323-tcp-522", Protocol: "tcp", DestinationPort: "522"},
				{Name: "junos-h323-tcp-1731", Protocol: "tcp", DestinationPort: "1731"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.set, func(t *testing.T) {
			got, ok := expandUserspacePolicyApplications(&config.Config{}, []string{tc.set})
			if !ok {
				t.Fatalf("expandUserspacePolicyApplications(%q) ok=false", tc.set)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("expandUserspacePolicyApplications(%q) = %+v, want %+v", tc.set, got, tc.want)
			}
		})
	}
}
