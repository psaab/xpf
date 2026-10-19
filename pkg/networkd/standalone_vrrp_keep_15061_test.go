package networkd

import (
	"strings"
	"testing"
)

// #15061 (A37-02): a standalone vrrp-group VIP is installed by pkg/vrrp
// as a genuine kernel address but is never rendered as an Address= line,
// so it is foreign to systemd-networkd. Before the fix the static keep
// class required a rendered Address=, so even a row with
// KeepAddresses=true emitted no KeepConfiguration and an ordinary
// networkctl reconfigure stripped the VIP (e.g. 10.0.1.1/32) while the
// VRRP instance stayed MASTER.
//
// FAIL-ON-REVERT: drop KeepForeignStatic from keepConfigurationValue and
// the foreign-only and foreign+DHCP cells go RED. The rendered-static
// and no-keep controls must stay exactly as before.
func TestGenerateNetwork_StandaloneVRRPForeignKeep15061(t *testing.T) {
	m := New()
	cases := []struct {
		name string
		ifc  InterfaceConfig
		want string
	}{
		{
			name: "standalone VIP foreign only",
			// Real address renders; the VIP (10.0.1.1) does not.
			ifc: InterfaceConfig{Name: "ge-0-0-0", KeepAddresses: true, KeepForeignStatic: true,
				Addresses: []string{"10.0.1.2/24"}},
			want: "KeepConfiguration=static\n",
		},
		{
			name: "standalone VIP foreign plus DHCP lease",
			ifc: InterfaceConfig{Name: "ge-0-0-0", KeepAddresses: true, KeepForeignStatic: true,
				DHCPv4: true, Addresses: []string{"10.0.1.2/24"}},
			want: "KeepConfiguration=yes\n",
		},
		{
			name: "RETH rendered static unchanged",
			ifc: InterfaceConfig{Name: "ge-0-0-0", KeepAddresses: true,
				Addresses: []string{"169.254.1.1/32"}},
			want: "KeepConfiguration=static\n",
		},
		{
			name: "plain static no keep",
			ifc: InterfaceConfig{Name: "ge-0-0-0",
				Addresses: []string{"10.0.3.2/24"}},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := m.generateNetwork(tc.ifc)
			count := strings.Count(got, "KeepConfiguration=")
			if tc.want == "" {
				if count != 0 {
					t.Errorf("generated .network carries a keep directive, want none:\n%s", got)
				}
				return
			}
			if count != 1 {
				t.Errorf("generated .network has %d KeepConfiguration lines, want exactly 1 (%q):\n%s",
					count, tc.want, got)
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("generated .network missing %q:\n%s", tc.want, got)
			}
		})
	}
}
