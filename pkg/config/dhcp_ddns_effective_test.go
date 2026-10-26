package config

import "testing"

// TestDHCPServerConfigEffectiveDynamicDNS pins the #2663 single-block
// inheritance rule at its single owner (#17006): when only one family's
// dynamic-dns block is present the other family inherits that exact block,
// and inheritedFrom names the family the lone block was configured under.
func TestDHCPServerConfigEffectiveDynamicDNS(t *testing.T) {
	v4Block := &DHCPDynamicDNSConfig{Enabled: true, Domain: "v4.example"}
	v6Block := &DHCPDynamicDNSConfig{Enabled: true, Domain: "v6.example"}

	cases := []struct {
		name          string
		cfg           *DHCPServerConfig
		wantV4        *DHCPDynamicDNSConfig
		wantV6        *DHCPDynamicDNSConfig
		wantInherited int
	}{
		{"nil receiver", nil, nil, nil, 0},
		{"both nil", &DHCPServerConfig{}, nil, nil, 0},
		{"v4 only inherits to v6", &DHCPServerConfig{DynamicDNS: v4Block}, v4Block, v4Block, 4},
		{"v6 only inherits to v4", &DHCPServerConfig{DynamicDNSv6: v6Block}, v6Block, v6Block, 6},
		{"both independent", &DHCPServerConfig{DynamicDNS: v4Block, DynamicDNSv6: v6Block}, v4Block, v6Block, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v4, v6, inherited := tc.cfg.EffectiveDynamicDNS()
			if v4 != tc.wantV4 || v6 != tc.wantV6 {
				t.Fatalf("EffectiveDynamicDNS() = (%p, %p), want (%p, %p)", v4, v6, tc.wantV4, tc.wantV6)
			}
			if inherited != tc.wantInherited {
				t.Fatalf("inheritedFrom = %d, want %d", inherited, tc.wantInherited)
			}
		})
	}
}
