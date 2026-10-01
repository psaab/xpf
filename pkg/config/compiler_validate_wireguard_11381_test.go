package config

import (
	"strings"
	"testing"
)

// TestWireguardMergedDuplicateAllowedIPs11381 proves that distinct unit peers
// cannot claim the same exact prefix when emitted into one interface-level
// endpoint, even when their CIDR spellings differ only by host bits.
func TestWireguardMergedDuplicateAllowedIPs11381(t *testing.T) {
	parentPeer := strings.Repeat("a1", 32)
	unitPeerA := strings.Repeat("b2", 32)
	unitPeerB := strings.Repeat("c3", 32)
	privateKey := strings.Repeat("e4", 32)

	for _, tc := range []struct {
		name       string
		allowedA   string
		allowedB   string
		wantPrefix string
	}{
		{
			name:       "exact prefix",
			allowedA:   "10.200.1.0/24",
			allowedB:   "10.200.1.0/24",
			wantPrefix: "10.200.1.0/24",
		},
		{
			name:       "host bits canonicalize to same prefix",
			allowedA:   "10.200.1.17/24",
			allowedB:   "10.200.1.0/24",
			wantPrefix: "10.200.1.0/24",
		},
		{
			name:     "overlapping but distinct prefixes",
			allowedA: "10.200.1.0/24",
			allowedB: "10.200.1.128/25",
		},
		{
			name:     "different prefixes",
			allowedA: "10.200.1.0/24",
			allowedB: "10.200.2.0/24",
		},
		{
			name:     "different address families",
			allowedA: "10.200.1.0/24",
			allowedB: "2001:db8::/24",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := []string{
				"set interfaces wg0 tunnel mode wireguard",
				"set interfaces wg0 tunnel wireguard listen-port 51820",
				"set interfaces wg0 tunnel wireguard private-key " + privateKey,
				"set interfaces wg0 tunnel wireguard peer " + parentPeer + " allowed-ips 10.100.0.0/24",
				"set interfaces wg0 unit 1 tunnel wireguard peer " + unitPeerA + " allowed-ips " + tc.allowedA,
				"set interfaces wg0 unit 2 tunnel wireguard peer " + unitPeerB + " allowed-ips " + tc.allowedB,
			}
			_, err := CompileConfig(buildTree4953(t, lines))
			if tc.wantPrefix != "" {
				if err == nil {
					t.Fatalf("strict compile accepted merged peers %s and %s sharing %s", unitPeerA, unitPeerB, tc.wantPrefix)
				}
				for _, want := range []string{tc.wantPrefix, unitPeerA, unitPeerB} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("strict error must name %q, got: %v", want, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("distinct merged prefixes must compile, got: %v", err)
			}
		})
	}
}
