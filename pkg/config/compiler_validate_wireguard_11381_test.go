package config

import (
	"strings"
	"testing"
)

// TestWireguardMergedDuplicateAllowedIPs11381 proves that distinct unit peers
// cannot claim the same exact prefix when emitted into one interface-level
// endpoint, even when their CIDR spellings differ only by host bits.
func TestWireguardMergedDuplicateAllowedIPs11381(t *testing.T) {
	parentPeer := "00bedd4ed26623ab2f765d16af2dcba4f6dbe17c284a66c6494b48b823f4c654"
	unitPeerA := "04d9dab116416940a490d8bab5d0dd921094f0a278dee3db867df8fbd2db6e16"
	unitPeerB := "15d9fd16500e6a671c69ef3dfa24e72ae7a463c3cf2a659b2969de785bb98504"
	privateKey := "21a8e89546569ec63441fbc82a72e6a59c0528cb39896d0adf84e77c4758e6b3"

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
