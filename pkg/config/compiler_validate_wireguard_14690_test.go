package config

import (
	"strings"
	"testing"
)

// #14690: isWireguardKeyHex accepts both hex cases and Rust decodes both to the
// same [u8;32], yet raw-string pubkey maps treated MIXED-case spellings of one
// key as distinct peers.

var (
	wg14690Priv  = "21a8e89546569ec63441fbc82a72e6a59c0528cb39896d0adf84e77c4758e6b3"
	wg14690Lower = "281c44584e21c01c573fc55561689a5bca17013ee790fa272cf51ed1681066e9"
	wg14690Upper = "281C44584E21C01C573FC55561689A5BCA17013EE790FA272CF51ED1681066E9"
	wg14690PeerX = "258ca6d9d6515c4e5b2166b183d9cd1efacfb2ee6d1337cf525843c940b022ff"
)

// Direct validator: mixed-case must error (parse normally lowercases, so direct + Compile are distinct).
func TestValidateWireguardRejectsMixedCaseDuplicatePeerPubkey(t *testing.T) {
	tc := &TunnelConfig{
		WgListenPort:      51820,
		WgLocalPrivkeyHex: Secret(wg14690Priv),
		WgPeers: []WgPeerConfig{
			{PublicKeyHex: wg14690Lower, AllowedIPs: []string{"10.90.0.0/24"}},
			{PublicKeyHex: wg14690Upper, AllowedIPs: []string{"10.91.0.0/24"}},
		},
	}
	if err := validateOneWireguardTunnel(tc); err == nil {
		t.Fatal("mixed-case duplicate peer pubkey must be rejected")
	}
}

func TestValidateWireguardRejectsMixedCaseDuplicatePeerPubkeyStrictCompile(t *testing.T) {
	lines := []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wg14690Priv,
		"set interfaces wg0 tunnel wireguard peer " + wg14690Lower + " allowed-ips 10.90.0.0/24",
		"set interfaces wg0 unit 1 tunnel wireguard peer " + wg14690Upper + " allowed-ips 10.91.0.0/24",
	}
	if _, err := CompileConfig(buildTree4953(t, lines)); err == nil {
		t.Fatal("strict compile must reject interface lower + unit upper spelling of same key")
	} else if !strings.Contains(err.Error(), "duplicate peer public key") {
		t.Errorf("error should name duplicate, got %v", err)
	}
	// Cross-unit upper vs lower (parser lowercases, but merged view must also be safe if reached via other paths)
	lines2 := []string{
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + wg14690Priv,
		"set interfaces wg0 tunnel wireguard peer " + wg14690PeerX + " allowed-ips 10.100.0.0/24",
		"set interfaces wg0 unit 1 tunnel wireguard peer " + wg14690Lower + " allowed-ips 10.90.0.0/24",
		"set interfaces wg0 unit 2 tunnel wireguard peer " + wg14690Upper + " allowed-ips 10.91.0.0/24",
	}
	if _, err := CompileConfig(buildTree4953(t, lines2)); err == nil {
		t.Fatal("strict compile must reject cross-unit mixed-case duplicate")
	}
}

// Merged view: cross-unit case-variants reject; interface+unit emit collapses to one.
func TestWireguardMixedCaseMergedEmitExactlyOne(t *testing.T) {
	// (a) Two units authoring case-variants of one non-inherited key.
	ifcCross := &InterfaceConfig{
		Tunnel: &TunnelConfig{Name: "wg0", Mode: "wireguard", WgListenPort: 51820, WgLocalPrivkeyHex: Secret(wg14690Priv),
			WgPeers: []WgPeerConfig{{PublicKeyHex: wg14690PeerX, AllowedIPs: []string{"10.100.0.0/24"}}}},
		Units: map[int]*InterfaceUnit{
			1: {Number: 1, Tunnel: &TunnelConfig{Name: "wg0", Mode: "wireguard", WgPeers: []WgPeerConfig{{PublicKeyHex: wg14690Lower, AllowedIPs: []string{"10.90.0.0/24"}}}}},
			2: {Number: 2, Tunnel: &TunnelConfig{Name: "wg0", Mode: "wireguard", WgPeers: []WgPeerConfig{{PublicKeyHex: wg14690Upper, AllowedIPs: []string{"10.91.0.0/24"}}}}},
		},
	}
	if err := validateMergedWireguardUnitPeers("wg0", ifcCross, []int{1, 2}); err == nil {
		t.Fatal("merged validator must reject cross-unit mixed-case duplicate")
	}
	// (b) Issue emit cell: interface lower + unit upper => exactly one emitted peer.
	ifc := &InterfaceConfig{
		Tunnel: &TunnelConfig{Name: "wg0", Mode: "wireguard", WgListenPort: 51820, WgLocalPrivkeyHex: Secret(wg14690Priv),
			WgPeers: []WgPeerConfig{{PublicKeyHex: wg14690Lower, AllowedIPs: []string{"10.90.0.0/24"}}}},
		Units: map[int]*InterfaceUnit{
			1: {Number: 1, Tunnel: &TunnelConfig{Name: "wg0", Mode: "wireguard", WgListenPort: 51820, WgLocalPrivkeyHex: Secret(wg14690Priv),
				WgPeers: []WgPeerConfig{
					{PublicKeyHex: wg14690Lower, AllowedIPs: []string{"10.90.0.0/24"}},
					{PublicKeyHex: wg14690Upper, AllowedIPs: []string{"10.91.0.0/24"}},
				}}},
		},
	}
	merged := mergeWireguardUnitPeers(ifc, []int{1})
	if merged == nil {
		t.Fatal("merged nil")
	}
	count := 0
	for _, p := range merged.WgPeers {
		if strings.EqualFold(p.PublicKeyHex, wg14690Lower) {
			count++
		}
	}
	if count != 1 || len(merged.WgPeers) != 1 {
		t.Fatalf("merged emit must contain exactly one spelling of the key, got %+v", merged.WgPeers)
	}
}

func TestWireguardMixedCasePrefixOwnerCanonical(t *testing.T) {
	ifc := &InterfaceConfig{
		Tunnel: &TunnelConfig{Name: "wg0", Mode: "wireguard", WgListenPort: 51820, WgLocalPrivkeyHex: Secret(wg14690Priv),
			WgPeers: []WgPeerConfig{{PublicKeyHex: wg14690Lower, AllowedIPs: []string{"10.90.0.0/24"}}}},
		Units: map[int]*InterfaceUnit{
			1: {Number: 1, Tunnel: &TunnelConfig{Name: "wg0", Mode: "wireguard", WgPeers: []WgPeerConfig{{PublicKeyHex: wg14690Upper, AllowedIPs: []string{"10.90.0.0/24"}}}}},
		},
	}
	if err := validateMergedWireguardUnitPeers("wg0", ifc, []int{1}); err != nil {
		t.Fatalf("same key in different case re-claiming same prefix must not be a distinct-owner prefix conflict, got %v", err)
	}
	other := "358ca6d9d6515c4e5b2166b183d9cd1efacfb2ee6d1337cf525843c940b022ff"
	ifc2 := &InterfaceConfig{
		Tunnel: &TunnelConfig{Name: "wg0", Mode: "wireguard", WgListenPort: 51820, WgLocalPrivkeyHex: Secret(wg14690Priv),
			WgPeers: []WgPeerConfig{{PublicKeyHex: wg14690Lower, AllowedIPs: []string{"10.90.0.0/24"}}}},
		Units: map[int]*InterfaceUnit{
			1: {Number: 1, Tunnel: &TunnelConfig{Name: "wg0", Mode: "wireguard", WgPeers: []WgPeerConfig{{PublicKeyHex: other, AllowedIPs: []string{"10.90.0.0/24"}}}}},
		},
	}
	if err := validateMergedWireguardUnitPeers("wg0", ifc2, []int{1}); err == nil || !strings.Contains(err.Error(), "claimed by two peers") {
		t.Fatalf("distinct peers claiming same exact prefix must still error, got %v", err)
	}
}

func TestWireguardMixedCaseAuthoredPeerCanonicalEmit(t *testing.T) {
	text := "interfaces { wg0 { tunnel { mode wireguard; wireguard { listen-port 51820; private-key " + wg14690Priv + "; peer " + wg14690Upper + " { allowed-ips 10.90.0.0/24; } } } } }"
	tree := parseHierarchical(t, text)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("single uppercase peer must compile: %v", err)
	}
	iface := cfg.Interfaces.Interfaces["wg0"]
	if len(iface.Tunnel.WgPeers) != 1 || iface.Tunnel.WgPeers[0].PublicKeyHex != wg14690Lower {
		t.Fatalf("authored uppercase peer must canonicalise to one lowercase peer, got %+v", iface.Tunnel.WgPeers)
	}
}
