package userspace

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestBuildTunnelEndpointSnapshotsBuildsUnitEndpoint(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"gr-0/0/0": {
			Name: "gr-0/0/0",
			Units: map[int]*config.InterfaceUnit{
				0: {
					Number: 0,
				},
			},
			Tunnel: &config.TunnelConfig{
				Name:        "gr-0-0-0",
				Mode:        "gre",
				Source:      "2001:559:8585:80::8",
				Destination: "2602:ffd3:0:2::7",
			},
		},
	}
	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
		{
			Name:            "gr-0/0/0.0",
			Zone:            "sfmix",
			LinuxName:       "gr-0-0-0",
			Ifindex:         362,
			RedundancyGroup: 1,
			MTU:             1476,
		},
	})
	if len(endpoints) != 1 {
		t.Fatalf("len(endpoints) = %d, want 1", len(endpoints))
	}
	if want := config.StableTunnelEndpointID("gr-0/0/0.0"); endpoints[0].ID != want {
		t.Fatalf("endpoint id = %d, want %d (stable hash of name, #1873)", endpoints[0].ID, want)
	}
	if endpoints[0].Interface != "gr-0/0/0.0" {
		t.Fatalf("endpoint interface = %q, want gr-0/0/0.0", endpoints[0].Interface)
	}
	if endpoints[0].TransportTable != "inet6.0" {
		t.Fatalf("endpoint transport table = %q, want inet6.0", endpoints[0].TransportTable)
	}
	if endpoints[0].OuterFamily != "inet6" {
		t.Fatalf("endpoint outer family = %q, want inet6", endpoints[0].OuterFamily)
	}
}

func TestBuildTunnelEndpointSnapshotsUsesConfiguredTransportTable(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"gr-0/0/0": {
			Name: "gr-0/0/0",
			Units: map[int]*config.InterfaceUnit{
				0: {
					Number: 0,
				},
			},
			Tunnel: &config.TunnelConfig{
				Name:            "gr-0-0-0",
				Mode:            "gre",
				Source:          "172.16.50.8",
				Destination:     "198.51.100.7",
				RoutingInstance: "transport",
			},
		},
	}
	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
		{
			Name:      "gr-0/0/0.0",
			LinuxName: "gr-0-0-0",
			Ifindex:   362,
		},
	})
	if len(endpoints) != 1 {
		t.Fatalf("len(endpoints) = %d, want 1", len(endpoints))
	}
	if endpoints[0].TransportTable != "transport.inet.0" {
		t.Fatalf("endpoint transport table = %q, want transport.inet.0", endpoints[0].TransportTable)
	}
	if endpoints[0].OuterFamily != "inet" {
		t.Fatalf("endpoint outer family = %q, want inet", endpoints[0].OuterFamily)
	}
}

func TestBuildTunnelEndpointSnapshotsDerivesRGFromTunnelSourceAddress(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"gr-0/0/0": {
			Name: "gr-0/0/0",
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0},
			},
			Tunnel: &config.TunnelConfig{
				Name:        "gr-0-0-0",
				Mode:        "gre",
				Source:      "2001:559:8585:80::8",
				Destination: "2602:ffd3:0:2::7",
			},
		},
	}
	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
		{
			Name:      "gr-0/0/0.0",
			Zone:      "sfmix",
			LinuxName: "gr-0-0-0",
			Ifindex:   1116,
			MTU:       1500,
		},
		{
			Name:            "reth0.80",
			LinuxName:       "ge-7-0-2",
			Ifindex:         12,
			RedundancyGroup: 1,
			Addresses: []InterfaceAddressSnapshot{
				{Family: "inet6", Address: "2001:559:8585:80::8/64"},
			},
		},
	})
	if len(endpoints) != 1 {
		t.Fatalf("len(endpoints) = %d, want 1", len(endpoints))
	}
	if endpoints[0].RedundancyGroup != 1 {
		t.Fatalf("endpoint RG = %d, want 1", endpoints[0].RedundancyGroup)
	}
}

func TestSnapshotHasNativeGRE(t *testing.T) {
	snapshot := &ConfigSnapshot{
		TunnelEndpoints: []TunnelEndpointSnapshot{{
			ID:   1,
			Mode: "ip6gre",
		}},
	}
	if !snapshotHasNativeGRE(snapshot) {
		t.Fatal("expected native GRE snapshot to be detected")
	}
	if snapshotHasNativeGRE(&ConfigSnapshot{}) {
		t.Fatal("did not expect empty snapshot to enable native GRE")
	}
}

// #1432 S2a: a mode=="wireguard" tunnel populates the Wg* DTO fields and
// is not dropped by the GRE source/destination gate (WG carries the peer
// in wg_endpoint and may have no source/destination).
func TestBuildTunnelEndpointSnapshotsPopulatesWireGuard(t *testing.T) {
	const privHex = "a01010101010101010101010101010101010101010101010101010101010101a"
	const peerHex = "b02020202020202020202020202020202020202020202020202020202020202b"
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"wg0": {
			Name: "wg0",
			Tunnel: &config.TunnelConfig{
				Name:              "wg0",
				Mode:              "wireguard",
				WgListenPort:      51820,
				WgLocalPrivkeyHex: privHex,
				WgPeers: []config.WgPeerConfig{{
					PublicKeyHex:  peerHex,
					AllowedIPs:    []string{"10.0.0.0/24", "10.0.1.0/24"},
					Endpoint:      "203.0.113.1:51820",
					KeepaliveSecs: 25,
				}},
			},
		},
	}
	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
		{Name: "wg0", LinuxName: "wg0", Ifindex: 42, Zone: "vpn"},
	})
	if len(endpoints) != 1 {
		t.Fatalf("len(endpoints) = %d, want 1 (WG endpoint must not be dropped)", len(endpoints))
	}
	e := endpoints[0]
	if e.Mode != "wireguard" {
		t.Fatalf("mode = %q, want wireguard", e.Mode)
	}
	if e.WgListenPort != 51820 {
		t.Fatalf("wg_listen_port = %d, want 51820", e.WgListenPort)
	}
	if e.WgLocalPrivkeyHex != privHex {
		t.Fatalf("wg_local_privkey_hex not populated")
	}
	if len(e.WgPeers) != 1 {
		t.Fatalf("wg_peers = %v, want 1 peer", e.WgPeers)
	}
	p := e.WgPeers[0]
	if p.WgPeerPubkeyHex != peerHex {
		t.Fatalf("wg_peers[0].wg_peer_pubkey_hex = %q, want %q", p.WgPeerPubkeyHex, peerHex)
	}
	if len(p.WgAllowedIPs) != 2 {
		t.Fatalf("wg_peers[0].wg_allowed_ips = %v, want 2 entries", p.WgAllowedIPs)
	}
	if p.WgEndpoint != "203.0.113.1:51820" {
		t.Fatalf("wg_peers[0].wg_endpoint = %q", p.WgEndpoint)
	}
	if p.WgKeepaliveSecs != 25 {
		t.Fatalf("wg_peers[0].wg_keepalive_secs = %d, want 25", p.WgKeepaliveSecs)
	}
	// IPv4 peer endpoint -> inet outer family.
	if e.OuterFamily != "inet" {
		t.Fatalf("outer family = %q, want inet for IPv4 endpoint", e.OuterFamily)
	}
}

// The RI member may use the kernel spelling while the endpoint emitter uses
// the authored Junos spelling. Both rows name the same tunnel device, so the
// builder must recover the transport table through ResolveKernelIfName rather
// than relying on an exact InterfaceSnapshot.Name lookup (#10196).
func TestBuildTunnelEndpointSnapshotsResolvesWireguardRIByKernelIdentity10196(t *testing.T) {
	const (
		privHex = "a01010101010101010101010101010101010101010101010101010101010101a"
		peerHex = "b02020202020202020202020202020202020202020202020202020202020202b"
	)
	cfg := &config.Config{
		RoutingInstances: []*config.RoutingInstanceConfig{{
			Name:         "blue",
			InstanceType: "virtual-router",
			Interfaces:   []string{"gr-0-0-0"},
		}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"gr-0/0/0": {
			Name:  "gr-0/0/0",
			Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
			Tunnel: &config.TunnelConfig{
				Name:              "gr-0-0-0",
				Mode:              "wireguard",
				WgListenPort:      51820,
				WgLocalPrivkeyHex: privHex,
				WgPeers: []config.WgPeerConfig{{
					PublicKeyHex: peerHex,
					Endpoint:     "[2001:db8::1]:51820",
				}},
			},
		},
	}
	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{{
		Name:      "gr-0/0/0.0",
		LinuxName: "gr-0-0-0",
		Ifindex:   42,
	}})
	if len(endpoints) != 1 {
		t.Fatalf("len(endpoints) = %d, want 1", len(endpoints))
	}
	if got := endpoints[0].TransportTable; got != "blue.inet6.0" {
		t.Fatalf("transport table = %q, want blue.inet6.0 from kernel-identity RI membership", got)
	}
	if endpoints[0].OuterFamily != "inet6" {
		t.Fatalf("outer family = %q, want inet6 for the IPv6 peer", endpoints[0].OuterFamily)
	}
}

// An interface-level WG owns one socket even when a unit-only tunnel stanza
// adds the routing-instance. The emitter's singleton merge must carry that
// unique scope into the endpoint snapshot (#10196).
func TestBuildTunnelEndpointSnapshotsCarriesSharedUnitWireguardScope10196(t *testing.T) {
	const (
		privHex = "a01010101010101010101010101010101010101010101010101010101010101a"
		peerHex = "b02020202020202020202020202020202020202020202020202020202020202b"
	)
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"wg0": {
			Name: "wg0",
			Tunnel: &config.TunnelConfig{
				Name:              "wg0",
				Mode:              "wireguard",
				WgListenPort:      51820,
				WgLocalPrivkeyHex: privHex,
				WgPeers: []config.WgPeerConfig{{
					PublicKeyHex: peerHex,
					Endpoint:     "203.0.113.1:51820",
				}},
			},
			Units: map[int]*config.InterfaceUnit{
				0: {
					Number: 0,
					Tunnel: &config.TunnelConfig{
						Name:            "wg0",
						Mode:            "wireguard",
						RoutingInstance: "blue",
					},
				},
			},
		},
	}
	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{{
		Name: "wg0.0", LinuxName: "wg0", Ifindex: 42,
	}})
	if len(endpoints) != 1 {
		t.Fatalf("len(endpoints) = %d, want one shared WG endpoint", len(endpoints))
	}
	if got := endpoints[0].TransportTable; got != "blue.inet.0" {
		t.Fatalf("transport table = %q, want blue.inet.0 from unit-only scope", got)
	}
}

// A GRE tunnel must be unaffected by the WG relaxation: a GRE endpoint
// with no source/destination is still dropped.
func TestBuildTunnelEndpointSnapshotsGREStillRequiresSourceDest(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"gr-0/0/0": {
			Name:   "gr-0/0/0",
			Tunnel: &config.TunnelConfig{Name: "gr-0-0-0", Mode: "gre"}, // no src/dst
		},
	}
	endpoints := buildTunnelEndpointSnapshots(cfg, []InterfaceSnapshot{
		{Name: "gr-0/0/0", LinuxName: "gr-0-0-0", Ifindex: 99},
	})
	if len(endpoints) != 0 {
		t.Fatalf("GRE endpoint without source/destination must be dropped, got %d", len(endpoints))
	}
}

// The WG local private key is delivered to the Rust dataplane over the
// control socket (the Go DTO serializes it with omitempty), but the Rust
// side marks it skip_serializing so the on-disk state snapshot the
// helper persists never contains it (verified in the Rust suite by
// wg_local_privkey_hex_is_skipped_in_state_snapshot). This Go test pins
// the control-channel contract: the private key round-trips over the
// wire (so Rust can build the engine) while a snapshot with an empty key
// carries no privkey field at all (omitempty).
func TestTunnelEndpointSnapshotPrivkeyControlChannelContract(t *testing.T) {
	const privHex = "a01010101010101010101010101010101010101010101010101010101010101a"
	withKey := TunnelEndpointSnapshot{
		ID:                1,
		Mode:              "wireguard",
		WgLocalPrivkeyHex: privHex,
		WgPeers: []TunnelWgPeerWire{{
			WgPeerPubkeyHex: "b02020202020202020202020202020202020202020202020202020202020202b",
		}},
	}
	b, err := json.Marshal(withKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got TunnelEndpointSnapshot
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.WgLocalPrivkeyHex != privHex {
		t.Fatalf("private key must round-trip over the control channel for engine build")
	}
	// An endpoint with no private key must omit the field entirely.
	noKey := TunnelEndpointSnapshot{ID: 1, Mode: "wireguard"}
	nb, err := json.Marshal(noKey)
	if err != nil {
		t.Fatalf("marshal noKey: %v", err)
	}
	if strings.Contains(string(nb), "wg_local_privkey_hex") {
		t.Fatalf("empty private key must be omitted, got %s", nb)
	}
}
