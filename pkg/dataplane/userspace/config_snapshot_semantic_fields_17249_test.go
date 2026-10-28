package userspace

import (
	"encoding/json"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// ConfigSnapshot.Config is opaque to Rust, but the Go producer must carry the
// fields added to compiled-config JSON in the helper payload too.
func TestSnapshotConfigIncludesSemanticFields17249(t *testing.T) {
	cfg := &config.Config{
		RoutingOptions: config.RoutingOptionsConfig{StaticRoutes: []*config.StaticRoute{{
			Destination:   "10.172.49.0/24",
			NoInstall:     true,
			Preference:    5,
			HasPreference: true,
		}}},
		System: config.SystemConfig{
			NTPPeers: []string{"192.0.2.49"},
			NTPPeerOptions: map[string]config.NTPServerOption{
				"192.0.2.49": {Prefer: true},
			},
		},
		Security: config.SecurityConfig{
			AddressBook: &config.AddressBook{Addresses: map[string]*config.Address{
				"partner-api": {Name: "partner-api", DNSName: "api.example.com", DNSFamily: "ipv4-only"},
			}},
			Zones: map[string]*config.ZoneConfig{
				"trust": {Name: "trust", ScreenProfile: "edge", ScreenProfileConfigured: true},
			},
		},
	}
	raw, err := json.Marshal(&ConfigSnapshot{Config: cfg})
	if err != nil {
		t.Fatalf("marshal ConfigSnapshot: %v", err)
	}
	var got struct {
		Config struct {
			RoutingOptions struct {
				StaticRoutes []struct {
					NoInstall     bool
					Preference    int
					HasPreference bool
				} `json:"StaticRoutes"`
			} `json:"RoutingOptions"`
			System struct {
				NTPPeers       []string
				NTPPeerOptions map[string]struct {
					Prefer bool
				}
			} `json:"System"`
			Security struct {
				AddressBook struct {
					Addresses map[string]struct {
						DNSName   string
						DNSFamily string
					}
				}
			} `json:"Security"`
		} `json:"config"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode ConfigSnapshot: %v; payload=%s", err, raw)
	}
	if len(got.Config.RoutingOptions.StaticRoutes) != 1 {
		t.Fatalf("snapshot static route count = %d, want 1: %s",
			len(got.Config.RoutingOptions.StaticRoutes), raw)
	}
	route := got.Config.RoutingOptions.StaticRoutes[0]
	if !route.NoInstall || route.Preference != 5 || !route.HasPreference {
		t.Errorf("snapshot route fields = %+v, want NoInstall=true, Preference=5, HasPreference=true", route)
	}
	if len(got.Config.System.NTPPeers) != 1 || got.Config.System.NTPPeers[0] != "192.0.2.49" {
		t.Errorf("snapshot NTPPeers = %v, want [192.0.2.49]", got.Config.System.NTPPeers)
	}
	if option := got.Config.System.NTPPeerOptions["192.0.2.49"]; !option.Prefer {
		t.Errorf("snapshot NTPPeerOptions[192.0.2.49] = %+v, want Prefer=true",
			option)
	}
	dnsAddress := got.Config.Security.AddressBook.Addresses["partner-api"]
	if dnsAddress.DNSName != "api.example.com" || dnsAddress.DNSFamily != "ipv4-only" {
		t.Errorf("snapshot DNS fields = %+v, want api.example.com/ipv4-only; payload=%s",
			dnsAddress, raw)
	}
}
