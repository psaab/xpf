// #13215 (D3-09): compileInterfaces silently dropped three AST shapes:
//  1. WireGuard peers hoisted by expandResolvingRuns9792 in a flat-set run
//     were discarded because parseTunnelWireguard re-read peers from the
//     unexpanded node.
//  2. Brace-elided prefix-delegating / update-router-advertisement children
//     under dhcpv6-client were lost because only FindChild (never packedBody)
//     was used on those nested containers.
//  3. Braced source { ...; } / destination { ...; } / mode { ...; } on an
//     interface-level tunnel were lost because the reader required Keys[1]
//     instead of nodeVal (which also reads the braced child shape).
package config

import "testing"

func TestCompileInterfacesWireguardRunAndDHCPv6PackedChildren(t *testing.T) {
	t.Run("D3-09a wireguard flat-set run peer after listen-port", func(t *testing.T) {
		cfg, err := compileSet(t, []string{
			"set interfaces wg0 tunnel mode wireguard",
			"set interfaces wg0 tunnel wireguard listen-port 51820 peer " + wgKeyB + " allowed-ips 10.0.0.0/24",
			"set interfaces wg0 tunnel wireguard private-key " + wgKeyA,
		})
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		tc := wgTunnel(t, cfg, "wg0")
		if tc.WgListenPort != 51820 {
			t.Errorf("WgListenPort = %d, want 51820", tc.WgListenPort)
		}
		if len(tc.WgPeers) != 1 {
			t.Fatalf("WgPeers = %v, want 1 peer from expanded flat-set run", tc.WgPeers)
		}
		if tc.WgPeers[0].PublicKeyHex != wgKeyB {
			t.Errorf("WgPeers[0].PublicKeyHex = %q, want %q", tc.WgPeers[0].PublicKeyHex, wgKeyB)
		}
		if len(tc.WgPeers[0].AllowedIPs) != 1 || tc.WgPeers[0].AllowedIPs[0] != "10.0.0.0/24" {
			t.Errorf("WgPeers[0].AllowedIPs = %v, want [10.0.0.0/24]", tc.WgPeers[0].AllowedIPs)
		}
	})

	t.Run("D3-09b dhcpv6-client brace-elided children", func(t *testing.T) {
		src := `interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet6 {
                dhcpv6-client {
                    client-type stateful;
                    client-ia-type ia-pd;
                    prefix-delegating preferred-prefix-length 48;
                    prefix-delegating sub-prefix-length 64;
                    update-router-advertisement interface ge-0/0/1.0;
                }
            }
        }
    }
}`
		cfg := compileHierarchical(t, src)
		iface := cfg.Interfaces.Interfaces["ge-0/0/0"]
		if iface == nil || len(iface.Units) == 0 {
			t.Fatalf("interface/unit not compiled: %+v", cfg.Interfaces.Interfaces)
		}
		dc := iface.Units[0].DHCPv6Client
		if dc == nil {
			t.Fatal("DHCPv6Client not compiled")
		}
		if dc.PrefixDelegatingPrefixLen != 48 {
			t.Errorf("PrefixDelegatingPrefixLen = %d, want 48", dc.PrefixDelegatingPrefixLen)
		}
		if dc.PrefixDelegatingSubPrefLen != 64 {
			t.Errorf("PrefixDelegatingSubPrefLen = %d, want 64", dc.PrefixDelegatingSubPrefLen)
		}
		if dc.UpdateRAInterface != "ge-0/0/1.0" {
			t.Errorf("UpdateRAInterface = %q, want %q", dc.UpdateRAInterface, "ge-0/0/1.0")
		}
		if dc.ClientType != "stateful" {
			t.Errorf("ClientType = %q, want stateful", dc.ClientType)
		}
	})

	t.Run("D3-09c braced source destination mode on interface tunnel", func(t *testing.T) {
		src := `interfaces {
    gr-0/0/0 {
        tunnel {
            source { 10.0.0.1; }
            destination { 10.0.0.2; }
            mode { ip6gre; }
        }
    }
}`
		cfg := compileHierarchical(t, src)
		iface := cfg.Interfaces.Interfaces["gr-0/0/0"]
		if iface == nil || iface.Tunnel == nil {
			t.Fatalf("interface tunnel not compiled: %+v", cfg.Interfaces.Interfaces)
		}
		if iface.Tunnel.Source != "10.0.0.1" {
			t.Errorf("Source = %q, want 10.0.0.1", iface.Tunnel.Source)
		}
		if iface.Tunnel.Destination != "10.0.0.2" {
			t.Errorf("Destination = %q, want 10.0.0.2", iface.Tunnel.Destination)
		}
		if iface.Tunnel.Mode != "ip6gre" {
			t.Errorf("Mode = %q, want ip6gre", iface.Tunnel.Mode)
		}
	})
}
