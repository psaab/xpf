package config

import (
	"strings"
	"testing"
)

func TestTunnelStanzaAndListDeviceClaimsConflictBothOrders11060(t *testing.T) {
	for _, mode := range []string{"gre", "wireguard"} {
		for _, order := range []string{"stanza-first", "list-first"} {
			t.Run(mode+"/"+order, func(t *testing.T) {
				var tunnelLines []string
				if mode == "gre" {
					tunnelLines = []string{
						"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
						"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
						"set interfaces gr-0/0/0 tunnel routing-instance destination blue",
					}
				} else {
					tunnelLines = append(wgBase9909(t, "wg0", "51820", wgKeyA, wgKeyB),
						"set interfaces wg0 tunnel routing-instance destination blue")
				}
				device, member := "gr-0-0-0", "gr-0/0/0"
				if mode == "wireguard" {
					device, member = "wg0", "wg0"
				}
				instanceLines := []string{
					"set routing-instances blue instance-type virtual-router",
					"set routing-instances red instance-type virtual-router",
					"set routing-instances red interface " + member,
				}
				lines := []string{}
				if order == "stanza-first" {
					lines = append(lines, tunnelLines...)
					lines = append(lines, instanceLines...)
				} else {
					lines = append(lines, instanceLines...)
					lines = append(lines, tunnelLines...)
				}

				_, strictErr := CompileConfig(buildTree(t, lines))
				if strictErr == nil {
					t.Fatalf("strict compile accepted tunnel stanza and list claims on %s", device)
				}
				for _, want := range []string{device, "blue", "red", "#11060"} {
					if !strings.Contains(strictErr.Error(), want) {
						t.Errorf("strict conflict %q omits %q", strictErr, want)
					}
				}

				cfg, err := CompileConfigLenient(buildTree(t, lines))
				if err != nil {
					t.Fatalf("tolerant compile: %v", err)
				}
				if len(cfg.QuarantinedRIMemberDeviceConflicts) != 1 ||
					cfg.QuarantinedRIMemberDeviceConflicts[0].LinuxName != device {
					t.Fatalf("quarantined conflict = %+v, want %s",
						cfg.QuarantinedRIMemberDeviceConflicts, device)
				}
				ifcName := "gr-0/0/0"
				if mode == "wireguard" {
					ifcName = "wg0"
				}
				ifc := cfg.Interfaces.Interfaces[ifcName]
				if ifc == nil || ifc.Tunnel == nil || ifc.Tunnel.RoutingInstance != "" {
					t.Fatalf("conflicting tunnel stanza survived quarantine: %+v", ifc)
				}
				for _, ri := range cfg.RoutingInstances {
					if len(ri.Interfaces) != 0 {
						t.Errorf("conflicting list membership survived in %s: %v", ri.Name, ri.Interfaces)
					}
				}
			})
		}
	}
}
