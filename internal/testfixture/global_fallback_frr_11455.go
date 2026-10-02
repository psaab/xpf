package testfixture

import "github.com/psaab/xpf/pkg/config"

// GlobalFallbackFRR11455 extends the per-instance FRR fixture with global
// protocols, policy options, and IPv6 statics for legacy CLI parity coverage.
func GlobalFallbackFRR11455() *config.Config {
	cfg := RoutingInstanceFRR11393()
	cfg.Interfaces.Interfaces["ge-0/0/2"] = &config.InterfaceConfig{
		Name:  "ge-0/0/2",
		Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
	}
	cfg.Protocols = config.ProtocolsConfig{
		BGP: &config.BGPConfig{
			LocalAS:  65001,
			RouterID: "192.0.2.100",
			Neighbors: []*config.BGPNeighbor{{
				Address: "192.0.2.2",
				PeerAS:  65002,
				Export:  []string{"GLOBAL-EXPORT"},
			}},
		},
		RIP: &config.RIPConfig{Interfaces: []string{"ge-0/0/2.0"}},
		ISIS: &config.ISISConfig{
			NET:        "49.0001.0200.0000.0001.00",
			Interfaces: []*config.ISISInterface{{Name: "ge-0/0/2.0"}},
		},
	}
	cfg.PolicyOptions = config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"GLOBAL-EXPORT": {
				Name:  "GLOBAL-EXPORT",
				Terms: []*config.PolicyTerm{{Name: "allow", Action: "accept"}},
			},
		},
	}
	cfg.RoutingOptions.Inet6StaticRoutes = []*config.StaticRoute{{
		Destination: "2001:db8:100::/48",
		NextHops:    []config.NextHopEntry{{Address: "2001:db8::1"}},
	}}
	return cfg
}

// ExpectedGlobalFallbackFRR11455 is the byte-exact daemon and legacy-CLI
// managed FRR output for GlobalFallbackFRR11455.
const ExpectedGlobalFallbackFRR11455 = `log syslog informational
! BEGIN BPFRX MANAGED CONFIG - do not edit this section
! xpf managed config - do not edit
!
ipv6 route 2001:db8:100::/48 2001:db8::1
!
ip route 10.20.0.0/16 192.0.2.1 vrf vrf-tenant
ipv6 route 2001:db8:1::/48 2001:db8::1 vrf vrf-tenant
!
route-map GLOBAL-EXPORT permit 10
exit
route-map GLOBAL-EXPORT permit 20
exit
!
route-map GLOBAL-EXPORT-xpf-redist permit 10
exit
route-map GLOBAL-EXPORT-xpf-redist deny 20
exit
!
router bgp 65001
 bgp router-id 192.0.2.100
 neighbor 192.0.2.2 remote-as 65002
 !
 address-family ipv4 unicast
  neighbor 192.0.2.2 activate
  neighbor 192.0.2.2 route-map GLOBAL-EXPORT out
 exit-address-family
exit
!
router rip
 network ge-0-0-2
exit
!
router isis xpf
 net 49.0001.0200.0000.0001.00
 is-type level-2-only
exit
!
interface ge-0-0-2
 ip router isis xpf
 ipv6 router isis xpf
exit
!
router rip vrf vrf-tenant
 network ge-0-0-1
exit
!
router isis xpf vrf vrf-tenant
 net 49.0001.0100.0000.0001.00
 is-type level-2-only
exit
!
interface ge-0-0-1
 ip router isis xpf
 ipv6 router isis xpf
exit
!
! END BPFRX MANAGED CONFIG
`
