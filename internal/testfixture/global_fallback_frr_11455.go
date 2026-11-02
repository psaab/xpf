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
		// Keep global RIP in a separate routing table from the instance's IS-IS;
		// #17735 rejects both protocols when they share a table.
		RIP: &config.RIPConfig{Interfaces: []string{"ge-0/0/2.0"}},
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
// #12065/#17893: the BGP policy is composed with per-protocol redistribution
// guards so its permits cannot unintentionally authorize other route sources.
const ExpectedGlobalFallbackFRR11455 = `log syslog informational
! BEGIN BPFRX MANAGED CONFIG - do not edit this section
! xpf managed config - do not edit
!
ipv6 route 2001:db8:100::/48 2001:db8::1 5
!
ip route 10.20.0.0/16 192.0.2.1 5 vrf vrf-tenant
ipv6 route 2001:db8:1::/48 2001:db8::1 5 vrf vrf-tenant
!
route-map GLOBAL-EXPORT permit 10
exit
route-map GLOBAL-EXPORT permit 20
 match source-protocol bgp
exit
route-map GLOBAL-EXPORT deny 30
exit
!
route-map GLOBAL-EXPORT-connected-xpf-redist permit 10
exit
route-map GLOBAL-EXPORT-connected-xpf-redist deny 20
exit
!
route-map GLOBAL-EXPORT-isis-xpf-redist permit 10
exit
route-map GLOBAL-EXPORT-isis-xpf-redist deny 20
exit
!
route-map GLOBAL-EXPORT-kernel-xpf-redist permit 10
exit
route-map GLOBAL-EXPORT-kernel-xpf-redist deny 20
exit
!
route-map GLOBAL-EXPORT-ospf-xpf-redist permit 10
exit
route-map GLOBAL-EXPORT-ospf-xpf-redist deny 20
exit
!
route-map GLOBAL-EXPORT-ospf6-xpf-redist permit 10
exit
route-map GLOBAL-EXPORT-ospf6-xpf-redist deny 20
exit
!
route-map GLOBAL-EXPORT-rip-xpf-redist permit 10
exit
route-map GLOBAL-EXPORT-rip-xpf-redist deny 20
exit
!
route-map GLOBAL-EXPORT-ripng-xpf-redist permit 10
exit
route-map GLOBAL-EXPORT-ripng-xpf-redist deny 20
exit
!
route-map GLOBAL-EXPORT-static-xpf-redist permit 10
exit
route-map GLOBAL-EXPORT-static-xpf-redist deny 20
exit
!
router bgp 65001
 no bgp ebgp-requires-policy
 distance bgp 170 170 170
 bgp router-id 192.0.2.100
 neighbor 192.0.2.2 remote-as 65002
 redistribute connected route-map GLOBAL-EXPORT-connected-xpf-redist
 redistribute isis route-map GLOBAL-EXPORT-isis-xpf-redist
 redistribute kernel route-map GLOBAL-EXPORT-kernel-xpf-redist
 redistribute ospf route-map GLOBAL-EXPORT-ospf-xpf-redist
 redistribute rip route-map GLOBAL-EXPORT-rip-xpf-redist
 redistribute static route-map GLOBAL-EXPORT-static-xpf-redist
 !
 address-family ipv4 unicast
  neighbor 192.0.2.2 activate
  neighbor 192.0.2.2 route-map GLOBAL-EXPORT out
 exit-address-family
 !
 address-family ipv6 unicast
  redistribute connected route-map GLOBAL-EXPORT-connected-xpf-redist
  redistribute isis route-map GLOBAL-EXPORT-isis-xpf-redist
  redistribute kernel route-map GLOBAL-EXPORT-kernel-xpf-redist
  redistribute ospf6 route-map GLOBAL-EXPORT-ospf6-xpf-redist
  redistribute ripng route-map GLOBAL-EXPORT-ripng-xpf-redist
  redistribute static route-map GLOBAL-EXPORT-static-xpf-redist
 exit-address-family
exit
!
ip prefix-list xpf-rip-0-grp-0 seq 5 deny 0.0.0.0/0 le 32
ipv6 prefix-list xpf-rip-0-grp-0-v6 seq 5 deny ::/0 le 128
!
router rip
 distance 100
 network ge-0-0-2
 distribute-list prefix xpf-rip-0-grp-0 out ge-0-0-2
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
