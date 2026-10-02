package testfixture

import "github.com/psaab/xpf/pkg/config"

// RoutingInstanceFRR11393 returns the shared config exercised by both FRR
// assembly paths for the legacy CLI regression.

func RoutingInstanceFRR11393() *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		}},
		RoutingInstances: []*config.RoutingInstanceConfig{{
			Name:         "tenant",
			InstanceType: "virtual-router",
			Interfaces:   []string{"ge-0/0/1.0"},
			RIP:          &config.RIPConfig{Interfaces: []string{"ge-0/0/1.0"}},
			ISIS: &config.ISISConfig{
				NET:        "49.0001.0100.0000.0001.00",
				Interfaces: []*config.ISISInterface{{Name: "ge-0/0/1.0"}},
			},
			StaticRoutes: []*config.StaticRoute{{
				Destination: "10.20.0.0/16",
				NextHops:    []config.NextHopEntry{{Address: "192.0.2.1"}},
			}},
			Inet6StaticRoutes: []*config.StaticRoute{{
				Destination: "2001:db8:1::/48",
				NextHops:    []config.NextHopEntry{{Address: "2001:db8::1"}},
			}},
		}},
	}
}

// ExpectedFRRInstanceConfig11393 is the byte-exact managed FRR output both
// the CLI fallback and daemon assembler must produce for the fixture.

const ExpectedFRRInstanceConfig11393 = `log syslog informational
! BEGIN BPFRX MANAGED CONFIG - do not edit this section
! xpf managed config - do not edit
!
ip route 10.20.0.0/16 192.0.2.1 vrf vrf-tenant
ipv6 route 2001:db8:1::/48 2001:db8::1 vrf vrf-tenant
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
