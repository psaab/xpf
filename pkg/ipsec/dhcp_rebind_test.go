package ipsec

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// dhcpBoundConfig builds a config with one IPsec gateway whose
// local_addrs resolves from the named external interface unit. dhcp
// controls whether that unit is DHCP-managed; addr (CIDR, "" to omit)
// gives the unit a deterministic configured address so PrepareConfig can
// resolve a stable local-address in CI without a real kernel lease.
func dhcpBoundConfig(extIface, localAddr, addr string, dhcp bool) *config.Config {
	unit := &config.InterfaceUnit{DHCP: dhcp}
	if addr != "" {
		unit.PrimaryAddress = addr
		unit.Addresses = []string{addr}
	}
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"wan0": {
					Name:  "wan0",
					Units: map[int]*config.InterfaceUnit{0: unit},
				},
			},
		},
		Security: config.SecurityConfig{
			IPsec: config.IPsecConfig{
				Gateways: map[string]*config.IPsecGateway{
					"gw": {
						Name:          "gw",
						Address:       "203.0.113.1",
						ExternalIface: extIface,
						LocalAddress:  localAddr,
					},
				},
				VPNs: map[string]*config.IPsecVPN{
					"tun": {PSK: "fixture-secret", Gateway: "gw"},
				},
			},
		},
	}
}

// TestHasDHCPBoundGateway covers the scoping predicate that gates the
// daemon's DHCP-lease-change swanctl re-render (#2884): true only when a
// gateway resolves local_addrs dynamically from a DHCP interface, so an
// unrelated lease refresh never triggers a reload storm.
func TestHasDHCPBoundGateway(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want bool
	}{
		{
			name: "dynamic gateway on dhcp interface",
			cfg:  dhcpBoundConfig("wan0.0", "", "192.0.2.10/24", true),
			want: true,
		},
		{
			name: "bare interface ref with a dhcp unit",
			cfg:  dhcpBoundConfig("wan0", "", "192.0.2.10/24", true),
			want: true,
		},
		{
			name: "explicit local-address is not lease-dependent",
			cfg:  dhcpBoundConfig("wan0.0", "192.0.2.10", "192.0.2.10/24", true),
			want: false,
		},
		{
			name: "interface is not dhcp-managed",
			cfg:  dhcpBoundConfig("wan0.0", "", "192.0.2.10/24", false),
			want: false,
		},
		{
			name: "no external interface",
			cfg:  dhcpBoundConfig("", "", "192.0.2.10/24", true),
			want: false,
		},
		{
			name: "nil config",
			cfg:  nil,
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasDHCPBoundGateway(tc.cfg); got != tc.want {
				t.Fatalf("HasDHCPBoundGateway = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPrepareConfigReResolvesDHCPLocalAddress proves that PrepareConfig
// re-derives local_addrs from the CURRENT interface address each time it
// runs — so re-invoking it after a lease change yields the new bind
// address rather than a cached stale one (#2884).
func TestPrepareConfigReResolvesDHCPLocalAddress(t *testing.T) {
	m := &Manager{configDir: t.TempDir()}

	// #6824: an exact match on the connection's local_addrs subsumes the
	// separate "stale address absent" needle. That third check existed only
	// because containment cannot say a value is the WHOLE value -- with the
	// setting read at a known path, a render that kept the old address either
	// fails the equality or declares local_addrs twice, and setting() rejects
	// a duplicated key outright.
	old := dhcpBoundConfig("wan0.0", "", "198.51.100.7/24", true)
	localAddrs_6824(t, m.renderMust(t, PrepareConfig(old)), "198.51.100.7")

	// Simulate a DHCP renew to a new lease address.
	renewed := dhcpBoundConfig("wan0.0", "", "203.0.113.42/24", true)
	renewedDoc := m.renderMust(t, PrepareConfig(renewed))
	localAddrs_6824(t, renewedDoc, "203.0.113.42")
	// The stale address must be gone from the WHOLE document. Equality at the
	// connection does not say that: a stale local_addrs under any other section
	// would satisfy it, and the deleted needle would have caught that.
	parseSwanctlDoc(t, renewedDoc).hasNoValueSubstringAnywhere(t, "198.51.100.7")
}

// renderMust renders the swanctl config for prepared, failing the test on
// error.
func (m *Manager) renderMust(t *testing.T, prepared *config.IPsecConfig) string {
	t.Helper()
	got, _, err := m.renderConfig(prepared)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}
	return got
}

// localAddrs_6824 asserts the single rendered connection's local_addrs is
// exactly want.
//
// It resolves the connection by taking the document's only child of
// connections{}, so the assertion does not silently depend on a section name
// the fixture never states.
func localAddrs_6824(t *testing.T, doc, want string) {
	t.Helper()
	conns := parseSwanctlDoc(t, doc).at(t, "connections")
	if len(conns.order) != 1 {
		t.Fatalf("expected exactly one connection, got %v\n%s", conns.childNames(), conns)
	}
	conns.at(t, conns.order[0]).requireSetting(t, "local_addrs", want)
}
