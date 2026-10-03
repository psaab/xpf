package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// renderDHCP5519 runs renderDHCPDefaults over fc and returns the rendered
// text so a test can assert whether the DHCP-learned default survived or was
// suppressed by a static default.
func renderDHCP5519(fc *FullConfig) string {
	var b strings.Builder
	renderDHCPDefaults(&b, fc)
	return b.String()
}

// #5519 (availability / remote lockout): renderDHCPDefaults suppressed the
// DHCP-learned default for ANY static 0.0.0.0/0 (or ::/0) stanza, but
// generateStaticRoute emits NOTHING for a zero-next-hop, non-discard default
// (#3872). Deleting the last ECMP next-hop of a static default therefore left a
// 0.0.0.0/0 object that rendered no FIB entry AND still masked the DHCP
// fallback → no default route at all → WAN / management lockout. Suppression
// must be derived from the static default's ACTUAL renderability
// (staticRouteRendersFIB), not the mere presence of the stanza.
//
// RED-on-revert: restore the old `sr.Destination == "0.0.0.0/0"` /
// `sr.Destination == "::/0"` suppression (drop the staticRouteRendersFIB
// guard) and the zero-next-hop cases below fail — the DHCP default vanishes.

// (a) A zero-next-hop, non-discard static default must NOT suppress the
// DHCP-learned v4 default: the DHCP default survives in the rendered output.
func TestZeroNextHopStaticDefaultKeepsDHCPDefault_v4_5519(t *testing.T) {
	fc := &FullConfig{
		StaticRoutes: []*config.StaticRoute{{Destination: "0.0.0.0/0"}}, // no next-hops
		DHCPRoutes:   []DHCPRoute{{Destination: "", Gateway: "10.0.2.1"}},
	}
	got := renderDHCP5519(fc)
	if !strings.Contains(got, "ip route 0.0.0.0/0 10.0.2.1 200") {
		t.Fatalf("zero-next-hop static default suppressed the DHCP v4 default (remote lockout); rendered:\n%s", got)
	}
}

// (b) A static default WITH next-hops renders a FIB entry, so it DOES suppress
// the DHCP-learned v4 default (unchanged pre-#5519 behavior).
func TestNextHopStaticDefaultSuppressesDHCPDefault_v4_5519(t *testing.T) {
	fc := &FullConfig{
		StaticRoutes: []*config.StaticRoute{{
			Destination: "0.0.0.0/0",
			NextHops:    []config.NextHopEntry{{Address: "10.0.2.254"}},
		}},
		DHCPRoutes: []DHCPRoute{{Destination: "", Gateway: "10.0.2.1"}},
	}
	if got := renderDHCP5519(fc); strings.Contains(got, "0.0.0.0/0") {
		t.Fatalf("next-hop static default did not suppress the DHCP v4 default; rendered:\n%s", got)
	}
}

// (c) A discard or reject static default renders a negative FIB entry, so it
// DOES suppress the DHCP-learned v4 default.
func TestDiscardRejectStaticDefaultSuppressesDHCPDefault_v4_5519(t *testing.T) {
	for _, tc := range []struct {
		name string
		sr   *config.StaticRoute
	}{
		{"discard", &config.StaticRoute{Destination: "0.0.0.0/0", Discard: true}},
		{"reject", &config.StaticRoute{Destination: "0.0.0.0/0", Reject: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc := &FullConfig{
				StaticRoutes: []*config.StaticRoute{tc.sr},
				DHCPRoutes:   []DHCPRoute{{Destination: "", Gateway: "10.0.2.1"}},
			}
			if got := renderDHCP5519(fc); strings.Contains(got, "0.0.0.0/0") {
				t.Fatalf("%s static default did not suppress the DHCP v4 default; rendered:\n%s", tc.name, got)
			}
		})
	}
}

// (d) Same matrix for the IPv6 ::/0 default.
func TestZeroNextHopStaticDefaultKeepsDHCPDefault_v6_5519(t *testing.T) {
	fc := &FullConfig{
		Inet6StaticRoutes: []*config.StaticRoute{{Destination: "::/0"}}, // no next-hops
		DHCPRoutes:        []DHCPRoute{{Destination: "", Gateway: "fe80::1", Interface: "ge-0-0-2", IsIPv6: true}},
	}
	got := renderDHCP5519(fc)
	if !strings.Contains(got, "ipv6 route ::/0 fe80::1 ge-0-0-2 200") {
		t.Fatalf("zero-next-hop static ::/0 default suppressed the DHCP v6 default (remote lockout); rendered:\n%s", got)
	}
}

func TestNextHopStaticDefaultSuppressesDHCPDefault_v6_5519(t *testing.T) {
	fc := &FullConfig{
		Inet6StaticRoutes: []*config.StaticRoute{{
			Destination: "::/0",
			NextHops:    []config.NextHopEntry{{Address: "2001:db8::1"}},
		}},
		DHCPRoutes: []DHCPRoute{{Destination: "", Gateway: "fe80::1", Interface: "ge-0-0-2", IsIPv6: true}},
	}
	if got := renderDHCP5519(fc); strings.Contains(got, "::/0") {
		t.Fatalf("next-hop static ::/0 default did not suppress the DHCP v6 default; rendered:\n%s", got)
	}
}

func TestDiscardRejectStaticDefaultSuppressesDHCPDefault_v6_5519(t *testing.T) {
	for _, tc := range []struct {
		name string
		sr   *config.StaticRoute
	}{
		{"discard", &config.StaticRoute{Destination: "::/0", Discard: true}},
		{"reject", &config.StaticRoute{Destination: "::/0", Reject: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc := &FullConfig{
				Inet6StaticRoutes: []*config.StaticRoute{tc.sr},
				DHCPRoutes:        []DHCPRoute{{Destination: "", Gateway: "fe80::1", Interface: "ge-0-0-2", IsIPv6: true}},
			}
			if got := renderDHCP5519(fc); strings.Contains(got, "::/0") {
				t.Fatalf("%s static ::/0 default did not suppress the DHCP v6 default; rendered:\n%s", tc.name, got)
			}
		})
	}
}

// staticRouteRendersFIB is the route-existence predicate. The tests below pin
// its truth table separately from effective default distance, including
// qualified-next-hop overrides (#11424).
func TestStaticRouteRendersFIB_5519(t *testing.T) {
	cases := []struct {
		name string
		sr   *config.StaticRoute
		want bool
	}{
		{"zero-next-hop", &config.StaticRoute{Destination: "0.0.0.0/0"}, false},
		{"next-hop", &config.StaticRoute{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "10.0.0.1"}}}, true},
		{"discard", &config.StaticRoute{Destination: "0.0.0.0/0", Discard: true}, true},
		{"reject", &config.StaticRoute{Destination: "0.0.0.0/0", Reject: true}, true},
		{"cross-family-next-hop", &config.StaticRoute{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "2001:db8::1"}}}, false},
		{"discard-with-unused-cross-family-next-hop", &config.StaticRoute{Destination: "0.0.0.0/0", Discard: true, NextHops: []config.NextHopEntry{{Address: "2001:db8::1"}}}, true},
		{"next-table", &config.StaticRoute{Destination: "0.0.0.0/0", NextTable: "Comcast"}, false},
	}
	for _, tc := range cases {
		if got := staticRouteRendersFIB(tc.sr); got != tc.want {
			t.Errorf("staticRouteRendersFIB(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// #11421: a cross-family static default is not rendered, so it must not mask
// the DHCP-learned fallback. Negative routes still use their discard/reject
// disposition, independently of any unused next-hop list.
func TestCrossFamilyStaticDefaultKeepsDHCPDefault11421(t *testing.T) {
	for _, tc := range []struct {
		name   string
		route  *config.StaticRoute
		dhcp   DHCPRoute
		want   string
		isIPv6 bool
	}{
		{
			name:  "IPv4",
			route: &config.StaticRoute{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "2001:db8::1"}}},
			dhcp:  DHCPRoute{Destination: "", Gateway: "10.0.2.1"},
			want:  "ip route 0.0.0.0/0 10.0.2.1 200",
		},
		{
			name:   "IPv6",
			route:  &config.StaticRoute{Destination: "::/0", NextHops: []config.NextHopEntry{{Address: "192.0.2.1"}}},
			dhcp:   DHCPRoute{Destination: "", Gateway: "fe80::1", Interface: "ge-0-0-2", IsIPv6: true},
			want:   "ipv6 route ::/0 fe80::1 ge-0-0-2 200",
			isIPv6: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fc := &FullConfig{DHCPRoutes: []DHCPRoute{tc.dhcp}}
			if tc.isIPv6 {
				fc.Inet6StaticRoutes = []*config.StaticRoute{tc.route}
			} else {
				fc.StaticRoutes = []*config.StaticRoute{tc.route}
			}
			if got := renderDHCP5519(fc); !strings.Contains(got, tc.want) {
				t.Fatalf("unrenderable cross-family static default suppressed DHCP fallback %q:\n%s", tc.want, got)
			}
		})
	}
}

// #11424: renderability is not enough to suppress DHCP defaults; the effective
// static route distance must be no worse than the DHCP distance 200. The
// qualified-next-hop cells make the check follow the distance actually emitted
// per next-hop rather than only the route-level preference.
func TestStaticDefaultPreferenceControlsDHCPSuppression11424(t *testing.T) {
	families := []struct {
		name, destination, staticNextHop, dhcpGateway, dhcpInterface, dhcpLine string
		isIPv6                                                                 bool
	}{
		{"v4", "0.0.0.0/0", "192.0.2.254", "192.0.2.1", "", "ip route 0.0.0.0/0 192.0.2.1 200", false},
		{"v6", "::/0", "2001:db8::2", "fe80::1", "ge-0-0-2", "ipv6 route ::/0 fe80::1 ge-0-0-2 200", true},
	}
	cases := []struct {
		name                    string
		preference              int
		qualifiedPreference     int
		includePrimary, discard bool
		wantDHCP                bool
	}{
		{"static-preference-250", 250, 0, true, false, true},
		{"static-preference-5", 5, 0, true, false, false},
		{"qualified-next-hop-250", 5, 250, false, false, true},
		{"primary-5-with-floating-backup-250", 5, 250, true, false, false},
		{"discard-preference-250", 250, 0, false, true, true},
	}
	for _, family := range families {
		t.Run(family.name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					sr := &config.StaticRoute{
						Destination: family.destination,
						Preference:  tc.preference,
						Discard:     tc.discard,
					}
					if tc.includePrimary {
						sr.NextHops = append(sr.NextHops, config.NextHopEntry{Address: family.staticNextHop})
					}
					if tc.qualifiedPreference > 0 {
						sr.NextHops = append(sr.NextHops, config.NextHopEntry{
							Address:       family.staticNextHop,
							Preference:    tc.qualifiedPreference,
							HasPreference: true,
						})
					}
					dr := DHCPRoute{
						Gateway:   family.dhcpGateway,
						Interface: family.dhcpInterface,
						IsIPv6:    family.isIPv6,
					}
					fc := &FullConfig{DHCPRoutes: []DHCPRoute{dr}}
					if family.isIPv6 {
						fc.Inet6StaticRoutes = []*config.StaticRoute{sr}
					} else {
						fc.StaticRoutes = []*config.StaticRoute{sr}
					}

					dhcpRendered := renderDHCP5519(fc)
					staticRendered := New().generateStaticRoute(sr, "", nil, nil, nil)
					if staticRendered == "" {
						t.Fatal("static default was not rendered")
					}
					gotDHCP := strings.Contains(dhcpRendered, family.dhcpLine)
					if gotDHCP != tc.wantDHCP {
						t.Fatalf("DHCP default rendered = %v, want %v; static=%q DHCP=%q",
							gotDHCP, tc.wantDHCP, staticRendered, dhcpRendered)
					}
					if tc.wantDHCP && !strings.Contains(staticRendered, family.destination) {
						t.Fatalf("pref-250 static default missing alongside DHCP default: %q", staticRendered)
					}
				})
			}
		})
	}
}
