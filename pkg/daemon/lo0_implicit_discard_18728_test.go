package daemon

import (
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #18728: the kernel lo0 mirror ends each family's lo0 filter that has no
// terminal catch-all with the Junos implicit final discard,
//
//	meta nfproto <f> iifname != { "lo", <control>, <fabric> } counter name "xpflo0implicit_<family>" drop
//
// placed after that family's authored rules. The exemption keeps loopback and
// the cluster control/fabric links off the IMPLICIT drop only.

func lo0AllowlistCfg18728() *config.Config {
	cfg := &config.Config{}
	cfg.System.Lo0FilterInputV4 = "protect-re"
	cfg.System.Lo0FilterInputV6 = "protect-re6"
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"protect-re": {Name: "protect-re", Terms: []*config.FirewallFilterTerm{
			{Name: "ssh", Protocols: []string{"tcp"}, DestinationPorts: []string{"22"}, Action: config.FilterActionAccept},
		}},
	}
	cfg.Firewall.FiltersInet6 = map[string]*config.FirewallFilter{
		"protect-re6": {Name: "protect-re6", Terms: []*config.FirewallFilterTerm{
			{Name: "ssh6", Protocols: []string{"tcp"}, DestinationPorts: []string{"22"}, Action: config.FilterActionAccept},
		}},
	}
	return cfg
}

func lineIndex18728(t *testing.T, lines []string, needle string) int {
	t.Helper()
	for i, l := range lines {
		if strings.Contains(l, needle) {
			return i
		}
	}
	t.Fatalf("payload has no line containing %q:\n%s", needle, strings.Join(lines, "\n"))
	return -1
}

// Standalone: each family gets its counted drop right after its own rules,
// exempting only loopback, and both counters are declared.
func TestLo0OracleImplicitDiscardPerFamily18728(t *testing.T) {
	payload := buildLo0FilterPayload(lo0AllowlistCfg18728(), "protect-re", "protect-re6")
	wantV4 := `    meta nfproto ipv4 iifname != "lo" meta sdifname != "lo" counter name "xpflo0implicit_inet" drop`
	wantV6 := `    meta nfproto ipv6 iifname != "lo" meta sdifname != "lo" counter name "xpflo0implicit_inet6" drop`
	lines := strings.Split(payload, "\n")
	v4 := lineIndex18728(t, lines, wantV4)
	v6 := lineIndex18728(t, lines, wantV6)
	if lines[v4] != wantV4 || lines[v6] != wantV6 {
		t.Fatalf("implicit rules = %q / %q, want %q / %q", lines[v4], lines[v6], wantV4, wantV6)
	}
	// The v4 ssh accept precedes the v4 drop; the v4 drop precedes every v6
	// rule; the v6 ssh accept precedes the v6 drop.
	ssh4 := -1
	ssh6 := -1
	for i, l := range lines {
		if strings.Contains(l, "th dport 22") && strings.Contains(l, "accept") {
			if ssh4 < 0 {
				ssh4 = i
			} else {
				ssh6 = i
			}
		}
	}
	if !(ssh4 >= 0 && ssh4 < v4-1 && v4 < ssh6 && ssh6 < v6) {
		t.Fatalf("rule order ssh4=%d drop4=%d ssh6=%d drop6=%d; want the drop after its own family's rules\n%s", ssh4, v4, ssh6, v6, payload)
	}
	for _, decl := range []string{"  counter xpflo0implicit_inet {", "  counter xpflo0implicit_inet6 {"} {
		if !strings.Contains(payload, decl+"\n") {
			t.Errorf("payload lacks counter declaration %q:\n%s", decl, payload)
		}
	}
	// The IPv4 VRF-local accept (iifname = sdifname = VRF master: traffic the
	// box generates inside a VRF) sits right before the IPv4 drop. IPv6 has
	// none: its VRF-local traffic carries the address-owning slave as
	// sdifname, indistinguishable from fxp0 ingress, so the line before the
	// IPv6 drop is the authored ssh accept.
	if want := `    meta nfproto ipv4 iifname "vrf-mgmt" meta sdifname "vrf-mgmt" accept`; lines[v4-1] != want {
		t.Errorf("line before the IPv4 implicit drop = %q, want %q", lines[v4-1], want)
	}
	if strings.Contains(payload, "meta nfproto ipv6 iifname \"vrf-mgmt\"") || ssh6 != v6-1 {
		t.Errorf("IPv6 must have no VRF-local accept (ssh6=%d drop6=%d):\n%s", ssh6, v6, payload)
	}
	if got := lo0RenderedRuleCount(lo0AllowlistCfg18728(), "protect-re", "protect-re6"); got != 5 {
		t.Errorf("rendered rule count = %d, want 5 (two ssh accepts + the IPv4 VRF-local accept + two implicit drops)", got)
	}
}

// A family whose filter has a terminal catch-all gets no implicit drop; the
// other family still does. The modifier-only catch-all counts (#14632).
func TestLo0OracleNoImplicitDiscardWithCatchAll18728(t *testing.T) {
	cfg := lo0AllowlistCfg18728()
	cfg.Firewall.FiltersInet["protect-re"].Terms = append(cfg.Firewall.FiltersInet["protect-re"].Terms,
		&config.FirewallFilterTerm{Name: "count-rest", Count: "rest"})
	payload := buildLo0FilterPayload(cfg, "protect-re", "protect-re6")
	if strings.Contains(payload, "xpflo0implicit_inet ") || strings.Contains(payload, `"xpflo0implicit_inet"`) {
		t.Fatalf("a v4 filter with a modifier-only catch-all must not get the implicit drop:\n%s", payload)
	}
	if !strings.Contains(payload, `counter name "xpflo0implicit_inet6" drop`) {
		t.Fatalf("the v6 allowlist must still get its implicit drop:\n%s", payload)
	}
	spec := toNftLo0Spec(cfg, "protect-re", "protect-re6")
	if spec.ImplicitDiscardV4 || !spec.ImplicitDiscardV6 {
		t.Fatalf("spec flags v4=%v v6=%v, want false/true", spec.ImplicitDiscardV4, spec.ImplicitDiscardV6)
	}
	// Only one family configured: the other family is untouched.
	payload = buildLo0FilterPayload(lo0AllowlistCfg18728(), "protect-re", "")
	if strings.Contains(payload, "nfproto ipv6 iifname") {
		t.Fatalf("no inet6 lo0 filter: no v6 implicit drop:\n%s", payload)
	}
}

// Cluster: the control link and the fabric (the fabric interface and its
// member links) are exempt; fxp0 is not. The netlink spec carries the same
// set the oracle renders.
func TestLo0ImplicitDiscardExemptsClusterLinks18728(t *testing.T) {
	cfg := lo0AllowlistCfg18728()
	cfg.Chassis.Cluster = &config.ClusterConfig{ControlInterface: "em0"}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"em0":      {Name: "em0", Units: map[int]*config.InterfaceUnit{0: {Number: 0, Addresses: []string{"10.99.0.1/24"}}}},
		"fab0":     {Name: "fab0", FabricMembers: []string{"ge-0/0/0"}},
		"fxp0":     {Name: "fxp0", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCP: true}}},
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	want := []string{"lo", "em0", "fab0", "ge-0-0-0"}
	if got := config.Lo0ImplicitDiscardExemptNetdevs(cfg); !reflect.DeepEqual(got, want) {
		t.Fatalf("exempt netdevs = %v, want %v (control link + fabric, never fxp0 or a data port)", got, want)
	}
	payload := buildLo0FilterPayload(cfg, "protect-re", "protect-re6")
	wantRule := `meta nfproto ipv4 iifname != { "lo", "em0", "fab0", "ge-0-0-0" } meta sdifname != { "lo", "em0", "fab0", "ge-0-0-0" } counter name "xpflo0implicit_inet" drop`
	if !strings.Contains(payload, wantRule) {
		t.Fatalf("payload lacks %q:\n%s", wantRule, payload)
	}
	spec := toNftLo0Spec(cfg, "protect-re", "protect-re6")
	if !reflect.DeepEqual(spec.ImplicitDiscardExemptNetdevs, want) {
		t.Fatalf("netlink spec exempt = %v, want %v", spec.ImplicitDiscardExemptNetdevs, want)
	}
	// A catch-all-only config carries no exemption list (nothing uses it).
	cfg.Firewall.FiltersInet["protect-re"].Terms = append(cfg.Firewall.FiltersInet["protect-re"].Terms,
		&config.FirewallFilterTerm{Name: "default", Action: config.FilterActionAccept})
	cfg.Firewall.FiltersInet6["protect-re6"].Terms = append(cfg.Firewall.FiltersInet6["protect-re6"].Terms,
		&config.FirewallFilterTerm{Name: "default6", Action: config.FilterActionAccept})
	if spec := toNftLo0Spec(cfg, "protect-re", "protect-re6"); spec.ImplicitDiscardV4 || spec.ImplicitDiscardV6 || spec.ImplicitDiscardExemptNetdevs != nil {
		t.Fatalf("catch-all filters: spec = %+v, want no implicit discard", spec)
	}
}

// The exemption is the implicit drop's only: an authored discard term still
// renders without any iifname scope (#18729 tracks exempting internal
// traffic from authored terms too).
func TestLo0ExplicitDiscardTermUnchanged18728(t *testing.T) {
	cfg := lo0AllowlistCfg18728()
	cfg.Firewall.FiltersInet["protect-re"].Terms = append(cfg.Firewall.FiltersInet["protect-re"].Terms,
		&config.FirewallFilterTerm{Name: "deny-rest", Action: config.FilterActionDiscard})
	payload := buildLo0FilterPayload(cfg, "protect-re", "")
	lines := strings.Split(payload, "\n")
	last := lines[len(lines)-4] // "    drop", "  }", "}", ""
	if strings.TrimSpace(last) != "drop" {
		t.Fatalf("authored unconstrained discard must render as a bare drop (no implicit rule after it); tail:\n%s", strings.Join(lines[len(lines)-6:], "\n"))
	}
	if strings.Contains(payload, "xpflo0implicit") {
		t.Fatalf("an authored catch-all discard leaves no implicit rule:\n%s", payload)
	}
}

// fakeLo0Rules mirrors the installer count, implicit rules included.
func TestFakeLo0RulesCountsImplicitDiscard18728(t *testing.T) {
	spec := toNftLo0Spec(lo0AllowlistCfg18728(), "protect-re", "protect-re6")
	if got := fakeLo0Rules(spec); got != 5 {
		t.Fatalf("fakeLo0Rules = %d, want 5", got)
	}
}
