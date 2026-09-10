package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9523 — `show security match-policies` resolves a match-all keyword before a
// name, as the snapshot builder does. Channel: config.CompileConfigLenient, plus
// config.CompileConfig for the name-before-literal control (a legitimate,
// committable config).

func compileSet9523(t *testing.T, lines []string, lenient bool) (*config.Config, error) {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, l := range lines {
		p, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	if lenient {
		return config.CompileConfigLenient(tree)
	}
	return config.CompileConfig(tree)
}

func policy9523(name, src, app, action string) []string {
	p := "set security policies from-zone trust to-zone untrust policy " + name + " "
	return []string{p + "match source-address " + src, p + "match destination-address any", p + "match application " + app, p + "then " + action}
}

func TestAddressNamedAnyVerdictKeepsMatchAll9523(t *testing.T) {
	base := append(append([]string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies default-policy deny-all",
	}, policy9523("d1", "any", "junos-telnet", "deny")...), policy9523("p1", "any", "any", "permit")...)
	for _, tc := range []struct {
		name    string
		lines   []string
		overlay map[string][]string
	}{
		{"address any", []string{"set security address-book global address any 10.99.0.0/16"}, nil},
		{"address-set any", []string{
			"set security address-book global address a1 10.99.0.0/16",
			"set security address-book global address-set any address a1",
		}, nil},
		{"dynamic-address address-name any", []string{
			"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
			"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
			"set security dynamic-address address-name any profile feed-name malware",
		}, map[string][]string{"any": {"10.99.0.0/16"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := compileSet9523(t, append(append([]string{}, base...), tc.lines...), true)
			if err != nil {
				t.Fatal(err)
			}
			q := Query{FromZone: "trust", ToZone: "untrust", SrcIP: net.ParseIP("1.2.3.4"), DstIP: net.ParseIP("5.6.7.8"), Protocol: "tcp", SrcPort: 40000, DstPort: 23, FeedOverlay: tc.overlay}
			if res := Match(cfg, q); !res.Matched || res.PolicyName != "d1" || res.Action != config.PolicyDeny {
				t.Errorf("#9523: telnet outside the object's prefix must hit the `deny any` rule, got Matched=%v Policy=%q Action=%v", res.Matched, res.PolicyName, res.Action)
			}
			q.DstPort = 80
			if res := Match(cfg, q); !res.Matched || res.PolicyName != "p1" || res.Action != config.PolicyPermit {
				t.Errorf("#9523: web outside the object's prefix must hit the `permit any` rule, got Matched=%v Policy=%q Action=%v", res.Matched, res.PolicyName, res.Action)
			}
		})
	}
}

// Name-before-literal is documented and matches Junos; it must survive. The
// config commits on the strict channel, which is what makes it a legitimate
// control rather than a second malformed fixture.
func TestAddressNameBeforeLiteralStillHolds9523(t *testing.T) {
	lines := append([]string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies default-policy permit-all",
		"set security address-book global address 10.0.1.0/24 192.0.2.0/24",
	}, policy9523("d1", "10.0.1.0/24", "any", "deny")...)
	cfg, err := compileSet9523(t, lines, false)
	if err != nil {
		t.Fatalf("control must commit: %v", err)
	}
	q := Query{FromZone: "trust", ToZone: "untrust", DstIP: net.ParseIP("5.6.7.8"), Protocol: "tcp", SrcPort: 40000, DstPort: 80}
	q.SrcIP = net.ParseIP("192.0.2.5")
	if res := Match(cfg, q); !res.Matched || res.PolicyName != "d1" {
		t.Errorf("the token names the address, so its VALUE must match: %+v", res)
	}
	q.SrcIP = net.ParseIP("10.0.1.5")
	if res := Match(cfg, q); res.Matched {
		t.Errorf("the token is a name, not the literal 10.0.1.0/24: %+v", res)
	}
}
