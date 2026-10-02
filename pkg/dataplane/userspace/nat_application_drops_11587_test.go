package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compileNATApplication11587(t *testing.T, body string) *config.Config {
	t.Helper()
	return lenientHier9571(t, `applications { application bad { `+body+` } }`)
}

func TestNATApplicationMatchDropsFailClosed11587(t *testing.T) {
	cases := []struct {
		name, body, wantDrop string
	}{
		{"unknown ICMP token", `protocol icmp; icmp-type bogus;`, `bogus`},
		{"incomplete direct ICMP type", `protocol icmp; icmp-type;`, `icmp-type`},
		{"duplicate direct ICMP type", `protocol icmp; icmp-type 8; icmp-type 3;`, `icmp-type`},
		{"incomplete term ICMP type", `term t1 { protocol icmp; icmp-type; }`, `icmp-type`},
		{"duplicate term ICMP type", `term t1 { protocol icmp; icmp-type 8; icmp-type 3; }`, `icmp-type`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileNATApplication11587(t, tc.body)
			drops := config.ApplicationReferenceMatchDrops("bad", &cfg.Applications)
			if !strings.Contains(strings.Join(drops, "\n"), tc.wantDrop) {
				t.Fatalf("fixture drops = %q, want a drop naming %q", drops, tc.wantDrop)
			}
			assertNATApplicationNeverMatches11587(t, cfg, "bad")
		})
	}
}

func TestNATApplicationSetMatchDropsFailClosed11587(t *testing.T) {
	cfg := lenientHier9571(t, `applications {
		application bad { protocol icmp; icmp-type bogus; }
		application-set bad-set { application bad; }
	}`)
	drops := config.ApplicationReferenceMatchDrops("bad-set", &cfg.Applications)
	if !strings.Contains(strings.Join(drops, "\n"), "bogus") {
		t.Fatalf("application-set drops = %q, want the nested malformed ICMP constraint", drops)
	}
	assertNATApplicationNeverMatches11587(t, cfg, "bad-set")
}

func assertNATApplicationNeverMatches11587(t *testing.T, cfg *config.Config, appName string) {
	t.Helper()
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name: "source-rs",
		Rules: []*config.NATRule{{
			Name:  "source-bad",
			Match: config.NATMatch{Application: appName},
		}},
	}}
	source := buildSourceNATSnapshots(cfg, nil)
	if len(source) != 1 || len(source[0].MatchApplications) != 1 ||
		source[0].MatchApplications[0].Protocol != natProtoNever {
		t.Fatalf("SNAT app terms = %+v, want the natProtoNever sentinel", source)
	}

	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"p1": {Name: "p1", Address: "192.0.2.1", Port: 8080},
		},
		RuleSets: []*config.NATRuleSet{{
			Name: "destination-rs",
			Rules: []*config.NATRule{{
				Name:  "destination-bad",
				Match: config.NATMatch{DestinationAddress: "198.51.100.10", Application: appName},
				Then:  config.NATThen{Type: config.NATDestination, PoolName: "p1"},
			}},
		}},
	}
	destination := buildDestinationNATSnapshots(cfg, nil)
	if len(destination) != 1 || len(destination[0].MatchSourcePorts) != 1 ||
		destination[0].MatchSourcePorts[0] != natNeverMatchPortRange {
		t.Fatalf("DNAT app constraints = %+v, want one impossible source-port sentinel", destination)
	}
	if destination[0].MatchICMPType != nil || destination[0].MatchICMPCode != nil {
		t.Fatalf("DNAT retained unconstrained/dropped ICMP fields: %+v", destination[0])
	}
}

func TestNATJunosPingApplicationKeepsEchoType11587(t *testing.T) {
	cfg := lenientHier9571(t, `applications { application ping { protocol junos-ping; } }`)
	if drops := config.ApplicationReferenceMatchDrops("ping", &cfg.Applications); len(drops) != 0 {
		t.Fatalf("valid junos-ping application was refused: %q", drops)
	}

	source := buildSourceNATAppTerms(cfg, []string{"ping"})
	if len(source) != 1 || source[0].Protocol != 1 || source[0].ICMPType == nil || *source[0].ICMPType != 8 {
		t.Fatalf("SNAT junos-ping terms = %+v, want ICMP protocol 1 constrained to type 8", source)
	}

	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"p1": {Name: "p1", Address: "192.0.2.1", Port: 8080},
		},
		RuleSets: []*config.NATRuleSet{{
			Name: "destination-rs",
			Rules: []*config.NATRule{{
				Name:  "destination-ping",
				Match: config.NATMatch{DestinationAddress: "198.51.100.10", Application: "ping"},
				Then:  config.NATThen{Type: config.NATDestination, PoolName: "p1"},
			}},
		}},
	}
	destination := buildDestinationNATSnapshots(cfg, nil)
	if len(destination) != 1 || destination[0].MatchICMPType == nil || *destination[0].MatchICMPType != 8 {
		t.Fatalf("DNAT junos-ping terms = %+v, want ICMP type 8 only", destination)
	}
	if destination[0].MatchICMPCode != nil {
		t.Fatalf("DNAT junos-ping ICMP code = %v, want unconstrained code", destination[0].MatchICMPCode)
	}
}
