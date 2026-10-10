package policymatch

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestPostNATInputRequirement12246(t *testing.T) {
	tests := []struct {
		name string
		nat  config.NATConfig
		want bool
	}{
		{
			name: "destination NAT",
			nat: config.NATConfig{Destination: &config.DestinationNATConfig{
				RuleSets: []*config.NATRuleSet{{Name: "dnat"}},
			}},
			want: true,
		},
		{
			name: "static NAT and NPTv6",
			nat:  config.NATConfig{Static: []*config.StaticNATRuleSet{{Name: "static"}}},
			want: true,
		},
		{
			name: "NAT64",
			nat:  config.NATConfig{NAT64: []*config.NAT64RuleSet{{Name: "nat64"}}},
			want: true,
		},
		{
			name: "source NAT only",
			nat:  config.NATConfig{Source: []*config.NATRuleSet{{Name: "snat"}}},
			want: false,
		},
		{
			name: "no NAT",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{Security: config.SecurityConfig{NAT: tt.nat}}
			res := Match(cfg, Query{FromZone: "untrust", ToZone: "trust"})
			if got := res.PostNATInputNote != ""; got != tt.want {
				t.Errorf("post-NAT requirement present = %v, want %v; note %q", got, tt.want, res.PostNATInputNote)
			}
			if tt.want && res.PostNATInputNote != PostNATInputRequirementNote {
				t.Errorf("configured inbound destination NAT must carry the post-NAT input requirement; got %q", res.PostNATInputNote)
			}
		})
	}

	for name, usage := range map[string]string{
		"match-policies": MatchPoliciesUsage,
		"test policy":    TestPolicyUsage,
	} {
		if !strings.Contains(usage, "post-DNAT/post-translation") ||
			!strings.Contains(usage, "destination-ip") ||
			!strings.Contains(usage, "destination-port") {
			t.Errorf("%s usage must state the expected post-DNAT destination tuple:\n%s", name, usage)
		}
	}
}
