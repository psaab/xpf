package natshow

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15269 C09-01: RenderDestRuleDetail must show source match.

func TestDestRuleDetailSourceMatch15269(t *testing.T) {
	mk := func(src string) *config.Config {
		r := &config.NATRule{Name: "r1"}
		r.Match.DestinationAddress = "203.0.113.10/32"
		if src != "" {
			r.Match.SourceAddress = src
			r.Match.SourceAddresses = []string{src}
		}
		r.Then.PoolName = "p1"
		return &config.Config{Security: config.SecurityConfig{NAT: config.NATConfig{Destination: &config.DestinationNATConfig{
			Pools:    map[string]*config.NATPool{"p1": {Address: "10.0.0.5"}},
			RuleSets: []*config.NATRuleSet{{Name: "rs", FromZone: "untrust", Rules: []*config.NATRule{r}}},
		}}}}
	}
	var scoped, open bytes.Buffer
	RenderDestRuleDetail(context.Background(), &scoped, mk("198.51.100.0/24"), nil, nil)
	RenderDestRuleDetail(context.Background(), &open, mk(""), nil, nil)
	if !strings.Contains(scoped.String(), "Source addresses:") || !strings.Contains(scoped.String(), "198.51.100.0/24") {
		t.Errorf("scoped missing source:\n%s", scoped.String())
	}
	if !strings.Contains(open.String(), "Source addresses:") || !strings.Contains(open.String(), "0.0.0.0/0") {
		t.Errorf("open missing 0.0.0.0/0:\n%s", open.String())
	}
	if scoped.String() == open.String() {
		t.Error("scoped and open renders must differ")
	}
}
