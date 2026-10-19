package natshow

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// dest_ports_15226_test.go — #15226 (A42-02), the port sibling of #7363.
//
// Every NAT display surface rendered a multi-port or port-range DNAT match
// as its first port only, while the dataplane enforces the full list. The
// probe rows from the issue: (2) a bracket list must list all ports, and
// (3) a port range must not collapse to its first port.
//
// RED-on-revert: restore any surface's singular-field read
// (rule.Match.DestinationPort) and the corresponding cell fails — the text
// renderer here, and the structured surfaces in pkg/grpcapi / pkg/api /
// cmd/cli's own #15226 cells.

func destPortsCfg15226(m config.NATMatch) *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"dp1": {Name: "dp1", Address: "10.0.30.5"}},
		RuleSets: []*config.NATRuleSet{{
			Name: "drs", FromZone: "untrust",
			Rules: []*config.NATRule{{
				Name: "d1", Match: m, Then: config.NATThen{PoolName: "dp1"},
			}},
		}},
	}
	return cfg
}

func renderDestPorts15226(t *testing.T, m config.NATMatch) string {
	t.Helper()
	var b bytes.Buffer
	RenderDestRuleDetail(context.Background(), &b, destPortsCfg15226(m), nil, nil)
	return b.String()
}

func TestRuleMatchDestPorts15226(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    config.NATMatch
		want []int
		text string
	}{
		{"bracket list", config.NATMatch{DestinationPort: 80, DestinationPorts: []int{443, 80}}, []int{80, 443}, "80,443"},
		{"range expanded by parser", config.NATMatch{DestinationPort: 20000, DestinationPorts: []int{20000, 20001, 20002, 20003}}, []int{20000, 20001, 20002, 20003}, "20000-20003"},
		{"mixed discrete and range", config.NATMatch{DestinationPorts: []int{9002, 80, 9000, 443, 9001}}, []int{80, 443, 9000, 9001, 9002}, "80,443,9000-9002"},
		{"scalar only (peer-synced shape)", config.NATMatch{DestinationPort: 8443}, []int{8443}, "8443"},
		{"plural supersedes scalar, no duplicate", config.NATMatch{DestinationPort: 80, DestinationPorts: []int{80, 80, 443}}, []int{80, 443}, "80,443"},
		{"no constraint", config.NATMatch{}, nil, ""},
		{"out-of-range only renders unconstrained", config.NATMatch{DestinationPorts: []int{70000, 0}}, nil, ""},
		{"out-of-range dropped, valid kept", config.NATMatch{DestinationPorts: []int{70000, 443}}, []int{443}, "443"},
	} {
		rule := &config.NATRule{Match: tc.m}
		got := RuleMatchDestPorts(rule)
		if len(got) != len(tc.want) {
			t.Errorf("%s: RuleMatchDestPorts = %v, want %v", tc.name, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: RuleMatchDestPorts = %v, want %v", tc.name, got, tc.want)
				break
			}
		}
		if text := RuleMatchDestPortsText(rule); text != tc.text {
			t.Errorf("%s: RuleMatchDestPortsText = %q, want %q", tc.name, text, tc.text)
		}
	}
	if got := RuleMatchDestPorts(nil); got != nil {
		t.Errorf("nil rule: RuleMatchDestPorts = %v, want nil", got)
	}
}

// Probe row 2: a bracket-list rule must list ALL ports in the detail text.
func TestDestRuleDetailListsAllBracketPorts15226(t *testing.T) {
	out := renderDestPorts15226(t, config.NATMatch{
		DestinationAddress: "198.51.100.7/32",
		DestinationPort:    80, DestinationPorts: []int{80, 443},
	})
	if !strings.Contains(out, "Destination port:      80,443") {
		t.Errorf("bracket-list rule must render every port, got:\n%s", out)
	}
	if strings.Contains(out, "Destination port:      80\n") {
		t.Errorf("bracket-list rule collapsed to its first port:\n%s", out)
	}
}

// Probe row 3: a port range must render as the range, not its first port.
func TestDestRuleDetailRendersPortRange15226(t *testing.T) {
	out := renderDestPorts15226(t, config.NATMatch{
		DestinationAddress: "198.51.100.7/32",
		DestinationPort:    20000, DestinationPorts: []int{20000, 20001, 20002, 20003},
	})
	if !strings.Contains(out, "Destination port:      20000-20003") {
		t.Errorf("range rule must render the full range, got:\n%s", out)
	}
}

// CONTROL: a single-port rule renders exactly as before, and a rule with no
// port constraint renders no port line at all.
func TestDestRuleDetailPortControls15226(t *testing.T) {
	single := renderDestPorts15226(t, config.NATMatch{
		DestinationAddress: "198.51.100.7/32", DestinationPort: 443,
	})
	if !strings.Contains(single, "Destination port:      443\n") {
		t.Errorf("single-port control changed:\n%s", single)
	}
	none := renderDestPorts15226(t, config.NATMatch{
		DestinationAddress: "198.51.100.7/32",
	})
	if strings.Contains(none, "Destination port:") {
		t.Errorf("unconstrained rule gained a port line:\n%s", none)
	}
}

// The combined address+ports form behind destination_match / rule-all.
func TestRuleMatchDestinationWithPorts15226(t *testing.T) {
	rule := &config.NATRule{Match: config.NATMatch{
		DestinationAddress: "198.51.100.7/32",
		DestinationPort:    80, DestinationPorts: []int{80, 443},
	}}
	if got := RuleMatchDestinationWithPorts(rule); got != "198.51.100.7/32:80,443" {
		t.Errorf("RuleMatchDestinationWithPorts = %q, want %q", got, "198.51.100.7/32:80,443")
	}
	noPort := &config.NATRule{Match: config.NATMatch{DestinationAddress: "198.51.100.7/32"}}
	if got := RuleMatchDestinationWithPorts(noPort); got != "198.51.100.7/32" {
		t.Errorf("no-port control = %q, want bare address", got)
	}
}

// Census: no display surface may go back to reading the singular field.
// Mirrors the #8580 census shape — a private copy is how the first-port
// rendering spread to five surfaces in the first place.
var singularDestPortRenderRe15226 = regexp.MustCompile(`Match\.DestinationPort\b`)

func TestNoSingularDestPortRenderCopy15226(t *testing.T) {
	surfaces := []string{
		filepath.Join("dest.go"),
		filepath.Join("..", "grpcapi", "server_nat.go"),
		filepath.Join("..", "api", "nat.go"),
		filepath.Join("..", "cli", "cli_show_nat.go"),
	}
	for _, rel := range surfaces {
		src, err := os.ReadFile(rel)
		if err != nil {
			t.Fatalf("read %s: %v — census cannot run and would pass vacuously", rel, err)
		}
		if m := singularDestPortRenderRe15226.FindString(string(src)); m != "" {
			t.Errorf("%s reads the singular %s again; a multi-port rule would "+
				"render as its first port only. Call natshow.RuleMatchDestPorts / "+
				"RuleMatchDestPortsText / RuleMatchDestinationWithPorts.", rel, m)
		}
	}
}
