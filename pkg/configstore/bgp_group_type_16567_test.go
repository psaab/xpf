package configstore

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// CheckText is the shared commit/check-config gate, including schema and
// group expansion. Pin both acceptance and rejection through that entrypoint.
func TestCheckTextBGPGroupType16567(t *testing.T) {
	for _, instance := range []bool{false, true} {
		for _, tc := range []struct {
			name, body string
			wantAS     uint32
			wantError  string
		}{
			{"derive internal", "type internal; neighbor 10.0.2.3;", 65000, ""},
			{"explicit internal", "type internal; peer-as 65000; neighbor 10.0.2.3;", 65000, ""},
			{"explicit external", "type external; peer-as 65001; neighbor 10.0.2.3;", 65001, ""},
			{"type absent", "peer-as 65001; neighbor 10.0.2.3;", 65001, ""},
			{"foreign internal", "type internal; peer-as 65001; neighbor 10.0.2.3;", 0, "type internal"},
			{"own external", "type external; peer-as 65000; neighbor 10.0.2.3;", 0, "type external"},
			{"typo", "type internl; peer-as 65001; neighbor 10.0.2.3;", 0, "internl"},
			{"missing value", "type; peer-as 65001; neighbor 10.0.2.3;", 0, "type"},
			{"empty typo group", "type internl;", 0, "internl"},
			{"empty missing value", "type;", 0, "type"},
			{"empty internal group", "type internal;", 0, ""},
			{"empty external group", "type external;", 0, ""},
			{"missing external AS", "type external; neighbor 10.0.2.3;", 0, "peer-as"},
			{"invalid internal AS", "type internal; peer-as 0; neighbor 10.0.2.3;", 0, "peer-as"},
		} {
			t.Run(fmt.Sprintf("instance=%v/%s", instance, tc.name), func(t *testing.T) {
				text := "protocols { bgp { group G { " + tc.body + " } } }"
				if instance {
					text = "routing-instances { VR1 { instance-type virtual-router; " + text + " } }"
				}
				text = "routing-options { autonomous-system 65000; } " + text
				cfg, err := CheckText(text, -1)
				if tc.wantError != "" {
					if err == nil || !strings.Contains(err.Error(), tc.wantError) {
						t.Fatalf("want error containing %q, got %v", tc.wantError, err)
					}
					return
				}
				if err != nil {
					t.Fatalf("valid group rejected: %v", err)
				}
				var bgp *config.BGPConfig
				if instance {
					if len(cfg.RoutingInstances) != 1 {
						t.Fatalf("missing routing instance: %+v", cfg.RoutingInstances)
					}
					bgp = cfg.RoutingInstances[0].BGP
				} else {
					bgp = cfg.Protocols.BGP
				}
				if bgp == nil {
					t.Fatal("BGP was not compiled")
				}
				if tc.wantAS == 0 {
					if len(bgp.Neighbors) != 0 {
						t.Fatalf("empty group created neighbors: %+v", bgp.Neighbors)
					}
				} else if len(bgp.Neighbors) != 1 || bgp.Neighbors[0].PeerAS != tc.wantAS {
					t.Fatalf("want one neighbor with peer-as %d, got %+v", tc.wantAS, bgp.Neighbors)
				}
			})
		}
	}
}
