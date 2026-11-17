package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #19182: #17688's union pool applies to OPERATOR-configured RIP groups
// (group-less configs keep the ordered chain, which the #15158 cells pin).
// A bare `static` export that reaches the pool must still carry the #15158
// cluster deny-tag guard map, so the tagged Null0 cluster default is never
// redistributed to RIP neighbours. The non-cluster twin stays bare.
func TestRIPOperatorGroupBareStaticIsGuardedInCluster19182(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cluster bool
	}{{"cluster", true}, {"non-cluster", false}} {
		t.Run(tc.name, func(t *testing.T) {
			fc := &FullConfig{
				ClusterMode: tc.cluster,
				RIP: &config.RIPConfig{
					Interfaces:   []string{"ge-0/0/0.0"},
					Redistribute: []string{"static"},
					Groups:       []*config.RIPGroup{{Name: "core", Interfaces: []string{"ge-0/0/0.0"}, Export: []string{"static"}}},
				},
			}
			got := clusterNull0Section15158(t, fc)
			guarded := strings.Contains(got, " redistribute static route-map "+clusterNull0DenyRouteMap15158+"\n")
			bare := strings.Contains(got, " redistribute static\n")
			if tc.cluster && (!guarded || bare) {
				t.Errorf("operator RIP group's bare static must attach the cluster deny-tag map in cluster mode (guarded=%v bare=%v):\n%s", guarded, bare, got)
			}
			if !tc.cluster && (guarded || !bare) {
				t.Errorf("non-cluster operator RIP group's bare static must stay bare (guarded=%v bare=%v):\n%s", guarded, bare, got)
			}
		})
	}
}
