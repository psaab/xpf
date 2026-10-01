package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func TestLifelineRIMemberFenceRendersCoMemberIngressDrop11364(t *testing.T) {
	lines := []string{
		"set interfaces ge-0/0/4 unit 0 family inet address 10.4.0.1/24",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.1.0.1/24",
		"set chassis cluster authentication-key xpf-test-cluster-authentication-key-1234567890",
		"set chassis cluster node 0",
		"set chassis cluster control-interface ge-0/0/4",
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue interface ge-0/0/4.0",
		"set routing-instances blue interface ge-0/0/1.0",
		"set security zones security-zone control interfaces ge-0/0/4.0",
		"set security zones security-zone control host-inbound-traffic system-services ssh",
		"set security zones security-zone trust interfaces ge-0/0/1.0",
		"set security zones security-zone trust host-inbound-traffic system-services ssh",
	}
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	views := dpuserspace.BuildZoneHostInboundViews(cfg)
	payload := buildHostInboundFilterPayload(views, nil, nil, nil, nil, true)

	for _, view := range views {
		if view.Zone != "trust" {
			continue
		}
		if !strings.Contains(strings.Join(view.IngressNetdevs, " "), "vrf-blue") {
			t.Fatalf("co-member has no matchable VRF master ingress scope: %+v", view)
		}
		for _, line := range strings.Split(payload, "\n") {
			if strings.Contains(line, "iifname") && strings.Contains(line, "vrf-blue") &&
				strings.Contains(line, "10.1.0.1") && strings.Contains(line, "drop") {
				return
			}
		}
		t.Fatalf("rendered input lacks the co-member's VRF-scoped ingress drop:\n%s", payload)
	}
	t.Fatalf("compiled co-member zone has no host-inbound view: %+v", views)
}
