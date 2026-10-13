package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestQuarantinedGRECollisionAppliesOnlyValidTunnel12520 is the kernel half of
// the userspace snapshot cell: when clearing gr-0/0/0's undefined target lands
// it on gr-0/0/1's GRE outer, the tunnel manager is handed only the valid
// gr-0-0-1, in the default domain, so both planes agree on one owner.
func TestQuarantinedGRECollisionAppliesOnlyValidTunnel12520(t *testing.T) {
	cfg, err := config.CompileConfigLenient(tree12082(t, []string{
		"set system dataplane-type userspace",
		"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/0 tunnel routing-instance destination missing",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.0.0.1/30",
		"set interfaces gr-0/0/1 tunnel source 192.0.2.1",
		"set interfaces gr-0/0/1 tunnel destination 192.0.2.2",
		"set interfaces gr-0/0/1 unit 0 family inet address 10.0.1.1/30",
	}))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	applied := collectAppliedTunnels(cfg)
	if len(applied) != 1 || applied[0].Name != "gr-0-0-1" {
		t.Fatalf("applied tunnels = %+v, want only the valid gr-0-0-1", applied)
	}
	if applied[0].RoutingInstance != "" || applied[0].RIListMember != "" {
		t.Errorf("valid tunnel bind target = (%q, %q), want the default domain",
			applied[0].RoutingInstance, applied[0].RIListMember)
	}
}
