package api

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestRIMemberDeviceConflictGaugeTracksTolerantQuarantine11060(t *testing.T) {
	store := newDescriptorCoverageStore(t)
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("fixture has no active config")
	}
	server := &Server{store: store}
	for _, tc := range []struct {
		name string
		data []config.RoutingInstanceMemberDeviceConflict
		want float64
	}{
		{name: "healthy", want: 0},
		{
			name: "one quarantined device",
			data: []config.RoutingInstanceMemberDeviceConflict{{
				LinuxName: "ge-0-0-7.100",
				Claims: []config.RoutingInstanceMemberClaim{
					{Instance: "blue", Member: "ge-0/0/7.10"},
					{Instance: "red", Member: "ge-0-0-7.10"},
				},
			}},
			want: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg.QuarantinedRIMemberDeviceConflicts = tc.data
			got, ok := gatherSingleSample6802(t, server, "xpf_routing_instance_member_device_conflicts")
			if !ok {
				t.Fatal("xpf_routing_instance_member_device_conflicts was not emitted for an active config")
			}
			if got != tc.want {
				t.Fatalf("RI member device conflict gauge = %v, want %v", got, tc.want)
			}
		})
	}
}
