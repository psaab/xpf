package routing

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #6549: InterfaceMonitorStatus.Weight must carry the EFFECTIVE monitor weight,
// bounded to the [0,255] heartbeat weight domain — not the raw configured one.
//
// #17132: these statuses are DISPLAY ONLY (they were election debt via the
// daemon apply tail before #17132 removed that feed). They are what
// `show chassis cluster interfaces` renders for a live monitor, so a raw
// out-of-range value is an observability lie: the display would claim a
// monitor contributes -100 while the election (pkg/cluster, the only
// producer) contributes the clamped 0.
//
// An out-of-range weight is rejected at commit but survives the TOLERANT paths
// (Store.Load of a persisted config, Store.SyncApply of a peer-pushed one),
// where compileTreeLenient downgrades the gate to a warning so a node never
// bricks (#1960).
//
// Fail-on-revert: restore `Weight: mon.Weight` in monitorManager.Apply and
// every out-of-range row reports the raw value.
func TestInterfaceMonitorStatus_WeightIsBounded_6549(t *testing.T) {
	tests := []struct {
		name       string
		configured int
		want       int
	}{
		// Over-reach guard: legal weights must be reported verbatim.
		{"legal-zero", 0, 0},
		{"legal-one", 1, 1},
		{"legal-half", 128, 128},
		{"legal-max", 255, 255},
		// Out-of-range: bounded into the domain.
		{"negative-small", -1, 0},
		{"negative-large", -100, 0},
		{"over-max", 256, 255},
		{"over-max-large", 100000, 255},
	}

	const ifName = "ge-0/0/0"
	linuxName := config.LinuxIfName(ifName)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, up := range []bool{true, false} {
				var oper netlink.LinkOperState = netlink.OperDown
				if up {
					oper = netlink.OperUp
				}
				mm := &monitorManager{
					ops: &monitorFakeOps{links: map[string]netlink.Link{
						linuxName: &monitorFakeLink{attrs: netlink.LinkAttrs{
							Name:      linuxName,
							OperState: oper,
							Flags:     net.FlagUp,
						}},
					}},
					monitorStatus: make(map[int][]InterfaceMonitorStatus),
				}

				mm.Apply([]*config.RedundancyGroup{{
					ID: 0,
					InterfaceMonitors: []*config.InterfaceMonitor{
						{Interface: ifName, Weight: tt.configured},
					},
				}})

				statuses := mm.Statuses()[0]
				if len(statuses) != 1 {
					t.Fatalf("up=%v: expected 1 status, got %d", up, len(statuses))
				}
				if statuses[0].Weight != tt.want {
					t.Errorf("up=%v: configured weight %d reported as %d, want the "+
						"effective %d", up, tt.configured, statuses[0].Weight, tt.want)
				}
			}
		})
	}
}
