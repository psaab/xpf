package daemon

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #6811: the SEND-PATH half of the multi-family cross-fan.
//
// pkg/flowexport proves the resolver now partitions collectors into one group
// per (template, address family). That alone does not stop the cross-fan: the
// fan-out lives here, in flowExportCallback, which gates the INSTANCE once via
// ServesFamily and then sends the record to EVERY group of that instance.
// Delete the per-group gate and every resolver cell stays green while the bug
// is fully restored — so this cell exists to bind the gate, not the grouping.
//
// The existing #2462 isolation test looks like it covers this and does not: it
// uses two family-DISJOINT instances, where the instance-level ServesFamily gate
// is sufficient. The defect needs ONE instance holding BOTH families, which no
// test configured. That is precisely why it went unnoticed, and the strict
// validator explicitly permits the shape.

// oneInstanceBothFamiliesV9Config is the shape the defect needs: a single
// sampling instance with an inet flow-server AND an inet6 flow-server, each
// pointed at its own collector port so a cross-fan is directly observable.
func oneInstanceBothFamiliesV9Config(addr string, inetPort, inet6Port int) *config.Config {
	cfg := &config.Config{}
	cfg.ForwardingOptions.Sampling = &config.SamplingConfig{
		Instances: map[string]*config.SamplingInstance{
			"both": {
				Name:      "both",
				InputRate: 1,
				FamilyInet: &config.SamplingFamily{
					FlowServers: []*config.FlowServer{
						{Address: addr, Port: inetPort, Version: config.FlowServerVersion9},
					},
				},
				FamilyInet6: &config.SamplingFamily{
					FlowServers: []*config.FlowServer{
						{Address: addr, Port: inet6Port, Version: config.FlowServerVersion9},
					},
				},
			},
		},
	}
	cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{
		Version9: &config.NetFlowV9Config{
			Templates: map[string]*config.NetFlowV9Template{},
		},
	}
	return cfg
}

// groupStatsForFamily totals exported flows across the groups of one instance
// that serve the given address family. Keyed on GroupIsV6 rather than on the
// instance name, because this defect lives BETWEEN the groups of a single
// instance — an instance-keyed total (what the #2462 helper reports) sums both
// families and cannot see a cross-fan at all.
func groupStatsForFamily(b *exporterBundle, inst string, isV6 bool) uint64 {
	var total uint64
	for _, g := range b.groups {
		if g.ec.InstanceName == inst && g.ec.GroupIsV6 == isV6 {
			flows, _ := g.exp.Stats()
			total += flows
		}
	}
	return total
}

// TestSessionCloseSingleInstanceMultiFamilyDoesNotCrossFan_6811 is the
// fail-on-revert cell for the send path.
//
// One instance, both families, two collector ports. An IPv4 SESSION_CLOSE is fed
// through the REAL reconcile + callback path and must reach ONLY the inet group.
// The inet6 group must export nothing: an IPv6-only collector receiving IPv4
// records is the contamination R72 describes.
//
// FAIL-ON-REVERT: delete the `if b.groups[k].ec.GroupIsV6 != sd.IsIPv6 { continue }`
// gate in flowExportCallback and the inet6 count goes from 0 to >= 1.
func TestSessionCloseSingleInstanceMultiFamilyDoesNotCrossFan_6811(t *testing.T) {
	inetColl, inetPort := listenUDP(t)
	t.Cleanup(func() { inetColl.Close() })
	inet6Coll, inet6Port := listenUDP(t)
	t.Cleanup(func() { inet6Coll.Close() })

	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)

	if !d.reconcileFlowExporters(oneInstanceBothFamiliesV9Config("127.0.0.1", inetPort, inet6Port)) {
		t.Fatal("single-instance multi-family v9 reconcile must start exporters")
	}
	b := d.flowBundle.Load()
	if b == nil {
		t.Fatal("no v9 bundle")
	}
	if len(b.groups) != 2 {
		t.Fatalf("expected 2 groups for one instance with two families, got %d. One group "+
			"holding both families IS the cross-fan — every export to it reaches both "+
			"collectors (#6811)", len(b.groups))
	}

	// The instance-level flags must still report BOTH families: they gate the
	// single per-instance sampling decision, and narrowing them to the group
	// would change the 1-in-N denominator rather than fix the fan-out.
	for _, g := range b.groups {
		if !g.ec.ServesFamily(false) || !g.ec.ServesFamily(true) {
			t.Errorf("instance-level ServesFamily lost a family (v4=%v v6=%v); it must stay "+
				"instance-wide (#2462) while GroupIsV6 does the per-group gating (#6811)",
				g.ec.ServesFamily(false), g.ec.ServesFamily(true))
		}
	}

	// Feed an IPv4 SESSION_OPEN then its SESSION_CLOSE.
	payload := buildSessionCloseRawEventV4(
		6, // TCP
		[4]byte{10, 0, 1, 102}, [4]byte{172, 16, 80, 200},
		12345, 443,
		[4]byte{172, 16, 80, 8}, 40000,
		2, 3, // trust -> untrust
	)
	feedOpenThenClose15946(t, d, payload)

	// The inet group MUST export it — without this the cell passes against a
	// build that exports nothing at all, which is a silent loss of flow data
	// rather than a fix.
	deadline := time.Now().Add(2 * time.Second)
	var v4 uint64
	for time.Now().Before(deadline) {
		if v4 = groupStatsForFamily(b, "both", false); v4 >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if v4 < 1 {
		t.Fatalf("the inet group did not export the IPv4 SESSION_CLOSE (got %d flows); the "+
			"family partition must not drop the record it is supposed to route", v4)
	}

	// The inet6 group must NEVER receive it. Give the 100ms flush ticker margin
	// to (incorrectly) transmit before asserting zero — under the pre-#6811
	// fan-out it would have exported by now.
	time.Sleep(300 * time.Millisecond)
	if v6 := groupStatsForFamily(b, "both", true); v6 != 0 {
		t.Fatalf("the inet6 group exported %d IPv4 flows. A single instance carrying both "+
			"families cross-fanned each family's records to the other family's collectors: "+
			"IPv4 records reach IPv6-only collectors and vice versa, contaminating the "+
			"dataset and violating the configured export routing (#6811)", v6)
	}
}
