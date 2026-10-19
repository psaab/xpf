package daemon

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/snmp"
)

// #15232 A48-02: deriveIfCounters must carry kernel error/discard and
// Counter32 unicast/non-unicast counters.
func TestDeriveIfCountersErrorsDiscardsUcast15232(t *testing.T) {
	stats := &netlink.LinkStatistics{
		RxPackets: 1250000, TxPackets: 4000000,
		RxBytes: 9000000000, TxBytes: 8000000000,
		Multicast: 250000,
		RxErrors:  11, TxErrors: 22, RxDropped: 33, TxDropped: 44,
	}
	var entry snmp.IfData
	deriveIfCounters(&entry, stats)
	if entry.InErrors != 11 || entry.OutErrors != 22 {
		t.Errorf("errors in/out = %d/%d, want 11/22", entry.InErrors, entry.OutErrors)
	}
	if entry.InDiscards != 33 || entry.OutDiscards != 44 {
		t.Errorf("discards in/out = %d/%d, want 33/44", entry.InDiscards, entry.OutDiscards)
	}
	if entry.InUcastPkts != 1000000 {
		t.Errorf("InUcastPkts=%d want 1000000", entry.InUcastPkts)
	}
	if entry.InNonUcastPkts != 250000 {
		t.Errorf("InNonUcastPkts=%d want 250000", entry.InNonUcastPkts)
	}
	if entry.OutUcastPkts != 4000000 {
		t.Errorf("OutUcastPkts=%d want 4000000", entry.OutUcastPkts)
	}
	if entry.OutNonUcastPkts != 0 {
		t.Errorf("OutNonUcastPkts=%d want 0 (kernel exposes no TX breakdown)", entry.OutNonUcastPkts)
	}
}

// #15232 A48-02: ifLastChange tracks oper transitions in TimeTicks
// (hundredths since agent start); 0 while never changed.
func TestIfLastChangeTracksOperTransition15232(t *testing.T) {
	prevLister, prevSpeed := snmpLinkLister, snmpLinkSpeedReader
	t.Cleanup(func() { snmpLinkLister, snmpLinkSpeedReader = prevLister, prevSpeed })
	snmpLinkSpeedReader = func([]netlink.Link) map[int]uint32 { return nil }
	up := true
	snmpLinkLister = func() ([]netlink.Link, error) {
		var st netlink.LinkOperState = netlink.OperDown
		if up {
			st = netlink.OperUp
		}
		return []netlink.Link{&testLink{attrs: netlink.LinkAttrs{
			Index: 42, Name: "lc15232", Flags: net.FlagUp, OperState: st,
		}}}, nil
	}
	resetSNMPLastChangeForTest()
	first := buildSNMPIfDataForTest()
	if len(first) != 1 || first[0].LastChange != 0 {
		t.Fatalf("first poll LastChange=%v, want one row with 0", first)
	}
	// No transition: still 0.
	second := buildSNMPIfDataForTest()
	if second[0].LastChange != 0 {
		t.Fatalf("no-transition LastChange=%d, want 0", second[0].LastChange)
	}
	up = false
	third := buildSNMPIfDataForTest()
	if third[0].LastChange == 0 {
		t.Fatalf("after up->down transition LastChange=0, want >0 TimeTicks")
	}
	lc := third[0].LastChange
	// Stable while state unchanged (value may only stay / not regress to 0).
	fourth := buildSNMPIfDataForTest()
	if fourth[0].LastChange != lc {
		t.Fatalf("LastChange changed without transition: %d -> %d", lc, fourth[0].LastChange)
	}
}

// #15232 A48-03: trap-group-only config must be SNMP-enabled so the
// agent + link monitor start and a link transition enqueues a trap.
func TestTrapGroupOnlySNMPEnabled15232(t *testing.T) {
	cfg := &config.Config{System: config.SystemConfig{SNMP: &config.SNMPConfig{
		TrapGroups: map[string]*config.SNMPTrapGroup{
			"managers": {Name: "managers", Targets: []string{"192.0.2.1"}, Version: "v2"},
		},
	}}}
	if !snmpEnabled(cfg) {
		t.Fatal("trap-group-only config: snmpEnabled=false, want true (traps silently never sent pre-fix)")
	}
	// Controls: empty stanza and nil stay disabled.
	if snmpEnabled(&config.Config{System: config.SystemConfig{SNMP: &config.SNMPConfig{}}}) {
		t.Fatal("empty SNMP stanza must stay disabled")
	}
	if snmpEnabled(&config.Config{}) {
		t.Fatal("no SNMP stanza must stay disabled")
	}
}

func TestTrapGroupOnlyStartsAgentAndMonitor15232(t *testing.T) {
	rec := &snmpServeRecorder{}
	d := newSNMPReconcileDaemon(t, rec.serve)
	cfg := &config.Config{System: config.SystemConfig{SNMP: &config.SNMPConfig{
		TrapGroups: map[string]*config.SNMPTrapGroup{
			"managers": {Name: "managers", Targets: []string{"192.0.2.1"}, Version: "v2"},
		},
	}}}
	if err := d.applyConfigLocked(context.Background(), cfg); err != nil {
		t.Fatalf("apply trap-only: %v", err)
	}
	if d.snmpAgent == nil {
		t.Fatal("trap-group-only apply did not start SNMP agent")
	}
	if !d.snmpMonitorRunning {
		t.Fatal("trap-group-only apply did not start link-state trap monitor")
	}
	// Simulated link transition enqueues one trap via the monitor path.
	before, _, _ := d.snmpAgent.TrapStats()
	d.emitLinkStateTrap(99, "ge-0-0-9", true)
	after, _, _ := d.snmpAgent.TrapStats()
	if after <= before {
		t.Fatalf("link transition enqueued no trap: before=%d after=%d", before, after)
	}
}

// #15232 A48-04: bondless reth gets a synthetic ifTable row with a
// stable synthetic ifIndex, owning-member counters, and
// oper = RG-primary && member-up.
func rethConfig15232() *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
			"ge-7/0/0": {Name: "ge-7/0/0", RedundantParent: "reth0"},
			"reth0":    {Name: "reth0", RedundancyGroup: 1},
		}},
		Chassis: config.ChassisConfig{Cluster: &config.ClusterConfig{
			NodeID: 0, RethCount: 1,
			RedundancyGroups: []*config.RedundancyGroup{{ID: 1}},
		}},
	}
}

func TestBuildSNMPIfDataSynthesizesRethRow15232(t *testing.T) {
	prevLister, prevSpeed := snmpLinkLister, snmpLinkSpeedReader
	prevSrc := snmpRethSource
	t.Cleanup(func() {
		snmpLinkLister, snmpLinkSpeedReader, snmpRethSource = prevLister, prevSpeed, prevSrc
	})
	snmpLinkSpeedReader = func([]netlink.Link) map[int]uint32 { return map[int]uint32{5: 1000} }
	snmpLinkLister = func() ([]netlink.Link, error) {
		return []netlink.Link{&testLink{attrs: netlink.LinkAttrs{
			Index: 5, Name: "ge-0-0-0", MTU: 1500, Flags: net.FlagUp, OperState: netlink.OperUp,
			Statistics: &netlink.LinkStatistics{RxBytes: 1000, TxBytes: 2000, RxPackets: 10, TxPackets: 20},
		}}}, nil
	}
	resetSNMPLastChangeForTest()
	// Primary for RG1, member up => reth oper up, counters = member's.
	snmpRethSource = func() ([]snmpRethInfo, []snmp.IfData) {
		rows := buildSNMPKernelIfData()
		return []snmpRethInfo{{Name: "reth0", RedundancyGroup: 1, MemberName: "ge-0-0-0", Primary: true}}, rows
	}
	got := buildSNMPIfData()
	var reth *snmp.IfData
	for i := range got {
		if got[i].IfDescr == "reth0" {
			reth = &got[i]
		}
		if got[i].IfIndex >= snmpRethIndexBase && got[i].IfDescr != "reth0" {
			t.Errorf("synthetic index leaked to non-reth row: %+v", got[i])
		}
	}
	if reth == nil {
		t.Fatalf("no reth0 row in %v", got)
	}
	if reth.IfIndex != snmpRethIndexBase {
		t.Errorf("reth0 IfIndex=%d, want stable synthetic %d", reth.IfIndex, snmpRethIndexBase)
	}
	if reth.HCInOctets != 1000 || reth.HCOutOctets != 2000 {
		t.Errorf("reth counters = %d/%d, want member 1000/2000", reth.HCInOctets, reth.HCOutOctets)
	}
	if reth.OperStatus != 1 {
		t.Errorf("reth OperStatus=%d, want 1 (RG primary && member up)", reth.OperStatus)
	}
	// Stable index across polls.
	got2 := buildSNMPIfData()
	for i := range got2 {
		if got2[i].IfDescr == "reth0" && got2[i].IfIndex != reth.IfIndex {
			t.Errorf("reth index unstable: %d -> %d", reth.IfIndex, got2[i].IfIndex)
		}
	}
	// Secondary => oper down even though member up.
	snmpRethSource = func() ([]snmpRethInfo, []snmp.IfData) {
		rows := buildSNMPKernelIfData()
		return []snmpRethInfo{{Name: "reth0", RedundancyGroup: 1, MemberName: "ge-0-0-0", Primary: false}}, rows
	}
	got3 := buildSNMPIfData()
	found := false
	for i := range got3 {
		if got3[i].IfDescr == "reth0" {
			found = true
			if got3[i].OperStatus != 2 {
				t.Errorf("secondary reth OperStatus=%d, want 2", got3[i].OperStatus)
			}
		}
	}
	if !found {
		t.Fatal("reth row vanished on secondary (must stay, oper down)")
	}
}

// Production path: daemonSNMPRethInfos + buildSNMPIfData resolve the
// committed config and cluster primary state end to end.
func TestDaemonSNMPRethInfosProduction15232(t *testing.T) {
	prevLister, prevSpeed := snmpLinkLister, snmpLinkSpeedReader
	prevSrc := snmpRethSource
	t.Cleanup(func() {
		snmpLinkLister, snmpLinkSpeedReader = prevLister, prevSpeed
		snmpRethSourceMu.Lock()
		snmpRethSource = prevSrc
		snmpRethSourceMu.Unlock()
	})
	snmpLinkSpeedReader = func([]netlink.Link) map[int]uint32 { return nil }
	snmpLinkLister = func() ([]netlink.Link, error) {
		return []netlink.Link{&testLink{attrs: netlink.LinkAttrs{
			Index: 5, Name: "ge-0-0-0", MTU: 1500, Flags: net.FlagUp, OperState: netlink.OperUp,
			Statistics: &netlink.LinkStatistics{RxBytes: 7000, TxBytes: 8000},
		}}}, nil
	}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	sets := "set chassis cluster cluster-id 1\n" +
		"set chassis cluster authentication-key test-cluster-psk-15232\n" +
		"set chassis cluster reth-count 1\n" +
		"set chassis cluster redundancy-group 1 node 0 priority 200\n" +
		"set chassis cluster redundancy-group 1 node 1 priority 100\n" +
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth0\n" +
		"set interfaces reth0 redundant-ether-options redundancy-group 1\n"
	if _, err := store.LoadSet(sets); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(store.ActiveConfig().Chassis.Cluster)
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	d := &Daemon{store: store, cluster: cm}
	infos := d.daemonSNMPRethInfos()
	if len(infos) != 1 || infos[0].Name != "reth0" || infos[0].MemberName != "ge-0-0-0" || !infos[0].Primary {
		t.Fatalf("infos=%+v, want one primary reth0 -> ge-0-0-0", infos)
	}
	snmpRethSourceMu.Lock()
	snmpRethSource = func() ([]snmpRethInfo, []snmp.IfData) { return d.daemonSNMPRethInfos(), nil }
	snmpRethSourceMu.Unlock()
	resetSNMPLastChangeForTest()
	got := buildSNMPIfData()
	found := false
	for i := range got {
		if got[i].IfDescr == "reth0" {
			found = true
			if got[i].HCInOctets != 7000 || got[i].OperStatus != 1 {
				t.Errorf("production reth row = %+v, want member counters + oper up", got[i])
			}
		}
	}
	if !found {
		t.Fatalf("production buildSNMPIfData has no reth0 row: %v", got)
	}
	cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	got = buildSNMPIfData()
	for i := range got {
		if got[i].IfDescr == "reth0" && got[i].OperStatus != 2 {
			t.Errorf("secondary production reth oper=%d, want 2", got[i].OperStatus)
		}
	}
}
