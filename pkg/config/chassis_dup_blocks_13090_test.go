package config

import (
	"strings"
	"testing"
)

// #13090 (source finding D7-14): the chassis readers fetched sibling blocks
// with a singular FindChild, so a SECOND `cluster` or `device-map` block was
// silently dropped at compile, and compileRGIPMonitoring overwrote
// rg.IPMonitoring wholesale — wiping GlobalWeight/GlobalThreshold/Targets
// recorded from an earlier block of the SAME redundancy-group (#6543 folds
// every instance body into one record, so the second `redundancy-group 1`
// block replays through the same statement table). These regressions fail on
// the pre-#13090 compiler: the second block's statements vanish and IP
// monitoring runs with GlobalWeight 0 — failover fail-open.

func findRG13090(t *testing.T, cfg *Config, id int) *RedundancyGroup {
	t.Helper()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		t.Fatal("chassis cluster did not compile")
	}
	var found []*RedundancyGroup
	for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
		if rg != nil && rg.ID == id {
			found = append(found, rg)
		}
	}
	if len(found) != 1 {
		t.Fatalf("redundancy-group %d compiled %d records, want exactly 1 (#6543 canonical-id fold)",
			id, len(found))
	}
	return found[0]
}

// TestRGIPMonitoringAccumulatesAcrossFoldedBlocks_13090: the #6543 fold
// replays both `redundancy-group 1` bodies into one record; the second
// block's lone `family inet` target must not wipe the first block's
// global-weight/global-threshold/target.
func TestRGIPMonitoringAccumulatesAcrossFoldedBlocks_13090(t *testing.T) {
	tree := hierTree(t, `chassis {
	cluster {
		cluster-id 1;
		node 0;
		authentication-key aaaaaaaaaaaaaaaa;
		redundancy-group 1 {
			ip-monitoring {
				global-weight 255;
				global-threshold 200;
				family inet { 10.0.1.1 weight 100; }
			}
		}
		redundancy-group 1 {
			ip-monitoring {
				family inet { 10.0.1.2 weight 90; }
			}
		}
	}
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile rejected a folded redundancy-group: %v", err)
	}
	rg := findRG13090(t, cfg, 1)
	ipm := rg.IPMonitoring
	if ipm == nil {
		t.Fatal("ip-monitoring lost entirely across the folded blocks")
	}
	if ipm.GlobalWeight != 255 {
		t.Errorf("GlobalWeight = %d, want 255 (second block wiped the first)", ipm.GlobalWeight)
	}
	if ipm.GlobalThreshold != 200 {
		t.Errorf("GlobalThreshold = %d, want 200 (second block wiped the first)", ipm.GlobalThreshold)
	}
	want := map[string]int{"10.0.1.1": 100, "10.0.1.2": 90}
	if len(ipm.Targets) != len(want) {
		t.Fatalf("targets = %v, want one per family entry %v", ipm.Targets, want)
	}
	for _, tg := range ipm.Targets {
		if w, ok := want[tg.Address]; !ok || tg.Weight != w {
			t.Errorf("target %+v, want address %q weight %d", tg, tg.Address, w)
		}
	}
}

// TestRGIPMonitoringTwoStatementsAccumulate_13090: the same accumulation
// contract inside ONE redundancy-group body carrying two `ip-monitoring`
// statements.
func TestRGIPMonitoringTwoStatementsAccumulate_13090(t *testing.T) {
	tree := hierTree(t, `chassis {
	cluster {
		cluster-id 1;
		authentication-key aaaaaaaaaaaaaaaa;
		node 0;
		redundancy-group 1 {
			ip-monitoring {
				global-weight 255;
				global-threshold 200;
				family inet { 10.0.1.1 weight 100; }
			}
			ip-monitoring {
				family inet { 10.0.1.2 weight 90; }
			}
		}
	}
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile rejected the two-statement body: %v", err)
	}
	ipm := findRG13090(t, cfg, 1).IPMonitoring
	if ipm == nil || ipm.GlobalWeight != 255 || ipm.GlobalThreshold != 200 ||
		len(ipm.Targets) != 2 || ipm.Targets[1].Address != "10.0.1.2" || ipm.Targets[1].Weight != 90 {
		t.Fatalf("second ip-monitoring statement did not accumulate: %+v", ipm)
	}
}

// TestChassisSecondClusterBlockSurvives_13090: a second `cluster` block's
// heartbeat-interval and redundancy-group definitions must compile, not be
// dropped by the singular FindChild in normalizedClusterNode.
func TestChassisSecondClusterBlockSurvives_13090(t *testing.T) {
	tree := hierTree(t, `chassis {
	cluster {
		cluster-id 1;
		node 0;
		authentication-key aaaaaaaaaaaaaaaa;
		reth-count 2;
	}
	cluster {
		heartbeat-interval 500;
		heartbeat-threshold 3;
		redundancy-group 1 { node 0 priority 200; }
	}
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile rejected the two-block cluster: %v", err)
	}
	cl := cfg.Chassis.Cluster
	if cl == nil {
		t.Fatal("chassis cluster did not compile")
	}
	if cl.RethCount != 2 {
		t.Errorf("RethCount = %d, want 2 (first block lost)", cl.RethCount)
	}
	if cl.HeartbeatInterval != 500 {
		t.Errorf("HeartbeatInterval = %d, want 500 (second block dropped)", cl.HeartbeatInterval)
	}
	if cl.HeartbeatThreshold != 3 {
		t.Errorf("HeartbeatThreshold = %d, want 3 (second block dropped)", cl.HeartbeatThreshold)
	}
	if got := findRG13090(t, cfg, 1).NodePriorities[0]; got != 200 {
		t.Errorf("second block's redundancy-group 1 node 0 priority = %d, want 200", got)
	}
}

// TestChassisSecondClusterBlockPackedSurvives_13090: the fold must also cover
// a second block in a PACKED spelling (`cluster reth-count 2;` on one line),
// and the schema-walker pre-pass (chassisClusterIsPacked) must agree with the
// compiler that the chassis node needs normalization when a LATER block is
// the packed one.
func TestChassisSecondClusterBlockPackedSurvives_13090(t *testing.T) {
	tree := hierTree(t, `chassis {
	cluster {
		cluster-id 1;
		authentication-key aaaaaaaaaaaaaaaa;
	}
	cluster reth-count 2;
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile rejected the mixed two-block cluster: %v", err)
	}
	cl := cfg.Chassis.Cluster
	if cl == nil {
		t.Fatal("chassis cluster did not compile")
	}
	if cl.RethCount != 2 {
		t.Errorf("RethCount = %d, want 2 (packed second block dropped)", cl.RethCount)
	}
}

// TestChassisSecondDeviceMapBlockSurvives_13090: entries — and the
// unmapped-interface-policy — authored in a second `device-map` block must
// compile rather than vanish behind the singular FindChild in compileChassis.
func TestChassisSecondDeviceMapBlockSurvives_13090(t *testing.T) {
	tree := hierTree(t, `chassis {
	device-map {
		interface ge-0/0/3 { pci 0000:09:00.0; }
	}
	device-map {
		unmapped-interface-policy manage-down;
		interface ge-0/0/4 { pci 0000:0a:00.0; }
	}
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile rejected the two-block device-map: %v", err)
	}
	dm := cfg.Chassis.DeviceMap
	if dm == nil {
		t.Fatal("device-map did not compile")
	}
	if dm.UnmappedPolicy != "manage-down" {
		t.Errorf("UnmappedPolicy = %q, want manage-down (second block dropped)", dm.UnmappedPolicy)
	}
	got := map[string]string{}
	for _, e := range dm.Entries {
		got[e.LogicalName] = e.PCIAddr
	}
	if len(got) != 2 || got["ge-0/0/3"] != "0000:09:00.0" || got["ge-0/0/4"] != "0000:0a:00.0" {
		t.Errorf("entries = %v, want both blocks' interfaces (ge-0/0/3 and ge-0/0/4)", got)
	}
}

// TestChassisDeviceMapCrossBlockDuplicateNameFatal_13090: merging the blocks
// must stay fail-closed — one interface mapped twice across sibling blocks
// is the same nondeterministic-binding hazard as within one block (#6546),
// so the strict gate must keep rejecting it.
func TestChassisDeviceMapCrossBlockDuplicateNameFatal_13090(t *testing.T) {
	tree := hierTree(t, `chassis {
	device-map {
		interface ge-0/0/3 { pci 0000:09:00.0; }
	}
	device-map {
		interface ge-0/0/3 { pci 0000:0a:00.0; }
	}
}`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("duplicate logical name across sibling device-map blocks must stay fatal")
	}
	if !strings.Contains(err.Error(), "mapped twice") {
		t.Errorf("error %q does not keep the mapped-twice wording", err.Error())
	}
}

// TestLenientDropsUnsafeDeviceMapEntryInSecondBlock_13090: the #9886
// render-safe prune gate must cover EVERY device-map block — pruning only the
// first would leave a poisoned logical name from the second block in the AST
// for the .link writer (fail-open).
func TestLenientDropsUnsafeDeviceMapEntryInSecondBlock_13090(t *testing.T) {
	tree := hierTree(t, `chassis {
	device-map {
		interface ge-0-0-1 { pci 0000:09:00.1; }
	}
	device-map {
		interface "ge 0" { pci 0000:09:00.0; }
	}
}`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must drop the poisoned entry, not fail: %v", err)
	}
	dm := cfg.Chassis.DeviceMap
	if dm == nil {
		t.Fatal("device-map did not compile")
	}
	for _, e := range dm.Entries {
		if e.LogicalName == "ge 0" {
			t.Fatal(`"ge 0" from the second block survived the #9886 prune (fail-open)`)
		}
	}
	found := false
	for _, e := range dm.Entries {
		if e.LogicalName == "ge-0-0-1" {
			found = true
		}
	}
	if !found {
		t.Fatal("the clean first-block entry must survive the prune")
	}
	all := warningsJoin9886(cfg.Warnings)
	for _, want := range []string{"DROPPED", "#9886"} {
		if !strings.Contains(all, want) {
			t.Errorf("drop warning must mention %q, got warnings:\n%s", want, all)
		}
	}
}
