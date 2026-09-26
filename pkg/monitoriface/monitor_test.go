package monitoriface

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

var _ RuntimeDataPlane = (*fakeRuntimeDataPlane)(nil)

type fakeRuntimeDataPlane struct {
	loaded       bool
	counters     InterfaceCounters
	gotIfindex   int
	readCounters bool
}

func (f *fakeRuntimeDataPlane) IsLoaded() bool {
	return f.loaded
}

func (f *fakeRuntimeDataPlane) ReadInterfaceCounters(ifindex int) (InterfaceCounters, error) {
	f.gotIfindex = ifindex
	f.readCounters = true
	return f.counters, nil
}

func TestParseSummaryMode(t *testing.T) {
	cases := map[string]SummaryMode{
		"":         SummaryModeCombined,
		"combined": SummaryModeCombined,
		"all":      SummaryModeCombined,
		"packets":  SummaryModePackets,
		"bytes":    SummaryModeBytes,
		"delta":    SummaryModeDelta,
		"rate":     SummaryModeRate,
	}
	for input, want := range cases {
		got, ok := ParseSummaryMode(input)
		if !ok {
			t.Fatalf("ParseSummaryMode(%q) unexpectedly rejected", input)
		}
		if got != want {
			t.Fatalf("ParseSummaryMode(%q) = %v, want %v", input, got, want)
		}
	}
	if _, ok := ParseSummaryMode("bogus"); ok {
		t.Fatal("ParseSummaryMode accepted invalid mode")
	}
}

func TestReadSnapshotUsesRuntimeDataPlaneCounters(t *testing.T) {
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("loopback interface unavailable: %v", err)
	}
	dp := &fakeRuntimeDataPlane{
		loaded: true,
		counters: InterfaceCounters{
			RxPackets: 11,
			RxBytes:   22,
			TxPackets: 33,
			TxBytes:   44,
		},
	}

	snap, err := ReadSnapshot(dp, nil, "lo")
	if err != nil {
		t.Fatalf("ReadSnapshot: %v", err)
	}

	if !dp.readCounters {
		t.Fatal("ReadSnapshot did not read counters from RuntimeDataPlane")
	}
	if dp.gotIfindex != iface.Index {
		t.Fatalf("ReadInterfaceCounters ifindex = %d, want %d", dp.gotIfindex, iface.Index)
	}
	if snap.RxPkts != 11 || snap.RxBytes != 22 || snap.TxPkts != 33 || snap.TxBytes != 44 {
		t.Fatalf("ReadSnapshot counters = rxPkts=%d rxBytes=%d txPkts=%d txBytes=%d, want 11/22/33/44",
			snap.RxPkts, snap.RxBytes, snap.TxPkts, snap.TxBytes)
	}
}

func TestRenderTrafficSummaryCombinedIncludesTotals(t *testing.T) {
	now := time.Now()
	names := []string{"lan0", "wan0"}
	kernelNames := map[string]string{
		"lan0": "lan0",
		"wan0": "wan0",
	}
	snaps := map[string]*Snapshot{
		"lan0": {
			RxBytes:   2_000_000,
			TxBytes:   4_000_000,
			RxPkts:    2_000,
			TxPkts:    4_000,
			Timestamp: now,
		},
		"wan0": {
			RxBytes:   6_000_000,
			TxBytes:   8_000_000,
			RxPkts:    6_000,
			TxPkts:    8_000,
			Timestamp: now,
		},
	}
	prev := map[string]*Snapshot{
		"lan0": {
			RxBytes:   1_000_000,
			TxBytes:   2_000_000,
			RxPkts:    1_000,
			TxPkts:    2_000,
			Timestamp: now.Add(-1 * time.Second),
		},
		"wan0": {
			RxBytes:   3_000_000,
			TxBytes:   4_000_000,
			RxPkts:    3_000,
			TxPkts:    4_000,
			Timestamp: now.Add(-1 * time.Second),
		},
	}

	var buf bytes.Buffer
	RenderTrafficSummary(&buf, "xpf", names, kernelNames, snaps, prev, SummaryModeCombined, now.Add(-5*time.Second))
	out := buf.String()
	for _, needle := range []string{
		"mode: combined",
		"iface",
		"total:",
		"Rx",
		"Tx",
		"1.00 MB/s",
		"3.00 MB/s",
		"10.00 MB/s",
		"lan0",
		"wan0",
		"Keys: q=quit  c=combined",
	} {
		if !strings.Contains(out, needle) {
			t.Fatalf("combined summary missing %q\n%s", needle, out)
		}
	}
}

func TestDisplayTrafficCountersIncludeUserspaceXSKTraffic(t *testing.T) {
	snap := &Snapshot{
		RxBytes: 1000,
		TxBytes: 2000,
		RxPkts:  10,
		TxPkts:  20,
		Userspace: &UserspaceSnapshot{
			RxBytes:   3000,
			TxBytes:   4000,
			RxPackets: 30,
			TxPackets: 40,
		},
	}

	counters := displayTrafficCounters(snap)
	if counters.rxBytes != 4000 || counters.txBytes != 6000 || counters.rxPkts != 40 || counters.txPkts != 60 {
		t.Fatalf("displayTrafficCounters() = %+v, want rxBytes=4000 txBytes=6000 rxPkts=40 txPkts=60", counters)
	}
}

func TestSnapshotRatesMarksCounterReset(t *testing.T) {
	now := time.Now()
	rates := snapshotRates(&Snapshot{
		RxBytes:   100,
		TxBytes:   200,
		RxPkts:    10,
		TxPkts:    20,
		Timestamp: now,
	}, &Snapshot{
		RxBytes:   1_000,
		TxBytes:   2_000,
		RxPkts:    100,
		TxPkts:    200,
		Timestamp: now.Add(-1 * time.Second),
	})
	if rates.rxPps != 0 || rates.txPps != 0 || rates.rxBytesPerSec != 0 || rates.txBytesPerSec != 0 {
		t.Fatalf("snapshotRates() returned nonzero rates after reset: %+v", rates)
	}
	if !rates.rxPktsReset || !rates.txPktsReset || !rates.rxBytesReset || !rates.txBytesReset {
		t.Fatalf("snapshotRates() did not mark all reset counters invalid: %+v", rates)
	}
}

func TestSnapshotRatesIncludeUserspaceXSKTraffic(t *testing.T) {
	now := time.Now()
	rates := snapshotRates(&Snapshot{
		RxBytes:   1000,
		TxBytes:   2000,
		RxPkts:    10,
		TxPkts:    20,
		Timestamp: now,
		Userspace: &UserspaceSnapshot{
			RxBytes:   2000,
			TxBytes:   3000,
			RxPackets: 20,
			TxPackets: 30,
		},
	}, &Snapshot{
		RxBytes:   400,
		TxBytes:   500,
		RxPkts:    4,
		TxPkts:    5,
		Timestamp: now.Add(-1 * time.Second),
		Userspace: &UserspaceSnapshot{
			RxBytes:   600,
			TxBytes:   700,
			RxPackets: 6,
			TxPackets: 7,
		},
	})
	if rates.rxPps != 20 || rates.txPps != 38 || rates.rxBytesPerSec != 2000 || rates.txBytesPerSec != 3800 {
		t.Fatalf("snapshotRates() = %+v, want 20/38/2000/3800", rates)
	}
}

func TestSnapshotRatesPreserveInterfaceDeltaWhenUserspaceDisappears(t *testing.T) {
	now := time.Now()
	rates := snapshotRates(&Snapshot{
		RxBytes:   2000,
		TxBytes:   3000,
		RxPkts:    20,
		TxPkts:    30,
		Timestamp: now,
		Userspace: &UserspaceSnapshot{StatusNote: "userspace status unavailable"},
	}, &Snapshot{
		RxBytes:   1000,
		TxBytes:   1500,
		RxPkts:    10,
		TxPkts:    15,
		Timestamp: now.Add(-1 * time.Second),
		Userspace: &UserspaceSnapshot{
			TxBytes:   9000,
			TxPackets: 90,
			Bindings:  1,
		},
	})
	if rates.rxPps != 10 || rates.txPps != 15 || rates.rxBytesPerSec != 1000 || rates.txBytesPerSec != 1500 {
		t.Fatalf("snapshotRates() = %+v, want interface-only 10/15/1000/1500 when userspace disappears", rates)
	}
}

func TestRenderSingleInterfaceCounterResetMarksInvalidAndRebaselines(t *testing.T) {
	start := time.Now().Add(-2 * time.Second)
	baseline := &Snapshot{
		RxBytes: 1000, TxBytes: 2000, RxPkts: 100, TxPkts: 200, RxErrors: 7,
		Timestamp: start,
		Userspace: &UserspaceSnapshot{
			Bindings: 1, RxBytes: 3000, TxBytes: 4000, RxPackets: 300, TxPackets: 400,
			DirectTXPackets: 9,
		},
	}
	previous := *baseline
	previous.Userspace = &*baseline.Userspace
	current := &Snapshot{
		RxBytes: 10, TxBytes: 20, RxPkts: 1, TxPkts: 2, RxErrors: 1,
		Timestamp: start.Add(time.Second),
		Userspace: &UserspaceSnapshot{
			Bindings: 1, RxBytes: 30, TxBytes: 40, RxPackets: 3, TxPackets: 4,
			DirectTXPackets: 1,
		},
	}

	line := func(output, prefix string) string {
		for _, candidate := range strings.Split(output, "\n") {
			if strings.Contains(candidate, prefix) {
				return candidate
			}
		}
		return ""
	}
	var first bytes.Buffer
	RenderSingleInterface(&first, "host", "lo", "lo", current, &previous, baseline, start)
	for _, prefix := range []string{"Input  bytes:", "Input  packets:", "Input  errors:", "RX bytes:", "Direct TX packets:"} {
		if got := line(first.String(), prefix); !strings.Contains(got, "[n/a]") {
			t.Errorf("reset delta for %q = %q, want n/a", prefix, got)
		}
	}
	for _, prefix := range []string{"Input  bytes:", "Input  packets:", "RX bytes:"} {
		if got := line(first.String(), prefix); !strings.Contains(got, "(n/a)") {
			t.Errorf("reset rate for %q = %q, want n/a", prefix, got)
		}
	}
	if baseline.RxBytes != current.RxBytes || baseline.TxBytes != current.TxBytes ||
		baseline.RxPkts != current.RxPkts || baseline.TxPkts != current.TxPkts ||
		baseline.RxErrors != current.RxErrors || baseline.Userspace.RxBytes != current.Userspace.RxBytes ||
		baseline.Userspace.RxPackets != current.Userspace.RxPackets ||
		baseline.Userspace.DirectTXPackets != current.Userspace.DirectTXPackets {
		t.Fatalf("counter reset did not rebaseline: %+v", baseline)
	}

	next := &Snapshot{
		RxBytes: 17, TxBytes: 29, RxPkts: 5, TxPkts: 8, RxErrors: 3,
		Timestamp: current.Timestamp.Add(time.Second),
		Userspace: &UserspaceSnapshot{
			Bindings: 1, RxBytes: 35, TxBytes: 47, RxPackets: 7, TxPackets: 9,
			DirectTXPackets: 3,
		},
	}
	var second bytes.Buffer
	RenderSingleInterface(&second, "host", "lo", "lo", next, current, baseline, start)
	for prefix, want := range map[string]string{
		"Input  bytes:":      "(96 bps)    [12]",
		"Input  packets:":    "(8 pps)    [8]",
		"Input  errors:":     "[2]",
		"RX bytes:":          "(40 bps)    [5]",
		"Direct TX packets:": "[2]",
	} {
		if got := line(second.String(), prefix); !strings.Contains(got, want) {
			t.Errorf("rebased delta for %q = %q, want it to contain %q", prefix, got, want)
		}
	}
}

func TestRenderSingleInterfaceRebaselinesOnlyResetCounterSource(t *testing.T) {
	start := time.Now().Add(-time.Second)
	baseline := &Snapshot{
		RxBytes: 100, TxBytes: 200, RxPkts: 10, TxPkts: 20, Timestamp: start,
		Userspace: &UserspaceSnapshot{
			Bindings: 1, RxBytes: 1000, TxBytes: 2000, RxPackets: 100, TxPackets: 200,
		},
	}
	previous := *baseline
	previous.Userspace = &*baseline.Userspace
	current := &Snapshot{
		RxBytes: 110, TxBytes: 220, RxPkts: 11, TxPkts: 22, Timestamp: start.Add(time.Second),
		Userspace: &UserspaceSnapshot{
			Bindings: 1, RxBytes: 5, TxBytes: 2005, RxPackets: 5, TxPackets: 205,
		},
	}
	var buf bytes.Buffer
	RenderSingleInterface(&buf, "host", "lo", "lo", current, &previous, baseline, start)

	if baseline.RxBytes != 100 || baseline.RxPkts != 10 {
		t.Errorf("userspace reset rebaselined unchanged interface counters: rxBytes=%d rxPkts=%d", baseline.RxBytes, baseline.RxPkts)
	}
	if baseline.Userspace.RxBytes != current.Userspace.RxBytes ||
		baseline.Userspace.RxPackets != current.Userspace.RxPackets {
		t.Errorf("userspace reset was not rebaselined: %+v", baseline.Userspace)
	}
	if baseline.TxBytes != 200 || baseline.Userspace.TxBytes != 2000 {
		t.Errorf("unreset TX baselines changed: interface=%d userspace=%d", baseline.TxBytes, baseline.Userspace.TxBytes)
	}
}

func TestRenderTrafficSummaryCounterResetMarksRatesNA(t *testing.T) {
	now := time.Now()
	snaps := map[string]*Snapshot{
		"wan0": {RxBytes: 10, TxBytes: 20, RxPkts: 1, TxPkts: 2, Timestamp: now},
	}
	previous := map[string]*Snapshot{
		"wan0": {RxBytes: 100, TxBytes: 200, RxPkts: 10, TxPkts: 20, Timestamp: now.Add(-time.Second)},
	}
	var buf bytes.Buffer
	RenderTrafficSummary(&buf, "xpf", []string{"wan0"}, map[string]string{"wan0": "wan0"},
		snaps, previous, SummaryModeRate, now.Add(-time.Second))
	for _, prefix := range []string{"wan0:", "total:"} {
		var row string
		for _, candidate := range strings.Split(buf.String(), "\n") {
			if strings.Contains(candidate, prefix) {
				row = candidate
				break
			}
		}
		if got := strings.Count(row, "n/a"); got != 6 {
			t.Errorf("rate summary %q has %d n/a cells, want 6: %q", prefix, got, row)
		}
	}
}

func TestRenderTrafficSummaryCombinedIncludesUserspaceXSKTotals(t *testing.T) {
	now := time.Now()
	names := []string{"wan0"}
	kernelNames := map[string]string{"wan0": "wan0"}
	snaps := map[string]*Snapshot{
		"wan0": {
			RxBytes:   1_000_000,
			TxBytes:   2_000_000,
			RxPkts:    1_000,
			TxPkts:    2_000,
			Timestamp: now,
			Userspace: &UserspaceSnapshot{
				RxBytes:   4_000_000,
				TxBytes:   5_000_000,
				RxPackets: 4_000,
				TxPackets: 5_000,
			},
		},
	}
	prev := map[string]*Snapshot{
		"wan0": {
			RxBytes:   500_000,
			TxBytes:   1_000_000,
			RxPkts:    500,
			TxPkts:    1_000,
			Timestamp: now.Add(-1 * time.Second),
			Userspace: &UserspaceSnapshot{
				RxBytes:   2_000_000,
				TxBytes:   2_500_000,
				RxPackets: 2_000,
				TxPackets: 2_500,
			},
		},
	}

	var buf bytes.Buffer
	RenderTrafficSummary(&buf, "xpf", names, kernelNames, snaps, prev, SummaryModeCombined, now.Add(-5*time.Second))
	out := buf.String()
	for _, needle := range []string{
		"2.50 MB/s",
		"3.50 MB/s",
		"6.00 MB/s",
		"2.50K",
		"3.50K",
		"6.00K",
	} {
		if !strings.Contains(out, needle) {
			t.Fatalf("combined summary missing merged userspace traffic %q\n%s", needle, out)
		}
	}
}

func TestRenderTrafficSummaryCombinedShowsIngressAndEgressUserspaceRows(t *testing.T) {
	now := time.Now()
	names := []string{"reth0", "reth1"}
	kernelNames := map[string]string{
		"reth0": "ge-0-0-2",
		"reth1": "ge-0-0-1",
	}
	snaps := map[string]*Snapshot{
		"reth0": {
			Timestamp: now,
			Userspace: &UserspaceSnapshot{
				TxBytes:   8_000_000,
				TxPackets: 8_000,
			},
		},
		"reth1": {
			Timestamp: now,
			Userspace: &UserspaceSnapshot{
				RxBytes:   8_000_000,
				RxPackets: 8_000,
			},
		},
	}
	prev := map[string]*Snapshot{
		"reth0": {
			Timestamp: now.Add(-1 * time.Second),
			Userspace: &UserspaceSnapshot{
				TxBytes:   3_000_000,
				TxPackets: 3_000,
			},
		},
		"reth1": {
			Timestamp: now.Add(-1 * time.Second),
			Userspace: &UserspaceSnapshot{
				RxBytes:   3_000_000,
				RxPackets: 3_000,
			},
		},
	}

	var buf bytes.Buffer
	RenderTrafficSummary(&buf, "xpf", names, kernelNames, snaps, prev, SummaryModeCombined, now.Add(-5*time.Second))
	out := buf.String()
	for _, needle := range []string{
		"reth0:",
		"reth1:",
		"5.00 MB/s",
		"5.00K",
		"10.00 MB/s",
		"10.00K",
	} {
		if !strings.Contains(out, needle) {
			t.Fatalf("combined summary missing ingress/egress userspace row data %q\n%s", needle, out)
		}
	}
}

func TestBuildTrafficSummaryInterfacesPrefersFabAndRethAliases(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
				"ge-0/0/7": {Name: "ge-0/0/7"},
				"fab0":     {Name: "fab0", LocalFabricMember: "ge-0/0/7", FabricMembers: []string{"ge-0/0/7"}},
				"reth0":    {Name: "reth0", RedundancyGroup: 1},
			},
		},
	}

	names, kernelNames := buildTrafficSummaryInterfaces(cfg, []string{"ge-0-0-0", "ge-0-0-7", "fxp0"}, func(name string) string {
		return name
	})

	if len(names) != 3 {
		t.Fatalf("summary names = %v, want 3 entries", names)
	}
	if !contains(names, "fab0") {
		t.Fatalf("summary names %v missing fab0", names)
	}
	if !contains(names, "reth0") {
		t.Fatalf("summary names %v missing reth0", names)
	}
	if kernelNames["fab0"] != "ge-0-0-7" {
		t.Fatalf("fab0 kernel = %q, want ge-0-0-7", kernelNames["fab0"])
	}
	if kernelNames["reth0"] != "ge-0-0-0" {
		t.Fatalf("reth0 kernel = %q, want ge-0-0-0", kernelNames["reth0"])
	}
	if contains(names, "ge-0-0-0") || contains(names, "ge-0-0-7") {
		t.Fatalf("summary names %v should prefer config aliases over raw kernel names", names)
	}
}

func TestBuildTrafficSummaryInterfacesCollapsesFabricOverlayToOneRow(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"fab0": {Name: "fab0", LocalFabricMember: "ge-0/0/7", FabricMembers: []string{"ge-0/0/7"}},
			},
		},
	}

	names, kernelNames := buildTrafficSummaryInterfaces(cfg, []string{"fab0", "ge-0-0-7"}, func(name string) string {
		if name == "fab0" {
			return "ge-0-0-7"
		}
		return name
	})

	if len(names) != 1 {
		t.Fatalf("summary names = %v, want a single deduplicated row", names)
	}
	if names[0] != "fab0" {
		t.Fatalf("summary name = %q, want fab0", names[0])
	}
	if kernelNames["fab0"] != "ge-0-0-7" {
		t.Fatalf("fab0 kernel = %q, want ge-0-0-7", kernelNames["fab0"])
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
