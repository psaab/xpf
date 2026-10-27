package daemon

import (
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/flowexport"
)

// #17057 acceptance: an IPFIX-only config and a v9-only config driven
// through the same open→close sequence must show identical tracker and
// export behaviour via the single parameterized flowFamily path.
// Hermetic (class U): loopback UDP collectors, no kernel/netns access.

func TestFlowFamilyParitySingleProtocolConfigs17057(t *testing.T) {
	_ = flowSamplingConfig
	_ = ipfixOnlySamplingConfig
	cases := []struct {
		name string
		cfg  func(t *testing.T, v9Port, ipfixPort int) *config.Config
		fam  func(*Daemon) *flowFamily
		peer func(*Daemon) *flowFamily
	}{
		{"v9-only", func(t *testing.T, v9Port, _ int) *config.Config {
			cfg := openSamplingConfig16303(t, v9Port, v9Port, "1")
			cfg.Services.FlowMonitoring.VersionIPFIX = nil
			// Drop the IPFIX flow-server so only v9 groups resolve.
			for _, inst := range cfg.ForwardingOptions.Sampling.Instances {
				for _, fam := range []*config.SamplingFamily{inst.FamilyInet, inst.FamilyInet6} {
					if fam == nil {
						continue
					}
					kept := fam.FlowServers[:0]
					for _, srv := range fam.FlowServers {
						if srv.Version == config.FlowServerVersion9 {
							kept = append(kept, srv)
						}
					}
					fam.FlowServers = kept
				}
			}
			return cfg
		}, (*Daemon).v9Family, (*Daemon).ipfixFamily},
		{"ipfix-only", func(t *testing.T, _, ipfixPort int) *config.Config {
			cfg := openSamplingConfig16303(t, ipfixPort, ipfixPort, "1")
			cfg.Services.FlowMonitoring.Version9 = nil
			for _, inst := range cfg.ForwardingOptions.Sampling.Instances {
				for _, fam := range []*config.SamplingFamily{inst.FamilyInet, inst.FamilyInet6} {
					if fam == nil {
						continue
					}
					kept := fam.FlowServers[:0]
					for _, srv := range fam.FlowServers {
						if srv.Version == config.FlowServerVersionIPFIX {
							kept = append(kept, srv)
						}
					}
					fam.FlowServers = kept
				}
			}
			return cfg
		}, (*Daemon).ipfixFamily, (*Daemon).v9Family},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			coll, port := listenUDP(t)
			t.Cleanup(func() { coll.Close() })
			d := newFlowTestDaemon()
			t.Cleanup(d.stopFlowExporter)
			t.Cleanup(d.stopIPFIXExporter)
			d.eventReader.SetIfNames(map[uint32]string{11: "ge-0/0/0.0", 12: "ge-0/0/2.0"})
			if !d.reconcileFlowExporters(tc.cfg(t, port, port)) {
				t.Fatal("single-protocol config must reconcile")
			}
			ff := tc.fam(d)
			if b := ff.bundle.Load(); b == nil || b.firstExp() == nil {
				t.Fatalf("%s: configured family must be live", tc.name)
			}
			if b := tc.peer(d).bundle.Load(); b != nil && b.firstExp() != nil {
				t.Fatalf("%s: peer family must stay unpublished", tc.name)
			}
			if n := d.eventReader.CallbackCount(); n != 2 {
				t.Fatalf("%s: callbacks = %d, want 2 (open fanout + one close)", tc.name, n)
			}
			trust, untrust := config.StableZoneID("trust"), config.StableZoneID("untrust")
			if !d.eventReader.ProcessRawEvent(openRaw16303(23457, 11, 12, uint16(trust), uint16(untrust))) {
				t.Fatal("open rejected")
			}
			key := flowexport.FlowKey{SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 23457, DstPort: 443, Protocol: 6}
			if !ff.bundle.Load().firstExp().Tracked(key) {
				t.Fatalf("%s: sampled open must be tracked", tc.name)
			}
			if !d.eventReader.ProcessRawEvent(closeRaw16742(23457, trust, untrust)) {
				t.Fatal("close rejected")
			}
			if got := waitFlows(t, ff.bundle.Load().firstExp().Stats); got != 1 {
				t.Fatalf("%s: exported flows = %d, want 1", tc.name, got)
			}
			if ff.bundle.Load().firstExp().Tracked(key) {
				t.Fatalf("%s: close must forget the tracked flow", tc.name)
			}
			// Sampling stats: exactly one row for this family, evaluated once.
			stats := d.FlowExportSamplingStats()
			if len(stats) != 1 || stats[0].Protocol != ff.name {
				t.Fatalf("%s: sampling stats = %+v, want one %s row", tc.name, stats, ff.name)
			}
		})
	}
}

// TestFlowFamiliesAreSingleParameterizedPath17057 pins the consolidation
// invariant: exactly two families with the expected names, and the
// exported error accessors read the matching family.
func TestFlowFamiliesAreSingleParameterizedPath17057(t *testing.T) {
	d := newFlowTestDaemon()
	fams := d.flowFamiliesOrNil()
	if len(fams) != 2 || fams[0].name != "netflow-v9" || fams[1].name != "ipfix" {
		t.Fatalf("families = %v, want [netflow-v9 ipfix]", fams)
	}
	if d.FlowExportError() != nil || d.IPFIXExportError() != nil {
		t.Fatal("fresh daemon must report no build errors")
	}
	if v9, ipfix := d.FlowExportHandoffDropped(); v9 != 0 || ipfix != 0 {
		t.Fatalf("handoff dropped = %d/%d, want 0/0", v9, ipfix)
	}
}

// TestFlowFamiliesConcurrentFirstUse17057 proves the Once-guarded lazy
// init (Rev18098 fold): concurrent first use of a bare &Daemon{} — as a
// metrics scrape racing a boot reconcile/stop would — must observe the
// same two family pointers, never a torn or double-allocated pair.
// Run with -race; the census below also fails on divergent identities.
func TestFlowFamiliesConcurrentFirstUse17057(t *testing.T) {
	d := &Daemon{}
	const racers = 16
	results := make([][]*flowFamily, racers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i] = d.flowFamiliesOrNil()
			_ = d.v9Family()
			_ = d.ipfixFamily()
			_, _ = d.FlowExportHandoffDropped()
		}()
	}
	close(start)
	wg.Wait()
	for i, fams := range results {
		if len(fams) != 2 || fams[0].name != "netflow-v9" || fams[1].name != "ipfix" {
			t.Fatalf("racer %d families = %v, want [netflow-v9 ipfix]", i, fams)
		}
		if fams[0] != results[0][0] || fams[1] != results[0][1] {
			t.Fatalf("racer %d got divergent family pointers (double init)", i)
		}
		if fams[0] != d.flowFamilies[0] || fams[1] != d.flowFamilies[1] {
			t.Fatalf("racer %d families differ from the daemon's stored pair", i)
		}
	}
}
