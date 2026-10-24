package api

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/conntrack"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// newFilterStore commits a config built from the given flat-set lines and
// returns the store, so the filter collector's cfg.Firewall.Filters* and
// cfg.PolicyOptions.PrefixLists are populated.
func newFilterStore(t *testing.T, setLines []string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet(strings.Join(setLines, "\n")); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// filterHitsByTerm gathers xpf_filter_hits_total samples keyed by their term
// label, with the sample value.
func filterHitsByTerm(t *testing.T, c *xpfCollector, dp apiRuntimeDataPlane) map[string]float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 64)
	c.collectFilterCounters(ch, dp, fetchUserspaceStatus(dp))
	close(ch)
	out := map[string]float64{}
	for m := range ch {
		if !strings.Contains(m.Desc().String(), "xpf_filter_hits_total") {
			continue
		}
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric write: %v", err)
		}
		var term string
		for _, l := range pb.GetLabel() {
			if l.GetName() == "term" {
				term = l.GetValue()
			}
		}
		out[term] = pb.GetCounter().GetValue()
	}
	return out
}

// filterSlotDP serves per-slot filter counters (Packets == slot index + 1) so
// a test can detect both an undercounted per-term sum and a drifted
// ruleOffset. It deliberately does NOT implement Status(), so no userspace
// merge runs — this isolates the #3459 expansion/stride path.
type filterSlotDP struct {
	*dataplane.Manager
	apply *dataplane.ApplyResult
}

func (d *filterSlotDP) IsLoaded() bool                          { return true }
func (d *filterSlotDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }
func (d *filterSlotDP) ReadFilterConfig(uint32) (dataplane.FilterConfig, error) {
	return dataplane.FilterConfig{RuleStart: 0}, nil
}
func (d *filterSlotDP) ReadFilterCounters(idx uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{Packets: uint64(idx) + 1}, nil
}

// TestCollectFilterCountersExpandsPortsAndPrefixLists is the #3459 RED-on-revert
// pin. Term t1 expands to nSrc(=2 prefixes) × nDst(=1) × nDstPorts(=2) ×
// nSrcPorts(=1) = 4 dataplane rules, so it owns slots 0..3 and t2 owns slot 4.
// With per-slot Packets == idx+1: t1 = 1+2+3+4 = 10, t2 = 5.
//
// FAIL-ON-REVERT: restoring the old `numRules = nSrc*nDst` (ignoring ports and
// prefix-lists) makes t1 read only slot 0 (=1) and advance the offset by 1, so
// t2 reads slot 1 (=2) — the wrong term. Both asserted values then go RED.
func TestCollectFilterCountersExpandsPortsAndPrefixLists(t *testing.T) {
	store := newFilterStore(t, []string{
		"set policy-options prefix-list pl1 10.1.0.0/24",
		"set policy-options prefix-list pl1 10.2.0.0/24",
		"set firewall family inet filter fin term t1 from source-prefix-list pl1",
		"set firewall family inet filter fin term t1 from destination-port 80",
		"set firewall family inet filter fin term t1 from destination-port 443",
		"set firewall family inet filter fin term t1 then count c1",
		"set firewall family inet filter fin term t1 then accept",
		"set firewall family inet filter fin term t2 then count c2",
		"set firewall family inet filter fin term t2 then accept",
	})
	c := newCollector(&Server{store: store})
	dp := &filterSlotDP{
		Manager: dataplane.New(),
		apply:   &dataplane.ApplyResult{FilterIDs: map[string]uint32{"inet:fin": 0}},
	}

	got := filterHitsByTerm(t, c, dp)
	if got["t1"] != 10 {
		t.Errorf("term t1 hit count = %v, want 10 (sum of its 4 expanded slots "+
			"0..3); a wrong value means ports/prefix-list expansion was dropped", got["t1"])
	}
	if got["t2"] != 5 {
		t.Errorf("term t2 hit count = %v, want 5 (slot 4); a wrong value means the "+
			"running ruleOffset drifted and t2 read another term's slot", got["t2"])
	}
}

// filterUserspaceDP publishes a per-term hit counter via helper Status() and
// has NO eBPF apply result (LastApplyResult == nil) — modeling the userspace-dp
// runtime where filter hits live only in the helper status.
type filterUserspaceDP struct {
	*dataplane.Manager
	status dpuserspace.ProcessStatus
}

func (d *filterUserspaceDP) IsLoaded() bool                          { return true }
func (d *filterUserspaceDP) LastApplyResult() *dataplane.ApplyResult { return nil }
func (d *filterUserspaceDP) Status() (dpuserspace.ProcessStatus, error) {
	return d.status, nil
}

// TestCollectFilterCountersMergesUserspaceCounters is the #3461 RED-on-revert
// pin: the userspace helper publishes a filter-term counter, there is no eBPF
// map path (cr == nil), and the collector must still emit xpf_filter_hits_total
// carrying the helper-published value — exactly as the CLI/gRPC text paths do.
//
// FAIL-ON-REVERT: dropping the userspace merge (or restoring the
// `if cr == nil { return }` early-out) emits NO sample for the term, so
// got["t1"] is absent (0) and the assertion goes RED.
func TestCollectFilterCountersMergesUserspaceCounters(t *testing.T) {
	store := newFilterStore(t, []string{
		"set firewall family inet filter fin term t1 from protocol tcp",
		"set firewall family inet filter fin term t1 then count c1",
		"set firewall family inet filter fin term t1 then accept",
	})
	c := newCollector(&Server{store: store})
	dp := &filterUserspaceDP{
		Manager: dataplane.New(),
		status: dpuserspace.ProcessStatus{
			FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
				{Family: "inet", FilterName: "fin", TermName: "t1", Packets: 777},
			},
		},
	}

	got := filterHitsByTerm(t, c, dp)
	if got["t1"] != 777 {
		t.Errorf("term t1 hit count = %v, want 777 (helper-published filter-term "+
			"counter must merge into xpf_filter_hits_total even with no eBPF map path)", got["t1"])
	}
}

// filterUserspaceMapErrDP models the REAL userspace-dp production path: the
// apply result IS populated (LastApplyResult carries FilterIDs), but the shim
// has no eBPF filter_configs loaded, so ReadFilterConfig fails — hasMap stays
// false and counterReadErrors is bumped per filter — while the helper status
// carries the actual per-term hit counters.
type filterUserspaceMapErrDP struct {
	*dataplane.Manager
	apply  *dataplane.ApplyResult
	status dpuserspace.ProcessStatus
}

func (d *filterUserspaceMapErrDP) IsLoaded() bool                          { return true }
func (d *filterUserspaceMapErrDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }
func (d *filterUserspaceMapErrDP) ReadFilterConfig(uint32) (dataplane.FilterConfig, error) {
	return dataplane.FilterConfig{}, errors.New("filter_configs not loaded in shim")
}
func (d *filterUserspaceMapErrDP) Status() (dpuserspace.ProcessStatus, error) {
	return d.status, nil
}

// TestCollectFilterCountersMergesUserspaceCountersWhenMapConfigUnavailable is
// the #3461 REAL-PATH pin: a populated apply result (FilterIDs present) with a
// failing ReadFilterConfig — exactly the userspace-dp runtime where the eBPF
// filter_configs map is not loaded. The per-filter ReadFilterConfig failure
// bumps counterReadErrors (hasMap=false), and the helper-published term counter
// must still be emitted on xpf_filter_hits_total.
//
// FAIL-ON-REVERT: dropping the userspace merge leaves hasMap=false AND
// userspaceOk unused, so no sample is emitted for the term — got["t1"] is
// absent (0) and the value assertion goes RED. (The counterReadErrors bump is
// the independent #3408 path and is asserted separately.)
func TestCollectFilterCountersMergesUserspaceCountersWhenMapConfigUnavailable(t *testing.T) {
	store := newFilterStore(t, []string{
		"set firewall family inet filter fin term t1 from protocol tcp",
		"set firewall family inet filter fin term t1 then count c1",
		"set firewall family inet filter fin term t1 then accept",
	})
	c := newCollector(&Server{store: store})
	dp := &filterUserspaceMapErrDP{
		Manager: dataplane.New(),
		apply:   &dataplane.ApplyResult{FilterIDs: map[string]uint32{"inet:fin": 0}},
		status: dpuserspace.ProcessStatus{
			FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
				{Family: "inet", FilterName: "fin", TermName: "t1", Packets: 555},
			},
		},
	}

	got := filterHitsByTerm(t, c, dp)
	if got["t1"] != 555 {
		t.Errorf("term t1 hit count = %v, want 555 (helper-published counter must "+
			"merge even when the eBPF filter_configs map read fails)", got["t1"])
	}
	if c.counterReadErrors.Load() == 0 {
		t.Error("counterReadErrors not bumped on the per-filter ReadFilterConfig failure")
	}
}

// zoneErrScrapeDP reuses the fully-wired descriptorCoverageDP but fails the
// per-policy counter reads, so a full Collect() bumps counterReadErrors AFTER
// collectGlobalCounters has already run. (#3643: this pin previously failed the
// per-zone reads, but the per-zone Prometheus collector was removed with the
// HIDE fix; policy reads are the next post-global counterReadErrors bumper.)
type policyErrScrapeDP struct {
	*descriptorCoverageDP
}

func (d *policyErrScrapeDP) ReadPolicyCounters(uint32) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, errors.New("policy bridge degraded")
}

// TestCollectEmitsCounterReadErrorsAfterSubcollectors is the #3462
// RED-on-revert pin. Global/interface/filter reads SUCCEED and the pre-gate
// host-inbound read is neutralized, so the ONLY counterReadErrors bumps in the
// scrape come from the per-policy reads — which run AFTER collectGlobalCounters.
// A full Collect() must therefore emit a NON-ZERO xpf_counter_read_errors_total
// in the SAME scrape.
//
// FAIL-ON-REVERT: moving the emit back into collectGlobalCounters (before the
// policy collector) makes the emitted sample read 0 — the policy failures land
// after the sample was produced — so the > 0 assertion goes RED.
func TestCollectEmitsCounterReadErrorsAfterSubcollectors(t *testing.T) {
	// Neutralize the pre-gate kernel host-inbound read so it cannot bump the
	// counter before collectGlobalCounters (which would mask the ordering bug).
	orig := readHostInboundDenyCounters
	readHostInboundDenyCounters = func() ([]xnft.HostInboundDenyCount, xnft.HostInboundTableState, error) {
		return nil, xnft.HostInboundTableAbsent, nil
	}
	defer func() { readHostInboundDenyCounters = orig }()

	store := newDescriptorCoverageStore(t)
	srv := &Server{store: store, gc: conntrack.NewGC(nil, time.Minute), startTime: time.Now()}
	srv.dp = &policyErrScrapeDP{&descriptorCoverageDP{
		Manager: dataplane.New(),
		status:  dpuserspace.ProcessStatus{},
		apply: &dataplane.ApplyResult{
			ZoneIDs:   map[string]uint16{"trust": 1, "untrust": 2},
			FilterIDs: map[string]uint32{"inet:fin": 0, "inet6:fin6": 100},
		},
	}}
	c := newCollector(srv)

	// Drive the real Collect() so the production ordering (not a test
	// reconstruction) is what is exercised.
	ch := make(chan prometheus.Metric)
	done := make(chan struct{})
	var errTotal float64
	var saw bool
	go func() {
		for m := range ch {
			if !strings.Contains(m.Desc().String(), "xpf_counter_read_errors_total") {
				continue
			}
			var pb dto.Metric
			if err := m.Write(&pb); err != nil {
				t.Errorf("metric write: %v", err)
				continue
			}
			saw = true
			errTotal = pb.GetCounter().GetValue()
		}
		close(done)
	}()
	c.Collect(ch)
	close(ch)
	<-done

	if !saw {
		t.Fatal("xpf_counter_read_errors_total was not emitted by Collect()")
	}
	if errTotal <= 0 {
		t.Errorf("xpf_counter_read_errors_total = %v in the scrape whose policy reads "+
			"failed; want > 0 — the error sample must reflect a late (post-global) "+
			"sub-collector failure in the SAME scrape (#3462)", errTotal)
	}
}
