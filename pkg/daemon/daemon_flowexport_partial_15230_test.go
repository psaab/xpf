package daemon

import (
	"strconv"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// #15230 A46-02: one sampling instance whose collector source-address is
// not (yet) local must not stop flow export for every other instance, and
// a later commit must publish the healthy instance's NEW config instead of
// freezing the previously running set. Instance a is healthy; instance b
// pins source 192.0.2.250 (TEST-NET-1, never local). FAIL-ON-REVERT: the
// build loop returns on b's error, so a is never published (nothing
// running) or the old a set is frozen.

func twoInstanceConfig15230(aCollector string, aPort int, bSource string) *config.Config {
	cfg := &config.Config{}
	cfg.ForwardingOptions.Sampling = &config.SamplingConfig{
		Instances: map[string]*config.SamplingInstance{
			"a": {
				Name: "a",
				FamilyInet: &config.SamplingFamily{
					FlowServers: []*config.FlowServer{{Address: aCollector, Port: aPort, Version: config.FlowServerVersion9}},
				},
			},
			"b": {
				Name: "b",
				FamilyInet: &config.SamplingFamily{
					SourceAddress: bSource,
					FlowServers:   []*config.FlowServer{{Address: "127.0.0.1", Port: 2056, Version: config.FlowServerVersion9}},
				},
			},
		},
	}
	cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{
		Version9:     &config.NetFlowV9Config{Templates: map[string]*config.NetFlowV9Template{"t": {Name: "t"}}},
		VersionIPFIX: &config.NetFlowIPFIXConfig{Templates: map[string]*config.NetFlowIPFIXTemplate{"t": {Name: "t"}}},
	}
	// IPFIX groups for both instances, healthy collectors, so the v9
	// partial failure cannot hide behind an IPFIX failure.
	for _, inst := range cfg.ForwardingOptions.Sampling.Instances {
		inst.FamilyInet.FlowServers = append(inst.FamilyInet.FlowServers,
			&config.FlowServer{Address: "127.0.0.1", Port: 4739, Version: config.FlowServerVersionIPFIX})
	}
	// b's IPFIX server must not inherit the bad source: source is per
	// family output, shared by both versions of that instance's inet
	// family. Give b a separate healthy inet6 IPFIX group instead by
	// keeping the shared bad source only on the v9-checked path: the
	// resolver applies SamplingFamily.SourceAddress to every collector
	// of the family, so b IPFIX would fail too. That is acceptable:
	// assertions below are on the v9 family plus per-instance BuildFailed.
	cfg.ForwardingOptions.Sampling.Instances["b"].FamilyInet.FlowServers =
		cfg.ForwardingOptions.Sampling.Instances["b"].FamilyInet.FlowServers[:1]
	return cfg
}

func TestPartialBuildPublishesHealthyInstance15230(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	d.stopFlowExportRetryLoop()

	cfg := twoInstanceConfig15230("127.0.0.1", 2055, "192.0.2.250")
	if !d.reconcileFlowExporters(cfg) {
		t.Fatal("partial reconcile must report a change")
	}
	b := d.flowBundle.Load()
	if b == nil || len(b.groups) == 0 {
		t.Fatal("healthy instance a must be live despite instance b build failure")
	}
	for _, g := range b.groups {
		if g.ec.InstanceName != "a" {
			t.Fatalf("published v9 group instance = %q, want only \"a\" (groups=%d)", g.ec.InstanceName, len(b.groups))
		}
	}
	if d.FlowExportError() == nil {
		t.Fatal("partial failure must surface via FlowExportError / BuildFailed")
	}
	failed := map[string]bool{}
	for _, name := range d.FlowExportFailedGroups() {
		failed[name] = true
	}
	if !failed["netflow-v9\x00b"] {
		t.Fatalf("FlowExportFailedGroups = %v, want netflow-v9/b marked failed", d.FlowExportFailedGroups())
	}
	if failed["netflow-v9\x00a"] {
		t.Fatal("healthy instance a must not be marked failed")
	}
	var v9StateFailed bool
	for _, st := range d.FlowExportBuildStates() {
		if st.Family == "netflow-v9" {
			v9StateFailed = st.BuildFailed
			if st.ConfiguredGroups != 2 {
				t.Fatalf("v9 ConfiguredGroups = %d, want 2", st.ConfiguredGroups)
			}
		}
	}
	if !v9StateFailed {
		t.Fatal("v9 BuildState.BuildFailed must be true on partial failure")
	}
	// The healthy exporter actually exports.
	d.flowExportCallback(logging.EventRecord{
		Type: "SESSION_CLOSE", SrcAddr: "10.0.0.1:1234", DstAddr: "10.0.0.2:80", Protocol: "tcp",
	}, nil)
}

// TestPartialBuildDoesNotFreezeHealthyInstance15230: a was running with
// collector port P1; a new commit moves a to P2 while b still fails. The
// published a group must carry the NEW config, not the frozen old one.
func TestPartialBuildDoesNotFreezeHealthyInstance15230(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	d.stopFlowExportRetryLoop()

	// Start fully healthy (b source local).
	healthy := twoInstanceConfig15230("127.0.0.1", 2055, "127.0.0.1")
	// twoInstanceConfig15230 gives b port 2056; healthy build must succeed fully.
	if !d.reconcileFlowExporters(healthy) {
		t.Fatal("healthy reconcile must start exporters")
	}
	if err := d.FlowExportError(); err != nil {
		t.Fatalf("healthy reconcile error = %v", err)
	}
	firstBundle := d.flowBundle.Load()
	if len(firstBundle.groups) != 2 {
		t.Fatalf("healthy groups = %d, want 2 (a+b)", len(firstBundle.groups))
	}
	// Day-2: a moves to a new collector port, b breaks.
	changed := twoInstanceConfig15230("127.0.0.1", 3199, "192.0.2.250")
	if !d.reconcileFlowExporters(changed) {
		t.Fatal("partial day-2 reconcile must report a change")
	}
	b := d.flowBundle.Load()
	if b == nil || len(b.groups) != 2 {
		t.Fatalf("published groups after partial day-2 = %v, want a(new)+b(retained)", b)
	}
	var aAddr, bSrc string
	var aFound, bFound bool
	for _, g := range b.groups {
		if g.ec.InstanceName == "a" {
			aFound = true
			aAddr = g.ec.Collectors[0].Address
		}
		if g.ec.InstanceName == "b" {
			bFound = true
			bSrc = g.ec.Collectors[0].SourceAddress
		}
	}
	if !aFound || !bFound {
		t.Fatalf("published groups must contain a and retained b: %+v", b.groups)
	}
	wantAddr := "127.0.0.1:" + strconv.Itoa(3199)
	if aAddr != wantAddr {
		t.Fatalf("healthy instance frozen on old config: collector = %q, want new %q", aAddr, wantAddr)
	}
	if bSrc != "127.0.0.1" {
		t.Fatalf("retained b must keep old source 127.0.0.1, got %q (new failed config leaked in)", bSrc)
	}
	if d.FlowExportError() == nil {
		t.Fatal("b failure must remain surfaced after partial day-2")
	}
	// Recovery: b fixed, identical-shape commit retries (hash not recorded
	// for the failed group) and both instances publish.
	fixed := twoInstanceConfig15230("127.0.0.1", 3199, "127.0.0.1")
	if !d.reconcileFlowExporters(fixed) {
		t.Fatal("recovery reconcile must report a change")
	}
	if b := d.flowBundle.Load(); b == nil || len(b.groups) != 2 {
		t.Fatalf("recovered groups = %v, want 2", b)
	}
	if err := d.FlowExportError(); err != nil {
		t.Fatalf("recovered reconcile must clear error, got %v", err)
	}
	if len(d.FlowExportFailedGroups()) != 0 {
		t.Fatalf("recovered FailedGroups = %v, want empty", d.FlowExportFailedGroups())
	}
}
