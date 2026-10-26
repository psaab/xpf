package daemon

import (
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/flowexport"
	"github.com/psaab/xpf/pkg/logging"
)

func TestConcurrentSyncOpenDecisionIsAtomic17815(t *testing.T) {
	d := rejectedTestDaemon(t, "1")
	trust, untrust := config.StableZoneID("trust"), config.StableZoneID("untrust")
	delta := syncOpen17815(24041, trust, untrust)

	const callers = 128
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			<-start
			d.trackFlowOpenFromSync(delta)
		}()
	}
	close(start)
	wg.Wait()

	if evaluated, selected := samplingTotals17815(t, d); evaluated != 2 || selected != 2 {
		t.Fatalf("concurrent duplicate opens sampled %d/%d, want 2/2 (one decision per protocol bundle)", evaluated, selected)
	}
	key := flowexport.FlowKey{SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: 24041, DstPort: 443, Protocol: 6}
	if !d.flowBundle.Load().firstExp().Tracked(key) || !d.ipfixBundlePtr.Load().firstExp().Tracked(key) {
		t.Fatal("the one selected decision must be registered in both protocol bundles")
	}
}

func TestCloseWaitsForStateCarryAndPublication17815(t *testing.T) {
	d := rejectedTestDaemon(t, "2")
	trust, untrust := config.StableZoneID("trust"), config.StableZoneID("untrust")
	const srcPort = uint16(24042)
	if !d.eventReader.ProcessRawEvent(openRaw16303(srcPort, 11, 12, uint16(trust), uint16(untrust))) {
		t.Fatal("rejected open rejected")
	}

	oldBundle := d.flowBundle.Load()
	if oldBundle == nil || len(oldBundle.groups) == 0 {
		t.Fatal("initial v9 exporter bundle missing")
	}
	key := flowexport.FlowKey{SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: srcPort, DstPort: 443, Protocol: 6}
	if !oldBundle.groups[0].exp.HasFlowState(key) {
		t.Fatal("initial rejected open decision missing")
	}

	collector, port := listenUDP(t)
	t.Cleanup(func() { collector.Close() })
	configs := d.buildFlowExportConfigs(openSamplingConfig16303(t, port, port, "1"))
	newGroups := make([]v9Group, 0, len(configs))
	var replacement *flowexport.Exporter
	var replacementConfig *flowexport.ExportConfig
	for _, ec := range configs {
		exp, err := flowexport.NewExporter(ec)
		if err != nil {
			t.Fatalf("NewExporter replacement: %v", err)
		}
		t.Cleanup(exp.Close)
		group := v9Group{exp: exp, ec: ec}
		newGroups = append(newGroups, group)
		if flowGroupKey(ec) == flowGroupKey(oldBundle.groups[0].ec) {
			replacement, replacementConfig = exp, ec
		}
	}
	if replacement == nil {
		t.Fatal("replacement for original flow group missing")
	}

	// This is the same critical section used by reconcile: copy first,
	// then publish. The concurrent close must wait for publication, so it
	// consumes the copied decision on the new bundle instead of deleting
	// only the old copy and resurrecting stale state.
	d.flowReconMu.Lock()
	d.flowStateMu.Lock()
	d.carryFlowStateV9Locked(newGroups)
	if !replacement.HasFlowState(key) {
		d.flowStateMu.Unlock()
		d.flowReconMu.Unlock()
		t.Fatal("replacement did not inherit the rejected decision")
	}
	closeRec := logging.EventRecord{
		Time: time.Now(), Type: "SESSION_CLOSE",
		SrcAddr: "10.0.0.102:24042", DstAddr: "192.0.2.200:443", ProtocolNum: 6,
		InZone: uint16(trust), OutZone: uint16(untrust),
	}
	closeStarted := make(chan struct{})
	closeDone := make(chan struct{})
	go func() {
		close(closeStarted)
		d.flowExportCallback(closeRec, nil)
		close(closeDone)
	}()
	<-closeStarted
	runtime.Gosched()
	select {
	case <-closeDone:
		d.flowStateMu.Unlock()
		d.flowReconMu.Unlock()
		t.Fatal("close passed the state-transfer lock before bundle publication")
	case <-time.After(25 * time.Millisecond):
	}
	d.flowBundle.Store(&exporterBundle{groups: newGroups})
	d.flowStateMu.Unlock()
	d.flowReconMu.Unlock()
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("close did not resume after bundle publication")
	}
	if replacement.HasFlowState(key) {
		t.Fatal("close must consume the replacement's copied rejection")
	}

	// The next session reusing the same tuple must now make its own fresh
	// decision in the published generation (rate 1 selects it).
	openRec := logging.EventRecord{
		Time: time.Now(), Type: "SESSION_OPEN",
		SrcAddr: "10.0.0.102:24042", DstAddr: "192.0.2.200:443", ProtocolNum: 6,
		InZone: uint16(trust), OutZone: uint16(untrust),
		IngressIface: "ge-0/0/0.0", EgressIface: "ge-0/0/2.0",
	}
	d.trackFlowOpen(openRec)
	if evaluated, selected, _ := replacementConfig.SamplingStats(); evaluated != 1 || selected != 1 {
		t.Fatalf("same-tuple replacement decision = %d/%d, want 1/1", evaluated, selected)
	}
	if !replacement.Tracked(key) {
		t.Fatal("same-tuple session was not registered after its fresh selected decision")
	}
}

func syncOpen17815(srcPort uint16, trust, untrust uint32) dpuserspace.SessionDeltaInfo {
	return dpuserspace.SessionDeltaInfo{
		Event: "open", AddrFamily: dataplane.AFInet, Protocol: 6,
		SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: srcPort, DstPort: 443,
		IngressZoneID: uint16(trust), EgressZoneID: uint16(untrust),
		IngressIfindex: 11, EgressIfindex: 12,
	}
}

func TestStopIPFIXExporterClearsOnlyIPFIXError17815(t *testing.T) {
	d := newFlowTestDaemon()
	v9Err := errors.New("v9 build error")
	ipfixErr := errors.New("IPFIX build error")
	d.flowExportErr = v9Err
	d.ipfixExportErr = ipfixErr

	d.stopIPFIXExporter()
	if got := d.IPFIXExportError(); got != nil {
		t.Fatalf("IPFIX error after stop = %v, want nil", got)
	}
	if got := d.FlowExportError(); got != v9Err {
		t.Fatalf("NetFlow v9 error after IPFIX stop = %v, want original error", got)
	}
}
