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
	if !d.v9Family().bundle.Load().firstExp().Tracked(key) || !d.ipfixFamily().bundle.Load().firstExp().Tracked(key) {
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

	oldBundle := d.v9Family().bundle.Load()
	if oldBundle == nil || len(oldBundle.groups) == 0 {
		t.Fatal("initial v9 exporter bundle missing")
	}
	oldGroup := oldBundle.groups[0]
	if oldGroup.cancel == nil || oldGroup.wg == nil {
		t.Fatal("initial v9 generation is missing lifecycle handles")
	}
	key := flowexport.FlowKey{SrcIP: "10.0.0.102", DstIP: "192.0.2.200", SrcPort: srcPort, DstPort: 443, Protocol: 6}
	if !oldGroup.exp.HasFlowState(key) {
		t.Fatal("initial rejected open decision missing")
	}

	collector, port := listenUDP(t)
	t.Cleanup(func() { collector.Close() })
	replacementConfig := openSamplingConfig16303(t, port, port, "1")
	copied := make(chan flowExporter, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseCarry := func() { releaseOnce.Do(func() { close(release) }) }
	d.v9Family().stateCarryTestHook = func() {
		var replacement flowExporter
		for _, exp := range d.v9Family().exporters {
			if exp != oldGroup.exp && exp.HasFlowState(key) {
				replacement = exp
				break
			}
		}
		copied <- replacement
		<-release
	}

	reconcileDone := make(chan struct{})
	var reconcileOK bool
	var closeDone chan struct{}
	go func() {
		reconcileOK = d.v9Family().reconcile(replacementConfig)
		close(reconcileDone)
	}()
	t.Cleanup(func() {
		releaseCarry()
		<-reconcileDone
		if closeDone != nil {
			<-closeDone
		}
		d.v9Family().stateCarryTestHook = nil
		// Also retire the captured original explicitly: cleanup remains
		// complete even if the test exits while reconciliation is paused.
		d.v9Family().retireGroups(map[string]flowGroup{flowGroupKey(oldGroup.ec): oldGroup}, nil)
	})

	var replacement flowExporter
	select {
	case replacement = <-copied:
	case <-reconcileDone:
		t.Fatal("reconcile returned without carrying the rejected decision")
	}
	if replacement == nil {
		t.Fatal("replacement did not inherit the rejected decision")
	}
	if d.flowStateMu.TryLock() {
		d.flowStateMu.Unlock()
		t.Fatal("reconcile must hold the state lock through carry and publication")
	}

	closeRec := logging.EventRecord{
		Time: time.Now(), Type: "SESSION_CLOSE",
		SrcAddr: "10.0.0.102:24042", DstAddr: "192.0.2.200:443", ProtocolNum: 6,
		InZone: uint16(trust), OutZone: uint16(untrust),
	}
	closeDone = make(chan struct{})
	closeStarted := make(chan struct{})
	go func() {
		close(closeStarted)
		d.v9Family().closeCallback(closeRec, nil)
		close(closeDone)
	}()
	<-closeStarted
	runtime.Gosched()
	select {
	case <-closeDone:
		t.Fatal("close passed the state-transfer lock before bundle publication")
	case <-time.After(25 * time.Millisecond):
	}
	releaseCarry()
	<-reconcileDone
	if !reconcileOK {
		t.Fatal("v9 reconciliation failed")
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("close did not resume after bundle publication")
	}

	published := d.v9Family().bundle.Load()
	if published == nil {
		t.Fatal("replacement bundle was not published")
	}
	var replacementConfigForGroup *flowexport.ExportConfig
	foundReplacement := false
	for _, group := range published.groups {
		if group.exp == replacement {
			replacementConfigForGroup = group.ec
			foundReplacement = true
			break
		}
	}
	if !foundReplacement {
		t.Fatal("carried exporter is not in the published bundle")
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
	if evaluated, selected, _ := replacementConfigForGroup.SamplingStats(); evaluated != 1 || selected != 1 {
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
		IngressZoneID: trust, EgressZoneID: untrust,
		IngressIfindex: 11, EgressIfindex: 12,
	}
}

func TestStopIPFIXExporterClearsOnlyIPFIXError17815(t *testing.T) {
	d := newFlowTestDaemon()
	v9Err := errors.New("v9 build error")
	ipfixErr := errors.New("IPFIX build error")
	d.v9Family().err = v9Err
	d.ipfixFamily().err = ipfixErr

	d.stopIPFIXExporter()
	if got := d.IPFIXExportError(); got != nil {
		t.Fatalf("IPFIX error after stop = %v, want nil", got)
	}
	if got := d.FlowExportError(); got != v9Err {
		t.Fatalf("NetFlow v9 error after IPFIX stop = %v, want original error", got)
	}
}
