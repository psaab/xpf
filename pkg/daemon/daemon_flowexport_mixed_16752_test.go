package daemon

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/flowexport"
)

// #16752 R3-A46-05: when one instance fails to build, the old build was
// retained whole at the generation level, so the replaced exporter of
// the healthy instance kept running, kept its SourceID, and kept
// sending to the old collector. Acceptance: the b-fails arm receives
// 0 datagrams after the healthy instance moves, and live exporters
// equal published groups.

func drainUDP16752(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	buf := make([]byte, 65536)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
		if _, _, err := conn.ReadFromUDP(buf); err != nil {
			return
		}
	}
}

func countDatagrams16752(conn *net.UDPConn, window time.Duration) int {
	buf := make([]byte, 65536)
	n := 0
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		if _, _, err := conn.ReadFromUDP(buf); err == nil {
			n++
		}
	}
	return n
}

func TestMixedGenerationRetiresReplacedHealthyExporter16752(t *testing.T) {
	oldColl, oldPort := listenUDP(t)
	t.Cleanup(func() { oldColl.Close() })

	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	d.stopFlowExportRetryLoop()

	healthy := twoInstanceConfig15230("127.0.0.1", oldPort, "127.0.0.1")
	healthy.Services.FlowMonitoring.Version9.Templates["t"].TemplateRefreshRate = 1
	if !d.reconcileFlowExporters(healthy) {
		t.Fatal("healthy reconcile must start exporters")
	}
	first := d.flowBundle.Load()
	if first == nil || len(first.groups) != 2 {
		t.Fatalf("healthy groups = %v, want 2", first)
	}
	var aOld, bOld *flowexport.Exporter
	for _, g := range first.groups {
		switch g.ec.InstanceName {
		case "a":
			aOld = g.exp
		case "b":
			bOld = g.exp
		}
	}
	if aOld == nil || bOld == nil {
		t.Fatal("both instances must be live after healthy boot")
	}

	time.Sleep(250 * time.Millisecond)
	drainUDP16752(t, oldColl)

	changed := twoInstanceConfig15230("127.0.0.1", 3199, "192.0.2.250")
	changed.Services.FlowMonitoring.Version9.Templates["t"].TemplateRefreshRate = 1
	if !d.reconcileFlowExporters(changed) {
		t.Fatal("partial day-2 reconcile must report a change")
	}
	b := d.flowBundle.Load()
	if b == nil || len(b.groups) != 2 {
		t.Fatalf("published groups after partial day-2 = %v, want a(new)+b(retained)", b)
	}
	if len(d.flowExporters) != len(b.groups) {
		t.Fatalf("live v9 exporters = %d, want %d (published groups)",
			len(d.flowExporters), len(b.groups))
	}
	var aNewAddr string
	for _, g := range b.groups {
		if g.ec.InstanceName == "a" {
			aNewAddr = g.ec.Collectors[0].Address
		}
	}
	if want := "127.0.0.1:3199"; aNewAddr != want {
		t.Fatalf("healthy instance collector = %q, want new %q", aNewAddr, want)
	}
	for _, exp := range d.flowExporters {
		if exp == aOld {
			t.Fatal("replaced old a exporter is still in the live exporter set (#16752 leak)")
		}
	}
	foundB := false
	for _, exp := range d.flowExporters {
		if exp == bOld {
			foundB = true
		}
	}
	if !foundB {
		t.Fatal("retained b exporter must remain live (control)")
	}
	// Window spans a full 1s template-refresh cadence of the old
	// exporter, so a leaked Run loop must emit at least one template
	// datagram to the old collector.
	if n := countDatagrams16752(oldColl, 1600*time.Millisecond); n != 0 {
		t.Fatalf("old collector received %d datagrams after healthy instance moved, want 0 (#16752)", n)
	}
}

func TestMixedGenerationIPFIXMirror16752(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	d.stopFlowExportRetryLoop()

	mk := func(aPort int, bSource string) *config.Config {
		cfg := twoInstanceConfig15230("127.0.0.1", aPort, bSource)
		// twoInstanceConfig15230 trims b to its v9 server only; give b
		// an IPFIX server as well so its bad source fails its IPFIX
		// build on day-2 exactly as it fails its v9 build.
		bFam := cfg.ForwardingOptions.Sampling.Instances["b"].FamilyInet
		bFam.FlowServers = append(bFam.FlowServers, &config.FlowServer{
			Address: "127.0.0.1", Port: 4739, Version: config.FlowServerVersionIPFIX,
		})
		return cfg
	}

	if !d.reconcileFlowExporters(mk(2055, "127.0.0.1")) {
		t.Fatal("healthy reconcile must start exporters")
	}
	first := d.ipfixBundlePtr.Load()
	if first == nil || len(first.groups) != 2 {
		t.Fatalf("healthy IPFIX groups = %v, want 2 (a+b)", first)
	}
	var aOld, bOld *flowexport.IPFIXExporter
	for _, g := range first.groups {
		switch g.ec.InstanceName {
		case "a":
			aOld = g.exp
		case "b":
			bOld = g.exp
		}
	}
	if aOld == nil || bOld == nil {
		t.Fatal("both IPFIX instances must be live after healthy boot")
	}

	if !d.reconcileFlowExporters(mk(3199, "192.0.2.250")) {
		t.Fatal("partial day-2 reconcile must report a change")
	}
	b := d.ipfixBundlePtr.Load()
	if b == nil || len(b.groups) != 2 {
		t.Fatalf("published IPFIX groups after partial day-2 = %v, want a(new)+b(retained)", b)
	}
	if len(d.ipfixExporters) != len(b.groups) {
		t.Fatalf("live IPFIX exporters = %d, want %d (published groups)",
			len(d.ipfixExporters), len(b.groups))
	}
	for _, exp := range d.ipfixExporters {
		if exp == aOld {
			t.Fatal("replaced old IPFIX a exporter is still live (#16752 leak)")
		}
	}
	foundB := false
	for _, exp := range d.ipfixExporters {
		if exp == bOld {
			foundB = true
		}
	}
	if !foundB {
		t.Fatal("retained IPFIX b exporter must remain live (control)")
	}
}

func twoFamilyConfig17801(aPort int, bSource string) *config.Config {
	cfg := twoInstanceConfig15230("127.0.0.1", aPort, bSource)
	bFamily := cfg.ForwardingOptions.Sampling.Instances["b"].FamilyInet
	bFamily.FlowServers = append(bFamily.FlowServers, &config.FlowServer{
		Address: "127.0.0.1", Port: 4739, Version: config.FlowServerVersionIPFIX,
	})
	return cfg
}

func waitV9GroupsDone17801(t *testing.T, groups []v9Group) bool {
	t.Helper()
	done := make(chan struct{}, len(groups))
	for _, g := range groups {
		if g.wg == nil {
			return false
		}
		go func(g v9Group) {
			g.wg.Wait()
			done <- struct{}{}
		}(g)
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for range groups {
		select {
		case <-done:
		case <-timer.C:
			return false
		}
	}
	return true
}

func waitIPFIXGroupsDone17801(t *testing.T, groups []ipfixGroup) bool {
	t.Helper()
	done := make(chan struct{}, len(groups))
	for _, g := range groups {
		if g.wg == nil {
			return false
		}
		go func(g ipfixGroup) {
			g.wg.Wait()
			done <- struct{}{}
		}(g)
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for range groups {
		select {
		case <-done:
		case <-timer.C:
			return false
		}
	}
	return true
}

func TestRemoveAllExporterGroupsJoinsEveryWorker17801(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	d.stopFlowExportRetryLoop()

	for cycle := range 2 {
		if !d.reconcileFlowExporters(twoFamilyConfig17801(2055, "127.0.0.1")) {
			t.Fatalf("cycle %d: adding exporters must report a change", cycle+1)
		}
		v9Bundle := d.flowBundle.Load()
		ipfixBundle := d.ipfixBundlePtr.Load()
		if v9Bundle == nil || len(v9Bundle.groups) != 2 {
			t.Fatalf("cycle %d: v9 groups = %v, want 2", cycle+1, v9Bundle)
		}
		if ipfixBundle == nil || len(ipfixBundle.groups) != 2 {
			t.Fatalf("cycle %d: IPFIX groups = %v, want 2", cycle+1, ipfixBundle)
		}
		v9Groups := append([]v9Group(nil), v9Bundle.groups...)
		ipfixGroups := append([]ipfixGroup(nil), ipfixBundle.groups...)

		if !d.reconcileFlowExporters(&config.Config{}) {
			t.Fatalf("cycle %d: removing all exporters must report a change", cycle+1)
		}
		v9Done := waitV9GroupsDone17801(t, v9Groups)
		ipfixDone := waitIPFIXGroupsDone17801(t, ipfixGroups)
		if !v9Done || !ipfixDone {
			t.Fatalf("cycle %d: remove-all worker completion: v9=%t IPFIX=%t, want both true",
				cycle+1, v9Done, ipfixDone)
		}
	}
}

func assertGroupStillRunning17801(t *testing.T, family string, wg *sync.WaitGroup) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-done:
		t.Fatalf("%s retained worker exited before remove-all", family)
	case <-timer.C:
	}
}

func TestRemoveAllExporterGroupsJoinsRetainedFailedSiblings17801(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)
	d.stopFlowExportRetryLoop()

	if !d.reconcileFlowExporters(twoFamilyConfig17801(2055, "127.0.0.1")) {
		t.Fatal("initial healthy reconcile must report a change")
	}
	initialV9 := d.flowBundle.Load()
	initialIPFIX := d.ipfixBundlePtr.Load()
	if initialV9 == nil || initialIPFIX == nil {
		t.Fatal("initial healthy reconcile must publish both families")
	}
	var retainedV9 *flowexport.Exporter
	var retainedIPFIX *flowexport.IPFIXExporter
	var retainedV9Group v9Group
	var retainedIPFIXGroup ipfixGroup
	for _, g := range initialV9.groups {
		if g.ec.InstanceName == "b" {
			retainedV9 = g.exp
			retainedV9Group = g
		}
	}
	for _, g := range initialIPFIX.groups {
		if g.ec.InstanceName == "b" {
			retainedIPFIX = g.exp
			retainedIPFIXGroup = g
		}
	}
	if retainedV9 == nil || retainedIPFIX == nil {
		t.Fatal("initial config must publish both b exporter groups")
	}

	if !d.reconcileFlowExporters(twoFamilyConfig17801(3199, "192.0.2.250")) {
		t.Fatal("partial reconcile with failed b siblings must report a change")
	}
	v9Bundle := d.flowBundle.Load()
	ipfixBundle := d.ipfixBundlePtr.Load()
	if v9Bundle == nil || len(v9Bundle.groups) != 2 {
		t.Fatalf("partial v9 groups = %v, want replaced a and retained b", v9Bundle)
	}
	if ipfixBundle == nil || len(ipfixBundle.groups) != 2 {
		t.Fatalf("partial IPFIX groups = %v, want replaced a and retained b", ipfixBundle)
	}
	foundV9, foundIPFIX := false, false
	for _, g := range v9Bundle.groups {
		foundV9 = foundV9 || g.exp == retainedV9
	}
	for _, g := range ipfixBundle.groups {
		foundIPFIX = foundIPFIX || g.exp == retainedIPFIX
	}
	if !foundV9 || !foundIPFIX {
		t.Fatal("failed b siblings must remain published until remove-all")
	}
	assertGroupStillRunning17801(t, "v9", retainedV9Group.wg)
	assertGroupStillRunning17801(t, "IPFIX", retainedIPFIXGroup.wg)

	v9Groups := append([]v9Group(nil), v9Bundle.groups...)
	ipfixGroups := append([]ipfixGroup(nil), ipfixBundle.groups...)
	if !d.reconcileFlowExporters(&config.Config{}) {
		t.Fatal("removing all exporters after partial failure must report a change")
	}
	v9Done := waitV9GroupsDone17801(t, v9Groups)
	ipfixDone := waitIPFIXGroupsDone17801(t, ipfixGroups)
	if !v9Done || !ipfixDone {
		t.Fatalf("remove-all after partial failure worker completion: v9=%t IPFIX=%t, want both true",
			v9Done, ipfixDone)
	}
}
