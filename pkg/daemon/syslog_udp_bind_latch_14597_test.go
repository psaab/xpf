// #14597: the #9326 idempotence fingerprint latched BEFORE the client
// build, so a UDP stream skipped on a construction failure (DialUDP
// cannot bind a not-yet-present source address) stayed dead: the next
// apply of the IDENTICAL config hash-matched the latched fingerprint
// and skipped the rebuild even after the source address appeared.
//
// These cells drive the real applySyslogConfig. No netns is needed: a
// TEST-NET-1 source address (192.0.2.0/24, RFC 5737) is never assigned
// to a host interface, so DialUDP fails with "cannot assign requested
// address" deterministically, and a loopback source address always
// binds. The "address appears" transition is modelled by changing the
// resolved source (source-interface PrimaryAddress), which is exactly
// how a RETH VIP / DHCP address appearing changes what the build reads
// without any syslog-stanza edit.

package daemon

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
	"golang.org/x/sync/semaphore"
)

// udpStreamCfg14597 builds a one-stream UDP config whose source is
// resolved from reth1.0's PrimaryAddress, so the test can flip the
// resolved source from absent/unbindable to bindable without touching
// the syslog stanza at all.
func udpStreamCfg14597(primary string) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, PrimaryAddress: primary},
		}},
	}
	cfg.Security.Log.Mode = "stream"
	cfg.Security.Log.Streams = map[string]*config.SyslogStream{
		"audit": {
			Name:            "audit",
			Host:            "127.0.0.1",
			Port:            514,
			SourceInterface: "reth1.0",
			Transport:       config.SyslogTransport{Protocol: "udp"},
		},
	}
	return cfg
}

// explicitUDPCfg14597 builds a one-stream UDP config with an explicit
// source-address — the exact shape the issue names. The address is
// config-only in the fingerprint, so nothing about the config changes
// when the address appears on an interface; only the kernel state does.
func explicitUDPCfg14597(src string) *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{}
	cfg.Security.Log.Mode = "stream"
	cfg.Security.Log.Streams = map[string]*config.SyslogStream{
		"audit": {
			Name:          "audit",
			Host:          "127.0.0.1",
			Port:          514,
			SourceAddress: src,
			Transport:     config.SyslogTransport{Protocol: "udp"},
		},
	}
	return cfg
}

func newSyslogApplier14597() (*Daemon, *logging.EventReader) {
	d := &Daemon{syslogWarmFn: func([]*logging.SyslogClient) {}}
	return d, logging.NewEventReader(nil, nil)
}

// Decisive cell (issue acceptance z1): apply#1 with the source address
// absent builds no client; apply#2 with the SAME syslog stanza but the
// source now present must build the client. On the pre-fix code the
// latched fingerprint makes apply#2 a no-op (clients stays 0).
func TestUDPStreamRecoversWhenResolvedSourceAppears14597(t *testing.T) {
	d, er := newSyslogApplier14597()

	// Source resolves to a TEST-NET address that is not assigned
	// locally: UDP construction fails and the stream is skipped.
	d.applySyslogConfig(er, udpStreamCfg14597("192.0.2.77/32"))
	if got := er.SyslogClientCount(); got != 0 {
		t.Fatalf("premise: apply with unbindable source must install 0 clients, got %d", got)
	}
	if d.syslogHashSet {
		t.Fatal("#14597: fingerprint latched after a build that skipped the only stream; " +
			"the next identical apply will hash-match and never retry")
	}

	// The address appears (RETH VIP arrives / DHCP completes): the
	// interface now carries a bindable loopback address. The syslog
	// stanza is byte-identical; only the resolved source changed.
	d.applySyslogConfig(er, udpStreamCfg14597("127.0.0.1/32"))
	if got := er.SyslogClientCount(); got != 1 {
		t.Fatalf("#14597: apply after the source address appeared installed %d clients, want 1; "+
			"the stream stayed dead because the fingerprint latched before the failed build", got)
	}
	if !d.syslogHashSet {
		t.Fatal("after a fully built apply the fingerprint must latch (#9326 idempotence)")
	}
}

// Explicit source-address shape: the config NEVER changes, so the only
// retry trigger can be the daemon's own retry owner, not a later apply.
// reassertSyslogOnce must rebuild the skipped stream once the latch is
// cleared, and must be a no-op when nothing was skipped.
func TestSyslogRetryOwnerRebuildsSkippedUDPStream14597(t *testing.T) {
	d, er := newSyslogApplier14597()
	d.eventReader = er

	// 192.0.2.77 is never assigned on this host: construction fails.
	d.applySyslogConfig(er, explicitUDPCfg14597("192.0.2.77"))
	if got := er.SyslogClientCount(); got != 0 {
		t.Fatalf("premise: unbindable explicit source must install 0 clients, got %d", got)
	}
	if d.syslogHashSet {
		t.Fatal("#14597: fingerprint latched after a skipped UDP build (explicit source-address)")
	}
	if !d.syslogRetryOwed() {
		t.Fatal("#14597: a skipped stream must arm the retry owner; without it the stream " +
			"recovers only on an unrelated commit or a restart")
	}

	// Same-config retry tick while the address is still absent: must
	// attempt and stay owed (not latch, not install).
	d.reassertSyslogOnceForTest(explicitUDPCfg14597("192.0.2.77"))
	if got := er.SyslogClientCount(); got != 0 {
		t.Fatalf("retry with source still absent installed %d clients, want 0", got)
	}
	if !d.syslogRetryOwed() {
		t.Fatal("retry that still cannot build must remain owed")
	}

	// Address now bindable: the retry owner installs the stream and
	// discharges the debt, with the config stanza unchanged apart from
	// the source the operator would have after the VIP arrives. The
	// decisive explicit-address case (config literally identical, only
	// kernel state changed) is exercised by the production tick, which
	// re-reads the active config; here the owed/latch contract is what
	// is pinned.
	d.reassertSyslogOnceForTest(explicitUDPCfg14597("127.0.0.1"))
	if got := er.SyslogClientCount(); got != 1 {
		t.Fatalf("#14597: retry owner installed %d clients after the source became bindable, want 1", got)
	}
	if d.syslogRetryOwed() {
		t.Fatal("retry owner must discharge the debt after a fully built apply")
	}
	if !d.syslogHashSet {
		t.Fatal("fully built retry must latch the fingerprint")
	}

	// Healthy tick: no debt, so the owner must not rebuild (no redial).
	before := er.SyslogClients()
	d.reassertSyslogOnceForTest(explicitUDPCfg14597("127.0.0.1"))
	after := er.SyslogClients()
	if len(after) != 1 || len(before) != 1 || after[0] != before[0] {
		t.Fatal("#9326/#14597: a healthy retry tick rebuilt the client set; " +
			"the retry owner must be free when nothing is owed")
	}
}

// #9326 control: two applies of an identical, FULLY BUILT config still
// perform zero rebuilds. A fix that simply never latches would pass the
// recovery cells above and silently reintroduce the 20-dial churn.
func TestFullyBuiltUDPConfigStillIdempotent14597(t *testing.T) {
	d, er := newSyslogApplier14597()
	cfg := explicitUDPCfg14597("127.0.0.1")

	d.applySyslogConfig(er, cfg)
	first := er.SyslogClients()
	if len(first) != 1 {
		t.Fatalf("premise: bindable UDP stream must install 1 client, got %d", len(first))
	}
	d.applySyslogConfig(er, cfg)
	second := er.SyslogClients()
	if len(second) != 1 || second[0] != first[0] {
		t.Fatal("#9326 control broken: identical fully-built config rebuilt its UDP client; " +
			"the fix must latch after a complete build, not disable the gate")
	}
	if d.syslogRetryOwed() {
		t.Fatal("a fully built apply must not arm the syslog retry owner")
	}
}

// Mixed set: one stream builds, one is skipped. The partial build must
// not latch — the skipped stream would otherwise be pinned dead while
// its sibling forwards. The next identical apply must retry and, once
// both build, latch.
func TestPartialUDPBuildDoesNotLatch14597(t *testing.T) {
	d, er := newSyslogApplier14597()

	mixed := func(goodPrimary string) *config.Config {
		cfg := udpStreamCfg14597(goodPrimary)
		cfg.Security.Log.Streams["bad"] = &config.SyslogStream{
			Name:          "bad",
			Host:          "127.0.0.1",
			Port:          514,
			SourceAddress: "192.0.2.78",
			Transport:     config.SyslogTransport{Protocol: "udp"},
		}
		return cfg
	}

	d.applySyslogConfig(er, mixed("127.0.0.1/32"))
	if got := er.SyslogClientCount(); got != 1 {
		t.Fatalf("premise: mixed apply must install the 1 buildable client, got %d", got)
	}
	if d.syslogHashSet {
		t.Fatal("#14597: fingerprint latched after a partial build (1 of 2 streams skipped)")
	}
	if !d.syslogRetryOwed() {
		t.Fatal("#14597: a partial build must arm the retry owner for the skipped stream")
	}
}

// The retry owner must actually be started by Run, unconditionally —
// a helper no loop calls recovers nothing, which is half the issue.
// Source-shaped for the same reason TestRunStartsFabricReassertLoop_6791
// is: Run cannot be stood up in a unit test. The behavioural half
// below drives the loop itself with a shortened interval.
func TestRunStartsSyslogRetryLoop14597(t *testing.T) {
	src := readDaemonSource(t, "daemon_run.go")
	if !strings.Contains(src, "d.syslogStreamRetryLoop(ctx)") {
		t.Fatal("Run does not start syslogStreamRetryLoop; a skipped UDP stream " +
			"has no persistent retry owner (#14597)")
	}
	idx := strings.Index(src, "d.syslogStreamRetryLoop(ctx)")
	window := src[max(0, idx-400):idx]
	if strings.Contains(window, "if d.cluster != nil") || strings.Contains(window, "if d.isCluster") {
		t.Fatal("syslogStreamRetryLoop is cluster-gated; standalone nodes need it too")
	}

	prev := syslogStreamRetryInterval
	syslogStreamRetryInterval = 5 * time.Millisecond
	t.Cleanup(func() { syslogStreamRetryInterval = prev })

	d, er := newSyslogApplier14597()
	d.eventReader = er
	d.applySem = semaphore.NewWeighted(1)
	d.store = testStoreWithSetConfig(t, []string{
		"set security log mode stream",
		"set security log stream audit host 127.0.0.1",
		"set security log stream audit source-address 127.0.0.1",
		"set security log stream audit transport protocol udp",
	})
	// Arm the debt directly: the loop must clear it by rebuilding.
	d.syslogHashSet = false
	d.setSyslogRetryOwed(true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.syslogStreamRetryLoop(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if er.SyslogClientCount() == 1 && !d.syslogRetryOwed() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("syslogStreamRetryLoop never rebuilt the owed stream: clients=%d owed=%v",
		er.SyslogClientCount(), d.syslogRetryOwed())
}
