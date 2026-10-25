package daemon

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
	"golang.org/x/sync/semaphore"
)

// --- A47-04: system syslog host skipped at boot must be retried ---

func systemSyslogCfg15231(src string) *config.Config {
	cfg := &config.Config{}
	cfg.System.Syslog = &config.SystemSyslogConfig{
		Hosts: []*config.SyslogHostConfig{{
			Address:       "127.0.0.1",
			Port:          514,
			SourceAddress: src,
			Facilities:    []config.SyslogFacility{{Facility: "daemon", Severity: "info"}},
		}},
	}
	return cfg
}

// commitSyslog15231 replaces the store's active config with the given
// set lines, modelling the address appearing (or the stanza being
// removed) without any daemon apply in between.
func commitSyslog15231(t *testing.T, d *Daemon, lines ...string) {
	t.Helper()
	if err := d.store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if len(lines) == 0 {
		if err := d.store.LoadOverride(""); err != nil {
			t.Fatalf("LoadOverride(empty): %v", err)
		}
	} else if _, err := d.store.LoadSet(strings.Join(lines, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := d.store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	d.store.ExitConfigure()
}

// newSystemSyslogDaemon15231 builds a store-backed Daemon whose only
// syslog debt can be system debt: no eventReader is installed, so the
// production tick's stream branch cannot run. #16716: this is the
// fixture that makes M1 (system branch of rebuildSyslog dropped) and
// M2 (tick gate narrowed to stream debt) observable — the old twin
// reassertSystemSyslogOnceForTest bypassed applySem, the store and
// rebuildSyslog entirely, so neither mutant red-ed any cell.
func newSystemSyslogDaemon15231(t *testing.T, src string) *Daemon {
	t.Helper()
	d := &Daemon{
		slogHandler: logging.NewSyslogSlogHandler(slog.Default().Handler()),
		applySem:    semaphore.NewWeighted(1),
		store: testStoreWithSetConfig(t, []string{
			"set system syslog host 127.0.0.1 daemon info",
			"set system syslog host 127.0.0.1 source-address " + src,
		}),
	}
	d.store.ExitConfigure()
	t.Cleanup(func() { d.slogHandler.SetClients(nil) })
	return d
}

func TestSystemSyslogRetryRecovers15231(t *testing.T) {
	ctx := context.Background()
	d := newSystemSyslogDaemon15231(t, "192.0.2.77")

	// Unbindable source: client construction fails (cannot assign requested address).
	d.applySystemSyslog(d.store.ActiveConfig())
	if got := len(d.slogHandler.Clients()); got != 0 {
		t.Fatalf("premise: unbindable system syslog must install 0, got %d", got)
	}
	if !d.systemSyslogRetryOwed() {
		t.Fatal("#15231 A47-04: skipped system syslog host must arm retry debt")
	}
	if d.syslogRetryOwed() {
		t.Fatal("premise: fixture must carry system-only debt, stream debt armed")
	}
	// Still unbindable: production tick stays owed.
	d.reassertSyslogOnce(ctx)
	if !d.systemSyslogRetryOwed() {
		t.Fatal("retry while still unbindable must remain owed")
	}
	if got := len(d.slogHandler.Clients()); got != 0 {
		t.Fatalf("retry while unbindable installed %d, want 0", got)
	}
	// Address appears: active config now names a bindable source, with
	// no commit-time apply — the production tick alone must recover.
	commitSyslog15231(t, d,
		"set system syslog host 127.0.0.1 daemon info",
		"set system syslog host 127.0.0.1 source-address 127.0.0.1")
	d.reassertSyslogOnce(ctx)
	if got := len(d.slogHandler.Clients()); got != 1 {
		t.Fatalf("#15231 A47-04/#16716: production tick must install system syslog host after address appears, got %d", got)
	}
	if d.systemSyslogRetryOwed() {
		t.Fatal("successful system syslog retry must discharge debt")
	}
	// No hosts: debt cleared via the production apply path.
	commitSyslog15231(t, d)
	d.applySystemSyslog(d.store.ActiveConfig())
	if d.systemSyslogRetryOwed() {
		t.Fatal("removing system syslog hosts must clear retry debt")
	}
}

// Behavioural loop cell: tick syslogStreamRetryLoop with a shortened
// interval and system-only debt. M1/M2 each leave the loop spinning
// with the debt armed and no client installed, so this times out red.
func TestSystemSyslogRetryLoopWired15231(t *testing.T) {
	prev := syslogStreamRetryInterval
	syslogStreamRetryInterval = 5 * time.Millisecond
	t.Cleanup(func() { syslogStreamRetryInterval = prev })

	d := newSystemSyslogDaemon15231(t, "127.0.0.1")
	d.applySystemSyslog(systemSyslogCfg15231("192.0.2.77"))
	if !d.systemSyslogRetryOwed() || d.syslogRetryOwed() {
		t.Fatalf("premise: want system-only debt, system=%v stream=%v",
			d.systemSyslogRetryOwed(), d.syslogRetryOwed())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.syslogStreamRetryLoop(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(d.slogHandler.Clients()) == 1 && !d.systemSyslogRetryOwed() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("#16716: syslogStreamRetryLoop never recovered system-only debt: clients=%d owed=%v",
		len(d.slogHandler.Clients()), d.systemSyslogRetryOwed())
}

// --- A47-06: partial stream build must preserve healthy clients ---

func mixedCfg15231(goodSrc string) *config.Config {
	cfg := explicitUDPCfg14597(goodSrc) // stream "audit" good (explicit source)
	// Rename good stream key handling: explicit uses "audit". Add bad stream.
	cfg.Security.Log.Streams["bad"] = &config.SyslogStream{
		Name: "bad", Host: "127.0.0.1", Port: 514, SourceAddress: "192.0.2.78",
		Transport: config.SyslogTransport{Protocol: "udp"},
	}
	return cfg
}

func TestPartialBuildPreservesHealthyClient15231(t *testing.T) {
	d, er := newSyslogApplier14597()

	d.applySyslogConfig(er, mixedCfg15231("127.0.0.1"))
	first := er.SyslogClients()
	if len(first) != 1 {
		t.Fatalf("premise: mixed apply must install 1 good client, got %d", len(first))
	}
	if !d.syslogRetryOwed() {
		t.Fatal("partial build must arm retry debt")
	}
	warmedBefore := 0
	_ = warmedBefore

	// Retry tick with bad still dead: healthy client must be SAME object, not closed/replaced.
	d.applySyslogConfig(er, mixedCfg15231("127.0.0.1"))
	second := er.SyslogClients()
	if len(second) != 1 {
		t.Fatalf("retry with bad still dead installed %d, want 1", len(second))
	}
	if second[0] != first[0] {
		t.Fatal("#15231 A47-06: healthy stream client was replaced on a retry where only the dead stream was owed; want same deferred/UDP client object preserved")
	}
	if !d.syslogRetryOwed() {
		t.Fatal("retry with dead stream still present must remain owed")
	}

	// Now bad becomes bindable: retry installs both, healthy still preserved, debt cleared, latch set.
	cfg2 := mixedCfg15231("127.0.0.1")
	cfg2.Security.Log.Streams["bad"].SourceAddress = "127.0.0.1"
	d.applySyslogConfig(er, cfg2)
	third := er.SyslogClients()
	if len(third) != 2 {
		t.Fatalf("recovery apply installed %d, want 2", len(third))
	}
	found := false
	for _, c := range third {
		if c == first[0] {
			found = true
		}
	}
	if !found {
		t.Fatal("#15231 A47-06: healthy client must survive recovery apply too")
	}
	if d.syslogRetryOwed() {
		t.Fatal("full build must discharge debt")
	}
	if !d.syslogHashSet {
		t.Fatal("full build must latch fingerprint")
	}

	// Healthy identical apply after latch: zero rebuild (same objects).
	d.applySyslogConfig(er, cfg2)
	fourth := er.SyslogClients()
	if len(fourth) != 2 {
		t.Fatalf("latched apply installed %d want 2", len(fourth))
	}
	for _, a := range third {
		ok := false
		for _, b := range fourth {
			if a == b {
				ok = true
			}
		}
		if !ok {
			t.Fatal("#9326 control: latched identical apply rebuilt a client")
		}
	}
}
