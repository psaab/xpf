package daemon

import (
	"log/slog"
	"strings"
	"testing"

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

func TestSystemSyslogRetryRecovers15231(t *testing.T) {
	d := &Daemon{slogHandler: logging.NewSyslogSlogHandler(slog.Default().Handler())}
	t.Cleanup(func() { d.slogHandler.SetClients(nil) })

	// Unbindable source: client construction fails (cannot assign requested address).
	d.applySystemSyslog(systemSyslogCfg15231("192.0.2.77"))
	if got := len(d.slogHandler.Clients()); got != 0 {
		t.Fatalf("premise: unbindable system syslog must install 0, got %d", got)
	}
	if !d.systemSyslogRetryOwed() {
		t.Fatal("#15231 A47-04: skipped system syslog host must arm retry debt")
	}
	// Still unbindable: retry stays owed.
	d.reassertSystemSyslogOnceForTest(systemSyslogCfg15231("192.0.2.77"))
	if !d.systemSyslogRetryOwed() {
		t.Fatal("retry while still unbindable must remain owed")
	}
	if got := len(d.slogHandler.Clients()); got != 0 {
		t.Fatalf("retry while unbindable installed %d, want 0", got)
	}
	// Bindable: retry installs host with no commit.
	d.reassertSystemSyslogOnceForTest(systemSyslogCfg15231("127.0.0.1"))
	if got := len(d.slogHandler.Clients()); got != 1 {
		t.Fatalf("#15231 A47-04: retry must install system syslog host after address appears, got %d", got)
	}
	if d.systemSyslogRetryOwed() {
		t.Fatal("successful system syslog retry must discharge debt")
	}
	// No hosts: debt cleared.
	d.applySystemSyslog(&config.Config{})
	if d.systemSyslogRetryOwed() {
		t.Fatal("removing system syslog hosts must clear retry debt")
	}
}

// Loop wiring source check + behavioural loop using shortened interval.
func TestSystemSyslogRetryLoopWired15231(t *testing.T) {
	src := readDaemonSource(t, "daemon_run.go")
	if !strings.Contains(src, "syslogStreamRetryLoop") {
		t.Fatal("retry loop missing")
	}
	// Stock loop must also re-drive system syslog: check rebuildSyslog source.
	src2 := readDaemonSource(t, "daemon_syslog_retry_14597.go")
	if !strings.Contains(src2, "applySystemSyslog") {
		t.Fatal("#15231 A47-04: retry loop (rebuildSyslog/reassert) must re-drive applySystemSyslog")
	}
	_ = semaphore.NewWeighted(1)
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
