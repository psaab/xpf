package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// #18387: teardown branches (event mode and zero-stream) must close a
// displaced OPEN cached client. The displaced client is cached but not
// installed (drift via SetSyslogClients, which does not close), so
// ReplaceSyslogClients(nil) alone cannot close it; pre-fix
// syslogClearCache15231() discarded it unclosed.

func displacedCachedClient18387(t *testing.T) (*Daemon, *logging.EventReader, *logging.SyslogClient) {
	t.Helper()
	d, er, _ := newStreamSyslogApplier18368(t)
	cfg := streamSyslogCfg18368("audit")

	d.applySyslogConfig(er, cfg)
	first := er.SyslogClients()
	if len(first) != 1 || first[0].Closed() {
		t.Fatalf("premise: first apply did not install one live client: %v", first)
	}
	// Drift: replace the installed set with a foreign client without
	// closing the cached one (SetSyslogClients is the non-closing swap).
	foreign, err := logging.NewSyslogClientDeferred("127.0.0.1", 514, "", "tcp", nil)
	if err != nil || foreign == nil {
		t.Fatalf("create foreign client: client=%v err=%v", foreign, err)
	}
	t.Cleanup(func() { foreign.Close() })
	er.SetSyslogClients([]*logging.SyslogClient{foreign})
	if first[0].Closed() {
		t.Fatal("premise: drift must leave the cached client open")
	}
	if _, ok := d.syslogBuiltByName15231["audit"]; !ok {
		t.Fatal("premise: displaced client not still cached")
	}
	return d, er, first[0]
}

func TestApplySyslogConfigEventModeClosesDisplacedCachedClient18387(t *testing.T) {
	d, er, displaced := displacedCachedClient18387(t)

	cfg := &config.Config{}
	cfg.Security.Log.Mode = "event"
	d.applySyslogConfig(er, cfg)

	if !displaced.Closed() {
		t.Fatalf("#18387: event-mode teardown discarded displaced open cached client unclosed: %p", displaced)
	}
	if got := er.SyslogClientCount(); got != 0 {
		t.Fatalf("#18387: event mode must leave zero remote syslog clients, got %d", got)
	}
	d.syslogBuiltMu.Lock()
	_, cached := d.syslogBuiltByName15231["audit"]
	d.syslogBuiltMu.Unlock()
	if cached {
		t.Fatal("#18387: event-mode teardown left displaced client in cache")
	}
}

func TestApplySyslogConfigZeroStreamsClosesDisplacedCachedClient18387(t *testing.T) {
	d, er, displaced := displacedCachedClient18387(t)

	cfg := &config.Config{}
	cfg.Security.Log.Mode = "stream"
	// No streams: zero-stream teardown branch.
	d.applySyslogConfig(er, cfg)

	if !displaced.Closed() {
		t.Fatalf("#18387: zero-stream teardown discarded displaced open cached client unclosed: %p", displaced)
	}
	if got := er.SyslogClientCount(); got != 0 {
		t.Fatalf("#18387: zero-stream teardown must leave zero remote syslog clients, got %d", got)
	}
	d.syslogBuiltMu.Lock()
	_, cached := d.syslogBuiltByName15231["audit"]
	d.syslogBuiltMu.Unlock()
	if cached {
		t.Fatal("#18387: zero-stream teardown left displaced client in cache")
	}
}
