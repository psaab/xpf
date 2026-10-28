package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

func streamSyslogCfg18368(names ...string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.Log.Mode = "stream"
	cfg.Security.Log.Streams = make(map[string]*config.SyslogStream, len(names))
	for _, name := range names {
		cfg.Security.Log.Streams[name] = &config.SyslogStream{
			Name:      name,
			Host:      "127.0.0.1",
			Port:      514,
			Transport: config.SyslogTransport{Protocol: "tcp"},
		}
	}
	return cfg
}

func newStreamSyslogApplier18368(t *testing.T) (*Daemon, *logging.EventReader, *int) {
	t.Helper()
	built := 0
	d := &Daemon{syslogWarmFn: func(clients []*logging.SyslogClient) {
		built += len(clients)
	}}
	er := logging.NewEventReader(nil, nil)
	t.Cleanup(func() { er.ReplaceSyslogClients(nil) })
	return d, er, &built
}

// #18368: even when the handler still contains the exact cached pointer,
// Close is terminal and an unchanged fingerprint must rebuild it.
func TestApplySecurityStreamSyslogSameIdentityRebuildsClosedClient18368(t *testing.T) {
	d, er, built := newStreamSyslogApplier18368(t)
	cfg := streamSyslogCfg18368("audit")

	d.applySyslogConfig(er, cfg)
	first := er.SyslogClients()
	if len(first) != 1 || *built != 1 || first[0].Closed() {
		t.Fatalf("premise: first apply installed %d clients after %d constructions", len(first), *built)
	}

	first[0].Close() // same-identity retirement: the cached pointer remains installed
	if !first[0].Closed() {
		t.Fatal("premise: test retirement did not close the cached client")
	}
	d.applySyslogConfig(er, cfg)

	current := er.SyslogClients()
	if *built != 2 {
		t.Fatalf("#18368: unchanged apply after same-identity retirement constructed %d clients, want 2 total", *built)
	}
	if len(current) != 1 || current[0] == first[0] || current[0].Closed() {
		t.Fatalf("#18368: unchanged apply did not install a fresh live client: %v", current)
	}
}

// #18368: the reordered handler set carries terminally closed cached
// clients. The stream cache must reject and rebuild both rather than
// serving either pointer back into the installed set.
func TestApplySecurityStreamSyslogReorderedClosedClients18368(t *testing.T) {
	d, er, built := newStreamSyslogApplier18368(t)
	cfg := streamSyslogCfg18368("audit-a", "audit-b")

	d.applySyslogConfig(er, cfg)
	first := er.SyslogClients()
	if len(first) != 2 || *built != 2 || first[0] == first[1] {
		t.Fatalf("premise: first apply installed %d distinct clients after %d constructions", len(first), *built)
	}

	first[0].Close()
	first[1].Close()
	er.SetSyslogClients([]*logging.SyslogClient{first[1], first[0]})
	if got := er.SyslogClients(); len(got) != 2 || got[0] != first[1] || got[1] != first[0] {
		t.Fatalf("premise: handler clients were not reordered: %v", got)
	}
	d.applySyslogConfig(er, cfg)

	current := er.SyslogClients()
	if *built != 4 {
		t.Fatalf("#18368: reordered closed clients were not both rebuilt (constructions=%d, want 4 total)", *built)
	}
	if len(current) != 2 {
		t.Fatalf("#18368: rebuilt apply installed %d clients, want 2", len(current))
	}
	for _, client := range current {
		if client == first[0] || client == first[1] || client.Closed() {
			t.Fatalf("#18368: reordered apply retained a retired client: %v", current)
		}
	}
}

// #18368: a same-fingerprint handler replacement must not make an
// uninstalled-but-open cached client eligible for per-stream reuse.
func TestApplySecurityStreamSyslogRebuildsAfterInstalledSetDrift18368(t *testing.T) {
	d, er, built := newStreamSyslogApplier18368(t)
	cfg := streamSyslogCfg18368("audit")

	d.applySyslogConfig(er, cfg)
	first := er.SyslogClients()
	if len(first) != 1 || *built != 1 || first[0].Closed() {
		t.Fatalf("premise: first apply installed %d clients after %d constructions", len(first), *built)
	}
	// EventReader.SetSyslogClients deliberately does not close displaced
	// clients, so this exercises drift independently of Closed().
	foreign, err := logging.NewSyslogClientDeferred("127.0.0.1", 514, "", "tcp", nil)
	if err != nil || foreign == nil {
		t.Fatalf("create foreign client: client=%v err=%v", foreign, err)
	}
	t.Cleanup(func() { first[0].Close() })
	er.SetSyslogClients([]*logging.SyslogClient{foreign})
	d.applySyslogConfig(er, cfg)

	current := er.SyslogClients()
	if *built != 2 {
		t.Fatalf("#18368: apply after installed-set drift constructed %d clients, want 2 total", *built)
	}
	if len(current) != 1 || current[0] == first[0] || current[0] == foreign || current[0].Closed() {
		t.Fatalf("#18368: apply after installed-set drift did not install a fresh live client: %v", current)
	}
}

// Control: an unchanged, open cached stream remains installed without
// another construction/warm attempt.
func TestApplySecurityStreamSyslogUnchangedOpenClientNoRedial18368(t *testing.T) {
	d, er, built := newStreamSyslogApplier18368(t)
	cfg := streamSyslogCfg18368("audit")

	d.applySyslogConfig(er, cfg)
	first := er.SyslogClients()
	if len(first) != 1 || *built != 1 || first[0].Closed() {
		t.Fatalf("premise: first apply installed %d clients after %d constructions", len(first), *built)
	}
	d.applySyslogConfig(er, cfg)

	current := er.SyslogClients()
	if *built != 1 {
		t.Fatalf("control: unchanged open client caused another construction/warm attempt (total=%d, want 1)", *built)
	}
	if len(current) != 1 || current[0] != first[0] || current[0].Closed() {
		t.Fatalf("control: unchanged apply did not preserve the open client: %v", current)
	}
}

func TestSyslogCachedStreamLookupEvictsClosedClient18368(t *testing.T) {
	d := &Daemon{}
	client, err := logging.NewSyslogClientDeferred("127.0.0.1", 514, "", "tcp", nil)
	if err != nil || client == nil {
		t.Fatalf("create client: client=%v err=%v", client, err)
	}
	defer client.Close()
	d.syslogCacheClient15231("audit", "fingerprint", client)
	client.Close()

	if got := d.syslogCachedClient15231("audit", "fingerprint"); got != nil {
		t.Fatalf("closed cached client was returned: %p", got)
	}
	if _, ok := d.syslogBuiltByName15231["audit"]; ok {
		t.Fatal("closed cached client was not evicted")
	}
	if _, ok := d.syslogBuiltFP15231["audit"]; ok {
		t.Fatal("closed cached fingerprint was not evicted")
	}
}
