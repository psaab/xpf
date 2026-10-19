package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// #15231 A47-05: reloadSyslog must not replace daemon-installed clients with
// freshly dialed ones. Second reload with unchanged config keeps same object.
func TestReloadSyslogKeepsDaemonClient15231(t *testing.T) {
	er := logging.NewEventReader(nil, nil)
	cfg := &config.Config{}
	cfg.Security.Log.Mode = "stream"
	cfg.Security.Log.Streams = map[string]*config.SyslogStream{
		"audit": {
			Name: "audit", Host: "127.0.0.1", Port: 514,
			Transport: config.SyslogTransport{Protocol: "tcp"},
		},
	}
	// Simulate daemon-installed deferred client.
	daemonClient, err := logging.NewSyslogClientDeferred("127.0.0.1", 514, "", "tcp", nil)
	if err != nil {
		t.Fatalf("deferred: %v", err)
	}
	er.ReplaceSyslogClients([]*logging.SyslogClient{daemonClient})

	c := &CLI{eventReader: er, applyConfigFn: func(*config.Config) {}}
	c.reloadSyslog(cfg)
	got := er.SyslogClients()
	if len(got) != 1 {
		t.Fatalf("reloadSyslog installed %d want 1", len(got))
	}
	if got[0] != daemonClient {
		t.Fatal("#15231 A47-05: reloadSyslog replaced the daemon's deferred client with a freshly dialed/built client; second reload must keep same object")
	}
	// Second reload also keeps it.
	c.reloadSyslog(cfg)
	got2 := er.SyslogClients()
	if len(got2) != 1 || got2[0] != daemonClient {
		t.Fatal("#15231 A47-05: second reloadSyslog must keep same deferred client")
	}
}
