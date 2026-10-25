package daemon

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// #16772 (R3-A47-03): the daemon fingerprints call
// ResolveSyslogSourceAddrForCollector unconditionally — per stream
// (rsi=) and for the global source-interface (gsrc=) — before the hash
// gate. With no source-interface configured (the default shape) the
// resolver fell through to the #15078 WARN, so every apply of a
// default-shaped stream logged a false "leaving the syslog source
// unbound (#15078)" — twice more per rebuild — indistinguishable from
// a genuine configured-interface family loss.
//
// FAIL-ON-REVERT: remove the empty-srcIface early return in
// pkg/config/syslog_source.go and the default-shape apply below
// captures the #15078 WARN again.

type syslogWarnCapture16772 struct{ msgs *[]string }

func (h syslogWarnCapture16772) Enabled(context.Context, slog.Level) bool { return true }
func (h syslogWarnCapture16772) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		*h.msgs = append(*h.msgs, r.Message)
	}
	return nil
}
func (h syslogWarnCapture16772) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h syslogWarnCapture16772) WithGroup(string) slog.Handler      { return h }

func captureDaemonSyslogWarns16772(t *testing.T) *[]string {
	t.Helper()
	msgs := &[]string{}
	old := slog.Default()
	slog.SetDefault(slog.New(syslogWarnCapture16772{msgs: msgs}))
	t.Cleanup(func() { slog.SetDefault(old) })
	return msgs
}

func countDaemonUnboundWarns16772(msgs []string) int {
	n := 0
	for _, m := range msgs {
		if strings.Contains(m, "leaving the syslog source unbound") {
			n++
		}
	}
	return n
}

// Defect cell (probe shape): apply a default-shaped stream — IPv6
// collector, NO per-stream or global source-interface — through the
// real applySyslogConfig and count the #15078 WARN records. Pre-fix
// the fingerprints alone emitted it (rsi= and gsrc= terms); post-fix 0.
func TestApplySyslogConfigDefaultShapeNoUnboundWarn16772(t *testing.T) {
	msgs := captureDaemonSyslogWarns16772(t)
	er := logging.NewEventReader(nil, nil)
	cfg := syslogFamilyCfg15078("2001:db8:9::1", "", "", "tcp")
	d := &Daemon{}
	d.applySyslogConfig(er, cfg)
	clients := er.SyslogClients()
	if len(clients) != 1 {
		t.Fatalf("expected 1 syslog client after apply, got %d", len(clients))
	}
	defer clients[0].Close()
	if got := clients[0].SourceAddr(); got != "" {
		t.Errorf("default-shape stream bound source %q, want \"\" (unbound, kernel-chosen)", got)
	}
	if n := countDaemonUnboundWarns16772(*msgs); n != 0 {
		t.Errorf("captured %d #15078 unbound WARN(s) for a default-shaped stream, want 0 (#16772): %v", n, *msgs)
	}
	// Direct fingerprint probe: both hash helpers resolve unconditionally.
	msgs2 := captureDaemonSyslogWarns16772(t)
	if _, ok := syslogClientFingerprint(cfg); !ok {
		t.Fatalf("syslogClientFingerprint returned ok=false for a valid config")
	}
	_ = syslogStreamFingerprint15231(cfg, "audit", cfg.Security.Log.Streams["audit"], "", "tcp", "")
	if n := countDaemonUnboundWarns16772(*msgs2); n != 0 {
		t.Errorf("fingerprints captured %d #15078 unbound WARN(s), want 0 (#16772): %v", n, *msgs2)
	}
}

// Positive control: a CONFIGURED v4-only source-interface serving an
// IPv6 collector must still emit the #15078 WARN through the real
// apply path — the genuine signal must stay loud.
func TestApplySyslogConfigConfiguredWrongFamilyStillWarns16772(t *testing.T) {
	// syslogFamilyCfg15078's reth1.100 is dual-stack; add a v4-only unit
	// by pointing the stream at it via a dedicated config.
	cfg := syslogFamilyCfg15078("2001:db8:9::1", "reth1.100", "", "tcp")
	// Make reth1.100 v4-only for this cell.
	cfg.Interfaces.Interfaces["reth1"].Units[100].Addresses = []string{"10.0.1.20/24"}
	cfg.Interfaces.Interfaces["reth1"].Units[100].PrimaryAddress = "10.0.1.20/24"
	cfg.Interfaces.Interfaces["reth1"].Units[100].PreferredAddress = "10.0.1.20/24"
	// Clear any per-family v6 slots if the fixture/compiler populated them.
	cfg.Interfaces.Interfaces["reth1"].Units[100].PrimaryAddressV6 = ""
	cfg.Interfaces.Interfaces["reth1"].Units[100].PreferredAddressV6 = ""

	msgs := captureDaemonSyslogWarns16772(t)
	er := logging.NewEventReader(nil, nil)
	d := &Daemon{}
	d.applySyslogConfig(er, cfg)
	clients := er.SyslogClients()
	if len(clients) != 1 {
		t.Fatalf("expected 1 syslog client after apply, got %d", len(clients))
	}
	defer clients[0].Close()
	if n := countDaemonUnboundWarns16772(*msgs); n == 0 {
		t.Errorf("captured 0 #15078 unbound WARNs for a configured v4-only source-interface with an IPv6 collector, want >= 1 (positive control must stay loud): %v", *msgs)
	}
	_ = config.SyslogStream{}
}
