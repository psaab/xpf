package daemon

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
)

// #9165: the daemon-side reader for the remote-syslog drop counters.
func TestSyslogDropStatsReportsTheInstalledClients9165(t *testing.T) {
	er := &logging.EventReader{}
	c, err := logging.NewSyslogClientDeferred("203.0.113.7", 514, "", "tcp", nil)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	er.SetSyslogClients([]*logging.SyslogClient{c})

	d := &Daemon{eventReader: er}
	stats := d.syslogDropStats()
	if len(stats) != 1 {
		t.Fatalf("syslogDropStats returned %d rows, want 1", len(stats))
	}
	if stats[0].Protocol != "tcp" {
		t.Errorf("row protocol = %q, want tcp (%+v)", stats[0].Protocol, stats[0])
	}
	if stats[0].Sink != "security" {
		t.Errorf("stream row sink = %q, want security (%+v)", stats[0].Sink, stats[0])
	}
}

// A metrics scrape races daemon startup and every commit that rebuilds the
// client set, so both nil hops must be no-ops rather than panics.
func TestSyslogDropStatsIsNilSafe9165(t *testing.T) {
	if got := (*Daemon)(nil).syslogDropStats(); got != nil {
		t.Errorf("nil daemon returned %v", got)
	}
	if got := (&Daemon{}).syslogDropStats(); got != nil {
		t.Errorf("daemon with neither reader returned %v", got)
	}
	// #16769: a daemon with only a slog handler (no event reader) must not
	// panic and must report the system set (empty here).
	if got := (&Daemon{slogHandler: logging.NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))}).syslogDropStats(); got != nil {
		t.Errorf("daemon with only empty slog handler returned %v", got)
	}
}

// failingSyslogConn16769 fails every write, the shape of a dead collector.
type failingSyslogConn16769 struct{ net.Conn }

func (failingSyslogConn16769) Write([]byte) (int, error) {
	return 0, errors.New("connection refused")
}
func (failingSyslogConn16769) Close() error                  { return nil }
func (failingSyslogConn16769) SetWriteDeadline(time.Time) error { return nil }

// #16769: the system-host case. A `system syslog host` client installed
// through the real applySystemSyslog -> slogHandler.SetClients path, with a
// counted write drop, must surface as one sink="system" row with Writes>0.
// Pre-fix syslogDropStats read only the EventReader set, so this returned
// zero rows. The stream control (sink="security") must stay unchanged.
func TestSyslogDropStatsReportsSystemHost16769(t *testing.T) {
	d := &Daemon{
		eventReader: &logging.EventReader{},
		slogHandler: logging.NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil)),
	}
	t.Cleanup(func() { d.slogHandler.SetClients(nil) })

	// Stream control.
	stream, err := logging.NewSyslogClientDeferred("203.0.113.7", 514, "", "tcp", nil)
	if err != nil {
		t.Fatalf("stream client: %v", err)
	}
	d.eventReader.SetSyslogClients([]*logging.SyslogClient{stream})

	// System host via the real apply path: proves applySystemSyslog installs
	// through slogHandler.SetClients and the reader sees that set.
	cfg := &config.Config{}
	cfg.System.Syslog = &config.SystemSyslogConfig{
		Hosts: []*config.SyslogHostConfig{{Address: "127.0.0.1", Port: 1}},
	}
	d.applySystemSyslog(cfg)
	if got := len(d.slogHandler.Clients()); got != 1 {
		t.Fatalf("premise: applySystemSyslog installed %d system clients, want 1", got)
	}
	appliedAddr := d.slogHandler.Clients()[0].RemoteAddr()
	// Swap in a failing client so the write drop is deterministic, then
	// drive one slog record through the handler. NewSyslogClientWithConn
	// leaves RemoteAddr empty, so assert on the row the swap produces
	// rather than on the applied destination.
	sysClient := logging.NewSyslogClientWithConn(failingSyslogConn16769{}, "udp")
	d.slogHandler.SetClients([]*logging.SyslogClient{sysClient})
	if err := sysClient.Send(logging.SyslogInfo, "auth record"); err == nil {
		t.Fatal("premise: send to dead collector must fail")
	}
	if sysClient.DroppedWrites() == 0 {
		t.Fatal("premise: dead collector counted no write drop")
	}
	_ = appliedAddr

	stats := d.syslogDropStats()
	var sysRows, secRows []logging.SyslogDropStat
	for _, st := range stats {
		switch st.Sink {
		case "system":
			sysRows = append(sysRows, st)
		case "security":
			secRows = append(secRows, st)
		default:
			t.Errorf("row with unexpected sink %q: %+v", st.Sink, st)
		}
	}
	if len(sysRows) != 1 {
		t.Fatalf("system-host case yielded %d sink=system rows, want 1 (all rows: %+v)", len(sysRows), stats)
	}
	if sysRows[0].Writes == 0 {
		t.Errorf("system row Writes=0, want >0 (%+v)", sysRows[0])
	}
	if sysRows[0].Writes != sysClient.DroppedWrites() {
		t.Errorf("system row Writes=%d, want live client count %d (%+v)", sysRows[0].Writes, sysClient.DroppedWrites(), sysRows[0])
	}
	if len(secRows) != 1 || secRows[0].Protocol != "tcp" {
		t.Errorf("stream control changed: %+v", secRows)
	}
}

// #16769: counters stay cumulative per destination across rebuilds. Retiring
// a system client that counted drops and installing a fresh client for the
// same destination must not reset the exported count to the new client's
// (zero) value.
func TestSyslogDropStatsCumulativeAcrossRebuild16769(t *testing.T) {
	d := &Daemon{
		eventReader: &logging.EventReader{},
		slogHandler: logging.NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil)),
	}
	t.Cleanup(func() { d.slogHandler.SetClients(nil) })

	first := logging.NewSyslogClientWithConn(failingSyslogConn16769{}, "udp")
	d.slogHandler.SetClients([]*logging.SyslogClient{first})
	_ = first.Send(logging.SyslogInfo, "one")
	_ = first.Send(logging.SyslogInfo, "two")
	before := first.DroppedWrites()
	if before == 0 {
		t.Fatal("premise: first generation counted no drops")
	}

	// Rebuild: same destination (empty RemoteAddr on both fakes), fresh client.
	second := logging.NewSyslogClientWithConn(failingSyslogConn16769{}, "udp")
	d.slogHandler.SetClients([]*logging.SyslogClient{second})

	stats := d.syslogDropStats()
	if len(stats) != 1 {
		t.Fatalf("after rebuild got %d rows, want 1 (%+v)", len(stats), stats)
	}
	if stats[0].Writes != before {
		t.Errorf("counter reset across rebuild: got Writes=%d, want cumulative %d", stats[0].Writes, before)
	}
	_ = second.Send(logging.SyslogInfo, "three")
	stats = d.syslogDropStats()
	if len(stats) != 1 || stats[0].Writes != before+1 {
		t.Errorf("post-rebuild drop not cumulative: %+v, want Writes=%d", stats, before+1)
	}
}

// #16769: the same cumulative rule on the security-log (EventReader) set.
func TestSyslogDropStatsSecurityCumulativeAcrossRebuild16769(t *testing.T) {
	er := &logging.EventReader{}
	d := &Daemon{eventReader: er}

	first := logging.NewSyslogClientWithConn(failingSyslogConn16769{}, "udp")
	er.ReplaceSyslogClients([]*logging.SyslogClient{first})
	_ = first.Send(logging.SyslogInfo, "one")
	before := first.DroppedWrites()
	if before == 0 {
		t.Fatal("premise: first generation counted no drops")
	}
	second := logging.NewSyslogClientWithConn(failingSyslogConn16769{}, "udp")
	er.ReplaceSyslogClients([]*logging.SyslogClient{second})

	stats := d.syslogDropStats()
	if len(stats) != 1 || stats[0].Sink != "security" || stats[0].Writes != before {
		t.Fatalf("security counter reset across rebuild: %+v, want one security row Writes=%d", stats, before)
	}
}
