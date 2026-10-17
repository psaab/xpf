package logging

import (
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

// filter_log_system_syslog_14612_test.go — #14612 (residual of #6859).
//
// #6859 gated the EventReader's OWN syslog fan-out (er.syslogClients, the
// `security log` stream clients), but logEvent emits the daemon
// "firewall event" slog line BEFORE that gate. In the daemon that line
// goes to slog.Default(), a SyslogSlogHandler whose clients are the
// `system syslog host` collectors (pkg/daemon applySystemSyslog ->
// slogHandler.SetClients). The handler forwarded every record by
// severity alone, so a `then log`-only FILTER_LOG hit still left the box
// via system syslog even though the stream sink was correctly gated.
//
// These cells wire BOTH sinks the way the daemon does — one UDP collector
// as the EventReader stream client and a second, distinct UDP collector
// as the SyslogSlogHandler (system syslog) client, with the handler
// installed as slog.Default() — and assert at the wire which collector
// receives the hit. Distinct collectors matter: sharing one would let
// the stream fan-out mask the slog leak (and vice versa).

// systemCollector14612 wires an EventReader with two distinct UDP
// collectors: streamPC backs the EventReader's security-log stream
// client, systemPC backs the SyslogSlogHandler installed as
// slog.Default() (the `system syslog host` sink). It also returns the
// event buffer backing `show security log`.
func systemCollector14612(t *testing.T) (reader *EventReader, buffer *EventBuffer, streamPC, systemPC net.PacketConn, handler *SyslogSlogHandler) {
	t.Helper()

	streamPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { streamPC.Close() })
	systemPC, err = net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { systemPC.Close() })

	streamAddr := streamPC.LocalAddr().(*net.UDPAddr)
	streamClient, err := NewSyslogClient("127.0.0.1", streamAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { streamClient.Close() })

	systemAddr := systemPC.LocalAddr().(*net.UDPAddr)
	systemClient, err := NewSyslogClient("127.0.0.1", systemAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	// MinSeverity 0 == Junos `any any`: every severity passes, mirroring
	// the collector in the acceptance criterion.
	systemClient.MinSeverity = 0
	t.Cleanup(func() { systemClient.Close() })

	handler = NewSyslogSlogHandler(slog.NewTextHandler(io.Discard, nil))
	handler.SetClients([]*SyslogClient{systemClient})
	t.Cleanup(handler.Close)
	withSlogDefault(t, handler)

	buffer = NewEventBuffer(16)
	reader = NewEventReader(nil, buffer)
	reader.SetSyslogClients([]*SyslogClient{streamClient})
	return reader, buffer, streamPC, systemPC, handler
}

// collectorDatagram14612 returns the datagram a collector received, or ""
// if none arrived within the wait bound. The EventReader -> handler ->
// SendFromEventReader path is queued per client, so a short wait is
// required even for a datagram that is coming; the bound is a wait, not
// a timing assertion.
func collectorDatagram14612(t *testing.T, pc net.PacketConn) string {
	t.Helper()
	if err := pc.SetReadDeadline(time.Now().Add(600 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, _, err := pc.ReadFrom(buf)
	if err == nil {
		return string(buf[:n])
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return ""
	}
	t.Fatalf("collector read failed for a reason other than timeout: %v", err)
	return ""
}

// TestThenLogDoesNotReachSystemSyslog14612 is the issue: with a
// `then log`-only term (empty non-nil map) and a `system syslog host ..
// any any` client, a FILTER_LOG event produces NO datagram at the system
// collector, while `show security log` (the buffer) is unchanged.
func TestThenLogDoesNotReachSystemSyslog14612(t *testing.T) {
	reader, buffer, _, systemPC, _ := systemCollector14612(t)
	reader.SetFilterTermSyslog(map[uint64]bool{})

	if ok := reader.ProcessRawEvent(rawFilterLogFrame6859(0, 0)); !ok {
		t.Fatal("ProcessRawEvent returned false")
	}

	if got := collectorDatagram14612(t, systemPC); got != "" {
		t.Fatalf("a `then log`-only FILTER_LOG hit reached the `system syslog host` "+
			"collector via the daemon slog line (#14612): %q", got)
	}

	recs := buffer.Latest(16)
	if len(recs) != 1 {
		t.Fatalf("`show security log` shows %d records, want 1 — suppressing the "+
			"system-syslog copy must not blind the local surface (#14612)", len(recs))
	}
	if recs[0].Type != "FILTER_LOG" {
		t.Fatalf("local record Type = %q, want FILTER_LOG", recs[0].Type)
	}
}

// TestThenSyslogStillReachesSystemSyslog14612 is the paired control: a
// `then syslog` term's FILTER_LOG hit is NOT suppressed — it still
// reaches the system collector via the slog line (and the stream
// collector via the EventReader fan-out). Without it, "suppress every
// FILTER_LOG slog copy" would pass the cell above.
func TestThenSyslogStillReachesSystemSyslog14612(t *testing.T) {
	reader, _, streamPC, systemPC, _ := systemCollector14612(t)
	reader.SetFilterTermSyslog(map[uint64]bool{FilterTermSyslogKey(0, 1): true})

	if ok := reader.ProcessRawEvent(rawFilterLogFrame6859(0, 1)); !ok {
		t.Fatal("ProcessRawEvent returned false")
	}

	if got := collectorDatagram14612(t, systemPC); got == "" {
		t.Fatal("a `then syslog` FILTER_LOG hit did NOT reach the `system syslog host` " +
			"collector — the #14612 suppression is over-broad")
	} else if !strings.Contains(got, "FILTER_LOG") {
		t.Fatalf("system collector datagram does not name FILTER_LOG: %q", got)
	}
	if got := collectorDatagram14612(t, streamPC); got == "" {
		t.Fatal("a `then syslog` FILTER_LOG hit did NOT reach the security-log stream " +
			"collector — the #6859 stream routing regressed")
	}
}

// TestSystemSyslogGateDiscriminatesOnTerm14612 proves the suppression
// keys on the term identity through BOTH sinks on one reader with one
// map: term 6 (log-only) reaches neither collector, term 7
// (`then syslog`) reaches both.
func TestSystemSyslogGateDiscriminatesOnTerm14612(t *testing.T) {
	reader, _, streamPC, systemPC, _ := systemCollector14612(t)
	reader.SetFilterTermSyslog(map[uint64]bool{FilterTermSyslogKey(3, 7): true})

	if ok := reader.ProcessRawEvent(rawFilterLogFrame6859(3, 6)); !ok {
		t.Fatal("ProcessRawEvent returned false")
	}
	if got := collectorDatagram14612(t, systemPC); got != "" {
		t.Fatalf("term 6 (log-only) reached the system collector while term 7 is the "+
			"only syslog term — suppression is not keyed on term identity: %q", got)
	}
	if got := collectorDatagram14612(t, streamPC); got != "" {
		t.Fatalf("term 6 (log-only) reached the stream collector: %q", got)
	}

	if ok := reader.ProcessRawEvent(rawFilterLogFrame6859(3, 7)); !ok {
		t.Fatal("ProcessRawEvent returned false")
	}
	if got := collectorDatagram14612(t, systemPC); got == "" {
		t.Fatal("term 7 (`then syslog`) did not reach the system collector")
	}
	if got := collectorDatagram14612(t, streamPC); got == "" {
		t.Fatal("term 7 (`then syslog`) did not reach the stream collector")
	}
}

// TestUnwiredMapStillReachesSystemSyslog14612 pins the nil-vs-empty
// contract on the slog sink: nil means "never wired" and must preserve
// the legacy fan-out, exactly as on the stream sink (#6859).
func TestUnwiredMapStillReachesSystemSyslog14612(t *testing.T) {
	reader, _, _, systemPC, _ := systemCollector14612(t)
	// Deliberately NOT calling SetFilterTermSyslog.

	if ok := reader.ProcessRawEvent(rawFilterLogFrame6859(0, 0)); !ok {
		t.Fatal("ProcessRawEvent returned false")
	}
	if got := collectorDatagram14612(t, systemPC); got == "" {
		t.Fatal("with no map wired, the FILTER_LOG slog copy must still reach the " +
			"system collector — nil is 'not wired', not 'suppress everything'")
	}
}

// TestNonFilterEventsStillReachSystemSyslog14612 bounds the blast
// radius: the suppression is FILTER_LOG-only. A SESSION_CLOSE slog copy
// still reaches the system collector even with an empty (suppress-all
// FILTER_LOG) map installed.
func TestNonFilterEventsStillReachSystemSyslog14612(t *testing.T) {
	reader, _, _, systemPC, _ := systemCollector14612(t)
	reader.SetFilterTermSyslog(map[uint64]bool{})

	if ok := reader.ProcessRawEvent(rawSessionFrame(eventTypeSessionClose, 1)); !ok {
		t.Fatal("ProcessRawEvent returned false")
	}
	if got := collectorDatagram14612(t, systemPC); got == "" {
		t.Fatal("a SESSION_CLOSE slog copy was suppressed by the FILTER_LOG gate — " +
			"the #14612 suppression must apply to FILTER_LOG only")
	} else if !strings.Contains(got, "SESSION_CLOSE") {
		t.Fatalf("system collector datagram does not name SESSION_CLOSE: %q", got)
	}
}

// TestOrdinarySlogStillReachesSystemSyslog14612 pins that only
// EventReader FILTER_LOG records marked suppressed are withheld: an
// ordinary daemon slog record through the same handler still forwards.
func TestOrdinarySlogStillReachesSystemSyslog14612(t *testing.T) {
	_, _, _, systemPC, _ := systemCollector14612(t)

	slog.Info("ordinary daemon record 14612")
	if got := collectorDatagram14612(t, systemPC); got == "" {
		t.Fatal("an ordinary slog record did not reach the system collector — the " +
			"#14612 suppression leaked beyond EventReader FILTER_LOG records")
	} else if !strings.Contains(got, "ordinary daemon record 14612") {
		t.Fatalf("system collector datagram is not the ordinary record: %q", got)
	}
}
