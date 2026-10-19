package logging

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// #15231 A47-02: hostname must be read per Send, not captured at construction.
// RED on revert: restoring s.hostname capture makes second frame carry old name.
func TestSyslogHostnameReadPerSend15231(t *testing.T) {
	prev := syslogHostnameFn
	syslogHostnameFn = func() (string, error) { return "old-name", nil }
	t.Cleanup(func() { syslogHostnameFn = prev })

	clientConn, serverConn := net.Pipe()
	client := NewSyslogClientWithConn(clientConn, "tcp")
	t.Cleanup(func() { _ = client.Close(); _ = serverConn.Close() })
	_ = serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))

	readFrame := func() string {
		reader := bufio.NewReader(serverConn)
		prefix, err := reader.ReadString(' ')
		if err != nil {
			t.Fatalf("read prefix: %v", err)
		}
		n, err := strconv.Atoi(strings.TrimSpace(prefix))
		if err != nil {
			t.Fatalf("prefix %q: %v", prefix, err)
		}
		frame := make([]byte, n)
		if _, err := io.ReadFull(reader, frame); err != nil {
			t.Fatalf("read frame: %v", err)
		}
		return string(frame)
	}
	// net.Pipe is synchronous: Send and read must overlap.
	sendAndRead := func() string {
		errCh := make(chan error, 1)
		go func() { errCh <- client.Send(SyslogInfo, "hello") }()
		f := readFrame()
		if err := <-errCh; err != nil {
			t.Fatalf("Send: %v", err)
		}
		return f
	}
	if f := sendAndRead(); !strings.Contains(f, " old-name ") {
		t.Fatalf("first frame must carry old-name, got %q", f)
	}
	syslogHostnameFn = func() (string, error) { return "new-name", nil }
	if f := sendAndRead(); !strings.Contains(f, " new-name ") || strings.Contains(f, "old-name") {
		t.Fatalf("#15231 A47-02: second frame must carry new-name after rename, got %q", f)
	}
}

// #15231 A47-03: debug records must map to SyslogDebug (7), not SyslogInfo (6).
func TestSlogLevelToSyslogDebug15231(t *testing.T) {
	cases := []struct {
		level slog.Level
		want  int
	}{
		{slog.LevelDebug, SyslogDebug},
		{slog.LevelDebug - 4, SyslogDebug},
		{slog.LevelInfo, SyslogInfo},
		{slog.LevelWarn, SyslogWarning},
		{slog.LevelError, SyslogError},
	}
	for _, tc := range cases {
		if got := slogLevelToSyslog(tc.level); got != tc.want {
			t.Errorf("slogLevelToSyslog(%v)=%d want %d", tc.level, got, tc.want)
		}
	}
	// Filter consequence: an info host (MinSeverity=SyslogInfo) must not receive debug.
	c := &SyslogClient{MinSeverity: SyslogInfo}
	if c.ShouldSend(SyslogDebug) {
		t.Fatal("info host must not receive debug record")
	}
	// A debug host receives debug at PRI <31> for local0: 16*8+7=135? check: facility local0=16 => 135.
	// Wire PRI verified via Send in handler tests; here severity value is decisive.
	if got := slogLevelToSyslog(slog.LevelDebug); got != 7 {
		t.Fatalf("debug severity=%d want 7 (<31> is daemon debug; stream PRI uses its facility)", got)
	}
}
