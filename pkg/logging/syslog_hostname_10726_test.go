package logging

import (
	"bufio"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const hostileHostname10726 = "edge\nforged host\x1b"
const safeHostname10726 = "edge_forged_host_"

func sendSyslogAndReadFrame10726(t *testing.T, format string) string {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	client := NewSyslogClientWithConn(clientConn, "tcp")
	client.Format = format
	client.hostname = hostileHostname10726
	t.Cleanup(func() {
		_ = client.Close()
		_ = serverConn.Close()
	})
	if err := serverConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	sendErr := make(chan error, 1)
	go func() { sendErr <- client.Send(SyslogInfo, "health check") }()

	reader := bufio.NewReader(serverConn)
	prefix, err := reader.ReadString(' ')
	if err != nil {
		t.Fatalf("read RFC 6587 length prefix: %v", err)
	}
	length, err := strconv.Atoi(strings.TrimSpace(prefix))
	if err != nil || length < 0 {
		t.Fatalf("invalid RFC 6587 length prefix %q: %v", prefix, err)
	}
	frame := make([]byte, length)
	if _, err := io.ReadFull(reader, frame); err != nil {
		t.Fatalf("read syslog frame: %v", err)
	}
	if err := <-sendErr; err != nil {
		t.Fatalf("Send: %v", err)
	}
	return string(frame)
}

// TestSyslogHostnameCannotForgeFraming10726 exercises both network formats at
// the final frame boundary. Before sanitization, an OS hostname containing LF
// could inject an RFC 3164 record and whitespace could alter HOSTNAME/APP-NAME
// framing; the same raw value was also emitted in RFC 5424.
func TestSyslogHostnameCannotForgeFraming10726(t *testing.T) {
	for _, format := range []string{"", "sd-syslog"} {
		t.Run(map[string]string{"": "rfc3164", "sd-syslog": "rfc5424"}[format], func(t *testing.T) {
			frame := sendSyslogAndReadFrame10726(t, format)
			if strings.Contains(frame, hostileHostname10726) || strings.ContainsAny(frame, "\r\n\x1b") {
				t.Fatalf("unsafe hostname/control byte reached syslog frame: %q", frame)
			}
			if !strings.Contains(frame, " "+safeHostname10726+" ") {
				t.Fatalf("sanitized hostname not present as one framing token: %q", frame)
			}
			if strings.Contains(frame, "forged host") {
				t.Fatalf("hostname whitespace changed framing fields: %q", frame)
			}
		})
	}
}

// TestLocalSyslogHostnameCannotForgeFraming10726 pins the independent local
// RFC 5424 envelope path; fixing SyslogClient alone would leave the local
// security log framing the raw hostname.
func TestLocalSyslogHostnameCannotForgeFraming10726(t *testing.T) {
	path := filepath.Join(t.TempDir(), "security.log")
	writer, err := NewLocalLogWriter(LocalLogConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	writer.Format = "sd-syslog"
	writer.hostname = hostileHostname10726
	if err := writer.Send(SyslogInfo, "health check"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := string(got)
	if strings.Contains(line, hostileHostname10726) || strings.ContainsAny(line, "\r\x1b") {
		t.Fatalf("unsafe hostname/control byte reached local syslog frame: %q", line)
	}
	if strings.Count(line, "\n") != 1 || !strings.Contains(line, " "+safeHostname10726+" ") {
		t.Fatalf("local RFC 5424 frame not single-line with sanitized hostname: %q", line)
	}
}

func TestSanitizeSyslogHostnameToken10726(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"router.example", "router.example"},
		{"2001:db8::1", "2001:db8::1"},
		{"bad host", "bad_host"},
		{"", "xpf"},
	} {
		if got := sanitizeSyslogHostname(tc.input); got != tc.want {
			t.Errorf("sanitizeSyslogHostname(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
