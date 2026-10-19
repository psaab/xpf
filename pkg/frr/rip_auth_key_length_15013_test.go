package frr

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15013 (A12-01): render belt. A RIP key longer than 16 characters
// arriving on the tolerant path must not be emitted: ripd rejects
// `ip rip authentication string <17+ chars>` on every frr-reload, so
// the reload never converges. The renderer must omit RIP enrollment
// entirely (no `router rip`, no `network`, no auth lines) and warn,
// while a 16-character key renders byte-identically to before.

func TestRIPOverlongKeyDoesNotEnroll15013(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(prev)

	m := New()
	rip := &config.RIPConfig{
		AuthType:   "md5",
		AuthKey:    config.Secret("12345678901234567"), // 17 chars
		Interfaces: []string{"trust0"},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, nil, nil)
	if strings.Contains(got, "network trust0") || strings.Contains(got, "ip rip authentication") || strings.Contains(got, "router rip") {
		t.Fatalf("over-long RIP key enrolled trust0 / rendered a line ripd rejects forever:\n%s", got)
	}
	if !strings.Contains(logs.String(), "15013") {
		t.Errorf("over-long render emitted no #15013 warning; logs=%q rendered=\n%s", logs.String(), got)
	}
	if strings.Contains(logs.String(), "12345678901234567") {
		t.Errorf("warning leaks the key value; logs=%q", logs.String())
	}

	// Control: exactly 16 characters enrolls with mode + string.
	logs.Reset()
	rip.AuthKey = config.Secret("1234567890123456")
	got = m.generateProtocols(nil, nil, nil, rip, nil, "", 0, nil, nil)
	for _, w := range []string{"router rip\n", " network trust0\n", " ip rip authentication mode md5\n", " ip rip authentication string 1234567890123456\n"} {
		if !strings.Contains(got, w) {
			t.Errorf("16-char RIP key lost %q:\n%s", w, got)
		}
	}

	// Control: 16-char simple/text key also enrolls.
	rip.AuthType = "simple"
	got = m.generateProtocols(nil, nil, nil, rip, nil, "", 0, nil, nil)
	for _, w := range []string{" ip rip authentication mode text\n", " ip rip authentication string 1234567890123456\n"} {
		if !strings.Contains(got, w) {
			t.Errorf("16-char simple RIP key lost %q:\n%s", w, got)
		}
	}

	// Control: no auth at all still enrolls plain RIP.
	rip.AuthType, rip.AuthKey = "", ""
	got = m.generateProtocols(nil, nil, nil, rip, nil, "", 0, nil, nil)
	if !strings.Contains(got, " network trust0\n") || strings.Contains(got, "ip rip authentication") {
		t.Errorf("plain RIP no longer enrolls cleanly:\n%s", got)
	}
}

// The VRF (routing-instance) render path shares generateProtocols with
// a vrf suffix; the belt must fire there too.
func TestRIPOverlongKeyDoesNotEnrollVRF15013(t *testing.T) {
	m := New()
	rip := &config.RIPConfig{
		AuthType:   "md5",
		AuthKey:    config.Secret("12345678901234567"),
		Interfaces: []string{"trust0"},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "VRF-A", 0, nil, nil)
	if strings.Contains(got, "network trust0") || strings.Contains(got, "ip rip authentication") {
		t.Fatalf("over-long VRF RIP key enrolled trust0:\n%s", got)
	}
	rip.AuthKey = config.Secret("1234567890123456")
	got = m.generateProtocols(nil, nil, nil, rip, nil, "VRF-A", 0, nil, nil)
	if !strings.Contains(got, " network trust0\n") || !strings.Contains(got, " ip rip authentication string 1234567890123456\n") {
		t.Errorf("16-char VRF RIP key no longer enrolls:\n%s", got)
	}
}
