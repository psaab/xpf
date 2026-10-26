package snmp

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #4302 (follow-up to #4289 S-3): two pre-existing debug log lines in agent.go
// echoed the SNMP v2c community string — the shared secret. Even at debug
// level, logging the secret increases accidental exposure (journald, log
// shipping). The scrub logs the request SOURCE (and a non-secret authorization
// level / known-community boolean) instead of the community value, matching the
// #4289 source-denied log.
//
// RED-on-revert: with the pre-#4302 code, the community value is written to the
// log record and these assertions fail (the secret leaks).

// captureDebugLog installs a Debug-level text handler as the default slog
// logger for the duration of fn and returns everything it emitted.
func captureDebugLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)
	fn()
	return buf.String()
}

// The invalid-community (unknown community) drop must NOT log the community
// value; it must log the source and known_community=false.
func TestV2cInvalidCommunityLogDoesNotLeakSecret(t *testing.T) {
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"public": {Name: "public", Authorization: "read-only"},
		},
	})

	const secret = "s3cr3t-unknown-community"
	pkt := buildV2cGetRequest(secret, 1, oidSysDescr)
	src := net.ParseIP("198.51.100.7")

	out := captureDebugLog(t, func() {
		if resp := a.handlePacketFrom(pkt, src); resp != nil {
			t.Fatal("GET with an unknown community must be dropped (nil response)")
		}
	})

	if !strings.Contains(out, "SNMP: invalid community") {
		t.Fatalf("expected the invalid-community debug line to fire; got: %q", out)
	}
	if strings.Contains(out, secret) {
		t.Fatalf("invalid-community log LEAKED the community secret %q: %q", secret, out)
	}
	if !strings.Contains(out, "198.51.100.7") {
		t.Fatalf("invalid-community log should record the source IP; got: %q", out)
	}
}

// The SET-denied (read-only community, not authorized for write) log must NOT
// log the community value; it logs the source and the non-secret authorization.
func TestV2cSetDeniedLogDoesNotLeakSecret(t *testing.T) {
	const secret = "s3cr3t-readonly-community"
	a := NewAgent(&config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			secret: {Name: secret, Authorization: "read-only"},
		},
	})

	pkt := buildV2cSetRequest(secret, 7, oidSysContact)
	src := net.ParseIP("198.51.100.9")

	out := captureDebugLog(t, func() {
		// A read-only community is denied write (noAccess), a non-nil response.
		if resp := a.handlePacketFrom(pkt, src); resp == nil {
			t.Fatal("SET from a read-only community should return a denial response, not nil")
		}
	})

	if !strings.Contains(out, "SET denied") {
		t.Fatalf("expected the SET-denied debug line to fire; got: %q", out)
	}
	if strings.Contains(out, secret) {
		t.Fatalf("SET-denied log LEAKED the community secret %q: %q", secret, out)
	}
	if !strings.Contains(out, "198.51.100.9") {
		t.Fatalf("SET-denied log should record the source IP; got: %q", out)
	}
}

// The trap-group name IS the v1/v2c trap community (#15052/#16728), so trap
// lifecycle logs must not emit it. RED-on-revert: restoring job.group to the
// slog "group" field leaks the configured community in this stopped-drop path.
func TestTrapGroupNameNotLoggedOnStoppedDrop(t *testing.T) {
	const secret = "s3cr3t-trap-group"
	a := &Agent{
		cfg: &config.SNMPConfig{
			TrapGroups: map[string]*config.SNMPTrapGroup{
				secret: {Name: secret, Targets: []string{"192.0.2.9:162"}, Version: "v1"},
			},
		},
		stopped: true,
	}

	out := captureDebugLog(t, func() {
		a.NotifyLinkDown(3, "ge-0-0-1", true)
	})

	if !strings.Contains(out, "SNMP trap dropped: agent stopped") {
		t.Fatalf("expected stopped-drop warning to fire; got: %q", out)
	}
	if strings.Contains(out, secret) {
		t.Fatalf("trap log LEAKED trap-group community %q: %q", secret, out)
	}
	if !strings.Contains(out, config.SecretDataPlaceholder) {
		t.Fatalf("trap log should retain a redacted group field; got: %q", out)
	}
	if !strings.Contains(out, "192.0.2.9:162") {
		t.Fatalf("trap log should retain target; got: %q", out)
	}
}
