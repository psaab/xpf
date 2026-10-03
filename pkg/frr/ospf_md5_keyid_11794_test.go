package frr

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #11794: renderer belt for configs that bypass the strict schema/compiler
// gates (legacy tolerant loads and externally-assembled configs). There is no
// implicit key-id 1: malformed/out-of-range IDs omit BOTH auth lines, while
// both legal boundaries are rendered exactly as configured.
func TestOSPFFRRNeverFabricatesOrEmitsInvalidMD5KeyID11794(t *testing.T) {
	for _, tc := range []struct {
		name    string
		keyID   int
		valid   bool
		wantKey string
	}{
		{name: "unset", keyID: 0},
		{name: "negative", keyID: -5},
		{name: "over-255", keyID: 256},
		{name: "far-over-255", keyID: 999},
		{name: "minimum", keyID: 1, valid: true, wantKey: "ip ospf message-digest-key 1 md5 key11794"},
		{name: "maximum", keyID: 255, valid: true, wantKey: "ip ospf message-digest-key 255 md5 key11794"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			defer slog.SetDefault(previous)

			ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFInterface{{
					Name: "eth0", AuthType: "md5", AuthKey: "key11794", AuthKeyID: tc.keyID,
				}},
			}}}
			got := New().generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
			if tc.valid {
				if !strings.Contains(got, "ip ospf authentication message-digest") || !strings.Contains(got, tc.wantKey) {
					t.Fatalf("valid key-id %d did not render the configured ID and auth mode:\n%s", tc.keyID, got)
				}
				if strings.Contains(logs.String(), "invalid key-id") {
					t.Fatalf("valid key-id %d unexpectedly warned: %s", tc.keyID, logs.String())
				}
				return
			}
			if strings.Contains(got, "ip ospf authentication message-digest") || strings.Contains(got, "ip ospf message-digest-key") {
				t.Fatalf("invalid key-id %d emitted MD5 auth or fabricated an ID:\n%s", tc.keyID, got)
			}
			if !strings.Contains(logs.String(), "invalid key-id") || !strings.Contains(logs.String(), "interface=eth0") {
				t.Fatalf("invalid key-id %d did not produce a scoped warning: %s", tc.keyID, logs.String())
			}
			if strings.Contains(logs.String(), "key11794") {
				t.Fatalf("warning exposed the MD5 secret: %s", logs.String())
			}
		})
	}
}
