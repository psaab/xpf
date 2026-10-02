package frr

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestOSPFAuthTokenFirst11462(t *testing.T) {
	for _, tc := range []struct {
		name      string
		authType  string
		key       config.Secret
		modeLine  string
		keyPrefix string
		keyLine   string
		wantWarn  bool
	}{
		{
			name:     "md5 whitespace key",
			authType: "md5", key: " \t ",
			modeLine:  " ip ospf authentication message-digest\n",
			keyPrefix: " ip ospf message-digest-key ", wantWarn: true,
		},
		{
			name:     "md5 valid key",
			authType: "md5", key: "s3cret",
			modeLine:  " ip ospf authentication message-digest\n",
			keyPrefix: " ip ospf message-digest-key ",
			keyLine:   " ip ospf message-digest-key 1 md5 s3cret\n",
		},
		{
			name:     "simple whitespace key",
			authType: "simple", key: " \t ",
			modeLine:  " ip ospf authentication\n",
			keyPrefix: " ip ospf authentication-key ", wantWarn: true,
		},
		{
			name:     "simple valid key",
			authType: "simple", key: "s3cret",
			modeLine:  " ip ospf authentication\n",
			keyPrefix: " ip ospf authentication-key ",
			keyLine:   " ip ospf authentication-key s3cret\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			defer slog.SetDefault(previous)

			ospf := &config.OSPFConfig{RouterID: "1.1.1.1", Areas: []*config.OSPFArea{{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFInterface{{
					Name: "eth0", AuthType: tc.authType, AuthKey: tc.key,
				}},
			}}}
			m := New()
			got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
			if tc.wantWarn {
				if count := strings.Count(logs.String(), "OMITTING a routing authentication line"); count != 1 {
					t.Errorf("warning count = %d, want exactly one; logs: %s", count, logs.String())
				}
				if strings.Contains(logs.String(), string(tc.key)) {
					t.Errorf("warning exposed secret: %s", logs.String())
				}
				if strings.Contains(got, tc.modeLine) || strings.Contains(got, tc.keyPrefix) {
					t.Errorf("invalid key emitted auth mode or key line:\n%s", got)
				}
				return
			}
			if !strings.Contains(got, tc.modeLine) || !strings.Contains(got, tc.keyLine) {
				t.Errorf("valid key must emit both mode and key lines:\n%s", got)
			}
			if strings.Contains(logs.String(), "OMITTING a routing authentication line") {
				t.Errorf("valid key unexpectedly warned: %s", logs.String())
			}
		})
	}
}
