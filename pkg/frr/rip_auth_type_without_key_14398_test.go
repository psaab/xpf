package frr

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14398: renderer belt. A type-without-key RIP config arriving on the
// tolerant path must not silently render an unauthenticated RIP block:
// generateProtocols must warn loudly and emit no `network` activation
// (the interface is not enrolled in RIP) rather than `router rip` +
// `network <iface>` with zero auth lines. Keyed rendering is unchanged.

func TestRIPAuthTypeWithoutKeyRenderBelt14398(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(prev)

	m := New()
	rip := &config.RIPConfig{
		AuthType:   "md5",
		Interfaces: []string{"trust0"},
	}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, nil, nil)
	if strings.Contains(got, "ip rip authentication") {
		t.Errorf("type-without-key rendered auth lines:\n%s", got)
	}
	if strings.Contains(got, "network trust0") {
		t.Errorf("type-without-key silently enrolled trust0 in unauthenticated RIP (must fail closed, not render a no-auth block):\n%s", got)
	}
	if !strings.Contains(logs.String(), "14398") || !strings.Contains(logs.String(), "authentication-key") {
		t.Errorf("type-without-key render emitted no #14398 warning naming authentication-key; logs=%q rendered=\n%s", logs.String(), got)
	}
}

func TestRIPKeyedRenderUnchanged14398(t *testing.T) {
	m := New()
	for _, tc := range []struct {
		name string
		rip  *config.RIPConfig
		want []string
	}{
		{"keyed md5", &config.RIPConfig{AuthType: "md5", AuthKey: config.Secret("s3cret"), Interfaces: []string{"trust0"}},
			[]string{"router rip\n", " network trust0\n", " ip rip authentication mode md5\n", " ip rip authentication string s3cret\n"}},
		{"keyed simple", &config.RIPConfig{AuthType: "simple", AuthKey: config.Secret("s3cret"), Interfaces: []string{"trust0"}},
			[]string{"router rip\n", " network trust0\n", " ip rip authentication mode text\n", " ip rip authentication string s3cret\n"}},
		{"keyed text", &config.RIPConfig{AuthType: "text", AuthKey: config.Secret("s3cret"), Interfaces: []string{"trust0"}},
			[]string{" ip rip authentication mode text\n", " ip rip authentication string s3cret\n"}},
		{"neither leaf", &config.RIPConfig{Interfaces: []string{"trust0"}},
			[]string{"router rip\n", " network trust0\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := m.generateProtocols(nil, nil, nil, tc.rip, nil, "", 0, nil, nil)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("missing %q in:\n%s", w, got)
				}
			}
			if tc.name == "neither leaf" && strings.Contains(got, "ip rip authentication") {
				t.Errorf("neither-leaf rendered auth lines:\n%s", got)
			}
		})
	}
}
