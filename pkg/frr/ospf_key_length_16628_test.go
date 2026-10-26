package frr

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16628 (R3-A12-04): render belt. An OSPF MD5 key longer than 16
// bytes or a simple-password longer than 8 bytes arriving on the
// tolerant path must not be emitted: ospfd truncates it, so the
// rendered line churns on every frr-reload (delete-and-add) and the
// effective key diverges from the configuration. The renderer must
// withhold the over-long key fail-closed and warn, while keys at the
// bound render byte-identically to before.

func captureLogs16628(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &logs
}

func TestOSPFOverlongMD5KeyWithheld16628(t *testing.T) {
	logs := captureLogs16628(t)
	m := New()
	ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
		{Name: "ge-0/0/1.0", AuthType: "md5", AuthKeyID: 1, AuthKey: config.NewSecret("12345678901234567"),
			AuthMD5Keys: []config.OSPFMD5Key12186{{ID: 1, Key: config.NewSecret("12345678901234567")}}},
	}}}}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "interface ge-0/0/1.0") || strings.Contains(got, "ip ospf area") || strings.Contains(got, "message-digest-key") {
		t.Fatalf("over-long MD5 key activated the interface / rendered a truncating line:\n%s", got)
	}
	if !strings.Contains(logs.String(), "16628") {
		t.Errorf("over-long MD5 render emitted no #16628 warning; logs=%q rendered=\n%s", logs.String(), got)
	}
	if strings.Contains(logs.String(), "12345678901234567") {
		t.Errorf("warning leaks the key value; logs=%q", logs.String())
	}
	// 16 multi-byte runes are 32 bytes and must be withheld, even though
	// their rune count is still at ospfd's 16-byte boundary.
	logs.Reset()
	md5Over := strings.Repeat("é", 16)
	ospf.Areas[0].Interfaces[0].AuthKey = config.NewSecret(md5Over)
	ospf.Areas[0].Interfaces[0].AuthMD5Keys[0].Key = config.NewSecret(md5Over)
	got = m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "interface ge-0/0/1.0") || strings.Contains(got, "ip ospf area") || strings.Contains(got, "message-digest-key") {
		t.Fatalf("16-rune/32-byte MD5 key activated the interface / rendered a truncating line:\n%s", got)
	}
	if !strings.Contains(logs.String(), "16628") || strings.Contains(logs.String(), md5Over) {
		t.Errorf("multi-byte MD5 warning missing issue or leaks key: logs=%q", logs.String())
	}

	// Control: exactly 16 bytes renders byte-identically.
	logs.Reset()
	ospf.Areas[0].Interfaces[0].AuthKey = config.NewSecret("1234567890123456")
	ospf.Areas[0].Interfaces[0].AuthMD5Keys[0].Key = config.NewSecret("1234567890123456")
	got = m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	for _, w := range []string{"interface ge-0/0/1.0\n", " ip ospf authentication message-digest\n", " ip ospf message-digest-key 1 md5 1234567890123456\n", " ip ospf area 0.0.0.0\n"} {
		if !strings.Contains(got, w) {
			t.Errorf("16-char MD5 key lost %q:\n%s", w, got)
		}
	}
	// Control: the exact byte limit remains accepted with UTF-8 input.
	logs.Reset()
	md5AtByteLimit := strings.Repeat("é", 8)
	ospf.Areas[0].Interfaces[0].AuthKey = config.NewSecret(md5AtByteLimit)
	ospf.Areas[0].Interfaces[0].AuthMD5Keys[0].Key = config.NewSecret(md5AtByteLimit)
	got = m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, " ip ospf message-digest-key 1 md5 "+md5AtByteLimit+"\n") {
		t.Errorf("16-byte multi-byte MD5 key lost:\n%s", got)
	}
}

func TestOSPFOverlongSimplePasswordWithheld16628(t *testing.T) {
	logs := captureLogs16628(t)
	m := New()
	ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
		{Name: "ge-0/0/1.0", AuthType: "simple", AuthKey: config.NewSecret("123456789")}, // 9 chars
	}}}}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "interface ge-0/0/1.0") || strings.Contains(got, "ip ospf area") || strings.Contains(got, "authentication-key") {
		t.Fatalf("over-long simple-password activated the interface / rendered a truncating line:\n%s", got)
	}
	if !strings.Contains(logs.String(), "16628") {
		t.Errorf("over-long simple render emitted no #16628 warning; logs=%q rendered=\n%s", logs.String(), got)
	}
	if strings.Contains(logs.String(), "123456789") {
		t.Errorf("warning leaks the key value; logs=%q", logs.String())
	}
	// 8 multi-byte runes are 16 bytes and must be withheld.
	logs.Reset()
	simpleOver := strings.Repeat("é", 8)
	ospf.Areas[0].Interfaces[0].AuthKey = config.NewSecret(simpleOver)
	got = m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "interface ge-0/0/1.0") || strings.Contains(got, "ip ospf area") || strings.Contains(got, "authentication-key") {
		t.Fatalf("8-rune/16-byte simple-password activated the interface / rendered a truncating line:\n%s", got)
	}
	if !strings.Contains(logs.String(), "16628") || strings.Contains(logs.String(), simpleOver) {
		t.Errorf("multi-byte simple-password warning missing issue or leaks key: logs=%q", logs.String())
	}

	// Control: exactly 8 bytes renders byte-identically.
	logs.Reset()
	ospf.Areas[0].Interfaces[0].AuthKey = config.NewSecret("12345678")
	got = m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	for _, w := range []string{"interface ge-0/0/1.0\n", " ip ospf authentication\n", " ip ospf authentication-key 12345678\n", " ip ospf area 0.0.0.0\n"} {
		if !strings.Contains(got, w) {
			t.Errorf("8-char simple-password lost %q:\n%s", w, got)
		}
	}
	// Control: exactly 8 bytes is allowed with multi-byte input.
	logs.Reset()
	simpleAtByteLimit := strings.Repeat("é", 4)
	ospf.Areas[0].Interfaces[0].AuthKey = config.NewSecret(simpleAtByteLimit)
	got = m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, " ip ospf authentication-key "+simpleAtByteLimit+"\n") {
		t.Errorf("8-byte multi-byte simple-password lost:\n%s", got)
	}

	// Control: no auth at all still activates plain OSPF.
	plain := &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
		{Name: "ge-0/0/1.0"},
	}}}}
	got = m.generateProtocols(plain, nil, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "interface ge-0/0/1.0\n") || !strings.Contains(got, " ip ospf area 0.0.0.0\n") {
		t.Errorf("plain OSPF no longer activates:\n%s", got)
	}
}

// Rollover mix: the over-long entry is withheld, the valid entry
// still renders, and the interface stays up on the surviving key.
func TestOSPFOverlongRolloverMixKeepsValidKey16628(t *testing.T) {
	logs := captureLogs16628(t)
	ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
		{Name: "ge-0/0/1.0", AuthType: "md5", AuthKeyID: 2, AuthKey: config.NewSecret("1234567890123456"),
			AuthMD5Keys: []config.OSPFMD5Key12186{
				{ID: 1, Key: config.NewSecret("12345678901234567")}, // 17 — withheld
				{ID: 2, Key: config.NewSecret("1234567890123456")},  // 16 — renders
			}},
	}}}}
	got := New().generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "message-digest-key 1 ") || strings.Contains(got, "12345678901234567") {
		t.Fatalf("over-long rollover entry rendered:\n%s", got)
	}
	for _, w := range []string{"interface ge-0/0/1.0\n", " ip ospf message-digest-key 2 md5 1234567890123456\n", " ip ospf area 0.0.0.0\n"} {
		if !strings.Contains(got, w) {
			t.Errorf("valid rollover key lost %q:\n%s", w, got)
		}
	}
	if !strings.Contains(logs.String(), "16628") {
		t.Errorf("rollover mix emitted no #16628 warning; logs=%q", logs.String())
	}
}

// The VRF (routing-instance) render path shares generateProtocols
// with a vrf suffix; the belt must fire there too.
func TestOSPFOverlongKeyWithheldVRF16628(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
		{Name: "ge-0/0/1.0", AuthType: "simple", AuthKey: config.NewSecret("123456789")},
	}}}}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "VRF-A", 0, nil, nil)
	if strings.Contains(got, "interface ge-0/0/1.0") || strings.Contains(got, "authentication-key") {
		t.Fatalf("over-long VRF simple-password rendered:\n%s", got)
	}
	ospf.Areas[0].Interfaces[0].AuthKey = config.NewSecret("12345678")
	got = m.generateProtocols(ospf, nil, nil, nil, nil, "VRF-A", 0, nil, nil)
	if !strings.Contains(got, " ip ospf authentication-key 12345678\n") {
		t.Errorf("8-char VRF simple-password no longer renders:\n%s", got)
	}
}
