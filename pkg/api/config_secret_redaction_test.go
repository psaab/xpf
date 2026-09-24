package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// secretSentinels is the set of distinctive cleartext secret values fed into
// the candidate config below — one per secret-bearing config field (#2053).
// The regression assertion is that NONE of these strings appears in the JSON
// returned by GET /api/v1/config, while the redaction sentinel does. Each
// value is unique so a single leaking field is identifiable.
var secretSentinels = []string{
	"LEAK-IKE-PSK",            // IKEPolicy.PSK
	"LEAK-IPSEC-VPN-PSK",      // IPsecVPN.PSK (legacy vpn-level)
	"LEAK-OSPF-AUTHKEY",       // OSPFInterface.AuthKey
	"LEAK-RIP-AUTHKEY",        // RIPConfig.AuthKey
	"LEAK-ISIS-AREA-AUTHKEY",  // ISISConfig.AuthKey
	"LEAK-ISIS-IFACE-AUTHKEY", // ISISInterface.AuthKey
	"LEAK-BGP-AUTHPW",         // BGPNeighbor.AuthPassword (group-level)
	"LEAK-API-USER-PW",        // APIAuthUser.Password
	"LEAK-API-KEY-TOKEN",      // APIAuthConfig.APIKeys
	"LEAK-SNMPV3-AUTHPW",      // SNMPv3User.AuthPassword
	"LEAK-SNMPV3-PRIVPW",      // SNMPv3User.PrivPassword
	"LEAK-SNMP-COMMUNITY",     // SNMPCommunity.Name (v1/v2c community string)
}

// crypt(3) hashes are validated by the commit gate, so the root/login
// EncryptedPassword sentinels must be well-formed $6$ hashes. They are
// still secrets that must not leak.
const (
	rootCryptSentinel  = "$6$LEAKsalt$rootHASHrootHASHrootHASHrootHASHrootHASHrootHASHrootHASHrootHASHro0"
	loginCryptSentinel = "$6$LEAKsalt$loginHASHloginHASHloginHASHloginHASHloginHASHloginHASHloginHASHl1"
	tsigSecretSentinel = "LEAKTSIGc2VjcmV0"                                                 // RFC2136 TSIG HMAC key (base64-ish)
	wgPrivkeySentinel  = "a01010101010101010101010101010101010101010101010101010101010101a" // 64-hex X25519 privkey
)

// secretSetCommands stages every secret-bearing config leaf with a
// distinctive cleartext sentinel so a single compile + GET /api/v1/config
// round-trip exercises the whole redaction surface.
var secretSetCommands = []string{
	// IKE pre-shared key (policy-level).
	"set security ike proposal ike-p1 authentication-method pre-shared-keys",
	"set security ike proposal ike-p1 encryption-algorithm aes-256-cbc",
	"set security ike proposal ike-p1 dh-group group14",
	"set security ike policy pol1 mode main",
	"set security ike policy pol1 proposals ike-p1",
	"set security ike policy pol1 pre-shared-key ascii-text LEAK-IKE-PSK",
	"set security ike gateway gw1 address 10.0.0.1",
	"set security ike gateway gw1 ike-policy pol1",
	"set security ike gateway gw1 external-interface ge-0-0-0",
	// IPsec VPN with a legacy vpn-level PSK.
	"set security ipsec proposal aes256 protocol esp",
	"set security ipsec proposal aes256 encryption-algorithm aes-256-cbc",
	"set security ipsec proposal aes256 authentication-algorithm hmac-sha-256",
	"set security ipsec proposal aes256 dh-group 14",
	"set security ipsec vpn site-a gateway 10.0.0.1",
	"set security ipsec vpn site-a bind-interface st0",
	"set security ipsec vpn site-a ipsec-policy aes256",
	"set security ipsec vpn site-a pre-shared-key LEAK-IPSEC-VPN-PSK",
	// OSPF interface auth key.
	"set protocols ospf area 0.0.0.0 interface ge-0-0-1 authentication md5 1 key LEAK-OSPF-AUTHKEY",
	// RIP auth key.
	"set protocols rip neighbor ge-0-0-1",
	"set protocols rip authentication-type md5",
	"set protocols rip authentication-key LEAK-RIP-AUTHKEY",
	// IS-IS area + per-interface auth keys.
	"set protocols isis net 49.0001.0100.0000.0001.00",
	"set protocols isis authentication-type md5",
	"set protocols isis authentication-key LEAK-ISIS-AREA-AUTHKEY",
	"set protocols isis interface ge-0-0-2 authentication-type md5",
	"set protocols isis interface ge-0-0-2 authentication-key LEAK-ISIS-IFACE-AUTHKEY",
	// BGP TCP-MD5 password (group-level).
	"set protocols bgp local-as 65001",
	"set protocols bgp group external peer-as 65002",
	"set protocols bgp group external authentication-key LEAK-BGP-AUTHPW",
	"set protocols bgp group external neighbor 10.0.2.1",
	// VRRP group (no authentication: VRRP authentication-type/-key are
	// hard-rejected at strict commit since #4288 — the dataplane is RFC 5798
	// VRRPv3, which has no authentication, so an operator commit carrying it
	// is refused rather than silently accepted as a false-security posture).
	// VRRPGroup.AuthKey is a config.Secret, so its JSON/YAML redaction is
	// covered by the dozen other Secret sentinels here; the AST-level
	// `authentication-key` leaf redaction is covered by the RIP/ISIS/BGP lines
	// above (same leaf name) and by pkg/config/ast_redact_test.go, which stage
	// a VRRP auth key through the AST RedactedClone path (no strict commit).
	"set interfaces ge-0-0-3 unit 0 family inet address 10.0.3.1/24 vrrp-group 1 virtual-address 10.0.3.254/24",
	// REST API basic-auth password + API key.
	"set system services web-management http",
	"set system services web-management api-auth user admin password LEAK-API-USER-PW",
	"set system services web-management api-auth api-key LEAK-API-KEY-TOKEN",
	// SNMPv3 auth + priv passwords, and a v1/v2c community string (the secret).
	"set snmp v3 usm local-engine user admin authentication-sha256 authentication-password LEAK-SNMPV3-AUTHPW",
	"set snmp v3 usm local-engine user admin privacy-des privacy-password LEAK-SNMPV3-PRIVPW",
	"set snmp community LEAK-SNMP-COMMUNITY authorization read-only",
	// TSIG HMAC key.
	"set system services dhcp-local-server dynamic-dns enable",
	"set system services dhcp-local-server dynamic-dns domain corp.example.com",
	"set system services dhcp-local-server dynamic-dns tsig-secret " + tsigSecretSentinel,
	// WireGuard private key.
	"set interfaces wg0 tunnel wireguard private-key " + wgPrivkeySentinel,
	"set interfaces wg0 tunnel wireguard listen-port 51820",
	// root + login crypt(3) hashes.
	`set system root-authentication encrypted-password "` + rootCryptSentinel + `"`,
	"set system login user op class read-only",
	`set system login user op authentication encrypted-password "` + loginCryptSentinel + `"`,
}

// stageSecretConfig builds a Server whose active config has every secret
// field populated with a distinctive sentinel, via the real LoadSet +
// Commit compile path. Returns the server plus the compiled config so a
// test can confirm the cleartext survived into memory (Reveal path) before
// asserting the JSON surface redacts it.
func stageSecretConfig(t *testing.T) (*Server, *config.Config) {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet(strings.Join(secretSetCommands, "\n")); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	cfg, err := store.Commit()
	if err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	if cfg == nil {
		t.Fatal("Commit() returned nil config")
	}
	return &Server{store: store}, cfg
}

// TestConfigHandlerRedactsSecrets is the #2053 leak-regression net. It
// drives the live GET /api/v1/config route (configHandler -> ActiveConfig
// -> writeOK -> json.Encode of the compiled *config.Config) and asserts
// that no cleartext secret appears in the response while the redaction
// sentinel does. This FAILS against pre-#2053 code, where the secret fields
// were plain strings and marshalled verbatim.
func TestConfigHandlerRedactsSecrets(t *testing.T) {
	s, _ := stageSecretConfig(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/config", nil)
	s.configHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()

	for _, leak := range secretSentinels {
		if strings.Contains(body, leak) {
			t.Errorf("GET /api/v1/config leaked plaintext secret %q in response body", leak)
		}
	}
	for _, leak := range []string{rootCryptSentinel, loginCryptSentinel, tsigSecretSentinel, wgPrivkeySentinel} {
		if strings.Contains(body, leak) {
			t.Errorf("GET /api/v1/config leaked plaintext secret %q in response body", leak)
		}
	}
	// writeOK uses json.NewEncoder which HTML-escapes the sentinel's
	// "<"/">"; match the encoded form so the positive check tracks the
	// real response bytes.
	rb, _ := json.Marshal(config.SecretRedacted)
	if !strings.Contains(body, strings.Trim(string(rb), `"`)) {
		t.Errorf("response did not contain redaction sentinel %q; redaction not applied?\nbody: %s",
			config.SecretRedacted, body)
	}
}

// TestConfigHandlerPreservesCleartextInMemory proves the redaction is a
// marshal-time concern only: the compiled config still carries the real
// secrets for the reconciler/render paths (Reveal). This guards against an
// over-eager fix that blanks the value in memory and silently breaks
// IPsec/FRR/SNMP/etc. rendering.
func TestConfigHandlerPreservesCleartextInMemory(t *testing.T) {
	_, cfg := stageSecretConfig(t)

	if got := cfg.Security.IPsec.IKEPolicies["pol1"].PSK.Reveal(); got != "LEAK-IKE-PSK" {
		t.Errorf("in-memory IKE PSK = %q, want cleartext LEAK-IKE-PSK (render path broken)", got)
	}
	if cfg.System.SNMP == nil || cfg.System.SNMP.V3Users["admin"] == nil {
		t.Fatal("SNMPv3 user not compiled")
	}
	if got := cfg.System.SNMP.V3Users["admin"].AuthPassword.Reveal(); got != "LEAK-SNMPV3-AUTHPW" {
		t.Errorf("in-memory SNMPv3 auth-password = %q, want cleartext (render path broken)", got)
	}
	if cfg.System.RootAuthentication == nil ||
		cfg.System.RootAuthentication.EncryptedPassword.Reveal() != rootCryptSentinel {
		t.Errorf("in-memory root encrypted-password not preserved cleartext (chpasswd path broken)")
	}
	if cfg.System.Login == nil || len(cfg.System.Login.Users) == 0 {
		t.Fatal("login user not compiled (the leak-test sentinel would never be set)")
	}
	if got := cfg.System.Login.Users[0].EncryptedPassword.Reveal(); got != loginCryptSentinel {
		t.Errorf("in-memory login encrypted-password = %q, want cleartext sentinel "+
			"(secret never set -> leak test would falsely pass)", got)
	}
}

// TestConfigHandlerJSONStaysValid confirms the redacted response is still
// well-formed JSON (a Marshaler that returns malformed bytes would corrupt
// the whole envelope, not just the secret).
func TestConfigHandlerJSONStaysValid(t *testing.T) {
	s, _ := stageSecretConfig(t)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/config", nil)
	s.configHandler(rr, req)

	var envelope map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("response is not valid JSON after redaction: %v\nbody: %s", err, rr.Body.String())
	}
}
