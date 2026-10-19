package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15180 (C02-01): renderedSectionEntry located a connection by the
// unanchored substring "  <name> {\n". For a VPN named local, remote or
// children that substring is satisfied by an earlier-sorting VPN's
// nested four-space block ("    local {\n" contains "  local {\n" at
// offset 2), so the keyword VPN hashed the earlier VPN's nested tail
// instead of its own top-level block. Changes to the keyword VPN's own
// block then left its fingerprint unchanged (the #10878 teardown was
// lost), and edits to the earlier VPN tore the keyword VPN down
// spuriously.
//
// Fixture: inline-endpoint VPNs (Gateway is a peer IP, no Gateways
// entry) so each VPN is its own connection named after the VPN.
// "aaa" sorts before every keyword and renders local/remote/children
// nested blocks inside its own connection.

func keywordCfg15180(keyword, aaaPSK, keywordPSK string) *config.IPsecConfig {
	return &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"aaa": {
				LocalAddr: "10.0.1.1",
				Gateway:   "10.0.2.10",
				PSK:       config.Secret(aaaPSK),
			},
			keyword: {
				LocalAddr: "10.0.1.1",
				Gateway:   "10.0.2.20",
				PSK:       config.Secret(keywordPSK),
			},
		},
		Proposals: map[string]*config.IPsecProposal{},
	}
}

func keywordHashes15180(t *testing.T, cfg *config.IPsecConfig) map[string]string {
	t.Helper()
	m := NewWithConfigDir(t.TempDir())
	text, rendered, err := m.renderConfig(cfg)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	hashes, err := renderedConnectionHashes(text, rendered)
	if err != nil {
		t.Fatalf("hashes: %v", err)
	}
	return hashes
}

// TestRenderedHashesKeywordNamesOwnBlock15180 is the RED-on-revert core
// for the lost-teardown direction: rotating the keyword VPN's own PSK
// must change its fingerprint, and rotating only aaa's PSK must leave
// the keyword fingerprint unchanged (the hash must not be a slice of
// aaa's block). Control: rotating aaa's PSK changes aaa's fingerprint.
func TestRenderedHashesKeywordNamesOwnBlock15180(t *testing.T) {
	for _, keyword := range []string{"local", "remote", "children"} {
		t.Run(keyword, func(t *testing.T) {
			base := keywordHashes15180(t, keywordCfg15180(keyword, "secret-aaa", "secret-kw"))
			if base["aaa"] == "" || base[keyword] == "" {
				t.Fatalf("hashes missing: %v", base)
			}
			if base["aaa"] == base[keyword] {
				t.Fatalf("aaa and %q hashes identical (%q); each connection must hash its own block", keyword, base["aaa"])
			}

			// Own-block change: keyword PSK rotation must move its hash.
			own := keywordHashes15180(t, keywordCfg15180(keyword, "secret-aaa", "secret-kw-rotated"))
			if own[keyword] == base[keyword] {
				t.Fatalf("%q hash unchanged after its own PSK rotation (%q); the #10878 teardown is lost for this name", keyword, own[keyword])
			}
			if own["aaa"] != base["aaa"] {
				t.Fatalf("aaa hash changed when only %q rotated: %q -> %q (control broke)", keyword, base["aaa"], own["aaa"])
			}

			// Other-block change: aaa PSK rotation must NOT move the
			// keyword hash (spurious teardown direction).
			other := keywordHashes15180(t, keywordCfg15180(keyword, "secret-aaa-rotated", "secret-kw"))
			if other[keyword] != base[keyword] {
				t.Fatalf("%q hash changed when only aaa rotated: %q -> %q; it hashes aaa's block, so editing aaa tears %q down spuriously", keyword, base[keyword], other[keyword], keyword)
			}
			if other["aaa"] == base["aaa"] {
				t.Fatalf("aaa hash unchanged after its own PSK rotation (control broke)")
			}
		})
	}
}

// TestRenderedHashesKeywordSectionEntry15180 pins the helper directly:
// the entry returned for a keyword name must be its own top-level
// two-space block, not an earlier connection's nested tail.
func TestRenderedHashesKeywordSectionEntry15180(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	text, rendered, err := m.renderConfig(keywordCfg15180("remote", "secret-aaa", "secret-kw"))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !rendered["aaa"] || !rendered["remote"] {
		t.Fatalf("rendered=%v", rendered)
	}
	// Extract the connections section the same way the hasher does.
	const connectionsHeader = "connections {\n"
	const secretsHeader = "\nsecrets {\n"
	connectionsStart := strings.Index(text, connectionsHeader)
	secretsStart := strings.Index(text, secretsHeader)
	connections := text[connectionsStart+len(connectionsHeader) : secretsStart]

	entry, ok := renderedSectionEntry(connections, "remote")
	if !ok {
		t.Fatalf("no entry for remote")
	}
	wantPrefix := "  remote {\n"
	if len(entry) < len(wantPrefix) || entry[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("entry for remote does not start at its top-level header: %q", entry)
	}
	// The own block carries remote's peer address (10.0.2.20), not
	// aaa's (10.0.2.10).
	if !strings.Contains(entry, "10.0.2.20") {
		t.Fatalf("entry for remote lacks its own remote_addrs: %q", entry)
	}
	if strings.Contains(entry, "10.0.2.10") {
		t.Fatalf("entry for remote contains aaa's remote_addrs: %q", entry)
	}

	secret, ok := renderedSectionEntry(text[secretsStart+len(secretsHeader):], "ike-remote")
	if !ok {
		t.Fatalf("no secret entry for ike-remote")
	}
	if !strings.Contains(secret, "secret-kw") {
		t.Fatalf("secret for ike-remote lacks its own PSK: %q", secret)
	}
}

// TestApplyKeywordVPNChangeTearsDown15180 is the Apply-level check:
// gen1 {aaa, remote} then gen2 rotates only remote's PSK. Apply must
// terminate remote's stale SA and must not terminate aaa.
func TestApplyKeywordVPNChangeTearsDown15180(t *testing.T) {
	rec := &swanctlRecorder{}
	m := newRecordingManager(t, rec)
	if err := m.Apply(keywordCfg15180("remote", "secret-aaa", "secret-kw")); err != nil {
		t.Fatalf("gen1 Apply: %v", err)
	}
	rec.listSAs = liveSA("aaa", "remote")
	rec.calls = nil
	if err := m.Apply(keywordCfg15180("remote", "secret-aaa", "secret-kw-rotated")); err != nil {
		t.Fatalf("gen2 Apply: %v", err)
	}
	got := rec.terminateCalls()
	foundRemote := false
	for _, n := range got {
		if n == "remote" {
			foundRemote = true
		}
		if n == "aaa" {
			t.Fatalf("aaa terminated spuriously on remote's rotation: %v", got)
		}
	}
	if !foundRemote {
		t.Fatalf("remote not terminated after its own PSK rotation; terminate calls=%v (stale SA keeps forwarding under superseded config)", got)
	}

	// Control direction: rotating only aaa must not terminate remote.
	rec2 := &swanctlRecorder{}
	m2 := newRecordingManager(t, rec2)
	if err := m2.Apply(keywordCfg15180("remote", "secret-aaa", "secret-kw")); err != nil {
		t.Fatalf("control gen1 Apply: %v", err)
	}
	rec2.listSAs = liveSA("aaa", "remote")
	rec2.calls = nil
	if err := m2.Apply(keywordCfg15180("remote", "secret-aaa-rotated", "secret-kw")); err != nil {
		t.Fatalf("control gen2 Apply: %v", err)
	}
	for _, n := range rec2.terminateCalls() {
		if n == "remote" {
			t.Fatalf("remote terminated spuriously on aaa's rotation: %v", rec2.terminateCalls())
		}
	}
}
