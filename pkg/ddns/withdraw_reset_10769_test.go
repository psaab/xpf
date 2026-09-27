package ddns

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func writeResetState10769(t *testing.T, path string, records ...ownedRecord) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(ddnsStateFile{Version: ddnsStateVersion, Records: records})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLeaseResetWithdrawalRejectsBackendFingerprintMismatch10769(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "ddns.json")
	oldConfig := &config.DHCPDynamicDNSConfig{Enabled: true, Backend: "rfc2136", UpdateServer: "192.0.2.53:53"}
	changedConfig := &config.DHCPDynamicDNSConfig{Enabled: true, Backend: "rfc2136", UpdateServer: "198.51.100.53:53"}
	owned := ownedRecord{
		Family: 4, Identity: "client", Address: "192.0.2.8", FQDN: "client.example.test",
		ForwardType: "A", PTRName: "8.2.0.192.in-addr.arpa", TTL: 300,
		BackendFingerprint: dhcpBackendFingerprint(policyFromConfig(oldConfig), oldConfig),
	}
	writeResetState10769(t, statePath, owned)
	updater := newFakeUpdater()
	m := newManagerForTesting(nil, updater, statePath, "", "", "node0", time.Now)
	m.newUpdater = func(ddnsPolicy, *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
		return updater, nil
	}

	err := m.WithdrawForReset(context.Background(), &config.DHCPServerConfig{DynamicDNS: changedConfig})
	if err == nil {
		t.Fatal("backend fingerprint mismatch must block factory reset withdrawal")
	}
	if got := len(updater.deletes); got != 0 {
		t.Fatalf("mismatched backend received %d delete(s), want none", got)
	}
	if got := len(m.state.all()); got != 1 {
		t.Fatalf("mismatched backend must retain delete authority, got %d records", got)
	}
}

func TestLeaseResetWithdrawalErasesOnlyAfterOwnedEndpointDelete10769(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "ddns.json")
	provider := &config.DHCPDynamicDNSConfig{Enabled: true, Backend: "rfc2136", UpdateServer: "192.0.2.53:53"}
	owned := ownedRecord{
		Family: 4, Identity: "client", Address: "192.0.2.8", FQDN: "client.example.test",
		ForwardType: "A", PTRName: "8.2.0.192.in-addr.arpa", TTL: 300,
		BackendFingerprint: dhcpBackendFingerprint(policyFromConfig(provider), provider),
	}
	writeResetState10769(t, statePath, owned)
	updater := newFakeUpdater()
	m := newManagerForTesting(nil, updater, statePath, "", "", "node0", time.Now)
	m.newUpdater = func(ddnsPolicy, *config.DHCPDynamicDNSConfig) (DNSUpdater, error) {
		return updater, nil
	}

	if err := m.WithdrawForReset(context.Background(), &config.DHCPServerConfig{DynamicDNS: provider}); err != nil {
		t.Fatalf("matching backend reset withdrawal: %v", err)
	}
	if got := len(updater.deletes); got != 1 {
		t.Fatalf("matching backend deletes = %d, want one exact owned record", got)
	}
	if got := len(m.state.all()); got != 0 {
		t.Fatalf("successful withdrawal retained %d ownership records", got)
	}
	if err := CheckStateEmpty(statePath); err != nil {
		t.Fatalf("state must be provably empty after successful withdrawal: %v", err)
	}
}

func TestSurfaceAResetWithdrawalRejectsBackendFingerprintMismatch10769(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "surface-a.json")
	provider := &config.DDNSProvider{Name: "p", Backend: "rfc2136", UpdateServer: "192.0.2.53:53"}
	changed := &config.DDNSProvider{Name: "p", Backend: "rfc2136", UpdateServer: "198.51.100.53:53"}
	scope := ScopeKey{Family: FamilyV4, PolicyID: "p"}
	owned := ownedRecord{
		Family: 4, Identity: "router", FQDN: "fw.example.test", AddrText: "192.0.2.10",
		ForwardType: "A", TTL: 300, BackendFingerprint: backendFingerprint(provider),
	}.withScope(scope)
	writeResetState10769(t, statePath, owned)
	updater := newFakeUpdater()
	m := newSurfaceAManagerForTesting(statePath, updater, time.Now)
	m.newBackend = func(*config.DDNSProvider, string, int) (DNSUpdater, error) {
		return updater, nil
	}

	err := m.WithdrawForReset(context.Background(), map[string]*config.DDNSProvider{"p": changed})
	if err == nil {
		t.Fatal("Surface A backend fingerprint mismatch must block factory reset withdrawal")
	}
	if got := len(updater.deletes); got != 0 {
		t.Fatalf("mismatched Surface A backend received %d delete(s), want none", got)
	}
	if got := len(m.state.all()); got != 1 {
		t.Fatalf("mismatched Surface A backend must retain delete authority, got %d records", got)
	}
}

func TestSurfaceAResetWithdrawalPreservesRecordWithoutAddress10769(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "surface-a.json")
	provider := &config.DDNSProvider{Name: "p", Backend: "rfc2136", UpdateServer: "192.0.2.53:53"}
	scope := ScopeKey{Family: FamilyV4, PolicyID: "p"}
	owned := ownedRecord{
		Family: 4, Identity: "router", FQDN: "fw.example.test",
		ForwardType: "A", TTL: 300, BackendFingerprint: backendFingerprint(provider), Scope: &scope,
	}
	writeResetState10769(t, statePath, owned)
	updater := newFakeUpdater()
	m := newSurfaceAManagerForTesting(statePath, updater, time.Now)
	m.newBackend = func(*config.DDNSProvider, string, int) (DNSUpdater, error) {
		return updater, nil
	}

	err := m.WithdrawForReset(context.Background(), map[string]*config.DDNSProvider{"p": provider})
	if err == nil {
		t.Fatal("Surface A reset must fail closed when stored ownership has no deletable address")
	}
	if got := len(updater.deletes); got != 0 {
		t.Fatalf("record without an address must not issue guessed deletes, got %d", got)
	}
	if got := len(m.state.all()); got != 1 {
		t.Fatalf("record without an address must retain delete authority, got %d records", got)
	}
}
