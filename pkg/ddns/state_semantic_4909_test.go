package ddns

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestLoadDDNSStateRejectsMalformedAddress pins #4909 (load half): a
// valid-JSON, valid-version ownership store whose record carries an unparseable
// address must FAIL CLOSED (errDDNSStateCorrupt, empty store), exactly like a
// corrupt-JSON or bad-version file. Trusting the malformed record let the
// reconciler silently drop it without a wire delete, leaking uncleanable DNS.
//
// RED on revert: without the semantic check the malformed store loads with a
// nil error and one record — both assertions below fail.
func TestLoadDDNSStateRejectsMalformedAddress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	bad := `{"version":1,"records":[{"family":4,"identity":"id1","address":"not-an-ip",` +
		`"fqdn":"host.example.net","forward_type":"A"}]}`
	if err := os.WriteFile(path, []byte(bad), 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}
	s, err := loadDDNSState(path)
	if err == nil {
		t.Fatal("loadDDNSState accepted a malformed address; want a corrupt error")
	}
	if !errors.Is(err, errDDNSStateCorrupt) {
		t.Fatalf("error not classified corrupt: %v", err)
	}
	if len(s.records) != 0 {
		t.Fatalf("store not emptied on corrupt load: %d records", len(s.records))
	}

	// A well-formed store still loads clean (no false positive).
	good := `{"version":1,"records":[{"family":4,"identity":"id1","address":"203.0.113.5",` +
		`"fqdn":"host.example.net","forward_type":"A"}]}`
	if err := os.WriteFile(path, []byte(good), 0o644); err != nil {
		t.Fatalf("write good state: %v", err)
	}
	s2, err := loadDDNSState(path)
	if err != nil {
		t.Fatalf("loadDDNSState rejected a valid store: %v", err)
	}
	if len(s2.records) != 1 {
		t.Fatalf("valid store: want 1 record, got %d", len(s2.records))
	}
}

// TestDeleteOwnedUnparseableAddrPersistsDrop pins #4909 (cleanup half): when
// deleteOwnedLocked drops an owned record whose address no longer parses (no
// safe wire delete is possible), it must PERSIST the drop so the record does
// not reload and oscillate across restart.
//
// RED on revert: remove the m.state.save() call and the writeFile seam is never
// invoked — `saved` stays empty and the persist assertion fails (the in-memory
// drop still happens in both versions).
func TestDeleteOwnedUnparseableAddrPersistsDrop(t *testing.T) {
	var saved int
	st := &ddnsState{
		path:    filepath.Join(t.TempDir(), "state.json"),
		records: map[string]ownedRecord{},
		writeFile: func(_ string, _ []byte, _ os.FileMode) error {
			saved++
			return nil
		},
	}
	bad := ownedRecord{
		Family: 4, Identity: "id1", Address: "not-an-ip",
		FQDN: "host.example.net", ForwardType: "A",
	}
	st.put(bad)

	m := &Manager{state: st}
	if err := m.deleteOwnedLocked(context.Background(), nopUpdater{}, bad, false); err != nil {
		t.Fatalf("deleteOwnedLocked: %v", err)
	}
	if len(st.records) != 0 {
		t.Fatalf("unparseable-address entry not dropped: %d records", len(st.records))
	}
	if saved == 0 {
		t.Fatal("drop of unparseable-address record was not persisted (state.save not called)")
	}
}
