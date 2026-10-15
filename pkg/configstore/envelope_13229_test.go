package configstore

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEnvelopeHeaderRejectsMismatchedASTAndRollbackFormat_13229 pins the
// fail-closed gate for envelope ast=/rollback-fmt= values. All eight rows
// carry v=1 min-reader=1 so pre-fix they strip cleanly (RED); post-fix the
// mismatched rows error while exact/missing rows still load.
func TestEnvelopeHeaderRejectsMismatchedASTAndRollbackFormat_13229(t *testing.T) {
	body := []byte(`{"Children":null}`)
	cases := []struct {
		name    string
		header  string
		wantErr bool
	}{
		{"exact", envelopeMagic + " v=1 writer=w ast=1 min-reader=1 rollback-fmt=1\n", false},
		{"missing ast and rollback-fmt", envelopeMagic + " v=1 writer=w min-reader=1\n", false},
		{"future ast", envelopeMagic + " v=1 writer=w ast=999 min-reader=1 rollback-fmt=1\n", true},
		{"unsupported rollback-fmt", envelopeMagic + " v=1 writer=w ast=1 min-reader=1 rollback-fmt=99\n", true},
		{"zero ast", envelopeMagic + " v=1 writer=w ast=0 min-reader=1 rollback-fmt=1\n", true},
		{"zero rollback-fmt", envelopeMagic + " v=1 writer=w ast=1 min-reader=1 rollback-fmt=0\n", true},
		{"negative ast", envelopeMagic + " v=1 writer=w ast=-1 min-reader=1 rollback-fmt=1\n", true},
		{"negative rollback-fmt", envelopeMagic + " v=1 writer=w ast=1 min-reader=1 rollback-fmt=-1\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			dbDir := filepath.Join(dir, ".configdb")
			db, err := NewDB(dbDir)
			if err != nil {
				t.Fatal(err)
			}
			data := append([]byte(tc.header), body...)
			if err := os.WriteFile(filepath.Join(dbDir, "active.json"), data, 0644); err != nil {
				t.Fatal(err)
			}
			_, _, err = db.ReadActiveMeta()
			if tc.wantErr && err == nil {
				t.Fatalf("header %q read without error; want fail-closed rejection", tc.header)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("header %q errored: %v; want legacy/exact envelope to load", tc.header, err)
			}
			_, enveloped, inspectErr := InspectEnvelopeHeader(data)
			if !enveloped {
				t.Fatal("header was not recognized as an envelope")
			}
			if tc.wantErr && inspectErr == nil {
				t.Fatalf("InspectEnvelopeHeader(%q) returned no error; want fail-closed rejection", tc.header)
			}
			if !tc.wantErr && inspectErr != nil {
				t.Fatalf("InspectEnvelopeHeader(%q) errored: %v; want compatible envelope", tc.header, inspectErr)
			}
		})
	}
}
