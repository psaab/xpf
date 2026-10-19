package journal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #15143: pre-#1896 v1 journal lines embed the FULL compiled config in
// before/after, including the cleartext REST api-auth password and API
// keys (config.Config System.Services.WebManagement.APIAuth). The #10826
// salted-hash migration rewrote active/rollback/rescue/archive copies but
// had no journal arm, and #1896/#5188 kept legacy segments intact (0600
// only). So an upgraded box still carries superuser-equivalent cleartext
// in .config.journal[.N] until rotation ages it out.
//
// The fix scrubs legacy payloads on first use (the same first-use pass
// that repairs permissions): every owned segment is rewritten once,
// dropping before/after while preserving the metadata the renderers
// print (timestamp/action/detail/config_hash/principal), atomically via
// temp+rename at 0600. RED on base: no scrub exists, Tail leaves the
// cleartext bytes on disk.

const legacySecret15143 = "correct-horse-battery"
const legacyAPIKey15143 = "machine-generated-key-alpha"

func legacyV1LineWithSecret15143(ts time.Time, action, detail string) string {
	// Shape of a real v1 line: After is a compiled *config.Config whose
	// JSON carries System.Services.WebManagement.APIAuth (no json tags
	// on the v1 struct, so Go field names). Password/APIKeys were plain
	// strings pre-#10826.
	return `{"timestamp":"` + ts.Format(time.RFC3339Nano) + `","action":"` + action +
		`","detail":"` + detail + `","before":null,"after":{"System":{"Services":{"WebManagement":{"APIAuth":{"Users":[{"Username":"api-admin","Password":"` +
		legacySecret15143 + `"}],"APIKeys":["` + legacyAPIKey15143 + `"]}}}}}}`
}

func writeSeg15143(t *testing.T, path, content string, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
}

func assertNoLegacySecrets15143(t *testing.T, j *Journal) {
	t.Helper()
	for seg := 0; seg <= j.maxSegments; seg++ {
		p := j.segmentPath(seg)
		data, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("read segment %s: %v", p, err)
		}
		if strings.Contains(string(data), legacySecret15143) {
			t.Fatalf("segment %s still contains cleartext api-auth password", p)
		}
		if strings.Contains(string(data), legacyAPIKey15143) {
			t.Fatalf("segment %s still contains cleartext API key", p)
		}
		if strings.Contains(string(data), `"before"`) || strings.Contains(string(data), `"after"`) {
			t.Fatalf("segment %s still carries legacy before/after payload:\n%s", p, data)
		}
	}
}

func TestLegacyV1SecretsScrubbedOnFirstUse15143(t *testing.T) {
	t.Run("Tail scrubs current and rotated segments and history still renders", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".config.journal")
		j := New(path)
		ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		writeSeg15143(t, j.segmentPath(1),
			legacyV1LineWithSecret15143(ts, "commit", "legacy rotated")+"\n", 0644)
		writeSeg15143(t, path,
			legacyV1LineWithSecret15143(ts.Add(time.Minute), "commit", "legacy current")+"\n"+
				`{"v":2,"timestamp":"`+ts.Add(2*time.Minute).Format(time.RFC3339Nano)+`","action":"commit","detail":"modern","config_hash":"abc123"}`+"\n",
			0644)

		// First use is a read (boot never reads the journal; the first
		// history view or append drives migration).
		got, err := j.Tail(50)
		if err != nil {
			t.Fatalf("Tail: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("history entries = %d, want 3 (legacy metadata must survive scrub)", len(got))
		}
		wantDetails := []string{"legacy rotated", "legacy current", "modern"}
		for i, want := range wantDetails {
			if got[i].Detail != want {
				t.Fatalf("entry %d detail = %q, want %q", i, got[i].Detail, want)
			}
		}
		if got[2].ConfigHash != "abc123" {
			t.Fatalf("modern entry config_hash lost: %q", got[2].ConfigHash)
		}

		assertNoLegacySecrets15143(t, j)

		// Scrubbed segments are owner-only.
		for seg := 0; seg <= j.maxSegments; seg++ {
			p := j.segmentPath(seg)
			fi, err := os.Stat(p)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0600 {
				t.Fatalf("segment %s mode = %04o, want 0600 after scrub", p, fi.Mode().Perm())
			}
		}

		// Idempotent: a second Tail does not corrupt or duplicate.
		got2, err := j.Tail(50)
		if err != nil {
			t.Fatalf("second Tail: %v", err)
		}
		if len(got2) != 3 {
			t.Fatalf("second Tail entries = %d, want 3", len(got2))
		}
	})

	t.Run("Log scrubs before appending", func(t *testing.T) {
		dir := t.TempDir()
		j := New(filepath.Join(dir, ".config.journal"))
		ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		writeSeg15143(t, j.path,
			legacyV1LineWithSecret15143(ts, "commit", "legacy current")+"\n", 0600)

		mustLog(t, j, &Entry{Action: "commit", Detail: "after upgrade"})

		assertNoLegacySecrets15143(t, j)
		got, err := j.Tail(50)
		if err != nil {
			t.Fatalf("Tail: %v", err)
		}
		if len(got) != 2 || got[0].Detail != "legacy current" || got[1].Detail != "after upgrade" {
			t.Fatalf("history after Log scrub wrong: %+v", got)
		}
	})

	t.Run("clean v2 journal is not rewritten", func(t *testing.T) {
		dir := t.TempDir()
		j := New(filepath.Join(dir, ".config.journal"))
		mustLog(t, j, &Entry{Action: "commit", Detail: "modern only"})
		before, err := os.ReadFile(j.path)
		if err != nil {
			t.Fatal(err)
		}
		fiBefore, err := os.Stat(j.path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := j.Tail(50); err != nil {
			t.Fatalf("Tail: %v", err)
		}
		after, err := os.ReadFile(j.path)
		if err != nil {
			t.Fatal(err)
		}
		fiAfter, err := os.Stat(j.path)
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) {
			t.Fatalf("clean v2 journal rewritten:\nbefore %q\nafter  %q", before, after)
		}
		if !fiBefore.ModTime().Equal(fiAfter.ModTime()) {
			t.Fatal("clean v2 journal mtime changed; scrub must be a no-op without legacy payloads")
		}
	})
}
