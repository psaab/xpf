package daemon

import (
	"errors"
	"testing"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #16753: the cold-prime bulk snapshot is a fourth producer of the same
// SessionDeltaInfo export the #7194 gate withholds on the stream, drain and
// FullResync paths. It must refuse too: doBulkSync fails closed on the error
// and frames no window, so the peer never authoritatively reconciles against
// rows decoded through a mismatched helper schema.
//
// FAIL-ON-REVERT: delete either userspaceDeltaSchemaAdmits call in
// userspaceBulkSnapshotWithConfig and the mismatch arm frames 1 row with a
// nil error; delete the recordUserspaceDeltaSchema call and the
// export-status-only arm (no prior drain) admits the window.

func TestUserspaceBulkSnapshotWithholdsOnDeltaSchemaMismatch16753(t *testing.T) {
	d, ss, cfg := snapshot6031Daemon()
	local := localSessionDeltaSchemaFingerprint()
	foreign := local ^ 0x5555_5555_5555_5555

	// A drain has already recorded the foreign fingerprint.
	d.recordUserspaceDeltaSchema(foreign)
	before := d.UserspaceDeltaSchemaWithheldCount()

	exporter := &recordingExporter{deltas: []dpuserspace.SessionDeltaInfo{transitDelta6031(39906)}}
	snap, err := d.userspaceBulkSnapshotWithConfig(exporter, ss, cfg, []int{1})
	if err == nil {
		t.Fatalf("#16753: mismatched helper schema must make the bulk snapshot ERROR, not frame an authoritative window; got snap=%+v", snap)
	}
	if !errors.Is(err, errUserspaceDeltaSchemaWithheld) {
		t.Fatalf("error = %v, want errUserspaceDeltaSchemaWithheld", err)
	}
	if len(snap.V4) != 0 || len(snap.V6) != 0 {
		t.Fatalf("framed_v4=%d framed_v6=%d, want 0/0 — nothing may be framed on a withheld bulk", len(snap.V4), len(snap.V6))
	}
	if got := d.UserspaceDeltaSchemaWithheldCount(); got <= before {
		t.Fatalf("withheld counter = %d, want > %d — the bulk refusal must advance the #7194 observable", got, before)
	}
}

func TestUserspaceBulkSnapshotRecordsExportStatus16753(t *testing.T) {
	d, ss, cfg := snapshot6031Daemon()
	local := localSessionDeltaSchemaFingerprint()
	foreign := local ^ 0x5555_5555_5555_5555

	// No prior drain: the ONLY fingerprint source is this export's own
	// returned ProcessStatus. Without recording it the gate stays unknown
	// and permits the foreign rows.
	exporter := &recordingExporter{
		deltas: []dpuserspace.SessionDeltaInfo{transitDelta6031(39906)},
		status: dpuserspace.ProcessStatus{SessionDeltaSchemaFingerprint: foreign},
	}
	snap, err := d.userspaceBulkSnapshotWithConfig(exporter, ss, cfg, []int{1})
	if err == nil {
		t.Fatalf("#16753: export advertising a foreign schema must be withheld even with no prior drain; got snap=%+v", snap)
	}
	if len(snap.V4) != 0 || len(snap.V6) != 0 {
		t.Fatalf("framed_v4=%d framed_v6=%d, want 0/0", len(snap.V4), len(snap.V6))
	}
	if got := d.UserspaceDeltaSchemaWithheldCount(); got == 0 {
		t.Fatal("withheld counter did not advance for the export-status mismatch")
	}
	if got := d.userspaceDeltaSchemaFP.Load(); got != foreign {
		t.Fatalf("recorded fingerprint = %d, want the export's %d", got, foreign)
	}

	// On export error the status must NOT be recorded (mirrors the
	// #16627 drain rule): a partial/zero status could clear a real
	// mismatch or invent one.
	d2, ss2, cfg2 := snapshot6031Daemon()
	d2.recordUserspaceDeltaSchema(local)
	boom := errors.New("helper control socket timed out")
	bad := &recordingExporter{err: boom, status: dpuserspace.ProcessStatus{SessionDeltaSchemaFingerprint: foreign}}
	if _, err := d2.userspaceBulkSnapshotWithConfig(bad, ss2, cfg2, []int{1}); !errors.Is(err, boom) {
		t.Fatalf("export error = %v, want wrapped %v", err, boom)
	}
	if got := d2.userspaceDeltaSchemaFP.Load(); got != local {
		t.Fatalf("failed export overwrote the recorded fingerprint: got %d, want %d", got, local)
	}
}

func TestUserspaceBulkSnapshotFramesOnDeltaSchemaMatch16753(t *testing.T) {
	local := localSessionDeltaSchemaFingerprint()

	for _, tc := range []struct {
		name   string
		status dpuserspace.ProcessStatus
		record *uint64
	}{
		{name: "export status matches", status: dpuserspace.ProcessStatus{SessionDeltaSchemaFingerprint: local}},
		{name: "export status unknown (older helper)", status: dpuserspace.ProcessStatus{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, ss, cfg := snapshot6031Daemon()
			delta := transitDelta6031(39906)
			exporter := &recordingExporter{
				deltas: []dpuserspace.SessionDeltaInfo{delta},
				status: tc.status,
			}
			snap, err := d.userspaceBulkSnapshotWithConfig(exporter, ss, cfg, []int{1})
			if err != nil {
				t.Fatalf("bulk snapshot error = %v, want nil (match/unknown must still frame)", err)
			}
			if len(snap.V4) != 1 {
				t.Fatalf("framed_v4 = %d, want 1", len(snap.V4))
			}
			if got := d.UserspaceDeltaSchemaWithheldCount(); got != 0 {
				t.Fatalf("withheld counter = %d, want 0 on the admitted arm", got)
			}
		})
	}
}
