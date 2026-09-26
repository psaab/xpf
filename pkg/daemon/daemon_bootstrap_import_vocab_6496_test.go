package daemon

import (
	"bytes"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/bootstrapshow"
)

// #6496: every status this package can RECORD must be one the operator-facing
// renderer understands.
//
// The four constants are aliases of the bootstrapshow vocabulary, so today
// this holds by construction. The test is here because that construction is
// exactly what a future change would break: adding a fifth outcome as a bare
// string literal (the shape the constants had before #6496) compiles, records,
// reaches /health, and reaches `show system bootstrap-import` — where the
// operator is told "unrecognized status — this xpfd records a state this CLI
// does not know". That is a silent-until-the-worst-moment failure on the day-0
// surface, so it is asserted rather than left to review.
func TestEveryRecordableStatusIsRenderable(t *testing.T) {
	// Every status recordBootstrapImport can be called with, by name so a new
	// constant that is not added here is visible as an omission in review.
	recordable := []string{
		bootstrapImportOK,
		bootstrapImportLoadedDB,
		bootstrapImportNoConfig,
		bootstrapImportPending,
		bootstrapImportCredentialFailed,
		bootstrapImportFailed,
	}
	for _, st := range recordable {
		var b bytes.Buffer
		bootstrapshow.Render(&b, bootstrapshow.Snapshot{Status: st})
		if strings.Contains(b.String(), "unrecognized status") {
			t.Errorf("daemon can record status %q but bootstrapshow does not "+
				"recognize it — the operator would be told the CLI does not "+
				"understand its own daemon:\n%s", st, b.String())
		}
	}
}

// The Failed flag and failure states must agree. /health keys
// bootstrap_import_failed off the snapshot's Failed field, and the renderer
// keys its remediation block off the same value; a split would make one
// surface call the box healthy while the other calls it broken.
func TestFailedFlagTracksTheFailedStatusOnly(t *testing.T) {
	d := &Daemon{}
	for _, st := range []string{
		bootstrapImportOK, bootstrapImportLoadedDB, bootstrapImportNoConfig,
		bootstrapImportPending,
	} {
		d.recordBootstrapImport(st, "")
		if got := d.BootstrapImportSnapshot(); got.Failed {
			t.Errorf("status %q must not report Failed", st)
		}
	}
	d.recordBootstrapImport(bootstrapImportFailed, "boom")
	got := d.BootstrapImportSnapshot()
	if !got.Failed {
		t.Error("import-failed must report Failed")
	}
	if got.Error != "boom" {
		t.Errorf("Error = %q, want the recorded detail", got.Error)
	}
	d.recordBootstrapImport(bootstrapImportCredentialFailed, "credential failure")
	if got := d.BootstrapImportSnapshot(); !got.Failed {
		t.Error("credential-apply-failed must report Failed")
	}
}

// bootstrapShowSnapshot is the ONE conversion both wiring sites use (the gRPC
// server config and the in-process CLI hook). Every field must survive it: a
// dropped Error is a box that reports import-failed with no reason, and a
// dropped Failed is one that reports the failure without the remediation
// block. RED on revert: drop any field from the conversion.
func TestBootstrapShowSnapshotCarriesEveryField(t *testing.T) {
	d := &Daemon{}
	d.recordBootstrapImport(bootstrapImportFailed, "day-0 config REJECTED: bad stanza")

	want := d.BootstrapImportSnapshot()
	got := d.bootstrapShowSnapshot()

	if got.Status != want.Status {
		t.Errorf("Status = %q, want %q", got.Status, want.Status)
	}
	if got.Error != want.Error {
		t.Errorf("Error = %q, want %q — an import-failed with no reason is the "+
			"state this command exists to avoid", got.Error, want.Error)
	}
	if got.UnixSec != want.UnixSec {
		t.Errorf("UnixSec = %d, want %d", got.UnixSec, want.UnixSec)
	}
	if got.Failed != want.Failed {
		t.Errorf("Failed = %v, want %v", got.Failed, want.Failed)
	}
	if got.UnixSec == 0 {
		t.Error("recordBootstrapImport did not stamp a time; the conversion " +
			"assertion above would pass vacuously")
	}
}
