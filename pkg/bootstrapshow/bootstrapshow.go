// Package bootstrapshow renders the day-0 / bootstrap config-import outcome
// (#4184) for the operator-facing show paths, and owns the status vocabulary
// itself.
//
// Background (#6496): the outcome was recorded by the daemon and rendered in
// exactly one place — the `/health` JSON on the loopback REST API. The
// operator this feature exists for is standing at a fresh box on day zero
// with the `cli` prompt open, asking the one question the status answers
// ("why didn't my day-0 config apply?"), and could not get it from the CLI
// they were already in: they had to know to leave it and curl
// 127.0.0.1:8080/health, documented only in the bare-metal device-map doc.
//
// This package is a leaf (stdlib only) so BOTH show paths — the in-process
// CLI (pkg/cli) and the gRPC ShowText path the remote `cli` binary uses
// (pkg/grpcapi) — render from one implementation, in the pkg/natshow idiom.
// Two renderings of the same recorded fact that disagree is ALWAYS a bug,
// never a legitimate difference, so this is single-sourced rather than
// duplicated-and-cross-checked.
//
// The status constants live here too, and pkg/daemon's unexported names are
// defined as aliases of them, so the recorded vocabulary and the rendered
// vocabulary cannot drift apart into a status the renderer does not know.
package bootstrapshow

import (
	"fmt"
	"io"
	"time"
)

// Status vocabulary for the boot-time config-import decision. pkg/daemon
// records its import result during startup and finalizes a successful import
// after initial host-credential reconciliation.
const (
	// StatusOK: the text config was imported and its initial host credentials
	// were applied successfully.
	StatusOK = "ok"
	// StatusLoadedDB: an active config was already present in the DB; no file
	// import was attempted (the normal steady-state boot).
	StatusLoadedDB = "loaded-from-db"
	// StatusNoConfig: no text config file present (factory / fresh boot).
	// Expected — NOT a failure.
	StatusNoConfig = "no-config"
	// StatusPending: import succeeded but initial host-credential reconciliation
	// has not completed.
	StatusPending = "credential-apply-pending"
	// StatusCredentialFailed: import succeeded but initial host credentials did
	// not converge.
	StatusCredentialFailed = "credential-apply-failed"
	// StatusFailed: a text-config import failed (read/parse/commit/device-map
	// preflight), or the day-0 loader rejected a medium before installing it.
	StatusFailed = "import-failed"
)

// Snapshot is the recorded outcome. It mirrors daemon.BootstrapImport
// without importing pkg/daemon (which imports both show paths).
type Snapshot struct {
	Status  string // a Status* constant; "" when the decision has not been reached yet
	Error   string // safe detail for an import or initial credential-apply failure
	UnixSec int64  // when the outcome was last updated
	Failed  bool   // true for a text-import or initial credential-apply failure
}

// explain returns the operator-facing meaning of a status. An UNKNOWN status
// is reported as unknown rather than silently rendered as a bare string: a
// status this package does not recognise means the daemon started recording a
// vocabulary the renderer was never taught, and saying so is more useful than
// printing it as if it were understood.
func explain(status string) string {
	switch status {
	case StatusOK:
		return "the day-0 / preseeded configuration was imported and host credentials were applied"
	case StatusLoadedDB:
		return "an active configuration was already present; no file import was attempted"
	case StatusNoConfig:
		return "no configuration file was present (factory boot) — expected, not a failure"
	case StatusPending:
		return "the day-0 configuration was imported; initial host-credential application is still running"
	case StatusCredentialFailed:
		return "the day-0 configuration was imported, but host-credential application failed"
	case StatusFailed:
		return "a configuration could NOT be applied — see Error below"
	case "":
		return "the daemon has not yet reached the boot-time import decision"
	default:
		return "unrecognized status — this xpfd records a state this CLI does not know"
	}
}

// Render writes the Junos-style rendering of the recorded outcome.
//
// Informational by construction (#6496 acceptance): it describes state and
// never signals failure through its own return, mirroring the /health posture.
// Import or credential-apply failure does not force a 503 because a box whose
// day-0 configuration did not fully converge can still be reachable.
//
// Unlike /health, this surface renders error details. /health withholds raw
// import errors on purpose (#5031), because they quote the submitted config
// and can echo a secret. The CLI and ShowText paths are authenticated; this is
// the in-band answer to "why didn't my day-0 config apply?"
func Render(w io.Writer, s Snapshot) {
	fmt.Fprintln(w, "Bootstrap configuration import:")
	status := s.Status
	if status == "" {
		status = "not-recorded"
	}
	fmt.Fprintf(w, "  Status:   %s\n", status)
	fmt.Fprintf(w, "  Meaning:  %s\n", explain(s.Status))
	if s.UnixSec != 0 {
		fmt.Fprintf(w, "  Recorded: %s\n",
			time.Unix(s.UnixSec, 0).UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	if s.Error != "" {
		fmt.Fprintf(w, "  Error:    %s\n", s.Error)
	}
	// The remediation hint is gated on Failed, not on Error being non-empty:
	// a failure whose detail was lost still needs to tell the operator what to
	// do next, and a non-failure that somehow carries detail must not be
	// dressed up as one.
	if s.Failed {
		fmt.Fprintln(w, "")
		if s.Status == StatusCredentialFailed {
			fmt.Fprintln(w, "  The day-0 configuration was imported, but host credentials")
			fmt.Fprintln(w, "  did not converge; configured access may be incomplete.")
			fmt.Fprintln(w, "  Inspect the daemon journal, fix the cause, then re-apply")
			fmt.Fprintln(w, "  or commit the configuration.")
		} else {
			fmt.Fprintln(w, "  The box is in the lifeline-safe bootstrap state; the running")
			fmt.Fprintln(w, "  configuration is NOT the one on the day-0 medium. Fix the cause")
			fmt.Fprintln(w, "  above, then either commit the corrected configuration from this")
			fmt.Fprintln(w, "  CLI or re-present a corrected day-0 medium and reboot.")
		}
	}
}
