package userspace

import (
	"bufio"
	"encoding/json"
	"errors"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// DefaultControlSocketPath returns the control-socket path the userspace
// helper listens on, resolved exactly the way the runtime Manager resolves it
// (deriveUserspaceConfig): the operator-configured
// `system services userspace-dataplane control-socket` when set, else the
// default under os.TempDir(). cfg may be nil (e.g. a compile-failed boot has no
// active config), in which case the default path is returned — which matches
// what a surviving helper from a default-config deployment is listening on.
func DefaultControlSocketPath(cfg *config.Config) string {
	return deriveUserspaceConfig(cfg).ControlSocket
}

// StateFilePathForConfig returns the effective helper state-file path for
// cfg, resolved exactly the way the runtime Manager resolves it at spawn
// (deriveUserspaceConfig): the operator-configured state-file when set,
// else the default beside the control socket. cfg may be nil, in which
// case the compiled default is returned. Factory-reset shutdown uses it
// to sweep the helper's final write, which may land outside /run/xpf.
func StateFilePathForConfig(cfg *config.Config) string {
	return deriveUserspaceConfig(cfg).StateFile
}

// ProbeForwardingArmed performs a lightweight, one-shot status query against a
// PRE-EXISTING userspace helper on its control socket, WITHOUT standing up a
// Manager or starting a helper. It is used early in boot (#1993) to decide
// whether a previous daemon's dataplane is genuinely still forwarding.
//
// It returns true only when the helper is reachable AND reports both
// Enabled && ForwardingArmed — the authoritative "forwarding is live" signal
// (ProcessStatus.Enabled / ForwardingArmed, the same pair manager.go and
// process.go gate forwarding on). Every failure mode — socket missing,
// connect-refused, timeout, malformed/!ok response, Enabled=false, or
// ForwardingArmed=false — returns false. The boolean is the decision; the
// error is informational only (connect/decode failures are returned with
// armed=false so the caller can log the cause but must still treat the helper
// as NOT armed).
//
// This deliberately does NOT distinguish "no helper" from "helper present but
// unarmed": both mean no live forwarding, and the #1993 caller fails toward
// clearing FRR in either case.
func ProbeForwardingArmed(controlSocket string, timeout time.Duration) (bool, error) {
	st, err := ProbeStatus(controlSocket, timeout)
	if err != nil {
		// No surviving helper (ENOENT / ECONNREFUSED), a bad path, or a
		// framing failure: not armed. The error is informational only.
		return false, err
	}
	if st == nil {
		// A !ok / nil-status response is a clean "not armed", not an error.
		return false, nil
	}
	return st.Enabled && st.ForwardingArmed, nil
}

// ProbeStatus performs the same one-shot control-socket "status" query as
// ProbeForwardingArmed but returns the FULL ProcessStatus, for callers that
// need more than the armed+forwarding bool. It stands up NO Manager and starts
// NO helper — it is the exact same request the runtime status loop and the
// boot armed-probe issue, so it does NOT invent a new IPC.
//
// #5286 uses it in the upgrade cutover readiness gate: beyond
// Enabled && ForwardingArmed it needs ProcessStatus.PID to tie the ARMED helper
// to the freshly-cut target-version binary (a stale previous-version helper
// still armed on the socket must not be mistaken for the new dataplane).
//
// Return contract:
//   - dial / encode / decode failure  -> (nil, err)   (helper unreachable or
//     framing broke)
//   - helper answered !ok (no live status) -> (nil, nil)
//   - helper answered ok               -> (status, nil)  (status may itself be
//     nil if the helper omitted it, which the caller treats as not-ready)
//
// It deliberately does NOT interpret Enabled/ForwardingArmed — the caller
// decides what "ready" means.
func ProbeStatus(controlSocket string, timeout time.Duration) (*ProcessStatus, error) {
	if controlSocket == "" {
		return nil, errors.New("userspace dataplane control socket not configured")
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	// #9003: this is the EARLIEST dial of the control socket — it runs before
	// any helper spawn (pkg/daemon/bootstrap.go), so removeStaleUnixSocket's
	// fail-closed guard has not run and no path check has happened yet. Whoever
	// answers here decides the #1993 fail-closed boot decision and the #5286
	// upgrade-readiness gate, so a squatter could LIE about Enabled /
	// ForwardingArmed. SO_PEERCRED is what makes that answer attributable.
	conn, err := dialTrustedHelperSocket("control socket", controlSocket, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := json.NewEncoder(conn).Encode(&ControlRequest{Type: "status"}); err != nil {
		return nil, err
	}
	var resp ControlResponse
	// #9003: byte-bounded as well as deadline-bounded.
	bounded := boundedResponseReader(conn)
	if err := json.NewDecoder(bufio.NewReader(bounded)).Decode(&resp); err != nil {
		// #9322: the third boundedResponseReader call site. It returns the error
		// bare, so without this a truncation here surfaces as an unadorned
		// "unexpected EOF" with nothing naming the cap.
		if bounded.truncated {
			return nil, responseCapError("status", err)
		}
		return nil, err
	}
	if !resp.OK {
		return nil, nil
	}
	return resp.Status, nil
}
