// vtysh.go holds the FRR shell-out surface for the package.
//
// All vtysh + frr-reload.py shell-outs go through the frrExecutor
// interface so tests can inject fakes. realExecutor wraps os/exec and
// is the production default; New() pre-populates Manager.exec with it.
//
// Symbols:
//   - frrExecutor interface (Vtysh / FrrReloadPy / VtyshLoad / VtyshStream)
//   - realExecutor (production implementation, exec.Command-backed)
//   - Manager.ExecVtysh (public)
//   - Thin raw-output shells: GetBFDPeers, GetRouteMapList,
//     GetISISAdjacencyDetail, GetISISDatabase, GetISISRoutes,
//     GetOSPFNeighborDetail, GetOSPFDatabase, GetOSPFInterface,
//     GetOSPFRoutes, GetBGPNeighborReceivedRoutes,
//     GetBGPNeighborAdvertisedRoutes, GetBGPNeighborDetail.
package frr

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"syscall"
	"time"

	"github.com/psaab/xpf/pkg/diagcmd"
)

// vtyshTimeout bounds every `vtysh -c` shell-out. Vtysh backs the
// show/clear operational paths (status_parse.go, ExecVtysh via
// gRPC/CLI), not the apply path — but a wedged vtysh (zebra hung, FRR
// mid-restart) would hang those gRPC/CLI handlers indefinitely, the
// same hang class #1794 bounded elsewhere. Same 15s budget as
// reloadTimeout (manager.go), which already covers FrrReloadPy /
// VtyshLoad via caller-supplied contexts. #1794/#1800.
const vtyshTimeout = 15 * time.Second

// frrReloadScript is the FRR diff-reload engine (frr-pythontools
// package). Invoked DIRECTLY — never via `systemctl reload frr`: on
// FRR 10.6 the unit's ExecReload (frrinit.sh reload) unconditionally
// restarts watchfrr, which is the Type=forking unit's MainPID, so every
// systemd-mediated reload cancels its own job, parks frr.service in
// stop-sigterm for TimeoutStopSec (2 minutes), and ends with systemd
// SIGKILLing every FRR daemon (#1880). Bypassing the systemd job
// machinery keeps the unit state untouched.
const frrReloadScript = "/usr/lib/frr/frr-reload.py"

// vtyshBinary is the `vtysh` executable realExecutor runs. It is a package var
// rather than a literal ONLY so a test can point it at a real, controllable
// child (a shell script that sleeps) and exercise realExecutor's own context
// handling — the code that actually reaps the process.
//
// #9143 added it because the mutation matrix caught a hole the cells could not
// see: every existing pkg/frr test injects a FAKE frrExecutor, so
// realExecutor.Vtysh — the only place the caller's context is composed with
// vtyshTimeout and handed to exec.CommandContext — had no coverage at all.
// Reverting it to context.Background() left the whole suite green. A guard that
// cannot be driven is not a guard, so the production path is made exercisable
// rather than excused.
//
// Production never assigns it; the tests that do restore it with t.Cleanup.
var vtyshBinary = "vtysh"

// frrReloadOutputTail bounds how much frr-reload.py output a failure
// message carries (the interesting part is at the tail).
const frrReloadOutputTail = 1024

// frrExecutor is the package-private indirection that all vtysh and
// frr-reload.py shell-outs route through. Production code uses
// realExecutor; tests inject a fake. The interface is intentionally
// minimal: it covers only the three call shapes that exist in pkg/frr
// today.
type frrExecutor interface {
	// Vtysh runs `vtysh -c <command>` under ctx and returns stdout. Errors
	// include the captured stderr in the message string.
	//
	// #9143: ctx is a PARAMETER, not context.Background(). Before, every
	// buffered FRR read hardcoded context.Background() with a 15s timeout, so
	// a client that abandoned its request left the forked vtysh child running
	// to completion — the server paid the full budget for an answer nobody
	// would read, at a concurrency the client chose. The 15s cap is still
	// applied ON TOP of ctx, so a caller with no deadline is bit-identical to
	// before and a caller with a shorter deadline wins.
	Vtysh(ctx context.Context, command string) (string, error)

	// FrrReloadPy runs `frr-reload.py --reload <conf>` with the supplied
	// context (which carries the 15s reload timeout). The config path is
	// a parameter so tests that override Manager.frrConf exercise the
	// real wiring. A nil return means the FULL diff (including removals)
	// converged. (#1880 — replaces the retired SystemctlReload.)
	FrrReloadPy(ctx context.Context, conf string) error

	// VtyshLoad runs `vtysh -f <conf>` with the supplied context and
	// returns CombinedOutput (so the caller can include stderr in error
	// messages — preserves the historical behavior). NOTE: vtysh -f is
	// ADDITIVE — it re-applies every desired line but cannot remove
	// stale config; it is the degraded fallback only.
	VtyshLoad(ctx context.Context, conf string) ([]byte, error)

	// VtyshStream runs `vtysh -c <command>` under ctx and returns stdout
	// as an io.ReadCloser plus a finish func that reaps the process. The
	// caller scans the reader INCREMENTALLY so a huge table (a full
	// internet BGP RIB, ~1M routes) is never buffered whole the way the
	// string-returning Vtysh does; cancelling ctx (client disconnect /
	// write failure) kills the vtysh process so it stops producing output
	// for a response nobody will read (#5056). The caller MUST call
	// finish() to release the process. finish() reports a genuine
	// non-zero exit; a kill triggered by the caller cancelling ctx to
	// stop early is EXPECTED and the caller's to interpret (StreamBGPRoutes
	// suppresses it on the truncate/callback-abort paths).
	VtyshStream(ctx context.Context, command string) (io.ReadCloser, func() error, error)
}

// realExecutor is the production frrExecutor. It is intentionally
// zero-field so it can be returned as a value from the zero-value
// accessor on Manager.
type realExecutor struct{}

// Vtysh runs `vtysh -c <command>` under the CALLER's ctx, capped at
// vtyshTimeout, and returns stdout. Output/error shape is identical to the
// historical vtyshCmd free function (frr.go:1597-1605 pre-split); the timeout
// bound was added in #1800 (U3) and the caller's context in #9143.
//
// WithTimeout(ctx, ...) composes: the effective deadline is the EARLIER of the
// caller's and 15s, and cancelling ctx (an HTTP client disconnect, a cancelled
// gRPC stream) makes exec.CommandContext kill and reap the child immediately
// rather than letting it run out the budget.
func (realExecutor) Vtysh(ctx context.Context, command string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, vtyshTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, vtyshBinary, "-c", command)
	// WaitDelay caps the post-SIGKILL pipe-drain window.
	cmd.WaitDelay = 5 * time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("vtysh %q: %w: %s", command, err, stderr.String())
	}
	return stdout.String(), nil
}

// VtyshStream runs `vtysh -c <command>` under ctx and streams stdout
// through a pipe instead of buffering the whole result (the memory bound
// for full-RIB dumps, #5056). exec.CommandContext kills the process when
// ctx is cancelled, so a client disconnect or a downstream write failure
// stops vtysh mid-dump rather than letting it render a multi-hundred-MB
// table nobody will read. WaitDelay bounds the post-kill pipe-drain
// window, matching Vtysh.
func (realExecutor) VtyshStream(ctx context.Context, command string) (io.ReadCloser, func() error, error) {
	cmd := exec.CommandContext(ctx, vtyshBinary, "-c", command)
	cmd.WaitDelay = 5 * time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("vtysh %q: stdout pipe: %w", command, err)
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("vtysh %q: %w: %s", command, err, stderr.String())
	}
	finish := func() error {
		if err := cmd.Wait(); err != nil {
			return fmt.Errorf("vtysh %q: %w: %s", command, err, stderr.String())
		}
		return nil
	}
	return stdout, finish, nil
}

// FrrReloadPy runs `frr-reload.py --reload <conf>` under ctx.
//
// Process-group teardown contract (#1880): frr-reload.py spawns vtysh
// children to apply the diff; exec.CommandContext's default Cancel
// kills only the direct python process, which could leave a child
// vtysh writer racing the fallback `vtysh -f`. Setpgid puts the whole
// tree in its own process group and Cancel SIGKILLs the group, so by
// the time Run returns (bounded by WaitDelay) no child writer
// survives.
func (realExecutor) FrrReloadPy(ctx context.Context, conf string) error {
	cmd := exec.CommandContext(ctx, frrReloadScript, "--reload", conf)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative pid = the whole process group (Setpgid above).
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	// WaitDelay caps the post-SIGKILL pipe-drain window; the fallback
	// is only entered after Run (i.e. Wait) returns.
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.CombinedOutput()
	if err != nil {
		if len(out) > frrReloadOutputTail {
			out = out[len(out)-frrReloadOutputTail:]
		}
		return fmt.Errorf("%s --reload %s: %w: %s", frrReloadScript, conf, err, out)
	}
	return nil
}

// VtyshLoad runs `vtysh -f <conf>` under ctx and returns CombinedOutput.
// Mirrors the historical reload() fallback (frr.go:1068-1069 pre-split).
func (realExecutor) VtyshLoad(ctx context.Context, conf string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, vtyshBinary, "-f", conf)
	// WaitDelay caps the post-SIGKILL pipe-drain window (apply-reachable
	// via the FRR reload fallback).
	cmd.WaitDelay = 5 * time.Second
	return cmd.CombinedOutput()
}

// ErrVtyshBusy is returned when the process-wide FRR shell-out admission bound
// (diagcmd.VtyshLimiter) is already at capacity. Callers map it to their
// surface's overload signal: HTTP 429 (REST) / codes.ResourceExhausted (gRPC),
// the same mapping diagcmd.ErrBusy already gets for ping/traceroute.
//
// It is a REFUSAL, not a fault: the FRR daemons are healthy and we declined to
// ask. Reporting it as a 5xx would send an operator debugging FRR after a load
// condition (the mistake #9142 fixed on the session-clear surface, and the one
// peerFetchErrorStatus (#7294/#8308) exists to avoid on the peer surfaces).
var ErrVtyshBusy = errors.New("FRR vtysh concurrency limit reached")

// vtysh is the SINGLE funnel every BUFFERED operational FRR shell-out in this
// package goes through. It applies the process-wide admission bound and then
// hands the caller's context to the executor. The one STREAMING read is exempt
// by design -- see #9755 below.
//
// #9143: the bound lives here, not at each handler, and that placement is the
// point. #6809 gated ONE branch of ONE handler (the REST full-RIB stream) and
// every other FRR read stayed unbounded — REST ospf (both branches) and bgp
// summary, plus the gRPC OSPF/BGP/RIP/IS-IS/route status RPCs. Gating them one
// at a time would leave the twentieth FRR read to be added unbounded again. A
// funnel makes every present AND future BUFFERED FRR read bounded by
// construction.
//
// #9755 CORRECTS THE SCOPE OF THAT CLAIM. This used to say "nothing in this
// package can reach vtysh except through here", and that was false: the ONE
// streaming read, StreamBGPRoutes, calls the executor's VtyshStream directly, so
// it takes no VtyshLimiter slot and gets no vtyshTimeout. The #9143 census had no
// row for it either, so nothing detected the gap between the sentence and the
// code.
//
// The exemption is KEPT rather than closed, deliberately. A full-RIB stream is
// allowed a 10-minute progress budget (pkg/api's bgpStreamTotalBudget), far
// longer than the 15 s here; making it hold one of four shared slots would let a
// single slow reader occupy a quarter of the budget for EVERY FRR status surface
// on the box for ten minutes. A shared limiter would also imply a cross-surface
// bound that does not exist -- the gRPC and CLI `show route protocol bgp` paths
// call the buffered GetBGPRoutes, which cannot be pinned by a slow reader.
//
// So the true invariant is: every BUFFERED operational read in this package goes
// through here; the one STREAMING read is exempt and carries its own admission
// (pkg/api's ribStreamLimiter, capacity 2) plus its own budget; and the apply
// path is excluded for the separate reason below. Worst case is therefore four
// buffered plus two streaming children, not four.
//
// That exemption is only safe while the stream path's single caller bounds
// itself, so the count is pinned by
// TestStreamPathKeepsExactlyOneBoundedCaller9755 -- a second caller has to choose
// a contract rather than inherit this one.
//
// Admission is FAIL-FAST, mirroring diagcmd.Limiter's contract and #6809's
// stated reason: a queued request holds the same connection it would have held
// while running, so queueing converts a concurrency bound into a latency bound
// and buys nothing.
//
// It bounds the operational read path only. FrrReloadPy and VtyshLoad are the
// APPLY path, are driven by the daemon rather than by a client, and are already
// serialized by the reload lock — putting them behind a client-facing budget
// would let a status flood refuse a config commit.
func (m *Manager) vtysh(ctx context.Context, command string) (string, error) {
	release, err := diagcmd.VtyshLimiter.Acquire()
	if err != nil {
		return "", ErrVtyshBusy
	}
	defer release()
	return m.executor().Vtysh(ctx, command)
}

// ExecVtysh runs an arbitrary vtysh command and returns the output.
func (m *Manager) ExecVtysh(ctx context.Context, command string) (string, error) {
	return m.vtysh(ctx, command)
}

// GetBFDPeers returns BFD peer status from FRR.
func (m *Manager) GetBFDPeers(ctx context.Context) (string, error) {
	return m.vtysh(ctx, "show bfd peers")
}

// GetRouteMapList returns the route-map configuration from FRR.
func (m *Manager) GetRouteMapList(ctx context.Context) (string, error) {
	return m.vtysh(ctx, "show route-map")
}

// GetISISAdjacencyDetail returns detailed IS-IS adjacency output.
func (m *Manager) GetISISAdjacencyDetail(ctx context.Context) (string, error) {
	return m.vtysh(ctx, "show isis neighbor detail")
}

// GetISISDatabase returns raw IS-IS link-state database output.
func (m *Manager) GetISISDatabase(ctx context.Context) (string, error) {
	return m.vtysh(ctx, "show isis database detail")
}

// GetISISRoutes returns raw IS-IS route output.
func (m *Manager) GetISISRoutes(ctx context.Context) (string, error) {
	return m.vtysh(ctx, "show isis route")
}

// GetOSPFNeighborDetail returns detailed OSPF neighbor output.
func (m *Manager) GetOSPFNeighborDetail(ctx context.Context) (string, error) {
	return m.vtysh(ctx, "show ip ospf neighbor detail")
}

// GetOSPFDatabase returns raw OSPF database output.
func (m *Manager) GetOSPFDatabase(ctx context.Context) (string, error) {
	return m.vtysh(ctx, "show ip ospf database")
}

// GetOSPFInterface returns raw OSPF interface output.
func (m *Manager) GetOSPFInterface(ctx context.Context) (string, error) {
	return m.vtysh(ctx, "show ip ospf interface")
}

// GetOSPFRoutes returns raw OSPF route output.
func (m *Manager) GetOSPFRoutes(ctx context.Context) (string, error) {
	return m.vtysh(ctx, "show ip ospf route")
}

// GetBGPNeighborReceivedRoutes returns received routes for a BGP neighbor.
//
// The neighbor IP is concatenated straight into the `vtysh -c` command,
// so it MUST be a syntactically valid IP address. This is the belt that
// keeps a raw, newline- or space-bearing token off the vtysh command
// line: the show path is reachable over the UNAUTHENTICATED local gRPC
// channel (GetBGPStatus, 127.0.0.1:50051) and, unlike the config path
// (sanitizeFRRValue/validateNodesControlChars, #4097/#1798), never went
// through a sanitizer. net.ParseIP rejects empty, spaces, and embedded
// newlines while accepting both IPv4 and IPv6 neighbors (#4588).
func (m *Manager) GetBGPNeighborReceivedRoutes(ctx context.Context, ip string) (string, error) {
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("invalid neighbor IP %q", ip)
	}
	return m.vtysh(ctx, "show bgp neighbor "+ip+" received-routes")
}

// GetBGPNeighborAdvertisedRoutes returns advertised routes for a BGP neighbor.
//
// The neighbor IP is validated with net.ParseIP before it reaches the
// vtysh command line — see GetBGPNeighborReceivedRoutes for the rationale
// (unauthenticated local gRPC show path, no config-style sanitizer, #4588).
func (m *Manager) GetBGPNeighborAdvertisedRoutes(ctx context.Context, ip string) (string, error) {
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("invalid neighbor IP %q", ip)
	}
	return m.vtysh(ctx, "show bgp neighbor "+ip+" advertised-routes")
}

// GetBGPNeighborDetail returns detailed info for a specific BGP neighbor,
// or all neighbors if ip is empty.
//
// An empty ip is legal (it selects every neighbor). A non-empty ip is
// validated with net.ParseIP so no raw token reaches the vtysh command
// line — see GetBGPNeighborReceivedRoutes for the rationale (#4588).
func (m *Manager) GetBGPNeighborDetail(ctx context.Context, ip string) (string, error) {
	cmd := "show bgp neighbor"
	if ip != "" {
		if net.ParseIP(ip) == nil {
			return "", fmt.Errorf("invalid neighbor IP %q", ip)
		}
		cmd += " " + ip
	}
	return m.vtysh(ctx, cmd)
}
