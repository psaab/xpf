package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	dpformat "github.com/psaab/xpf/pkg/dataplane/userspace/format"
	"github.com/psaab/xpf/pkg/diagcmd"
)

func (s *Server) systemInfoHandler(w http.ResponseWriter, r *http.Request) {
	typ := r.URL.Query().Get("type")
	var b strings.Builder

	switch typ {
	case "uptime":
		data, err := os.ReadFile("/proc/uptime")
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		fields := strings.Fields(string(data))
		if len(fields) < 1 {
			writeError(w, http.StatusInternalServerError, "unexpected /proc/uptime format")
			return
		}
		var upSec float64
		fmt.Sscanf(fields[0], "%f", &upSec)

		days := int(upSec) / 86400
		hours := (int(upSec) % 86400) / 3600
		mins := (int(upSec) % 3600) / 60
		secs := int(upSec) % 60

		now := time.Now()
		fmt.Fprintf(&b, "Current time: %s\n", now.Format("2006-01-02 15:04:05 MST"))
		fmt.Fprintf(&b, "System booted: %s\n", now.Add(-time.Duration(upSec)*time.Second).Format("2006-01-02 15:04:05 MST"))
		fmt.Fprintf(&b, "Daemon uptime: %s\n", time.Since(s.startTime).Truncate(time.Second))
		if days > 0 {
			fmt.Fprintf(&b, "System uptime: %d days, %d hours, %d minutes, %d seconds\n", days, hours, mins, secs)
		} else {
			fmt.Fprintf(&b, "System uptime: %d hours, %d minutes, %d seconds\n", hours, mins, secs)
		}

	case "memory":
		data, err := os.ReadFile("/proc/meminfo")
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		info := make(map[string]uint64)
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				key := strings.TrimSuffix(parts[0], ":")
				val, _ := strconv.ParseUint(parts[1], 10, 64)
				info[key] = val
			}
		}
		total := info["MemTotal"]
		free := info["MemFree"]
		buffers := info["Buffers"]
		cached := info["Cached"]
		available := info["MemAvailable"]
		used := total - free - buffers - cached

		fmt.Fprintf(&b, "%-20s %10s\n", "Type", "kB")
		fmt.Fprintf(&b, "%-20s %10d\n", "Total memory", total)
		fmt.Fprintf(&b, "%-20s %10d\n", "Used memory", used)
		fmt.Fprintf(&b, "%-20s %10d\n", "Free memory", free)
		fmt.Fprintf(&b, "%-20s %10d\n", "Buffers", buffers)
		fmt.Fprintf(&b, "%-20s %10d\n", "Cached", cached)
		fmt.Fprintf(&b, "%-20s %10d\n", "Available", available)
		if total > 0 {
			fmt.Fprintf(&b, "Utilization: %.1f%%\n", float64(used)/float64(total)*100)
		}

	default:
		writeError(w, http.StatusBadRequest, "type parameter required (uptime, memory)")
		return
	}

	writeOK(w, TextResponse{Output: b.String()})
}

// diagLimiter is the aggregate concurrency bound for the REST
// ping/traceroute handlers. It points at the process-wide
// diagcmd.DefaultLimiter so a diagnostic admitted over REST and one
// admitted over gRPC draw from the SAME MaxConcurrentDiagnostics budget
// — a request flood on either surface cannot exhaust host PIDs/FDs/
// goroutines (#5057). It is a package var so a test can swap in a fresh
// limiter without mutating global state.
var diagLimiter = diagcmd.DefaultLimiter

// diagRun executes a diagnostic argv and returns combined stdout+stderr.
// It is a package var so a test can inject a fake slow diagnostic and
// exercise the concurrency limiter without spawning real ping/traceroute
// subprocesses. The default mirrors the handlers' prior inline behavior:
// CommandContext under the caller's request-sized deadline, with
// WaitDelay capping the post-kill pipe-drain window (#1805).
var diagRun = func(ctx context.Context, argv []string) (string, error) {
	c := exec.CommandContext(ctx, argv[0], argv[1:]...)
	c.WaitDelay = requestExecWaitDelay
	out, err := c.CombinedOutput()
	return string(out), err
}

func (s *Server) pingHandler(w http.ResponseWriter, r *http.Request) {
	var req PingRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.Target == "" {
		writeError(w, http.StatusBadRequest, "target required")
		return
	}
	// #6904: bound every operator-supplied string field before it reaches exec
	// argv. The gRPC sibling has enforced this since #5060; REST did not, so
	// the guarantee was not a system property. Both surfaces now call the same
	// diagcmd.CheckArgs — sharing the RULE, not a second literal 512.
	if err := diagcmd.CheckArgs(req.Target, req.Source, req.RoutingInstance); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	count := diagcmd.ClampPingCount(req.Count)

	// Aggregate concurrency bound (#5057): acquire a diagnostic slot
	// before spawning any child. Fail-fast with 429 when the cap is
	// reached so a request flood is rejected immediately instead of
	// piling up processes/FDs/goroutines. Release on EVERY path via
	// defer (success, exec error, ctx timeout/cancel, panic).
	release, err := diagLimiter.Acquire()
	if err != nil {
		writeError(w, http.StatusTooManyRequests,
			"diagnostic concurrency limit reached; retry shortly")
		return
	}
	defer release()

	cmd := buildPingArgv(req, count)

	// Request-sized budget (#1819): count × 1s + slack, 30s floor,
	// 150s ceiling — see pingExecTimeout in exec_timeout.go.
	ctx, cancel := context.WithTimeout(r.Context(), pingExecTimeout(count))
	defer cancel()
	output, err := diagRun(ctx, cmd)
	if err != nil {
		output += "\n" + err.Error()
	}
	writeOK(w, TextResponse{Output: output})
}

func (s *Server) tracerouteHandler(w http.ResponseWriter, r *http.Request) {
	var req TracerouteRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.Target == "" {
		writeError(w, http.StatusBadRequest, "target required")
		return
	}
	// #6904: same bound as the ping handler and the gRPC surface.
	if err := diagcmd.CheckArgs(req.Target, req.Source, req.RoutingInstance); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Aggregate concurrency bound (#5057): see pingHandler. One shared
	// limiter covers ping AND traceroute across REST and gRPC.
	release, err := diagLimiter.Acquire()
	if err != nil {
		writeError(w, http.StatusTooManyRequests,
			"diagnostic concurrency limit reached; retry shortly")
		return
	}
	defer release()

	cmd := buildTracerouteArgv(req)

	// Shared diag budget (#1819): same 60s as the gRPC Traceroute path
	// — see diagTracerouteTimeout in exec_timeout.go.
	ctx, cancel := context.WithTimeout(r.Context(), diagTracerouteTimeout)
	defer cancel()
	output, err := diagRun(ctx, cmd)
	if err != nil {
		output += "\n" + err.Error()
	}
	writeOK(w, TextResponse{Output: output})
}

// buildPingArgv builds the argv for the REST ping handler. It delegates
// to the shared diagcmd builder so the VRF-device normalization (apply
// "vrf-" exactly once, #2143) and the "--" end-of-options separator
// (option-confusion hardening, #2084) match the CLI and gRPC surfaces
// byte-for-byte. count is the already-clamped probe count.
func buildPingArgv(req PingRequest, count int) []string {
	size := ""
	if req.Size > 0 {
		// Clamp the payload to the max valid ICMP echo data (#5250 A8-b1
		// F4): an operator-supplied -s above diagcmd.MaxPingSize could never
		// yield a valid probe, so cap it here rather than hand the ping child
		// a value it would reject.
		s := req.Size
		if s > diagcmd.MaxPingSize {
			s = diagcmd.MaxPingSize
		}
		size = fmt.Sprintf("%d", s)
	}
	return diagcmd.PingArgv(diagcmd.PingOptions{
		Target:          req.Target,
		Count:           fmt.Sprintf("%d", count),
		Source:          req.Source,
		Size:            size,
		RoutingInstance: req.RoutingInstance,
	})
}

// buildTracerouteArgv builds the argv for the REST traceroute handler.
// Like buildPingArgv it delegates to the shared diagcmd builder so VRF
// normalization (#2143) and the "--" separator (#2084) stay identical
// across the CLI, REST, and gRPC surfaces.
func buildTracerouteArgv(req TracerouteRequest) []string {
	return diagcmd.TracerouteArgv(diagcmd.TracerouteOptions{
		Target:          req.Target,
		Source:          req.Source,
		RoutingInstance: req.RoutingInstance,
	})
}

// systemBuffersHandler answers the REST buffer query.
//
// This is the one surface that cannot say "not loaded", and the omission is
// knowing rather than accidental. It takes three independent loads of the
// cell — IsLoaded here, dpProbe below, and GetMapStats further down. The
// gRPC and CLI peers now take one load each, but they did not get there in
// a single step: #2114 converted only their USERSPACE arm, and their
// map-stats arm still ended in a second load (dp.SessionCount()) until
// #6743 r4-F1. Do not read the peers as a finished pattern this handler
// was measured against; read them as a pattern that took two passes.
//
// The outcome here is nonetheless equivalent, and the reason is NOT that
// "every load of an empty cell agrees" — that answers a different
// question, since the interesting schedule is a cell that is FULL at load
// 1 and empty afterwards. What actually saves it is that both later loads
// FAIL CLOSED to the same body the early return produces: on an emptied
// cell dpProbe() resolves nil so the Status() assertion fails, and
// GetMapStats() returns nil so the loop appends nothing and writeOK emits
// the same empty list as the `!IsLoaded()` return above. A torn view in
// which the cell only EMPTIES is therefore byte-identical to the untorn
// one.
//
// That scope is deliberate: the argument covers MONOTONE schedules and not
// a REFILL. If the cell were to empty before load 2 and be RE-PUBLISHED
// before load 3, dpProbe() would be nil so the userspace arm is skipped,
// and GetMapStats() would then resolve the new backend and emit MAP rows
// where an untorn view of either instant would have emitted userspace rows
// — a different body, not a byte-identical one.
//
// #6743 r6-B3, correcting r5: that schedule is NOT reachable in a running
// daemon, and the example r5 gave for it was doubly wrong. Commit-confirmed
// rollback does not empty the cell at all — bootstrap.go's teardown calls
// Teardown() and deliberately KEEPS the object ("Keep the object so a later
// confirmed commit re-arms it via runBootstrapExitStartup"), a retention
// contract daemon_dp_live.go states again and TestDataplaneCell_Rollback-
// RearmRecurrence pins. Unwrap and resolve key on the cell's NIL-ness, never
// on armed-ness, so on that path load 2 resolves the retained backend and
// the userspace arm is not skipped: the scenario's own premise never holds
// there. More generally the cell is MONOTONE within a daemon lifetime —
// exactly one production site publishes a non-nil value
// (daemon_run_bringup.go's setupDataplaneAndInitialConfig, reached once from
// the boot phase list), and every other writer publishes nil. So the refill
// arm above is a statement about a shape this handler could take, not a gap
// it has.
//
// That premise is load-bearing for the paragraph above, so it is bound
// rather than asserted: pkg/daemon's TestDataplaneCellRefilledOnlyAtBoot
// reds if a second non-nil publication site appears. If you are reading
// this because that test failed, the byte-identity argument here is what
// your change invalidated.
//
// What remains is a SURFACE gap: for identical daemon state gRPC and CLI
// print "Dataplane not loaded", while REST returns 200 with an empty list,
// which a client cannot distinguish from a healthy firewall that simply
// has no buffers. The divergence predates this change. It is recorded here
// because this is the change that made every other surface deliberately
// uniform, which is what turns leaving REST alone into a decision instead
// of an oversight.
func (s *Server) systemBuffersHandler(w http.ResponseWriter, _ *http.Request) {
	if s.dp == nil || !s.dp.IsLoaded() {
		writeOK(w, []BufferInfo{})
		return
	}

	if provider, ok := s.dpProbe().(interface {
		Status() (dpuserspace.ProcessStatus, error)
	}); ok {
		status, err := provider.Status()
		if err != nil {
			msg := fmt.Sprintf("userspace buffer status unavailable: %v", err)
			writeError(w, http.StatusServiceUnavailable, msg)
			return
		}
		rows := dpformat.StructuredSystemBufferRows(status, false)
		if len(rows.Utilization) == 0 {
			msg := "userspace buffer status missing bounded capacity fields"
			writeError(w, http.StatusServiceUnavailable, msg)
			return
		}
		buffers := make([]BufferInfo, 0, len(rows.Utilization)+len(rows.Counters))
		for _, row := range rows.Utilization {
			buffers = append(buffers, BufferInfo{
				Name:         row.Name,
				Type:         "Userspace",
				Scope:        row.Scope,
				MaxEntries:   row.Capacity,
				UsedCount:    row.Used,
				UsagePercent: row.UsagePercent,
				Status:       row.Status,
			})
		}
		for _, row := range rows.Counters {
			buffers = append(buffers, BufferInfo{
				Name:   row.Name,
				Type:   "UserspaceCounter",
				Scope:  row.Scope,
				Value:  row.Value,
				Status: "OK",
			})
		}
		writeOK(w, buffers)
		return
	}

	stats := s.dp.GetMapStats()
	buffers := make([]BufferInfo, 0, len(stats))
	for _, st := range stats {
		usage := 0.0
		status := "OK"
		if st.MaxEntries > 0 && st.Type != "Array" && st.Type != "PerCPUArray" {
			usage = float64(st.UsedCount) / float64(st.MaxEntries) * 100
			if usage >= 90 {
				status = "CRITICAL"
			} else if usage >= 80 {
				status = "WARNING"
			}
		}
		buffers = append(buffers, BufferInfo{
			Name:         st.Name,
			Type:         st.Type,
			MaxEntries:   uint64(st.MaxEntries),
			UsedCount:    uint64(st.UsedCount),
			UsagePercent: usage,
			Status:       status,
		})
	}
	writeOK(w, buffers)
}

// apiSchedulePowerAction runs `systemctl <arg>` after a 1s grace so the HTTP
// response reaches the client first. It is a package var so a test can drive
// the reboot/halt REST verbs (to assert the #4108 F8 / #4484 L-1 journal
// wiring) WITHOUT actually taking the host down. Mirrors the grpcapi
// schedulePowerAction seam.
var apiSchedulePowerAction = func(systemctlArg string) {
	go func() {
		time.Sleep(1 * time.Second)
		// context.Background(): a confirmed power action must not be
		// cancelled by client disconnect. Errors ignored as before.
		runTimeout(context.Background(), "systemctl", systemctlArg)
	}()
}

// logSystemAction records a destructive maintenance action to the configstore
// audit journal BEFORE it executes (#4108 F8, #4484 L-1). The gRPC
// SystemAction handler already journals reboot/halt/power-off/zeroize; the
// REST path did not, so a reboot/halt issued over the REST API left NO durable
// attributable trail (the journald slog line does not survive the reboot).
// Best-effort: a nil store (standalone build / unit test without a store) is
// skipped, and the store layer never blocks the confirmed action on a journal
// write failure.
func (s *Server) logSystemAction(action string, r *http.Request) {
	if s.store == nil {
		return
	}
	s.store.LogSystemActionAs(action, journalPrincipalForRequest(r, ""))
}

func (s *Server) systemActionHandler(w http.ResponseWriter, r *http.Request) {
	var req SystemActionRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}

	switch req.Action {
	case "reboot":
		// Journal BEFORE the box goes down: the fsynced record survives the
		// reboot even though the journald line does not (#4108 F8 / #4484 L-1).
		s.logSystemAction("reboot", r)
		apiSchedulePowerAction("reboot")
		writeOK(w, map[string]string{"message": "System going down for reboot NOW!"})

	case "halt":
		s.logSystemAction("halt", r)
		apiSchedulePowerAction("halt")
		writeOK(w, map[string]string{"message": "System halting NOW!"})

	case "clear-config-lock":
		// Self-recover a wedged candidate-config lock over REST (parity with
		// the gRPC SystemAction verb, #4484 L-1). Non-destructive: it only
		// force-exits the configure session that holds the lock, so an
		// operator can recover from an H-3 / #4476 lock wedge without shell
		// access to the box.
		if s.store == nil {
			writeError(w, http.StatusServiceUnavailable, "config store not available")
			return
		}
		holder, locked := s.store.ConfigHolder()
		if !locked {
			writeOK(w, map[string]string{"message": "No configuration lock held"})
			return
		}
		s.store.ForceExitConfigure()
		writeOK(w, map[string]string{"message": fmt.Sprintf("Configuration lock cleared (was held by %s)", holder)})

	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown action: %s (use 'reboot', 'halt', or 'clear-config-lock')", req.Action))
	}
}
