package api

import (
	"net/http"
	"time"

	"github.com/psaab/xpf/pkg/flowexport"
)

// healthHandler surfaces dataplane compile health (#758) and config
// persistence health (#1799) alongside the simple "ok" probe. When the
// dataplane compile has failed and has never succeeded since startup,
// or the running active config failed to persist to disk (a restart
// would load a stale config), return 503 with a structured "status:
// degraded" payload so operators scanning a probe can distinguish the
// catastrophic-silent-fail cases from a healthy daemon.
func (s *Server) healthHandler(w http.ResponseWriter, _ *http.Request) {
	payload := map[string]any{"status": "ok"}
	if s.compileHealthFn != nil {
		h := s.compileHealthFn()
		payload["compile_ever_succeeded"] = h.EverSucceeded
		payload["compile_failure_count"] = h.FailureCount
		// #5031: /health is intentionally unauthenticated (authMiddleware
		// exempts it unconditionally). The raw compile error string
		// (h.LastError) is copied verbatim from the compiler and can carry
		// file paths, config internals, or a secret echoed by a schema
		// validator that quotes the submitted value — so it MUST NOT cross
		// into this always-public payload. Surface only the presence +
		// timestamp of a failure (a stable, non-secret signal); the full
		// detail stays in the journal ("failed to compile dataplane" WARN/
		// ERROR in daemon_health.go) for authenticated operators.
		if h.LastErrorUnixSec != 0 {
			payload["compile_last_error_unix"] = h.LastErrorUnixSec
		}
		if !h.EverSucceeded && h.FailureCount > 0 {
			payload["status"] = "degraded"
			writeJSON(w, http.StatusServiceUnavailable, Response{Success: false, Data: payload, Error: "dataplane compile has never succeeded"})
			return
		}
	}
	// #4184: surface the day-0 / bootstrap config-import outcome. This is a
	// non-fatal field (like rollback_history_degraded): a failed import leaves
	// the box in the lifeline-safe bootstrap state, so it does NOT force a 503
	// — the point is visibility of "why didn't my config apply" beyond a
	// single boot-time journald WARN. The factory no-config state reports
	// bootstrap_import_status without bootstrap_import_failed set.
	if s.bootstrapImportFn != nil {
		b := s.bootstrapImportFn()
		if b.Status != "" {
			payload["bootstrap_import_status"] = b.Status
			payload["bootstrap_import_failed"] = b.Failed
			// #5031: b.Error is the raw import failure string — a parse/commit
			// error that quotes the offending day-0 config, which can include a
			// submitted secret (e.g. a `system login` password echoed by a
			// schema validator). Do NOT emit it on the unauthenticated /health
			// surface. The status enum, failed flag, and timestamp are the
			// stable signal; the full detail stays in the journal and in the
			// in-band BOOTSTRAP_IMPORT_FAILED event (authenticated event stream
			// / ring buffer, daemon_health.go recordBootstrapImport).
			if b.UnixSec != 0 {
				payload["bootstrap_import_unix"] = b.UnixSec
			}
		}
	}
	if s.configPersistDegradedFn != nil {
		degraded := s.configPersistDegradedFn()
		payload["config_persist_degraded"] = degraded
		if degraded {
			payload["status"] = "degraded"
			writeJSON(w, http.StatusServiceUnavailable, Response{Success: false, Data: payload, Error: "active configuration failed to persist to disk; restart would load stale config"})
			return
		}
	}
	// #3441: report rollback-history degradation as a non-fatal field. The
	// active config is durable (the commit succeeded via the #1799 path);
	// only the best-effort text rollback copies failed, so unlike
	// config_persist_degraded this does NOT force a 503 — a perfectly
	// forwarding firewall must not be pulled from rotation over a degraded
	// recovery aid. The xpf_config_rollback_persist_degraded gauge is the
	// alerting hook; this field gives a probe the same visibility.
	if s.rollbackHistoryDegradedFn != nil {
		payload["rollback_history_degraded"] = s.rollbackHistoryDegradedFn()
	}
	// #9811: the node is enforcing a configuration it does not report. A
	// commit-confirmed auto-rollback promotes the store FIRST and then applies;
	// when that apply fails, every other surface in this payload — and `show
	// configuration`, and the peer the rolled-back config was re-synced to —
	// names C1 while the dataplane still enforces C2 under the #5679 contract.
	//
	// This returns 503, unlike rollback_history_degraded directly above. The
	// difference is not severity-by-feel: a degraded rollback history is a
	// recovery aid failing on a node that forwards exactly what it reports, and
	// the comment above is right that such a node must not be pulled from
	// rotation. Here the reported state and the enforced state DISAGREE, which
	// is ConfigPersistDegradedFn's class, and an orchestrator that keeps
	// steering traffic at a node whose policy is not the policy it published is
	// acting on a false premise.
	//
	// #5031: lastErr is a raw apply error and can quote config internals, so it
	// does NOT cross onto this unauthenticated surface. The owed flag and the
	// attempt COUNT are the stable non-secret signal — and the count is the
	// useful one, because a climbing count means the retry owner is running and
	// failing while a flat count with owed set means it is not running at all.
	if s.configApplyDebtFn != nil {
		owed, failures, _ := s.configApplyDebtFn()
		payload["config_apply_debt_owed"] = owed
		payload["config_apply_failure_count"] = failures
		if owed {
			payload["status"] = "degraded"
			writeJSON(w, http.StatusServiceUnavailable, Response{Success: false, Data: payload, Error: "the dataplane is enforcing a configuration other than the active one; a caller-less apply failed and the retry owner has not converged"})
			return
		}
	}
	writeOK(w, payload)
}

// flowExportersHandler surfaces the per-collector NetFlow v9 / IPFIX
// write-health (#2464): for every configured collector, its write
// attempt/failure counters, the current healthy flag, and the last
// error / last success timestamps. Flow export is forensics/compliance
// data; a collector going silently unreachable used to be invisible
// (every failed UDP write was debug-logged and dropped while the
// exporter kept counting "exported"). The response payload mirrors the
// Prometheus xpf_flow_export_collector_* family. Empty when no flow
// export is configured.
func (s *Server) flowExportersHandler(w http.ResponseWriter, _ *http.Request) {
	var collectors []flowexport.ExporterCollectorHealth
	if s.flowCollectorHealthFn != nil {
		collectors = s.flowCollectorHealthFn()
	}
	writeOK(w, map[string]any{"collectors": collectors})
}

func (s *Server) statusHandler(w http.ResponseWriter, _ *http.Request) {
	resp := StatusResponse{
		Uptime:          time.Since(s.startTime).Truncate(time.Second).String(),
		DataplaneLoaded: s.dp != nil && s.dp.IsLoaded(),
		ConfigLoaded:    s.store.ActiveConfig() != nil,
	}
	if cfg := s.store.ActiveConfig(); cfg != nil {
		resp.ZoneCount = len(cfg.Security.Zones)
	}
	// #3929: report the live session count from the dataplane session table,
	// NOT the BPF GC sweep stats. On the userspace dataplane (the only live
	// forwarding path) the BPF GC sweep is skipped (#333), so
	// gc.Stats().TotalEntries is permanently 0 — this reported 0 sessions on
	// every real deployment.
	if s.dp != nil && s.dp.IsLoaded() {
		// #5939: SessionCount() is a full v4+v6 session-map iteration holding the
		// per-bucket BPF-map locks for O(table) — the SAME lock-contention DoS
		// class #5708/#5782 bounded, reachable UNGATED here on the REST surface.
		// Gate it through the shared diagcmd.SessionWalkLimiter (the same instance
		// the /security/sessions* scans use, sessions.go) and fail fast with HTTP
		// 429 on contention rather than driving another concurrent full-table walk,
		// mirroring sessions.go. This is the AUTHENTICATED /api/v1/status query
		// (authCheck exempts only /health + loopback-/metrics); the unauthenticated
		// liveness /health handler does NOT walk the session table, so a 429 here
		// cannot flap the liveness probe.
		release, err := sessionWalkLimiter.Acquire()
		if err != nil {
			writeError(w, http.StatusTooManyRequests,
				"session count concurrency limit reached; retry shortly")
			return
		}
		defer release() // idempotent; released on panic too (limiter contract)
		v4, v6 := s.dp.SessionCount()
		resp.SessionCount = v4 + v6
	}
	writeOK(w, resp)
}
