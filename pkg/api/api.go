package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// apiRuntimeDataPlane is the API server's legacy-compatible runtime surface.
// It intentionally stays narrower than dataplane.DataPlane while REST handlers
// still migrate one domain at a time.
type apiRuntimeDataPlane interface {
	IsLoaded() bool
	IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
	// GetSessionV4/V6 look up a single session entry by key. The session
	// view uses them to merge the companion reverse entry's counters into
	// the forward entry, matching the gRPC enrichment (#3419 H3). Without
	// the merge, REST top-talkers/accounting under-report the reverse
	// direction's volume.
	GetSessionV4(dataplane.SessionKey) (dataplane.SessionValue, error)
	GetSessionV6(dataplane.SessionKeyV6) (dataplane.SessionValueV6, error)
	// SessionCount returns the live forward-only count. The cancellable
	// variant is used by request-bound full-table reads.
	SessionCount() (v4, v6 int)
	SessionCountContext(context.Context) (v4, v6 int, err error)
	ClearAllSessions() (int, int, error)

	ReadGlobalCounter(uint32) (uint64, error)
	ReadInterfaceCounters(int) (dataplane.InterfaceCounterValue, error)
	ReadZoneCounters(uint16, int) (dataplane.CounterValue, error)
	ReadPolicyCounters(uint32) (dataplane.CounterValue, error)
	ReadFilterConfig(uint32) (dataplane.FilterConfig, error)
	ReadFilterCounters(uint32) (dataplane.CounterValue, error)
	ReadNATRuleCounter(uint32) (dataplane.CounterValue, error)
	ReadNATPortCounter(uint32) (uint64, error)
	ClearAllCounters() error
	GetMapStats() []dataplane.MapStats
}

// writeJSON encodes v and writes it as the response body with the given
// status. It marshals to a buffer FIRST so a marshal failure becomes a
// clean 500 instead of a truncated 200: the old form set the 200 status
// line and Content-Type before json.NewEncoder(w).Encode(v) ran, so an
// Encode error (a partial write, already committed to the 200 status) left
// the client with a truncated body under a success code (#4541). Buffering
// first keeps the header uncommitted until the encode is known to succeed.
//
// The success path is byte-identical to the previous behavior: json.Marshal
// produces the same bytes as Encoder.Encode minus its trailing newline, so
// the '\n' is re-appended to preserve the exact wire body.
func writeJSON(w http.ResponseWriter, status int, v any) {
	buf, err := json.Marshal(v)
	if err != nil {
		slog.Error("api: failed to encode JSON response", "err", err, "status", status)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		// Static body: v itself failed to marshal, so nothing derived from
		// it can be safely encoded here.
		w.Write([]byte(`{"success":false,"error":"internal server error: response encoding failed"}` + "\n"))
		return
	}
	buf = append(buf, '\n')
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(buf)
}

func writeOK(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, Response{Success: true, Data: data})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, Response{Success: false, Error: msg})
}

// maxRequestBodyBytes bounds every REST mutation request body (M-7). Without
// it, a mutating handler `json.Decode`s r.Body with no ceiling: a crafted or
// accidental multi-gigabyte POST — e.g. `POST /api/v1/config/load` with a huge
// `Content` string — is buffered whole by the decoder and then parsed a second
// time by the configstore, spiking daemon RSS to an OOM-kill (gosec
// resource-exhaustion; the gRPC side is already bounded by grpc-go's 4 MiB
// default recv cap, so this is REST-specific). 16 MiB is orders of magnitude
// above any legitimate payload — the largest real body is a full candidate
// config, well under a megabyte — while keeping even thousands of concurrent
// maxed-out requests bounded. This is the transport-layer guard; it is
// independent of any parser-layer config-size ceiling (which bounds the parsed
// string, not the wire body).
const maxRequestBodyBytes = 16 << 20 // 16 MiB

// decodeJSONBody caps r.Body at maxRequestBodyBytes, then decodes JSON into
// dst. It returns true on success. On an oversized body it writes HTTP 413; on
// any other decode failure it writes HTTP 400. In BOTH failure cases it has
// already written the error response, so a false return means the caller must
// return from the handler immediately without writing anything else.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func (s *Server) applyResult() *dataplane.ApplyResult {
	if s.dp == nil {
		return nil
	}
	return dataplane.LastApplyResultOf(s.dp)
}

// nodeID returns this node's cluster id (0 standalone or when unwired),
// stamped on the REST session responses so an operator knows which node a
// result was observed on (#3423 M5).
func (s *Server) nodeID() int {
	if s.nodeIDFn == nil {
		return 0
	}
	return s.nodeIDFn()
}

// clusterSession resolves the HA-aware session service the REST handlers
// delegate to for cross-node clear/list/summary (#3423). It returns nil
// (local-only fallback) when the provider is unwired or reports no service
// — the latter guards the typed-nil-in-interface trap for a standalone
// build whose provider returns a nil *grpcapi.Server.
func (s *Server) clusterSession() ClusterSessionService {
	if s.clusterSessionFn == nil {
		return nil
	}
	return s.clusterSessionFn()
}

// The lenient queryInt/queryUint16 helpers that used to sit here are gone
// (#7171). They had zero callers -- every REST handler was moved to the
// FAILS-CLOSED queryIntStrict/queryUint16Strict variants below (#2934, #3443,
// #4926) -- but they were left in place next to their strict replacements,
// which is the failure mode: the two differ only by a suffix, the lenient one
// silently returns the caller's default on a malformed value, and that default
// is routinely a filter sentinel meaning "no filter". A future handler picking
// the shorter name by reflex would reintroduce exactly the cross-zone
// observability widening those three issues each closed by hand. Deleting them
// makes the wrong choice unavailable rather than merely discouraged.

// queryUint16Strict parses a uint16 query parameter and FAILS CLOSED on a
// malformed/out-of-range non-empty value. Filter sentinels such as
// zone=0 mean "no filter", so a typo'd value (zone=abc / zone=65536) must
// NOT silently fall through to the no-filter default — that widens the
// query to every session/event and is a cross-zone observability leak
// (#2934). An empty value returns (def, true); a bad value returns
// (0, false) so the caller can emit HTTP 400, mirroring the gRPC contract
// (pkg/grpcapi sessionFilter.validate → InvalidArgument).
func queryUint16Strict(r *http.Request, key string, def uint16) (uint16, bool) {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def, true
	}
	n, err := strconv.ParseUint(v, 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(n), true
}

// queryIntStrict parses a non-negative int query parameter and FAILS
// CLOSED on a malformed/negative/non-canonical non-empty value (#2934,
// #3679). An empty value returns (def, true); a bad value returns
// (0, false) so the caller can emit HTTP 400. Used for filter/predicate
// parameters (e.g. dst_port in the policy-match simulator) where a bad
// value silently becoming the default is a wildcard that yields a
// misleading verdict.
//
// #3679: parsing routes through config.ParseCanonicalUint rather than
// strconv.Atoi so a signed spelling ("+80" — Atoi accepted it as 80,
// which then simulated port 80) is rejected here exactly as the #3606
// commit-time and dataplane port parsers reject it. ParseCanonicalUint
// requires a bare run of ASCII digits (no sign, no whitespace) and never
// returns a negative value, so the historical n < 0 guard is subsumed.
func queryIntStrict(r *http.Request, key string, def int) (int, bool) {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def, true
	}
	n, err := config.ParseCanonicalUint(v)
	if err != nil {
		return 0, false
	}
	return n, true
}

// parseRefBaseUnit splits a Junos interface ref into its base name
// and unit number, returning ok=false for malformed (non-numeric)
// suffixes. A bare ref returns (ref, 0, true). This matches the
// stricter Atoi semantics used in (*Config).ResolveKernelIfName and
// avoids the partial-numeric-prefix bug fmt.Sscanf has
// (e.g. "80foo" parsing as 80).
func parseRefBaseUnit(ref string) (base string, unitNum int, ok bool) {
	parts := strings.SplitN(ref, ".", 2)
	base = parts[0]
	if len(parts) == 1 {
		return base, 0, true
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil {
		return base, 0, false
	}
	return base, n, true
}

// canonicalInterfaceName returns the canonical row identity for a
// config/zone interface reference (#15726). A unit-0 reference
// ("reth0.0", "ge-0/0/0.0") denotes the same logical interface as its
// bare base ("reth0", "ge-0/0/0"): both resolve to the same kernel
// device via ResolveKernelIfName. Collapsing unit 0 to the base keeps
// one row per physical interface instead of a duplicate bare + ".0"
// pair with split zone attribution (the bare row keyed the raw zone
// string "reth0.0" and therefore got Zone=""). Non-zero units, bare
// names, and declared dotted interface names are returned unchanged.
// A declared dotted name outranks the parse via SplitInterfaceUnitRef.
func canonicalInterfaceName(cfg *config.Config, ref string) string {
	if cfg == nil {
		return ref
	}
	s := cfg.SplitInterfaceUnitRef(ref)
	if s.HasUnit {
		if n, _, err := config.CanonicalLogicalUnit(s.UnitTok); err == nil && n == 0 {
			return s.Base
		}
	}
	return ref
}

// interfaceZoneMap builds the interface->zone map keyed by canonical
// name (#15726) so a zone binding written as "reth0.0" attaches to the
// canonical "reth0" row.
func interfaceZoneMap(cfg *config.Config) map[string]string {
	ifZone := make(map[string]string)
	for zoneName, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		for _, ifName := range zone.Interfaces {
			ifZone[canonicalInterfaceName(cfg, ifName)] = zoneName
		}
	}
	return ifZone
}

// allInterfaceNames returns a deduplicated set of canonical interface
// names from both the interfaces config and zone declarations
// (#15726: unit-0 refs collapse to their base).
func allInterfaceNames(cfg *config.Config) map[string]bool {
	names := make(map[string]bool)
	for ifName := range cfg.Interfaces.Interfaces {
		names[canonicalInterfaceName(cfg, ifName)] = true
	}
	for _, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		for _, ifName := range zone.Interfaces {
			names[canonicalInterfaceName(cfg, ifName)] = true
		}
	}
	return names
}

// dpProbe returns the value that OPTIONAL-capability assertions must be
// made against. See pkg/grpcapi/runtime.go's dpProbe for the full #2114 /
// #6743-F1 rationale: the daemon publishes a live indirection whose method
// set is exactly apiRuntimeDataPlane, so probing it directly erases every
// optional capability (Status(), AppliedNATView, the session cursor) and
// blanks the NAT-pool and userspace Prometheus families on a healthy
// deployment. Unwrap is the identity for a plain backend and nil once the
// daemon has disowned one.
func (s *Server) dpProbe() any {
	if s == nil {
		return nil
	}
	return dataplane.Unwrap(s.dp)
}
