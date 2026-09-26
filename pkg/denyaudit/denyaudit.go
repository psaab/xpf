// Package denyaudit bounds the log volume of authorization denials while
// keeping the aggregate observable.
//
// #9042: five denial sites emitted an unconditional slog.Warn PER REQUEST --
// two of them on the network-exposed fabric listener -- with no limiter, no
// dedup, and no counter. The denial path is exactly the path whose rate an
// attacker controls: `principalForPeer` returns Unauthenticated for any
// unattributable peer and `PrincipalForUID` returns an empty-Class principal
// for any resolvable UID that is not a configured login user, so every local
// non-root UID can drive the line at one Warn per unary call.
//
// Warn always ships (default level is Info) and every record fans out to remote
// syslog, so this was off-box traffic per denied RPC -- and journald's stock
// 10000/30s cap then suppresses xpfd's OTHER lines, the drowning mechanism this
// project was already bitten by with the HA watchdog.
//
// THE COUNTER IS THE LOAD-BEARING HALF, NOT AN EXTRA. There was no denial
// metric anywhere and the audit journal records no authorization events, so a
// bare demote to Debug would have deleted the only signal that a denial
// happened. Bounding the volume must not hide the volume: suppressed
// occurrences are counted and reported with the next emission, and the
// per-surface totals are exported so the aggregate survives at any log level.
package denyaudit

import (
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"
)

// Surface names a denial site class. One per distinct decision, so an operator
// reading the metric can tell a loopback authorization denial from a fabric
// authentication failure without correlating logs.
type Surface string

const (
	SurfaceGRPCLoginClass Surface = "grpc_login_class"
	SurfaceFabricAuth     Surface = "fabric_auth"
	SurfaceFabricMethod   Surface = "fabric_method_allowlist"
	SurfaceFabricStream   Surface = "fabric_stream_allowlist"
	SurfaceRESTCrossSite  Surface = "rest_cross_site"
	// #10832: REST login-class denials (pkg/api/authz.go) and api-auth
	// credential failures (dynamicAuthMiddleware) were Debug-only with no
	// counter, invisible at the shipped Info level while the gRPC half was
	// Warned and counted. Same bounded pattern as the surfaces above.
	SurfaceRESTLoginClass  Surface = "rest_login_class"
	SurfaceRESTAPIAuthFail Surface = "rest_api_auth_fail"
)

// Surfaces returns every surface, in a stable order.
//
// A FUNCTION rather than a second list, following the #8312 convention: a
// duplicated enumeration of the same fact is the drift this codebase has been
// bitten by, so the collector and any test read THIS.
func Surfaces() []Surface {
	return []Surface{
		SurfaceGRPCLoginClass,
		SurfaceFabricAuth,
		SurfaceFabricMethod,
		SurfaceFabricStream,
		SurfaceRESTCrossSite,
		SurfaceRESTLoginClass,
		SurfaceRESTAPIAuthFail,
	}
}

// Interval bounds how often one bucket may emit. It matches the cluster
// heartbeat-reject limiter's 30s so two lines describing denials cannot
// disagree about their rate.
const Interval = 30 * time.Second

// nowNanos is the injectable clock. The interval is the thing under test, so a
// test must step across it without sleeping. Production never replaces it.
var nowNanos = func() int64 { return time.Now().UnixNano() }

// resetForTest clears all windows. Package state is process-wide, so tests
// that assert a FIRST emission must start from a known state or they measure
// whatever ran before them.
func resetForTest() {
	for i := range state {
		// Reset the FIELDS, not the struct. `state[i] = bucket{}` while
		// holding state[i].mu replaces the mutex itself, so the deferred
		// unlock releases a different, unlocked mutex -- "sync: unlock of
		// unlocked mutex", fatal and not recoverable.
		state[i].mu.Lock()
		state[i].lastNanos = 0
		state[i].started = false
		state[i].suppressed = 0
		state[i].mu.Unlock()
	}
}

// ResetWindowsForTest clears all rate-limit windows for tests OUTSIDE this
// package that assert a FIRST emission (#10832: pkg/api proves a denied REST
// request Warns at the shipped Info level). Same caveat as resetForTest —
// package state is process-wide — so callers must not run in parallel with
// other tests that assert emissions. Counters are untouched: Total stays
// monotonic across a reset.
func ResetWindowsForTest() { resetForTest() }

// buckets is FIXED, and that is the point.
//
// A per-principal map would be keyed by attacker-supplied identity -- a remote
// address, a UID, a method name -- so an attacker varying the key grows the map
// without bound. That is the SAME defect class this package exists to fix, one
// level down: a limiter whose key space is attacker-controlled is not a bound.
// Hashing into a fixed number of buckets keeps memory constant. THE COST IS
// REAL AND IS ACCEPTED DELIBERATELY: two principals can share a window, so
// under an attacker who varies the key fast enough to occupy every bucket, a
// legitimate new principal's FIRST denial may be suppressed rather than logged
// promptly.
//
// That trade cannot be avoided, only chosen. Guaranteeing every new key logs
// immediately means the line count grows with the key count, which is the flood
// this package exists to stop -- and the key count is attacker-controlled. So
// the bound wins, and observability is preserved by the two things that do NOT
// degrade under load: the per-surface counter advances on every denial
// including suppressed ones, and each emitted line carries the number
// suppressed since the last. An operator under that attack sees a rate, not
// silence.
const buckets = 64

type bucket struct {
	mu         sync.Mutex
	lastNanos  int64
	started    bool
	suppressed uint64
}

var (
	state  [buckets]bucket
	totals = func() map[Surface]*atomic.Uint64 {
		m := make(map[Surface]*atomic.Uint64, len(Surfaces()))
		for _, s := range Surfaces() {
			m[s] = &atomic.Uint64{}
		}
		return m
	}()
)

// Note records one denial on surface s attributed to key, and reports whether a
// log line should be emitted now and how many were suppressed since the last
// emission for that bucket.
//
// The counter is incremented on EVERY call, including suppressed ones -- that
// is what keeps the aggregate true while the log stays bounded.
// bucketIndexForTest exposes the bucket choice so a test can distinguish "this
// key reached a FREE bucket" from "it collided", which is the difference
// between the guarantee the design makes and the one it does not.
func bucketIndexForTest(s Surface, key string) uint32 { return bucketIndex(s, key) }

func bucketIndex(s Surface, key string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(string(s)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(key))
	return h.Sum32() % buckets
}

func Note(s Surface, key string) (emit bool, suppressed uint64) {
	if c, ok := totals[s]; ok {
		c.Add(1)
	}
	b := &state[bucketIndex(s, key)]

	b.mu.Lock()
	defer b.mu.Unlock()
	now := nowNanos()
	if b.started && now-b.lastNanos < int64(Interval) {
		b.suppressed++
		return false, 0
	}
	b.started = true
	b.lastNanos = now
	suppressed, b.suppressed = b.suppressed, 0
	return true, suppressed
}

// Total returns the cumulative denial count for a surface. Process-lifetime and
// monotonic: a restart resets it, which is the ordinary Prometheus counter
// contract and is handled by rate() at query time.
func Total(s Surface) uint64 {
	if c, ok := totals[s]; ok {
		return c.Load()
	}
	return 0
}
