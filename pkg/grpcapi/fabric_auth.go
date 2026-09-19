package grpcapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/psaab/xpf/pkg/denyaudit"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Fabric gRPC listener authentication (#4107 F1).
//
// The #4122 allowlist already fail-closes the network-exposed fabric listener
// to the handful of read/monitor/failover RPCs the cluster peer legitimately
// proxies. But the allowlist alone is an authorization gate, NOT authentication:
// ANY host on the shared control segment could still invoke those RPCs
// (GetSessions, ClearSessions, MonitorInterface, cross-node cluster-failover)
// with no credential — flushing sessions or driving RG ownership from an
// unauthenticated on-segment attacker.
//
// This layer authenticates the caller with the SAME control-link PSK that #4326
// applies to the heartbeat (cluster.Manager.ControlLinkAuthKey, set via
// `set chassis cluster authentication-key <secret>`). The token is a
// time-windowed HMAC bearer credential carried in gRPC metadata; the fabric
// listener verifies it before the allowlist interceptor runs. The loopback
// (127.0.0.1) listener is UNCHANGED — local callers are trusted.
//
// Dual-accept (rolling upgrade / key rollout), mirroring
// cluster.heartbeatAuthDecision:
//   - No local key configured: accept everything (this node cannot verify; it
//     may be the not-yet-keyed side of a key rollout, or a standalone/legacy
//     node). Standalone nodes never start a fabric listener anyway.
//   - Local key + valid token: accept, and record that the peer holds the key.
//   - Local key + present-but-invalid token: reject (Unauthenticated).
//   - Local key + no token + enforcement NOT armed: accept (grace window while
//     the config-synced key propagates to the peer).
//   - Local key + no token + enforcement armed: reject — a downgrade to
//     tokenless once both nodes are keyed is an attack.
//
// ARMING SOURCE (the #4107 fold): the downgrade-guard arms off EITHER a prior
// valid fabric token OR the heartbeat having authenticated the peer
// (cluster.Manager.HeartbeatPeerAuthSeen). Arming only off the fabric token
// would be LAZY: nothing periodically dials the fabric listener, so after a
// keyed node restarts there is a window — until the peer next proxies an
// on-demand RPC (operator show/clear/failover) — where the fabric would
// grace-accept tokenless ClearSessions / cross-node-failover from any
// on-segment host. Heartbeats flow continuously at ~200ms, so arming off the
// heartbeat closes that window to ~one interval. The rolling-upgrade grace is
// preserved: a not-yet-keyed peer is not signing heartbeats either, so neither
// source arms during the transition.
//
// Residual 1 (same-method replay): the token is HMAC(PSK, domain ||
// method-length || method || window), where window = unix_time /
// fabricAuthWindowSeconds. Binding the canonical gRPC method into the digest
// means a captured GetStatus token cannot be replayed on ClearSessions or
// failover. A same-method retry remains stateless and succeeds while its
// window is accepted (the current window plus one adjacent window for clock
// skew). mTLS with per-node certs would remove that bounded same-method horizon
// entirely and is the deferred stronger posture (#4047 convergence); this PSK
// layer closes the "no auth at all" HIGH hole with zero cert-lifecycle
// machinery, reusing the key the operator already provisions for the heartbeat.
//
// Residual 2 (clock skew): because the token is time-windowed, a wall-clock skew
// between the two nodes larger than the tolerance (window ± 1 = ~60–90s across a
// boundary) makes the peer's token verify against no accepted window, so
// cross-node fabric RPCs fail Unauthenticated until the skew is corrected.
//
// #6708 measured this on the loss userspace cluster — 141s apart,
// NTPSynchronized=no on both nodes, every cross-node RPC dead — so the previous
// wording here ("an accepted tradeoff rather than a bug") was describing a
// hypothetical. What made it expensive was not the rejection but the LABEL: it
// reads as "invalid auth token", identical to a forged token or a PSK mismatch,
// and the operator-visible symptom named sessions ("fw0 has only 1 established
// sessions") while the cause was the clock.
//
// The accept band is still ±1 and deliberately so — it IS the replay horizon,
// and the allowlisted RPCs include ClearSessions and cross-node failover, so
// widening it to tolerate a drifting clock would trade a real attack bound for
// an operational fault the operator can fix in seconds once it is named. What
// changed in #6708 is diagnosis: fabric_auth_skew_6708.go scans a bounded band
// around the local window on the REJECT path and, when the token verifies under
// an accepted key at some other window, reports that offset — an AUTHENTICATED
// measurement, since only a key holder can produce such a token. The rejection
// then names the clock and the remedy, `show chassis cluster status` carries the
// skew, and a forged token or a genuine key mismatch still says nothing about
// clocks. Making fabric RPC skew-INDEPENDENT is a separate design change.

const (
	// fabricAuthMetadataKey is the gRPC metadata header carrying the hex token.
	// Lowercase per the gRPC metadata-key contract.
	fabricAuthMetadataKey = "xpf-fabric-auth"

	// fabricAuthWindowSeconds is the token validity window. The verifier also
	// accepts the adjacent windows (±1), so a token is honored for up to
	// ~2×window across a clock-skew boundary. Small enough to bound replay,
	// large enough to tolerate NTP skew between cluster nodes.
	fabricAuthWindowSeconds = 30

	// fabricAuthDomain is a domain-separation prefix so a fabric token can never
	// be confused with (or substituted for) the heartbeat HMAC, which signs a
	// different byte layout under the same key.
	fabricAuthDomain = "xpf-fabric-grpc-auth\x00"
)

// fabricAuthWindow returns the token window index for a wall-clock time.
func fabricAuthWindow(t time.Time) int64 {
	return t.Unix() / fabricAuthWindowSeconds
}

// computeFabricAuthToken returns HMAC-SHA256(key,
// domain || method-length || method || window) — the raw 32-byte digest for
// one window. The optional method argument lets isolated skew fixtures use an
// empty method; production verification and client credentials always pass the
// full gRPC method explicitly.
func computeFabricAuthToken(key []byte, window int64, method ...string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(fabricAuthDomain))
	methodName := ""
	if len(method) > 0 {
		methodName = method[0]
	}
	// Length-prefix the method so the signed message has one canonical,
	// unambiguous framing before the window integer.
	var ml [8]byte
	methodBytes := []byte(methodName)
	binary.LittleEndian.PutUint64(ml[:], uint64(len(methodBytes)))
	mac.Write(ml[:])
	mac.Write(methodBytes)
	var wb [8]byte
	binary.LittleEndian.PutUint64(wb[:], uint64(window))
	mac.Write(wb[:])
	return mac.Sum(nil)
}

// fabricAuthTokenHex returns the hex-encoded current-window token for a key, or
// "" when no key is configured (a not-yet-keyed peer sends no token — legacy).
// Passing method binds the token to that canonical gRPC method. Omitting method
// is retained only for isolated empty-method skew fixtures; the inbound
// interceptor always supplies the method and never accepts an empty-method
// credential for an RPC.
func fabricAuthTokenHex(key []byte, t time.Time, method ...string) string {
	if len(key) == 0 {
		return ""
	}
	return hex.EncodeToString(computeFabricAuthToken(key, fabricAuthWindow(t), method...))
}

// verifyFabricAuthToken reports whether tokenHex is a valid token for key in
// the current or an adjacent window. Passing method verifies a token bound to
// that canonical gRPC method. Omitting it is retained only for isolated
// empty-method skew fixtures; the inbound interceptor always supplies method.
// The digest comparison is constant-time (hmac.Equal).
func verifyFabricAuthToken(key []byte, tokenHex string, method ...string) bool {
	if len(key) == 0 || tokenHex == "" {
		return false
	}
	got, err := hex.DecodeString(tokenHex)
	if err != nil || len(got) != sha256.Size {
		return false
	}
	now := fabricAuthWindow(time.Now())
	// Accept the current window plus one on each side (clock skew / boundary).
	for _, w := range []int64{now, now - 1, now + 1} {
		if hmac.Equal(got, computeFabricAuthToken(key, w, method...)) {
			return true
		}
	}
	return false
}

// fabricAuthTokenFromMetadata extracts the token header from an inbound context.
// present is false when the caller sent no token (a not-yet-keyed peer).
func fabricAuthTokenFromMetadata(ctx context.Context) (token string, present bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}
	vals := md.Get(fabricAuthMetadataKey)
	if len(vals) == 0 || vals[0] == "" {
		return "", false
	}
	return vals[0], true
}

// fabricAuthDecision applies the #4107 dual-accept policy for one inbound fabric
// RPC and returns whether to accept it (and, when rejected, a short reason for
// logging — never the token or key). It mirrors cluster.heartbeatAuthDecision so
// the two control surfaces share one auth posture.
//
//	keyConfigured — the local ControlLinkAuthKey is set (we can verify).
//	present       — the caller sent an auth token.
//	tokenOK       — the token verified (only meaningful when present).
//	enforceArmed  — the downgrade-guard is armed: the peer has proven it holds
//	                the key, via EITHER a prior valid fabric token OR an
//	                authenticated heartbeat (see checkFabricAuth). Once armed, a
//	                subsequent tokenless call is a downgrade attack, not a
//	                rollout gap.
func fabricAuthDecision(keyConfigured, present, tokenOK, enforceArmed bool) (bool, string) {
	if !keyConfigured {
		return true, ""
	}
	if present {
		if !tokenOK {
			return false, "invalid auth token"
		}
		return true, ""
	}
	if enforceArmed {
		return false, "missing auth token (enforced: peer previously authenticated)"
	}
	return true, ""
}

// fabricAuthKey returns the control-link PSK the fabric listener SIGNS with,
// or nil when none is configured. fabricAuthKeyFn is a test seam; production
// reads the live key from the cluster manager (nil when standalone).
//
// Signing only. Verification goes through fabricAcceptedKeys, which is a
// SUPERSET during a rotation (#6630) — see there.
func (s *Server) fabricAuthKey() []byte {
	if s.fabricAuthKeyFn != nil {
		return s.fabricAuthKeyFn()
	}
	if s.cluster != nil {
		return s.cluster.ControlLinkAuthKey()
	}
	return nil
}

// fabricAcceptedKeys returns every key an inbound fabric token may be verified
// against (#6630): the signing key, plus the additional rotation key while a
// rotation window is open.
//
// The fabric listener widens with the heartbeat, not after it. Both surfaces
// key off the SAME PSK and both are consulted during a failover, so leaving
// one narrow would turn a rotation from "no outage" into "no outage on the
// heartbeat, `Unauthenticated` on every peer-proxied RPC" — a partial fix that
// looks like a whole one right up to the moment an operator needs a
// cross-node RPC mid-rotation.
//
// The test seam is honoured: a test that pins fabricAuthKeyFn gets exactly
// that one key and no widening, so the #4107 fixtures keep meaning what they
// meant.
func (s *Server) fabricAcceptedKeys() [][]byte {
	if s.fabricAuthKeyFn != nil {
		if k := s.fabricAuthKeyFn(); len(k) > 0 {
			return [][]byte{k}
		}
		return nil
	}
	if s.cluster != nil {
		return s.cluster.ControlLinkAcceptedKeys()
	}
	return nil
}

// heartbeatPeerAuthSeen reports whether the cluster heartbeat receiver has
// accepted a valid authenticated heartbeat from the peer — the FAST arming
// signal for the fabric downgrade-guard. Heartbeats flow continuously (~200ms),
// so this arms within one interval of a keyed peer coming up, whereas the
// fabric's own sticky flag arms only when the peer next dials an on-demand RPC
// (an operator show/clear/failover) — which may be a long time, leaving a
// post-restart window where the fabric would grace-accept tokenless calls.
// heartbeatAuthSeenFn is a test seam; production reads the cluster manager.
func (s *Server) heartbeatPeerAuthSeen() bool {
	if s.heartbeatAuthSeenFn != nil {
		return s.heartbeatAuthSeenFn()
	}
	if s.cluster != nil {
		return s.cluster.HeartbeatPeerAuthSeen()
	}
	return false
}

// checkFabricAuth authenticates one inbound fabric RPC by its metadata token.
// Returns a codes.Unauthenticated status when the call is rejected; nil to
// admit it. The key is never logged.
func (s *Server) checkFabricAuth(ctx context.Context, method string) error {
	// #6630: verify against every ACCEPTED key so a PSK rotation does not turn
	// every peer-proxied RPC into codes.Unauthenticated for the window between
	// the two nodes' commits. keyConfigured below is the accepted SET being
	// non-empty, for the same reason.
	keys := s.fabricAcceptedKeys()
	token, present := fabricAuthTokenFromMetadata(ctx)
	tokenOK := false
	if present {
		for _, k := range keys {
			if verifyFabricAuthToken(k, token, method) {
				tokenOK = true
				break
			}
		}
	}
	if tokenOK {
		// Sticky: once the peer proves it holds the key on the fabric channel,
		// a later tokenless call is a downgrade attack, not a rollout gap.
		s.fabricPeerAuthSeen.Store(true)
		// #6708: the clocks agree again — stop reporting a skew and re-arm the
		// one-shot warning for the next episode.
		s.noteFabricAuthOK()
	}
	// The downgrade-guard is armed by EITHER a prior valid fabric token OR the
	// heartbeat having authenticated the peer. The heartbeat path is what closes
	// the post-restart window: after a keyed node restarts, nothing dials its
	// fabric listener on-demand to arm the sticky flag, but its heartbeat
	// receiver re-authenticates the peer within ~one interval and arms
	// enforcement immediately. In a rolling upgrade where the peer is not yet
	// keyed, the peer is not signing heartbeats either, so neither source arms
	// and the dual-accept grace still holds.
	armed := s.fabricPeerAuthSeen.Load() || s.heartbeatPeerAuthSeen()
	accept, reason := fabricAuthDecision(len(keys) > 0, present, tokenOK, armed)
	if !accept {
		// #6708: a present-but-invalid token may be a forgery, a wrong PSK, or
		// a peer whose wall clock has drifted past the ±1-window accept band —
		// and those read IDENTICALLY as "invalid auth token". The throttled
		// scan distinguishes them: it only reports a skew when the token
		// verifies under an accepted key at some other window, which only a key
		// holder can produce. A forgery or a genuine key mismatch adds nothing,
		// so a bad-PSK failure is never mislabelled as a clock problem.
		if present && !tokenOK {
			reason += s.noteFabricAuthSkew(keys, token, time.Now(), method)
		}
		// #9042: the fabric listener is NETWORK-EXPOSED, so this is the
		// worst-positioned of the five sites -- an off-box peer controls the
		// rate. Keyed on the reason rather than a remote address: the address
		// is attacker-supplied and would spread one flood across every bucket.
		if emit, suppressed := denyaudit.Note(denyaudit.SurfaceFabricAuth, reason); emit {
			slog.Warn("fabric gRPC listener rejected call: authentication failed",
				"method", method, "reason", reason,
				"suppressed_since_last", suppressed,
				"denials_total", denyaudit.Total(denyaudit.SurfaceFabricAuth))
		} else {
			slog.Debug("fabric gRPC listener rejected call: authentication failed",
				"method", method, "reason", reason)
		}
		return status.Errorf(codes.Unauthenticated, "fabric RPC authentication failed: %s", reason)
	}
	return nil
}

// fabricAuthUnaryInterceptor authenticates unary RPCs on the fabric listener
// with the control-link PSK (#4107). It runs BEFORE the #4122 allowlist
// interceptor, so an unauthenticated caller is rejected before authorization is
// even consulted. The loopback listener does NOT install this interceptor.
func (s *Server) fabricAuthUnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if err := s.checkFabricAuth(ctx, info.FullMethod); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

// fabricAuthStreamInterceptor authenticates streaming RPCs on the fabric
// listener with the control-link PSK (#4107), before the #4122 allowlist.
func (s *Server) fabricAuthStreamInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := s.checkFabricAuth(ss.Context(), info.FullMethod); err != nil {
		return err
	}
	return handler(srv, ss)
}

// fabricAuthMethodContextKey carries the full gRPC method from the client
// interceptor to the per-RPC credentials callback. gRPC's uri argument to
// GetRequestMetadata is only the service audience, not the method, so relying
// on uri would leave every RPC in a service sharing one replayable token.
type fabricAuthMethodContextKey struct{}

func withFabricAuthMethod(ctx context.Context, method string) context.Context {
	return context.WithValue(ctx, fabricAuthMethodContextKey{}, method)
}

// WithFabricAuthMethod is a narrow helper for custom fabric clients that need
// to compose the credential manually. Generated gRPC clients should install
// FabricAuthUnaryClientInterceptor and FabricAuthStreamClientInterceptor
// instead, which populate this context automatically.
func WithFabricAuthMethod(ctx context.Context, method string) context.Context {
	return withFabricAuthMethod(ctx, method)
}

func fabricAuthMethod(ctx context.Context) string {
	method, _ := ctx.Value(fabricAuthMethodContextKey{}).(string)
	return method
}

// FabricAuthUnaryClientInterceptor carries the exact method being invoked to
// fabricAuthCreds. Install it alongside NewFabricAuthCreds on every fabric
// client connection.
func FabricAuthUnaryClientInterceptor(
	ctx context.Context,
	method string,
	req, reply interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts ...grpc.CallOption,
) error {
	return invoker(withFabricAuthMethod(ctx, method), method, req, reply, cc, opts...)
}

// FabricAuthStreamClientInterceptor carries the exact stream method being
// invoked to fabricAuthCreds. Install it alongside NewFabricAuthCreds on every
// fabric client connection.
func FabricAuthStreamClientInterceptor(
	ctx context.Context,
	desc *grpc.StreamDesc,
	cc *grpc.ClientConn,
	method string,
	streamer grpc.Streamer,
	opts ...grpc.CallOption,
) (grpc.ClientStream, error) {
	return streamer(withFabricAuthMethod(ctx, method), desc, cc, method, opts...)
}

// fabricAuthCreds is the client-side gRPC per-RPC credential that attaches the
// control-link PSK token bound to the full method being invoked. keyFn is read
// fresh per RPC so the token rotates with the window and picks up a live key
// change. Calls made without one of the method-carrying client interceptors
// deliberately emit no metadata rather than falling back to a cross-method
// replayable token.
type fabricAuthCreds struct {
	keyFn func() []byte
}

func (c fabricAuthCreds) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	method := fabricAuthMethod(ctx)
	if method == "" || c.keyFn == nil {
		return nil, nil
	}
	token := fabricAuthTokenHex(c.keyFn(), time.Now(), method)
	if token == "" {
		return nil, nil
	}
	return map[string]string{fabricAuthMetadataKey: token}, nil
}

func (c fabricAuthCreds) RequireTransportSecurity() bool { return false }

// NewFabricAuthCreds returns the client-side per-RPC credential that attaches
// the #4107 control-link PSK token to every RPC dialed on a peer's fabric
// listener. Pair it with FabricAuthUnaryClientInterceptor and
// FabricAuthStreamClientInterceptor; without those interceptors no token is
// emitted, which is safer than silently reverting to an unbound credential.
func NewFabricAuthCreds(keyFn func() []byte) credentials.PerRPCCredentials {
	return fabricAuthCreds{keyFn: keyFn}
}
