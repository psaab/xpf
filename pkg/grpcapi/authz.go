package grpcapi

import (
	"context"
	"log/slog"
	"net"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/denyaudit"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// authz.go enforces per-principal authorization on the PRIMARY (loopback) gRPC
// listener (#5278).
//
// # What was wrong
//
// Until this landed, `Run` installed only a message-size cap and the
// connection-scoped config-lock lifecycle owner, and NewServer's doc asserted
// that "gRPC is local-only (127.0.0.1) so all RPCs are inherently trusted".
// That assertion was false on this appliance. The daemon provisions every
// `system login user` a real shell account (`useradd -m -s /bin/bash`,
// pkg/daemon/daemon_system.go), so a `read-only` or `operator` class holder can
// log in and dial 127.0.0.1:50051 with three lines of insecure gRPC client and
// invoke SystemAction{zeroize,reboot,power-off}, Commit, Delete and Rollback —
// executed by a root daemon. pkg/cli's checkPermission runs in the CLI PROCESS,
// on the caller's side of the boundary, so it constrains only callers who
// choose to use the CLI. `cmd/cli` does not even do that: it carries no login
// class at all and never called checkPermission for a remote session.
//
// The #5035 clamp is a LOCATION, not an identity, and #5209 enforces which
// connection holds the config lock, not who is on it.
//
// # Where the identity comes from
//
// The same place the REST leg's does (#5561): pkg/authz reads the owning UID of
// the peer's socket out of the kernel's own socket table. The caller supplies
// nothing and can forge nothing. That UID resolves through /etc/passwd to an
// account name and through `system login user <name> class` to a login class,
// and config.ClassHasPermission — the evaluator pkg/cli uses — decides.
//
// The research plan for this issue (docs/research/5278-loopback-grpc-rbac)
// prescribed a Unix-socket + SO_PEERCRED transport flag-day and REJECTED a
// loopback peer lookup as "inherently racy/TOCTOU (PID reuse ...) socket
// inode -> /proc/<pid> owner". That objection describes a DIFFERENT mechanism:
// pkg/authz reads the uid column of the socket row itself, so there is no
// inode->pid step and no pid to be reused. The transport section of that plan
// is superseded; nothing here changes the listener, the port, or any client.
//
// # There is no credential row here, and that makes this leg STRICTER
//
// pkg/api has two identities (peer UID, and an `api-auth` shared secret) and
// therefore a precedence rule, a locality re-derivation, and a residual for the
// row that admits on the strength of a negative. This listener has ONE: the
// peer UID. Anything that is not an attributed peer UID is denied, whether the
// caller looks local or not. So authz.PeerIdentity.Local is deliberately not
// consulted below — both of its values lead to the same denial when OK is
// false, and authz.PeerCouldBeLocalNow (which exists to narrow the credential
// row) has nothing to narrow.
//
// # Why the identity is captured at connection setup
//
// A caller can take its own socket out of TCP_ESTABLISHED and still have its
// request served — write the whole request, then `shutdown(fd, SHUT_WR)` or an
// SO_LINGER-0 reset. A lookup performed when the RPC is dispatched would then
// find no established row. Under this file's fail-closed default that is a
// denial rather than an escalation, but it is a denial a caller can inflict on
// ITSELF at a moment of its choosing, and (more to the point) it would put a
// socket-table read on every RPC of every long-lived CLI connection.
//
// So the lookup runs once per CONNECTION, in a stats.Handler TagConn, and every
// RPC on that connection is adjudicated against the answer. This mirrors
// pkg/api's ConnContext hook and reuses a seam this package already depends on:
// #5849 established that the context TagConn returns is the connection context
// every stream derives from (connSessionID reads a value installed there).
//
// It is deliberately NOT run in a goroutine, which is where this leg diverges
// from pkg/api. http.Server calls ConnContext SERIALLY IN ITS ACCEPT LOOP, so a
// slow lookup there fills the listen backlog and locks out everyone; pkg/api
// therefore spawns, bounds the spawns, and makes the request wait. grpc-go does
// not: Server.Serve hands each accepted connection to its own goroutine
// (handleRawConn), which finishes the HTTP/2 handshake and only then calls
// serveStreams -> TagConn (google.golang.org/grpc@v1.78.0 server.go:958,
// 1038-1046). A blocking lookup there blocks that connection alone, on a
// goroutine grpc-go already created and would already be blocking on the
// caller's HTTP/2 frames. There is nothing extra to bound, so there is no pool,
// no deadline and no waiter — which also removes every failure mode those have.
//
// The cost this leaves is bounded elsewhere: pkg/authz single-flights the
// /proc/net/tcp{,6} read across concurrent lookups and caps its own queue,
// answering a saturated queue with an error that this file turns into a denial.
// And because Run clamps the primary listener to loopback (#5035), the delivery
// address is always a loopback one, so authz.LookupPeer's locality fallback
// short-circuits on loopbackDelivery and never enumerates interfaces at all.
//
// # What is NOT gated here
//
// The FABRIC listener (RunFabricListener) keeps its own, unrelated chain: the
// #4107 control-link PSK authentication plus the #4122 RPC allowlist. A fabric
// peer is a NODE, not a login user; it has no uid on this host and pkg/authz
// would deny it. The two chains are built in different functions
// (Run vs buildFabricServer) and share no interceptor —
// TestFabricListenerDoesNotInstallThePrincipalGate_5278 pins that they cannot
// be confused.

// connPeerKey is the context key for the per-connection peer identity.
type connPeerKey struct{}

// authorizedPrincipalKey carries the exact principal admitted by the unary
// authorization boundary. Handlers must use it instead of re-resolving
// against a later active-config snapshot.
type authorizedPrincipalKey struct{}

// connPeer is one connection's peer identity, resolved once at connection setup
// and read by every RPC on that connection.
//
// client and server are retained for the log line and for a future caller that
// needs to re-derive something from the addresses; the authorization decision
// itself reads only id.
type connPeer struct {
	id             authz.PeerIdentity
	client, server net.Addr
}

// peerAuthStatsHandler resolves the peer identity of each accepted connection
// and publishes it on the connection context (#5278).
//
// It is a SECOND stats.Handler rather than another responsibility bolted onto
// configLockStatsHandler: grpc.StatsHandler appends (grpc@v1.78.0 server.go:533)
// and the combined handler threads each TagConn's returned context into the
// next (internal/stats/stats.go:59-64), so two handlers compose exactly. Keeping
// them separate means the config-lock lifecycle and the authorization identity
// can be reasoned about — and reverted — independently.
type peerAuthStatsHandler struct {
	s *Server
}

// TagConn resolves the connection's peer identity and stores it on the
// connection context. Every stream on the connection derives from this context.
//
// A missing ConnTagInfo leaves the context untagged, which authorizeRPC treats
// as "identity was not captured" and DENIES. That is the correct direction: an
// untagged connection is one we cannot say anything about.
func (h *peerAuthStatsHandler) TagConn(ctx context.Context, info *stats.ConnTagInfo) context.Context {
	if info == nil {
		return ctx
	}
	return context.WithValue(ctx, connPeerKey{}, &connPeer{
		id:     h.s.lookupPeer(info.RemoteAddr, info.LocalAddr),
		client: info.RemoteAddr,
		server: info.LocalAddr,
	})
}

func (h *peerAuthStatsHandler) HandleConn(context.Context, stats.ConnStats) {}

// TagRPC returns the RPC context unchanged: the identity installed on the
// CONNECTION context by TagConn is already visible to the interceptor.
func (h *peerAuthStatsHandler) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return ctx
}

func (h *peerAuthStatsHandler) HandleRPC(context.Context, stats.RPCStats) {}

// lookupPeer resolves a connection's peer identity through the injected
// resolver (Config.PeerLookupFn) or pkg/authz's kernel lookup.
//
// The normalization mirrors pkg/api's: an injected resolver is not bound by
// LookupPeer's invariants and could report the nonsensical (OK, !Local), a
// combination the policy has no row for. An attributed peer is local by
// construction — its uid was read out of THIS host's socket table.
func (s *Server) lookupPeer(client, server net.Addr) authz.PeerIdentity {
	fn := s.peerLookupFn
	if fn == nil {
		fn = authz.LookupPeer
	}
	id := fn(client, server)
	if id.OK {
		id.Local = true
	}
	return id
}

// activeConfig returns the active config snapshot the login model is read from,
// or nil when the store is unwired or nothing is active yet (early boot).
//
// A nil snapshot does not fail the listener open: authz resolves UID 0 without
// consulting it, and every other principal resolves to "not a configured login
// user", which denies.
func (s *Server) activeConfig() *config.Config {
	if s.store == nil {
		return nil
	}
	return s.store.ActiveConfig()
}

// principalForPeer turns one connection's peer identity into a principal.
//
// Unlike pkg/api's principalFrom there is no precedence to apply: an
// unattributed peer has nothing weaker to fall through to, so both PeerIdentity
// rows that carry OK=false — "local but unattributable" and "not on this host" —
// produce the same unauthenticated principal, and Authorize denies it with the
// reason the lookup recorded.
func principalForPeer(cfg *config.Config, id authz.PeerIdentity) authz.Principal {
	if !id.OK {
		detail := id.Detail
		if detail == "" {
			detail = "the kernel socket table did not attribute this connection to a local account"
		}
		return authz.Unauthenticated(detail)
	}
	return authz.PrincipalForUID(cfg, id.UID)
}

// grpcDenialRemedy is appended to every denial so an operator who hits one is
// told what to change rather than only what failed. It names configuration, not
// a workaround: the login model is where access is supposed to be written down.
const grpcDenialRemedy = " — grant the account the permission with " +
	"`set system login user <name> class <class>` (a class holding it), or run the command from an account that already holds it"

// authorizeRPC is the whole authorization decision for one inbound RPC on the
// primary listener. It returns nil to admit, or a codes.PermissionDenied status
// carrying the reason and the remedy.
//
// The ORDER of the two reads is the one pkg/api's authorizeInputs argues for,
// and it holds here for free: the peer identity was fixed at connection setup,
// so reading it blocks on nothing, and the config snapshot is read immediately
// before Authorize. The residual pkg/api names survives here too — the
// /etc/passwd read inside PrincipalForUID separates the snapshot from the
// verdict — and is bounded, local, and holds no lock.
//
// Every outcome, including "no identity at all", is decided by ONE call to
// authz.Authorize. The alternative — an early return for the unidentified
// caller — would render a second denial sentence for the same state, which is
// how the two surfaces start disagreeing about what a denial means.
// authorizeRPC is the compatibility wrapper used by direct gate tests and
// stream re-authorization. Unary dispatch uses authorizeRPCContext so the
// exact admitted principal reaches the handler.
func (s *Server) authorizeRPC(ctx context.Context, fullMethod string, req any) error {
	_, err := s.authorizeRPCContext(ctx, fullMethod, req)
	return err
}

func (s *Server) authorizeRPCContext(ctx context.Context, fullMethod string, req any) (context.Context, error) {
	required, mapped := methodPermission(fullMethod, req)
	if !mapped {
		// Unreachable while TestEveryServiceMethodHasAPermission_5278 passes;
		// logged at Error because reaching it means a method was registered
		// without a table entry and is now super-user-only in production.
		slog.Error("gRPC method has no authorization mapping; requiring the strictest permission (#5278)",
			"method", fullMethod, "required", authz.PermissionName(required))
	}

	cfg := s.activeConfig()
	p := principalFromContext(ctx, cfg)
	if err := authz.Authorize(cfg, p, required); err != nil {
		return nil, denyRPC(fullMethod, required, p, err)
	}

	// #9324: the method table prices ShowConfig at PermView, but ConfigTarget's
	// proto3 zero value is CANDIDATE, so a view-only principal that omitted the
	// target read another session's uncommitted configuration. #9889 is the
	// same shape on the sibling RPC: ShowCompare diffs against the candidate
	// on BOTH arms with no ACTIVE arm at all. Reading a candidate costs
	// PermConfig — the permission that lets you be in configuration mode at
	// all — and it is charged HERE, at the same choke point as the coarse
	// check, so a new candidate-reading RPC cannot be added with its
	// continuation ungated.
	if err := s.authorizeRPCConfigTargetRead(cfg, p, fullMethod, req); err != nil {
		return nil, denyRPC(fullMethod, config.PermConfig, p, err)
	}

	// #7172 cut 5b: the class's fine-grained `deny-commands` regexes, AFTER the
	// coarse permission bits and never instead of them — Junos authorizes the
	// command family first and the regexes narrow within it.
	//
	// A SUPERUSER is exempt, and that is the same exemption authz.Authorize
	// already makes rather than a second one invented here: uid 0 owns the
	// config DB and the daemon process, so a regex denial would be theater, and
	// p.Class is empty for a superuser anyway.
	if !p.Superuser {
		if err := s.authorizeRPCCommand(cfg, p.Class, fullMethod, req); err != nil {
			return nil, denyRPC(fullMethod, required, p, err)
		}
		// #9154: the class's `*-configuration` regexes, which this surface did
		// not consult at all. #7172's acceptance says both dispatch surfaces
		// must use them and "neither may be gated alone"; only pkg/cli did.
		if err := s.authorizeRPCConfigMutation(cfg, p.Class, fullMethod, req); err != nil {
			return nil, denyRPC(fullMethod, required, p, err)
		}
	}
	return context.WithValue(ctx, authorizedPrincipalKey{}, p), nil
}

// principalFromContext reads the identity TagConn fixed for this connection.
//
// An untagged context means no TagConn ran for this connection — a direct
// in-process handler call, or a server built without the stats handler — so we
// cannot say who is calling and must refuse rather than guess.
func principalFromContext(ctx context.Context, cfg *config.Config) authz.Principal {
	cp, ok := ctx.Value(connPeerKey{}).(*connPeer)
	if !ok || cp == nil {
		return authz.Unauthenticated("connection identity was not captured at accept")
	}
	return principalForPeer(cfg, cp.id)
}

// authorizedPrincipalFromContext returns the immutable principal captured by
// authorizeRPCContext at the admission boundary.
func authorizedPrincipalFromContext(ctx context.Context) (authz.Principal, bool) {
	p, ok := ctx.Value(authorizedPrincipalKey{}).(authz.Principal)
	return p, ok
}

// denyRPC renders a denial for the caller and records it for the operator.
//
// The message reports only identity the caller already knows about ITSELF
// (authz.Principal.String()), never another principal's and never a secret.
func denyRPC(fullMethod string, required config.LoginClassPermission, p authz.Principal, reason error) error {
	// #9042: bounded, and COUNTED whether or not it is logged. The denial
	// path's rate is attacker-controlled -- every local non-root UID resolves
	// to an empty-Class principal and is denied -- so an unconditional
	// per-RPC Warn shipped to remote syslog at request rate and pushed xpfd's
	// other lines past journald's cap. Keyed on the principal so one noisy
	// caller cannot hide a first denial from a different one.
	if emit, suppressed := denyaudit.Note(denyaudit.SurfaceGRPCLoginClass, p.String()); emit {
		slog.Warn("gRPC call denied by login-class authorization (#5278)",
			"method", fullMethod,
			"required", authz.PermissionName(required),
			"principal", p.String(),
			"reason", reason.Error(),
			"suppressed_since_last", suppressed,
			"denials_total", denyaudit.Total(denyaudit.SurfaceGRPCLoginClass))
	} else {
		slog.Debug("gRPC call denied by login-class authorization (#5278)",
			"method", fullMethod, "principal", p.String(), "reason", reason.Error())
	}
	return status.Error(codes.PermissionDenied, reason.Error()+grpcDenialRemedy)
}

// principalUnaryInterceptor authorizes a unary RPC on the primary listener.
//
// It receives the DECODED request, which is what lets the SystemAction verb be
// priced individually (see methodPermission) instead of folding the whole
// multiplexed method up to its destructive floor the way pkg/api's
// body-agnostic middleware must.
func (s *Server) principalUnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	authorizedCtx, err := s.authorizeRPCContext(ctx, info.FullMethod, req)
	if err != nil {
		return nil, err
	}
	return handler(authorizedCtx, req)
}

// principalStreamInterceptor authorizes a streaming RPC on the primary
// listener. No message has been received when it runs, so it passes a nil
// request; the only method whose permission depends on its request is the unary
// SystemAction, and methodPermission prices a request-less lookup of it at the
// destructive floor regardless.
func (s *Server) principalStreamInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := s.authorizeRPC(ss.Context(), info.FullMethod, nil); err != nil {
		return err
	}
	// #9051: a stream outlives its verdict. Keep re-checking while it runs, or
	// a principal demoted mid-stream keeps its feed until it disconnects.
	return s.authorizeStreamContinuously(srv, ss, info.FullMethod, handler)
}

// splitFullMethod splits a gRPC "/service/method" into its two halves.
func splitFullMethod(fullMethod string) (service, method string, ok bool) {
	if !strings.HasPrefix(fullMethod, "/") {
		return "", "", false
	}
	rest := fullMethod[1:]
	i := strings.IndexByte(rest, '/')
	if i <= 0 || i == len(rest)-1 {
		return "", "", false
	}
	return rest[:i], rest[i+1:], true
}

// serviceName is the only service registered on this listener. A method on any
// other service is unmapped by construction.
var serviceName = pb.BpfrxService_ServiceDesc.ServiceName
