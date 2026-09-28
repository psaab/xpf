// Package authz derives and authorizes a SERVER-SIDE principal for the local
// control-plane surfaces: the HTTP REST API (#5561, pkg/api/authz.go) and the
// primary gRPC listener (#5278, pkg/grpcapi/authz.go).
//
// # Why this exists
//
// Both local control surfaces — the HTTP REST API on 127.0.0.1:8080 and the
// gRPC API on 127.0.0.1:50051 — historically trusted their loopback bind as an
// authorization boundary. It is not one. The daemon provisions every `system
// login user` a real shell account (`useradd -m -s /bin/bash`,
// pkg/daemon/daemon_system.go), so a `read-only` or `operator` class holder can
// log in and speak to loopback directly. The CLI's RBAC check
// (pkg/cli/permissions.go) runs in the CLI process, on the caller's side of the
// boundary, so it constrains only callers who choose to use the CLI. Anyone
// willing to run `curl` skipped it entirely.
//
// # What a principal is here
//
// The identity is the kernel's, not the caller's. For a connection whose peer
// is on this host, the owning UID is read out of the kernel's socket table
// (peer.go) — the caller supplies nothing and can forge nothing. That UID is
// resolved to an OS account name via /etc/passwd and then to a login class via
// `system login user <name> class <class>`. For every NON-ROOT caller the
// passwd database names unambiguously, the result is the same class the CLI
// would have applied, now enforced on the server side where it cannot be
// skipped.
//
// The qualification is exact, not defensive. UID 0 is authorized
// unconditionally here (PrincipalForUID short-circuits before reading cfg),
// while the CLI honours an explicit `system login user root { class read-only; }`
// — so for root the two surfaces CAN differ, by design and documented. And an
// ambiguous uid resolves to no name at all on both surfaces since #6645, which
// is agreement, but agreement on a denial rather than on a class.
//
// A configured `system services web-management api-auth` identity is the
// second identity. Basic usernames and named API-key labels select configured
// `system login class` scopes; the default is read-only, and no credential
// becomes a superuser just by being valid. A peer UID that resolves to a
// configured local login user is MORE specific and therefore wins over it.
//
// # Fail-closed, and what that costs
//
// When neither identity can be established, an authorization request is
// DENIED. That is a deliberate behavior change for one population: a local
// process running as a non-root UID that is not a configured `system login
// user` and presents no credential. Such a caller could previously mutate and
// commit config; it now receives a denial naming the remedy. Nothing in this
// repository drives the REST mutation surface (the CLI speaks gRPC; the deploy
// and day-0 tooling reads /metrics only), and root — which can write the config
// DB directly, making a denial theater — is always authorized. See
// pkg/api/README.md "Server-side authorization".
//
// The gRPC leg (#5278) inherits that cost and one more, because it gates READS
// as well as mutations: the remote `cli` binary carried no login class at all,
// so every one of its callers was effectively super-user, and an account
// outside `system login user` now gets nothing rather than everything. There is
// no api-auth analogue on that listener — a peer UID is the ONLY identity — so
// its precedence rule is a single row. See pkg/grpcapi/README.md
// "Server-side authorization".
package authz

import (
	"fmt"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/osident"
)

// Source records HOW a principal's identity was established. It exists so a
// denial can say what was and was not proven, and so precedence between the two
// identities is explicit rather than implied by field emptiness.
type Source int

const (
	// SourceNone means no identity could be established. Every authorization
	// request from a SourceNone principal is denied.
	SourceNone Source = iota
	// SourcePeerUID means the kernel reported the UID owning the peer end of
	// the connection. Unforgeable by the caller.
	SourcePeerUID
	// SourceCredential means the request proved possession of a configured
	// api-auth secret mapped to this identity and class.
	SourceCredential
)

func (s Source) String() string {
	switch s {
	case SourcePeerUID:
		return "peer-uid"
	case SourceCredential:
		return "api-auth-credential"
	default:
		return "none"
	}
}

// Principal is the server-derived identity of one control-plane caller.
//
// It is a value, not a handle: it is resolved once per request from the
// connection plus a config snapshot and is never mutated afterwards.
type Principal struct {
	// Source is how the identity was established. SourceNone denies.
	Source Source
	// UID is the peer's numeric UID. Meaningful only for SourcePeerUID.
	UID uint32
	// Username is the OS account name for UID, or the configured API identity
	// name. Empty for an unnamed API key or an unresolved UID.
	Username string
	// Class is the `system login class` assigned to this principal.
	Class string
	// Superuser marks UID 0, which is authorized without a configured login
	// class because root owns the daemon and its on-disk config.
	Superuser bool
	// Detail explains an unestablished or unusable identity, for the denial
	// message and the audit log. Never carries a secret.
	Detail string
}

// Resolved reports whether this principal is usable for an authorization
// decision — i.e. it is a superuser, or it carries a login class to evaluate.
//
// A peer UID that resolved to no configured login user is NOT resolved: the
// RBAC model says nothing about that account. Callers use this to decide
// whether a more specific identity should yield to a weaker one (a peer UID
// with no class falls through to an api-auth credential) — never to skip the
// authorization call itself.
func (p Principal) Resolved() bool {
	return p.Superuser || p.Class != ""
}

// String renders the principal for a log line or a denial message. It reports
// only identity the caller already knows about ITSELF (its own UID, account
// name and class), never another principal's, and never a secret.
func (p Principal) String() string {
	switch {
	case p.Source == SourceCredential && p.Username != "":
		return fmt.Sprintf("api-auth identity %q (class %q)", p.Username, p.Class)
	case p.Source == SourceCredential:
		return fmt.Sprintf("api-auth key (class %q)", p.Class)
	case p.Source == SourcePeerUID && p.Username != "":
		return fmt.Sprintf("uid %d (%s, class %q)", p.UID, p.Username, p.Class)
	case p.Source == SourcePeerUID:
		return fmt.Sprintf("uid %d", p.UID)
	default:
		return "unauthenticated caller"
	}
}

// Authorize reports whether p may perform an action requiring permission
// `required`, evaluated against the login model in cfg. A nil error means
// authorized; a non-nil error is the denial reason, suitable for returning to
// the caller and for the audit log.
//
// The order of the checks is the authorization policy:
//
//  1. A superuser principal (UID 0) is authorized for everything. Denying UID 0
//     would be theater — root owns the config DB on disk and the daemon process.
//  2. A principal carrying a login class is authorized iff that class holds
//     `required` (config.ClassHasPermission — the same evaluator the CLI uses).
//  3. Everything else is DENIED, including a peer UID that resolved to a real
//     OS account which is not a configured `system login user`.
func Authorize(cfg *config.Config, p Principal, required config.LoginClassPermission) error {
	if p.Superuser {
		return nil
	}
	if p.Source == SourceNone {
		detail := p.Detail
		if detail == "" {
			detail = "no local peer identity and no api-auth credential"
		}
		return fmt.Errorf("permission denied: the server could not establish who is calling (%s)", detail)
	}
	if p.Class == "" {
		return fmt.Errorf("permission denied: %s has no assigned login class", p)
	}
	if _, known := config.ResolveClassPermissions(cfg, p.Class); !known {
		return fmt.Errorf("permission denied: %s holds unknown login class %q", p, p.Class)
	}
	if !config.ClassHasPermission(cfg, p.Class, required) {
		return fmt.Errorf("permission denied: %s lacks the %s permission this action requires", p, PermissionName(required))
	}
	return nil
}

// PermissionName renders a coarse permission for a denial message using the
// Junos vocabulary an operator sees in `system login class ... permissions`.
func PermissionName(p config.LoginClassPermission) string {
	switch p {
	case config.PermView:
		return "view"
	case config.PermClear:
		return "clear"
	case config.PermControl:
		return "control"
	case config.PermConfig:
		return "configure"
	case config.PermMaint:
		return "maintenance"
	case config.PermAll:
		return "all"
	default:
		return fmt.Sprintf("permission(%d)", int(p))
	}
}

// PrincipalForUID builds the principal for a kernel-reported peer UID by
// resolving it through /etc/passwd and then through the `system login user`
// model in cfg (#5561).
//
// UID 0 short-circuits to a superuser principal WITHOUT consulting /etc/passwd
// or the config: root already owns the daemon and its on-disk config DB, and
// making root's authorization depend on a passwd entry or an active config
// would deny the operator on a box whose config has not been loaded yet.
//
// Every other outcome — no passwd entry, an account absent from `system login
// user`, an account whose class is empty — produces an UNRESOLVED principal
// carrying the reason. The caller may fall through to a weaker identity; if it
// does not, Authorize denies with that reason.
func PrincipalForUID(cfg *config.Config, uid uint32) Principal {
	if uid == 0 {
		return Principal{Source: SourcePeerUID, UID: 0, Username: "root", Superuser: true}
	}
	p := Principal{Source: SourcePeerUID, UID: uid}
	id := osident.ForUID(int(uid))
	if !id.Resolved() {
		// Say WHICH failure it was. "No passwd entry" was the only detail
		// before #6645 because the old resolver had only that outcome; the
		// shared resolver also refuses an AMBIGUOUS uid, and reporting that as
		// "no entry" would send an operator hunting for a missing account when
		// the real problem is two accounts sharing one uid.
		//
		// The RULE is single-sourced (osident); the WORDING is deliberately
		// per-surface — this is a REST error body, pkg/cli's
		// unidentifiedReason writes the longer console sentence for the same
		// three reasons. Both must stay accurate; neither is the other's SSOT.
		switch id.Reason {
		case osident.ReasonAmbiguousUID:
			p.Detail = fmt.Sprintf("uid %d is shared by more than one passwd account, "+
				"so it does not name a single `system login user`", uid)
		case osident.ReasonLookupFailed:
			p.Detail = fmt.Sprintf("the passwd database could not be read for uid %d", uid)
		default:
			p.Detail = fmt.Sprintf("uid %d has no /etc/passwd entry", uid)
		}
		return p
	}
	name := id.Name
	p.Username = name
	class, ok := config.LoginUserClass(cfg, name)
	if !ok {
		p.Detail = fmt.Sprintf("uid %d (%s) is not a configured `system login user`", uid, name)
		return p
	}
	if class == "" {
		p.Detail = fmt.Sprintf("`system login user %s` has no class", name)
		return p
	}
	p.Class = class
	return p
}

// CredentialPrincipal builds a class-scoped principal for a valid named
// api-auth credential. `identity` is the Basic username or named API key;
// unnamed legacy tokens have an empty identity. Class defaults are resolved by
// config compilation and runtime wiring, not elevated here.
func CredentialPrincipal(identity, class string) Principal {
	return Principal{Source: SourceCredential, Username: identity, Class: class}
}

// Unauthenticated returns the principal for a caller whose identity could not
// be established at all, carrying `detail` as the reason. Every authorization
// request from it is denied.
func Unauthenticated(detail string) Principal {
	return Principal{Source: SourceNone, Detail: detail}
}
