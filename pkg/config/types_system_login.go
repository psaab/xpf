package config

import (
	"fmt"
	"sort"
)

// types_system_login.go holds the `system login` typed model: the coarse
// permission enum, the class and user records, and the Junos-permission fold.
//
// Split out of types_system.go by #7172 cut 6, which pushed that file past the
// 2000-LOC modularity floor. The seam is not arbitrary: these types are the
// only ones in the system section with their own compiler
// (compiler_login_deny.go), their own runtime evaluator
// (login_regex.go / login_regex_scope_7172.go) and their own operator document
// (docs/system-login.md), and every one of those references them as a group.

// LoginClassPermission defines what a login class can do.
type LoginClassPermission int

const (
	PermView    LoginClassPermission = iota // show commands
	PermClear                               // clear commands
	PermControl                             // restart/request commands
	PermConfig                              // configure mode
	// PermMaint gates the destructive maintenance verbs — `request system
	// {reboot,halt,power-off,zeroize}` and `request chassis cluster failover`
	// — that on Junos require the `maintenance` permission the predefined
	// `operator` class LACKS (#4108 F21). It is intentionally NOT held by any
	// non-super class; super-user reaches these verbs through PermAll (which
	// matches every required permission), so PermMaint need not appear in
	// super-user's list to allow them.
	PermMaint
	PermAll // super-user: everything (subsumes every permission incl. PermMaint)
)

// String renders a coarse permission in the Junos vocabulary an operator
// sees in `system login class ... permissions` (#17121). This is the ONLY
// rendering table for LoginClassPermission: the commit advisory
// (loginClassAdvisoryWarnings) and the authorization
// denial (authz.PermissionName, which delegates here) both consume it, so
// the word named at commit time is the word named at denial time. PermAll
// is "all" — the Junos permission token — not "super-user", which names a
// predefined CLASS, not a permission. An out-of-range value renders
// "permission(<n>)" so a corrupt value stays diagnosable instead of
// collapsing into the same word as a missing one.
func (p LoginClassPermission) String() string {
	switch p {
	case PermView:
		return "view"
	case PermClear:
		return "clear"
	case PermControl:
		return "control"
	case PermConfig:
		return "configure"
	case PermMaint:
		return "maintenance"
	case PermAll:
		return "all"
	default:
		return fmt.Sprintf("permission(%d)", int(p))
	}
}

// LoginClassPermissions maps class names to their allowed permissions.
//
// The key set here is the authoritative list of system-defined Junos login
// classes xpf accepts; ValidLoginClasses (and the schema `class` enum, #2008
// H6) is derived from it so the commit-time validator and the runtime RBAC
// table can never drift apart.
//
// PermMaint (destructive maintenance) is deliberately absent from every
// non-super class: only `super-user` (via PermAll) may reboot/halt/power-off/
// zeroize the box or trigger a chassis-cluster failover, matching Junos where
// the predefined `operator` class has no `maintenance` permission (#4108 F21).
var LoginClassPermissions = map[string][]LoginClassPermission{
	"super-user": {PermAll},
	"operator":   {PermView, PermClear, PermControl},
	"read-only":  {PermView},
	// config-viewer can view (including config display, which routes through
	// `show`) but cannot enter configure to modify, clear, or operate (#2008
	// H6). Within the current coarse permission model that is PermView only.
	"config-viewer": {PermView},
	"unauthorized":  {},
}

// ValidLoginClasses is the sorted set of system-defined login class names the
// `system login user <name> class <class>` leaf accepts at commit (#2008 H6).
// Derived from LoginClassPermissions so the commit-time enum validator and the
// runtime RBAC table stay in lockstep.
func ValidLoginClasses() []string {
	classes := make([]string, 0, len(LoginClassPermissions))
	for name := range LoginClassPermissions {
		classes = append(classes, name)
	}
	sort.Strings(classes)
	return classes
}

// LoginConfig holds user account definitions.
type LoginConfig struct {
	Users []*LoginUser
	// Classes are custom `system login class <name>` RBAC definitions
	// (#4304 S-2). xpf recognizes them so a real vSRX RBAC config commits,
	// and maps their Junos permission set onto the coarse xpf permission
	// model (LoginClass.MappedPermissions) consulted by pkg/cli/permissions.
	Classes []*LoginClass
}

// LoginClass is a custom `system login class <name>` definition (#4304 S-2).
//
// Junos ships a large fine-grained permission vocabulary and per-command
// allow/deny regexes; xpf's runtime RBAC is coarse
// (view/clear/control/config/maint/all, types_system.go LoginClassPermission).
// So xpf recognizes the class (a valid config commits instead of being
// hard-rejected at the `user ... class` enum) and maps the whole-box Junos
// permission tokens onto the nearest coarse bucket.
//
// The four regex sub-statements have different Junos semantics (#5831, #7172):
//
//   - allow-commands / allow-configuration are ADDITIVE — they grant access
//     beyond the permission bits, so xpf enforces them as allowlists rather
//     than folding them into the coarse permission mapping.
//   - idle-timeout is retained for legacy loads but rejected on strict commits
//     because no runtime surface applies its session deadline (#10828).
//   - deny-commands / deny-configuration are RESTRICTIVE — they subtract from
//     the permission bits, so xpf enforces them as denials. DenyLeavesPresent
//     preserves explicit empty regex leaves for that enforcement.
type LoginClass struct {
	Name              string
	Permissions       []string               // raw Junos permission tokens as written
	MappedPermissions []LoginClassPermission // coarse xpf perms derived from Permissions
	IdleTimeout       int                    // minutes; retained only for legacy config, never enforced
	// IdleTimeoutSet records explicit leaf presence (including value 0) so
	// strict commit validation can reject the unsupported setting (#10828).
	IdleTimeoutSet     bool   `json:"-" yaml:"-"`
	AllowCommands      string // additive regex; enforced as an allowlist (#7172)
	DenyCommands       string // restrictive regex; enforced; see DenyLeavesPresent
	AllowConfiguration string // additive regex; enforced as an allowlist (#7172)
	DenyConfiguration  string // restrictive regex; enforced; see DenyLeavesPresent

	// DenyLeavesPresent records which RESTRICTIVE regex leaves the operator
	// actually WROTE, in config order, independent of their value (#5831).
	//
	// It exists because the value alone cannot answer that question: the
	// parser compiles `deny-commands ""` and a bare valueless `deny-commands`
	// to the SAME empty string as an absent leaf (both AST shapes retain the
	// leaf node — Keys=["deny-commands",""] and Keys=["deny-commands"] — but
	// nodeVal flattens each to ""). A quoted-empty regex is not a harmless
	// no-op: an empty POSIX regex matches at every position, so in Junos it
	// denies EVERY command — the single most restrictive thing an operator can
	// write, and therefore the most dangerous one to silently drop. Gating on
	// `DenyCommands != ""` would wave exactly that config through, so the gate
	// reads this presence list instead.
	//
	// Populated by compiler_system.go from loginClassLeafRestrictive
	// (compiler_login_deny.go) rather than from a per-leaf `case` arm, so
	// classifying a new restrictive leaf is the only edit needed to gate it.
	DenyLeavesPresent []string

	// AllowLeavesPresent records which ALLOW regex leaves the operator actually
	// WROTE, in config order, independent of their value (#7172 cut 6).
	//
	// The symmetric sibling of DenyLeavesPresent, needed for a reason that is
	// NOT symmetric. An empty deny denies everything while an absent deny denies
	// nothing — opposite, obviously. An empty ALLOW matches everything, so on
	// its own it looks indistinguishable from an absent allow and a value test
	// looks sufficient. It is not: `allow-commands ""` beside `deny-commands ""`
	// puts the IDENTICAL pattern in both leaves, which is precedence tier 1,
	// where allow wins and the class is allowed everything. Read that empty
	// allow as absent and the same config denies everything.
	//
	// Populated by compiler_system.go from loginClassLeafAllowRegex
	// (compiler_login_deny.go), the same table-driven shape DenyLeavesPresent
	// uses, so classifying a new allow leaf is the only edit needed.
	AllowLeavesPresent []string
	// RegexValues15712 records every DISTINCT authored value per regex leaf
	// (#15712), in author order, populated by compiler_system.go alongside
	// the presence lists. The scalar fields above keep only the last value
	// (the #8436 merge overwrite), so without this record a conflicting
	// duplicate — an earlier deny silently overwritten by a later block —
	// is invisible to any compiled-config gate. One distinct value is the
	// normal case; >1 is a strict-commit rejection / tolerant warning.
	// Not serialized: it is commit-time diagnostic provenance, rebuilt on
	// every compile from the authored tree.
	RegexValues15712 map[string][]string `json:"-" yaml:"-"`
}

// mapJunosPermissions maps a custom login class's Junos permission tokens onto
// xpf's coarse permission model (#4304 S-2). Whole-box tokens map precisely;
// every other recognized token is granted the full PermView bucket and is
// returned in widenedToView so the compiler advisory can name the widening.
// PermView is whole-box read: it admits the non-secret configuration render
// and the live session table (ShowConfig ACTIVE, GetSessions and the other
// PermView-priced reads), not just the subsystem the Junos token names. A
// narrow subsystem-read token (network, trace, snmp, interface, rollback,
// ...) therefore WIDENS on the read axis: the class reads more in xpf than
// the token permits in Junos. That widening is bounded — PermView carries no
// secret, configure, control, clear or maintenance grant — and it is the
// deliberate coarse-model trade: xpf has no per-subsystem read bucket.
// Tokens that would imply a write bucket in Junos (a *-control token,
// shell, secret, ...) likewise receive only PermView, so on the write axis
// the mapping still never grants config, control or maintenance from a
// narrow token. The PermView bucket lets the class holder log in and view
// even when no token maps precisely; unauthorized (empty token set) grants
// nothing.
//
// all and super-user map to PermAll even on a custom class because this bit
// describes command authorization. It does not grant the CLI's cleartext
// secret-display exception, which is keyed to the exact built-in class name.
//
// CRITICAL (write-axis no-escalation, review of #4311): no token maps to a
// write bucket it does not permit in Junos. Two Junos tokens are deceptive:
//   - reset permits restarting software DAEMONS (restart <process>), NOT
//     rebooting/halting/zeroizing the box. It must map to PermControl, NOT
//     PermMaint — PermMaint is exactly the destructive box verbs (request
//     system reboot/halt/power-off/zeroize + chassis cluster failover), which
//     reset does not authorize.
//   - rollback permits reverting to a prior commit only, NOT arbitrary
//     set/delete. It must map to PermView, NOT PermConfig (which gates
//     entering configure to make arbitrary changes). rollback is one of the
//     widened tokens above: Junos rollback alone grants no general read,
//     but PermView admits the whole non-secret configuration and session
//     table.
//
// Only maintenance maps to PermMaint (the correct whole-box-destructive
// grant), and only configure maps to PermConfig.
func mapJunosPermissions(tokens []string) (perms []LoginClassPermission, widenedToView []string) {
	have := map[LoginClassPermission]bool{}
	add := func(p LoginClassPermission) {
		if !have[p] {
			have[p] = true
			perms = append(perms, p)
		}
	}
	for _, tok := range tokens {
		switch tok {
		case "all", "super-user":
			add(PermAll)
		case "maintenance":
			add(PermMaint)
		case "clear":
			add(PermClear)
		case "control", "reset":
			// `reset` = restart daemons (restart <process>); NOT the
			// box-destructive reboot/halt/zeroize verbs that PermMaint gates.
			add(PermControl)
		case "configure":
			add(PermConfig)
		case "rollback":
			// rollback reverts to a prior commit only, not arbitrary
			// set/delete, so it must not map to PermConfig. It is a
			// widened token (#16638): PermView admits the whole
			// non-secret configuration and session table, which Junos
			// rollback alone does not.
			add(PermView)
			widenedToView = append(widenedToView, tok)
		case "view", "view-configuration":
			add(PermView)
		default:
			// Any other recognized Junos permission (a subsystem read
			// like network/interface/routing/firewall, a *-control
			// write token, shell, secret, ...) is granted the full
			// PermView bucket. On the read axis this widens a narrow
			// token (see the function comment); on the write axis it
			// under-grants, because the coarse model cannot represent
			// per-subsystem write scope and must not grant config,
			// control or maintenance from a narrow token.
			add(PermView)
			widenedToView = append(widenedToView, tok)
		}
	}
	return perms, widenedToView
}

// LoginUser defines a system user account.
type LoginUser struct {
	Name              string
	UID               int
	Class             string   // "super-user", "read-only", etc.
	EncryptedPassword Secret   // crypt(3) hash; applied via `chpasswd -e` (#1944); redacted on marshal (#2053)
	SSHKeys           []string // authorized SSH public keys
}
