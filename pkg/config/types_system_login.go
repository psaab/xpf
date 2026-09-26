package config

import "sort"

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
// The four regex sub-statements are NOT symmetric (#5831):
//
//   - allow-commands / allow-configuration are ADDITIVE in Junos — they grant
//     access BEYOND the permission bits. Ignoring an additive grant can only
//     ever hand the class LESS than the operator wrote, so they stay
//     recognized-but-not-enforced with an advisory (fail-closed).
//   - idle-timeout is retained for legacy loads but rejected on strict commits
//     because no runtime surface applies its session deadline (#10828).
//   - deny-commands / deny-configuration are RESTRICTIVE — they subtract from
//     the permission bits. Ignoring them hands the class MORE than the
//     operator wrote, so they are hard-rejected at commit
//     (validateLoginClassDenyStrict) and, on the tolerant load / peer-sync
//     path, fold the class down to the REPAIR FLOOR — {view, configure}
//     intersected with what the class already held
//     (foldLoginClassDenyToRepairableFloor). Not to view-only: the configured
//     class can be bound to the console login, and a class that cannot enter
//     `configure` cannot delete the statement that is blocking every commit.
type LoginClass struct {
	Name              string
	Permissions       []string               // raw Junos permission tokens as written
	MappedPermissions []LoginClassPermission // coarse xpf perms derived from Permissions
	IdleTimeout       int                    // minutes; retained only for legacy config, never enforced
	// IdleTimeoutSet records explicit leaf presence (including value 0) so
	// strict commit validation can reject the unsupported setting (#10828).
	IdleTimeoutSet     bool   `json:"-" yaml:"-"`
	AllowCommands      string // regex; additive, recognized, not enforced
	DenyCommands       string // regex; restrictive — see DenyLeavesPresent
	AllowConfiguration string // regex; additive, recognized, not enforced
	DenyConfiguration  string // regex; restrictive — see DenyLeavesPresent

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
}

// mapJunosPermissions folds a custom login class's Junos permission tokens onto
// xpf's coarse permission model (#4304 S-2). Only the unambiguous whole-box
// tokens map precisely; every other recognized subsystem/-control token folds
// DOWN to a PermView floor (least-privilege — never silently grant config,
// control, or maintenance from a narrow subsystem token) and is returned in
// foldedToView so the compiler advisory can list what is coarsely mapped. The
// PermView floor lets the class holder log in and view even when no token maps
// precisely; `unauthorized` (empty token set) grants nothing.
//
// CRITICAL (no privilege escalation, review of #4311): the mapping must never
// grant MORE than the Junos token permits. Two Junos tokens are deceptive:
//   - `reset` permits restarting software DAEMONS (`restart <process>`), NOT
//     rebooting/halting/zeroizing the box. It must map to PermControl, NOT
//     PermMaint — PermMaint is exactly the destructive box verbs (request
//     system reboot/halt/power-off/zeroize + chassis cluster failover), which
//     `reset` does not authorize.
//   - `rollback` permits reverting to a prior commit only, NOT arbitrary
//     set/delete. It must map to the PermView floor, NOT PermConfig (which
//     gates entering configure to make arbitrary changes).
//
// Only `maintenance` maps to PermMaint (the correct whole-box-destructive
// grant), and only `configure` maps to PermConfig.
func mapJunosPermissions(tokens []string) (perms []LoginClassPermission, foldedToView []string) {
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
			// `rollback` reverts to a prior commit only, not arbitrary
			// set/delete; fold to the least-privilege view floor rather than
			// PermConfig.
			add(PermView)
		case "view", "view-configuration":
			add(PermView)
		default:
			// Any other recognized Junos permission (a subsystem read like
			// `network`/`interface`/`routing`/`firewall`, a `*-control`
			// write token, `shell`, `secret`, ...) is coarsely folded to a
			// view-only floor. Under-granting is the safe direction: xpf's
			// coarse model cannot faithfully represent per-subsystem write
			// scope, so it must not over-grant config/control from a narrow
			// token.
			add(PermView)
			foldedToView = append(foldedToView, tok)
		}
	}
	return perms, foldedToView
}

// LoginUser defines a system user account.
type LoginUser struct {
	Name              string
	UID               int
	Class             string   // "super-user", "read-only", etc.
	EncryptedPassword Secret   // crypt(3) hash; applied via `chpasswd -e` (#1944); redacted on marshal (#2053)
	SSHKeys           []string // authorized SSH public keys
}
