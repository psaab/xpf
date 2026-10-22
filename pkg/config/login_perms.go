package config

// login_perms.go holds the ONE login-class -> coarse-permission evaluator every
// RBAC enforcement point shares (#5561).
//
// The mapping used to live only in pkg/cli (resolveClassPerms), which was fine
// while the CLI was the only place that enforced it. It stopped being fine when
// the REST control surface began enforcing the same boundary server-side
// (#5561) and again when the gRPC listener did (#5278): three copies of "which
// permissions does class X hold" drift, and a drift here is a silent
// authorization difference between control planes, not a cosmetic one. Keeping
// the evaluator next to the data it reads (LoginClassPermissions and
// LoginClass.MappedPermissions, both in this package) makes a divergent copy
// impossible to introduce by accident.

// ResolveClassPermissions returns the coarse permission set held by login class
// `class`, consulting the system-defined built-ins FIRST (LoginClassPermissions)
// and then any custom `system login class <name>` defined in cfg (#4304 S-2). A
// custom class's Junos permission tokens were folded to the coarse model at
// compile time (LoginClass.MappedPermissions); without consulting them a
// custom-class holder would be denied every action at runtime even though the
// config committed cleanly.
//
// ok=false means the class name is unknown — neither built-in nor defined in
// cfg. Every caller MUST treat that as a denial: an unknown class is not an
// empty permission set that happens to deny, it is a configuration the runtime
// cannot evaluate, and failing open on it would grant whatever the caller's
// default is. A nil cfg resolves built-ins only.
func ResolveClassPermissions(cfg *Config, class string) ([]LoginClassPermission, bool) {
	if perms, ok := LoginClassPermissions[class]; ok {
		return perms, true
	}
	if cfg != nil && cfg.System.Login != nil {
		for _, lc := range cfg.System.Login.Classes {
			if lc != nil && lc.Name == class {
				return lc.MappedPermissions, true
			}
		}
	}
	return nil, false
}

// ClassHasPermission reports whether login class `class` may perform an action
// requiring `required`. PermAll (super-user) matches every requirement,
// including PermMaint, which is deliberately held by no non-super class
// (types_system.go).
//
// It returns false for an unknown class — see ResolveClassPermissions.
func ClassHasPermission(cfg *Config, class string, required LoginClassPermission) bool {
	perms, ok := ResolveClassPermissions(cfg, class)
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == PermAll || p == required {
			return true
		}
	}
	return false
}

// LoginUserClass returns the login class configured for OS account `name` via
// `system login user <name> class <class>`, and whether such a user exists in
// cfg (#5561). It is the config half of a server-derived principal: a control
// surface that has established WHICH local account is calling resolves that
// account's class here, then evaluates it with ClassHasPermission.
//
// ok=false means the account is not a configured login user at all. A caller
// enforcing an authorization boundary must not substitute a default class for
// that case — it means the RBAC model says nothing about this account, which is
// a reason to deny, not a reason to pick a class.
//
// A name the daemon would REFUSE TO PROVISION is treated the same way, and this
// is the one place the rule is not obvious, so it is stated: a strict commit
// rejects an invalid `system login user <name>` at the schema (ValidateLoginUsername),
// but the TOLERANT load and peer-sync paths downgrade that to a warning (#1960)
// and keep the stanza active. pkg/daemon's account reconciliation
// (applySystemLogin) already refuses to provision such a name, so the daemon
// never created the account — yet this function would still hand its class to
// whatever OS account happens to bear the name. That is a config the runtime
// declined to realize granting authority over a control surface, which is a
// fail-open. Resolving it the same way as an absent user makes the two halves
// agree: an account the daemon would not create is an account the daemon does
// not authorize. It cannot deny anyone the daemon actually provisioned, because
// provisioning applies the identical validator.
func LoginUserClass(cfg *Config, name string) (string, bool) {
	if cfg == nil || cfg.System.Login == nil || name == "" {
		return "", false
	}
	if err := ValidateLoginUsername(name); err != nil {
		return "", false
	}
	for _, u := range cfg.System.Login.Users {
		if u != nil && u.Name == name {
			return u.Class, true
		}
	}
	return "", false
}
