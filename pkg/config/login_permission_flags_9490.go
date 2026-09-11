package config

import (
	"fmt"
	"sort"
)

// junosLoginPermissionFlags is the Junos login-class permission flag set,
// transcribed from the permission flags table in Juniper's "User Access
// Privileges" documentation (Junos OS user access guide).
//
// #9490: `system login class <c> permissions` carried no validator, so a typo
// such as `permissions view xpfbogus v1` committed clean. mapJunosPermissions
// folds any token it does not special-case to PermView, so the misspelled class
// silently became a different class from the one written. The mapping stays as
// it is for a persisted config (the tolerant load path does not run
// SchemaValidate); the commit gate is what refuses the typo.
var junosLoginPermissionFlags = map[string]struct{}{
	"access": {}, "access-control": {}, "admin": {}, "admin-control": {}, "all": {},
	"clear": {}, "configure": {}, "control": {}, "field": {}, "firewall": {},
	"firewall-control": {}, "floppy": {}, "flow-tap": {}, "flow-tap-control": {},
	"flow-tap-operation": {}, "idp-profiler-operation": {}, "interface": {},
	"interface-control": {}, "maintenance": {}, "network": {},
	"pgcp-session-mirroring": {}, "pgcp-session-mirroring-control": {}, "reset": {},
	"rollback": {}, "routing": {}, "routing-control": {}, "secret": {},
	"secret-control": {}, "security": {}, "security-control": {}, "shell": {},
	"snmp": {}, "snmp-control": {}, "storage": {}, "storage-control": {},
	"system": {}, "system-control": {}, "trace": {}, "trace-control": {},
	"unified-edge": {}, "unified-edge-control": {}, "view": {},
	"view-configuration": {},
}

// loginPermissionSuperUserAlias is not a Junos flag. mapJunosPermissions has
// always accepted it as PermAll, so refusing it now would reject configs that
// commit today.
const loginPermissionSuperUserAlias = "super-user"

// LoginPermissionFlags returns every token the permissions leaf accepts,
// sorted, for `?` completion.
func LoginPermissionFlags() []string {
	out := make([]string, 0, len(junosLoginPermissionFlags)+1)
	for f := range junosLoginPermissionFlags {
		out = append(out, f)
	}
	out = append(out, loginPermissionSuperUserAlias)
	sort.Strings(out)
	return out
}

// ValidateLoginPermission accepts one `permissions` token.
func ValidateLoginPermission(raw string, _ *Config) error {
	if _, ok := junosLoginPermissionFlags[raw]; ok || raw == loginPermissionSuperUserAlias {
		return nil
	}
	return fmt.Errorf("%q is not a Junos login-class permission flag (e.g. view, configure, "+
		"clear, maintenance, all); an unrecognised token would silently fold to view-only, "+
		"granting a different class from the one written", raw)
}
