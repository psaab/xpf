// Login-class based RBAC permission enforcement for CLI actions.
// `checkPermission` is invoked by the dispatch layer before any top-level
// command runs; when the user's login class is unset we keep the legacy
// behavior of allowing everything.
package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// checkPermission verifies the current user's login class permits the given
// command. `parts` is the resolved operational command line (parts[0] is the
// canonical top-level word, parts[1:] its arguments). Most commands are gated
// on the top-level word alone, but a few privileged subcommands need a finer
// gate (see requiredPermission). If userClass is empty (not set), all actions
// are allowed for backward compatibility.
// resolveClassPerms returns the coarse permission set for a login class,
// consulting the system-defined built-ins FIRST and then any custom `system
// login class <name>` defined in the active config (#4304 S-2). A custom
// class's Junos permissions were mapped to the coarse model at compile
// (config.LoginClass.MappedPermissions); without this resolution a
// custom-class user would be locked out of every command at runtime even
// though the config committed cleanly.
//
// The evaluation itself lives in config.ResolveClassPermissions (#5561) so the
// CLI and the REST control surface — which now enforces the same classes
// server-side — cannot drift into disagreeing about what a class may do. This
// method remains as the CLI's store-bound adapter.
func (c *CLI) resolveClassPerms(class string) ([]config.LoginClassPermission, bool) {
	var cfg *config.Config
	if c.store != nil {
		cfg = c.store.ActiveConfig()
	}
	return config.ResolveClassPermissions(cfg, class)
}

func (c *CLI) checkPermission(parts []string) error {
	if c.userClass == "" {
		return nil
	}
	if len(parts) == 0 {
		return nil
	}

	perms, ok := c.resolveClassPerms(c.userClass)
	if !ok {
		return fmt.Errorf("permission denied: unknown login class %q", c.userClass)
	}

	required := requiredPermission(parts)

	for _, p := range perms {
		if p == config.PermAll || p == required {
			return nil
		}
	}

	return fmt.Errorf("permission denied: %q requires a higher login class", strings.Join(parts, " "))
}

// showConfigRedacted reports whether the config-render CLI show paths — `show
// configuration` (all formats), `show system rollback`, `show system
// login|internet-options|root-authentication`, `show system configuration
// rescue`, and the config-mode `show`/`show | compare` — must mask secret
// leaves for the current login class (#4099).
//
// Junos never renders cleartext secrets in `show configuration` (it shows the
// $9$/##SECRET-DATA form to every class), and xpf already redacts the REST and
// gRPC ShowConfig raw-AST render paths unconditionally (#4051/F-020). The
// on-box CLI, however, historically printed cleartext for every class (the
// deliberate #4057 scope note: "operator reads own secret, root has DB
// access"). That rationale holds for the privileged super-user / root operator
// working at the console, but NOT for a VIEW-only read-only or config-viewer
// login class — both PermView (types_system.go) — which could run `show
// configuration | display set` and harvest every IKE PSK, SNMP community and
// authentication-key in cleartext.
//
// We therefore redact for every login class EXCEPT super-user (the only class
// carrying PermAll). super-user == the console root that #4057 protected and
// that already has direct DB filesystem access, so it still reads cleartext to
// copy a secret; read-only, config-viewer and operator see ##SECRET-DATA##. An
// UNSET login class (CLI spawned without RBAC configured — the legacy
// allow-everything mode, mirroring checkPermission's empty-class shortcut) is
// treated as privileged and reads cleartext, so a deployment with no `system
// login` classes is bit-identical to before this change. An UNKNOWN class
// fails closed (redacted).
func (c *CLI) showConfigRedacted() bool {
	if c.userClass == "" {
		return false
	}
	perms, ok := c.resolveClassPerms(c.userClass)
	if !ok {
		return true
	}
	for _, p := range perms {
		if p == config.PermAll {
			return false
		}
	}
	return true
}

// showActiveConfigPath renders an active-config subtree as hierarchical text,
// masking secret leaves when showConfigRedacted() flags the current login
// class (#4099). It is the redaction-aware replacement for direct
// store.ShowActivePath calls on secret-bearing subtrees (`show system login`,
// `show system root-authentication`).
func (c *CLI) showActiveConfigPath(path []string) string {
	if c.showConfigRedacted() {
		return c.store.ShowActiveRedacted(path)
	}
	return c.store.ShowActivePath(path)
}

// showSystemRollbackCompare reports whether the operational `show system
// rollback` handler will read the shared candidate for a compare request.
//
// The first spelling is `show system rollback compare N`; the second is
// `show system rollback N ... compare`, which the handler recognizes with its
// substring check. Keep this predicate aligned with handleShowSystem: its
// `| display set` branch wins over the second spelling, while the first
// spelling is checked before any display suffix. The system token is resolved
// here exactly as handleShow does, so an unambiguous abbreviation cannot
// bypass the candidate-read price.
func showSystemRollbackCompare(args []string) bool {
	if len(args) < 3 {
		return false
	}
	system, err := resolveCommand(args[0], keysFromTree(operationalTree["show"].Children))
	if err != nil || system != "system" || args[1] != "rollback" {
		return false
	}

	// `show system rollback compare N` is the handler's first branch.
	if args[2] == "compare" {
		if len(args) < 4 {
			return false
		}
		n, err := strconv.Atoi(args[3])
		return err == nil && n >= 1
	}

	// `show system rollback N ... compare` is the handler's second branch.
	n, err := strconv.Atoi(args[2])
	if err != nil || n < 1 {
		return false
	}
	rest := strings.Join(args[3:], " ")
	if strings.Contains(rest, "| display set") {
		return false
	}
	return strings.Contains(rest, "compare")
}

// requiredPermission returns the login-class permission a resolved operational
// command needs. Gating is on the top-level word (parts[0]) for almost every
// command, with a few privileged subcommands needing a finer gate.
func requiredPermission(parts []string) config.LoginClassPermission {
	action := parts[0]

	// #10094/#9889: ShowCompare's two operational console spellings both
	// render a diff against the shared CANDIDATE. Reading another session's
	// uncommitted configuration is a configure-mode activity, so price only
	// those compare paths at PermConfig while the rest of `show` remains
	// PermView. This mirrors #9889's gRPC contract; the in-process console's
	// single coarse command price is intentionally a replacement (like the
	// REST twin), rather than gRPC's additive method-table-plus-gate price.
	if action == "show" && showSystemRollbackCompare(parts[1:]) {
		return config.PermConfig
	}

	// `monitor traffic` = privileged capture (root tcpdump). Gate it at the
	// control level even though the `monitor` top-level word is view-level.
	if action == "monitor" && monitorSubcommandIsTraffic(parts[1:]) {
		return config.PermControl
	}

	// `monitor security flow {file|start}` drives a ROOT-privileged write to a
	// trace file on disk (openTraceFile create/append + rotation rename). A
	// view-only / read-only class must not be able to make the root daemon
	// create/append/rotate on-disk files — even confined to the dedicated trace
	// dir that is a privilege escalation and a disk-fill/telemetry-exposure vector
	// — so gate the file-backed flow-trace verbs at the control level even though
	// `monitor` is otherwise view-level (#5038). The terminal-only `monitor
	// security packet-drop` and the flow status/filter/stop verbs stay view-level.
	if action == "monitor" && monitorSubcommandIsSecurityFlowFileWrite(parts[1:]) {
		return config.PermControl
	}

	// `request system {reboot,halt,power-off,zeroize}` and `request chassis
	// cluster failover` are DESTRUCTIVE maintenance verbs. On Junos the
	// predefined `operator` class lacks the `maintenance` permission and so
	// cannot reboot/zeroize; xpf mirrors that by gating them at the
	// super-user-only PermMaint level instead of the plain PermControl the
	// rest of the `request` family (request session, request security, etc.)
	// keeps, so `operator` retains benign request verbs but not the ones that
	// take the box down or wipe it (#4108 F21).
	if action == "request" && requestSubcommandIsMaintenance(parts[1:]) {
		return config.PermMaint
	}

	switch action {
	case "show", "ping", "traceroute", "monitor":
		return config.PermView
	case "clear":
		return config.PermClear
	case "request", "test":
		return config.PermControl
	case "configure":
		return config.PermConfig
	default:
		return config.PermAll
	}
}

// requestSubcommandIsMaintenance reports whether the `request` arguments
// resolve to a destructive maintenance verb: `request system
// {reboot,halt,power-off,zeroize}` or `request chassis cluster failover ...`.
// It applies the same prefix resolution the CLI dispatcher uses (resolveCommand
// over the cmdtree children), so an abbreviated `request system zero` or
// `request sys reboot` is gated identically to the fully-spelled form and
// cannot bypass the gate. Resolution errs toward the dispatcher: an
// unresolvable/ambiguous token that would never actually run returns false
// (plain control), while every token the dispatcher would execute as a
// destructive verb resolves here and elevates to PermMaint (fail-closed).
func requestSubcommandIsMaintenance(args []string) bool {
	if len(args) == 0 {
		return false
	}
	reqNode, ok := operationalTree["request"]
	if !ok || reqNode == nil {
		return false
	}
	target, err := resolveCommand(args[0], keysFromTree(reqNode.Children))
	if err != nil {
		return false
	}
	switch target {
	case "system":
		if len(args) < 2 {
			return false
		}
		sysNode := reqNode.Children["system"]
		if sysNode == nil {
			return false
		}
		verb, err := resolveCommand(args[1], keysFromTree(sysNode.Children))
		if err != nil {
			return false
		}
		switch verb {
		case "reboot", "halt", "power-off", "zeroize":
			return true
		case "software":
			// `request system software in-service-upgrade` drives
			// cluster.ForceSecondary() — the ISSU ownership drain forces this
			// node secondary for ALL redundancy groups (an availability action),
			// so it must require PermMaint like the other maintenance verbs
			// (#4859). Any other `software` subcommand stays at PermControl.
			if len(args) < 3 {
				return false
			}
			swNode := sysNode.Children["software"]
			if swNode == nil {
				return false
			}
			issu, err := resolveCommand(args[2], keysFromTree(swNode.Children))
			if err != nil {
				return false
			}
			return issu == "in-service-upgrade"
		}
		return false
	case "chassis":
		// request chassis cluster {failover ... | data-plane ...}
		if len(args) < 3 {
			return false
		}
		chNode := reqNode.Children["chassis"]
		if chNode == nil {
			return false
		}
		clusterTok, err := resolveCommand(args[1], keysFromTree(chNode.Children))
		if err != nil || clusterTok != "cluster" {
			return false
		}
		clNode := chNode.Children["cluster"]
		if clNode == nil {
			return false
		}
		sub, err := resolveCommand(args[2], keysFromTree(clNode.Children))
		if err != nil {
			return false
		}
		switch sub {
		case "failover":
			return true
		case "data-plane":
			return dataplaneVerbIsMaintenance(clNode.Children["data-plane"], args[3:])
		}
		return false
	}
	return false
}

// dataplaneVerbIsMaintenance reports whether a `request chassis cluster
// data-plane ...` argument tail resolves to a DESTRUCTIVE userspace-dataplane
// control verb that must require the super-user-only PermMaint rather than the
// plain PermControl the predefined operator class holds (#4859):
//
//   - forwarding disarm / queue N {unregister|disarm} / binding slot N
//     {unregister|disarm} — take live forwarding or a redirect binding OUT of
//     service (SetForwardingArmed(false) / SetQueueState / SetBindingState);
//   - inject-packet — raw synthetic packet injection into the dataplane.
//
// The RESTORATIVE arm|register verbs and any read/status path stay at
// PermControl so operator keeps its benign dataplane control. args is the token
// tail AFTER "data-plane" (args[0] is the "userspace" token). The tree tokens
// go through resolveCommand (prefix-abbreviation safe, mirroring the
// dispatcher) and the operation token is matched case-insensitively exactly
// like pkg/dataplane/userspace.ParseForwardingCommand /
// ParseRegistrationOperation, so the gate and the dispatcher never disagree
// about which inputs actually run a destructive verb.
func dataplaneVerbIsMaintenance(dpNode *completionNode, args []string) bool {
	if dpNode == nil || len(args) < 2 {
		return false
	}
	usTok, err := resolveCommand(args[0], keysFromTree(dpNode.Children))
	if err != nil || usTok != "userspace" {
		return false
	}
	usNode := dpNode.Children["userspace"]
	if usNode == nil {
		return false
	}
	verb, err := resolveCommand(args[1], keysFromTree(usNode.Children))
	if err != nil {
		return false
	}
	switch verb {
	case "inject-packet":
		return true
	case "forwarding":
		// forwarding <arm|disarm>
		return len(args) >= 3 && isDestructiveDataplaneOp(args[2])
	case "queue":
		// queue <N> <register|unregister|arm|disarm>
		return len(args) >= 4 && isDestructiveDataplaneOp(args[3])
	case "binding":
		// binding slot <N> <register|unregister|arm|disarm>
		return len(args) >= 5 && isDestructiveDataplaneOp(args[4])
	}
	return false
}

// isDestructiveDataplaneOp reports whether op TEARS DOWN forwarding / redirect
// ownership — `disarm` or `unregister` — mirroring
// pkg/dataplane/userspace.ParseRegistrationOperation / ParseForwardingCommand,
// which lowercase and exact-match. `arm` and `register` are restorative and
// stay at PermControl.
func isDestructiveDataplaneOp(op string) bool {
	switch strings.ToLower(op) {
	case "disarm", "unregister":
		return true
	}
	return false
}

// monitorSubcommandIsTraffic reports whether the monitor arguments resolve to
// the `traffic` subcommand. It applies the same prefix resolution the monitor
// dispatcher uses (`handleMonitor`), so an abbreviated `monitor tr` is gated
// identically to the fully-spelled `monitor traffic` — the RBAC gate and the
// dispatcher can never disagree about what a token resolves to.
func monitorSubcommandIsTraffic(args []string) bool {
	if len(args) == 0 {
		return false
	}
	monNode, ok := operationalTree["monitor"]
	if !ok || monNode == nil {
		return false
	}
	resolved, err := resolveCommand(args[0], keysFromTree(monNode.Children))
	if err != nil {
		return false
	}
	return resolved == "traffic"
}

// monitorSubcommandIsSecurityFlowFileWrite reports whether the monitor
// arguments resolve to `monitor security flow file ...` or `monitor security
// flow start` — the two verbs that cause the root daemon to create/append/
// rotate a trace file on disk (#5038). It uses the same prefix resolution the
// monitor dispatcher applies (resolveCommand over the cmdtree children) so an
// abbreviated `monitor sec fl fi trace` or `monitor sec fl sta` is gated
// identically to the fully-spelled form and cannot bypass the gate. Bare
// `monitor security flow` (status), `filter`, `stop`, and `monitor security
// packet-drop` (terminal-only) resolve to false and stay view-level.
func monitorSubcommandIsSecurityFlowFileWrite(args []string) bool {
	// Need at least `security flow <verb>`.
	if len(args) < 3 {
		return false
	}
	monNode, ok := operationalTree["monitor"]
	if !ok || monNode == nil {
		return false
	}
	sec, err := resolveCommand(args[0], keysFromTree(monNode.Children))
	if err != nil || sec != "security" {
		return false
	}
	secNode := monNode.Children["security"]
	if secNode == nil {
		return false
	}
	flow, err := resolveCommand(args[1], keysFromTree(secNode.Children))
	if err != nil || flow != "flow" {
		return false
	}
	flowNode := secNode.Children["flow"]
	if flowNode == nil {
		return false
	}
	verb, err := resolveCommand(args[2], keysFromTree(flowNode.Children))
	if err != nil {
		return false
	}
	return verb == "file" || verb == "start"
}
