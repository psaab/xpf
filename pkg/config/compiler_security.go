package config

import "fmt"

func compileSecurity(node *Node, sec *SecurityConfig) error {
	for _, child := range node.Children {
		switch child.Name() {
		case "zones":
			if err := compileZones(child, sec); err != nil {
				return fmt.Errorf("zones: %w", err)
			}
		case "policies":
			if err := compilePolicies(child, sec); err != nil {
				return fmt.Errorf("policies: %w", err)
			}
		case "screen":
			if err := compileScreen(child, sec); err != nil {
				return fmt.Errorf("screen: %w", err)
			}
		case "nat":
			if err := compileNAT(child, sec); err != nil {
				return fmt.Errorf("nat: %w", err)
			}
		case "address-book":
			if err := compileAddressBook(child, sec); err != nil {
				return fmt.Errorf("address-book: %w", err)
			}
		case "log":
			if err := compileLog(child, sec); err != nil {
				return fmt.Errorf("log: %w", err)
			}
		case "flow":
			if err := compileFlow(child, sec); err != nil {
				return fmt.Errorf("flow: %w", err)
			}
		case "ike":
			if err := compileIKE(child, sec); err != nil {
				return fmt.Errorf("ike: %w", err)
			}
		case "ipsec":
			if err := compileIPsec(child, sec); err != nil {
				return fmt.Errorf("ipsec: %w", err)
			}
		case "dynamic-address":
			if err := compileDynamicAddress(child, sec); err != nil {
				return fmt.Errorf("dynamic-address: %w", err)
			}
		case "alg":
			if err := compileALG(child, sec); err != nil {
				return fmt.Errorf("alg: %w", err)
			}
		case "ssh-known-hosts":
			// #4821: initialize the map once (find-or-create), and APPEND
			// each host's keys rather than replacing the map entry
			// wholesale. A hand-authored `load override` config can carry
			// two literal `host <name> { ... }` top-level sibling blocks
			// under `ssh-known-hosts` (or two `ssh-known-hosts { ... }`
			// blocks themselves) — the hierarchical parser keeps repeated
			// same-key blocks as separate siblings (it does not merge, same
			// root cause as #4818/#4820), so namedInstances yields TWO
			// entries for the same host name. The pre-fix
			// `sec.SSHKnownHosts[hostInst.name] = keys` (bare overwrite, and
			// `sec.SSHKnownHosts = make(...)` re-executing on every
			// ssh-known-hosts block) let a later block silently REPLACE an
			// earlier one's key(s), discarding that key type entirely — an
			// operator-visible SSH host-key verification failure. Junos
			// merges repeated blocks. A SINGLE host block still produces
			// the identical key slice as before (append onto a nil slice
			// is byte-identical to a fresh slice), so this is a no-op for
			// the overwhelmingly common single-block case.
			if sec.SSHKnownHosts == nil {
				sec.SSHKnownHosts = make(map[string][]SSHKnownHostKey)
			}
			for _, hostInst := range namedInstances(child.FindChildren("host")) {
				for _, kp := range hostInst.node.Children {
					name := kp.Name()
					if v := nodeVal(kp); v != "" {
						sec.SSHKnownHosts[hostInst.name] = append(sec.SSHKnownHosts[hostInst.name], SSHKnownHostKey{Type: name, Key: v})
					}
				}
			}
		case "policy-stats":
			for _, sw := range child.FindChildren("system-wide") {
				enabled, valid := policyStatsValue12825(nodeVal(sw))
				if valid {
					sec.PolicyStatsEnabled = enabled
				}
			}
		case "pre-id-default-policy":
			if sec.PreIDDefaultPolicy == nil {
				sec.PreIDDefaultPolicy = &PreIDDefaultPolicy{}
			}
			// #3850: read EVERY `then {}` block, not just the first via
			// FindChild — a duplicate then block (load merge/override) would
			// otherwise have its session-log modes silently dropped.
			for _, thenNode := range child.FindChildren("then") {
				// #3703: multi-value session-log list leaf. Read every mode via
				// the firewallMatchValues SSOT (Keys[1:] AND/OR one-per-child)
				// across EVERY `log` leaf so a bracket `then log [ session-init
				// session-close ]` keeps BOTH flags AND separate `then log
				// session-init` / `then log session-close` lines (two sibling
				// leaves) both land. The prior single FindChild lookup read only
				// the first leaf and missed the tail (the #2419 collapse bug).
				// Unknown tokens are rejected at commit by SchemaValidate.
				for _, logNode := range thenNode.FindChildren("log") {
					for _, mode := range firewallMatchValues(logNode) {
						switch mode {
						case "session-init":
							sec.PreIDDefaultPolicy.LogSessionInit = true
						case "session-close":
							sec.PreIDDefaultPolicy.LogSessionClose = true
						}
					}
				}
			}
		}
	}
	return nil
}
