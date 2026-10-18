package cli

// #1044c: relocate handleShow from cli.go. Pure relocation — same
// methodology as #1043 server_show.go split. No behavior change.

import (
	"fmt"
	"os"
	"strings"

	"github.com/psaab/xpf/pkg/cmdtree"
)

// displayPipeFormat identifies a configuration render format selected by a
// `| display <format>` pipe.
type displayPipeFormat int

const (
	displayPipeNone displayPipeFormat = iota
	displayPipeJSON
	displayPipeSet
	displayPipeXML
	displayPipeInheritance
)

// splitDisplayPipe splits configuration-show arguments at the first bare
// `|` token and validates the pipe exactly.
//
// #14715: trailing tokens after a display format were silently discarded by
// substring selection (`strings.Contains(rest, "| display set")`), so
// `show configuration | display set interfaces` rendered the whole tree
// instead of interfaces — and the authorization gate saw a different command
// than the executor ran. Only `| display <json|set|xml|inheritance>` (with
// no trailing tokens) is a display pipe; a single recognised output filter
// may follow it (`| display set | match x`, which dispatch splits off
// before dispatchOperational — see the chained-pipe cell in the #14715
// regression). Any other pipe shape is returned as an unknown pipe so the
// caller can name it in a syntax error instead of guessing a format.
//
// Returns path (tokens before `|`), the format, the remaining pipe tokens
// when the pipe is not exactly a display pipe, and whether a pipe was present.
func splitDisplayPipe(args []string) (path []string, format displayPipeFormat, rest []string, piped bool, err error) {
	pipeIdx := -1
	for i, a := range args {
		if a == "|" {
			pipeIdx = i
			break
		}
	}
	if pipeIdx < 0 {
		return args, displayPipeNone, nil, false, nil
	}
	path = args[:pipeIdx]
	pipe := args[pipeIdx+1:]
	if len(pipe) == 0 {
		return path, displayPipeNone, pipe, true, fmt.Errorf("syntax error: missing pipe command after '|'")
	}
	if pipe[0] == "display" {
		if len(pipe) != 2 {
			return path, displayPipeNone, pipe, true, fmt.Errorf("syntax error: '| display' requires exactly one of json, set, xml, inheritance")
		}
		if !isDisplayFormat(pipe[1]) {
			return path, displayPipeNone, pipe, true, fmt.Errorf("syntax error: unknown display option '%s'", pipe[1])
		}
		switch pipe[1] {
		case "json":
			return path, displayPipeJSON, nil, true, nil
		case "set":
			return path, displayPipeSet, nil, true, nil
		case "xml":
			return path, displayPipeXML, nil, true, nil
		default:
			return path, displayPipeInheritance, nil, true, nil
		}
	}
	return path, displayPipeNone, pipe, true, nil
}

// splitConfigShowPipe is splitDisplayPipe for config-mode `show`, whose pipe
// additionally accepts `| compare [rollback <N>]`. It returns the same shape;
// a compare pipe is reported as format=none with rest=["compare", ...] so
// the caller renders the diff, and any other non-display pipe is an unknown
// pipe for the caller to name.
func splitConfigShowPipe(args []string) (path []string, format displayPipeFormat, rest []string, piped bool, err error) {
	pipeIdx := -1
	for i, a := range args {
		if a == "|" {
			pipeIdx = i
			break
		}
	}
	if pipeIdx < 0 {
		return args, displayPipeNone, nil, false, nil
	}
	pipe := args[pipeIdx+1:]
	if len(pipe) > 0 && pipe[0] == "compare" {
		return args[:pipeIdx], displayPipeNone, pipe, true, nil
	}
	return splitDisplayPipe(args)
}

func (c *CLI) handleShow(args []string) error {
	showTree := operationalTree["show"].Children
	if len(args) == 0 {
		fmt.Println("show: specify what to show")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(showTree))
		return nil
	}

	resolved, err := resolveCommand(args[0], keysFromTree(showTree))
	if err != nil {
		return err
	}
	args[0] = resolved

	switch args[0] {
	case "version":
		return c.showVersion()

	case "chassis":
		return c.showChassis(args[1:])

	case "configuration":
		// #14715: parse the display pipe token-exactly. Trailing tokens
		// after a format are a syntax error, never silently discarded.
		cfgPath, format, pipeRest, piped, pipeErr := splitDisplayPipe(args[1:])
		if pipeErr != nil {
			fmt.Println(pipeErr.Error())
			return nil
		}
		if piped && format == displayPipeNone {
			fmt.Printf("syntax error: unknown pipe command '%s'\n", pipeRest[0])
			return nil
		}
		// Secret redaction (#4099): a VIEW-only read-only / config-viewer (and
		// operator) login class must see ##SECRET-DATA## in place of IKE PSKs,
		// SNMP communities and authentication-keys — matching Junos and the
		// always-redacted REST/gRPC ShowConfig (#4051). super-user (and the
		// no-RBAC empty class) still reads cleartext. The *Redacted store
		// methods take the path directly (nil/empty == whole tree), mirroring
		// the gRPC/REST usage; the cleartext siblings back the whole-tree /
		// subtree split for the privileged path.
		redact := c.showConfigRedacted()
		var output string
		switch format {
		case displayPipeJSON:
			switch {
			case redact:
				output = c.store.ShowActiveJSONRedacted(cfgPath)
			case len(cfgPath) > 0:
				output = c.store.ShowActivePathJSON(cfgPath)
			default:
				output = c.store.ShowActiveJSON()
			}
		case displayPipeSet:
			switch {
			case redact:
				output = c.store.ShowActiveSetRedacted(cfgPath)
			case len(cfgPath) > 0:
				output = c.store.ShowActivePathSet(cfgPath)
			default:
				output = c.store.ShowActiveSet()
			}
		case displayPipeXML:
			switch {
			case redact:
				output = c.store.ShowActiveXMLRedacted(cfgPath)
			case len(cfgPath) > 0:
				output = c.store.ShowActivePathXML(cfgPath)
			default:
				output = c.store.ShowActiveXML()
			}
		case displayPipeInheritance:
			switch {
			case redact:
				output = c.store.ShowActiveInheritanceRedacted(cfgPath)
			case len(cfgPath) > 0:
				output = c.store.ShowActivePathInheritance(cfgPath)
			default:
				output = c.store.ShowActiveInheritance()
			}
		default:
			switch {
			case redact:
				output = c.store.ShowActiveRedacted(cfgPath)
			case len(cfgPath) > 0:
				output = c.store.ShowActivePath(cfgPath)
			default:
				output = c.store.ShowActive()
			}
		}
		if len(cfgPath) > 0 && output == "" {
			fmt.Printf("configuration path not found: %s\n", strings.Join(cfgPath, " "))
		} else {
			fmt.Print(output)
		}
		return nil

	case "class-of-service":
		return c.handleShowClassOfService(args[1:])

	case "dhcp":
		if len(args) >= 2 {
			switch args[1] {
			case "leases":
				return c.showDHCPLeases()
			case "client-identifier":
				return c.showDHCPClientIdentifier()
			}
		}
		cmdtree.PrintTreeHelp("show dhcp:", operationalTree, "show", "dhcp")
		return nil

	case "firewall":
		// #4422: `show firewall [filter <name>] effective [family <f>]` renders
		// the compiled FirewallFilterSnapshot the dataplane actually receives
		// (post prefix-list resolution, DSCP code-point resolution, TCP-flags
		// lowering, fall-through, fail-closed markers) instead of the raw config.
		// `effective` is a trailing modifier alongside the existing loose
		// `family <f>` modifier, so scan for both.
		// #14687: a dangling `filter` selector must error, not widen to the
		// all-filters listing the RBAC gate did not judge.
		if len(args) >= 2 && args[1] == "filter" && len(args) < 3 {
			return fmt.Errorf("usage: show firewall filter <name> [family inet|inet6] [effective]")
		}
		if firewallArgsHaveWord(args, "effective") {
			family := firewallFamilyArg(args)
			if len(args) >= 3 && args[1] == "filter" {
				return c.showEffectiveFirewallFilter(args[2], family)
			}
			return c.showEffectiveFirewallFilters(family)
		}
		if len(args) >= 3 && args[1] == "filter" {
			family := ""
			if len(args) >= 4 && args[3] == "family" {
				if len(args) < 5 {
					return fmt.Errorf("usage: show firewall filter <name> family inet|inet6")
				}
				family = args[4]
			}
			return c.showFirewallFilter(args[2], family)
		}
		return c.showFirewallFilters()

	case "flow-monitoring":
		if len(args) > 1 && args[1] == "statistics" {
			return c.showFlowMonitoringStatistics()
		}
		return c.showFlowMonitoring()

	case "log":
		return c.showDaemonLog(args[1:])

	case "route":
		return c.handleShowRoute(args[1:])

	case "security":
		return c.handleShowSecurity(args[1:])

	case "services":
		return c.handleShowServices(args[1:])

	case "interfaces":
		return c.showInterfaces(args[1:])

	case "protocols":
		return c.handleShowProtocols(args[1:])

	case "bgp":
		// "show bgp ..." is a shorthand alias for "show protocols bgp ..."
		return c.showBGP(args[1:])

	case "system":
		return c.handleShowSystem(args[1:])

	case "schedulers":
		return c.showSchedulers()

	case "dhcp-relay":
		return c.showDHCPRelay()

	case "dhcp-server":
		if len(args) >= 2 && args[1] == "dynamic-dns" {
			detail := len(args) >= 3 && args[2] == "detail"
			return c.showDHCPDynamicDNS(detail)
		}
		detail := len(args) >= 2 && args[1] == "detail"
		return c.showDHCPServer(detail)

	case "snmp":
		if len(args) >= 2 && args[1] == "v3" {
			return c.showSNMPv3()
		}
		return c.showSNMP()

	case "lldp":
		if len(args) >= 2 && args[1] == "neighbors" {
			return c.showLLDPNeighbors()
		}
		return c.showLLDP()

	case "arp":
		return c.showARP(args[1:])

	case "ipv6":
		return c.handleShowIPv6(args[1:])

	case "policy-options":
		return c.showPolicyOptions()

	case "route-map":
		return c.showRouteMap()

	case "event-options":
		return c.showEventOptions()

	case "routing-options":
		return c.showRoutingOptions()

	case "routing-instances":
		detail := len(args) >= 2 && args[1] == "detail"
		return c.showRoutingInstances(detail)

	case "forwarding-options":
		if len(args) >= 2 && args[1] == "port-mirroring" {
			return c.showPortMirroring()
		}
		return c.showForwardingOptions()

	case "vlans":
		return c.showVlans()

	case "task":
		return c.showTask()

	case "monitor":
		if len(args) >= 3 && args[1] == "security" && args[2] == "flow" {
			return c.showMonitorSecurityFlow()
		}
		cmdtree.PrintTreeHelp("show monitor:", operationalTree, "show", "monitor")
		return nil

	default:
		return fmt.Errorf("unknown show target: %s", args[0])
	}
}

// firewallArgsHaveWord reports whether word appears anywhere in the firewall
// show arguments (args[0] is "firewall"). Used to detect the trailing
// `effective` modifier (#4422) regardless of its position relative to the
// `filter <name>` / `family <f>` tokens.
func firewallArgsHaveWord(args []string, word string) bool {
	for _, a := range args {
		if a == word {
			return true
		}
	}
	return false
}

// firewallFamilyArg extracts the value of the loose trailing `family <f>`
// modifier from the firewall show arguments, or "" if absent (#4422).
func firewallFamilyArg(args []string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "family" {
			return args[i+1]
		}
	}
	return ""
}
