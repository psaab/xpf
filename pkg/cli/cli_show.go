package cli

// #1044c: relocate handleShow from cli.go. Pure relocation — same
// methodology as #1043 server_show.go split. No behavior change.

import (
	"fmt"
	"os"
	"strings"

	"github.com/psaab/xpf/pkg/cmdtree"
)

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
		rest := strings.Join(args[1:], " ")
		// Build path (everything after "configuration" before "|")
		var cfgPath []string
		for _, a := range args[1:] {
			if a == "|" {
				break
			}
			cfgPath = append(cfgPath, a)
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
		switch {
		case strings.Contains(rest, "| display json"):
			switch {
			case redact:
				output = c.store.ShowActiveJSONRedacted(cfgPath)
			case len(cfgPath) > 0:
				output = c.store.ShowActivePathJSON(cfgPath)
			default:
				output = c.store.ShowActiveJSON()
			}
		case strings.Contains(rest, "| display set"):
			switch {
			case redact:
				output = c.store.ShowActiveSetRedacted(cfgPath)
			case len(cfgPath) > 0:
				output = c.store.ShowActivePathSet(cfgPath)
			default:
				output = c.store.ShowActiveSet()
			}
		case strings.Contains(rest, "| display xml"):
			switch {
			case redact:
				output = c.store.ShowActiveXMLRedacted(cfgPath)
			case len(cfgPath) > 0:
				output = c.store.ShowActivePathXML(cfgPath)
			default:
				output = c.store.ShowActiveXML()
			}
		case strings.Contains(rest, "| display inheritance"):
			switch {
			case redact:
				output = c.store.ShowActiveInheritanceRedacted(cfgPath)
			case len(cfgPath) > 0:
				output = c.store.ShowActivePathInheritance(cfgPath)
			default:
				output = c.store.ShowActiveInheritance()
			}
		case strings.Index(rest, "| ") >= 0:
			idx := strings.Index(rest, "| ")
			pipeParts := strings.Fields(strings.TrimSpace(rest[idx+2:]))
			if len(pipeParts) >= 2 && pipeParts[0] == "display" {
				fmt.Printf("syntax error: unknown display option '%s'\n", pipeParts[1])
			} else if len(pipeParts) > 0 {
				fmt.Printf("syntax error: unknown pipe command '%s'\n", pipeParts[0])
			}
			return nil
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
