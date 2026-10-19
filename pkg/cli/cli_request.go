package cli

// cli_request.go is the dispatch shell for the operational request /
// diagnostic command families that were historically one 1300-line grab-bag
// (#4653). It keeps only the top-level `request` dispatcher plus the small
// `request dhcp` / `request protocols` handlers that do not warrant their own
// file. The per-family handlers live in sibling files in this package (same
// package, so unexported symbols stay reachable):
//
//	cli_request_ping.go     ping / traceroute (+ diagcmd argv builders)
//	cli_request_testcmd.go  test policy / routing / security-zone
//	monitor_traffic.go      monitor + monitor traffic (tcpdump argv builder)
//	cli_request_chassis.go  request chassis cluster failover / data-plane
//	cli_request_system.go   request system reboot/halt/zeroize/software/...
//	cli_request_security.go request security ipsec / policies / wireguard
//
// The split is pure code motion — no behavior change. The security-sensitive
// diagcmd/tcpdump argv construction with its `--` end-of-options separators
// (#4527 / #2084 / #4524) moved verbatim.

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/psaab/xpf/pkg/termsafe"
)

// rejectScopedClear returns the error for a global-only `request ... clear`
// that was handed a scoped-looking suffix. #5647: the FRR/strongSwan wiring
// behind these clears has no per-neighbor / per-area / per-SA plumbing, so a
// trailing selector token (`... clear neighbor 10.0.0.1`, `... sa clear 42`)
// used to be silently DROPPED while the selector-free global reset still ran —
// the operator believed the action was scoped but every OSPF adjacency / BGP
// session / IPsec SA was reset. Mirror the remote CLI (cmd/cli, #5652): reject
// the suffix before the mutation rather than silently widen scope, because
// Junos never widens scope silently. cmd is the full command path, effect
// describes the global action, and extra is the rejected trailing token(s).
func rejectScopedClear(cmd, effect string, extra []string) error {
	return fmt.Errorf("%s does not accept a selector (%q); it %s. Re-run "+
		"without a selector to confirm the global clear",
		cmd, strings.Join(extra, " "), effect)
}

func (c *CLI) handleRequest(args []string) error {
	if len(args) == 0 {
		fmt.Println("request:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children))
		return nil
	}

	switch args[0] {
	case "chassis":
		return c.handleRequestChassis(args[1:])
	case "dhcp":
		return c.handleRequestDHCP(args[1:])
	case "protocols":
		return c.handleRequestProtocols(args[1:])
	case "security":
		return c.handleRequestSecurity(args[1:])
	case "system":
		return c.handleRequestSystem(args[1:])
	default:
		return fmt.Errorf("unknown request target: %s", args[0])
	}
}

func (c *CLI) handleRequestDHCP(args []string) error {
	if len(args) == 0 || args[0] != "renew" {
		fmt.Println("request dhcp:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["dhcp"].Children))
		return nil
	}
	if len(args) < 2 {
		return fmt.Errorf("usage: request dhcp renew <interface>")
	}
	if c.dhcp == nil {
		return fmt.Errorf("DHCP manager not available")
	}
	// #15227 A43-04: resolve through the active config like the gRPC
	// surface; the raw Junos spelling never matches the manager's lease
	// key. Nil store keeps the raw target (manager diagnosis stands).
	renewTarget := args[1]
	if c.store != nil {
		resolved, rerr := c.store.ActiveConfig().ResolveDHCPRenewTarget(args[1])
		if rerr != nil {
			return rerr
		}
		renewTarget = resolved
	}
	if err := c.dhcp.Renew(renewTarget); err != nil {
		return err
	}
	fmt.Printf("DHCP renewal initiated on %s\n", renewTarget)
	return nil
}

func (c *CLI) handleRequestProtocols(args []string) error {
	if len(args) == 0 {
		fmt.Println("request protocols:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["protocols"].Children))
		return nil
	}
	switch args[0] {
	case "ospf":
		if len(args) < 2 || args[1] != "clear" {
			fmt.Println("request protocols ospf:")
			writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["protocols"].Children["ospf"].Children))
			return nil
		}
		// #5647: reject a scoped-looking suffix BEFORE the mutation — the
		// suffix validation is input-shape checking and precedes the runtime
		// manager-availability gate.
		if len(args) > 2 {
			return rejectScopedClear("request protocols ospf clear",
				"resets the entire OSPF process", args[2:])
		}
		if c.frr == nil {
			return fmt.Errorf("FRR manager not available")
		}
		output, err := c.frr.ExecVtysh(context.Background(), "clear ip ospf process")
		if err != nil {
			return fmt.Errorf("clear OSPF: %w", err)
		}
		if output != "" {
			// #6468 D2: raw vtysh stdout to the operator terminal. `clear`
			// normally prints nothing, but the guard belongs on the print,
			// not on an assumption about what FRR chooses to emit.
			fmt.Print(termsafe.SanitizeBlockForDisplay(output))
		}
		fmt.Println("OSPF process cleared")
		return nil
	case "bgp":
		if len(args) < 2 || args[1] != "clear" {
			fmt.Println("request protocols bgp:")
			writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["protocols"].Children["bgp"].Children))
			return nil
		}
		// #5647: reject a scoped-looking suffix BEFORE the mutation.
		if len(args) > 2 {
			return rejectScopedClear("request protocols bgp clear",
				"soft-clears every BGP session", args[2:])
		}
		if c.frr == nil {
			return fmt.Errorf("FRR manager not available")
		}
		output, err := c.frr.ExecVtysh(context.Background(), "clear bgp * soft")
		if err != nil {
			return fmt.Errorf("clear BGP: %w", err)
		}
		if output != "" {
			// #6468 D2: see the OSPF clear above — same guard, same reason.
			fmt.Print(termsafe.SanitizeBlockForDisplay(output))
		}
		fmt.Println("BGP sessions cleared (soft reset)")
		return nil
	default:
		return fmt.Errorf("unknown request protocols target: %s", args[0])
	}
}
