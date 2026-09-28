package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/clusterfailover"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/wgkey"
)

const maxDynamicAddressShrinkAckReasonBytes = 512

// confirmYes prompts the operator with `prompt`, reads a line via
// the readline instance, and returns true when the trimmed +
// lowercased response is exactly "yes". Any other response (or a
// read error) returns false with a nil error so callers can print
// their "cancelled" message and return cleanly.
//
// When invoked without a readline instance (non-TTY `-c` mode) the
// caller has no way to gather confirmation. Rather than silently
// reading stdin and possibly executing a destructive action against
// unintended input, hard-error so the script visibly fails. This
// applies to reboot / halt / power-off / zeroize / in-service-upgrade
// — operator-authored automation should drive these through the
// gRPC SystemAction RPC directly, not via the interactive CLI
// binary. See #1563.
func (c *ctl) confirmYes(prompt string) (bool, error) {
	if c.rl == nil {
		return false, fmt.Errorf(
			"this command requires interactive confirmation (TTY); " +
				"not available in -c mode")
	}
	fmt.Print(prompt)
	c.rl.SetPrompt("")
	line, err := c.rl.Readline()
	// Restore the correct prompt for the current mode so this
	// helper composes with both `request system ...` (operational)
	// and `run request system ...` (from configuration mode).
	if c.configMode.Load() {
		c.rl.SetPrompt(c.configPrompt())
	} else {
		c.rl.SetPrompt(c.operationalPrompt())
	}
	if err != nil {
		return false, nil
	}
	return strings.TrimSpace(strings.ToLower(line)) == "yes", nil
}

func (c *ctl) handleRequest(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("request:", "request")
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
	default:
		return fmt.Errorf("unknown request target: %s", args[0])
	}
	if len(args) < 2 {
		printRemoteTreeHelp("request system:", "request", "system")
		return nil
	}

	switch args[1] {
	case "reboot", "halt", "power-off":
		ok, err := c.confirmYes(fmt.Sprintf(
			"%s the system? [yes,no] (no) ", strings.Title(args[1])))
		if err != nil {
			return err
		}
		if !ok {
			fmt.Printf("%s cancelled\n", strings.Title(args[1]))
			return nil
		}
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: args[1],
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	case "zeroize":
		fmt.Println("WARNING: This will erase all configuration and return to factory defaults.")
		ok, err := c.confirmYes("Zeroize the system? [yes,no] (no) ")
		if err != nil {
			return err
		}
		if !ok {
			fmt.Println("Zeroize cancelled")
			return nil
		}
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: "zeroize",
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	case "software":
		if len(args) < 3 || args[2] != "in-service-upgrade" {
			printRemoteTreeHelp("request system software:", "request", "system", "software")
			return nil
		}
		fmt.Println("WARNING: This will force this node to secondary for all redundancy groups.")
		ok, err := c.confirmYes("Proceed with in-service upgrade? [yes,no] (no) ")
		if err != nil {
			return err
		}
		if !ok {
			fmt.Println("ISSU cancelled")
			return nil
		}
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: "in-service-upgrade",
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	case "configuration":
		return c.handleRequestSystemConfiguration(args[2:])

	case "dynamic-dns":
		// #3276: operator force-now / check-now. `update` forces an immediate
		// publish of all owned DDNS records; `check` re-observes and publishes
		// only changed records. The daemon honors the per-RG owner gate.
		if len(args) < 3 {
			printRemoteTreeHelp("request system dynamic-dns:", "request", "system", "dynamic-dns")
			return nil
		}
		var action string
		switch args[2] {
		case "update":
			action = "dynamic-dns-update"
		case "check":
			action = "dynamic-dns-check"
		default:
			printRemoteTreeHelp("request system dynamic-dns:", "request", "system", "dynamic-dns")
			return nil
		}
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: action,
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	default:
		return fmt.Errorf("unknown request system command: %s", args[1])
	}
}

func (c *ctl) handleRequestChassis(args []string) error {
	if len(args) == 0 || args[0] != "cluster" {
		printRemoteTreeHelp("request chassis:", "request", "chassis")
		return nil
	}
	args = args[1:]
	if len(args) == 0 {
		printRemoteTreeHelp("request chassis cluster:", "request", "chassis", "cluster")
		return nil
	}
	switch args[0] {
	case "failover":
		return c.handleRequestChassisClusterFailover(args[1:])
	case "data-plane":
		return c.handleRequestChassisClusterDataPlane(args[1:])
	default:
		printRemoteTreeHelp("request chassis cluster:", "request", "chassis", "cluster")
		return nil
	}
}

func (c *ctl) handleRequestChassisClusterFailover(args []string) error {
	// One strict grammar, shared with the in-process CLI and the gRPC handler
	// (pkg/clusterfailover). Reject a malformed selector, a missing/extra
	// operand, or an out-of-range node BEFORE issuing the privileged
	// SystemAction RPC — the old per-form ad-hoc parsing silently degraded a
	// misspelled/truncated `node` selector into an untargeted RG failover
	// (#5810, #4883-C).
	op, err := clusterfailover.ParseCommand(args)
	if err != nil {
		return err
	}
	resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
		Action: op.Action(),
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println(resp.Message)
	return nil
}

func (c *ctl) handleRequestChassisClusterDataPlane(args []string) error {
	if len(args) == 0 || args[0] != "userspace" {
		printRemoteTreeHelp("request chassis cluster data-plane:", "request", "chassis", "cluster", "data-plane")
		return nil
	}
	args = args[1:]
	var action string
	var target string
	switch {
	case len(args) > 0 && args[0] == "inject-packet":
		slot, mode, extra, err := dpuserspace.ParseInjectPacketCommand(args)
		if err != nil {
			return err
		}
		action = fmt.Sprintf("userspace-inject:%d:%s", slot, mode)
		target = dpuserspace.EncodeInjectPacketTarget(extra)
	case len(args) > 0 && args[0] == "forwarding":
		armed, err := dpuserspace.ParseForwardingCommand(args)
		if err != nil {
			return err
		}
		if armed {
			action = "userspace-forwarding:arm"
		} else {
			action = "userspace-forwarding:disarm"
		}
	case len(args) > 0 && args[0] == "queue":
		queueID, _, _, err := dpuserspace.ParseQueueCommand(args)
		if err != nil {
			return err
		}
		action = fmt.Sprintf("userspace-queue:%d:%s", queueID, strings.ToLower(args[2]))
	case len(args) > 0 && args[0] == "binding":
		slot, _, _, err := dpuserspace.ParseBindingCommand(args)
		if err != nil {
			return err
		}
		action = fmt.Sprintf("userspace-binding:%d:%s", slot, strings.ToLower(args[3]))
	default:
		printRemoteTreeHelp("request chassis cluster data-plane userspace:", "request", "chassis", "cluster", "data-plane", "userspace")
		return nil
	}
	resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
		Action: action,
		Target: target,
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println(resp.Message)
	return nil
}

func (c *ctl) handleRequestDHCP(args []string) error {
	if len(args) == 0 || args[0] != "renew" {
		printRemoteTreeHelp("request dhcp:", "request", "dhcp")
		return nil
	}
	if len(args) < 2 {
		return fmt.Errorf("usage: request dhcp renew <interface>")
	}
	resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
		Action: "dhcp-renew",
		Target: args[1],
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println(resp.Message)
	return nil
}

func (c *ctl) handleRequestProtocols(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("request protocols:", "request", "protocols")
		return nil
	}
	switch args[0] {
	case "ospf":
		if len(args) < 2 || args[1] != "clear" {
			printRemoteTreeHelp("request protocols ospf:", "request", "protocols", "ospf")
			return nil
		}
		// #5647: `ospf-clear` is a selector-free global reset (vtysh
		// `clear ip ospf process`). A scoped-looking suffix such as
		// `... clear neighbor 10.0.0.1` used to be silently dropped and
		// still reset the WHOLE process. Junos never widens scope
		// silently, so reject any trailing token BEFORE the RPC rather
		// than perform an untargeted global mutation.
		if len(args) > 2 {
			return fmt.Errorf("request protocols ospf clear does not accept a "+
				"selector (%q); it resets the entire OSPF process. Re-run "+
				"without a selector to confirm the global clear",
				strings.Join(args[2:], " "))
		}
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: "ospf-clear",
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	case "bgp":
		if len(args) < 2 || args[1] != "clear" {
			printRemoteTreeHelp("request protocols bgp:", "request", "protocols", "bgp")
			return nil
		}
		// #5647: `bgp-clear` soft-clears EVERY BGP session (vtysh
		// `clear bgp * soft`). Reject a scoped-looking suffix such as
		// `... clear neighbor 10.0.0.1` instead of silently dropping the
		// selector and soft-clearing all peers.
		if len(args) > 2 {
			return fmt.Errorf("request protocols bgp clear does not accept a "+
				"selector (%q); it soft-clears every BGP session. Re-run "+
				"without a selector to confirm the global clear",
				strings.Join(args[2:], " "))
		}
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: "bgp-clear",
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	default:
		return fmt.Errorf("unknown request protocols target: %s", args[0])
	}
}

func (c *ctl) handleRequestSecurity(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("request security:", "request", "security")
		return nil
	}
	switch args[0] {
	case "ipsec":
		if len(args) < 3 || args[1] != "sa" || args[2] != "clear" {
			printRemoteTreeHelp("request security ipsec sa:", "request", "security", "ipsec", "sa")
			return nil
		}
		// #5647: `ipsec-sa-clear` terminates EVERY IPsec SA
		// (TerminateAllSAs). Reject a scoped-looking suffix such as
		// `... sa clear 42` / `... sa clear tunnel foo` instead of
		// silently dropping the selector and tearing down all SAs.
		if len(args) > 3 {
			return fmt.Errorf("request security ipsec sa clear does not accept a "+
				"selector (%q); it terminates every IPsec SA. Re-run without a "+
				"selector to confirm the global clear",
				strings.Join(args[3:], " "))
		}
		resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
			Action: "ipsec-sa-clear",
		})
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		fmt.Println(resp.Message)
		return nil
	case "wireguard":
		return c.handleRequestSecurityWireguard(args[1:])
	case "policies":
		return c.handleRequestSecurityPolicies(args[1:])
	case "dynamic-address":
		return c.handleRequestSecurityDynamicAddress(args[1:])
	default:
		return fmt.Errorf("unknown request security target: %s", args[0])
	}
}

func (c *ctl) handleRequestSecurityDynamicAddress(args []string) error {
	if len(args) == 0 || args[0] != "acknowledge-shrink" {
		printRemoteTreeHelp("request security dynamic-address:", "request", "security", "dynamic-address")
		return nil
	}
	const usage = "usage: request security dynamic-address acknowledge-shrink <feed> candidate-id <id> candidate-hash <sha256> old-count <count> new-count <count> reason <reason...>"
	if len(args) < 12 || args[2] != "candidate-id" || args[4] != "candidate-hash" ||
		args[6] != "old-count" || args[8] != "new-count" || args[10] != "reason" {
		return fmt.Errorf("%s", usage)
	}
	feed := args[1]
	if feed == "" || strings.TrimSpace(feed) != feed {
		return fmt.Errorf("%s: feed name is required", usage)
	}
	idText := args[3]
	for i := range idText {
		if idText[i] < '0' || idText[i] > '9' {
			return fmt.Errorf("%s: candidate ID must be a positive uint64", usage)
		}
	}
	candidateID, err := strconv.ParseUint(idText, 10, 64)
	if err != nil || candidateID == 0 {
		return fmt.Errorf("%s: candidate ID must be a positive uint64", usage)
	}
	candidateHash := args[5]
	if !validDynamicAddressShrinkCandidateHash(candidateHash) {
		return fmt.Errorf("%s: candidate hash must be a 64-character lowercase SHA-256 hex value", usage)
	}
	oldCount, err := strconv.ParseUint(args[7], 10, 32)
	if err != nil || oldCount == 0 {
		return fmt.Errorf("%s: old count must be a positive uint32", usage)
	}
	newCount, err := strconv.ParseUint(args[9], 10, 32)
	if err != nil {
		return fmt.Errorf("%s: new count must be a uint32", usage)
	}
	reason := strings.TrimSpace(strings.Join(args[11:], " "))
	if reason == "" {
		return fmt.Errorf("%s: reason is required", usage)
	}
	if len(reason) > maxDynamicAddressShrinkAckReasonBytes {
		return fmt.Errorf("%s: reason exceeds %d bytes", usage, maxDynamicAddressShrinkAckReasonBytes)
	}
	for _, r := range reason {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s: reason must not contain control characters", usage)
		}
	}
	resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{
		Action:            "dynamic-address-shrink-ack",
		Target:            feed,
		CandidateId:       candidateID,
		CandidateHash:     candidateHash,
		CandidateOldCount: uint32(oldCount),
		CandidateNewCount: uint32(newCount),
		Reason:            reason,
	})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println(resp.Message)
	return nil
}

func validDynamicAddressShrinkCandidateHash(candidateHash string) bool {
	if len(candidateHash) != 64 {
		return false
	}
	for i := range candidateHash {
		if !((candidateHash[i] >= '0' && candidateHash[i] <= '9') ||
			(candidateHash[i] >= 'a' && candidateHash[i] <= 'f')) {
			return false
		}
	}
	return true
}

// handleRequestSecurityPolicies implements `request security policies check`
// over gRPC (#8597 K47).
//
// The verb is advertised by the SSOT command tree and implemented on the local
// console, and this dispatcher used to answer "unknown request security target:
// policies" — so tab-completion, served by that same tree, offered a command
// the dispatcher then refused. It is a pure config lint with no dataplane call,
// so the server runs it behind the `policies-check` ShowText topic and this
// prints what comes back; the analysis AND its rendering are single-sourced in
// pkg/policymatch, so the two surfaces cannot answer differently.
func (c *ctl) handleRequestSecurityPolicies(args []string) error {
	if len(args) == 0 || args[0] != "check" {
		printRemoteTreeHelp("request security policies:", "request", "security", "policies")
		return nil
	}
	if len(args) > 1 {
		return fmt.Errorf("request security policies check does not accept "+
			"arguments (%q)", strings.Join(args[1:], " "))
	}
	return c.showText("policies-check")
}

// handleRequestSecurityWireguard implements `request security wireguard
// generate-private-key` (#1434 Increment 1). The key is generated
// LOCALLY in the CLI (pure-Go X25519) — Junos `request` semantics are
// print-only, no config mutation, and a key generator must not depend
// on the daemon being up. No gRPC round-trip; the control socket is
// contended and there is no reason the key must come from the helper's
// RNG.
func (c *ctl) handleRequestSecurityWireguard(args []string) error {
	if len(args) == 0 || args[0] != "generate-private-key" {
		printRemoteTreeHelp("request security wireguard:", "request", "security", "wireguard")
		return nil
	}
	kp, err := wgkey.Generate()
	if err != nil {
		return fmt.Errorf("generate WireGuard key: %w", err)
	}
	fmt.Printf("Private key: %s\n", kp.PrivateKey)
	fmt.Printf("Public key:  %s\n", kp.PublicKey)
	return nil
}

// handleRequestSystemConfiguration implements `request system configuration
// rescue save|delete` over gRPC (#8597 K47), mirroring pkg/cli's local handler.
//
// The rescue config is a store operation with a one-line result, so it goes
// through SystemAction rather than a new RPC. The printed messages are the
// server's and are byte-identical to the console's: an operator following a
// runbook must see the same confirmation on either surface.
func (c *ctl) handleRequestSystemConfiguration(args []string) error {
	if len(args) == 0 {
		printRemoteTreeHelp("request system configuration:", "request", "system", "configuration")
		return nil
	}
	if args[0] != "rescue" {
		return fmt.Errorf("unknown request system configuration command: %s", args[0])
	}
	if len(args) < 2 {
		printRemoteTreeHelp("request system configuration rescue:",
			"request", "system", "configuration", "rescue")
		return nil
	}
	var action string
	switch args[1] {
	case "save":
		action = "rescue-save"
	case "delete":
		action = "rescue-delete"
	default:
		return fmt.Errorf("unknown request system configuration rescue command: %s", args[1])
	}
	// A trailing token would otherwise be dropped silently, and this verb
	// REPLACES the saved rescue config — the same reason `ipsec sa clear`
	// refuses a selector rather than widening it.
	if len(args) > 2 {
		return fmt.Errorf("request system configuration rescue %s does not accept "+
			"arguments (%q)", args[1], strings.Join(args[2:], " "))
	}
	resp, err := c.client.SystemAction(c.ctx(), &pb.SystemActionRequest{Action: action})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	fmt.Println(resp.Message)
	return nil
}
