package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/policymatch"
	"github.com/psaab/xpf/pkg/wgkey"
)

func (c *CLI) handleRequestSecurity(args []string) error {
	if len(args) == 0 {
		fmt.Println("request security:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["security"].Children))
		return nil
	}
	switch args[0] {
	case "ipsec":
		if len(args) < 3 || args[1] != "sa" || args[2] != "clear" {
			fmt.Println("request security ipsec sa:")
			writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["security"].Children["ipsec"].Children["sa"].Children))
			return nil
		}
		// #5647: `ipsec sa clear` terminates EVERY IPsec SA
		// (TerminateAllSAs). Reject a scoped-looking suffix such as
		// `... sa clear 42` / `... sa clear tunnel gw-a` BEFORE the mutation
		// instead of silently dropping the selector and tearing down all SAs.
		if len(args) > 3 {
			return rejectScopedClear("request security ipsec sa clear",
				"terminates every IPsec SA", args[3:])
		}
		if c.ipsec == nil {
			return fmt.Errorf("IPsec manager not available")
		}
		count, err := c.ipsec.TerminateAllSAs()
		if err != nil {
			return err
		}
		fmt.Printf("Cleared %d IPsec SA(s)\n", count)
		return nil
	case "dynamic-address":
		return c.handleRequestSecurityDynamicAddress(args[1:])
	case "wireguard":
		return c.handleRequestSecurityWireguard(args[1:])
	case "policies":
		return c.handleRequestSecurityPolicies(args[1:])
	default:
		return fmt.Errorf("unknown request security target: %s", args[0])
	}
}

func (c *CLI) handleRequestSecurityDynamicAddress(args []string) error {
	const usage = "usage: request security dynamic-address acknowledge-shrink <feed> candidate-id <id> candidate-hash <sha256> baseline-hash <sha256> old-count <count> new-count <count> reason <reason...>"
	if len(args) == 0 || args[0] != "acknowledge-shrink" {
		fmt.Println("request security dynamic-address:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["security"].Children["dynamic-address"].Children))
		return nil
	}
	if len(args) < 14 || args[2] != "candidate-id" || args[4] != "candidate-hash" ||
		args[6] != "baseline-hash" || args[8] != "old-count" || args[10] != "new-count" || args[12] != "reason" {
		return fmt.Errorf("%s", usage)
	}
	feed := args[1]
	if feed == "" || strings.TrimSpace(feed) != feed {
		return fmt.Errorf("%s: feed name is required", usage)
	}
	for i := range args[3] {
		if args[3][i] < '0' || args[3][i] > '9' {
			return fmt.Errorf("%s: candidate ID must be a positive uint64", usage)
		}
	}
	candidateID, err := strconv.ParseUint(args[3], 10, 64)
	if err != nil || candidateID == 0 {
		return fmt.Errorf("%s: candidate ID must be a positive uint64", usage)
	}
	candidateHash := args[5]
	if !validShrinkCandidateHash(candidateHash) {
		return fmt.Errorf("%s: candidate hash must be a 64-character lowercase SHA-256 hex value", usage)
	}
	baselineHash := args[7]
	if !validShrinkCandidateHash(baselineHash) {
		return fmt.Errorf("%s: baseline hash must be a 64-character lowercase SHA-256 hex value", usage)
	}
	oldCountValue, err := strconv.ParseUint(args[9], 10, 32)
	if err != nil || oldCountValue == 0 {
		return fmt.Errorf("%s: old count must be a positive uint32", usage)
	}
	newCountValue, err := strconv.ParseUint(args[11], 10, 32)
	if err != nil {
		return fmt.Errorf("%s: new count must be a uint32", usage)
	}
	oldCount, newCount := int(oldCountValue), int(newCountValue)
	reason := strings.TrimSpace(strings.Join(args[13:], " "))
	if reason == "" {
		return fmt.Errorf("%s: reason is required", usage)
	}
	if len(reason) > 512 {
		return fmt.Errorf("%s: reason exceeds 512 bytes", usage)
	}
	if c.feedsFn == nil || c.feedsAckFn == nil || c.store == nil {
		return fmt.Errorf("dynamic-address feed acknowledgement unavailable")
	}
	info, exists := c.feedsFn()[feed]
	if !exists {
		return fmt.Errorf("dynamic-address feed %q not found", feed)
	}
	if !info.ShrinkRefused {
		return fmt.Errorf("dynamic-address feed %q has no current refused shrink", feed)
	}
	if info.ShrinkRefusalID != candidateID ||
		info.ShrinkCandidateHash != candidateHash ||
		info.ShrinkBaselineHash != baselineHash ||
		info.ShrinkCandidateOldCount != oldCount ||
		info.ShrinkCandidateNewCount != newCount {
		return fmt.Errorf("dynamic-address feed %q refusal candidate tuple is stale", feed)
	}
	actor := c.journalPrincipal()
	if err := c.feedsAckFn(feed, candidateID, candidateHash, baselineHash, oldCount, newCount, actor, reason); err != nil {
		return fmt.Errorf("dynamic-address feed %q shrink acknowledgement rejected: %w", feed, err)
	}
	c.store.LogSystemActionAs(
		fmt.Sprintf("dynamic-address-shrink-ack feed=%q candidate_id=%d candidate_sha256=%q baseline_sha256=%q old_count=%d new_count=%d reason=%q", feed, candidateID, candidateHash, baselineHash, oldCount, newCount, reason),
		actor,
	)
	fmt.Printf("Acknowledged refused shrink candidate %d for dynamic-address feed %q\n", candidateID, feed)
	return nil
}

func validShrinkCandidateHash(candidateHash string) bool {
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
// (fable-167 C-1c, #4314): a static analysis of the configured policy set
// that reports shadowed / redundant rules. Junos `request security policies
// check` validates the compiled policy DB; xpf runs a conservative
// name-set-containment pass over config.ZonePairPolicies (no dataplane call —
// this is a config lint). It never mutates config.
func (c *CLI) handleRequestSecurityPolicies(args []string) error {
	if len(args) == 0 || args[0] != "check" {
		fmt.Println("request security policies:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["security"].Children["policies"].Children))
		return nil
	}
	// #8597 K47: the ANALYSIS and its RENDERING both live in pkg/policymatch
	// now, because the remote `cli` serves this verb through a gRPC ShowText
	// topic that runs the same two functions. Two surfaces printing the same
	// command must not each own a copy of the header line.
	fmt.Print(policymatch.RenderPolicyCheck(c.store.ActiveConfig()))
	return nil
}

// handleRequestSecurityWireguard implements `request security wireguard
// generate-private-key` (#1434 Increment 1): a stateless utility that
// prints a fresh WireGuard key pair for the operator to paste into
// config. Junos `request` semantics — it does NOT mutate config and
// needs no dataplane (pure-Go X25519 keygen). Mirrors `wg genkey` /
// `wg pubkey` output in WireGuard-canonical base64.
func (c *CLI) handleRequestSecurityWireguard(args []string) error {
	if len(args) == 0 || args[0] != "generate-private-key" {
		fmt.Println("request security wireguard:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(operationalTree["request"].Children["security"].Children["wireguard"].Children))
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
