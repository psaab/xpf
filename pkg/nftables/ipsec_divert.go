package nftables

import (
	"errors"
	"fmt"

	gnft "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// IpsecDivertTableName is the S3 capture table. It is deliberately separate
// from xpf_transit_barrier: §2.3 of the r6 plan requires fence reasserts and
// divert generation changes to own disjoint tables.
const IpsecDivertTableName = "xpf_ipsec_divert"

// IpsecDivertPriority is strictly before the shipped filter-priority fence
// (r6-plan §2.2/§2.3). Keeping this as one constant prevents an inet/bridge
// priority drift from weakening the coexistence proof.
const IpsecDivertPriority gnft.ChainPriority = -175

// IpsecDivertRule identifies one ownership-keyed xfrmi capture rule. The
// caller, not this renderer, resolves the admitted SecureTunnel ownership set
// (r6-plan §2.2); lexical st* discovery is intentionally not performed here.
type IpsecDivertRule struct {
	Ifname string
	Queue  uint16
}

// IpsecDivertSpec contains four provenance-specific hook classes. Queue
// numbers must be unique across all four lists: family and hook are part of
// CaptureOrigin and may not alias (§2.2/T12).
type IpsecDivertSpec struct {
	InetForward   []IpsecDivertRule
	InetInput     []IpsecDivertRule
	BridgeForward []IpsecDivertRule
	BridgeInput   []IpsecDivertRule
}

// InstallIpsecDivert installs xpf_ipsec_divert in both families. On a kernel
// with bridge nf_tables support, both family replacements are encoded into
// one cross-family Flush, so a generation cannot become inet-new/bridge-old
// (§2.2/T12). If bridge support is absent, the explicit degraded branch keeps
// an inet-only capture and returns ErrTransitBarrierBridgeUnsupported; callers
// must make no bridge packet-receipt claim.
func (in *netlinkInstaller) InstallIpsecDivert(spec IpsecDivertSpec) error {
	if err := validateIpsecDivertSpec(spec); err != nil {
		return err
	}

	// Probe bridge support separately so a later combined-flush failure can
	// never be misclassified as bridge-only. Once this probe succeeds, every
	// combined batch error is fatal and leaves both prior generations intact.
	probe, err := in.newConn()
	if err != nil {
		return fmt.Errorf("nftables conn: %w", err)
	}
	if _, err := probe.ListTablesOfFamily(gnft.TableFamilyBridge); err != nil &&
		!errors.Is(err, unix.ENOENT) {
		if !transitBarrierFamilyUnsupported(err) {
			return fmt.Errorf("bridge capability probe: %w", err)
		}
		inetErr := in.installIpsecDivertFamily(gnft.TableFamilyINet, spec.InetForward, spec.InetInput)
		bridgeErr := &transitBarrierBridgeUnsupportedError{err: err}
		if inetErr != nil {
			return errors.Join(fmt.Errorf("inet: %w", inetErr), fmt.Errorf("bridge: %w", bridgeErr))
		}
		return fmt.Errorf("bridge: %w", bridgeErr)
	}
	return in.installIpsecDivertAtomic(spec)
}

// RemoveIpsecDivert removes the divert table from both families. It is
// idempotent; a genuine failure remains visible because a stale queue rule is
// an unknown capture posture (§2.2/T12).
func (in *netlinkInstaller) RemoveIpsecDivert() error {
	c, err := in.newConn()
	if err != nil {
		return fmt.Errorf("nftables conn: %w", err)
	}
	for _, family := range []gnft.TableFamily{gnft.TableFamilyINet, gnft.TableFamilyBridge} {
		exists, listErr := tableExistsInFamily(c, family, IpsecDivertTableName)
		if listErr != nil {
			return fmt.Errorf("%s: %w", familyName(family), listErr)
		}
		if exists {
			c.DelTable(&gnft.Table{Family: family, Name: IpsecDivertTableName})
		}
	}
	if err := c.Flush(); err != nil {
		// tableExistsInFamily already normalizes an unavailable bridge family
		// to an absent table. Any Flush error therefore belongs to an encoded
		// removal (normally inet) and must remain visible to the gate.
		return fmt.Errorf("nftables remove %s: %w", IpsecDivertTableName, err)
	}
	return nil
}

func validateIpsecDivertSpec(spec IpsecDivertSpec) error {
	seen := make(map[uint16]string, len(spec.InetForward)+len(spec.InetInput)+len(spec.BridgeForward)+len(spec.BridgeInput))
	classes := []struct {
		name  string
		rules []IpsecDivertRule
	}{
		{"inet-forward", spec.InetForward},
		{"inet-input", spec.InetInput},
		{"bridge-forward", spec.BridgeForward},
		{"bridge-input", spec.BridgeInput},
	}
	for _, class := range classes {
		for _, rule := range class.rules {
			if rule.Ifname == "" {
				return fmt.Errorf("ipsec divert %s rule has empty ingress interface", class.name)
			}
			if prior, ok := seen[rule.Queue]; ok {
				return fmt.Errorf("ipsec divert queue %d is shared by %s and %s; provenance queues must be unique", rule.Queue, prior, class.name)
			}
			seen[rule.Queue] = class.name
		}
	}
	return nil
}
func ipsecDivertChain(tbl *gnft.Table, name string, hook *gnft.ChainHook) *gnft.Chain {
	prio := IpsecDivertPriority
	policy := gnft.ChainPolicyAccept
	return &gnft.Chain{
		Name:     name,
		Table:    tbl,
		Type:     gnft.ChainTypeFilter,
		Hooknum:  hook,
		Priority: &prio,
		Policy:   &policy,
	}
}

func emitIpsecDivertRules(p *nlPlan, rules []IpsecDivertRule) {
	for _, rule := range rules {
		// No bypass flag is intentional: a listener-death/missing-listener
		// matching packet must not fall through to ACCEPT (§2.2/T12).
		p.rule().iifname([]string{rule.Ifname}).emit(&expr.Queue{Num: rule.Queue, Total: 1})
	}
}

func ensureIpsecDivertPriorityFree(c *gnft.Conn, family gnft.TableFamily) error {
	chains, err := c.ListChainsOfTableFamily(family)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("%s list base chains: %w", familyName(family), err)
	}
	for _, chain := range chains {
		if chain == nil || chain.Table == nil || chain.Table.Name == IpsecDivertTableName ||
			chain.Hooknum == nil || chain.Priority == nil {
			continue
		}
		if *chain.Priority != IpsecDivertPriority {
			continue
		}
		if *chain.Hooknum == *gnft.ChainHookForward || *chain.Hooknum == *gnft.ChainHookInput {
			return fmt.Errorf("%s %s chain %q already uses divert priority %d",
				familyName(family), chain.Table.Name, chain.Name, IpsecDivertPriority)
		}
	}
	return nil
}

func (in *netlinkInstaller) installIpsecDivertAtomic(spec IpsecDivertSpec) error {
	c, err := in.newConn()
	if err != nil {
		return fmt.Errorf("nftables conn: %w", err)
	}
	families := []struct {
		family         gnft.TableFamily
		forward, input []IpsecDivertRule
	}{
		{gnft.TableFamilyINet, spec.InetForward, spec.InetInput},
		{gnft.TableFamilyBridge, spec.BridgeForward, spec.BridgeInput},
	}
	for _, family := range families {
		if err := ensureIpsecDivertPriorityFree(c, family.family); err != nil {
			return err
		}
		exists, err := tableExistsInFamily(c, family.family, IpsecDivertTableName)
		if err != nil {
			return err
		}
		tbl := &gnft.Table{Family: family.family, Name: IpsecDivertTableName}
		if exists {
			c.DelTable(tbl)
		}
		tbl = c.AddTable(tbl)
		forward := c.AddChain(ipsecDivertChain(tbl, "forward", gnft.ChainHookForward))
		input := c.AddChain(ipsecDivertChain(tbl, "input", gnft.ChainHookInput))
		p := &nlPlan{c: c, table: tbl, chain: forward}
		emitIpsecDivertRules(p, family.forward)
		p.chain = input
		emitIpsecDivertRules(p, family.input)
		if p.err != nil {
			return p.err
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables flush %s: %w", IpsecDivertTableName, err)
	}
	return nil
}

func (in *netlinkInstaller) installIpsecDivertFamily(family gnft.TableFamily, forward, input []IpsecDivertRule) error {
	c, err := in.newConn()
	if err != nil {
		return fmt.Errorf("nftables conn: %w", err)
	}
	if err := ensureIpsecDivertPriorityFree(c, family); err != nil {
		return err
	}
	exists, err := tableExistsInFamily(c, family, IpsecDivertTableName)
	if err != nil {
		return err
	}
	tbl := &gnft.Table{Family: family, Name: IpsecDivertTableName}
	if exists {
		c.DelTable(tbl)
	}
	tbl = c.AddTable(tbl)
	forwardChain := c.AddChain(ipsecDivertChain(tbl, "forward", gnft.ChainHookForward))
	inputChain := c.AddChain(ipsecDivertChain(tbl, "input", gnft.ChainHookInput))
	p := &nlPlan{c: c, table: tbl, chain: forwardChain}
	emitIpsecDivertRules(p, forward)
	p.chain = inputChain
	emitIpsecDivertRules(p, input)
	if p.err != nil {
		return p.err
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables flush %s: %w", IpsecDivertTableName, err)
	}
	return nil
}
