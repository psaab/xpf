package nftables

// netlink_installer.go defines the concrete injection interface (#6387 plan
// §12.4) covering EVERY kernel-touching host-inbound / lo0 / fence operation
// that today goes through the exec-`nft` package vars nftApplyPayload /
// nftDeleteTable in pkg/daemon/daemon_nft.go, plus its netlink implementation.
//
// PR-2 only DEFINES + implements + parity-tests this interface. PR-3 wires the
// daemon apply path to it and ports the 14 fail-closed tests onto its single
// failure-injection seam (a fake Installer that returns an error).

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// HostInboundGapTableName is the kernel nftables table for the #5789 additive
// coverage-gap fence (a distinct input-hook base chain at a later priority than
// the main host-inbound table).
const HostInboundGapTableName = "xpf_hostinbound_gap"

// HostInboundPreActivationTableName carries only temporary drops for newly
// activated local addresses. Keeping it separate means replacing it cannot
// erase an existing coverage-gap fence with DHCP or other backstop rules.
const HostInboundPreActivationTableName = "xpf_hostinbound_preactivation"

// Base-chain hook-input priorities, mirroring the pkg/daemon constants
// nftLo0FilterPriority (0) < nftHostInboundPriority (10) <
// nftHostInboundGapPriority (11) < early input barrier (12) <
// nftHostInboundPreActivationPriority (13).
const (
	lo0FilterPriority                = 0
	hostInboundPriority              = 10
	hostInboundGapPriority           = 11
	hostInboundPreActivationPriority = 13
)

type Installer interface {
	// InstallEarlyInputBarrier installs the #10751 pre-networkd host-input
	// barrier, a separate config-free DROP chain removed on daemon apply
	// handoff.
	InstallEarlyInputBarrier() error
	// RemoveEarlyInputBarrier idempotently removes that boot-only input barrier.
	RemoveEarlyInputBarrier() error
	// EarlyInputBarrierPresent reports whether that barrier table is currently
	// installed (kernel readback). The daemon attests presence before the
	// first handoff and gates link activation on it — unit state alone
	// cannot prove the table survived.
	EarlyInputBarrierPresent() (bool, error)
	// InstallEarlyInputBarrierWithLifelineAdmit installs the same barrier
	// table with leading per-member lifeline admits: `iifname {lifelines}
	// accept` plus `meta sdifname {lifelines} accept` (#15286 — bootstrap
	// recovery: data stays closed, each lifeline member stays reachable,
	// including an enslaved member via sdifname, without admitting its VRF
	// master or co-enslaved non-lifeline members; callers pass member names
	// only, never a VRF master). The ordinary handoff removes the table
	// unchanged.
	InstallEarlyInputBarrierWithLifelineAdmit(lifelines []string) error
	// InstallHostInbound installs the real host-inbound table (#3070/#3333).
	InstallHostInbound(spec HostInboundSpec) error
	// VerifyHostInboundOverlay reads back the exact marker and leading DROP
	// rule for a candidate overlay before publication.
	VerifyHostInboundOverlay(overlay HostInputFenceOverlay) error
	// InstallColdBootFence installs the #5644 cold-boot fail-closed fence
	// (the xpf_hostinbound table reduced to mandatory admits + address drops).
	InstallColdBootFence(spec FenceSpec) error
	// InstallLo0ColdBootFence installs the #6476 lo0 cold-boot fail-closed fence:
	// the shared mandatory admits + firewall-local address drops, but not the
	// host-inbound-only stale-reply guard; lo0 must preserve its established-flow
	// admit. It is installed into xpf_lo0 at the lo0 filter priority so a later
	// successful InstallLo0 atomically replaces it.
	InstallLo0ColdBootFence(spec FenceSpec) error
	// InstallGapFence installs the #5789 additive coverage-gap fence.
	InstallGapFence(spec GapFenceSpec) error
	// InstallLo0 installs the lo0 loopback input filter (#3445/#3392) and
	// reports how many kernel rules the spec lowered to. ZERO rules means the
	// installed table is an empty `policy accept` shell that enforces NOTHING —
	// a filter name that resolves to no filter, a filter with no terms, or one
	// whose every term lowers to zero rules (a Junos match-nothing scope). The
	// caller must not record such an install as a real operator filter being
	// loaded (#6529); a bare "the install succeeded" boolean cannot tell the two
	// apart.
	InstallLo0(spec Lo0FilterSpec) (rules int, err error)
	// DeleteTable idempotently removes a table (absent -> nil; a genuine
	// kernel/permission failure -> error, preserving the fail-closed teardown
	// contract #5790).
	DeleteTable(name string) error
	// TableEnforcing reports whether the named inet-family table currently
	// ENFORCES an input hook: the table exists with a type-filter
	// input-hook chain carrying at least one rule. A present-but-empty
	// (flushed shell) table is NOT enforcing — with no input hook it
	// filters nothing. The `ensure` command and the handoff tripwire
	// prove liveness through this instead of bare presence (#10751
	// R6-B/R7-D).
	TableEnforcing(name string) (bool, error)
	// TableDropsInput reports whether the named inet-family table
	// currently DROPS on its input hook: enforcing shape (see above)
	// PLUS at least one rule carrying a DROP verdict. An admits-only
	// table (mandatory accepts, zero DROP — e.g. a zero-drop fence
	// shell, or a stale restore that lost its drops) under the
	// tables' `policy accept` admits everything it does not
	// explicitly match, so presence/shape alone must not attest
	// protection. The `ensure` command proves liveness through this
	// (#10751 R7-A).
	TableDropsInput(name string) (bool, error)
	// inet and bridge families. Queue rules are fail-closed (no bypass).
	InstallIpsecDivert(spec IpsecDivertSpec) error
	// RemoveIpsecDivert removes the S3 capture table from both families.
	RemoveIpsecDivert() error

	// InstallTransitBarrier installs the unarmed forward-hook DROP in both
	// families. It retains replace-on-call behavior because the unarmed fence
	// carries no delivered-witness counter.
	InstallTransitBarrier() error
	// InstallArmedTransitFence ensures the armed forward-hook DROP with its
	// provenance-scoped XDP_PASS pinholes. The q0 witness shape performs an
	// internal canonical live-table comparison and skips delete+add only on
	// exact equality; all other calls retain replace-on-call behavior.
	InstallArmedTransitFence(spec ForwardFenceSpec) error
	// RemoveTransitBarrier removes the barrier from both families.
	// Idempotent; a genuine failure is returned because a table that survives
	// teardown leaves the box transit-closed while armed — the black hole this
	// design exists to avoid.
	RemoveTransitBarrier() error
}

// netlinkInstaller is the production Installer: it renders each ruleset into a
// single google/nftables batch and Flushes it as one nf_tables transaction.
type netlinkInstaller struct {
	// newConn returns a fresh *nftables.Conn. Overridable so tests can bind the
	// installer to a private network namespace (WithNetNSFd).
	newConn func() (*nftables.Conn, error)
	// forwardFenceMu guards the forward-fence install memory below. The memory
	// is consulted and mutated ONLY by the forward-fence installers in
	// transit_barrier.go (InstallTransitBarrier, InstallArmedTransitFence,
	// RemoveTransitBarrier); every other table installer is untouched and
	// keeps its unconditional replace semantics.
	forwardFenceMu sync.Mutex
	// forwardFenceInstalled reports whether this installer process has
	// successfully installed forwardFenceSpec and has not removed it since.
	// A repeat install of a byte-equal spec skips the kernel delete+recreate
	// ONLY when the live tables are verified present (see installForwardFence);
	// any doubt reinstalls, so the zero value is fail-closed.
	forwardFenceInstalled bool
	forwardFenceSpec      ForwardFenceSpec
	// forwardFenceBridgeUnsupported records that the memorised install
	// succeeded on inet while the bridge family reported unsupported (the
	// documented degraded-success shape). The live check then waives the
	// bridge table, so a bridge-less kernel does not churn inet every tick.
	forwardFenceBridgeUnsupported bool
	// These two seams are nil in production and let unit cells exercise the
	// skip/reinstall decision without manufacturing netlink dump messages.
	forwardFenceLiveEqualFn func(ForwardFenceSpec) (bool, error)
	forwardFenceReplaceFn   func(ForwardFenceSpec) error
}

// NewNetlinkInstaller returns an Installer that talks to the host's default
// network namespace via netlink (no `nft` binary).
func NewNetlinkInstaller() Installer {
	return &netlinkInstaller{newConn: newBoundedNetlinkConn}
}

// newNetlinkInstallerConn constructs a netlinkInstaller with a custom conn
// factory (used by the kernel-gated parity tests to target a private netns).
func newNetlinkInstallerConn(newConn func() (*nftables.Conn, error)) *netlinkInstaller {
	return &netlinkInstaller{newConn: newConn}
}

func (in *netlinkInstaller) InstallHostInbound(spec HostInboundSpec) error {
	_, err := in.replaceTable(HostInboundTableName, hostInboundPriority, func(p *nlPlan) {
		buildHostInboundNetlink(p, spec)
	})
	return err
}

// counter proves all authority fields and canonical masters were committed;
// for a nonempty set the first input rule is decoded and compared to the exact
// master set plus the marker object and DROP verdict.
func (in *netlinkInstaller) VerifyHostInboundOverlay(overlay HostInputFenceOverlay) error {
	overlay = CanonicalHostInputFenceOverlay(overlay)
	c, err := in.newConn()
	if err != nil {
		return fmt.Errorf("nftables conn: %w", err)
	}
	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: HostInboundTableName}
	objs, err := c.GetNamedObjects(tbl)
	if err != nil {
		return fmt.Errorf("read host overlay objects: %w", err)
	}
	marker := HostInputFenceOverlayCounterName(overlay)
	found := false
	for _, obj := range objs {
		named, ok := obj.(*nftables.NamedObj)
		if ok && named.Name == marker {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("host overlay marker %q absent", marker)
	}
	if len(overlay.MasterSet) == 0 && len(overlay.MasterSlavePairs) == 0 {
		return nil
	}
	sets, err := c.GetSets(tbl)
	if err != nil {
		return fmt.Errorf("read host overlay sets: %w", err)
	}
	setNames := map[string][]string{}
	for _, set := range sets {
		if set.KeyType.Name != "ifname" {
			continue
		}
		elements, err := c.GetSetElements(set)
		if err != nil {
			return fmt.Errorf("read host overlay set %q: %w", set.Name, err)
		}
		for _, element := range elements {
			setNames[set.Name] = append(setNames[set.Name], string(bytes.TrimRight(element.Key, "\x00")))
		}
	}
	rules, err := c.GetRules(tbl, &nftables.Chain{Name: "input", Table: tbl})
	if err != nil {
		return fmt.Errorf("read host overlay rules: %w", err)
	}
	if len(rules) == 0 {
		return fmt.Errorf("host overlay leading rule absent")
	}
	// Collect every leading overlay drop: paired slave-scoped rules first,
	// then the bare-master rule. All must carry the marker + DROP, the union
	// of iifname scopes must equal MasterSet plus pair masters, and the union
	// of sdifname scopes must equal the paired slaves (#14974).
	wantMasters := append([]string(nil), overlay.MasterSet...)
	var wantSlaves []string
	for _, pair := range overlay.MasterSlavePairs {
		wantMasters = append(wantMasters, pair.Master)
		wantSlaves = append(wantSlaves, pair.Slave)
	}
	var gotMasters, gotSlaves []string
	overlayRules := 0
	for _, rule := range rules {
		masters, slaves, markerSeen, dropSeen := decodeHostOverlayRule(rule, setNames, marker)
		if !markerSeen {
			break
		}
		if !dropSeen {
			return fmt.Errorf("host overlay rule lacks DROP verdict")
		}
		overlayRules++
		gotMasters = append(gotMasters, masters...)
		gotSlaves = append(gotSlaves, slaves...)
	}
	if overlayRules == 0 {
		return fmt.Errorf("host overlay leading rule absent")
	}
	sort.Strings(gotMasters)
	sort.Strings(gotSlaves)
	sort.Strings(wantMasters)
	sort.Strings(wantSlaves)
	wantMasters = canonicalIfNames(wantMasters)
	wantSlaves = canonicalIfNames(wantSlaves)
	gotMasters = canonicalIfNames(gotMasters)
	gotSlaves = canonicalIfNames(gotSlaves)
	if strings.Join(gotMasters, "\x00") != strings.Join(wantMasters, "\x00") ||
		strings.Join(gotSlaves, "\x00") != strings.Join(wantSlaves, "\x00") {
		return fmt.Errorf("host overlay readback mismatch: got masters=%v slaves=%v want masters=%v slaves=%v", gotMasters, gotSlaves, wantMasters, wantSlaves)
	}
	return nil
}

func decodeHostOverlayRule(rule *nftables.Rule, setNames map[string][]string, marker string) (masters, slaves []string, markerSeen, dropSeen bool) {
	pending := 0 // 1=iifname, 2=sdifname
	var reg uint32
	for _, anyExpr := range rule.Exprs {
		switch x := anyExpr.(type) {
		case *expr.Meta:
			pending = 0
			if x.Key == expr.MetaKeyIIFNAME {
				pending = 1
			} else if x.Key == expr.MetaKey(metaKeySDIFNAME) {
				pending = 2
			}
			reg = x.Register
		case *expr.Cmp:
			if pending != 0 && x.Register == reg {
				name := string(bytes.TrimRight(x.Data, "\x00"))
				if pending == 1 {
					masters = append(masters, name)
				} else {
					slaves = append(slaves, name)
				}
			}
			pending = 0
		case *expr.Lookup:
			if pending != 0 && x.SourceRegister == reg {
				if pending == 1 {
					masters = append(masters, setNames[x.SetName]...)
				} else {
					slaves = append(slaves, setNames[x.SetName]...)
				}
			}
			pending = 0
		case *expr.Objref:
			markerSeen = markerSeen || x.Name == marker
		case *expr.Verdict:
			dropSeen = dropSeen || x.Kind == expr.VerdictDrop
			pending = 0
		default:
			pending = 0
		}
	}
	return masters, slaves, markerSeen, dropSeen
}

func (in *netlinkInstaller) InstallColdBootFence(spec FenceSpec) error {
	_, err := in.replaceTable(HostInboundTableName, hostInboundPriority, func(p *nlPlan) {
		buildHostInboundFenceNetlink(p, spec)
	})
	return err
}

// InstallLo0ColdBootFence installs the #6476 lo0 cold-boot fence: the shared
// mandatory admits and firewall-local address DROPs, without the host-inbound-
// specific stale-reply guard. It preserves established-flow admits for lo0's
// distinct RE-protection policy, in xpf_lo0 at the lo0 filter priority.
func (in *netlinkInstaller) InstallLo0ColdBootFence(spec FenceSpec) error {
	_, err := in.replaceTable(Lo0TableName, lo0FilterPriority, func(p *nlPlan) {
		buildLo0FenceNetlink(p, spec)
	})
	return err
}

func (in *netlinkInstaller) InstallGapFence(spec GapFenceSpec) error {
	tableName, priority := HostInboundGapTableName, hostInboundGapPriority
	if spec.PreActivation {
		tableName, priority = HostInboundPreActivationTableName, hostInboundPreActivationPriority
	}
	_, err := in.replaceTable(tableName, nftables.ChainPriority(priority), func(p *nlPlan) {
		buildHostInboundGapFenceNetlink(p, spec)
	})
	return err
}

// InstallLo0 returns the rendered rule count alongside the error so the caller
// can tell a real operator filter from an empty `policy accept` shell (#6529).
// The count comes from the ACTUAL build — nlPlan.rules, populated as each rule
// is batched — so it can never drift from the lowering the way a second,
// daemon-side "does this spec enforce anything?" predicate would.
func (in *netlinkInstaller) InstallLo0(spec Lo0FilterSpec) (int, error) {
	return in.replaceTable(Lo0TableName, lo0FilterPriority, func(p *nlPlan) {
		buildLo0FilterNetlink(p, spec)
	})
}

// replaceTable queues the atomic delete-then-recreate of one inet table and its
// chains/rules in a SINGLE Flush. Each ruleset is its own transaction;
// xpf_lo0 / xpf_hostinbound / xpf_hostinbound_gap are never cross-coupled.
//
// A Flush error does not prove rollback: the kernel may have committed the
// atomic batch while its ACK was lost. In that case report success only after
// kernel readback matches the complete plan; otherwise preserve the Flush error.
func (in *netlinkInstaller) replaceTable(name string, priority nftables.ChainPriority, build func(p *nlPlan)) (int, error) {
	c, err := in.newConn()
	if err != nil {
		return 0, fmt.Errorf("nftables conn: %w", err)
	}
	exists, err := tableExists(c, name)
	if err != nil {
		return 0, err
	}
	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: name}
	if exists {
		c.DelTable(tbl)
	}
	tbl = c.AddTable(tbl)
	prio := priority
	policy := nftables.ChainPolicyAccept
	chain := c.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    tbl,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: &prio,
		Policy:   &policy,
	})
	p := &nlPlan{c: c, table: tbl, chain: chain, chains: []*nftables.Chain{chain}}
	build(p)
	if p.err != nil {
		return 0, p.err
	}
	if err := c.Flush(); err != nil {
		flushErr := fmt.Errorf("nftables flush %s: %w", name, err)
		installed, readbackErr := in.tableMatchesPlan(name, p)
		if readbackErr != nil {
			return 0, errors.Join(flushErr, fmt.Errorf("nftables readback %s: %w", name, readbackErr))
		}
		if installed {
			return len(p.rules), nil
		}
		return 0, flushErr
	}
	return len(p.rules), nil
}

func (in *netlinkInstaller) DeleteTable(name string) error {
	c, err := in.newConn()
	if err != nil {
		return fmt.Errorf("nftables conn: %w", err)
	}
	exists, err := tableExists(c, name)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	c.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: name})
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables delete table %s: %w", name, err)
	}
	return nil
}

// TableEnforcing reports whether the named inet-family table currently
// enforces an input hook (see the interface contract).
func (in *netlinkInstaller) TableEnforcing(name string) (bool, error) {
	c, err := in.newConn()
	if err != nil {
		return false, fmt.Errorf("nftables conn: %w", err)
	}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, fmt.Errorf("nftables list tables: %w", err)
	}
	var tbl *nftables.Table
	for _, candidate := range tables {
		if candidate != nil && candidate.Name == name {
			tbl = candidate
			break
		}
	}
	if tbl == nil {
		return false, nil
	}
	chain, err := c.ListChain(tbl, "input")
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, fmt.Errorf("nftables read %s input chain: %w", name, err)
	}
	if chain.Hooknum == nil || *chain.Hooknum != *nftables.ChainHookInput || chain.Type != nftables.ChainTypeFilter {
		return false, nil
	}
	rules, err := c.GetRules(tbl, chain)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, fmt.Errorf("nftables read %s input rules: %w", name, err)
	}
	return len(rules) > 0, nil
}

// TableDropsInput reports whether the named inet-family table currently
// carries a DROP verdict on its input hook (see the interface contract).
// Residual: only the base input chain is scanned — a program-only table
// (DROPs solely inside junos-host subchains) reads false, so a manual
// `ensure` over-installs the barrier fail-closed and the next apply heals
// it. Accepted: subchain-aware verdict proof is out of scope.
func (in *netlinkInstaller) TableDropsInput(name string) (bool, error) {
	c, err := in.newConn()
	if err != nil {
		return false, fmt.Errorf("nftables conn: %w", err)
	}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, fmt.Errorf("nftables list tables: %w", err)
	}
	var tbl *nftables.Table
	for _, candidate := range tables {
		if candidate != nil && candidate.Name == name {
			tbl = candidate
			break
		}
	}
	if tbl == nil {
		return false, nil
	}
	chain, err := c.ListChain(tbl, "input")
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, fmt.Errorf("nftables read %s input chain: %w", name, err)
	}
	if chain.Hooknum == nil || *chain.Hooknum != *nftables.ChainHookInput || chain.Type != nftables.ChainTypeFilter {
		return false, nil
	}
	rules, err := c.GetRules(tbl, chain)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, fmt.Errorf("nftables read %s input rules: %w", name, err)
	}
	for _, rule := range rules {
		for _, anyExpr := range rule.Exprs {
			if verdict, ok := anyExpr.(*expr.Verdict); ok && verdict.Kind == expr.VerdictDrop {
				return true, nil
			}
		}
	}
	return false, nil
}
func tableExists(c *nftables.Conn, name string) (bool, error) {
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, fmt.Errorf("nftables list tables: %w", err)
	}
	for _, t := range tables {
		if t != nil && t.Name == name {
			return true, nil
		}
	}
	return false, nil
}
