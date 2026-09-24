package nftables

import (
	"errors"
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// TransitBarrierTableName is the table installed on BOTH the inet and bridge
// families while the dataplane is unarmed or armed (#7191/#10302).
const TransitBarrierTableName = "xpf_transit_barrier"

// TransitFenceDeliveredCounterName is the named counter attached to the
// inet-forward q0 mark-conjunction rule. It is deliberately a named object:
// the daemon reads it back through netlink and treats its packet delta as a
// downstream-of-TUN witness. The object is not a verdict and therefore cannot
// alter the fence's ACCEPT/DROP decision.
const TransitFenceDeliveredCounterName = "xpf_transit_q0_delivered"

// ForwardFenceMark is an ingress-interface/packet-mark conjunction for the
// armed forward fence. A mark is never admitted without its owning interface.
type ForwardFenceMark struct {
	Ifname string
	Mark   uint32
	Mask   uint32
}

// AdjudicatedTransitMark is the skb mark set by the xpf-usp1 ingress queue
// classifier for userspace-adjudicated reinjects. Keep this outside the
// reserved RPM probe range (0x1000 + index).
const AdjudicatedTransitMark uint32 = 0x58465001

const AdjudicatedTransitMarkMask uint32 = 0xffffffff

// ForwardFenceSpec is the provenance-scoped allowlist for the armed forward
// fence. Every other packet reaches the base chain's DROP policy. Names must
// be resolved from runtime-owned XDP links; the xpf-usp1 TUN is admitted only
// through an exact packet-mark conjunction supplied in AllowedMarks.
type ForwardFenceSpec struct {
	AllowedIfnames []string
	AllowedMarks   []ForwardFenceMark
}

// ErrTransitBarrierBridgeUnsupported marks a kernel that does not provide the
// bridge nf_tables family. The inet fence remains useful on that kernel, so
// callers may treat this sentinel as a documented degraded-success condition
// only when it is the sole error from either forward-fence installer.
var ErrTransitBarrierBridgeUnsupported = errors.New("bridge nftables family unsupported")

type transitBarrierBridgeUnsupportedError struct {
	err error
}

func (e *transitBarrierBridgeUnsupportedError) Error() string {
	return fmt.Sprintf("%s: %v", ErrTransitBarrierBridgeUnsupported, e.err)
}

func (e *transitBarrierBridgeUnsupportedError) Unwrap() error {
	return e.err
}

func (e *transitBarrierBridgeUnsupportedError) Is(target error) bool {
	return target == ErrTransitBarrierBridgeUnsupported
}

// IsTransitBarrierBridgeUnsupportedOnly reports whether err is exactly the
// bridge-family unsupported degradation from a forward-fence installer, with
// no inet or other family failure joined alongside it.
func IsTransitBarrierBridgeUnsupportedOnly(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) != 1 {
			return false
		}
		err = children[0]
	}
	for err != nil {
		if err == ErrTransitBarrierBridgeUnsupported {
			return true
		}
		if _, ok := err.(*transitBarrierBridgeUnsupportedError); ok {
			return true
		}
		if _, ok := err.(interface{ Unwrap() []error }); ok {
			return false
		}
		unwrapped, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapped.Unwrap()
	}
	return false
}

func transitBarrierFamilyUnsupported(err error) bool {
	return errors.Is(err, unix.ENOENT) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EAFNOSUPPORT)
}

// #7191/#10302: nftables is the forward-hook half of the transit fence.
//
// The same table is rendered in both the inet and bridge families. While the
// daemon is unarmed, the base chain has an unconditional DROP policy. While it
// is armed, InstallArmedTransitFence adds only the provenance-scoped iifname
// ACCEPT rule(s) supplied by the daemon, then retains that DROP policy. This
// keeps configured-but-unzoned and leave-alone interfaces out of the kernel
// router while preserving only explicitly owned runtime XDP paths and the
// daemon-owned xpf-usp1 delegated TUN residual. xpf-usp0 is LocalDelivery/
// gated-only and is not a FORWARD pinhole; direct route-based IPsec plaintext
// arrives on xfrmi and remains dropped.
//
// WHY BOTH FAMILIES. `ip_forward` does not govern bridged frames at all, and
// this repo creates Linux bridge domains (compiler_iface.go), so an inet
// forward-hook drop alone leaves a bridged topology uncovered. The two
// families are installed and removed independently so a kernel without bridge
// netfilter still gets the inet leg.
//
// FLOWTABLE: plan §6 also calls for a flowtable disable. That leg is a NO-OP
// today and no code is written for it deliberately: xpf creates no flowtable
// anywhere (zero hits for `flowtable` outside prose), so there is nothing to
// flush. TestNoFlowtableIsEverCreated7191 pins that assumption so this
// sentence cannot rot into a false claim.

// transitBarrierFamilies is the family set the forward fence covers. inet
// carries routed transit; bridge carries frames that never traverse the inet
// forward hook at all.
func transitBarrierFamilies() []nftables.TableFamily {
	return []nftables.TableFamily{nftables.TableFamilyINet, nftables.TableFamilyBridge}
}

// InstallTransitBarrier installs an unconditional forward-hook DROP in every
// barrier family. It retains the historical replace-on-call behavior because
// the unarmed fence has no delivered-witness counter; the armed q0 path uses
// the internal canonical live-shape check in installForwardFence.
//
// A per-family failure is returned joined rather than short-circuited: the inet
// leg must still install when a kernel lacks bridge netfilter support. A bridge
// family-unsupported error carries ErrTransitBarrierBridgeUnsupported so a
// caller can report that documented degradation without hiding other failures.
func (in *netlinkInstaller) InstallTransitBarrier() error {
	return in.installForwardFence(ForwardFenceSpec{})
}

// InstallArmedTransitFence installs the armed-state forward fence. The base
// chain remains policy DROP; only the supplied provenance-scoped ingress names
// receive an explicit ACCEPT before that policy. An empty or failed allowlist
// therefore remains fail-closed rather than turning into an accept-all chain.
func (in *netlinkInstaller) InstallArmedTransitFence(spec ForwardFenceSpec) error {
	return in.installForwardFence(spec)
}

func (in *netlinkInstaller) installForwardFence(spec ForwardFenceSpec) error {
	in.forwardFenceMu.Lock()
	defer in.forwardFenceMu.Unlock()

	// Only the q0 witness-carrying armed shape may skip the old delete/add
	// transaction. Every other fence call keeps the pre-existing behavior.
	if forwardFenceSpecHasWitness(spec) &&
		in.forwardFenceInstalled &&
		forwardFenceSpecsEqual(in.forwardFenceSpec, spec) {
		equal, err := in.forwardFenceLiveEqualLocked(spec)
		if err == nil && equal {
			return nil
		}
		// Fetch errors, malformed/unknown live shapes, and any inequality all
		// fail toward the old behavior: replace the whole fence.
	}
	if !forwardFenceSpecHasWitness(spec) {
		in.forwardFenceInstalled = false
		in.forwardFenceBridgeUnsupported = false
	}
	err := in.installForwardFenceReplace(spec)
	if err == nil || IsTransitBarrierBridgeUnsupportedOnly(err) {
		in.forwardFenceInstalled = true
		in.forwardFenceSpec = cloneForwardFenceSpec(spec)
		in.forwardFenceBridgeUnsupported = IsTransitBarrierBridgeUnsupportedOnly(err)
	} else {
		in.forwardFenceInstalled = false
		in.forwardFenceBridgeUnsupported = false
	}
	return err
}

func (in *netlinkInstaller) installForwardFenceReplace(spec ForwardFenceSpec) error {
	if in.forwardFenceReplaceFn != nil {
		return in.forwardFenceReplaceFn(spec)
	}
	var errs []error
	for _, family := range transitBarrierFamilies() {
		if err := in.installBarrierFamily(family, spec); err != nil {
			if family == nftables.TableFamilyBridge && transitBarrierFamilyUnsupported(err) {
				err = &transitBarrierBridgeUnsupportedError{err: err}
			}
			errs = append(errs, fmt.Errorf("%s: %w", familyName(family), err))
		}
	}
	return errors.Join(errs...)
}

func (in *netlinkInstaller) forwardFenceLiveEqualLocked(spec ForwardFenceSpec) (bool, error) {
	if in.forwardFenceLiveEqualFn != nil {
		return in.forwardFenceLiveEqualFn(spec)
	}
	return in.readForwardFenceLiveEqual(spec)
}

func transitBarrierChain(tbl *nftables.Table) *nftables.Chain {
	prio := *nftables.ChainPriorityFilter
	policy := nftables.ChainPolicyDrop
	return &nftables.Chain{
		Name:     "forward",
		Table:    tbl,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: &prio,
		Policy:   &policy,
	}
}

// bridgeTransitFenceEtherTypes is the fixed link-layer allowlist for the
// bridge-leg unmarked pinhole (#10641, residual of #9888). The userspace XDP
// shim XDP_PASSes single-tag and untagged non-IP ethertypes for local-stack
// delivery; on a bridge-domain member that PASS also hands the frame to the
// kernel bridge, so the fence qualifies the pinhole by ethertype: IP, IPv6,
// and ARP (the explicit L2-control allowlist the bridge needs to function).
// Every other non-IP ethertype falls through to the base-chain DROP. Order is
// load-bearing: emission, desired-shape, and live decode all use it.
var bridgeTransitFenceEtherTypes = []uint16{0x0800, 0x86dd, 0x0806}

// etherType appends an `ether type` equality (link-layer header @12/2) to the
// rule under assembly. The value is wire-order (BigEndian): a host-order flip
// would never match a real frame (the #10410 P0 class), so the golden pins the
// bytes literally. Only the bridge leg uses this; the link-layer header is not
// addressable in the inet family.
func (a *ruleAsm) etherType(ether uint16) *ruleAsm {
	return a.add(
		&expr.Payload{Base: expr.PayloadBaseLLHeader, Offset: 12, Len: 2, DestRegister: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(ether)},
	)
}

func emitTransitFencePinhole(p *nlPlan, spec ForwardFenceSpec) {
	if len(spec.AllowedIfnames) > 0 {
		if p.table.Family == nftables.TableFamilyBridge {
			// #10641: one ACCEPT per allowlisted ethertype, each carrying
			// its own iifname match (and its own anonymous set in the
			// multi-name case — no cross-rule set sharing). The marked TUN
			// rules below stay ether-less: a TUN can never be a bridge port.
			for _, ether := range bridgeTransitFenceEtherTypes {
				p.rule().iifname(spec.AllowedIfnames).etherType(ether).emit(verdictAccept()...)
			}
		} else {
			p.rule().iifname(spec.AllowedIfnames).emit(verdictAccept()...)
		}
	}
	witnessDeclared := false
	for _, marked := range spec.AllowedMarks {
		if marked.Ifname == "" {
			p.fail(errors.New("marked transit pinhole has an empty ingress interface"))
			return
		}
		if marked.Mask == 0 {
			p.fail(fmt.Errorf("marked transit pinhole %q has a zero mark mask", marked.Ifname))
			return
		}
		counter := ""
		if p.table.Family == nftables.TableFamilyINet && isTransitFenceWitnessMark(marked) {
			counter = TransitFenceDeliveredCounterName
			if !witnessDeclared {
				p.counterObj(counter)
				witnessDeclared = true
			}
		}
		rule := p.rule().
			iifname([]string{marked.Ifname}).
			mark(marked.Mark, marked.Mask)
		if counter != "" {
			// CounterObj is a non-terminating accounting expression. The
			// ACCEPT remains the final verdict, so this witness is verdict-
			// neutral and cannot widen or narrow the security fence.
			rule.counterRef(counter)
		}
		rule.emit(verdictAccept()...)
	}
}

func (in *netlinkInstaller) installBarrierFamily(family nftables.TableFamily, spec ForwardFenceSpec) error {
	c, err := in.newConn()
	if err != nil {
		return fmt.Errorf("nftables conn: %w", err)
	}
	exists, err := tableExistsInFamily(c, family, TransitBarrierTableName)
	if err != nil {
		return err
	}
	tbl := &nftables.Table{Family: family, Name: TransitBarrierTableName}
	if exists {
		c.DelTable(tbl)
	}
	tbl = c.AddTable(tbl)
	chain := c.AddChain(transitBarrierChain(tbl))

	// An armed fence admits only the supplied XDP_PASS ownership proof. The
	// unarmed spec intentionally has no rules and is the old unconditional
	// policy DROP shape.
	p := &nlPlan{c: c, table: tbl, chain: chain}
	emitTransitFencePinhole(p, spec)
	if p.err != nil {
		return p.err
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables flush %s: %w", TransitBarrierTableName, err)
	}
	return nil
}

// RemoveTransitBarrier removes the barrier from every family. Idempotent:
// absent -> nil. A genuine kernel failure IS returned, because a barrier that
// could not be removed leaves the box transit-closed while armed — the black
// hole this design exists to avoid — and the caller must be able to see it.
func (in *netlinkInstaller) RemoveTransitBarrier() error {
	in.forwardFenceMu.Lock()
	defer in.forwardFenceMu.Unlock()
	in.forwardFenceInstalled = false
	in.forwardFenceBridgeUnsupported = false
	var errs []error
	for _, family := range transitBarrierFamilies() {
		if err := in.removeBarrierFamily(family); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", familyName(family), err))
		}
	}
	return errors.Join(errs...)
}

func (in *netlinkInstaller) removeBarrierFamily(family nftables.TableFamily) error {
	c, err := in.newConn()
	if err != nil {
		return fmt.Errorf("nftables conn: %w", err)
	}
	exists, err := tableExistsInFamily(c, family, TransitBarrierTableName)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	c.DelTable(&nftables.Table{Family: family, Name: TransitBarrierTableName})
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables delete %s: %w", TransitBarrierTableName, err)
	}
	return nil
}

// tableExistsInFamily is the family-aware twin of tableExists, which is pinned
// to inet. A missing family (no bridge netfilter) reads as "absent", not as an
// error, so removal on such a kernel is a clean no-op.
func tableExistsInFamily(c *nftables.Conn, family nftables.TableFamily, name string) (bool, error) {
	tables, err := c.ListTablesOfFamily(family)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EAFNOSUPPORT) {
			return false, nil
		}
		return false, fmt.Errorf("nftables list tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == name {
			return true, nil
		}
	}
	return false, nil
}

func familyName(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyBridge:
		return "bridge"
	default:
		return fmt.Sprintf("family(%d)", f)
	}
}
