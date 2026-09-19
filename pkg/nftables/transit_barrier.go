package nftables

import (
	"errors"
	"fmt"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

// TransitBarrierTableName is the table installed on BOTH the inet and bridge
// families while the dataplane is unarmed or armed (#7191/#10302).
const TransitBarrierTableName = "xpf_transit_barrier"

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
	AllowedMarks  []ForwardFenceMark
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
// barrier family. It is idempotent: an existing table is replaced in the same
// transaction, so a re-assert on the apply tail cannot accumulate chains.
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

func emitTransitFencePinhole(p *nlPlan, spec ForwardFenceSpec) {
	if len(spec.AllowedIfnames) > 0 {
		p.rule().iifname(spec.AllowedIfnames).emit(verdictAccept()...)
	}
	for _, marked := range spec.AllowedMarks {
		if marked.Ifname == "" {
			p.fail(errors.New("marked transit pinhole has an empty ingress interface"))
			return
		}
		if marked.Mask == 0 {
			p.fail(fmt.Errorf("marked transit pinhole %q has a zero mark mask", marked.Ifname))
			return
		}
		p.rule().
			iifname([]string{marked.Ifname}).
			mark(marked.Mark, marked.Mask).
			emit(verdictAccept()...)
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
