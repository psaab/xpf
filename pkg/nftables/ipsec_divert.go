package nftables

import (
	"errors"
	"fmt"
	"sort"

	gnft "github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// IpsecDivertTableName is the S3 capture table. It is deliberately separate
// from xpf_transit_barrier: §2.3 of the r6 plan requires fence reasserts and
// divert generation changes to own disjoint tables.
const IpsecDivertTableName = "xpf_ipsec_divert"

// IpsecQuarantineTableName is the temporary and steady-state D1b deny table.
// It is separate from the divert table so a guard can be ACKed before any
// replacement/removal of the current capture generation.
const IpsecQuarantineTableName = "xpf_ipsec_quarantine_guard"

// IpsecDivertPriority is strictly before the shipped filter-priority fence
// (r6-plan §2.2/§2.3). Keeping this as one constant prevents an inet/bridge
// priority drift from weakening the coexistence proof.
const IpsecDivertPriority gnft.ChainPriority = -175

// IpsecQuarantinePriority is before the divert priority. A quarantine guard
// therefore remains authoritative while a divert generation is replaced.
const IpsecQuarantinePriority gnft.ChainPriority = -200

// IpsecQuarantineReason is the closed D1b staging-reason set. The values are
// intentionally local to this package: they are metadata identity, while the
// corresponding P-MECH deny taxonomy is E3/E27/E2/E21.
type IpsecQuarantineReason uint8

const (
	IpsecQuarantineReasonUnknown IpsecQuarantineReason = iota
	IpsecQuarantineReasonIFIDUnderivable
	IpsecQuarantineReasonLinkLookup
	IpsecQuarantineReasonQueueOpen
	IpsecQuarantineReasonOwnerContested
	IpsecQuarantineReasonDomainOverlap
)

// Short aliases keep call sites readable and make the closed set explicit to
// package consumers without exposing the underlying numeric representation.
const (
	QuarantineReasonUnknown         = IpsecQuarantineReasonUnknown
	QuarantineReasonIFIDUnderivable = IpsecQuarantineReasonIFIDUnderivable
	QuarantineReasonLinkLookup      = IpsecQuarantineReasonLinkLookup
	QuarantineReasonQueueOpen       = IpsecQuarantineReasonQueueOpen
	QuarantineReasonOwnerContested  = IpsecQuarantineReasonOwnerContested
	QuarantineReasonDomainOverlap   = IpsecQuarantineReasonDomainOverlap
)

// IpsecQuarantineReasonMask is a bit set over the five closed reasons. The
// high bit is reserved for an unknown/raw reason and is always retained when
// an input contains an unknown bit or reason.
type IpsecQuarantineReasonMask uint32

const (
	IpsecQuarantineMaskIFIDUnderivable IpsecQuarantineReasonMask = 1 << iota
	IpsecQuarantineMaskLinkLookup
	IpsecQuarantineMaskQueueOpen
	IpsecQuarantineMaskOwnerContested
	IpsecQuarantineMaskDomainOverlap
)

const IpsecQuarantineMaskUnknown IpsecQuarantineReasonMask = 1 << 31
const ipsecQuarantineMaskUnknown = IpsecQuarantineMaskUnknown
const ipsecQuarantineKnownMask = IpsecQuarantineMaskIFIDUnderivable |
	IpsecQuarantineMaskLinkLookup |
	IpsecQuarantineMaskQueueOpen |
	IpsecQuarantineMaskOwnerContested |
	IpsecQuarantineMaskDomainOverlap

func (r IpsecQuarantineReason) String() string {
	switch r {
	case IpsecQuarantineReasonIFIDUnderivable:
		return "IFID_UNDERIVABLE"
	case IpsecQuarantineReasonLinkLookup:
		return "LINK_LOOKUP"
	case IpsecQuarantineReasonQueueOpen:
		return "QUEUE_OPEN"
	case IpsecQuarantineReasonOwnerContested:
		return "OWNER_CONTESTED"
	case IpsecQuarantineReasonDomainOverlap:
		return "DOMAIN_OVERLAP"
	default:
		return "UNKNOWN"
	}
}

func ipsecQuarantineReasonMask(reason IpsecQuarantineReason) IpsecQuarantineReasonMask {
	switch reason {
	case IpsecQuarantineReasonIFIDUnderivable:
		return IpsecQuarantineMaskIFIDUnderivable
	case IpsecQuarantineReasonLinkLookup:
		return IpsecQuarantineMaskLinkLookup
	case IpsecQuarantineReasonQueueOpen:
		return IpsecQuarantineMaskQueueOpen
	case IpsecQuarantineReasonOwnerContested:
		return IpsecQuarantineMaskOwnerContested
	case IpsecQuarantineReasonDomainOverlap:
		return IpsecQuarantineMaskDomainOverlap
	default:
		return ipsecQuarantineMaskUnknown
	}
}

func ipsecQuarantineReasonForMask(mask IpsecQuarantineReasonMask) IpsecQuarantineReason {
	// Fixed D1b precedence: DOMAIN_OVERLAP > OWNER_CONTESTED > QUEUE_OPEN >
	// LINK_LOOKUP > IFID_UNDERIVABLE. Unknown is the final closed outcome.
	switch {
	case mask&IpsecQuarantineMaskDomainOverlap != 0:
		return IpsecQuarantineReasonDomainOverlap
	case mask&IpsecQuarantineMaskOwnerContested != 0:
		return IpsecQuarantineReasonOwnerContested
	case mask&IpsecQuarantineMaskQueueOpen != 0:
		return IpsecQuarantineReasonQueueOpen
	case mask&IpsecQuarantineMaskLinkLookup != 0:
		return IpsecQuarantineReasonLinkLookup
	case mask&IpsecQuarantineMaskIFIDUnderivable != 0:
		return IpsecQuarantineReasonIFIDUnderivable
	default:
		return IpsecQuarantineReasonUnknown
	}
}

// normalizeIpsecQuarantineSpec closes unknown inputs. It never returns an
// admission-capable spec once quarantine metadata is present. Raw unknown
// bits remain in QuarantineRawMask for diagnostics and durable witnesses.
func normalizeIpsecQuarantineSpec(spec IpsecDivertSpec) IpsecDivertSpec {
	rawMask := spec.QuarantineReasonMask | spec.QuarantineRawMask
	rawReason := spec.QuarantineRawReason
	if rawReason == IpsecQuarantineReasonUnknown &&
		spec.QuarantinePrimaryReason > IpsecQuarantineReasonDomainOverlap {
		rawReason = spec.QuarantinePrimaryReason
	}
	requested := spec.QuarantineAll || rawMask != 0 || rawReason != IpsecQuarantineReasonUnknown ||
		spec.QuarantinePrimaryReason != IpsecQuarantineReasonUnknown || len(spec.CandidateIfindices) != 0
	if !requested {
		return spec
	}
	spec.QuarantineAll = true
	spec.InetForward = nil
	spec.InetInput = nil
	spec.BridgeForward = nil
	spec.BridgeInput = nil
	spec.QuarantineRawReason = rawReason
	spec.QuarantineRawMask = rawMask &^ ipsecQuarantineKnownMask
	spec.QuarantineReasonMask = rawMask & ipsecQuarantineKnownMask
	if spec.QuarantinePrimaryReason > IpsecQuarantineReasonDomainOverlap {
		spec.QuarantineReasonMask |= ipsecQuarantineMaskUnknown
	}
	if spec.QuarantineReasonMask == 0 && spec.QuarantineRawMask == 0 {
		if spec.QuarantinePrimaryReason != IpsecQuarantineReasonUnknown &&
			spec.QuarantinePrimaryReason <= IpsecQuarantineReasonDomainOverlap {
			spec.QuarantineReasonMask = ipsecQuarantineReasonMask(spec.QuarantinePrimaryReason)
		} else {
			spec.QuarantineReasonMask = ipsecQuarantineMaskUnknown
		}
	}
	if spec.QuarantineRawMask != 0 || spec.QuarantineRawReason != IpsecQuarantineReasonUnknown {
		spec.QuarantineReasonMask |= ipsecQuarantineMaskUnknown
	}
	spec.QuarantinePrimaryReason = ipsecQuarantineReasonForMask(spec.QuarantineReasonMask)
	seen := make(map[uint32]struct{}, len(spec.CandidateIfindices))
	candidates := spec.CandidateIfindices[:0]
	for _, ifindex := range spec.CandidateIfindices {
		if ifindex == 0 {
			spec.QuarantineRawMask |= ipsecQuarantineMaskUnknown
			spec.QuarantineReasonMask |= ipsecQuarantineMaskUnknown
			continue
		}
		if _, ok := seen[ifindex]; ok {
			continue
		}
		seen[ifindex] = struct{}{}
		candidates = append(candidates, ifindex)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i] < candidates[j] })
	spec.CandidateIfindices = candidates
	return spec
}

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
	InetForward          []IpsecDivertRule
	InetInput            []IpsecDivertRule
	BridgeForward        []IpsecDivertRule
	BridgeInput          []IpsecDivertRule
	QuarantineAll        bool
	QuarantineGeneration uint64
	// RunID identifies the daemon incarnation that authored this nftables
	// mutation. It is sourced from the durable D1b identity allocator and is
	// intentionally distinct from QuarantineGeneration, which is the logical
	// queue/config generation used by the capture actor and Rust dataplane.
	RunID string
	// InstallSequence is a durable operation number. It advances for each
	// install/remove mutation and must not be treated as a replacement for
	// QuarantineGeneration.
	InstallSequence uint64
	// LabelSchema identifies the metadata witness layout.
	LabelSchema string
	// IdentityLockPath names the same durable lock used for allocator updates.
	// It is internal coordination metadata and is never emitted on wire.
	IdentityLockPath        string
	QuarantineReasonMask    IpsecQuarantineReasonMask
	QuarantinePrimaryReason IpsecQuarantineReason
	// QuarantineRawReason preserves an unknown primary enum value without
	// allowing it to select an admission path.
	QuarantineRawReason IpsecQuarantineReason
	// QuarantineRawMask preserves unknown mask bits verbatim (zero when the
	// request was already closed). Normalized mask | raw describes the input.
	QuarantineRawMask  IpsecQuarantineReasonMask
	CandidateIfindices []uint32
}

// InstallIpsecDivert installs xpf_ipsec_divert in both families. A
// QuarantineAll request first installs and verifies a higher-priority,
// two-family DROP guard, then replaces the divert table under that guard and
// removes the guard only after a successful readback. If any later phase
// fails, the guard is intentionally retained as the sole deny authority.
func (in *netlinkInstaller) InstallIpsecDivert(spec IpsecDivertSpec) error {
	if spec.IdentityLockPath != "" {
		path := spec.IdentityLockPath
		spec.IdentityLockPath = ""
		return withIpsecDivertIdentityLock9506(path, func() error {
			return in.InstallIpsecDivert(spec)
		})
	}
	spec = normalizeIpsecQuarantineSpec(spec)
	if err := validateIpsecDivertSpec(spec); err != nil {
		return err
	}
	if spec.QuarantineAll {
		return in.installIpsecQuarantine(spec)
	}
	quarantined, err := in.ipsecQuarantineState()
	if err != nil {
		return fmt.Errorf("ipsec quarantine state: %w", err)
	}
	if quarantined {
		return in.installNormalUnderQuarantineGuard(spec)
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
		inetErr := in.installIpsecDivertFamily(gnft.TableFamilyINet, spec.InetForward, spec.InetInput, spec)
		bridgeErr := &transitBarrierBridgeUnsupportedError{err: err}
		if inetErr != nil {
			return errors.Join(fmt.Errorf("inet: %w", inetErr), fmt.Errorf("bridge: %w", bridgeErr))
		}
		return fmt.Errorf("bridge: %w", bridgeErr)
	}
	return in.installIpsecDivertAtomic(spec)
}

func (in *netlinkInstaller) ipsecQuarantineState() (bool, error) {
	c, err := in.newConn()
	if err != nil {
		return false, err
	}
	found := false
	for _, family := range []gnft.TableFamily{gnft.TableFamilyINet, gnft.TableFamilyBridge} {
		for _, tableName := range []string{IpsecDivertTableName, IpsecQuarantineTableName} {
			exists, err := tableExistsInFamily(c, family, tableName)
			if err != nil {
				return false, err
			}
			if !exists {
				continue
			}
			if tableName == IpsecQuarantineTableName {
				found = true
				continue
			}
			chains, err := c.ListChainsOfTableFamily(family)
			if err != nil {
				return false, err
			}
			for _, chain := range chains {
				if chain != nil && chain.Table != nil && chain.Table.Name == IpsecDivertTableName &&
					(chain.Name == "forward" || chain.Name == "input") &&
					chain.Policy != nil && *chain.Policy == gnft.ChainPolicyDrop {
					found = true
				}
			}
		}
	}
	return found, nil
}

func (in *netlinkInstaller) ipsecTablePresent(tableName string) (bool, error) {
	c, err := in.newConn()
	if err != nil {
		return false, err
	}
	for _, family := range []gnft.TableFamily{gnft.TableFamilyINet, gnft.TableFamilyBridge} {
		exists, err := tableExistsInFamily(c, family, tableName)
		if err != nil {
			return false, err
		}
		if exists {
			return true, nil
		}
	}
	return false, nil
}

func (in *netlinkInstaller) ipsecTableBothFamiliesPresent(tableName string) (bool, error) {
	c, err := in.newConn()
	if err != nil {
		return false, err
	}
	for _, family := range []gnft.TableFamily{gnft.TableFamilyINet, gnft.TableFamilyBridge} {
		exists, err := tableExistsInFamily(c, family, tableName)
		if err != nil {
			return false, err
		}
		if !exists {
			return false, nil
		}
	}
	return true, nil
}

func (in *netlinkInstaller) installNormalUnderQuarantineGuard(spec IpsecDivertSpec) error {
	// A failed prior transition may have left the guard active; only install
	// it when it is absent in either family. The normal replacement occurs
	// while a two-family DROP authority remains live.
	guardPresent, err := in.ipsecTableBothFamiliesPresent(IpsecQuarantineTableName)
	if err != nil {
		return err
	}
	if !guardPresent {
		guard := IpsecDivertSpec{
			QuarantineAll:        true,
			QuarantineGeneration: spec.QuarantineGeneration,
			RunID:                spec.RunID,
			InstallSequence:      spec.InstallSequence,
			LabelSchema:          spec.LabelSchema,
			IdentityLockPath:     spec.IdentityLockPath,
		}
		if err := in.installIpsecQuarantineTableAtomic(normalizeIpsecQuarantineSpec(guard), IpsecQuarantineTableName, IpsecQuarantinePriority); err != nil {
			return fmt.Errorf("quarantine recovery guard install: %w", err)
		}
		if err := in.verifyIpsecQuarantineTable(IpsecQuarantineTableName, true); err != nil {
			return fmt.Errorf("quarantine recovery guard readback: %w", err)
		}
	}
	if err := in.installIpsecDivertAtomic(spec); err != nil {
		return fmt.Errorf("quarantine recovery divert replacement: %w", err)
	}
	if err := in.verifyIpsecDivertAcceptTable(); err != nil {
		return fmt.Errorf("quarantine recovery divert readback: %w", err)
	}
	if err := in.removeIpsecQuarantineTable(); err != nil {
		return fmt.Errorf("quarantine recovery guard removal: %w", err)
	}
	return nil
}

func (in *netlinkInstaller) verifyIpsecDivertAcceptTable() error {
	c, err := in.newConn()
	if err != nil {
		return err
	}
	for _, family := range []gnft.TableFamily{gnft.TableFamilyINet, gnft.TableFamilyBridge} {
		exists, err := tableExistsInFamily(c, family, IpsecDivertTableName)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("%s %s table missing after normal replacement", familyName(family), IpsecDivertTableName)
		}
		chains, err := c.ListChainsOfTableFamily(family)
		if err != nil {
			return err
		}
		found := map[string]bool{"forward": false, "input": false}
		for _, chain := range chains {
			if chain == nil || chain.Table == nil || chain.Table.Name != IpsecDivertTableName ||
				(chain.Name != "forward" && chain.Name != "input") {
				continue
			}
			if chain.Policy == nil || *chain.Policy != gnft.ChainPolicyAccept {
				return fmt.Errorf("%s normal divert chain %q is not ACCEPT", familyName(family), chain.Name)
			}
			found[chain.Name] = true
		}
		if !found["forward"] || !found["input"] {
			return fmt.Errorf("%s normal divert forward/input chains missing", familyName(family))
		}
	}
	return nil
}

func (in *netlinkInstaller) requireIpsecBridgeFamily() error {
	probe, err := in.newConn()
	if err != nil {
		return fmt.Errorf("quarantine bridge capability probe: %w", err)
	}
	if _, err := probe.ListTablesOfFamily(gnft.TableFamilyBridge); err != nil &&
		!errors.Is(err, unix.ENOENT) {
		if transitBarrierFamilyUnsupported(err) {
			return fmt.Errorf("quarantine requires bridge nf_tables support: %w", &transitBarrierBridgeUnsupportedError{err: err})
		}
		return fmt.Errorf("quarantine bridge capability probe: %w", err)
	}
	return nil
}

// InstallIpsecQuarantineGuard installs and verifies only the two-family
// deny-first guard. It intentionally has no removal counterpart here: callers
// may retain it as the sole authority after any later transition failure.
func (in *netlinkInstaller) InstallIpsecQuarantineGuard(spec IpsecDivertSpec) error {
	if spec.IdentityLockPath != "" {
		path := spec.IdentityLockPath
		spec.IdentityLockPath = ""
		return withIpsecDivertIdentityLock9506(path, func() error {
			return in.InstallIpsecQuarantineGuard(spec)
		})
	}
	spec.QuarantineAll = true
	spec = normalizeIpsecQuarantineSpec(spec)
	if err := in.requireIpsecBridgeFamily(); err != nil {
		return err
	}
	if err := in.installIpsecQuarantineTableAtomic(spec, IpsecQuarantineTableName, IpsecQuarantinePriority); err != nil {
		return fmt.Errorf("quarantine guard install: %w", err)
	}
	if err := in.verifyIpsecQuarantineTable(IpsecQuarantineTableName, true); err != nil {
		return fmt.Errorf("quarantine guard readback: %w", err)
	}
	return nil
}

// InstallIpsecDivertWithDrain is the guarded transition seam used by the
// daemon. The callback runs only after both quarantine guard families have
// ACKed/read back; a callback or replacement failure deliberately retains the
// guard and never reuses the old generation.
func (in *netlinkInstaller) InstallIpsecDivertWithDrain(spec IpsecDivertSpec, drain func() error) error {
	if spec.IdentityLockPath != "" {
		path := spec.IdentityLockPath
		spec.IdentityLockPath = ""
		return withIpsecDivertIdentityLock9506(path, func() error {
			return in.InstallIpsecDivertWithDrain(spec, drain)
		})
	}
	spec = normalizeIpsecQuarantineSpec(spec)
	if err := validateIpsecDivertSpec(spec); err != nil {
		return err
	}
	if err := in.requireIpsecBridgeFamily(); err != nil {
		return err
	}
	if spec.QuarantineAll {
		return in.installIpsecQuarantineWithDrain(spec, drain)
	}
	guard := IpsecDivertSpec{
		QuarantineAll:        true,
		QuarantineGeneration: spec.QuarantineGeneration,
		RunID:                spec.RunID,
		InstallSequence:      spec.InstallSequence,
		IdentityLockPath:     spec.IdentityLockPath,
		LabelSchema:          spec.LabelSchema,
	}
	guardPresent, err := in.ipsecTableBothFamiliesPresent(IpsecQuarantineTableName)
	if err != nil {
		return err
	}
	if !guardPresent {
		if err := in.installIpsecQuarantineTableAtomic(normalizeIpsecQuarantineSpec(guard), IpsecQuarantineTableName, IpsecQuarantinePriority); err != nil {
			return fmt.Errorf("quarantine recovery guard install: %w", err)
		}
		if err := in.verifyIpsecQuarantineTable(IpsecQuarantineTableName, true); err != nil {
			return fmt.Errorf("quarantine recovery guard readback: %w", err)
		}
	}
	if drain != nil {
		if err := drain(); err != nil {
			return fmt.Errorf("quarantine recovery drain: %w", err)
		}
	}
	if err := in.installIpsecDivertAtomic(spec); err != nil {
		return fmt.Errorf("quarantine recovery divert replacement: %w", err)
	}
	if err := in.verifyIpsecDivertAcceptTable(); err != nil {
		return fmt.Errorf("quarantine recovery divert readback: %w", err)
	}
	if err := in.removeIpsecQuarantineTable(); err != nil {
		return fmt.Errorf("quarantine recovery guard removal: %w", err)
	}
	return nil
}

func (in *netlinkInstaller) installIpsecQuarantine(spec IpsecDivertSpec) error {
	return in.installIpsecQuarantineWithDrain(spec, nil)
}

func (in *netlinkInstaller) installIpsecQuarantineWithDrain(spec IpsecDivertSpec, drain func() error) error {
	if err := in.requireIpsecBridgeFamily(); err != nil {
		return err
	}
	if err := in.installIpsecQuarantineTableAtomic(spec, IpsecQuarantineTableName, IpsecQuarantinePriority); err != nil {
		return fmt.Errorf("quarantine guard install: %w", err)
	}
	if err := in.verifyIpsecQuarantineTable(IpsecQuarantineTableName, true); err != nil {
		return fmt.Errorf("quarantine guard readback: %w", err)
	}
	if drain != nil {
		if err := drain(); err != nil {
			return fmt.Errorf("quarantine drain: %w", err)
		}
	}
	// The guard is active before this replacement. Keep it installed on every
	// failure so an old ACCEPT/queue path can never become authoritative.
	if err := in.installIpsecQuarantineTableAtomic(spec, IpsecDivertTableName, IpsecDivertPriority); err != nil {
		return fmt.Errorf("quarantine divert replacement: %w", err)
	}
	if err := in.verifyIpsecQuarantineTable(IpsecDivertTableName, true); err != nil {
		return fmt.Errorf("quarantine divert readback: %w", err)
	}
	if err := in.removeIpsecQuarantineTable(); err != nil {
		return fmt.Errorf("quarantine guard removal: %w", err)
	}
	return nil
}

// RemoveIpsecDivert removes the divert and any retained quarantine guard from
// both families. It is idempotent; a genuine failure remains visible because
// a stale queue or deny rule is an unknown capture posture.
func (in *netlinkInstaller) RemoveIpsecDivert() error {
	c, err := in.newConn()
	if err != nil {
		return fmt.Errorf("nftables conn: %w", err)
	}
	for _, tableName := range []string{IpsecDivertTableName, IpsecQuarantineTableName} {
		for _, family := range []gnft.TableFamily{gnft.TableFamilyINet, gnft.TableFamilyBridge} {
			exists, listErr := tableExistsInFamily(c, family, tableName)
			if listErr != nil {
				return fmt.Errorf("%s: %w", familyName(family), listErr)
			}
			if exists {
				c.DelTable(&gnft.Table{Family: family, Name: tableName})
			}
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables remove %s: %w", IpsecDivertTableName, err)
	}
	return nil
}

func validateIpsecDivertSpec(spec IpsecDivertSpec) error {
	spec = normalizeIpsecQuarantineSpec(spec)
	if spec.QuarantineAll {
		return nil
	}
	total := len(spec.InetForward) + len(spec.InetInput) + len(spec.BridgeForward) + len(spec.BridgeInput)
	if total == 0 {
		return errors.New("ipsec divert: empty non-quarantine generation")
	}
	seen := make(map[uint16]string, total)
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
			if rule.Ifname == "" || rule.Queue == 0 {
				return fmt.Errorf("ipsec divert %s rule has unknown interface or queue", class.name)
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
func ipsecDenyChain(tbl *gnft.Table, name string, hook *gnft.ChainHook, priority gnft.ChainPriority) *gnft.Chain {
	policy := gnft.ChainPolicyDrop
	return &gnft.Chain{
		Name:     name,
		Table:    tbl,
		Type:     gnft.ChainTypeFilter,
		Hooknum:  hook,
		Priority: &priority,
		Policy:   &policy,
	}
}

// ipsecQuarantineCountingOwner names the sole first counting owner. All
// other family/hook chains remain DROP-only so a packet traversing bridge and
// inet (or forward and input) cannot increment the quarantine series twice.
func ipsecQuarantineCountingOwner(family, hook string) bool {
	return family == "inet" && hook == "forward"
}

func emitIpsecQuarantineRules(p *nlPlan, family, hook string, spec IpsecDivertSpec, countingOwner bool) {
	if p == nil || p.err != nil {
		return
	}
	generation := spec.QuarantineGeneration
	for _, ifindex := range spec.CandidateIfindices {
		counter := fmt.Sprintf("xpf_ipsec_quarantine_hits_%s_%s_g%d_if%d", family, hook, generation, ifindex)
		if countingOwner {
			p.counterObj(counter)
		}
		rule := p.rule().add(
			&expr.Meta{Key: expr.MetaKeyIIF, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(ifindex)},
		)
		if countingOwner {
			rule.counterRef(counter)
		}
		rule.emit(&expr.Verdict{Kind: expr.VerdictDrop})
	}
	counter := fmt.Sprintf("xpf_ipsec_quarantine_hits_%s_%s_g%d", family, hook, generation)
	if countingOwner {
		p.counterObj(counter)
		p.rule().counterRef(counter).emit(&expr.Verdict{Kind: expr.VerdictDrop})
	} else {
		// The base-chain DROP remains terminal but deliberately has no
		// counter object: the designated owner accounts this packet.
		p.rule().emit(&expr.Verdict{Kind: expr.VerdictDrop})
	}
}

func ipsecQuarantineMetadata(spec IpsecDivertSpec) []byte {
	return formatIpsecDivertIdentity(spec)
}

func addIpsecQuarantineMetadata(c *gnft.Conn, tbl *gnft.Table, spec IpsecDivertSpec) {
	meta := c.AddChain(&gnft.Chain{
		Name:  fmt.Sprintf("xpf_ipsec_quarantine_meta_g%d_s%d", spec.QuarantineGeneration, spec.InstallSequence),
		Table: tbl,
	})
	c.AddRule(&gnft.Rule{
		Table:    tbl,
		Chain:    meta,
		UserData: ipsecQuarantineMetadata(spec),
		Exprs:    []expr.Any{&expr.Verdict{Kind: expr.VerdictReturn}},
	})
}

func addIpsecDivertMetadata(c *gnft.Conn, tbl *gnft.Table, spec IpsecDivertSpec) {
	meta := c.AddChain(&gnft.Chain{
		Name:  fmt.Sprintf("%s%d", ipsecDivertMetaChainPrefix9506, spec.InstallSequence),
		Table: tbl,
	})
	c.AddRule(&gnft.Rule{
		Table:    tbl,
		Chain:    meta,
		UserData: ipsecQuarantineMetadata(spec),
		Exprs:    []expr.Any{&expr.Verdict{Kind: expr.VerdictReturn}},
	})
}

func (in *netlinkInstaller) installIpsecQuarantineTableAtomic(spec IpsecDivertSpec, tableName string, priority gnft.ChainPriority) error {
	if err := in.checkIpsecDivertNoRollback(spec); err != nil {
		return err
	}
	c, err := in.newConn()
	if err != nil {
		return fmt.Errorf("nftables conn: %w", err)
	}
	families := []struct {
		family         gnft.TableFamily
		name           string
		forward, input *gnft.ChainHook
	}{
		{gnft.TableFamilyINet, "inet", gnft.ChainHookForward, gnft.ChainHookInput},
		{gnft.TableFamilyBridge, "bridge", gnft.ChainHookForward, gnft.ChainHookInput},
	}
	for _, family := range families {
		if err := ensureIpsecPriorityFree(c, family.family, priority, tableName, "quarantine"); err != nil {
			return err
		}
		exists, err := tableExistsInFamily(c, family.family, tableName)
		if err != nil {
			return err
		}
		tbl := &gnft.Table{Family: family.family, Name: tableName}
		if exists {
			c.DelTable(tbl)
		}
		tbl = c.AddTable(tbl)
		forward := c.AddChain(ipsecDenyChain(tbl, "forward", family.forward, priority))
		input := c.AddChain(ipsecDenyChain(tbl, "input", family.input, priority))
		p := &nlPlan{c: c, table: tbl, chain: forward}
		emitIpsecQuarantineRules(p, family.name, "forward", spec, ipsecQuarantineCountingOwner(family.name, "forward"))
		p.chain = input
		emitIpsecQuarantineRules(p, family.name, "input", spec, ipsecQuarantineCountingOwner(family.name, "input"))
		addIpsecQuarantineMetadata(c, tbl, spec)
		if p.err != nil {
			return p.err
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables flush %s: %w", tableName, err)
	}
	return nil
}

func (in *netlinkInstaller) verifyIpsecQuarantineTable(tableName string, wantPresent bool) error {
	c, err := in.newConn()
	if err != nil {
		return fmt.Errorf("nftables readback conn: %w", err)
	}
	priority := IpsecDivertPriority
	if tableName == IpsecQuarantineTableName {
		priority = IpsecQuarantinePriority
	}
	for _, family := range []gnft.TableFamily{gnft.TableFamilyINet, gnft.TableFamilyBridge} {
		exists, err := tableExistsInFamily(c, family, tableName)
		if err != nil {
			return fmt.Errorf("%s %s table readback: %w", familyName(family), tableName, err)
		}
		if !wantPresent {
			if exists {
				return fmt.Errorf("%s %s table remains after removal", familyName(family), tableName)
			}
			continue
		}
		if !exists {
			return fmt.Errorf("%s %s table missing after install", familyName(family), tableName)
		}
		chains, err := c.ListChainsOfTableFamily(family)
		if err != nil {
			return fmt.Errorf("%s %s chains readback: %w", familyName(family), tableName, err)
		}
		found := map[string]bool{"forward": false, "input": false}
		for _, chain := range chains {
			if chain == nil || chain.Table == nil || chain.Table.Name != tableName ||
				(chain.Name != "forward" && chain.Name != "input") {
				continue
			}
			if chain.Priority == nil || *chain.Priority != priority || chain.Policy == nil || *chain.Policy != gnft.ChainPolicyDrop {
				return fmt.Errorf("%s %s chain %q readback is not a DROP chain at priority %d", familyName(family), tableName, chain.Name, priority)
			}
			found[chain.Name] = true
		}
		if !found["forward"] || !found["input"] {
			return fmt.Errorf("%s %s forward/input chains missing after install", familyName(family), tableName)
		}
	}
	return nil
}

func (in *netlinkInstaller) removeIpsecQuarantineTable() error {
	c, err := in.newConn()
	if err != nil {
		return fmt.Errorf("nftables quarantine remove conn: %w", err)
	}
	for _, family := range []gnft.TableFamily{gnft.TableFamilyINet, gnft.TableFamilyBridge} {
		exists, err := tableExistsInFamily(c, family, IpsecQuarantineTableName)
		if err != nil {
			return fmt.Errorf("%s quarantine table: %w", familyName(family), err)
		}
		if exists {
			c.DelTable(&gnft.Table{Family: family, Name: IpsecQuarantineTableName})
		}
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables flush %s: %w", IpsecQuarantineTableName, err)
	}
	if err := in.verifyIpsecQuarantineTable(IpsecQuarantineTableName, false); err != nil {
		return err
	}
	return nil
}

func emitIpsecDivertRules(p *nlPlan, rules []IpsecDivertRule) {
	for _, rule := range rules {
		// No bypass flag is intentional: a listener-death/missing-listener
		// matching packet must not fall through to ACCEPT (§2.2/T12).
		p.rule().iifname([]string{rule.Ifname}).emit(&expr.Queue{Num: rule.Queue, Total: 1})
	}
}

func ensureIpsecPriorityFree(c *gnft.Conn, family gnft.TableFamily, priority gnft.ChainPriority, tableName, label string) error {
	chains, err := c.ListChainsOfTableFamily(family)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("%s list base chains: %w", familyName(family), err)
	}
	for _, chain := range chains {
		if chain == nil || chain.Table == nil || chain.Table.Name == tableName ||
			chain.Hooknum == nil || chain.Priority == nil {
			continue
		}
		if *chain.Priority != priority {
			continue
		}
		if *chain.Hooknum == *gnft.ChainHookForward || *chain.Hooknum == *gnft.ChainHookInput {
			return fmt.Errorf("%s %s chain %q already uses %s priority %d",
				familyName(family), chain.Table.Name, chain.Name, label, priority)
		}
	}
	return nil
}

func ensureIpsecDivertPriorityFree(c *gnft.Conn, family gnft.TableFamily) error {
	return ensureIpsecPriorityFree(c, family, IpsecDivertPriority, IpsecDivertTableName, "divert")
}

func (in *netlinkInstaller) installIpsecDivertAtomic(spec IpsecDivertSpec) error {
	if err := in.checkIpsecDivertNoRollback(spec); err != nil {
		return err
	}
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
		addIpsecDivertMetadata(c, tbl, spec)
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables flush %s: %w", IpsecDivertTableName, err)
	}
	return nil
}

func (in *netlinkInstaller) installIpsecDivertFamily(family gnft.TableFamily, forward, input []IpsecDivertRule, spec IpsecDivertSpec) error {
	if err := in.checkIpsecDivertNoRollback(spec); err != nil {
		return err
	}
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
	addIpsecDivertMetadata(c, tbl, spec)
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables flush %s: %w", IpsecDivertTableName, err)
	}
	return nil
}
