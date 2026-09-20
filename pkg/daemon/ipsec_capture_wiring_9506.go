package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/nfqueue"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ipsecCaptureDivertSpec converts one complete four-class queue generation into
// the nftables ruleset shape. The caller must provide all four provenance
// classes for every tunnel; an incomplete generation is refused rather than
// installing a partial inet/bridge or forward/input diversion. An empty
// generation is itself a closed quarantine request.
func ipsecCaptureDivertSpec(handles []ipsecQueueHandle) (xnft.IpsecDivertSpec, error) {
	var spec xnft.IpsecDivertSpec
	if len(handles) == 0 {
		spec.QuarantineAll = true
		spec.QuarantinePrimaryReason = xnft.IpsecQuarantineReasonUnknown
		return spec, nil
	}
	unknown := func() (xnft.IpsecDivertSpec, error) {
		return xnft.IpsecDivertSpec{
			QuarantineAll:       true,
			QuarantineRawReason: xnft.IpsecQuarantineReason(0xff),
		}, nil
	}
	seen := make(map[uint16]struct{}, len(handles))
	for _, handle := range handles {
		if handle.Number == 0 || handle.Epoch == 0 || handle.Key.Owner == "" || handle.Key.STN == "" || handle.Key.Ifindex <= 0 {
			return unknown()
		}
		if _, exists := seen[handle.Number]; exists {
			return unknown()
		}
		seen[handle.Number] = struct{}{}
		ifname, ifID := config.XFRMIfNameAndID(handle.Key.STN)
		if ifID == 0 || ifname == "" {
			return xnft.IpsecDivertSpec{
				QuarantineAll:           true,
				QuarantineReasonMask:    xnft.IpsecQuarantineMaskIFIDUnderivable,
				QuarantinePrimaryReason: xnft.IpsecQuarantineReasonIFIDUnderivable,
			}, nil
		}
		rule := xnft.IpsecDivertRule{Ifname: ifname, Queue: handle.Number}
		switch handle.Key.Family {
		case ipsecFamilyInet:
			switch handle.Key.Hook {
			case ipsecHookForward:
				spec.InetForward = append(spec.InetForward, rule)
			case ipsecHookInput:
				spec.InetInput = append(spec.InetInput, rule)
			default:
				return unknown()
			}
		case ipsecFamilyBridge:
			switch handle.Key.Hook {
			case ipsecHookForward:
				spec.BridgeForward = append(spec.BridgeForward, rule)
			case ipsecHookInput:
				spec.BridgeInput = append(spec.BridgeInput, rule)
			default:
				return unknown()
			}
		default:
			return unknown()
		}
	}
	if len(spec.InetForward) == 0 || len(spec.InetInput) == 0 || len(spec.BridgeForward) == 0 || len(spec.BridgeInput) == 0 {
		return spec, fmt.Errorf("ipsec capture: incomplete four-class queue generation")
	}
	return spec, nil
}

func ipsecCaptureDivertSpecWithQuarantine(handles []ipsecQueueHandle, quarantine xnft.IpsecDivertSpec) (xnft.IpsecDivertSpec, error) {
	if quarantine.QuarantineAll || quarantine.QuarantineReasonMask != 0 ||
		quarantine.QuarantinePrimaryReason != xnft.IpsecQuarantineReasonUnknown ||
		quarantine.QuarantineRawReason != xnft.IpsecQuarantineReasonUnknown ||
		quarantine.QuarantineRawMask != 0 || len(quarantine.CandidateIfindices) != 0 {
		quarantine.QuarantineAll = true
		return quarantine, nil
	}
	return ipsecCaptureDivertSpec(handles)
}

// for one generation. A fresh registry is required on every rotation so a
// recycled queue number cannot reinterpret an old held packet as the new
// tunnel/hook/family owner.
func ipsecCaptureRegisterOrigins(registry *nfqueue.OriginRegistry, handles []ipsecQueueHandle) error {
	if registry == nil {
		return fmt.Errorf("ipsec capture: nil origin registry")
	}
	for _, handle := range handles {
		if handle.Number == 0 || handle.Key.Ifindex <= 0 || handle.Key.Owner == "" || handle.Key.STN == "" {
			return fmt.Errorf("ipsec capture: invalid origin handle %+v", handle)
		}
		family := nfqueue.CaptureFamilyInet
		if handle.Key.Family == ipsecFamilyBridge {
			family = nfqueue.CaptureFamilyBridge
		} else if handle.Key.Family != ipsecFamilyInet {
			return fmt.Errorf("ipsec capture: unknown origin family %d", handle.Key.Family)
		}
		hook := nfqueue.CaptureHookForward
		if handle.Key.Hook == ipsecHookInput {
			hook = nfqueue.CaptureHookInput
		} else if handle.Key.Hook != ipsecHookForward {
			return fmt.Errorf("ipsec capture: unknown origin hook %d", handle.Key.Hook)
		}
		if err := registry.Register(handle.Number, nfqueue.CaptureOrigin{
			Family:       family,
			Hook:         hook,
			Owner:        handle.Key.Owner,
			STN:          handle.Key.STN,
			OwnedIfindex: uint32(handle.Key.Ifindex),
		}); err != nil {
			return err
		}
	}
	return nil
}

// ipsecCaptureQueueEpochSnapshot returns deterministic wire order for a
// generation. Queue number is not sufficient authority identity; each row
// carries the allocator epoch that Rust checks before q0 admission.
func ipsecCaptureQueueEpochSnapshot(handles []ipsecQueueHandle) []dpuserspace.QueueEpochSnapshot {
	rows := make([]dpuserspace.QueueEpochSnapshot, 0, len(handles))
	for _, handle := range handles {
		if handle.Number == 0 || handle.Epoch == 0 {
			continue
		}
		rows = append(rows, dpuserspace.QueueEpochSnapshot{Queue: handle.Number, Epoch: handle.Epoch})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Queue < rows[j].Queue })
	return rows
}

type pmechTunnelZone struct {
	ifID    uint32
	ifindex uint32
	zoneID  uint16
	reason  nfqueue.ZoneReason
}

// pmechZoneSnapshot is immutable after publication. The live-ifindex map is
// frozen per generation; rotations publish a new value and mark the old one
// stale before any old descriptor can be interpreted by a new generation.
type pmechZoneSnapshot struct {
	generation    uint64
	fibGeneration uint32
	current       atomic.Bool
	tunnels       map[string]pmechTunnelZone
	queueEpochs   map[uint16]uint64
}

func (s *pmechZoneSnapshot) ResolveSTN(stn string) nfqueue.ZoneResolution {
	if s == nil {
		return nfqueue.ZoneResolution{Reason: nfqueue.ZoneReasonEvaluatorUnavailable}
	}
	if !s.Current() {
		return nfqueue.ZoneResolution{Reason: nfqueue.ZoneReasonStaleGeneration}
	}
	tunnel, ok := s.tunnels[stn]
	if !ok {
		return nfqueue.ZoneResolution{Reason: nfqueue.ZoneReasonUnknownGeneration}
	}
	return nfqueue.ZoneResolution{ZoneID: tunnel.zoneID, IfID: tunnel.ifID, Reason: tunnel.reason}
}

func (s *pmechZoneSnapshot) Generations() (uint64, uint32) {
	if s == nil {
		return 0, 0
	}
	return s.generation, s.fibGeneration
}

func (s *pmechZoneSnapshot) QueueEpoch(queue uint16) uint64 {
	if s == nil {
		return 0
	}
	return s.queueEpochs[queue]
}

func (s *pmechZoneSnapshot) Current() bool {
	return s != nil && s.current.Load()
}

func (s *pmechZoneSnapshot) ValidateOrigin(origin nfqueue.CaptureOrigin) nfqueue.ZoneReason {
	if s == nil || !s.Current() {
		return nfqueue.ZoneReasonStaleGeneration
	}
	tunnel, ok := s.tunnels[origin.STN]
	if !ok || tunnel.ifID == 0 {
		return nfqueue.ZoneReasonUnknownGeneration
	}
	if tunnel.ifindex == 0 || tunnel.ifindex != origin.OwnedIfindex {
		return nfqueue.ZoneReasonStaleGeneration
	}
	if tunnel.reason != nfqueue.ZoneReasonZoned {
		return tunnel.reason
	}
	return nfqueue.ZoneReasonZoned
}

// buildPMechZoneSnapshot performs the D1 ownership-aware if_id join. It
// intentionally takes already-staged handles: no packet-path netlink lookup
// is possible, and the resulting live-ifindex table is immutable.
func buildPMechZoneSnapshot(cfg *config.Config, handles []ipsecQueueHandle, generation uint64, fibGeneration uint32) *pmechZoneSnapshot {
	snapshot := &pmechZoneSnapshot{
		generation: generation, fibGeneration: fibGeneration,
		tunnels:     make(map[string]pmechTunnelZone),
		queueEpochs: make(map[uint16]uint64),
	}
	snapshot.current.Store(true)
	if cfg == nil {
		return snapshot
	}
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	quarantined := config.QuarantinedZoneNames(zoneNames)
	seenBind := make(map[uint32]map[string]struct{})
	vpnNames := make([]string, 0, len(cfg.Security.IPsec.VPNs))
	for name := range cfg.Security.IPsec.VPNs {
		vpnNames = append(vpnNames, name)
	}
	sort.Strings(vpnNames)
	for _, vpnName := range vpnNames {
		vpn := cfg.Security.IPsec.VPNs[vpnName]
		if vpn == nil || vpn.BindInterface == "" {
			continue
		}
		_, ifID := config.XFRMIfNameAndID(vpn.BindInterface)
		if ifID == 0 {
			continue
		}
		binds := seenBind[ifID]
		if binds == nil {
			binds = make(map[string]struct{})
			seenBind[ifID] = binds
		}
		binds[vpnName] = struct{}{}
		owned := uint16(0)
		claimSeen := false
		ambiguous := false
		for _, zoneName := range zoneNames {
			zone := cfg.Security.Zones[zoneName]
			if zone == nil {
				continue
			}
			for _, ref := range zone.Interfaces {
				_, refID := config.XFRMIfNameAndID(ref)
				if refID != ifID || !config.BindInterfaceOwnsRef(vpn.BindInterface, ref) {
					continue
				}
				claimSeen = true
				if _, blocked := quarantined[zoneName]; blocked {
					ambiguous = true
					continue
				}
				zoneID := config.StableZoneID(zoneName)
				if owned != 0 && owned != zoneID {
					ambiguous = true
					continue
				}
				owned = zoneID
			}
		}
		reason := nfqueue.ZoneReasonUnzoned
		zoneID := owned
		if ambiguous {
			zoneID = 0
			reason = nfqueue.ZoneReasonAmbiguous
		} else if claimSeen && owned != 0 {
			reason = nfqueue.ZoneReasonZoned
		}
		if prior, ok := snapshot.tunnels[vpn.BindInterface]; ok && prior.ifID == ifID {
			reason = nfqueue.ZoneReasonAmbiguous
			zoneID = 0
		}
		snapshot.tunnels[vpn.BindInterface] = pmechTunnelZone{ifID: ifID, zoneID: zoneID, reason: reason}
	}
	for _, handle := range handles {
		snapshot.queueEpochs[handle.Number] = handle.Epoch
		tunnel, ok := snapshot.tunnels[handle.Key.STN]
		if !ok {
			continue
		}
		if tunnel.ifindex != 0 && tunnel.ifindex != uint32(handle.Key.Ifindex) {
			tunnel.reason = nfqueue.ZoneReasonStaleGeneration
			tunnel.zoneID = 0
		}
		tunnel.ifindex = uint32(handle.Key.Ifindex)
		snapshot.tunnels[handle.Key.STN] = tunnel
	}
	for ifID, binds := range seenBind {
		if len(binds) < 2 {
			continue
		}
		for stn, tunnel := range snapshot.tunnels {
			if tunnel.ifID == ifID {
				tunnel.reason = nfqueue.ZoneReasonAmbiguous
				tunnel.zoneID = 0
				snapshot.tunnels[stn] = tunnel
			}
		}
	}
	return snapshot
}

type ipsecReinjectSubmitter interface {
	nfqueue.ReinjectSubmitter
	AnnounceReinject(runID string, generation, permitEpoch uint64, permitOpen bool, epochs []nfqueue.ReinjectQueueEpoch) error
	Close() error
}

type ipsecCaptureRuntime struct {
	supervisor   *ipsecSupervisor
	handles      []ipsecQueueHandle
	queues       []IpsecCaptureQueue
	registry     *nfqueue.OriginRegistry
	actor        *IpsecCapturePipeline
	submitter    ipsecReinjectSubmitter
	spec         xnft.IpsecDivertSpec
	runID        string
	zoneSnapshot *pmechZoneSnapshot

	authorityMu         sync.Mutex
	announced           bool
	announcedRunID      string
	announcedGeneration uint64
	announcedPermit     uint64
	announcedOpen       bool
	announcedRows       []nfqueue.ReinjectQueueEpoch
}

func (r *ipsecCaptureRuntime) sameKeys(keys []ipsecQueueKey) bool {
	if r == nil || len(r.handles) != len(keys) {
		return false
	}
	for i := range keys {
		current := r.handles[i].Key
		current.Generation = 0
		next := keys[i]
		next.Generation = 0
		if current != next {
			return false
		}
	}
	return true
}

func (r *ipsecCaptureRuntime) epochSnapshot() (uint64, []dpuserspace.QueueEpochSnapshot) {
	if r == nil || r.supervisor == nil {
		return 0, nil
	}
	permit := r.supervisor.loadPermit()
	if permit == nil || permit.state != ipsecPermitOpen {
		return 0, nil
	}
	return permit.permitEpoch, ipsecCaptureQueueEpochSnapshot(r.handles)
}

func (r *ipsecCaptureRuntime) authoritySnapshot() (string, uint64, uint64, bool, []nfqueue.ReinjectQueueEpoch) {
	if r == nil || r.supervisor == nil {
		return "", 0, 0, false, nil
	}
	permit := r.supervisor.loadPermit()
	if permit == nil {
		return r.runID, r.generation(), 0, false, nil
	}
	runID := r.runID
	generation := r.generation()
	if r.actor != nil {
		status := r.actor.Status()
		if status.RunID != "" {
			runID = status.RunID
		}
		if status.Generation != 0 {
			generation = status.Generation
		}
	}
	rows := ipsecCaptureQueueEpochSnapshot(r.handles)
	wireRows := make([]nfqueue.ReinjectQueueEpoch, 0, len(rows))
	for _, row := range rows {
		wireRows = append(wireRows, nfqueue.ReinjectQueueEpoch{Queue: row.Queue, Epoch: row.Epoch})
	}
	return runID, generation, permit.permitEpoch, permit.state == ipsecPermitOpen, wireRows
}

func (r *ipsecCaptureRuntime) generation() uint64 {
	if r == nil || len(r.handles) == 0 {
		return 0
	}
	return r.handles[0].Key.Generation
}

func (r *ipsecCaptureRuntime) announceAuthorityLocked() error {
	if r == nil || r.submitter == nil {
		return nil
	}
	runID, generation, permitEpoch, permitOpen, wireRows := r.authoritySnapshot()
	if r.announced && r.announcedRunID == runID && r.announcedGeneration == generation &&
		r.announcedPermit == permitEpoch && r.announcedOpen == permitOpen &&
		sameReinjectQueueEpochs(r.announcedRows, wireRows) {
		return nil
	}
	if err := r.submitter.AnnounceReinject(runID, generation, permitEpoch, permitOpen, wireRows); err != nil {
		r.announced = false
		return err
	}
	r.announced = true
	r.announcedRunID = runID
	r.announcedGeneration = generation
	r.announcedPermit = permitEpoch
	r.announcedOpen = permitOpen
	r.announcedRows = append(r.announcedRows[:0], wireRows...)
	return nil
}

func sameReinjectQueueEpochs(a, b []nfqueue.ReinjectQueueEpoch) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (r *ipsecCaptureRuntime) close() error {
	if r == nil {
		return nil
	}
	if r.zoneSnapshot != nil {
		r.zoneSnapshot.current.Store(false)
	}
	var firstErr error
	wasActive := false
	if r.actor != nil {
		wasActive = r.actor.Status().Active
		if err := r.actor.Stop(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// An actor that was only staged has not started its receive loops, so Stop
	// intentionally leaves queue ownership untouched; close those descriptors
	// here as the rollback/failed-apply path. An active actor closed its queues
	// during Stop and must not be closed a second time.
	if !wasActive {
		for _, captureQueue := range r.queues {
			if captureQueue.Queue != nil {
				if err := captureQueue.Queue.Close(); err != nil && firstErr == nil {
					firstErr = err
				}
			}
		}
	}
	if r.submitter != nil {
		if err := r.submitter.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if r.supervisor != nil {
		for _, handle := range r.handles {
			if err := r.supervisor.retireQueue(handle, true, true); err != nil &&
				!errors.Is(err, errIpsecQueueStale) && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

var ipsecCaptureLinkByName = netlink.LinkByName
var ipsecCaptureOpenQueue = openIpsecCaptureQueue

type ipsecCaptureQueuePlan struct {
	Keys         []ipsecQueueKey
	Quarantine   xnft.IpsecDivertSpec
	HasVPNConfig bool
}

func (p *ipsecCaptureQueuePlan) addQuarantine(reason xnft.IpsecQuarantineReason) {
	if p == nil {
		return
	}
	p.Quarantine.QuarantineAll = true
	switch reason {
	case xnft.IpsecQuarantineReasonIFIDUnderivable:
		p.Quarantine.QuarantineReasonMask |= xnft.IpsecQuarantineMaskIFIDUnderivable
	case xnft.IpsecQuarantineReasonLinkLookup:
		p.Quarantine.QuarantineReasonMask |= xnft.IpsecQuarantineMaskLinkLookup
	case xnft.IpsecQuarantineReasonQueueOpen:
		p.Quarantine.QuarantineReasonMask |= xnft.IpsecQuarantineMaskQueueOpen
	case xnft.IpsecQuarantineReasonOwnerContested:
		p.Quarantine.QuarantineReasonMask |= xnft.IpsecQuarantineMaskOwnerContested
	case xnft.IpsecQuarantineReasonDomainOverlap:
		p.Quarantine.QuarantineReasonMask |= xnft.IpsecQuarantineMaskDomainOverlap
	default:
		p.Quarantine.QuarantineRawReason = reason
	}
}

func (p *ipsecCaptureQueuePlan) finalize(generation uint64) {
	if p == nil {
		return
	}
	p.Quarantine.QuarantineGeneration = generation
	if !p.Quarantine.QuarantineAll {
		return
	}
	mask := p.Quarantine.QuarantineReasonMask
	switch {
	case mask&xnft.IpsecQuarantineMaskDomainOverlap != 0:
		p.Quarantine.QuarantinePrimaryReason = xnft.IpsecQuarantineReasonDomainOverlap
	case mask&xnft.IpsecQuarantineMaskOwnerContested != 0:
		p.Quarantine.QuarantinePrimaryReason = xnft.IpsecQuarantineReasonOwnerContested
	case mask&xnft.IpsecQuarantineMaskQueueOpen != 0:
		p.Quarantine.QuarantinePrimaryReason = xnft.IpsecQuarantineReasonQueueOpen
	case mask&xnft.IpsecQuarantineMaskLinkLookup != 0:
		p.Quarantine.QuarantinePrimaryReason = xnft.IpsecQuarantineReasonLinkLookup
	case mask&xnft.IpsecQuarantineMaskIFIDUnderivable != 0:
		p.Quarantine.QuarantinePrimaryReason = xnft.IpsecQuarantineReasonIFIDUnderivable
	default:
		p.Quarantine.QuarantinePrimaryReason = xnft.IpsecQuarantineReasonUnknown
	}
	seen := make(map[uint32]struct{}, len(p.Quarantine.CandidateIfindices))
	candidates := p.Quarantine.CandidateIfindices[:0]
	for _, ifindex := range p.Quarantine.CandidateIfindices {
		if ifindex == 0 {
			continue
		}
		if _, ok := seen[ifindex]; ok {
			continue
		}
		seen[ifindex] = struct{}{}
		candidates = append(candidates, ifindex)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i] < candidates[j] })
	p.Quarantine.CandidateIfindices = candidates
}

func buildIpsecCaptureQueuePlan(cfg *config.Config, generation uint64) (ipsecCaptureQueuePlan, error) {
	var plan ipsecCaptureQueuePlan
	if cfg == nil || generation == 0 {
		return plan, nil
	}
	names := make([]string, 0, len(cfg.Security.IPsec.VPNs))
	for name := range cfg.Security.IPsec.VPNs {
		names = append(names, name)
	}
	sort.Strings(names)
	plan.HasVPNConfig = len(names) != 0
	type validTunnel struct {
		name, bind    string
		ifID, ifindex uint32
	}
	valid := make([]validTunnel, 0, len(names))
	for _, name := range names {
		vpn := cfg.Security.IPsec.VPNs[name]
		if vpn == nil || vpn.BindInterface == "" {
			plan.addQuarantine(xnft.IpsecQuarantineReasonIFIDUnderivable)
			continue
		}
		ifname, ifID := config.XFRMIfNameAndID(vpn.BindInterface)
		if ifID == 0 || ifname == "" {
			plan.addQuarantine(xnft.IpsecQuarantineReasonIFIDUnderivable)
			continue
		}
		link, err := ipsecCaptureLinkByName(ifname)
		if err != nil || link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
			plan.addQuarantine(xnft.IpsecQuarantineReasonLinkLookup)
			continue
		}
		ifindex := uint32(link.Attrs().Index)
		valid = append(valid, validTunnel{name: name, bind: vpn.BindInterface, ifID: ifID, ifindex: ifindex})
		plan.Quarantine.CandidateIfindices = append(plan.Quarantine.CandidateIfindices, ifindex)
	}
	// Every distinct VPN claimant sharing one if_id is contested, including
	// two VPNs that authored the same bind string.
	owners := make(map[uint32]map[string]struct{}, len(valid))
	for _, tunnel := range valid {
		if owners[tunnel.ifID] == nil {
			owners[tunnel.ifID] = make(map[string]struct{})
		}
		owners[tunnel.ifID][tunnel.name] = struct{}{}
	}
	for _, claimants := range owners {
		if len(claimants) > 1 {
			plan.addQuarantine(xnft.IpsecQuarantineReasonOwnerContested)
		}
	}
	for _, tunnel := range valid {
		for _, class := range []struct {
			family ipsecQueueFamily
			hook   ipsecQueueHook
		}{
			{ipsecFamilyInet, ipsecHookForward},
			{ipsecFamilyInet, ipsecHookInput},
			{ipsecFamilyBridge, ipsecHookForward},
			{ipsecFamilyBridge, ipsecHookInput},
		} {
			plan.Keys = append(plan.Keys, ipsecQueueKey{
				Generation: generation,
				Family:     class.family,
				Hook:       class.hook,
				Owner:      tunnel.name,
				STN:        tunnel.bind,
				Ifindex:    int(tunnel.ifindex),
			})
		}
	}
	plan.finalize(generation)
	return plan, nil
}
func ipsecCaptureQueueKeys(cfg *config.Config, generation uint64) ([]ipsecQueueKey, error) {
	plan, err := buildIpsecCaptureQueuePlan(cfg, generation)
	if err != nil {
		return nil, err
	}
	return plan.Keys, nil
}

func openIpsecCaptureQueue(number uint16, family ipsecQueueFamily) (*nfqueue.Queue, error) {
	if family == ipsecFamilyBridge {
		return nfqueue.OpenFamily(number, unix.AF_BRIDGE)
	}
	return nfqueue.Open(number)
}

func ipsecCaptureReinjectSocketPaths(controlSocket string) (string, string) {
	dir := filepath.Dir(controlSocket)
	return filepath.Join(dir, "reinject-submit.sock"), filepath.Join(dir, "reinject-complete.sock")
}

func stagedIpsecQuarantineRuntime(d *Daemon, generation uint64, spec xnft.IpsecDivertSpec) *ipsecCaptureRuntime {
	if spec.QuarantineGeneration == 0 {
		spec.QuarantineGeneration = generation
	}
	runID := spec.RunID
	if runID == "" {
		runID = ipsecCaptureProcessRunID
	}
	return &ipsecCaptureRuntime{
		supervisor: d.ipsecS4,
		spec:       spec,
		runID:      runID,
	}
}

func closeStagedCaptureQueues(queues []IpsecCaptureQueue) {
	for _, captureQueue := range queues {
		if captureQueue.Queue != nil {
			_ = captureQueue.Queue.Close()
		}
	}
}

// stageIpsecCapture allocates, binds, and validates a complete generation but
// does not install nftables or start receive loops. A per-VPN failure is
// retained in the generation-wide quarantine spec; valid VPN metadata is still
// collected so the nft guard can deny every known candidate ifindex.
func (d *Daemon) stageIpsecCapture(cfg *config.Config) (old, staged *ipsecCaptureRuntime, err error) {
	if d == nil {
		return nil, nil, nil
	}
	d.ipsecCaptureMu.Lock()
	defer d.ipsecCaptureMu.Unlock()
	old = d.ipsecCapture
	d.ipsecCaptureStaged = nil
	d.ipsecCaptureStagePending = false
	if d.ipsecS4 == nil {
		d.ipsecS4 = newIpsecSupervisor()
	}
	generation := d.ipsecCaptureGeneration.Add(1)
	plan, err := buildIpsecCaptureQueuePlan(cfg, generation)
	if err != nil {
		return old, old, err
	}
	keys := plan.Keys
	if !plan.Quarantine.QuarantineAll && old != nil && old.sameKeys(keys) && !old.spec.QuarantineAll {
		return old, old, nil
	}
	var runID string
	if plan.Quarantine.QuarantineAll || len(keys) != 0 {
		var identityErr error
		runID, identityErr = ipsecCaptureRunID9506()
		if identityErr != nil {
			return old, old, identityErr
		}
		plan.Quarantine.RunID = runID
		if ipsecCaptureDurableIdentityEnabled9506() {
			plan.Quarantine.LabelSchema = xnft.IpsecDivertLabelSchema9506
		}
	}
	if plan.Quarantine.QuarantineAll {
		staged = stagedIpsecQuarantineRuntime(d, generation, plan.Quarantine)
		d.ipsecCaptureStaged = staged
		d.ipsecCaptureStagePending = true
		return old, staged, nil
	}
	if len(keys) == 0 {
		if old == nil {
			return old, nil, nil
		}
		d.ipsecCaptureStagePending = true
		return old, nil, nil
	}
	handles := make([]ipsecQueueHandle, 0, len(keys))
	cleanupHandles := func() {
		for _, handle := range handles {
			_ = d.ipsecS4.retireQueue(handle, true, true)
		}
	}
	quarantineWith := func(reason xnft.IpsecQuarantineReason, stageErr error) (*ipsecCaptureRuntime, error) {
		plan.addQuarantine(reason)
		plan.finalize(generation)
		return stagedIpsecQuarantineRuntime(d, generation, plan.Quarantine), nil
	}
	for _, key := range keys {
		handle, allocErr := d.ipsecS4.allocateQueue(key)
		if allocErr != nil {
			cleanupHandles()
			staged, _ = quarantineWith(xnft.IpsecQuarantineReasonQueueOpen, allocErr)
			d.ipsecCaptureStaged = staged
			d.ipsecCaptureStagePending = true
			return old, staged, nil
		}
		handles = append(handles, handle)
	}
	registry := new(nfqueue.OriginRegistry)
	if registerErr := ipsecCaptureRegisterOrigins(registry, handles); registerErr != nil {
		cleanupHandles()
		staged, _ = quarantineWith(xnft.IpsecQuarantineReasonUnknown, registerErr)
		d.ipsecCaptureStaged = staged
		d.ipsecCaptureStagePending = true
		return old, staged, nil
	}
	queues := make([]IpsecCaptureQueue, 0, len(handles))
	for _, handle := range handles {
		queue, openErr := ipsecCaptureOpenQueue(handle.Number, handle.Key.Family)
		if openErr != nil {
			closeStagedCaptureQueues(queues)
			cleanupHandles()
			staged, _ = quarantineWith(xnft.IpsecQuarantineReasonQueueOpen, openErr)
			d.ipsecCaptureStaged = staged
			d.ipsecCaptureStagePending = true
			return old, staged, nil
		}
		queues = append(queues, IpsecCaptureQueue{
			Queue:              queue,
			QueueNumber:        handle.Number,
			Tunnel:             uint32(handle.Key.Ifindex),
			Generation:         handle.Key.Generation,
			SnapshotGeneration: handle.Key.Generation,
			ConfigGeneration:   handle.Key.Generation,
			FIBGeneration:      uint32(handle.Key.Generation),
			QueueEpoch:         handle.Epoch,
		})
	}
	zoneSnapshot := buildPMechZoneSnapshot(cfg, handles, generation, uint32(generation))
	submitPath, completePath := ipsecCaptureReinjectSocketPaths(dpuserspace.DefaultControlSocketPath(cfg))
	submitter, submitErr := nfqueue.NewSocketReinjectSubmitter(submitPath, completePath)
	if submitErr != nil {
		closeStagedCaptureQueues(queues)
		cleanupHandles()
		staged, _ = quarantineWith(xnft.IpsecQuarantineReasonQueueOpen, submitErr)
		d.ipsecCaptureStaged = staged
		d.ipsecCaptureStagePending = true
		return old, staged, nil
	}
	queueEpochs := make(map[uint16]uint64, len(handles))
	for _, handle := range handles {
		queueEpochs[handle.Number] = handle.Epoch
	}
	actor, actorErr := NewIpsecCapturePipeline(IpsecCapturePipelineConfig{
		Supervisor:  d.ipsecS4,
		Registry:    registry,
		QueueEpochs: queueEpochs,
		Queues:      queues,
		RunID:       runID,
		Pipeline: nfqueue.CapturePipelineConfig{
			Phase:          nfqueue.PipelineEnforcing,
			HandoffCap:     16384,
			BatchCap:       64,
			FragmentSlots:  128,
			FragmentPieces: 128,
			Submitter:      submitter,
			ZoneEvaluator:  nfqueue.DefaultZoneEvaluator{},
			ZoneSnapshot:   zoneSnapshot,
		},
	})
	if actorErr != nil {
		closeStagedCaptureQueues(queues)
		cleanupHandles()
		_ = submitter.Close()
		staged, _ = quarantineWith(xnft.IpsecQuarantineReasonUnknown, actorErr)
		d.ipsecCaptureStaged = staged
		d.ipsecCaptureStagePending = true
		return old, staged, nil
	}
	spec, specErr := ipsecCaptureDivertSpecWithQuarantine(handles, plan.Quarantine)
	if specErr != nil {
		closeStagedCaptureQueues(queues)
		cleanupHandles()
		_ = submitter.Close()
		staged, _ = quarantineWith(xnft.IpsecQuarantineReasonUnknown, specErr)
		d.ipsecCaptureStaged = staged
		d.ipsecCaptureStagePending = true
		return old, staged, nil
	}
	spec.RunID = runID
	if ipsecCaptureDurableIdentityEnabled9506() {
		spec.LabelSchema = xnft.IpsecDivertLabelSchema9506
	}
	staged = &ipsecCaptureRuntime{
		supervisor:   d.ipsecS4,
		handles:      handles,
		queues:       queues,
		registry:     registry,
		actor:        actor,
		submitter:    submitter,
		spec:         spec,
		runID:        actor.Status().RunID,
		zoneSnapshot: zoneSnapshot,
	}
	d.ipsecCaptureStaged = staged
	d.ipsecCaptureStagePending = true
	return old, staged, nil
}

func lockIpsecCaptureAuthority(current, next *ipsecCaptureRuntime) func() {
	if current != nil {
		current.authorityMu.Lock()
	}
	if next != nil && next != current {
		next.authorityMu.Lock()
	}
	return func() {
		if next != nil && next != current {
			next.authorityMu.Unlock()
		}
		if current != nil {
			current.authorityMu.Unlock()
		}
	}
}

func (d *Daemon) restoreIpsecCaptureRuntime(runtime *ipsecCaptureRuntime) {
	if d == nil {
		return
	}
	d.ipsecCapturePublishMu.Lock()
	defer d.ipsecCapturePublishMu.Unlock()
	d.ipsecCaptureMu.Lock()
	current := d.ipsecCapture
	d.ipsecCaptureMu.Unlock()
	unlock := lockIpsecCaptureAuthority(current, runtime)
	defer unlock()
	if current != nil {
		current.announced = false
	}
	if runtime != nil {
		runtime.announced = false
	}
	d.ipsecCaptureMu.Lock()
	d.ipsecCapture = runtime
	d.ipsecCaptureStaged = nil
	d.ipsecCaptureStagePending = false
	d.ipsecCaptureAuthorityRevision.Add(1)
	d.ipsecCaptureMu.Unlock()
}

func (d *Daemon) publishIpsecCaptureCommitted(runtime *ipsecCaptureRuntime) {
	if d == nil {
		return
	}
	d.ipsecCapturePublishMu.Lock()
	defer d.ipsecCapturePublishMu.Unlock()
	d.ipsecCaptureMu.Lock()
	current := d.ipsecCapture
	d.ipsecCaptureMu.Unlock()
	unlock := lockIpsecCaptureAuthority(current, runtime)
	defer unlock()
	if current != nil {
		current.announced = false
	}
	if runtime != nil && runtime != current {
		runtime.announced = false
	}
	d.ipsecCaptureMu.Lock()
	d.ipsecCapture = runtime
	d.ipsecCaptureStaged = nil
	d.ipsecCaptureStagePending = false
	d.ipsecCaptureAuthorityRevision.Add(1)
	d.ipsecCaptureMu.Unlock()
}

func (d *Daemon) rollbackIpsecCaptureStage(old, staged *ipsecCaptureRuntime) error {
	if d == nil {
		return nil
	}
	d.restoreIpsecCaptureRuntime(old)
	if staged == nil {
		return nil
	}
	return staged.close()

}

type ipsecCaptureGuardedInstaller interface {
	InstallIpsecDivertWithDrain(xnft.IpsecDivertSpec, func() error) error
}

type ipsecCaptureQuarantineInstaller interface {
	InstallIpsecQuarantineGuard(xnft.IpsecDivertSpec) error
}

// commitIpsecCaptureStage installs the divert atomically before starting the
// actor. The old generation remains live until the new nftables transaction and
// receive loops are both ready; every failure restores the old pointer and
func (d *Daemon) commitIpsecCaptureStage(old, staged *ipsecCaptureRuntime) error {
	if d == nil {
		return nil
	}
	d.ipsecCaptureMu.Lock()
	pending := d.ipsecCaptureStagePending
	d.ipsecCaptureMu.Unlock()
	if !pending {
		return nil
	}
	if nftInstaller == nil {
		_ = d.rollbackIpsecCaptureStage(old, staged)
		return errors.New("ipsec capture: nftables installer is unavailable")
	}
	if staged == nil {
		var owner *xnft.IpsecDivertSpec
		if old != nil {
			owner = &old.spec
		}
		if err := removeIpsecDivert9506(owner); err != nil {
			d.restoreIpsecCaptureRuntime(old)
			return fmt.Errorf("ipsec capture: remove divert: %w", err)
		}
		d.publishIpsecCaptureCommitted(nil)
		if old != nil {
			if err := old.close(); err != nil {
				return fmt.Errorf("ipsec capture: retire old generation: %w", err)
			}
		}
		return nil
	}
	installSpec, err := ipsecCaptureInstallSpec9506(staged.spec)
	if err != nil {
		_ = d.rollbackIpsecCaptureStage(old, staged)
		return fmt.Errorf("ipsec capture: allocate divert identity: %w", err)
	}
	staged.spec = installSpec
	oldRetired := false
	guarded, canGuard := nftInstaller.(ipsecCaptureGuardedInstaller)
	if old != nil && canGuard {
		err := guarded.InstallIpsecDivertWithDrain(staged.spec, func() error {
			err := old.close()
			if err == nil {
				oldRetired = true
			}
			return err
		})
		if err != nil {
			// The guarded installer retains its deny authority on every
			// post-ACK failure. Never restore old as an authority after the
			// transition has been touched.
			if !oldRetired {
				_ = old.close()
			}
			d.restoreIpsecCaptureRuntime(nil)
			_ = staged.close()
			return fmt.Errorf("ipsec capture: guarded divert transition: %w", err)
		}
	} else {
		if err := nftInstaller.InstallIpsecDivert(staged.spec); err != nil {
			_ = d.rollbackIpsecCaptureStage(old, staged)
			return fmt.Errorf("ipsec capture: install divert: %w", err)
		}
	}
	if staged.actor != nil {
		if err := staged.actor.Start(); err != nil {
			// A post-drain actor failure must leave a two-family DROP
			// authority. Never remove both tables and fall through.
			if old != nil && !oldRetired {
				rollbackSpec, identityErr := ipsecCaptureInstallSpec9506(old.spec)
				rollbackOK := false
				if identityErr == nil {
					if rollbackErr := nftInstaller.InstallIpsecDivert(rollbackSpec); rollbackErr != nil {
						slog.Warn("ipsec capture: old divert rollback install failed", "err", rollbackErr)
					} else {
						rollbackOK = true
						old.spec = rollbackSpec
					}
				} else {
					slog.Warn("ipsec capture: old divert rollback identity allocation failed", "err", identityErr)
				}
				if rollbackOK {
					_ = d.rollbackIpsecCaptureStage(old, staged)
				} else {
					// Never restore old as an authority after a failed
					// kernel reinstall. Keep/attempt deny-first authority.
					if quarantineErr := installIpsecQuarantine9506(staged.spec); quarantineErr != nil {
						slog.Warn("ipsec capture: quarantine fallback after rollback failure failed", "err", quarantineErr)
					}
					d.restoreIpsecCaptureRuntime(nil)
					_ = staged.close()
				}
			} else {
				if quarantineErr := installIpsecQuarantine9506(staged.spec); quarantineErr != nil {
					slog.Warn("ipsec capture: quarantine fallback identity allocation failed", "err", quarantineErr)
				}
				d.restoreIpsecCaptureRuntime(nil)
				_ = staged.close()
			}
			return fmt.Errorf("ipsec capture: start actor: %w", err)
		}
	}
	d.publishIpsecCaptureCommitted(staged)
	if old != nil && !oldRetired {
		if err := old.close(); err != nil {
			return fmt.Errorf("ipsec capture: retire old generation: %w", err)
		}
	}
	return nil
}
func (d *Daemon) reconcileIpsecCaptureAuthority() error {
	return d.reconcileIpsecCaptureAuthorityWithHook(nil)
}

func (d *Daemon) reconcileIpsecCaptureAuthorityWithHook(afterSample func()) error {
	if d == nil {
		return nil
	}
	d.ipsecCaptureMu.Lock()
	runtime := d.ipsecCapture
	revision := d.ipsecCaptureAuthorityRevision.Load()
	d.ipsecCaptureMu.Unlock()
	if runtime == nil {
		return nil
	}
	if afterSample != nil {
		afterSample()
	}
	runtime.authorityMu.Lock()
	defer runtime.authorityMu.Unlock()
	d.ipsecCaptureMu.Lock()
	current := d.ipsecCapture
	currentRevision := d.ipsecCaptureAuthorityRevision.Load()
	d.ipsecCaptureMu.Unlock()
	if current != runtime || currentRevision != revision {
		return nil
	}
	return runtime.announceAuthorityLocked()
}

func (d *Daemon) shutdownIpsecCapture() {
	if d == nil {
		return
	}
	d.ipsecCaptureMu.Lock()
	active := d.ipsecCapture
	staged := d.ipsecCaptureStaged
	d.ipsecCaptureMu.Unlock()
	if active == nil && staged == nil {
		return
	}
	if nftInstaller != nil {
		var owner *xnft.IpsecDivertSpec
		if active != nil {
			owner = &active.spec
		}
		if err := removeIpsecDivert9506(owner); err != nil {
			slog.Warn("ipsec capture shutdown: remove divert failed", "err", err)
		}
	}
	d.restoreIpsecCaptureRuntime(nil)
	if staged != nil && staged != active {
		if err := staged.close(); err != nil {
			slog.Warn("ipsec capture shutdown: close staged generation failed", "err", err)
		}
	}
	if active != nil {
		if err := active.close(); err != nil {
			slog.Warn("ipsec capture shutdown: close active generation failed", "err", err)
		}
	}
}
