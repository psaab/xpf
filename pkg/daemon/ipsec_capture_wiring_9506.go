package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"sync"

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
// installing a partial inet/bridge or forward/input diversion.
func ipsecCaptureDivertSpec(handles []ipsecQueueHandle) (xnft.IpsecDivertSpec, error) {
	var spec xnft.IpsecDivertSpec
	if len(handles) == 0 {
		return spec, fmt.Errorf("ipsec capture: empty queue generation")
	}
	seen := make(map[uint16]struct{}, len(handles))
	for _, handle := range handles {
		if handle.Number == 0 || handle.Epoch == 0 || handle.Key.Owner == "" || handle.Key.STN == "" || handle.Key.Ifindex <= 0 {
			return spec, fmt.Errorf("ipsec capture: invalid queue handle %+v", handle)
		}
		if _, exists := seen[handle.Number]; exists {
			return spec, fmt.Errorf("ipsec capture: duplicate queue number %d", handle.Number)
		}
		seen[handle.Number] = struct{}{}
		ifname, ifID := config.XFRMIfNameAndID(handle.Key.STN)
		if ifID == 0 || ifname == "" {
			return spec, fmt.Errorf("ipsec capture: invalid secure-tunnel interface %q", handle.Key.STN)
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
				return spec, fmt.Errorf("ipsec capture: unknown inet hook %d", handle.Key.Hook)
			}
		case ipsecFamilyBridge:
			switch handle.Key.Hook {
			case ipsecHookForward:
				spec.BridgeForward = append(spec.BridgeForward, rule)
			case ipsecHookInput:
				spec.BridgeInput = append(spec.BridgeInput, rule)
			default:
				return spec, fmt.Errorf("ipsec capture: unknown bridge hook %d", handle.Key.Hook)
			}
		default:
			return spec, fmt.Errorf("ipsec capture: unknown family %d", handle.Key.Family)
		}
	}
	if len(spec.InetForward) == 0 || len(spec.InetInput) == 0 || len(spec.BridgeForward) == 0 || len(spec.BridgeInput) == 0 {
		return spec, fmt.Errorf("ipsec capture: incomplete four-class queue generation")
	}
	return spec, nil
}

// ipsecCaptureRegisterOrigins installs the immutable queue provenance registry
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

type ipsecCaptureRuntime struct {
	supervisor *ipsecSupervisor
	handles    []ipsecQueueHandle
	queues     []IpsecCaptureQueue
	registry   *nfqueue.OriginRegistry
	actor      *IpsecCapturePipeline
	submitter  *nfqueue.SocketReinjectSubmitter
	spec       xnft.IpsecDivertSpec

	authorityMu     sync.Mutex
	announced       bool
	announcedPermit uint64
	announcedOpen   bool
	announcedRows   []nfqueue.ReinjectQueueEpoch
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

func (r *ipsecCaptureRuntime) authoritySnapshot() (uint64, bool, []nfqueue.ReinjectQueueEpoch) {
	if r == nil || r.supervisor == nil {
		return 0, false, nil
	}
	permit := r.supervisor.loadPermit()
	if permit == nil {
		return 0, false, nil
	}
	rows := ipsecCaptureQueueEpochSnapshot(r.handles)
	wireRows := make([]nfqueue.ReinjectQueueEpoch, 0, len(rows))
	for _, row := range rows {
		wireRows = append(wireRows, nfqueue.ReinjectQueueEpoch{Queue: row.Queue, Epoch: row.Epoch})
	}
	return permit.permitEpoch, permit.state == ipsecPermitOpen, wireRows
}

func (r *ipsecCaptureRuntime) announceAuthority() error {
	if r == nil || r.submitter == nil {
		return nil
	}
	permitEpoch, permitOpen, wireRows := r.authoritySnapshot()
	r.authorityMu.Lock()
	defer r.authorityMu.Unlock()
	if r.announced && r.announcedPermit == permitEpoch && r.announcedOpen == permitOpen &&
		sameReinjectQueueEpochs(r.announcedRows, wireRows) {
		return nil
	}
	if err := r.submitter.AnnounceReinject(permitEpoch, permitOpen, wireRows); err != nil {
		r.announced = false
		return err
	}
	r.announced = true
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

func ipsecCaptureQueueKeys(cfg *config.Config, generation uint64) ([]ipsecQueueKey, error) {
	if cfg == nil || generation == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(cfg.Security.IPsec.VPNs))
	for name := range cfg.Security.IPsec.VPNs {
		names = append(names, name)
	}
	sort.Strings(names)
	keys := make([]ipsecQueueKey, 0, len(names)*4)
	for _, name := range names {
		vpn := cfg.Security.IPsec.VPNs[name]
		if vpn == nil || vpn.BindInterface == "" {
			continue
		}
		ifname, ifID := config.XFRMIfNameAndID(vpn.BindInterface)
		if ifID == 0 || ifname == "" {
			return nil, fmt.Errorf("ipsec capture: VPN %q has invalid bind-interface %q", name, vpn.BindInterface)
		}
		link, err := netlink.LinkByName(ifname)
		if err != nil {
			return nil, fmt.Errorf("ipsec capture: find %s for VPN %q: %w", ifname, name, err)
		}
		if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
			return nil, fmt.Errorf("ipsec capture: VPN %q bind-interface %s has no ifindex", name, ifname)
		}
		ifindex := link.Attrs().Index
		for _, class := range []struct {
			family ipsecQueueFamily
			hook   ipsecQueueHook
		}{
			{ipsecFamilyInet, ipsecHookForward},
			{ipsecFamilyInet, ipsecHookInput},
			{ipsecFamilyBridge, ipsecHookForward},
			{ipsecFamilyBridge, ipsecHookInput},
		} {
			keys = append(keys, ipsecQueueKey{
				Generation: generation,
				Family:     class.family,
				Hook:       class.hook,
				Owner:      name,
				STN:        vpn.BindInterface,
				Ifindex:    ifindex,
			})
		}
	}
	return keys, nil
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

// stageIpsecCapture allocates, binds, and validates a complete generation but
// does not install nftables or start receive loops. The staged runtime is
// published before the dataplane compile so Manager.Compile stamps these
// queue epochs into the same snapshot that authorizes the new diversion.
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
	keys, err := ipsecCaptureQueueKeys(cfg, generation)
	if err != nil {
		return old, old, err
	}
	if old != nil && old.sameKeys(keys) {
		return old, old, nil
	}
	if len(keys) == 0 {
		if old == nil {
			return old, nil, nil
		}
		d.ipsecCaptureStagePending = true
		return old, nil, nil
	}
	handles := make([]ipsecQueueHandle, 0, len(keys))
	for _, key := range keys {
		handle, allocErr := d.ipsecS4.allocateQueue(key)
		if allocErr != nil {
			for _, prior := range handles {
				_ = d.ipsecS4.retireQueue(prior, true, true)
			}
			return old, old, allocErr
		}
		handles = append(handles, handle)
	}
	cleanupHandles := func() {
		for _, handle := range handles {
			_ = d.ipsecS4.retireQueue(handle, true, true)
		}
	}
	registry := new(nfqueue.OriginRegistry)
	if err := ipsecCaptureRegisterOrigins(registry, handles); err != nil {
		cleanupHandles()
		return old, old, err
	}
	queues := make([]IpsecCaptureQueue, 0, len(handles))
	for _, handle := range handles {
		queue, openErr := openIpsecCaptureQueue(handle.Number, handle.Key.Family)
		if openErr != nil {
			for _, captureQueue := range queues {
				_ = captureQueue.Queue.Close()
			}
			cleanupHandles()
			return old, old, openErr
		}
		queues = append(queues, IpsecCaptureQueue{
			Queue:      queue,
			Tunnel:     uint32(handle.Key.Ifindex),
			Generation: handle.Key.Generation,
		})
	}
	submitPath, completePath := ipsecCaptureReinjectSocketPaths(dpuserspace.DefaultControlSocketPath(cfg))
	submitter, err := nfqueue.NewSocketReinjectSubmitter(submitPath, completePath)
	if err != nil {
		for _, captureQueue := range queues {
			_ = captureQueue.Queue.Close()
		}
		cleanupHandles()
		return old, old, err
	}
	queueEpochs := make(map[uint16]uint64, len(handles))
	for _, handle := range handles {
		queueEpochs[handle.Number] = handle.Epoch
	}
	actor, err := NewIpsecCapturePipeline(IpsecCapturePipelineConfig{
		Supervisor:  d.ipsecS4,
		Registry:    registry,
		QueueEpochs: queueEpochs,
		Queues:      queues,
		Pipeline: nfqueue.CapturePipelineConfig{
			Phase:          nfqueue.PipelineEnforcing,
			HandoffCap:     16384,
			BatchCap:       64,
			FragmentSlots:  128,
			FragmentPieces: 128,
			Submitter:      submitter,
		},
	})
	if err != nil {
		for _, captureQueue := range queues {
			_ = captureQueue.Queue.Close()
		}
		cleanupHandles()
		return old, old, err
	}
	spec, err := ipsecCaptureDivertSpec(handles)
	if err != nil {
		for _, captureQueue := range queues {
			_ = captureQueue.Queue.Close()
		}
		cleanupHandles()
		return old, old, err
	}
	staged = &ipsecCaptureRuntime{
		supervisor: d.ipsecS4,
		handles:    handles,
		queues:     queues,
		registry:   registry,
		actor:      actor,
		submitter:  submitter,
		spec:       spec,
	}
	d.ipsecCaptureStaged = staged
	d.ipsecCaptureStagePending = true
	return old, staged, nil
}

func (d *Daemon) restoreIpsecCaptureRuntime(runtime *ipsecCaptureRuntime) {
	if d == nil {
		return
	}
	if runtime != nil {
		runtime.authorityMu.Lock()
		runtime.announced = false
		runtime.authorityMu.Unlock()
	}
	d.ipsecCaptureMu.Lock()
	d.ipsecCapture = runtime
	d.ipsecCaptureStaged = nil
	d.ipsecCaptureStagePending = false
	d.ipsecCaptureMu.Unlock()
}

func (d *Daemon) publishIpsecCaptureCommitted(runtime *ipsecCaptureRuntime) {
	if d == nil {
		return
	}
	d.ipsecCaptureMu.Lock()
	d.ipsecCapture = runtime
	d.ipsecCaptureStaged = nil
	d.ipsecCaptureStagePending = false
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
		if err := nftInstaller.RemoveIpsecDivert(); err != nil {
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
	if err := nftInstaller.InstallIpsecDivert(staged.spec); err != nil {
		_ = d.rollbackIpsecCaptureStage(old, staged)
		return fmt.Errorf("ipsec capture: install divert: %w", err)
	}
	if err := staged.actor.Start(); err != nil {
		// The install is atomic, but an actor that cannot start must not leave
		// packets diverted into a dead queue generation.
		if old != nil {
			_ = nftInstaller.InstallIpsecDivert(old.spec)
		} else {
			_ = nftInstaller.RemoveIpsecDivert()
		}
		_ = d.rollbackIpsecCaptureStage(old, staged)
		return fmt.Errorf("ipsec capture: start actor: %w", err)
	}
	d.publishIpsecCaptureCommitted(staged)
	if old != nil {
		if err := old.close(); err != nil {
			return fmt.Errorf("ipsec capture: retire old generation: %w", err)
		}
	}
	return nil
}
func (d *Daemon) reconcileIpsecCaptureAuthority() error {
	if d == nil {
		return nil
	}
	d.ipsecCaptureMu.Lock()
	runtime := d.ipsecCapture
	d.ipsecCaptureMu.Unlock()
	if runtime == nil {
		return nil
	}
	return runtime.announceAuthority()
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
		if err := nftInstaller.RemoveIpsecDivert(); err != nil {
			slog.Warn("ipsec capture shutdown: remove divert failed", "err", err)
		}
	}
	d.ipsecCaptureMu.Lock()
	d.ipsecCapture = nil
	d.ipsecCaptureStaged = nil
	d.ipsecCaptureStagePending = false
	d.ipsecCaptureMu.Unlock()
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
