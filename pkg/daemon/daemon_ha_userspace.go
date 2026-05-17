package daemon

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/logging"
)

// buildZoneIDs replicates the deterministic zone ID assignment from the
// dataplane compiler (sorted zone names, 1-based sequential IDs).
func buildZoneIDs(cfg *config.Config) map[string]uint16 {
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)
	ids := make(map[string]uint16, len(names))
	for i, name := range names {
		ids[name] = uint16(i + 1)
	}
	return ids
}

type userspaceSessionDeltaDrainer interface {
	DrainSessionDeltas(max uint32) ([]dpuserspace.SessionDeltaInfo, dpuserspace.ProcessStatus, error)
}

type userspaceSessionExporter interface {
	ExportOwnerRGSessions(rgIDs []int, max uint32) ([]dpuserspace.SessionDeltaInfo, dpuserspace.ProcessStatus, error)
}

type userspaceEventStreamProvider interface {
	EventStream() *dpuserspace.EventStream
}

type userspaceEventStreamExporter interface {
	ExportAllSessionsViaEventStream() error
}

func daemonMonotonicSeconds() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)
}

func userspaceSessionTimeout(proto uint8) uint32 {
	switch proto {
	case 6:
		return 300
	case 17:
		return 60
	case 1, 58:
		return 15
	default:
		return 30
	}
}

func userspaceHostToNetwork16(v uint16) uint16 {
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], v)
	return binary.NativeEndian.Uint16(raw[:])
}

func userspaceNetworkToHost16(v uint16) uint16 {
	var raw [2]byte
	binary.NativeEndian.PutUint16(raw[:], v)
	return binary.BigEndian.Uint16(raw[:])
}

func userspaceReverseKeyV4(key dataplane.SessionKey, delta dpuserspace.SessionDeltaInfo) dataplane.SessionKey {
	rev := dataplane.SessionKey{
		SrcIP:    key.DstIP,
		DstIP:    key.SrcIP,
		SrcPort:  key.DstPort,
		DstPort:  key.SrcPort,
		Protocol: key.Protocol,
	}
	if ip := net.ParseIP(delta.NATDstIP).To4(); ip != nil {
		copy(rev.SrcIP[:], ip)
	}
	if ip := net.ParseIP(delta.NATSrcIP).To4(); ip != nil {
		copy(rev.DstIP[:], ip)
	}
	if delta.NATDstPort != 0 {
		rev.SrcPort = userspaceHostToNetwork16(delta.NATDstPort)
	}
	if delta.NATSrcPort != 0 {
		rev.DstPort = userspaceHostToNetwork16(delta.NATSrcPort)
	}
	return rev
}

func userspaceForwardWireKeyV4(key dataplane.SessionKey, delta dpuserspace.SessionDeltaInfo) dataplane.SessionKey {
	wire := key
	if ip := net.ParseIP(delta.NATSrcIP).To4(); ip != nil {
		copy(wire.SrcIP[:], ip)
		wire.SrcPort = userspaceHostToNetwork16(effectiveUserspaceNATSrcPort(delta))
	}
	if ip := net.ParseIP(delta.NATDstIP).To4(); ip != nil {
		copy(wire.DstIP[:], ip)
		wire.DstPort = userspaceHostToNetwork16(effectiveUserspaceNATDstPort(delta))
	}
	return wire
}

func effectiveUserspaceNATSrcPort(delta dpuserspace.SessionDeltaInfo) uint16 {
	if delta.NATSrcPort != 0 {
		return delta.NATSrcPort
	}
	if delta.NATSrcIP != "" {
		return delta.SrcPort
	}
	return 0
}

func effectiveUserspaceNATDstPort(delta dpuserspace.SessionDeltaInfo) uint16 {
	if delta.NATDstPort != 0 {
		return delta.NATDstPort
	}
	if delta.NATDstIP != "" {
		return delta.DstPort
	}
	return 0
}

func userspaceReverseKeyV6(key dataplane.SessionKeyV6, delta dpuserspace.SessionDeltaInfo) dataplane.SessionKeyV6 {
	rev := dataplane.SessionKeyV6{
		SrcIP:    key.DstIP,
		DstIP:    key.SrcIP,
		SrcPort:  key.DstPort,
		DstPort:  key.SrcPort,
		Protocol: key.Protocol,
	}
	if ip := net.ParseIP(delta.NATDstIP).To16(); ip != nil {
		copy(rev.SrcIP[:], ip)
	}
	if ip := net.ParseIP(delta.NATSrcIP).To16(); ip != nil {
		copy(rev.DstIP[:], ip)
	}
	if delta.NATDstPort != 0 {
		rev.SrcPort = userspaceHostToNetwork16(delta.NATDstPort)
	}
	if delta.NATSrcPort != 0 {
		rev.DstPort = userspaceHostToNetwork16(delta.NATSrcPort)
	}
	return rev
}

func userspaceParseSyncMAC(raw string) [6]byte {
	var out [6]byte
	if raw == "" {
		return out
	}
	mac, err := net.ParseMAC(raw)
	if err != nil || len(mac) != len(out) {
		return out
	}
	copy(out[:], mac)
	return out
}

func userspaceSessionFromDeltaV4(delta dpuserspace.SessionDeltaInfo, zoneIDs map[string]uint16) (dataplane.SessionKey, dataplane.SessionValue, bool) {
	src := net.ParseIP(delta.SrcIP).To4()
	dst := net.ParseIP(delta.DstIP).To4()
	if src == nil || dst == nil {
		return dataplane.SessionKey{}, dataplane.SessionValue{}, false
	}
	var key dataplane.SessionKey
	copy(key.SrcIP[:], src)
	copy(key.DstIP[:], dst)
	key.SrcPort = userspaceHostToNetwork16(delta.SrcPort)
	key.DstPort = userspaceHostToNetwork16(delta.DstPort)
	key.Protocol = delta.Protocol

	// #919/#922: prefer the u16 zone IDs from the binary event-stream
	// payload (bytes [21]/[22] in eventstream.go); fall back to legacy
	// name-string lookup for older helpers that emit JSON deltas only.
	ingressZone := delta.IngressZoneID
	if ingressZone == 0 {
		ingressZone = zoneIDs[delta.IngressZone]
	}
	egressZone := delta.EgressZoneID
	if egressZone == 0 {
		egressZone = zoneIDs[delta.EgressZone]
	}
	if ingressZone == 0 || egressZone == 0 {
		return dataplane.SessionKey{}, dataplane.SessionValue{}, false
	}

	now := daemonMonotonicSeconds()
	val := dataplane.SessionValue{
		State:       4, // SESS_STATE_ESTABLISHED
		SessionID:   uint64(now)<<16 | uint64(delta.Slot&0xffff),
		Created:     now,
		LastSeen:    now,
		Timeout:     userspaceSessionTimeout(delta.Protocol),
		IngressZone: ingressZone,
		EgressZone:  egressZone,
		ReverseKey:  userspaceReverseKeyV4(key, delta),
	}
	if delta.TunnelEndpointID != 0 {
		val.LogFlags |= dataplane.LogFlagUserspaceTunnelEndpoint
		val.FibGen = delta.TunnelEndpointID
	} else if delta.TXIfindex > 0 {
		val.FibIfindex = uint32(delta.TXIfindex)
	} else if delta.EgressIfindex > 0 {
		val.FibIfindex = uint32(delta.EgressIfindex)
	}
	val.FibVlanID = delta.TXVLANID
	val.FibDmac = userspaceParseSyncMAC(delta.NeighborMAC)
	val.FibSmac = userspaceParseSyncMAC(delta.SrcMAC)
	if ip := net.ParseIP(delta.NATSrcIP).To4(); ip != nil {
		val.Flags |= dataplane.SessFlagSNAT
		val.NATSrcIP = binary.NativeEndian.Uint32(ip)
		val.NATSrcPort = userspaceHostToNetwork16(effectiveUserspaceNATSrcPort(delta))
	}
	if ip := net.ParseIP(delta.NATDstIP).To4(); ip != nil {
		val.Flags |= dataplane.SessFlagDNAT
		val.NATDstIP = binary.NativeEndian.Uint32(ip)
		val.NATDstPort = userspaceHostToNetwork16(effectiveUserspaceNATDstPort(delta))
	}
	if delta.FabricIngress {
		val.LogFlags |= dataplane.LogFlagUserspaceFabricIngress
	}
	return key, val, true
}

func userspaceForwardWireAliasFromDeltaV4(delta dpuserspace.SessionDeltaInfo, zoneIDs map[string]uint16) (dataplane.SessionKey, dataplane.SessionValue, bool) {
	key, val, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
	if !ok {
		return dataplane.SessionKey{}, dataplane.SessionValue{}, false
	}
	wireKey := userspaceForwardWireKeyV4(key, delta)
	if wireKey == key {
		return dataplane.SessionKey{}, dataplane.SessionValue{}, false
	}
	return wireKey, val, true
}

func userspaceSessionFromDeltaV6(delta dpuserspace.SessionDeltaInfo, zoneIDs map[string]uint16) (dataplane.SessionKeyV6, dataplane.SessionValueV6, bool) {
	src := net.ParseIP(delta.SrcIP).To16()
	dst := net.ParseIP(delta.DstIP).To16()
	if src == nil || dst == nil {
		return dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}, false
	}
	var key dataplane.SessionKeyV6
	copy(key.SrcIP[:], src)
	copy(key.DstIP[:], dst)
	key.SrcPort = userspaceHostToNetwork16(delta.SrcPort)
	key.DstPort = userspaceHostToNetwork16(delta.DstPort)
	key.Protocol = delta.Protocol

	// #919/#922: prefer the u16 zone IDs from the binary event-stream
	// payload; fall back to legacy name-string lookup for JSON deltas.
	ingressZone := delta.IngressZoneID
	if ingressZone == 0 {
		ingressZone = zoneIDs[delta.IngressZone]
	}
	egressZone := delta.EgressZoneID
	if egressZone == 0 {
		egressZone = zoneIDs[delta.EgressZone]
	}
	if ingressZone == 0 || egressZone == 0 {
		return dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}, false
	}

	now := daemonMonotonicSeconds()
	val := dataplane.SessionValueV6{
		State:       4, // SESS_STATE_ESTABLISHED
		SessionID:   uint64(now)<<16 | uint64(delta.Slot&0xffff),
		Created:     now,
		LastSeen:    now,
		Timeout:     userspaceSessionTimeout(delta.Protocol),
		IngressZone: ingressZone,
		EgressZone:  egressZone,
		ReverseKey:  userspaceReverseKeyV6(key, delta),
	}
	if delta.TunnelEndpointID != 0 {
		val.LogFlags |= dataplane.LogFlagUserspaceTunnelEndpoint
		val.FibGen = delta.TunnelEndpointID
	} else if delta.TXIfindex > 0 {
		val.FibIfindex = uint32(delta.TXIfindex)
	} else if delta.EgressIfindex > 0 {
		val.FibIfindex = uint32(delta.EgressIfindex)
	}
	val.FibVlanID = delta.TXVLANID
	val.FibDmac = userspaceParseSyncMAC(delta.NeighborMAC)
	val.FibSmac = userspaceParseSyncMAC(delta.SrcMAC)
	if ip := net.ParseIP(delta.NATSrcIP).To16(); ip != nil {
		val.Flags |= dataplane.SessFlagSNAT
		copy(val.NATSrcIP[:], ip)
		val.NATSrcPort = userspaceHostToNetwork16(effectiveUserspaceNATSrcPort(delta))
	}
	if ip := net.ParseIP(delta.NATDstIP).To16(); ip != nil {
		val.Flags |= dataplane.SessFlagDNAT
		copy(val.NATDstIP[:], ip)
		val.NATDstPort = userspaceHostToNetwork16(effectiveUserspaceNATDstPort(delta))
	}
	if delta.FabricIngress {
		val.LogFlags |= dataplane.LogFlagUserspaceFabricIngress
	}
	return key, val, true
}

func userspaceForwardWireKeyV6(key dataplane.SessionKeyV6, delta dpuserspace.SessionDeltaInfo) dataplane.SessionKeyV6 {
	wire := key
	if ip := net.ParseIP(delta.NATSrcIP).To16(); ip != nil {
		copy(wire.SrcIP[:], ip)
		wire.SrcPort = userspaceHostToNetwork16(effectiveUserspaceNATSrcPort(delta))
	}
	if ip := net.ParseIP(delta.NATDstIP).To16(); ip != nil {
		copy(wire.DstIP[:], ip)
		wire.DstPort = userspaceHostToNetwork16(effectiveUserspaceNATDstPort(delta))
	}
	return wire
}

func userspaceForwardWireAliasFromDeltaV6(delta dpuserspace.SessionDeltaInfo, zoneIDs map[string]uint16) (dataplane.SessionKeyV6, dataplane.SessionValueV6, bool) {
	key, val, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
	if !ok {
		return dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}, false
	}
	wireKey := userspaceForwardWireKeyV6(key, delta)
	if wireKey == key {
		return dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}, false
	}
	return wireKey, val, true
}

func (d *Daemon) shouldSyncUserspaceDelta(delta dpuserspace.SessionDeltaInfo, ingressZone uint16) bool {
	// Local-delivery sessions are traffic destined TO the firewall itself
	// (management SSH, BGP peering, DHCP, NDP, ICMP echo, etc.).  These are
	// intentionally excluded from HA session sync because:
	//  1. Each cluster node handles its own host-bound traffic independently;
	//     the peer's kernel stack processes its own local-delivery sessions
	//     after failover with no need for synced state.
	//  2. Local-delivery sessions reference node-local ifindexes and addresses
	//     that are meaningless on the peer.
	//  3. The userspace dataplane already sets track_in_userspace=false for
	//     these (afxdp.rs), so they are not in the session sweep; this guard
	//     covers the helper event-stream path.
	// See #315 for discussion.
	if strings.EqualFold(delta.Disposition, "local_delivery") {
		slog.Debug("userspace delta: filtered (local_delivery)", "src", delta.SrcIP, "dst", delta.DstIP)
		return false
	}
	if strings.EqualFold(delta.Origin, "missing_neighbor_seed") {
		slog.Debug("userspace delta: filtered (missing_neighbor_seed)", "src", delta.SrcIP, "dst", delta.DstIP)
		return false
	}
	if delta.FabricRedirect && !delta.FabricIngress {
		return d.sessionSync != nil
	}
	if delta.OwnerRGID > 0 && d.sessionSync != nil && d.sessionSync.IsPrimaryForRGFn != nil {
		ok := d.sessionSync.IsPrimaryForRGFn(delta.OwnerRGID)
		if !ok {
			slog.Debug("userspace delta: filtered (not primary for owner RG)", "rg", delta.OwnerRGID, "src", delta.SrcIP, "dst", delta.DstIP)
		}
		return ok
	}
	ok := d.sessionSync != nil && d.sessionSync.ShouldSyncZone(ingressZone)
	if !ok {
		slog.Debug("userspace delta: filtered (zone not synced)", "zone", ingressZone, "src", delta.SrcIP, "dst", delta.DstIP)
	}
	return ok
}

// buildZoneRGMap builds a zone_id→RG mapping by looking up which interfaces
// belong to each zone, then checking those interfaces' RedundancyGroup.
// Zones with RETH interfaces inherit the RETH's RG; non-RETH zones are not
// included (they fall back to global IsPrimaryFn in session sync).
func buildZoneRGMap(cfg *config.Config, zoneIDs map[string]uint16) map[uint16]int {
	result := make(map[uint16]int)
	for zoneName, zone := range cfg.Security.Zones {
		zid, ok := zoneIDs[zoneName]
		if !ok {
			continue
		}
		rgSeen := -1
		for _, ifName := range zone.Interfaces {
			// Strip unit suffix (e.g. "reth0.0" → "reth0") for config lookup.
			baseName := ifName
			if idx := strings.IndexByte(ifName, '.'); idx >= 0 {
				baseName = ifName[:idx]
			}
			if ifc, ok := cfg.Interfaces.Interfaces[baseName]; ok && ifc.RedundancyGroup > 0 {
				if rgSeen >= 0 && rgSeen != ifc.RedundancyGroup {
					slog.Warn("zone spans multiple redundancy groups; "+
						"active/active session sync ownership is ambiguous",
						"zone", zoneName,
						"rg1", rgSeen, "rg2", ifc.RedundancyGroup)
				}
				if rgSeen < 0 {
					result[zid] = ifc.RedundancyGroup
					rgSeen = ifc.RedundancyGroup
				}
			}
		}
	}
	return result
}

// rgHasRETH returns whether the given redundancy group has any RETH interfaces.
func rgHasRETH(cfg *config.Config, rgID int) bool {
	if cfg == nil {
		return false
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc.RedundancyGroup == rgID {
			return true
		}
	}
	return false
}

func (d *Daemon) syncUserspaceSessionDeltas(ctx context.Context) {
	drainer, ok := d.dp.(userspaceSessionDeltaDrainer)
	if !ok || d.cluster == nil || d.sessionSync == nil {
		return
	}

	const (
		fastInterval      = 100 * time.Millisecond // event stream disconnected
		reconcileInterval = 5 * time.Second        // event stream connected
	)
	ticker := time.NewTicker(fastInterval)
	defer ticker.Stop()
	wasConnected := false

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		// Adjust cadence based on event stream state.
		connected := d.eventStreamConnected.Load()
		if connected != wasConnected {
			wasConnected = connected
			if connected {
				ticker.Reset(reconcileInterval)
			} else {
				ticker.Reset(fastInterval)
			}
		}

		if d.cluster == nil || d.sessionSync == nil {
			return
		}
		if !d.cluster.IsLocalPrimaryAny() || !d.sessionSync.IsConnected() {
			continue
		}
		cfg := d.store.ActiveConfig()
		if cfg == nil {
			continue
		}
		d.userspaceDeltaSyncMu.Lock()
		_, err := d.drainUserspaceSessionDeltasWithConfig(drainer, cfg, 1)
		d.userspaceDeltaSyncMu.Unlock()
		if err != nil {
			slog.Debug("userspace session delta drain failed", "err", err)
		}
	}
}

// runUserspaceEventStream attempts to consume session events from the helper's
// binary event stream. Falls back to the existing polling loop when the stream
// is unavailable or disconnected.
func (d *Daemon) runUserspaceEventStream(ctx context.Context) {
	provider, ok := d.dp.(userspaceEventStreamProvider)
	if !ok || d.cluster == nil || d.sessionSync == nil {
		// Manager doesn't support event stream — fall back to polling.
		d.syncUserspaceSessionDeltas(ctx)
		return
	}

	// Wait for the event stream to become available (helper may not have started yet).
	var es *dpuserspace.EventStream
	for {
		es = provider.EventStream()
		if es != nil {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}

	// Wire callbacks.
	es.SetOnEvent(func(eventType uint8, seq uint64, delta dpuserspace.SessionDeltaInfo) {
		d.handleEventStreamDelta(eventType, delta)
	})
	es.SetOnDataplaneEvent(func(seq uint64, rec logging.EventRecord) {
		if d.eventBuf != nil {
			d.eventBuf.Add(rec)
		}
	})
	es.SetOnFullResync(func() {
		d.handleEventStreamFullResync()
	})

	slog.Info("userspace: event stream consumer started, polling is primary until stream connects")

	// Monitor connection. When the stream is connected, events arrive via
	// callback and polling drops to 5s reconciliation. When disconnected,
	// polling resumes at 100ms.
	d.eventStreamFallbackLoop(ctx, provider)
}

// handleEventStreamDelta processes a single session event from the event stream.
func (d *Daemon) handleEventStreamDelta(eventType uint8, delta dpuserspace.SessionDeltaInfo) {
	if d.cluster == nil || d.sessionSync == nil {
		slog.Debug("userspace delta: dropped (no cluster/sync)", "type", eventType)
		return
	}
	if !d.cluster.IsLocalPrimaryAny() {
		slog.Debug("userspace delta: dropped (not primary for any RG)", "type", eventType)
		return
	}
	if !d.sessionSync.IsConnected() {
		slog.Debug("userspace delta: dropped (sync not connected)", "type", eventType)
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	zoneIDs := buildZoneIDs(cfg)

	// Map binary event type to the string event expected by queueUserspaceSessionDeltas.
	switch eventType {
	case dpuserspace.EventTypeSessionOpen, dpuserspace.EventTypeSessionUpdate:
		delta.Event = "open"
	case dpuserspace.EventTypeSessionClose:
		delta.Event = "close"
	}

	d.queueUserspaceSessionDeltas(zoneIDs, []dpuserspace.SessionDeltaInfo{delta})
}

// handleEventStreamFullResync handles a FullResync frame from the helper.
// This means the helper's replay buffer was trimmed past our last ack; we need
// a one-shot bulk export to catch up.
func (d *Daemon) handleEventStreamFullResync() {
	slog.Warn("userspace event stream: full resync requested, triggering bulk export")
	exporter, ok := d.dp.(userspaceSessionExporter)
	if !ok {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	// Export sessions for all RGs we're primary for.
	var rgIDs []int
	if d.cluster != nil {
		for rgID := 0; rgID < 16; rgID++ {
			if d.cluster.IsLocalPrimary(rgID) {
				rgIDs = append(rgIDs, rgID)
			}
		}
	}
	if len(rgIDs) == 0 {
		return
	}
	if _, err := d.exportUserspaceOwnerRGSessionsWithConfig(exporter, cfg, rgIDs); err != nil {
		slog.Warn("userspace event stream: full resync export failed", "err", err)
	}
}

// eventStreamFallbackLoop monitors the event stream connection and falls back
// to polling via DrainSessionDeltas when the stream is disconnected.
// When the event stream is live, polling slows to 5s reconciliation;
// when disconnected, it runs at 100ms to compensate for the lost stream.
func (d *Daemon) eventStreamFallbackLoop(ctx context.Context, provider userspaceEventStreamProvider) {
	drainer, hasDrainer := d.dp.(userspaceSessionDeltaDrainer)

	const (
		fastInterval      = 100 * time.Millisecond // event stream disconnected
		reconcileInterval = 5 * time.Second        // event stream connected
	)
	ticker := time.NewTicker(fastInterval)
	defer ticker.Stop()
	wasConnected := false

	defer d.eventStreamConnected.Store(false)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		es := provider.EventStream()
		connected := es != nil && es.IsConnected()

		// Track transitions and adjust cadence.
		if connected != wasConnected {
			wasConnected = connected
			d.eventStreamConnected.Store(connected)
			if connected {
				ticker.Reset(reconcileInterval)
				slog.Info("userspace: event stream connected, polling reduced to reconciliation (5s)")
			} else {
				ticker.Reset(fastInterval)
				slog.Info("userspace: event stream disconnected, polling resumed at 100ms")
			}
		}

		if connected {
			// Stream is live — run reconciliation drain to catch any
			// missed events, but at the slow 5s cadence.
			if !hasDrainer {
				continue
			}
			if d.cluster == nil || d.sessionSync == nil {
				return
			}
			if !d.cluster.IsLocalPrimaryAny() || !d.sessionSync.IsConnected() {
				continue
			}
			cfg := d.store.ActiveConfig()
			if cfg == nil {
				continue
			}
			d.userspaceDeltaSyncMu.Lock()
			n, _ := d.drainUserspaceSessionDeltasWithConfig(drainer, cfg, 1)
			d.userspaceDeltaSyncMu.Unlock()
			if n > 0 {
				slog.Info("userspace: reconciliation drain caught missed deltas", "count", n)
			}
			continue
		}

		// Stream disconnected — fall back to fast polling.
		if !hasDrainer {
			continue
		}
		if d.cluster == nil || d.sessionSync == nil {
			return
		}
		if !d.cluster.IsLocalPrimaryAny() || !d.sessionSync.IsConnected() {
			continue
		}
		cfg := d.store.ActiveConfig()
		if cfg == nil {
			continue
		}
		d.userspaceDeltaSyncMu.Lock()
		_, _ = d.drainUserspaceSessionDeltasWithConfig(drainer, cfg, 1)
		d.userspaceDeltaSyncMu.Unlock()
	}
}

func (d *Daemon) queueUserspaceSessionDeltas(
	zoneIDs map[string]uint16,
	deltas []dpuserspace.SessionDeltaInfo,
) int {
	if d.sessionSync == nil {
		return 0
	}
	queued := 0
	for _, delta := range deltas {
		switch strings.ToLower(delta.Event) {
		case "open":
			switch delta.AddrFamily {
			case dataplane.AFInet:
				key, val, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
				if !ok {
					slog.Debug("userspace delta: V4 conversion failed", "src", delta.SrcIP, "dst", delta.DstIP, "disposition", delta.Disposition)
					continue
				}
				if !d.shouldSyncUserspaceDelta(delta, val.IngressZone) {
					continue
				}
				d.sessionSync.QueueSessionV4(key, val)
				slog.Debug("userspace delta: queued V4", "src", delta.SrcIP, "dst", delta.DstIP, "ownerRG", delta.OwnerRGID)
				queued++
				if delta.FabricRedirect && !delta.FabricIngress {
					if wireKey, wireVal, ok := userspaceForwardWireAliasFromDeltaV4(delta, zoneIDs); ok {
						d.sessionSync.QueueSessionV4(wireKey, wireVal)
						queued++
					}
				}
			case dataplane.AFInet6:
				key, val, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
				if !ok || !d.shouldSyncUserspaceDelta(delta, val.IngressZone) {
					continue
				}
				d.sessionSync.QueueSessionV6(key, val)
				queued++
				if delta.FabricRedirect && !delta.FabricIngress {
					if wireKey, wireVal, ok := userspaceForwardWireAliasFromDeltaV6(delta, zoneIDs); ok {
						d.sessionSync.QueueSessionV6(wireKey, wireVal)
						queued++
					}
				}
			}
		case "close":
			switch delta.AddrFamily {
			case dataplane.AFInet:
				key, val, ok := userspaceSessionFromDeltaV4(delta, zoneIDs)
				if ok && d.shouldSyncUserspaceDelta(delta, val.IngressZone) {
					d.sessionSync.QueueDeleteV4(key)
					queued++
					if delta.FabricRedirect && !delta.FabricIngress {
						wireKey := userspaceForwardWireKeyV4(key, delta)
						if wireKey != key {
							d.sessionSync.QueueDeleteV4(wireKey)
							queued++
						}
					}
				}
			case dataplane.AFInet6:
				key, val, ok := userspaceSessionFromDeltaV6(delta, zoneIDs)
				if ok && d.shouldSyncUserspaceDelta(delta, val.IngressZone) {
					d.sessionSync.QueueDeleteV6(key)
					queued++
					if delta.FabricRedirect && !delta.FabricIngress {
						wireKey := userspaceForwardWireKeyV6(key, delta)
						if wireKey != key {
							d.sessionSync.QueueDeleteV6(wireKey)
							queued++
						}
					}
				}
			}
		}
	}
	return queued
}

func (d *Daemon) drainUserspaceSessionDeltasWithConfig(
	drainer userspaceSessionDeltaDrainer,
	cfg *config.Config,
	maxBatches int,
) (int, error) {
	if drainer == nil || cfg == nil || maxBatches <= 0 {
		return 0, nil
	}
	zoneIDs := buildZoneIDs(cfg)
	total := 0
	for batch := 0; batch < maxBatches; batch++ {
		deltas, _, err := drainer.DrainSessionDeltas(256)
		if err != nil {
			return total, err
		}
		if len(deltas) == 0 {
			break
		}
		total += d.queueUserspaceSessionDeltas(zoneIDs, deltas)
		if len(deltas) < 256 {
			break
		}
	}
	return total, nil
}

func (d *Daemon) exportUserspaceOwnerRGSessionsWithConfig(
	exporter userspaceSessionExporter,
	cfg *config.Config,
	rgIDs []int,
) (int, error) {
	if exporter == nil || cfg == nil || len(rgIDs) == 0 {
		return 0, nil
	}
	deltas, _, err := exporter.ExportOwnerRGSessions(rgIDs, 0)
	if err != nil {
		return 0, err
	}
	return d.queueUserspaceSessionDeltas(buildZoneIDs(cfg), deltas), nil
}

func (d *Daemon) tryPrepareUserspaceRGDemotion(rgID int) {
	if err := d.prepareUserspaceRGDemotionWithTimeout(rgID, 5*time.Second); err != nil {
		slog.Warn("userspace: prepare rg demotion failed", "rg", rgID, "err", err)
	}
}

func (d *Daemon) acquireUserspaceRGDemotionPrep(rgID int, hold time.Duration) bool {
	d.userspaceDemotionPrepMu.Lock()
	defer d.userspaceDemotionPrepMu.Unlock()
	now := time.Now()
	if until, ok := d.userspaceDemotionPrepUntil[rgID]; ok && now.Before(until) {
		return false
	}
	if hold < 10*time.Second {
		hold = 10 * time.Second
	}
	d.userspaceDemotionPrepUntil[rgID] = now.Add(hold)
	return true
}

// releaseUserspaceRGDemotionPrep clears the suppression window so retries
// (e.g. manual failover admission) can re-attempt demotion prep immediately.
func (d *Daemon) releaseUserspaceRGDemotionPrep(rgID int) {
	d.userspaceDemotionPrepMu.Lock()
	defer d.userspaceDemotionPrepMu.Unlock()
	delete(d.userspaceDemotionPrepUntil, rgID)
}

func (d *Daemon) prepareUserspaceRGDemotion(rgID int) error {
	return d.prepareUserspaceRGDemotionWithTimeout(rgID, 30*time.Second)
}

func wrapUserspaceManualFailoverPrepareError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "previous demotion barrier still pending") ||
		strings.Contains(msg, "session sync not ready before demotion") ||
		strings.Contains(msg, "session sync peer not quiescent before demotion") ||
		strings.Contains(msg, "demotion peer barrier failed") {
		return &cluster.RetryablePreFailoverError{Err: err}
	}
	return err
}

func userspaceManualFailoverTransferReadinessError(state cluster.TransferReadinessSnapshot) error {
	if state.ReadyForManualFailover() {
		return nil
	}
	if reason := state.Reason(); reason != "" {
		return fmt.Errorf("session sync transfer not ready before demotion: %s", reason)
	}
	return nil
}

type userspaceTransferReadinessProvider interface {
	IsConnected() bool
	PeerHealthy() bool
	TransferReadiness() cluster.TransferReadinessSnapshot
}

type userspaceHAProtocolMismatchProvider interface {
	HAProtocolVersionMismatch() (bool, uint16, uint16)
}

func userspaceHAProtocolMismatchReason(provider userspaceHAProtocolMismatchProvider) []string {
	if provider == nil {
		return nil
	}
	if mismatch, local, peer := provider.HAProtocolVersionMismatch(); mismatch {
		return []string{fmt.Sprintf("ha protocol mismatch local=%d peer=%d", local, peer)}
	}
	return nil
}

func computeUserspaceTransferReadiness(sync userspaceTransferReadinessProvider, syncPeerConnected bool) (bool, []string) {
	if !sync.IsConnected() || !sync.PeerHealthy() || !syncPeerConnected {
		return false, []string{"session sync disconnected"}
	}
	state := sync.TransferReadiness()
	if state.ReadyForManualFailover() {
		return true, nil
	}
	if reason := state.Reason(); reason != "" {
		return false, []string{reason}
	}
	return true, nil
}

func (d *Daemon) userspaceTransferReadiness(rgID int) (bool, []string) {
	if d.cluster != nil {
		if reasons := userspaceHAProtocolMismatchReason(d.cluster); len(reasons) > 0 {
			return false, reasons
		}
	}
	if d.sessionSync == nil {
		return false, []string{"session sync disconnected"}
	}
	return computeUserspaceTransferReadiness(d.sessionSync, d.syncPeerConnected.Load())
}

func (d *Daemon) prepareUserspaceManualFailover(rgID int) error {
	return wrapUserspaceManualFailoverPrepareError(
		d.prepareUserspaceRGDemotionWithTimeout(rgID, 60*time.Second),
	)
}

func (d *Daemon) prepareUserspaceRGDemotionWithTimeout(rgID int, barrierTimeout time.Duration) error {
	if !d.acquireUserspaceRGDemotionPrep(rgID, barrierTimeout) {
		slog.Info("userspace: skipping duplicate rg demotion prepare", "rg", rgID)
		return nil
	}
	success := false
	defer func() {
		if !success {
			d.releaseUserspaceRGDemotionPrep(rgID)
		}
	}()
	if d.sessionSync == nil || !d.sessionSync.IsConnected() {
		// Release suppression window so a reconnect + retry can re-run
		// the barrier check before the actual demotion proceeds.
		d.releaseUserspaceRGDemotionPrep(rgID)
		success = true
		return nil
	}
	// Transfer readiness (bulk sync state) is NOT checked here.
	// The barrier at the end of this function proves the peer has all
	// sessions. Planned failover should not depend on bulk sync state —
	// both nodes have full session state from continuous real-time sync.

	// Stop the bulk sync retry loop — it floods the sync TCP connection
	// with session data, delaying the barrier write/ack by 30+ seconds.
	// Advancing the retry generation causes the goroutine to exit.
	retryGen := d.syncPrimeRetryGen.Add(1)

	// If the barrier fails, restart the retry loop so the peer can still
	// receive its cold-start bootstrap. Only suppress the restart when
	// the barrier succeeds and the demotion completes (success=true).
	defer func() {
		if success {
			return
		}
		if d.syncPeerBulkPrimed.Load() {
			return // peer already primed, no retry needed
		}
		ss := d.sessionSync
		if ss == nil || !ss.IsConnected() {
			return // peer disconnected, retry would be pointless
		}
		if d.syncPrimeRetryGen.Load() != retryGen {
			return // a newer retry generation is already active
		}
		slog.Info("cluster: restarting bulk-prime retry loop after failed demotion prep",
			"retry_gen", retryGen, "rg", rgID)
		d.startSessionSyncPrimeRetry(retryGen)
	}()

	// Single barrier — peer ack means it has processed all queued deltas.
	// The actual demotion happens atomically in UpdateRGActive(false).
	if err := d.sessionSync.WaitForPeerBarrier(barrierTimeout); err != nil {
		return fmt.Errorf("demotion peer barrier failed: %w", err)
	}

	success = true
	slog.Info("userspace: peer barrier ready for rg demotion", "rg", rgID)
	return nil
}

// userspaceDataplaneActive returns true when the userspace dataplane is
// running in a mode that handles forwarding (not eBPF-only). Callers use
// this to skip eBPF-specific workarounds (blackhole routes) that the
// userspace pipeline doesn't need.
func (d *Daemon) userspaceDataplaneActive() bool {
	if um, ok := d.dp.(*dpuserspace.Manager); ok {
		return um.Mode() != dpuserspace.ModeEBPFOnly
	}
	return false
}

func userspaceRGConfigured(cfg *config.Config, rgID int) bool {
	if cfg == nil || cfg.System.DataplaneType != dataplane.TypeUserspace || rgID <= 0 {
		return false
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc != nil && ifc.RedundancyGroup == rgID {
			return true
		}
	}
	return false
}

// checkUserspaceTakeoverReadiness returns whether the userspace dataplane
// is ready to take over forwarding for the given RG. Returns (true, nil)
// for non-userspace RGs or when the dataplane is healthy.
func (d *Daemon) checkUserspaceTakeoverReadiness(rgID int) (bool, []string) {
	cfg := d.store.ActiveConfig()
	if !userspaceRGConfigured(cfg, rgID) {
		return true, nil
	}
	// Copilot fix: if dp is nil or wrong type but config says userspace,
	// the dataplane isn't ready — don't report takeover-ready.
	if d.dp == nil {
		return false, []string{fmt.Sprintf("userspace dataplane not initialized for RG %d", rgID)}
	}
	um, ok := d.dp.(*dpuserspace.Manager)
	if !ok {
		return false, []string{fmt.Sprintf("userspace dataplane manager not available for RG %d", rgID)}
	}
	return um.TakeoverReady()
}
