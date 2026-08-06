// Daemon-side glue invoked from CLI commit / rollback paths. The CLI
// owns these only when no daemon-supplied apply callback has been
// wired; in production xpfd wires applyConfigFn to its own reconcile
// loop and these helpers are skipped.
package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/psaab/xpf/pkg/logging"
)

// syslogZoneNameMap builds the zone-id -> name reverse map for structured
// (RT_FLOW) syslog rendering. The zone-id namespace is the STABLE name-hash
// config.StableZoneID(name) (#3075) — the SAME namespace the compiler installs
// into the dataplane and the daemon publishes via applySyslogConfig /
// buildZoneIDs (daemon_ha_userspace.go). This is load-bearing because the event
// reader is SHARED with the daemon (daemon_run.go builds the embedded CLI with
// d.eventReader) and reloadSyslog runs on every LOCAL-CONSOLE commit/rollback
// AFTER the daemon reconcile already set the name-hash map: the previous
// sorted-positional (i+1) assignment CLOBBERED the shared map with wrong ids,
// regressing local-TTY commits to `zone-N` RT_FLOW rendering while
// gRPC/remote/API commits stayed correct (#3704 follow-up). StableZoneID is a
// pure function of the name, so this write is byte-identical to the daemon's
// regardless of reconcile ordering.
func syslogZoneNameMap(cfg *config.Config) map[uint16]string {
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	// #3719: under a StableZoneID collision two zone names fold to the same id,
	// and the dataplane installs only the sorted-first (the survivor
	// config.QuarantinedZoneNames keeps). Skip the quarantined zone so the
	// reverse map names the id after the zone actually installed rather than
	// whichever name won a map-iteration overwrite race — RT_FLOW/syslog would
	// otherwise render the wrong zone for the surviving zone's traffic.
	quarantined := config.QuarantinedZoneNames(names)
	znMap := make(map[uint16]string, len(names))
	for _, name := range names {
		if _, drop := quarantined[name]; drop {
			continue
		}
		znMap[config.StableZoneID(name)] = name
	}
	return znMap
}

// reloadSyslog rebuilds the syslog client set and zone-name mapping from
// the supplied config. Safe to call with a nil event reader.
func (c *CLI) reloadSyslog(cfg *config.Config) {
	if c.eventReader == nil {
		return
	}
	c.eventReader.SetZoneNames(syslogZoneNameMap(cfg))

	// #5738 gap 2: honor event mode exactly like the daemon's applySyslogConfig.
	// In event mode the daemon CLEARS remote clients and installs a LOCAL writer;
	// the previous CLI reload unconditionally rebuilt remote clients from Streams,
	// so a config with BOTH event-mode AND remote streams re-installed the remote
	// clients the daemon had cleared (the CLI reload runs LAST on a local commit).
	if cfg.Security.Log.Mode == "event" {
		c.eventReader.ReplaceSyslogClients(nil) // close + clear any remote clients
		lw, err := logging.NewLocalLogWriter(logging.LocalLogConfig{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to create local log writer: %v\n", err)
		} else {
			if cfg.Security.Log.Format != "" {
				lw.Format = cfg.Security.Log.Format
			}
			c.eventReader.ReplaceLocalWriters([]*logging.LocalLogWriter{lw})
		}
		return
	}

	// Stream mode (default): clear local writers, install remote clients.
	c.eventReader.ReplaceLocalWriters(nil)
	c.eventReader.ReplaceSyslogClients(buildSyslogClients(cfg))
}

// buildSyslogClients constructs the syslog client set from the committed
// config's `security log stream` stanzas. It is the CLI-side, in-process
// commit/rollback counterpart of the daemon's applySyslogConfig
// (pkg/daemon/daemon_system.go) and MUST honor the configured transport the
// same way.
//
// #5712: this path runs on EVERY local-console commit/rollback (reloadSyslog,
// #3704) on the SHARED event reader, AFTER the daemon reconcile already
// installed the correct clients. It previously reconstructed every stream as
// plaintext UDP via NewSyslogClient — a duplicate runtime owner that
// CLOBBERED a configured TCP/TLS stream back down to UDP, silently downgrading
// the secure-syslog transport after an in-process commit. Building through
// NewSyslogClientTransport with the stream's configured protocol makes this
// rebuild PRESERVE the transport (idempotent with the daemon's build), so the
// single-owner posture holds regardless of which owner writes last. The
// per-stream source-address and facility are carried too, matching the daemon.
//
// A TCP/TLS receiver unreachable at commit returns a usable-but-unconnected
// client (#3351); it is installed in the reconnecting state rather than
// dropped, mirroring applySyslogConfig. Only a nil client (UDP construction
// failure, or an unsupported/typo'd transport rejected fail-closed by #5581)
// skips the stream.
func buildSyslogClients(cfg *config.Config) []*logging.SyslogClient {
	// #5738 gap 1: resolve the global `security log source-interface` to an IP,
	// used as the source binding for any stream that lacks a per-stream
	// source-address. applySyslogConfig computes and applies this same fallback,
	// so the previous CLI path (which passed stream.SourceAddress unconditionally)
	// bound a kernel-chosen source on an in-process commit while the daemon bound
	// the interface address — a divergence that persists because the CLI reload
	// writes LAST on a local commit. Mirror the daemon exactly.
	var globalSourceAddr string
	if cfg.Security.Log.SourceInterface != "" {
		globalSourceAddr = config.ResolveSyslogSourceAddr(cfg, cfg.Security.Log.SourceInterface)
	}
	var clients []*logging.SyslogClient
	for name, stream := range cfg.Security.Log.Streams {
		srcAddr := stream.SourceAddress
		if srcAddr == "" {
			srcAddr = globalSourceAddr
		}
		protocol := stream.Transport.Protocol
		if protocol == "" {
			protocol = "udp"
		}
		// The final *tls.Config is nil — a TLS stream trusts the system CA
		// roots; a named transport tls-profile is rejected at commit
		// (validateSecurityLogStreamTLSProfileAST), matching applySyslogConfig.
		// #6829 round 8: classify the facility BEFORE constructing the client.
		// Construction DIALS, and an unmappable facility is the one diagnosis
		// that does not depend on the network being up — the same reasoning
		// already written at the host site. Measured before this change: a
		// stream with `host 192.0.2.10` (TEST-NET, UDP construction returns
		// nil,err) was skipped by the `client == nil` continue below and the
		// operator was never told the facility was ALSO unmappable.
		//
		// SPLIT, not moved, and this is the load-bearing part. The old position
		// supplied something besides ordering: `client` is guaranteed non-nil
		// there precisely BECAUSE the nil case already `continue`d. Hoisting the
		// whole block would put `client.Facility` on a pointer that does not
		// exist yet. So only the COMPUTE half moves — it needs nothing from
		// client — and the ASSIGN half stays below the continue, keeping the
		// same guarantee from the same source.
		//
		// haveFacility preserves the original conditional assignment: a stream
		// with no facility must keep the constructor default rather than be
		// overwritten with a zero value.
		var facility int
		var haveFacility bool
		if stream.Facility != "" {
			// #6829 A2: use the CHECKED form and report the substitution. The
			// schema enum gates this on the STRICT path only —
			// configstore.Store downgrades the gate to a warning on Load (boot)
			// and SyncApply (HA peer sync), so an unmappable name reaches here
			// on exactly the tolerant paths the severity belt is built for.
			// Untold, every record on this stream leaves under local0 while
			// `show system syslog` still reports the authored name.
			f, known := logging.ParseFacilityChecked(stream.Facility)
			if !known && !logging.FacilityIsWildcard(stream.Facility) {
				slog.Warn("security log: unmapped facility name; forwarding under local0 — "+
					"records will carry a facility the configuration does not name (#5797)",
					"facility", stream.Facility, "using", "local0")
			}
			facility, haveFacility = f, true
		}
		client, err := logging.NewSyslogClientTransport(stream.Host, stream.Port, srcAddr, protocol, nil)
		if err != nil {
			if client == nil {
				fmt.Fprintf(os.Stderr, "warning: syslog stream %s (%s): %v\n", name, protocol, err)
				continue
			}
			// #3351: TCP/TLS receiver unreachable at apply — install reconnecting.
			fmt.Fprintf(os.Stderr, "warning: syslog stream %s (%s) receiver unreachable; installed in reconnecting state: %v\n", name, protocol, err)
		}
		if stream.Severity != "" {
			client.MinSeverity = logging.ParseSeverity(stream.Severity)
		}
		if haveFacility {
			// Assign half — see the classification block above the client
			// construction. This stays below the `client == nil` continue
			// because that continue is what makes the pointer safe here.
			client.Facility = facility
		}
		if stream.Category != "" {
			client.Categories = logging.ParseCategory(stream.Category)
		}
		// Per-stream format overrides global log format
		format := stream.Format
		if format == "" {
			format = cfg.Security.Log.Format
		}
		if format != "" {
			client.Format = format
		}
		clients = append(clients, client)
	}
	return clients
}

// applyToDataplane drives the legacy CLI-side apply sequence: tunnel
// interfaces, eBPF compile, FRR config, then IPsec. Only used when the
// daemon does not wire applyConfigFn (e.g. CLI spawned standalone for
// testing). When applyConfigFn IS wired, the daemon's full reconcile
// runs instead and this function is skipped.
func (c *CLI) applyToDataplane(cfg *config.Config) error {
	// 1. Create tunnel interfaces first
	if c.routing != nil {
		var tunnels []*config.TunnelConfig
		for _, ifc := range cfg.Interfaces.Interfaces {
			if ifc == nil { // #5886: skip present-but-nil InterfaceConfig
				continue
			}
			if ifc.Tunnel != nil && ifc.Tunnel.Source != "" {
				tunnels = append(tunnels, ifc.Tunnel)
			}
			for _, unit := range ifc.Units {
				if unit == nil { // #5886: skip present-but-nil InterfaceUnit
					continue
				}
				if unit.Tunnel != nil {
					tunnels = append(tunnels, unit.Tunnel)
				}
			}
		}
		if err := c.routing.ApplyTunnels(tunnels); err != nil {
			fmt.Fprintf(os.Stderr, "warning: tunnel apply failed: %v\n", err)
		}
		if err := c.routing.ApplyXfrmi(cfg.Security.IPsec.VPNs); err != nil {
			fmt.Fprintf(os.Stderr, "warning: xfrmi apply failed: %v\n", err)
		}
	}

	// 2. Compile eBPF dataplane
	if c.dp != nil && c.dp.IsLoaded() {
		if _, err := c.dp.Compile(cfg); err != nil {
			return err
		}
	}

	// 3. Apply all routes + dynamic protocols via FRR
	if c.frr != nil {
		// Collect interface bandwidths and point-to-point flags for FRR.
		ifaceBandwidths := make(map[string]uint64)
		ifaceP2P := make(map[string]bool)
		for name, ifc := range cfg.Interfaces.Interfaces {
			if ifc == nil { // #5886: skip present-but-nil InterfaceConfig
				continue
			}
			if ifc.Bandwidth > 0 {
				ifaceBandwidths[name] = ifc.Bandwidth
			}
			for _, unit := range ifc.Units {
				if unit == nil { // #5886: skip present-but-nil InterfaceUnit
					continue
				}
				if unit.PointToPoint {
					ifaceP2P[name] = true
				}
			}
		}

		fc := &frr.FullConfig{
			OSPF:                  cfg.Protocols.OSPF,
			OSPFv3:                cfg.Protocols.OSPFv3,
			BGP:                   cfg.Protocols.BGP,
			StaticRoutes:          cfg.RoutingOptions.StaticRoutes,
			InterfaceBandwidths:   ifaceBandwidths,
			InterfacePointToPoint: ifaceP2P,
		}
		if c.dhcp != nil {
			for _, lease := range c.dhcp.Leases() {
				if !lease.Gateway.IsValid() {
					continue
				}
				fc.DHCPRoutes = append(fc.DHCPRoutes, frr.DHCPRoute{
					Gateway:   lease.Gateway.String(),
					Interface: lease.Interface,
					IsIPv6:    lease.Family == dhcp.AFInet6,
				})
			}
		}
		for _, ri := range cfg.RoutingInstances {
			// Mirror daemon assembleFRRConfig (#1827 PR-2): forwarding
			// instances have no VRF device — render their statics into
			// the instance's dedicated kernel table.
			vrfName := "vrf-" + ri.Name
			tableID := 0
			if ri.InstanceType == "forwarding" {
				vrfName = ""
				tableID = ri.TableID
			}
			fc.Instances = append(fc.Instances, frr.InstanceConfig{
				Name:         ri.Name,
				VRFName:      vrfName,
				TableID:      tableID,
				OSPF:         ri.OSPF,
				OSPFv3:       ri.OSPFv3,
				BGP:          ri.BGP,
				StaticRoutes: ri.StaticRoutes,
			})
		}
		if err := c.frr.ApplyFull(fc); err != nil {
			fmt.Fprintf(os.Stderr, "warning: FRR apply failed: %v\n", err)
		}
	}

	// 5. Apply IPsec config
	if c.ipsec != nil {
		if err := c.ipsec.Apply(ipsec.PrepareConfig(cfg)); err != nil {
			fmt.Fprintf(os.Stderr, "warning: IPsec apply failed: %v\n", err)
		}
	}

	return nil
}
