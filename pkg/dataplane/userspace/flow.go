package userspace

import (
	"fmt"
	"log/slog"
	"math"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
)

// #1977: several FlowSnapshot/FlowExportSnapshot fields are Go signed `int` on
// the control-socket snapshot wire but Rust **unsigned** (u16/u32/u64). A
// negative or out-of-range value (e.g. an operator typo `tcp-mss-gre-in 70000`,
// or a sampling input-rate exceeding u32) serializes fine from Go but makes
// `serde_json::from_str::<ControlRequest>` ERROR on the helper, aborting the
// ENTIRE apply_snapshot decode — the helper stays unconfigured and forwarding
// silently breaks (the #1961 failure class). `buildFlowSnapshot` /
// `buildFlowExportSnapshot` are the sole pre-wire constructor of these structs
// (called only from `buildSnapshot`), so coercing each field into its Rust wire
// range here guards every input path (CLI, gRPC, file). In-range values pass
// through unchanged; out-of-range values are coerced to a safe sentinel and a
// single warning is logged (this runs once per config commit, never per
// packet). The complementary commit-time CLI validation (a clear `commit check`
// error instead of silent coercion) is tracked as a follow-up; this guard is
// the dataplane-safety guarantee.

// coerceWireU16 clamps an int destined for a Rust u16 wire field. Out-of-range
// (negative or >65535) becomes 0 — the "disabled"/"use default" sentinel these
// MSS fields already use (for GRE-out, Rust 0 means MTU-derived MSS).
func coerceWireU16(field string, v int) int {
	if v < 0 || v > math.MaxUint16 {
		slog.Warn("userspace: out-of-range u16 wire value coerced to 0 (#1977)",
			"field", field, "value", v)
		return 0
	}
	return v
}

// coerceWireU32Timeout clamps an int destined for a Rust u32 timeout field:
// negative -> 0 (= use default), >u32max -> u32max. u32max*1e9 fits in u64, so
// there is no Rust-side multiplication overflow at the cap.
func coerceWireU32Timeout(field string, v int) int {
	if v < 0 {
		slog.Warn("userspace: negative u32 wire timeout coerced to 0 (#1977)",
			"field", field, "value", v)
		return 0
	}
	if int64(v) > math.MaxUint32 {
		slog.Warn("userspace: out-of-range u32 wire timeout capped to u32 max (#1977)",
			"field", field, "value", v)
		return math.MaxUint32
	}
	return v
}

// coerceWireSessionTimeout clamps an int destined for a Rust u64 session-timeout
// field. The cap is MaxDurationSeconds (= MaxInt64/1e9), NOT u64 max, because
// the helper's SessionTimeouts::from_seconds multiplies seconds*1e9 without
// checked arithmetic; MaxDurationSeconds keeps the product within u64.
func coerceWireSessionTimeout(field string, v int) int {
	if v < 0 {
		slog.Warn("userspace: negative session timeout coerced to 0 (#1977)",
			"field", field, "value", v)
		return 0
	}
	if int64(v) > config.MaxDurationSeconds {
		slog.Warn("userspace: session timeout capped to MaxDurationSeconds (#1977)",
			"field", field, "value", v, "cap", config.MaxDurationSeconds)
		return int(config.MaxDurationSeconds)
	}
	return v
}

func buildFlowSnapshot(cfg *config.Config) FlowSnapshot {
	snap := FlowSnapshot{
		AllowDNSReply:     cfg.Security.Flow.AllowDNSReply,
		AllowEmbeddedICMP: cfg.Security.Flow.AllowEmbeddedICMP,
		// #2486: all-tcp now lands in its own wire field; the dataplane
		// applies it to plain forwarded SYNs (and as the gre-in / tunnel
		// fallback). ipsec-vpn is rejected at commit, so it is NOT sent
		// to the dataplane (it has no enforceable context there).
		TCPMSSAllTCP:       coerceWireU16("tcp_mss_all_tcp", cfg.Security.Flow.TCPMSSAllTCP),
		TCPMSSGreIn:        coerceWireU16("tcp_mss_gre_in", cfg.Security.Flow.TCPMSSGreIn),
		TCPMSSGreOut:       coerceWireU16("tcp_mss_gre_out", cfg.Security.Flow.TCPMSSGreOut),
		UDPSessionTimeout:  coerceWireSessionTimeout("udp_session_timeout", cfg.Security.Flow.UDPSessionTimeout),
		ICMPSessionTimeout: coerceWireSessionTimeout("icmp_session_timeout", cfg.Security.Flow.ICMPSessionTimeout),
		GREAcceleration:    cfg.Security.Flow.GREPerformanceAcceleration,
		PowerModeDisable:   cfg.Security.Flow.PowerModeDisable,
		Lo0FilterInputV4:   cfg.System.Lo0FilterInputV4,
		Lo0FilterInputV6:   cfg.System.Lo0FilterInputV6,
	}
	if ts := cfg.Security.Flow.TCPSession; ts != nil {
		snap.TCPSessionTimeout = coerceWireSessionTimeout(
			"tcp_session_timeout", ts.EstablishedTimeout)
		// #7342: the other three windows. Each goes through the same
		// MaxDurationSeconds clamp as established-timeout, for the same reason —
		// the helper multiplies seconds by 1e9 without checked arithmetic, so an
		// out-of-range value would wrap into a SHORT window rather than a long
		// one. Clamping here keeps the failure direction "held too long", which
		// an operator can see, rather than "reaped instantly", which looks like
		// a forwarding bug.
		snap.TCPInitialTimeout = coerceWireSessionTimeout(
			"tcp_initial_timeout", ts.InitialTimeout)
		snap.TCPClosingTimeout = coerceWireSessionTimeout(
			"tcp_closing_timeout", ts.ClosingTimeout)
		snap.TCPTimeWaitTimeout = coerceWireSessionTimeout(
			"tcp_time_wait_timeout", ts.TimeWaitTimeout)
		// #10703: carry both SYN-admission selectors. Strict mode overrides
		// the mid-stream no-syn-check opt-out.
		snap.TCPNoSynCheck = ts.NoSynCheck
		snap.TCPStrictSynCheck = ts.StrictSynCheck
	}
	snap.ALGDisableFlags = algDisableFlags(&cfg.Security.ALG)
	return snap
}

// algDisableFlags packs the `security alg <proto> disable` knobs into the
// bitfield the userspace dataplane consumes (#2008 H3/H4). The bit layout
// MUST match pkg/dataplane/compiler.go's legacy flow_config_map encoding and
// the Rust ALG_DISABLE_* constants: DNS=0x01, FTP=0x02, SIP=0x04, TFTP=0x08.
func algDisableFlags(alg *config.ALGConfig) uint8 {
	if alg == nil {
		return 0
	}
	var flags uint8
	if alg.DNSDisable {
		flags |= 0x01
	}
	if alg.FTPDisable {
		flags |= 0x02
	}
	if alg.SIPDisable {
		flags |= 0x04
	}
	if alg.TFTPDisable {
		flags |= 0x08
	}
	return flags
}

// buildAppCatalogSnapshot ships the L3/L4 application-identification catalog to
// the userspace dataplane (#2008 M5). The catalog assigns each configured
// application a numeric app_id and carries its protocol/port match rule; the
// dataplane stamps that app_id on a matching session at create time so `show
// security flow session` resolves a real application name instead of a port
// guess. The app_id values are produced by appid.BuildCatalog in the SAME
// sorted order with the SAME id assignment that pkg/dataplane.compileApplications
// uses for CompileResult.AppNames (the map ResolveSessionName consumes), so the
// stamped id resolves to the matching name on the show path.
//
// A BuildCatalog error is propagated, NOT swallowed into an empty catalog: a
// malformed application-set reference or an app_id-space overflow (#3438 H4)
// must fail the snapshot build closed so the apply path rejects the config and
// retains the prior dataplane state. The live apply path catches the same input
// earlier — compileApplications (the CompileUserspaceShim leg) hard-errors and
// aborts the apply before this builder runs — so in practice this returns nil
// here. But returning an empty catalog on error would silently degrade ALL
// session naming to UNKNOWN/tuple-guess instead of surfacing the fault, so the
// error is surfaced rather than masked.
func buildAppCatalogSnapshot(cfg *config.Config) ([]AppCatalogEntrySnapshot, error) {
	if cfg == nil {
		return nil, nil
	}
	cat, err := appid.BuildCatalog(cfg)
	if err != nil {
		return nil, fmt.Errorf("userspace: app catalog build failed (#2008 M5): %w", err)
	}
	if len(cat.Entries) == 0 {
		return nil, nil
	}
	out := make([]AppCatalogEntrySnapshot, 0, len(cat.Entries))
	for _, e := range cat.Entries {
		out = append(out, AppCatalogEntrySnapshot{
			AppID:       e.AppID,
			Protocol:    e.Protocol,
			DstPortLow:  e.DstPortLow,
			DstPortHigh: e.DstPortHigh,
			SrcPortLow:  e.SrcPortLow,
			SrcPortHigh: e.SrcPortHigh,
		})
	}
	return out, nil
}

// buildFlowExportSnapshot constructs the FlowExportSnapshot wire field.
//
// #2130: the userspace dataplane does NOT build/format the NetFlow/IPFIX
// flow records itself — flow export is owned entirely by the Go control
// plane (pkg/flowexport). The Rust FlowExporter that once consumed this
// snapshot was dead code (never wired into the forwarding path) and was
// removed; the helper now deserializes this field and ignores it. The
// field (and this builder) are retained as a documented-reserved wire
// contract so the #1977 decode-safety coercion tests
// (flow_wire_coerce_test.go, protocol/tests.rs) keep guarding the path and
// no cross-language wire break is introduced.
//
// #2460: the session-close records that drive flow export ARE now produced
// in userspace mode. On every session close the helper emits a SESSION_CLOSE
// RT_FLOW frame (EventFrameTypeSessionClose, type 14) on the raw
// dataplane-event channel; the daemon decodes it into a
// logging.EventRecord{Type:"SESSION_CLOSE"} via eventReader.ProcessRawEvent,
// which fires the NetFlow/IPFIX flowExportCallback / ipfixExportCallback
// (daemon_flowexport.go). The record carries the real 5-tuple, NAT tuple,
// zones, protocol, and — since #2501 — real per-session byte/packet volume
// (the helper accumulates per-session fwd/rev counters on the AF_XDP
// forwarding hot path and harvests them onto the SESSION_CLOSE frame's
// reserved [56:64]/[64:72]/[112:120]/[120:128] wire slots). The same
// counters are mirrored into the BPF conntrack map on the ~1s GC cadence so
// `show security flow session` reports live volume.
func buildFlowExportSnapshot(cfg *config.Config) *FlowExportSnapshot {
	if cfg == nil || cfg.Services.FlowMonitoring == nil {
		return nil
	}
	fm := cfg.Services.FlowMonitoring
	if fm.Version9 == nil || len(fm.Version9.Templates) == 0 {
		return nil
	}
	// Find sampling config for flow server
	if cfg.ForwardingOptions.Sampling == nil {
		return nil
	}
	for _, inst := range cfg.ForwardingOptions.Sampling.Instances {
		if inst == nil {
			continue
		}
		rate := inst.InputRate
		if rate <= 0 {
			rate = 1
		}
		// #1977: SamplingRate is a Rust u32; cap an out-of-range input rate so
		// it cannot abort the apply_snapshot decode.
		if int64(rate) > math.MaxUint32 {
			slog.Warn("userspace: sampling input rate capped to u32 max (#1977)",
				"value", inst.InputRate)
			rate = math.MaxUint32
		}
		families := []*config.SamplingFamily{inst.FamilyInet, inst.FamilyInet6}
		for _, fam := range families {
			if fam == nil {
				continue
			}
			for _, server := range fam.FlowServers {
				// #1977: CollectorPort is a Rust u16, so an absent (0),
				// negative or >65535 port cannot be exported — skip that
				// server rather than abort the whole export.
				//
				// #6565 row 11 / #7422: the verdict is now the SHARED
				// config.FlowServerExcludedReason, which the three show
				// surfaces also call, so a skipped collector can no longer
				// render as an active export target. The port-0 branch used to
				// `continue` SILENTLY — unlike its out-of-range sibling — so
				// there was not even a journal record; every exclusion now
				// warns with the same reason string the operator sees.
				if reason := config.FlowServerExcludedReason(server); reason != "" {
					addr, port := "", 0
					if server != nil {
						addr, port = server.Address, server.Port
					}
					slog.Warn("userspace: skipping flow-server excluded from the snapshot",
						"address", addr, "port", port, "reason", reason)
					continue
				}
				snap := &FlowExportSnapshot{
					CollectorAddress: server.Address,
					CollectorPort:    server.Port,
					SamplingRate:     rate,
				}
				// Use template config if the server references one
				if server.Version9Template != "" && fm.Version9.Templates != nil {
					if tmpl, ok := fm.Version9.Templates[server.Version9Template]; ok {
						snap.ActiveTimeout = coerceWireU32Timeout(
							"active_timeout", tmpl.FlowActiveTimeout)
						snap.InactiveTimeout = coerceWireU32Timeout(
							"inactive_timeout", tmpl.FlowInactiveTimeout)
					}
				}
				return snap
			}
		}
	}
	return nil
}
