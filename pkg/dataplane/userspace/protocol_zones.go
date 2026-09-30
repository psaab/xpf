package userspace

type ZoneSnapshot struct {
	Name string `json:"name"`
	ID   uint16 `json:"id"`
	// HostInbound* carry the zone's `host-inbound-traffic` admission set
	// (#3070). Before #3070 the zone's host-inbound system-service / protocol
	// set was parsed and modeled in Go but NEVER reached the dataplane, so
	// host-bound traffic (traffic destined to a firewall-local interface IP:
	// SSH, ping, routing protocols on the box itself) was admitted regardless
	// of the configured set — a security-boundary gap.
	//
	// HostInboundConfigured marks the zone host-inbound ENFORCING. Post-#3405
	// buildZoneSnapshots sets it true for EVERY configured zone (Junos
	// default-deny parity), so the Rust side default-denies host-bound
	// (local-delivery) traffic whose system-service / protocol is not in the
	// configured set — a zone with no `host-inbound-traffic` stanza carries an
	// EMPTY set and thus deny-all. (Pre-#3405 a false here preserved the
	// historical admit-all for a no-stanza zone; that no-opt-in admit-all was a
	// management-plane exposure and is gone.) Global ICMP/ND/PMTUD accepts
	// (#3171) and lifeline interfaces (fxp0 plus explicitly configured
	// control/fabric links) still bypass this deny.
	//
	// The token slices mirror config.HostInboundTraffic verbatim (lower-cased,
	// order-preserved). The Rust side classifies the tokens to L4 signatures
	// (proto + port / icmp) — keeping the wire as the raw Junos tokens means
	// the Go↔Rust contract stays byte-identical and the (large) token→port
	// mapping lives in one place (#1961 discipline). serde(default) on the
	// Rust side keeps wire parity with an older Go control plane that omits
	// these fields.
	HostInboundConfigured     bool     `json:"host_inbound_configured,omitempty"`
	HostInboundSystemServices []string `json:"host_inbound_system_services,omitempty"`
	HostInboundProtocols      []string `json:"host_inbound_protocols,omitempty"`
	// TCPRst carries the Junos `security zones security-zone <z> tcp-rst`
	// knob (#3071). When true, a non-SYN TCP transit packet dropped for a
	// session miss may receive a TCP RST toward its source when this is its
	// INGRESS (from) zone. Policy `deny` remains a silent drop. Additive wire
	// field: an old Rust helper without the field treats every zone as
	// tcp-rst off (pre-#3071 behavior); an old Go binary omits it (omitempty).
	TCPRst bool `json:"tcp_rst,omitempty"`
}

// ScreenProfileSnapshot captures a per-zone screen profile for the userspace
// dataplane. Mirrors the BPF screen_config structure.
type ScreenProfileSnapshot struct {
	Zone               string `json:"zone"`
	Land               bool   `json:"land,omitempty"`
	SynFin             bool   `json:"syn_fin,omitempty"`
	NoFlag             bool   `json:"tcp_no_flag,omitempty"`
	FinNoAck           bool   `json:"fin_no_ack,omitempty"`
	WinNuke            bool   `json:"winnuke,omitempty"`
	PingDeath          bool   `json:"ping_death,omitempty"`
	Teardrop           bool   `json:"teardrop,omitempty"`
	ICMPFragment       bool   `json:"icmp_fragment,omitempty"`
	SynFrag            bool   `json:"syn_frag,omitempty"`
	SourceRoute        bool   `json:"source_route,omitempty"`
	ICMPFloodThreshold uint32 `json:"icmp_flood_threshold,omitempty"`
	UDPFloodThreshold  uint32 `json:"udp_flood_threshold,omitempty"`
	SYNFloodThreshold  uint32 `json:"syn_flood_threshold,omitempty"`
	SYNCookie          bool   `json:"syn_cookie,omitempty"`
	// #3315: SYN-flood sub-thresholds. The Go compiler parses the full Junos
	// syn-flood shape (alarm/attack/source/destination/timeout) but only
	// attack-threshold (SYNFloodThreshold above) used to cross the wire, so the
	// other controls committed cleanly yet were operationally inert. These three
	// carry the per-source / per-destination caps and the log-only alarm rate to
	// the Rust dataplane. Additive + omitempty: an old helper missing these
	// decodes them as 0 (disabled), so version skew degrades safely (#1961
	// no-transit class).
	SYNFloodAlarmThreshold uint32 `json:"syn_flood_alarm_threshold,omitempty"`
	SYNFloodDstThreshold   uint32 `json:"syn_flood_dst_threshold,omitempty"`
	SYNFloodSrcThreshold   uint32 `json:"syn_flood_src_threshold,omitempty"`
	// #3527: the Junos `syn-flood timeout` (SECONDS), the
	// half-completed-connection queue window. Unlike the sub-thresholds above it
	// is NOT a screen-rate control — it maps to the per-zone half-open TCP
	// session window (tcp_opening_ns, 20 s default). The dataplane turns it into
	// a per-ingress-zone override of tcp_opening_ns so a bare-SYN session in this
	// zone is reaped on the operator's window instead of the global default. This
	// closes the #3315 deferred leaf (the compiler no longer warns it is inert).
	// Additive + omitempty: an old helper missing it decodes 0 (global default).
	SYNFloodTimeout uint32 `json:"syn_flood_timeout,omitempty"`
	// Advanced screen features for userspace dataplane
	SessionLimitSrc   uint32 `json:"session_limit_src,omitempty"`
	SessionLimitDst   uint32 `json:"session_limit_dst,omitempty"`
	PortScanThreshold uint32 `json:"port_scan_threshold,omitempty"`
	IPSweepThreshold  uint32 `json:"ip_sweep_threshold,omitempty"`
	// AlarmWithoutDrop is the Junos profile-wide `alarm-without-drop`
	// audit/log-only mode. When true, the dataplane converts every screen
	// DROP verdict for this zone into a log-only PERMIT alarm (carrying the
	// tripped reason) and forwards the packet. Additive + omitempty: an old
	// helper missing the field decodes false (drop-on-trip — today's
	// behavior), so version skew degrades safely (#1961 no-transit class).
	AlarmWithoutDrop bool `json:"alarm_without_drop,omitempty"`
}

// ScreenMissingProfileRef names a zone that references a screen profile which
// was not defined when the snapshot was built (#3082). Carried on the wire so
// the dataplane can emit a runtime WARN for the lenient-path fail-open instead
// of silently passing all screen checks for the zone. The verdict still stays
// Pass — see ConfigSnapshot.ScreenMissingProfiles.
type ScreenMissingProfileRef struct {
	Zone    string `json:"zone"`
	Profile string `json:"profile,omitempty"`
	// AlarmWithoutDrop is the referenced profile's `alarm-without-drop`
	// modifier (#9425). It is MEANINGFUL ONLY on the ScreenInertProfiles set:
	// there the profile IS defined, so the operator's audit request is a real
	// statement the dataplane must honour when it substitutes the conservative
	// default. On the ScreenMissingProfiles (UNDEFINED) set there is no profile
	// to read it from and it is always false — the Rust side consults it only
	// on the inert arm, so the two sets cannot pick up each other's meaning
	// from this shared struct.
	//
	// Why it must travel: an inert zone gets NO `screens` entry, so
	// ScreenState::alarm_without_drop's `zones` lookup misses and returns
	// false — and since #7888 that zone hard-drops the substituted
	// conservative default's malformed-packet set. The single most likely way
	// to reach the inert state is `set security screen ids-option p
	// alarm-without-drop` and nothing else, i.e. an explicit request for audit
	// mode is precisely the configuration that turned audit mode off and
	// started dropping.
	//
	// Additive + omitempty, per the rolling-upgrade rule (ADD a field, never
	// redefine one): an old helper missing the field decodes false, which is
	// exactly today's hard-drop behaviour; an old Go binary that does not emit
	// it leaves the Rust side false, likewise. Neither direction is worse than
	// the status quo and no existing field changes meaning.
	AlarmWithoutDrop bool `json:"alarm_without_drop,omitempty"`
}
