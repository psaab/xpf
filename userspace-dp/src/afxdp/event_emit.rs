use super::*;
use crate::event_stream::codec::{DataplaneEventKind, DataplaneEventPayload};
use crate::event_stream::EventStreamWorkerHandle;
use crate::filter::FilterAction;
use crate::policy::PolicyAction;
use crate::screen::ScreenPacketInfo;

const RT_FLOW_ACTION_DENY: u8 = 0;
const RT_FLOW_ACTION_PERMIT: u8 = 1;
const RT_FLOW_ACTION_REJECT: u8 = 2;
const RT_FLOW_CLOSE_REASON_POLICY: u8 = 5;
const NS_PER_SEC: u64 = 1_000_000_000;

const SCREEN_SYN_FLOOD: u32 = 1 << 0;
const SCREEN_ICMP_FLOOD: u32 = 1 << 1;
const SCREEN_UDP_FLOOD: u32 = 1 << 2;
const SCREEN_PORT_SCAN: u32 = 1 << 3;
const SCREEN_IP_SWEEP: u32 = 1 << 4;
const SCREEN_LAND_ATTACK: u32 = 1 << 5;
const SCREEN_PING_OF_DEATH: u32 = 1 << 6;
const SCREEN_TEARDROP: u32 = 1 << 7;
const SCREEN_TCP_SYN_FIN: u32 = 1 << 8;
const SCREEN_TCP_NO_FLAG: u32 = 1 << 9;
const SCREEN_TCP_FIN_NO_ACK: u32 = 1 << 10;
const SCREEN_WINNUKE: u32 = 1 << 11;
const SCREEN_IP_SOURCE_ROUTE: u32 = 1 << 12;
const SCREEN_SYN_FRAG: u32 = 1 << 13;
const SCREEN_SYN_COOKIE: u32 = 1 << 14;
const SCREEN_SESSION_LIMIT_SRC: u32 = 1 << 15;
const SCREEN_SESSION_LIMIT_DST: u32 = 1 << 16;
const SCREEN_ICMP_FRAGMENT: u32 = 1 << 17;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FilterLogSource {
    Pbr,
    Input,
    Output,
    CachedOutput,
    Lo0,
}

impl FilterLogSource {
    #[inline]
    pub(super) fn wire_reason(self) -> u8 {
        match self {
            Self::Pbr => 1,
            Self::Input => 2,
            Self::Output => 3,
            Self::CachedOutput => 4,
            Self::Lo0 => 5,
        }
    }
}

#[inline]
pub(super) fn event_now_ns_from_secs(now_secs: u64) -> u64 {
    now_secs.saturating_mul(NS_PER_SEC)
}

#[inline]
pub(super) fn emit_policy_deny_event(
    event_stream: Option<&EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    ingress_zone_id: u16,
    egress_zone_id: u16,
    owner_rg_id: i32,
    policy_id: u32,
    action: PolicyAction,
    now_ns: u64,
) {
    let Some(event_stream) = event_stream else {
        return;
    };
    let event = DataplaneEventPayload {
        kind: DataplaneEventKind::PolicyDeny,
        addr_family: flow.forward_key.addr_family,
        protocol: flow.forward_key.protocol,
        action: policy_action_to_rt_flow(action),
        src_ip: flow.src_ip,
        dst_ip: flow.dst_ip,
        src_port: flow.forward_key.src_port,
        dst_port: flow.forward_key.dst_port,
        nat_src_ip: None,
        nat_dst_ip: None,
        nat_src_port: 0,
        nat_dst_port: 0,
        ingress_zone_id,
        egress_zone_id,
        ingress_ifindex: ingress_ifindex_to_wire(meta.ingress_ifindex),
        policy_id,
        rule_id: policy_id,
        term_id: 0,
        reason: RT_FLOW_CLOSE_REASON_POLICY,
        owner_rg_id: owner_rg_id_to_wire(owner_rg_id),
        application_id: 0,
        filter_id: 0,
        screen_id: 0,
        timestamp_ns: 0,
    };
    let _ = event_stream.try_emit_dataplane_event_at(event, now_ns);
}

#[inline]
pub(super) fn emit_screen_drop_event(
    event_stream: Option<&EventStreamWorkerHandle>,
    pkt: &ScreenPacketInfo,
    meta: UserspaceDpMeta,
    ingress_zone_id: u16,
    reason: &'static str,
    now_ns: u64,
) {
    let Some(event_stream) = event_stream else {
        return;
    };
    let event = DataplaneEventPayload {
        kind: DataplaneEventKind::ScreenDrop,
        addr_family: pkt.addr_family,
        protocol: pkt.protocol,
        action: RT_FLOW_ACTION_DENY,
        src_ip: pkt.src_ip,
        dst_ip: pkt.dst_ip,
        src_port: pkt.src_port,
        dst_port: pkt.dst_port,
        nat_src_ip: None,
        nat_dst_ip: None,
        nat_src_port: 0,
        nat_dst_port: 0,
        ingress_zone_id,
        egress_zone_id: 0,
        ingress_ifindex: ingress_ifindex_to_wire(meta.ingress_ifindex),
        policy_id: 0,
        rule_id: 0,
        term_id: 0,
        reason: 0,
        owner_rg_id: 0,
        application_id: 0,
        filter_id: 0,
        screen_id: screen_reason_id(reason),
        timestamp_ns: 0,
    };
    let _ = event_stream.try_emit_dataplane_event_at(event, now_ns);
}

#[inline]
pub(super) fn emit_filter_log_event(
    event_stream: Option<&EventStreamWorkerHandle>,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    ingress_zone_id: u16,
    egress_zone_id: u16,
    filter_id: u32,
    term_id: u32,
    action: FilterAction,
    source: FilterLogSource,
    now_ns: u64,
) {
    let Some(event_stream) = event_stream else {
        return;
    };
    let event = DataplaneEventPayload {
        kind: DataplaneEventKind::FilterLog,
        addr_family: flow.forward_key.addr_family,
        protocol: flow.forward_key.protocol,
        action: filter_action_to_rt_flow(action),
        src_ip: flow.src_ip,
        dst_ip: flow.dst_ip,
        src_port: flow.forward_key.src_port,
        dst_port: flow.forward_key.dst_port,
        nat_src_ip: None,
        nat_dst_ip: None,
        nat_src_port: 0,
        nat_dst_port: 0,
        ingress_zone_id,
        egress_zone_id,
        ingress_ifindex: ingress_ifindex_to_wire(meta.ingress_ifindex),
        policy_id: 0,
        rule_id: 0,
        term_id,
        reason: source.wire_reason(),
        owner_rg_id: 0,
        application_id: 0,
        filter_id,
        screen_id: 0,
        timestamp_ns: 0,
    };
    let _ = event_stream.try_emit_dataplane_event_at(event, now_ns);
}

#[inline]
fn policy_action_to_rt_flow(action: PolicyAction) -> u8 {
    match action {
        PolicyAction::Permit => RT_FLOW_ACTION_PERMIT,
        PolicyAction::Deny => RT_FLOW_ACTION_DENY,
        PolicyAction::Reject => RT_FLOW_ACTION_REJECT,
    }
}

#[inline]
fn filter_action_to_rt_flow(action: FilterAction) -> u8 {
    match action {
        FilterAction::Accept => RT_FLOW_ACTION_PERMIT,
        FilterAction::Discard => RT_FLOW_ACTION_DENY,
        FilterAction::Reject => RT_FLOW_ACTION_REJECT,
    }
}

#[inline]
fn ingress_ifindex_to_wire(ifindex: u32) -> i32 {
    ifindex.min(i32::MAX as u32) as i32
}

#[inline]
fn owner_rg_id_to_wire(owner_rg_id: i32) -> i16 {
    owner_rg_id.clamp(i16::MIN as i32, i16::MAX as i32) as i16
}

#[inline]
fn screen_reason_id(reason: &'static str) -> u32 {
    match reason {
        "syn-flood" => SCREEN_SYN_FLOOD,
        "icmp-flood" => SCREEN_ICMP_FLOOD,
        "udp-flood" => SCREEN_UDP_FLOOD,
        "port-scan" => SCREEN_PORT_SCAN,
        "ip-sweep" => SCREEN_IP_SWEEP,
        "land-attack" => SCREEN_LAND_ATTACK,
        "ping-of-death" => SCREEN_PING_OF_DEATH,
        "teardrop" => SCREEN_TEARDROP,
        "tcp-syn-fin" => SCREEN_TCP_SYN_FIN,
        "tcp-no-flag" => SCREEN_TCP_NO_FLAG,
        "tcp-fin-no-ack" => SCREEN_TCP_FIN_NO_ACK,
        "winnuke" => SCREEN_WINNUKE,
        "ip-source-route" => SCREEN_IP_SOURCE_ROUTE,
        "syn-frag" => SCREEN_SYN_FRAG,
        "syn-cookie" | "syn-cookie-unavailable" => SCREEN_SYN_COOKIE,
        "session-limit-src" => SCREEN_SESSION_LIMIT_SRC,
        "session-limit-dst" => SCREEN_SESSION_LIMIT_DST,
        "icmp-fragment" => SCREEN_ICMP_FRAGMENT,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_stream::codec::DataplaneEventKind;
    use crate::event_stream::{DataplaneEventRateLimitConfig, EventStreamWorkerHandle};
    use crate::session::SessionKey;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_flow() -> SessionFlow {
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
        SessionFlow {
            src_ip,
            dst_ip,
            forward_key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip,
                dst_ip,
                src_port: 49152,
                dst_port: 443,
            },
        }
    }

    fn test_meta() -> UserspaceDpMeta {
        UserspaceDpMeta {
            ingress_ifindex: 42,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            pkt_len: 60,
            ..UserspaceDpMeta::default()
        }
    }

    fn unlimited_handle() -> (
        EventStreamWorkerHandle,
        std::sync::mpsc::Receiver<crate::event_stream::EventFrame>,
    ) {
        crate::event_stream::test_worker_handle(
            8,
            DataplaneEventRateLimitConfig {
                events_per_second: 0,
                burst: 0,
            },
        )
    }

    #[test]
    fn policy_deny_event_emit_builds_rt_flow_payload() {
        let (handle, rx) = unlimited_handle();
        let flow = test_flow();

        emit_policy_deny_event(
            Some(&handle),
            &flow,
            test_meta(),
            7,
            9,
            3,
            101,
            PolicyAction::Deny,
            123,
        );

        let event = rx
            .try_recv()
            .expect("policy event frame")
            .decode_dataplane_event()
            .expect("policy event payload");
        assert_eq!(event.kind, DataplaneEventKind::PolicyDeny);
        assert_eq!(event.action, RT_FLOW_ACTION_DENY);
        assert_eq!(event.reason, RT_FLOW_CLOSE_REASON_POLICY);
        assert_eq!(event.ingress_zone_id, 7);
        assert_eq!(event.egress_zone_id, 9);
        assert_eq!(event.ingress_ifindex, 42);
        assert_eq!(event.policy_id, 101);
        assert_eq!(event.rule_id, 101);
        assert_eq!(event.owner_rg_id, 3);
        assert_eq!(event.src_port, 49152);
        assert_eq!(event.dst_port, 443);
        assert_eq!(event.timestamp_ns, 0);
        assert_eq!(handle.dataplane_event_stats().policy_deny.sent, 1);
    }

    #[test]
    fn screen_drop_event_emit_uses_screen_reason_flag() {
        let (handle, rx) = unlimited_handle();
        let pkt = ScreenPacketInfo {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            tcp_flags: TCP_FLAG_SYN,
            src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            src_port: 12345,
            dst_port: 80,
            tcp_seq: 1,
            tcp_ack: 0,
            tcp_mss: 1460,
            pkt_len: 60,
            is_fragment: false,
            is_first_fragment: false,
            ip_ihl: 5,
            ip_frag_off: 0,
            ip_total_len: 60,
        };

        emit_screen_drop_event(Some(&handle), &pkt, test_meta(), 11, "land-attack", 456);

        let event = rx
            .try_recv()
            .expect("screen event frame")
            .decode_dataplane_event()
            .expect("screen event payload");
        assert_eq!(event.kind, DataplaneEventKind::ScreenDrop);
        assert_eq!(event.action, RT_FLOW_ACTION_DENY);
        assert_eq!(event.screen_id, SCREEN_LAND_ATTACK);
        assert_eq!(event.ingress_zone_id, 11);
        assert_eq!(event.egress_zone_id, 0);
        assert_eq!(event.src_ip, pkt.src_ip);
        assert_eq!(event.dst_ip, pkt.dst_ip);
        assert_eq!(handle.dataplane_event_stats().screen_drop.sent, 1);
    }

    #[test]
    fn screen_reason_id_maps_icmp_fragment() {
        let (handle, rx) = unlimited_handle();
        let pkt = ScreenPacketInfo {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            tcp_flags: 0,
            src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)),
            src_port: 0,
            dst_port: 0,
            tcp_seq: 0,
            tcp_ack: 0,
            tcp_mss: 0,
            pkt_len: 60,
            is_fragment: true,
            is_first_fragment: false,
            ip_ihl: 5,
            ip_frag_off: 0x2000,
            ip_total_len: 60,
        };

        emit_screen_drop_event(Some(&handle), &pkt, test_meta(), 11, "icmp-fragment", 456);

        let event = rx
            .try_recv()
            .expect("screen event frame")
            .decode_dataplane_event()
            .expect("screen event payload");
        assert_eq!(event.kind, DataplaneEventKind::ScreenDrop);
        assert_eq!(event.screen_id, SCREEN_ICMP_FRAGMENT);
    }

    #[test]
    fn filter_log_event_emit_builds_rt_flow_payload() {
        let (handle, rx) = unlimited_handle();
        let flow = test_flow();

        emit_filter_log_event(
            Some(&handle),
            &flow,
            test_meta(),
            7,
            0,
            23,
            5,
            FilterAction::Accept,
            FilterLogSource::Input,
            789,
        );

        let event = rx
            .try_recv()
            .expect("filter event frame")
            .decode_dataplane_event()
            .expect("filter event payload");
        assert_eq!(event.kind, DataplaneEventKind::FilterLog);
        assert_eq!(event.action, RT_FLOW_ACTION_PERMIT);
        assert_eq!(event.filter_id, 23);
        assert_eq!(event.term_id, 5);
        assert_eq!(event.reason, FilterLogSource::Input.wire_reason());
        assert_eq!(event.ingress_zone_id, 7);
        assert_eq!(event.egress_zone_id, 0);
        assert_eq!(handle.dataplane_event_stats().filter_log.sent, 1);
    }
}
