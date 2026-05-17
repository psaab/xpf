use super::super::{EventStreamShared, EventStreamWorkerHandle};
use super::*;
use crate::event_stream::codec::{DataplaneEventKind, DataplaneEventPayload};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, mpsc};

fn test_handle(
    capacity: usize,
    config: DataplaneEventRateLimitConfig,
) -> (
    EventStreamWorkerHandle,
    mpsc::Receiver<crate::event_stream::EventFrame>,
    Arc<EventStreamShared>,
) {
    let (tx, rx) = mpsc::sync_channel(capacity);
    let shared = Arc::new(EventStreamShared::new_with_dataplane_event_rate(config));
    (
        EventStreamWorkerHandle {
            tx,
            shared: shared.clone(),
        },
        rx,
        shared,
    )
}

fn test_event(kind: DataplaneEventKind, ingress_zone_id: u16) -> DataplaneEventPayload {
    DataplaneEventPayload {
        kind,
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        action: 0,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        src_port: 12345,
        dst_port: 443,
        nat_src_ip: None,
        nat_dst_ip: None,
        nat_src_port: 0,
        nat_dst_port: 0,
        ingress_zone_id,
        egress_zone_id: 9,
        ingress_ifindex: 42,
        policy_id: 101,
        rule_id: 202,
        term_id: 303,
        reason: 5,
        owner_rg_id: 1,
        application_id: 404,
        filter_id: 505,
        screen_id: 606,
        timestamp_ns: 123_456_789,
    }
}

#[test]
fn dataplane_event_emit_queues_frame_and_counts_sent() {
    let (handle, rx, shared) = test_handle(4, DataplaneEventRateLimitConfig::default());

    let outcome =
        handle.try_emit_dataplane_event_at(test_event(DataplaneEventKind::PolicyDeny, 7), 0);

    assert_eq!(outcome, DataplaneEventEmitOutcome::Queued { seq: 1 });
    let frame = rx.try_recv().expect("queued event frame");
    assert_eq!(frame.seq, 1);
    assert_eq!(
        frame
            .decode_dataplane_event()
            .expect("decode queued dataplane event")
            .kind,
        DataplaneEventKind::PolicyDeny
    );
    assert_eq!(shared.frames_sent.load(Ordering::Relaxed), 1);
    assert_eq!(shared.frames_dropped.load(Ordering::Relaxed), 0);

    let stats = handle.dataplane_event_stats();
    assert_eq!(stats.policy_deny.sent, 1);
    assert_eq!(stats.policy_deny.dropped, 0);
}

#[test]
fn dataplane_event_rate_limit_is_per_kind_and_ingress_zone() {
    let config = DataplaneEventRateLimitConfig {
        events_per_second: 1,
        burst: 1,
    };
    let (handle, _rx, shared) = test_handle(8, config);

    assert_eq!(
        handle.try_emit_dataplane_event_at(test_event(DataplaneEventKind::PolicyDeny, 7), 0),
        DataplaneEventEmitOutcome::Queued { seq: 1 }
    );
    assert_eq!(
        handle.try_emit_dataplane_event_at(test_event(DataplaneEventKind::PolicyDeny, 7), 0),
        DataplaneEventEmitOutcome::Dropped {
            reason: DataplaneEventDropReason::RateLimited
        }
    );
    assert_eq!(
        handle.try_emit_dataplane_event_at(test_event(DataplaneEventKind::ScreenDrop, 7), 0),
        DataplaneEventEmitOutcome::Queued { seq: 2 }
    );
    assert_eq!(
        handle.try_emit_dataplane_event_at(test_event(DataplaneEventKind::PolicyDeny, 8), 0),
        DataplaneEventEmitOutcome::Queued { seq: 3 }
    );
    assert_eq!(
        handle.try_emit_dataplane_event_at(
            test_event(DataplaneEventKind::PolicyDeny, 7),
            1_000_000_000
        ),
        DataplaneEventEmitOutcome::Queued { seq: 4 }
    );

    assert_eq!(shared.next_seq.load(Ordering::Relaxed), 4);
    assert_eq!(shared.frames_sent.load(Ordering::Relaxed), 4);
    assert_eq!(shared.frames_dropped.load(Ordering::Relaxed), 1);

    let stats = handle.dataplane_event_stats();
    assert_eq!(stats.policy_deny.sent, 3);
    assert_eq!(stats.policy_deny.rate_limited, 1);
    assert_eq!(stats.policy_deny.dropped, 1);
    assert_eq!(stats.screen_drop.sent, 1);
    assert_eq!(stats.screen_drop.dropped, 0);
}

#[test]
fn dataplane_event_queue_full_counts_per_kind_drop() {
    let (handle, _rx, shared) = test_handle(
        1,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );

    assert_eq!(
        handle.try_emit_dataplane_event_at(test_event(DataplaneEventKind::FilterLog, 7), 0),
        DataplaneEventEmitOutcome::Queued { seq: 1 }
    );
    assert_eq!(
        handle.try_emit_dataplane_event_at(test_event(DataplaneEventKind::FilterLog, 7), 0),
        DataplaneEventEmitOutcome::Dropped {
            reason: DataplaneEventDropReason::QueueFull
        }
    );

    assert_eq!(shared.frames_sent.load(Ordering::Relaxed), 1);
    assert_eq!(shared.frames_dropped.load(Ordering::Relaxed), 1);
    assert_eq!(shared.next_seq.load(Ordering::Relaxed), 2);

    let stats = handle.dataplane_event_stats();
    assert_eq!(stats.filter_log.sent, 1);
    assert_eq!(stats.filter_log.queue_full, 1);
    assert_eq!(stats.filter_log.dropped, 1);
}

#[test]
fn dataplane_event_disconnected_counts_per_kind_drop() {
    let (handle, rx, shared) = test_handle(
        1,
        DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    drop(rx);

    assert_eq!(
        handle.try_emit_dataplane_event_at(test_event(DataplaneEventKind::ScreenDrop, 7), 0),
        DataplaneEventEmitOutcome::Dropped {
            reason: DataplaneEventDropReason::Disconnected
        }
    );

    assert_eq!(shared.frames_sent.load(Ordering::Relaxed), 0);
    assert_eq!(shared.frames_dropped.load(Ordering::Relaxed), 1);
    assert_eq!(shared.next_seq.load(Ordering::Relaxed), 1);

    let stats = handle.dataplane_event_stats();
    assert_eq!(stats.screen_drop.sent, 0);
    assert_eq!(stats.screen_drop.disconnected, 1);
    assert_eq!(stats.screen_drop.dropped, 1);
}
