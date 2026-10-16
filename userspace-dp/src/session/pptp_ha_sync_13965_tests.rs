use crate::ip_proto::PROTO_GRE;
use crate::session::tests::{decision, key_v4, metadata};
use crate::session::{
    ExportProvenance, SessionDeltaKind, SessionKey, SessionOrigin, SessionTable,
    TunnelDiscriminator,
};
use std::net::IpAddr;

#[test]
fn live_pptp_open_and_bulk_export_carry_the_call_id_pair_13965() {
    let src: IpAddr = "198.51.100.7".parse().unwrap();
    let dst: IpAddr = "203.0.113.9".parse().unwrap();
    let call = crate::session::pptp::PptpCall::new(src, 0x1111, dst, 0x2222);
    let now_ns = 1_000_000_000;
    let mut table = SessionTable::new();
    table
        .pptp_mut()
        .install_synced_association(call, now_ns)
        .expect("install synced association");

    let key = SessionKey {
        protocol: PROTO_GRE,
        discriminator: TunnelDiscriminator::Pptp(call.handle()),
        src_ip: src,
        dst_ip: dst,
        ..key_v4()
    };
    assert!(
        table.install_with_protocol(key.clone(), decision(), metadata(), now_ns, PROTO_GRE, 0,)
    );

    let expected = call.to_wire_call_ids();
    let incremental = table.drain_deltas(8);
    assert_eq!(incremental.len(), 1);
    assert_eq!(incremental[0].pptp_call_ids, expected);

    let bulk = table.open_export_delta_with_provenance(
        key.clone(),
        decision(),
        metadata(),
        SessionOrigin::ForwardFlow,
        false,
        ExportProvenance::Incremental,
    );
    let bulk = bulk.expect("live forward PPTP session is exportable");
    assert_eq!(bulk.kind, SessionDeltaKind::Open);
    assert_eq!(bulk.key, key);
    assert_eq!(bulk.pptp_call_ids, expected);
}
