# Codex hostile plan review r1 — #1918 — task-mqho5rhv-3z75hl

Verdict: PLAN-NEEDS-WORK

- F1 MAJOR — datagram ICMP ID matching contradictory/wrong; ID rewritten to socket port for
  udp4/udp6 ping sockets; x/net/icmp returns substituted ID. Match on Seq + Data nonce; ID
  advisory only; raw fallback may use self-chosen ID.
- F2 MAJOR — VRF binding mechanics not concrete; icmp.ListenPacket has no Control hook; need a
  custom ping-socket constructor for SO_BINDTODEVICE (probeDialer sets it in Dialer.Control).
- F3 MAJOR — keepaliveRunner.matches() (tunnel.go:78-86) compares only remote/interval/retries;
  RI-only change retains stale runner probing the old VRF. Add VRF to identity or fetch per probe.
- F4 MAJOR — Axis D guarantees one in-memory decision, not one correct netlink effect; LinkByName
  transient failure after Up=false → no retry; same-name link recreate TOCTOU. Need
  generation/ifindex validation + error retry + earlier drain.
- F5 MINOR — C1 is right default but call it hold-on-unknown; update KeepaliveUp==nil contract
  (configured-but-unknown vs not-configured).
- F6 NIT — "§6 Option F" dangling (should be Axis C); pkg/rpm function is probeDialer not vrfDialer.

Required: rewrite §5a/§7 to Seq+nonce; specify VRF socket construction or drop it; VRF in runner
identity or per-probe; Axis D netlink-error + recreate handling; rename C1 + nil contract; fix nits.
