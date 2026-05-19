# Userspace Dataplane: Full eBPF Migration Plan

Goal: eliminate every remaining fallback to the eBPF pipeline so the userspace dataplane handles 100% of transit traffic.

## Remaining Gates And Evidence Work

### Gate 1: NAT (fix gate — features already implemented)
- **DNAT**: Implemented but gate at line 217 still rejects it
- **NATv6v4**: NAT64 implemented, NATv6v4 config option is benign
- **Fix**: Remove DNAT and NATv6v4 from the gate check
- **Complexity**: Trivial

### Gate 2: Policy scheduler + hit counters
- `SchedulerName != ""` — QoS scheduling action on policy match
- `Count == true` — per-policy packet/byte counters
- **Implement**: Add per-policy counter tracking in Rust session table, add DSCP rewrite for scheduler
- **Complexity**: Low (counters), Medium (DSCP scheduling)

### Gate 3: Source NAT pool mode
- Pool-based SNAT with port allocation (not just interface mode)
- Requires: address pool management, port allocation (1024-65535 range), round-robin or hash-based selection
- **Complexity**: Medium

### Gate 4: GRE performance acceleration
- `cfg.Security.Flow.GREPerformanceAcceleration`
- eBPF fast-paths GRE key extraction into session ports for per-tunnel tracking
- **Implement**: Parse GRE key in userspace, use as port fields in session key
- **Complexity**: Low

### Gate 5: Advanced screen profiles
- SYN cookies: generate SYN-ACK cookies in XDP for SYN flood protection
- Port scan detection: track per-source unique destination ports
- IP sweep detection: track per-source unique destination IPs
- Per-IP session limits: cap sessions per source/destination IP
- **Implement**: SYN cookies need XDP packet generation; port scan/IP sweep need per-source hash maps; session limits need atomic counters
- **Complexity**: High (SYN cookies), Medium (others)

### Gate 6: Firewall filters + policers
- inet/inet6 filter chains with match criteria + actions
- Actions: accept, discard, count, log, routing-instance, DSCP rewrite, forwarding-class
- Policers: token bucket rate limiting, three-color marking
- **Implement**: Filter evaluation engine in Rust, token bucket in worker state
- **Complexity**: High

### Gate 7: IPsec/XFRM
- Tunnel/transport mode ESP processing, IKE negotiation
- XFRM interface management, SA lifecycle
- **Implement**: NOT feasible in pure userspace — ESP encryption/decryption is kernel XFRM
- **Approach**: Allow IPsec config but pass ESP/IKE to kernel via slow-path. Inner packets after kernel decapsulation enter userspace via tunnel interface XDP
- **Complexity**: Medium (passthrough approach)

### Gate 8: Tunnel interfaces (GRE/ip6gre transit)
- POINTOPOINT interfaces deliver raw IP (no Ethernet header)
- eBPF prepends pseudo-Ethernet header, strips on TX
- **Implement**: Detect tunnel interfaces in userspace worker, handle raw IP frames
- **Complexity**: Medium

### Evidence 9: Port mirroring
- Duplicate egress packets to a mirror port
- **Status**: Userspace runtime admission exists through bounded full-L2
  mirror clones, per-binding sampling, CoS reserve handling, and drop
  counters
- **Remaining**: Collect mirror-fidelity evidence and prove primary
  forwarding survives mirror pressure before removing the BPF source
- **Complexity**: Low

### Gate 10: Flow export (NetFlow v9)
- 1-in-N sampling, template-based export via UDP
- **Implement**: Sample sessions on creation, buffer flow records, export via UDP socket
- **Complexity**: Medium

### XDP Shim: Mid-stream TCP (NO_SESSION)
- Non-SYN TCP without existing session falls back to eBPF for RST generation
- **Implement**: Generate TCP RST in userspace worker, send via TX ring
- **Complexity**: Low

## Implementation Waves

### Wave A — Gate fixes + trivial (launch immediately)
| Feature | Complexity | Team |
|---------|-----------|------|
| Fix NAT gate (DNAT + NATv6v4 already done) | Trivial | gate-fixes |
| GRE acceleration (key→ports) | Low | gate-fixes |
| Port mirroring evidence | Low | gate-fixes |
| Policy hit counters | Low | gate-fixes |
| Mid-stream TCP RST generation | Low | gate-fixes |

### Wave B — Medium features (launch in parallel)
| Feature | Complexity | Team |
|---------|-----------|------|
| Source NAT pool mode | Medium | pool-snat |
| Tunnel interfaces (GRE transit) | Medium | tunnel-transit |
| Firewall filters + policers | High | fw-filters |
| Flow export (NetFlow v9) | Medium | flow-export |

### Wave C — Advanced security
| Feature | Complexity | Team |
|---------|-----------|------|
| Per-IP session limits | Medium | adv-screen |
| Port scan / IP sweep detection | Medium | adv-screen |
| SYN cookie flood protection | High | syn-cookies |
| IPsec passthrough | Medium | ipsec-pass |
| Policy scheduler/QoS | Medium | qos |
