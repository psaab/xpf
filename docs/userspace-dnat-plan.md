# Userspace Dataplane: Destination NAT Implementation Plan

## 1. Background and Motivation

The eBPF dataplane already supports full DNAT via `dnat_table`/`dnat_table_v6` hash maps. The Go compiler (`pkg/dataplane/compiler.go`) populates these from `DestinationNATConfig` rules at commit time. The Rust AF_XDP userspace dataplane currently supports only interface-mode source NAT and static 1:1 NAT. This plan adds DNAT with port rewriting — the primary missing NAT feature.

### What DNAT Does

DNAT rewrites the destination IP and/or port of incoming packets **before routing** (pre-routing). Use cases:
- **Port forwarding**: `external_ip:port` → `internal_ip:port`
- **Service publishing**: expose internal services on public IPs
- **Load balancing**: redirect to different backend

Key differences from Static NAT:
- Unidirectional (only rewrites destination on inbound; return traffic uses conntrack)
- Can change ports (static NAT doesn't)
- Matches on protocol + port (static NAT matches any protocol)
- Has zone-pair matching (from_zone → to_zone)

## 2. Files to Modify

| File | Change |
|------|--------|
| `pkg/dataplane/userspace/protocol.go` | Add `DestinationNATRuleSnapshot`, field on `ConfigSnapshot`, port fields on sync types |
| `pkg/dataplane/userspace/manager.go` | Add `buildDestinationNATSnapshots()`, wire into snapshot builder |
| `userspace-dp/src/main.rs` | Add `DestinationNATRuleSnapshot` struct, `ConfigSnapshot` field |
| `userspace-dp/src/nat.rs` | Add port fields to `NatDecision`, add `merge()`, add `DnatKey`/`DnatValue`/`DnatTable` |
| `userspace-dp/src/session.rs` | Update `reverse_wire_key()` for port translation |
| `userspace-dp/src/afxdp.rs` | Add `dnat_table` to `ForwardingState`, DNAT lookup in session-miss, port rewriting in `apply_nat_*()` |

No new files needed — all changes are additions to existing files.

## 3. Go Side

### Step 1: Snapshot Type (`protocol.go`)

```go
type DestinationNATRuleSnapshot struct {
    Name               string `json:"name"`
    FromZone           string `json:"from_zone,omitempty"`
    DestinationAddress string `json:"destination_address"`
    DestinationPrefix  string `json:"destination_prefix,omitempty"` // #3164: non-host CIDR; empty for a host
    DestinationPort    uint16 `json:"destination_port,omitempty"`
    Protocol           string `json:"protocol,omitempty"`       // "tcp", "udp", or ""
    PoolAddress        string `json:"pool_address"`
    PoolPort           uint16 `json:"pool_port,omitempty"`
}
```

Each snapshot entry is a pre-expanded table entry: one per (protocol, destination IP, destination port) tuple. The Go builder handles multi-port expansion.

Add to `ConfigSnapshot`:
```go
DestinationNAT []DestinationNATRuleSnapshot `json:"destination_nat_rules,omitempty"`
```

### Step 2: Session Sync Port Fields (`protocol.go`)

Add to `SessionSyncRequest` and `SessionDeltaInfo`:
```go
NATSrcPort uint16 `json:"nat_src_port,omitempty"`
NATDstPort uint16 `json:"nat_dst_port,omitempty"`
```

### Step 3: Snapshot Builder (`manager.go`)

`buildDestinationNATSnapshots(cfg)` follows the same expansion logic as `pkg/dataplane/compiler.go:compileDNAT()`:

1. Iterate `cfg.Security.NAT.Destination.RuleSets`
2. For each rule: resolve match (dst address, protocol, ports) and pool (address, port)
3. If application specified, resolve via `config.ResolveApplication()` to get protocol+ports
4. Expand to one snapshot per (protocol, port) combination
5. Include `from_zone` for zone filtering

Wire into snapshot builder alongside `buildSourceNATSnapshots()`.

## 4. Rust Side

### Step 4: NatDecision Port Fields (`nat.rs`)

```rust
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NatDecision {
    pub(crate) rewrite_src: Option<IpAddr>,
    pub(crate) rewrite_dst: Option<IpAddr>,
    pub(crate) rewrite_src_port: Option<u16>,
    pub(crate) rewrite_dst_port: Option<u16>,
    pub(crate) nat64: bool,
}
```

Update `reverse()` to accept and reverse ports:
```rust
pub(crate) fn reverse(self, original_src: IpAddr, original_dst: IpAddr,
                       original_src_port: u16, original_dst_port: u16) -> Self {
    Self {
        rewrite_src: self.rewrite_dst.map(|_| original_dst),
        rewrite_dst: self.rewrite_src.map(|_| original_src),
        rewrite_src_port: self.rewrite_dst_port.map(|_| original_dst_port),
        rewrite_dst_port: self.rewrite_src_port.map(|_| original_src_port),
        nat64: self.nat64,
    }
}
```

Add `merge()` for combining DNAT + SNAT:
```rust
pub(crate) fn merge(self, other: NatDecision) -> Self {
    Self {
        rewrite_src: self.rewrite_src.or(other.rewrite_src),
        rewrite_dst: self.rewrite_dst.or(other.rewrite_dst),
        rewrite_src_port: self.rewrite_src_port.or(other.rewrite_src_port),
        rewrite_dst_port: self.rewrite_dst_port.or(other.rewrite_dst_port),
        nat64: self.nat64 || other.nat64,
    }
}
```

### Step 5: DNAT Table (`nat.rs`)

```rust
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct DnatKey {
    pub protocol: u8,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DnatValue {
    pub new_dst_ip: IpAddr,
    pub new_dst_port: u16,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DnatTable {
    entries: FxHashMap<DnatKey, DnatValue>,
}
```

Lookup strategy:
1. Exact match on `(protocol, dst_ip, dst_port)`
2. Wildcard port fallback: `(protocol, dst_ip, 0)` for IP-only DNAT rules
3. Protocol expansion: `protocol=""` entries expand to both TCP(6) and UDP(17) at parse time

### Step 6: Reverse Wire Key (`session.rs`)

```rust
fn reverse_wire_key(forward_key: &SessionKey, nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(forward_key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        (forward_key.src_port, forward_key.dst_port)
    } else {
        (
            nat.rewrite_dst_port.unwrap_or(forward_key.dst_port),
            nat.rewrite_src_port.unwrap_or(forward_key.src_port),
        )
    };
    SessionKey {
        addr_family: forward_key.addr_family,
        protocol: forward_key.protocol,
        src_ip: nat.rewrite_dst.unwrap_or(forward_key.dst_ip),
        dst_ip: nat.rewrite_src.unwrap_or(forward_key.src_ip),
        src_port,
        dst_port,
    }
}
```

Logic: when DNAT translates `forward_key.dst_port` to `new_dst_port`, the reply from the server uses `new_dst_port` as its source port. So in the reverse key, `src_port = nat.rewrite_dst_port` (the translated port the server sees).

### Step 7: Session-Miss Path Integration (`afxdp.rs`)

The critical design point: **DNAT must happen before routing** because the translated destination affects the FIB lookup result.

New sequence in session-miss path (~line 2310):
```
1. Extract packet 5-tuple
2. DNAT table lookup by (protocol, dst_ip, dst_port)
3. If no DNAT match: static NAT DNAT lookup
4. If DNAT/static match: use translated destination for FIB lookup
5. FIB lookup (with translated destination)
6. Zone pair determination
7. Policy evaluation
8. Source NAT matching
9. MERGE DNAT + SNAT decisions (fix existing overwrite bug)
10. Session creation with merged NatDecision
```

**Bug fix**: The current code at `afxdp.rs:2449` overwrites any pre-routing DNAT decision when SNAT matches:
```rust
// Before (BUG: overwrites DNAT):
decision.nat = match_source_nat_for_flow(...).unwrap_or_default();

// After (CORRECT: merge DNAT + SNAT):
let snat_decision = match_source_nat_for_flow(...).unwrap_or_default();
decision.nat = decision.nat.merge(snat_decision);
```

### Step 8: Port Rewriting in `apply_nat_*()` (`afxdp.rs`)

After IP rewriting, add L4 port rewriting:
```rust
if let Some(new_dst_port) = nat.rewrite_dst_port {
    if matches!(protocol, PROTO_TCP | PROTO_UDP) {
        let port_offset = l4_offset + 2;  // TCP/UDP dest port at offset +2
        let old_port = u16::from_be_bytes([packet[port_offset], packet[port_offset + 1]]);
        if old_port != new_dst_port {
            packet[port_offset..port_offset + 2].copy_from_slice(&new_dst_port.to_be_bytes());
            adjust_l4_checksum_port(packet, l4_offset, protocol, old_port, new_dst_port)?;
        }
    }
}
```

Port changes only affect L4 checksum (not IP header checksum). The incremental update is a simple 16-bit ones-complement subtraction/addition — same math as IP address changes. Port rewriting must happen AFTER IP rewriting to avoid double-counting in the checksum.

### Step 9: Local Address Registration

DNAT destination IPs must be recognized as locally-owned (otherwise traffic to those IPs gets forwarded elsewhere instead of being processed):
```rust
for dst_ip in state.dnat_table.destination_ips() {
    match dst_ip {
        IpAddr::V4(v4) => { state.local_v4.insert(v4); }
        IpAddr::V6(v6) => { state.local_v6.insert(v6); }
    }
}
```

## 5. Session Sync and HA

Session deltas and sync messages need the new port fields so DNAT state survives failover:
- Build: include `nat_src_port`/`nat_dst_port` in `SessionDeltaInfo`
- Parse: reconstruct port fields in `NatDecision` from sync request

## 6. Hit Counters

Initial implementation: use the existing per-binding `dnat_packets` counter (already in `BindingStatus`). Per-rule counters can be added later via a `Vec<u64>` in `DnatTable` indexed by rule position.

## 7. Testing Strategy

### Unit Tests

| # | Test | Location |
|---|------|----------|
| 1 | Basic DNAT lookup (TCP:203.0.113.10:80 → 192.168.1.10:8080) | `nat.rs` |
| 2 | Wildcard port fallback (port=0 matches any) | `nat.rs` |
| 3 | Protocol specificity (TCP entry, UDP miss) | `nat.rs` |
| 4 | IPv6 DNAT | `nat.rs` |
| 5 | Multiple entries, each matches correctly | `nat.rs` |
| 6 | No match returns None | `nat.rs` |
| 7 | Port-aware reverse (DNAT port rewrite) | `nat.rs` |
| 8 | DNAT+SNAT merge preserves both translations | `nat.rs` |
| 9 | Default NatDecision unchanged | `nat.rs` |
| 10 | DNAT port in reverse wire key | `session.rs` |
| 11 | DNAT+SNAT ports in reverse key | `session.rs` |
| 12 | ICMP port handling unchanged | `session.rs` |
| 13 | TCP checksum after port rewrite | `afxdp.rs` |
| 14 | IP + port combined rewrite checksum | `afxdp.rs` |
| 15 | UDP zero-checksum skip | `afxdp.rs` |

### Integration Tests

| # | Test |
|---|------|
| 16 | Port forwarding: external:8080 → internal:80, verify DNAT and session |
| 17 | DNAT + SNAT combination (port forwarding with interface SNAT) |
| 18 | Return traffic hits reverse session with correct reverse NAT |
| 19 | Multi-port DNAT (same IP, different port mappings) |
| 20 | IP-only DNAT (port=0 wildcard) |

## 8. Implementation Sequence

1. `NatDecision` port fields + `merge()` + `reverse()` update (`nat.rs`)
2. `DnatTable` structures + unit tests (`nat.rs`)
3. `reverse_wire_key` port handling (`session.rs`, `afxdp.rs`)
4. Go snapshot types (`protocol.go`)
5. Go snapshot builder (`manager.go`)
6. Rust snapshot parsing (`main.rs`)
7. `ForwardingState` + snapshot application (`afxdp.rs`)
8. Session-miss path integration + SNAT overwrite fix (`afxdp.rs`)
9. Port rewriting in `apply_nat_*()` (`afxdp.rs`)
10. Session sync protocol port fields (`protocol.go`, `afxdp.rs`)
11. End-to-end testing

## 9. Risks and Considerations

1. **SNAT overwrite bug (existing)**: Current code at `afxdp.rs:2449` overwrites any pre-routing DNAT decision when SNAT matches. The `merge()` fix resolves this for both static NAT and new DNAT.

2. **ICMP / non-TCP-UDP DNAT** (corrected #2396): ICMP has no ports, so
   port-matching DNAT doesn't apply to it. An IP-only DNAT (no protocol, no
   port) now genuinely covers ALL L4 protocols including ICMP/ICMPv6/GRE: the
   builder emits it with an empty `protocol` and zero port, and the Rust table
   keys it under a protocol WILDCARD sentinel, with
   `DnatTable::lookup_with_counter` falling back to that wildcard after the
   concrete-protocol and wildcard-port lookups miss. A DNAT rule that names a
   concrete non-TCP/UDP protocol (`protocol gre`, `application junos-icmp-all`,
   ...) resolves through `ip_proto::proto_number` (mirrors the Go SSOT
   `appid.ProtocolNumber`) and installs a protocol-scoped entry. The token is
   normalized (trim + lower-case) on both sides, and an unresolvable
   `match protocol` token is hard-rejected at commit by
   `validateDestinationNATProtocolStrict` (lenient-warn on tolerant load)
   rather than silently dropped.

   The wildcard sentinel is `PROTO_ANY = 256` — `DnatKey.protocol` is a `u16`
   so the sentinel sits OUTSIDE the 0-255 IANA range and is DISTINCT from every
   real protocol, including protocol `0` (HOPOPT). The first cut used
   `PROTO_ANY = 0`, which COLLIDED with HOPOPT: a `protocol 0` DNAT would have
   keyed under the wildcard and broadened to match every protocol. With the u16
   key, `protocol 0` is a normal exact match and only `""` (no protocol, no
   port) uses the wildcard. Before #2396 the Rust builder recognized only
   `tcp`/`udp`/`""` and SILENTLY DROPPED everything else (`_ => continue`), and
   `""`+port-0 expanded to TCP+UDP only — so a GRE/ICMP DNAT committed but never
   reached the dataplane, and an IP-only DNAT did NOT cover ICMP, contradicting
   the original claim here.

3. **Session key stability**: Forward session key uses the ORIGINAL 5-tuple (pre-DNAT). The translation is carried in `NatDecision`. Matches static NAT pattern.

4. **Worker isolation**: Each worker has its own `ForwardingState` snapshot with cloned `DnatTable`. No locking needed.

5. **Backward compatibility**: New `destination_nat_rules` JSON field defaults to empty array. Old binaries ignore it (serde `default`).

6. **Checksum ordering**: Port rewriting must happen AFTER IP rewriting. Both are independent incremental updates to the L4 checksum.

## 10. Source-address constraint (#2394)

Junos DNAT `match source-address` restricts which source IPs the destination
translation applies to. The original DNAT implementation parsed the constraint
into the typed rule but dropped it at the Go->Rust snapshot boundary, so the
helper installed a destination-only entry that DNAT'd traffic from ANY source —
a fail-open that published the internal service to sources the operator scoped
out.

#2394 carries the constraint end to end:

- `DestinationNATRuleSnapshot.SourceAddresses` (Go, `protocol.go`) /
  `source_addresses` (Rust, `protocol/nat.rs`) — a new wire field
  (`json:"source_addresses,omitempty"`, serde `default`). Old binaries ignore
  it; an absent/empty list means "match any source" so unscoped DNAT is
  unchanged. The default-specimen wire fixture (`protocol_wire_v1.json`) was
  regenerated.
- `buildDestinationNATSnapshots` (`nat.go`) populates the field from
  `rule.Match.SourceAddresses` with a singular `SourceAddress` fallback,
  mirroring the SNAT builder.
- `DnatEntry.{source_constrained, source_v4, source_v6}`
  (`nat/destination.rs`) hold whether the rule was scoped and the parsed
  prefixes. `DnatEntry::source_matches(src_ip)` returns: unscoped
  (`source_constrained == false`) -> match any; scoped but all entries
  unparseable (both prefix vecs empty) -> match NOTHING (fail closed); else
  the packet source must fall in a parsed prefix of its own family. The lookup
  takes `src_ip` and filters on both zone and source. The per-key dedup keys on
  `(from_zone, source_constrained, source_v4, source_v6)` so two distinct
  source-scoped rules on the same destination both survive (and an unscoped
  rule never collapses onto a fully-malformed scoped rule).
- The session-miss caller (`afxdp/poll_descriptor/mod.rs`) passes
  `flow.forward_key.src_ip`.

### Bare-host source + all-malformed (Copilot fold)

Junos carries `match source-address` verbatim and the Go compiler does NOT
normalize it, so a bare host (`set ... match source-address 198.51.100.42`,
no `/prefix`) reaches the wire without a mask. `IpNet::from_str` REQUIRES
`addr/prefix` form and rejects a bare IP. The first cut skipped any entry that
failed `IpNet` parse, so a bare-host source-scoped DNAT left its prefix lists
empty and matched ANY source — the #2394 fail-open reintroduced for bare IPs.

Two robustness fixes (the DNAT sibling of #2398 SNAT):

1. **Bare-IP fallback** — each source entry is parsed as `IpNet`; on failure it
   falls back to a bare `IpAddr` -> /32 (v4) or /128 (v6). So `198.51.100.42`
   matches only that host and the doc claim ("a bare host parses as /32/128")
   is now true.
2. **All-malformed -> fail-closed** — `source_constrained` (set when the
   snapshot source list is non-empty) distinguishes "unscoped rule -> match
   any" from "scoped rule, zero entries parsed -> match none". A scoped rule
   whose entries all fail to parse matches nothing rather than reverting to
   match-any. A mix of valid + garbage entries keeps the valid prefixes.

### Address-book-name source scope (#2416)

`match source-address` (#2394) takes literal prefixes; the sibling
`match source-address-name <book-entry>` takes an **address-book reference**.
The compiler parsed it into `NATMatch.SourceAddressName` but never resolved it
into the source list `buildDestinationNATSnapshots` reads, so a name-scoped DNAT
published an EMPTY `source_addresses` = `source_constrained == false` = match
ANY source — the same fail-open as #2394 for the named variant. SNAT shared the
gap (its match switch did not even parse the keyword, and the schema did not
expose it).

#2416 closes it:

- `appendNATSourceAddressName` (`nat.go`) resolves the name via
  `resolveUserspaceAddressBookEntry` — the same global-address-book expander the
  security-policy snapshot path uses — and appends the concrete prefixes to the
  rule's source list. Both `buildDestinationNATSnapshots` and
  `buildSourceNATSnapshots` call it.
- Fail-closed on an unknown / unresolvable name: the raw token is appended so
  the source list stays non-empty (`source_constrained` stays true) while the
  token fails `IpAddr`/`IpNet` parse and contributes no prefix — the rule
  matches NOTHING, never collapsing back to match-any. This reuses the existing
  #2394/#2398 all-malformed -> fail-closed Rust path; no wire change.
- The SNAT match parser (`compiler_nat.go`) now reads `source-address-name`, and
  the SNAT `match` schema (`schema_security.go`) exposes the keyword (DNAT
  already did).
- `validateNATSourceAddressNameReferencesStrict` (`compiler_validate_strict.go`)
  hard-rejects an undefined reference at commit / commit-check so the typo is
  operator-visible; the tolerant load / peer-sync path downgrades to a warning
  (`lenientFirewallRefs`, #1960) and the dataplane backstop fails closed. Mirrors
  the firewall prefix-list / policer reference gates.

### Static-NAT source-address (#3435)

`match source-address` on a **static** NAT rule is the bidirectional 1:1/DNAT
analog of the DNAT constraint above. It was accepted by the schema and stored
by the compiler, but dropped before runtime — the static snapshot had no source
field and the Rust matcher never checked source, so a rule meant to expose an
internal host only to selected client prefixes installed as an all-source
mapping (fail-open exposure broadening, H01). Separately the typed value was
truncated to a single scalar despite the schema's `multi: true`, so
bracket/repeated lists lost every prefix after the first (M02).

#3435 mirrors #2394 end to end:

- `StaticNATRule.SourceAddresses` (`types_security.go`) holds the full list;
  `compileNATStatic` (`compiler_nat.go`) appends `m.Keys[1:]` + child names
  (closing M02) and keeps the singular `SourceAddress` as the first element for
  back-compat (the NAT64 `::/0` readers, peer sync).
- `StaticNATRuleSnapshot.SourceAddresses` (Go `protocol.go` /
  `source_addresses` Rust `protocol/nat.rs`) — a new additive wire field
  (`json:"source_addresses,omitempty"`, serde `default`). Empty = match any
  source (unscoped, unchanged). `protocol_wire_v1.json` was regenerated.
- `buildStaticNATSnapshots` (`nat.go`) populates it from `rule.SourceAddresses`
  with the singular `SourceAddress` fallback.
- `static_nat.rs` parses the list into a `SourceConstraint`
  (`{constrained, v4, v6}`) on each `StaticNatEntry` and `StaticNatBlock`
  (host AND #3031 block paths). `SourceConstraint::matches`: unconstrained ->
  match any; constrained but zero entries parsed -> match NOTHING (fail closed,
  the #2394/#3435 guard); else the peer must fall in a parsed prefix of its
  family. Bare-host fallback to /32 /128 (IpNet rejects a bare IP) is shared
  with the DNAT path.
- **Direction.** The inbound `match_dnat_with_counter_scoped` gates on the
  packet SOURCE (`flow.forward_key.src_ip`, `poll_descriptor/mod.rs`); the
  reverse `match_snat_with_counter_scoped` gates on the packet DESTINATION (the
  original client, `flow.forward_key.dst_ip`, `nat_exception.rs`), symmetric
  with the #2871 egress-zone gate. The new peer argument is `Option<IpAddr>`;
  the non-scoped / test wrappers pass `None` (source gate skipped), the
  production scoped callers pass `Some(..)`.

### Malformed literal match prefixes rejected at commit (#7145)

Every mechanism above depends on the operator's literal `match source-address` /
`match destination-address` values being parseable, because the Go snapshot
builders copy them to the wire VERBATIM and the Rust consumers drop, per entry,
whatever they cannot parse:

| kind | Rust parse site |
|---|---|
| source NAT | `parse_match_prefix` (`nat/source.rs`) |
| destination NAT | `DnatTable::from_snapshots` (`nat/destination.rs`) |
| static NAT | `SourceConstraint::from_list` (`nat/static_nat.rs`) |

All three try `IpNet::from_str`, fall back to `IpAddr::from_str` (bare host ->
/32 / /128), and drop the entry otherwise while recording a bounded NAT
parse-error counter (#4718). The `*_constrained` flag is keyed on the SNAPSHOT
LIST being non-empty, not on how many entries parsed — that is what makes the
all-malformed case fail CLOSED rather than collapse to match-any.

Fail-closed at runtime was never the complaint. The complaint (#7145) was that
the operator boundary was SILENT about it in four of the six (kind x match leaf)
slots, while the other two rejected the identical value. Measured at
`bf10c6b7c` with `999.1.1.1/24`:

| kind | `match source-address` | `match destination-address` |
|---|---|---|
| source | accepted -> **rejected** | accepted -> **rejected** |
| destination | accepted -> **rejected** | rejected (#3228) |
| static | accepted -> **rejected** | rejected (#3206) |

`validateNATMatchAddressLiteralsStrict`
(`pkg/config/compiler_validate_strict_nat_match_addr.go`) closes the four. It
walks ONLY the literal leaves — `match source-address-name` /
`destination-address-name` are address-book references whose unresolvable raw
token is appended to the same wire list ON PURPOSE (#2416, above), so a gate
that walked the post-resolution list would reject the fail-closed backstop
itself.

The predicate is `net.ParseCIDR` then `net.ParseIP` (`natMatchPrefixParses`,
`compiler_nat_helpers.go`), chosen over the `netip` equivalents because
`netip.ParsePrefix` is STRICTER than Rust on the mask text — it rejects a
zero-padded prefix length (`1.2.3.4/024`) that Rust's `u8::from_str` reads as
24 and installs. Rejecting a value the dataplane installs is the one direction
a widened validator must never take.

Strict on commit / commit-check (hard reject naming the kind, rule-set, rule,
leaf, and value); lenient on load / peer-sync (warn, flag
`lenientNATMatchAddressLiterals`, #1960 no-brick — the value COMMITTED CLEAN on
every build before this, so the population of boxes carrying one is non-empty by
construction). **The tolerant path KEEPS the malformed value in the compiled
config.** Dropping it Go-side would empty an all-malformed list, clear
`*_constrained` and collapse the rule to MATCH-ANY — turning a fail-closed
silent break into a fail-OPEN one.

Known residuals, measured, NOT closed by #7145 (they are a different value
class from the issue's malformed CIDR):

- **#7215** — an out-of-range mask (`10.0.0.0/33`) is still accepted on
  destination-NAT `match destination-address`. That slot's own gate (#3228)
  strips the mask and parses only the address part, while its Go builder
  (`dnatDestinationParts`) uses `net.ParseCIDR` and skips the entry — a
  validator/builder divergence in the OLDER gate.
- **#7216** — an explicitly quoted empty value (`match destination-address ""`)
  is still accepted on static-NAT `match destination-address`, where an empty
  slot carries the deliberate #6673 "authored blank selection" meaning, so
  closing it needs to separate a machinery-produced blank from a typed one.

### Static-NAT invalid `match destination-port` fails closed (#5101)

The static-NAT typed `match destination-port` / `mapped-port` leaves are
range-checked 1..65535 at strict commit (§13; `validateNATMatchDestinationPort
Strict` / `validateNATHostMaskStrict`, `compiler_validate_strict_nat.go`), but
the compiler stores the raw `int` and the lenient load / peer-sync path (#1960)
can still carry an out-of-range value into `buildStaticNATSnapshots`
(`nat_static.go`). The snapshot port slot is a `uint16` whose ONLY "no port"
value is `0`, and the Rust side (`static_nat.rs`, `(0, _) => (None, None)`)
reads `0` as the **whole-address** wildcard — a 1:1 mapping that exposes EVERY
port of the external address.

`clampPort` previously coerced an out-of-range port to `0`, conflating "port
ABSENT" (a valid, common whole-address 1:1 shape) with "port PRESENT but
invalid". A persisted / peer-synced `match destination-port 70000` therefore
collapsed to whole-address — a fail-OPEN broadening, the exact opposite of the
"fails CLOSED" the code claimed (the static-NAT analog of the §13 H12 wildcard
hole for SNAT/DNAT).

The fix keeps the absent-vs-invalid distinction:

- `staticNATPortOutOfRange(p)` = `p != 0 && (p < 1 || p > 65535)` — the same
  predicate the strict commit gate uses. `0` (absent / match-any) is NOT out of
  range and is left untouched.
- `buildStaticNATSnapshots` drops any rule whose `MatchDestinationPort` OR
  `MappedPort` is present-but-out-of-range and emits an operator-visible
  `slog.Warn` (symmetric with the source-NAT unusable-pool and #3435
  source-address lenient-path guards). An invalid port therefore never reaches
  `clampPort`/the Rust `(0, _)` whole-address path — the rule fails CLOSED (no
  translation, no exposure) instead of widening to whole-address.
- Genuine-absent (`0` → whole-address 1:1) and valid in-range ports are
  unchanged. No wire change (Go-only); `protocol_wire_v1.json` unaffected.

## 11. Multiple destination-addresses (#2395)

Junos DNAT `match destination-address [ A B C ]` publishes the SAME
translation for several external destinations. The compiler already parsed the
full list into `rule.Match.DestinationAddresses` (with `DestinationAddress`
mirroring the first element), but `buildDestinationNATSnapshots` iterated only
the singular `DestinationAddress`. The rule therefore collapsed to its FIRST
destination — traffic to B and C was forwarded untranslated (configured
translation silently not applied; HIGH).

The DNAT table is keyed by exact destination IP (`DnatKey.dst_ip`,
`nat/destination.rs`), so the natural fix is **one snapshot entry per
destination** sharing the rule's pool/port/counter — no wire change (the
existing scalar `destination_address` field is reused; `protocol_wire_v1.json`
is unchanged).

- `buildDestinationNATSnapshots` (`nat.go`) now builds `destAddrs` from
  `rule.Match.DestinationAddresses` with a singular `DestinationAddress`
  fallback (mirrors the #2394 source-address idiom), then emits one
  `DestinationNATRuleSnapshot` per destination inside the existing
  app-term/port loop. Each destination has its CIDR suffix stripped (DNAT
  matches exact host IPs) and is validated with `net.ParseIP`.
- **Fail-closed on all-malformed** — a destination that is empty or not a bare
  host IP is skipped. If a rule has destinations but EVERY one is malformed, no
  snapshot row is emitted, so the rule matches NOTHING rather than broadening
  to match-any. (The Rust `from_snapshots` also `continue`s on a destination it
  cannot `IpAddr::parse`, so the fail-closed posture holds on both sides.)
- **Composition with #2394** — the per-destination loop is nested inside the
  source-constraint setup, so every emitted per-destination snapshot carries
  the same `SourceAddresses`. A source-scoped multi-destination DNAT fires for
  each destination only when the source also matches; neither constraint is
  regressed.

The rewrite target (translated destination/port from the pool) is unchanged —
only the MATCH set grows from one destination to all configured destinations.

### 11.1 Per-entry commit gate on a partial-valid list (#3228)

The all-malformed fail-closed posture above (no snapshot row when EVERY
destination is malformed) is caught at commit by
`validateDestinationNATAddressesStrict` (`compiler_validate_strict.go`). That
gate originally used an `anyGood` break: it passed commit as long as AT LEAST
ONE destination parsed. But the builder skips malformed entries PER-ENTRY, so a
MIXED list such as `match destination-address [ 192.0.2.1 web-server ]`
committed clean (one good entry satisfied `anyGood`) while `web-server` was
silently dropped from the installed DNAT table — traffic to it was never
translated, a partial, silent drop of a forwarding-relevant config (#3228).

The gate now rejects the rule if ANY listed destination-address fails to parse,
mirroring the builder's exact skip predicate (`natCIDRIPPart` CIDR strip, then
empty / `net.ParseIP` check). Validator and dataplane view agree: anything the
builder would drop, the validator rejects, naming the offending entry. An
all-valid list still compiles byte-identical and installs every entry (the
multi-destination behavior above is unchanged). On the tolerant load / peer-sync
path the rejection is downgraded to a `destination-nat address` warning (#1960
no-brick), consistent with the all-malformed (#2396(c)) gate that shares this
validator. (The multi-host-prefix reject — #3029 — was removed by #3164, which
implements prefix matching; see §12.)

## 12. Multi-host-prefix destination matching (#3164)

Junos DNAT `match destination-address` accepts a non-host CIDR prefix
(`198.51.100.0/24`): every host in the block is translated to the rule's pool.
Before #3164 the builder STRIPPED the `/mask` and emitted only the network base
as an exact host, and the Rust `DnatTable` keyed on an exact `IpAddr` — so only
the network address translated and every other host in the block bypassed DNAT
(silent under-translation). #3029 (PR #3162) closed the fail-open by REJECTING a
multi-host prefix at commit; #3164 implements the feature and removes that
reject.

**Scope.** A prefix destination is a many:1 MATCH to the configured pool (the
same translation the host case uses). Block-mapping semantics — a 1:1
host-N->host-N offset map between a destination prefix and a pool prefix — are
the unsettled design fork called out in #3164 and remain OUT OF SCOPE; the pool
is a single address (range support is the existing pool behavior, unchanged).

**Wire (additive, #1961).** A new `destination_prefix` field on
`DestinationNATRuleSnapshot` carries the canonical masked CIDR for a non-host
prefix; `destination_address` keeps the network base. For a host (bare IP, /32,
/128) `destination_prefix` is empty and the exact `destination_address` path is
used, byte-identical to pre-#3164. An older helper ignores the new field and
keys only `destination_address` (the network base) — the pre-#3164 narrowed
behavior, never a crash. `protocol_wire_v1.json` gains exactly the one
`destination_prefix: ""` key.

- `dnatDestinationParts` (`nat.go`) is the single host-vs-prefix classifier: a
  bare IP or a canonical host mask (/32, /128) is a HOST (base = address, prefix
  = ""); a non-host CIDR is a BLOCK (base = network address, prefix = canonical
  masked CIDR). It normalizes a non-canonical input (`198.51.100.7/24` ->
  base `198.51.100.0`, prefix `198.51.100.0/24`). An unparseable token returns
  `ok == false` and is skipped (fail-closed, same as before).
- The Rust `DnatTable` keeps the O(1) exact-host `entries` map for hosts and adds
  a `prefix_entries` map keyed by `(protocol, dst_port)` whose value is a vec of
  prefix slots. `lookup_with_counter` probes the exact map first (a host is the
  longest possible prefix, so it always wins), then falls back to a
  longest-prefix-match scan over `prefix_entries` using the SAME three proto/port
  tiers (exact proto+port, wildcard port, `PROTO_ANY`). Within a tier the LONGEST
  matching prefix wins; zone-specific entries beat zone-wildcard entries and the
  `match source-address` constraint (#2394) is enforced unchanged.

**Local-address registration is bounded.** `destination_ips()` (consumed by
`forwarding_build` to populate `local_v4`/`local_v6` for proxy-ARP/ND) expands a
prefix host-by-host only when the block is at or below `MAX_LOCAL_PREFIX_HOSTS`
(4096 usable hosts — a v4 /20 or longer; a v6 block must be host-scale). A larger
block registers only its network base and must be ROUTED to the firewall. The
DNAT MATCH is independent of this set (the pre-routing lookup keys on the packet
destination directly), so a large block is still translated in full — only
on-segment proxy-ARP for the whole block is bounded.

## 13. `match destination-port` range validation (#3446)

Source- and destination-NAT `match destination-port` had NO range validation
(unlike static NAT, which validates its typed `destination-port` leaf 1..65535
at commit — #2491). The parser (`parseDNATPortList`, `compiler_nat.go`) used a
bare `strconv.Atoi` with no bound check and dropped a non-numeric token
silently; the snapshot builders cast the value straight to `uint16`. The result
was three silent failure modes:

- **H12** — `match destination-port 0` installed the WILDCARD port (Rust treats
  `dst_port == 0` as "match any"), so the rule translated EVERY port.
- **H13** — `70000` wrapped to `4464` and `-1` to `65535` on the `uint16` cast,
  so the rule DNAT'd the wrong external port.
- **H14** — a non-numeric token (`http`) failed `Atoi`, was dropped, left an
  empty port list, and fell back to the wildcard port — again translating every
  port instead of failing closed.

**Commit gate.** `validateNATMatchDestinationPortStrict` (`compiler_validate_strict.go`)
hard-rejects a source- or destination-NAT rule whose `match destination-port`
carries a 0/negative/>65535 number or a non-numeric token. It runs after the
DNAT match-protocol gate and shares the `lenientDestNATAddresses` flag, so on
the tolerant load / peer-sync path (#1960) it downgrades to a warning rather
than bricking a config persisted before the gate existed. To see a non-numeric
token at commit (it never parses to an int), `parseDNATPortList` now returns the
unparseable raw tokens alongside the numeric ports; the compiler stores them on
`NATMatch.InvalidDestinationPorts` (the `to` range keyword and `[`/`]`
bracket-list delimiters are never reported). Out-of-range NUMBERS still flow
through `DestinationPorts` and are range-checked directly.

**Dataplane fail-closed (lenient backstop).** The source-NAT builder
(`coalescePortRanges` / `sourceNATDestPortRanges`) skips out-of-range values and
emits the `natNeverMatchPortRange` sentinel when a configured list coalesces to
nothing (#3429). **#3546** closed a residual hole here: `sourceNATDestPortRanges`
originally consulted only `DestinationPorts` (the numeric list) and ignored
`InvalidDestinationPorts`, so an ALL-nonnumeric source-NAT `match
destination-port` (e.g. `http`) parsed to an empty numeric list, coalesced to
nothing, and — with no configured numeric to trip the fail-closed branch —
returned an empty range list = unconstrained match-any-port on the #1960
tolerant-load / peer-sync path. The builder now passes
`rule.Match.InvalidDestinationPorts` into `sourceNATDestPortRanges`, which treats
the constraint as configured when EITHER list is non-empty and emits the
never-match sentinel when nothing valid survives. A mix of one valid port and an
invalid token (`[ http 8080 ]`) keeps the valid port, matching the DNAT builder.
The destination-NAT builder (`buildDestinationNATSnapshotsWithFeeds`) already
followed that doctrine: it filters each term's ports to 1..65535, and when a port
WAS configured (numeric list non-empty, or `InvalidDestinationPorts` non-empty on
the explicit-match fallback) but no valid port survives, it emits NO snapshot for
the term so the rule matches NOTHING — it never widens to the wildcard port. A
rule with no `destination-port` at all still emits the genuine wildcard
(`destination_port: 0`), unchanged.

**Wire.** No new wire field. `InvalidDestinationPorts` is compiler-internal
(never serialized to the helper); the builder uses the existing
`destination_port` slot and simply drops a term that would have wildcarded, so
`protocol_wire_v1.json` is unchanged.

## 13a. `match destination-port` range compaction (#3449)

A DNAT `match destination-port low to high` range was expanded into one
snapshot/table entry PER PORT, with no bound, on TWO axes — a control-plane
amplification hazard:

- **M01** — the parser (`parseDNATPortList`) expanded `low to high` with an
  unbounded `for p := low; p <= high` over operator-supplied endpoints, so
  `destination-port 1 to 4000000000` allocated billions of ints at COMPILE
  time (OOM) BEFORE the §13 strict gate could reject the out-of-range value;
  and a valid `1 to 65535` then produced 65 535 DNAT table entries.
- **M02** — an `applications application WIDE destination-port 1-65535`
  referenced by a DNAT rule expanded the same way through `appPortsFromSpec`,
  multiplied by application-set member count.

The Rust DNAT matcher already supports a port-RANGE match as an `l4_extra_matches`
AND-filter (the `match_src_ports` / `port_in_ranges` mechanism added for the
application source-port constraint, §"H10" / #3437). The fix represents a wide
destination-port range the same way instead of expanding it:

- **Parser bound (`appendDNATPortRange`).** A `low to high` range is expanded
  only when BOTH endpoints are inside 1..65535 (so the loop is bounded to
  ≤65535 ints); an out-of-range endpoint is NOT expanded — both endpoints are
  recorded verbatim on `DestinationPorts` so the §13 strict gate
  (`validateNATMatchDestinationPortStrict`) still rejects the bad value at
  commit (fail-closed). This removes the compile-time OOM. (`appPortsFromSpec`
  was already bounded — it parses endpoints with `ParseUint(..,16)`.)

- **Builder compaction (`buildDestinationNATSnapshotsWithFeeds`).** Each term's
  valid ports are coalesced with `coalescePortRanges` into inclusive `[Low,High]`
  wire ranges. A single port (`Low==High`, including the `[0,0]` wildcard) keeps
  the exact-port `DnatKey` O(1) fast path (`destination_port` set,
  `match_destination_ports` empty — unchanged for the common single-port and
  IP-only rules). A multi-port range is emitted as ONE wildcard-port entry
  (`destination_port == 0`) carrying the range on the NEW
  `match_destination_ports` wire field — so `destination-port 1 to 65535` is one
  entry, not 65 535.

- **Matcher (`nat/destination.rs`).** `DnatEntry.match_dst_ports` is checked in
  `l4_extra_matches(src_port, dst_port, packet_icmp)` via `port_in_ranges`: the
  wildcard-port (`dst_port=0`) probe tier finds the entry and the range
  AND-filter confirms the flow's destination port is in range; a port outside
  the range misses (the range entry is NOT a match-any wildcard). A `Low>High`
  range never matches (preserved verbatim, like the source-port never-match
  sentinel). `match_dst_ports` is part of the entry's dedup identity (two range
  rules differing only in range are distinct). The prefix (#3164 LPM) tier
  threads `dst_port` the same way.

**Wire.** New ADDITIVE field `DestinationNATRuleSnapshot.match_destination_ports`
(`[]NatPortRangeWire`, `omitempty`; Rust `#[serde(default)]`), regenerated into
`protocol_wire_v1.json`. Skew (#1961): an older helper that does not know the
field treats a `destination_port==0` range entry as match-ANY-port — a transient
fail-OPEN widening of that ONE entry during the upgrade window, the same tradeoff
the source-NAT range fields carry; an older Go binary omits it and the newer
helper falls back to the per-port `destination_port` expansion such a binary
still emits.

## 13b. Reversed application port range fails closed (#3726)

`appPortsFromSpec` (`pkg/dataplane/userspace/nat.go`) expands an application's
`source-port` / `destination-port` spec into concrete ports for the NAT match
terms. For a `lo-hi` range it expanded only when `hi > lo`; for every other case
it returned `[]int{lo}` — so a REVERSED range (`200-100`, `lo > hi`) silently
narrowed to an EXACT match on the low port (200) instead of a never-match. The
`hi == lo` case (e.g. `100-100`) legitimately returns `[lo]`.

- **H04** — a reversed application `destination-port` referenced by a source- or
  destination-NAT rule translated traffic on port 200 (the low bound), even
  though the configured range is invalid and can never match a real flow.

Strict commit rejects `lo > hi` (`pkg/config` range validation), so this is the
#1960 tolerant-load / peer-sync backstop — the same accepted threat model as
§13 (#3446) and the source-port / ICMP work (#3437 / #3491).

- **Helper fix (`appPortsFromSpec`).** A reversed range (`hi < lo`) returns `nil`
  (not `[]int{lo}`), so the caller sees "configured but unrepresentable" and
  fails CLOSED. `hi == lo` keeps its single exact port; valid `lo < hi` ranges
  expand unchanged.

- **Source-NAT** already failed closed on this signal: `buildSourceNATAppTerms`
  emits the `natNeverMatchPortRange` sentinel when a non-empty spec coalesces to
  nothing (the #3429 / #3491 guard), so a reversed range now yields the
  never-match `{Low:1, High:0}` term instead of an exact-200 match.

- **Destination-NAT** needed a matching guard. The app-term builder stored the
  coalesced ports but LOST the "a port was configured" signal, so a `nil` port
  slice fell through to the wildcard match-any-port default (`destination_port
  == 0`) — a fail-OPEN that widened the rule to every port (the same latent gap
  hit an all-out-of-range `70000-80000` app spec). The `appTerm` now carries
  `dstPortConfigured` (true when the application named a non-empty
  destination-port), and the port-filtering loop treats a configured-but-empty
  term as `portConfigured` → it emits NO snapshot for that term (the rule
  installs nothing and does not translate), matching the §13 fail-closed
  posture. A valid or `hi==lo` app destination-port still publishes its exact
  DNAT entry.

## 13c. Rule `match destination-port` + `match application` (#3857)

A DNAT rule that configured BOTH `match application` AND a rule-level `match
destination-port` mishandled the port on the lenient / HA peer-sync decode path
(`buildDestinationNATSnapshotsWithFeeds`, `nat.go`). Before #3857 the rule-level
`match destination-port` was consulted ONLY on the no-application explicit-match
path; when an application was ALSO present the builder read the application's own
destination-port for the term and reached the rule-level port through a stray
switch case that read only the SINGULAR first port. Three fail modes resulted
(fable-161 F-018, the source-NAT builder handled all three correctly):

- **F-018a (fail-open)** — a port-less application (`protocol tcp`, no
  destination-port) combined with an INVALID / unrepresentable rule
  destination-port (a non-numeric token on `InvalidDestinationPorts`, or an
  out-of-range numeric) fell through to the wildcard match-any-port default
  (`destination_port == 0`), WIDENING the rule to every port — the exact
  fail-open the #3446 guard (§13) closes, re-opened on the mixed-version /
  corrupt-snapshot path.
- **F-018b** — a VALID rule destination-port was DROPPED when an application was
  present (the application's own port, or a wildcard, won), so the operator's
  explicit `match destination-port` had no effect.
- **F-018c** — a MULTI-value rule destination-port list collapsed to the
  singular first port (the switch case read `rule.Match.DestinationPort`, not the
  full `DestinationPorts` list).

Strict commit rejects an out-of-range / non-numeric rule `match
destination-port` (`validateNATMatchDestinationPortStrict`), so this is the
#1960 tolerant-load / peer-sync backstop — the same accepted threat model as §13
/ §13a / §13b.

**Builder fix.** The explicit rule-level `match destination-port` is now
authoritative for the destination-port axis and applies to EVERY resolved
application term. The builder resolves the rule's port list once
(`ruleDstPorts`, the plural `DestinationPorts`, falling back to the scalar
`DestinationPort` a mixed-version peer may carry alone; `ruleDstPortConfigured`
also trips on a non-empty `InvalidDestinationPorts`) and, when configured, uses
it in place of the application's own destination-port on each term. The
application still constrains protocol / source-port / ICMP type-code (the #3437
axes) — only the destination-port is taken from the explicit rule match. The
full multi-value list is preserved (each port coalesces to its own compact wire
range), and a configured-but-unrepresentable value trips the same
`portConfigured` → emit-no-snapshot fail-closed branch used by §13 / §13b, so
the rule matches NOTHING instead of widening to `[0,0]`. The stray singular-port
switch case is removed; a port-less application with no rule destination-port
still emits the genuine wildcard entry, unchanged.

**Wire.** No new wire field and no Rust change — the Rust `l4_extra_matches`
(`nat/destination.rs`) already AND-checks `match_destination_ports` and the
exact `destination_port`, preserving the `low > high` never-match sentinel. The
builder simply emits correct port ranges (or omits the rule).

## 14. DNAT pool port/address validation (#3450)

A destination-NAT **pool**'s translated `port` and `address` had NO strict
commit validation (the analog of §13, which validates the rule's `match`
ports). The pool parser (`compileNATDestination`, `compiler_nat.go`) used a bare
`strconv.Atoi` for the port (no bound check, non-numeric silently dropped to
`Port == 0`) and stored the address verbatim; the snapshot builder
(`buildDestinationNATSnapshotsWithFeeds`) cast the port to `uint16` and stripped
any CIDR suffix from the address. Junos expresses the pool port as `address port
<N>` (nested under the address leaf), which the pre-#3450 parser mis-handled —
it set `Address` to the literal `"port"` and dropped the port entirely. The
result was four silent failure modes:

- **M03** — `port 70000` wrapped to `4464` (and `-1` to `65535`) on the `uint16`
  cast, so traffic was rewritten to an unintended backend port.
- **M04** — `port 0` / `port httpp` collapsed to `Port == 0`, which the Rust
  DNAT path treats as "preserve the destination port" — the requested rewrite
  was silently a no-op.
- **M05** — `address 10.0.0.0/24` had its CIDR stripped to the network base
  `10.0.0.0`, so all matching traffic was translated to the network base (no
  pool/range semantics).
- **M06** — `address web-server` (an address-book name) committed clean but the
  Rust `DnatTable` failed to parse it and `continue`d, so the rule installed NO
  entry and the VIP was silently untranslated.

**Parser.** `parseDNATPoolAddress` now walks every token of an `address`
statement (and its children for the hierarchical shape), capturing the
translated address AND a nested `port <N>` separately — so `address 10.0.1.100/32`
plus `address port 80` yields `Address = 10.0.1.100/32`, `Port = 80` instead of
`Address = "port"`. The raw port token is preserved on `NATPool.PortRaw` so a
configured port (which must be 1..65535) is distinguishable from no `port` leaf
at all (`Port == 0` = the legitimate preserve-destination-port mode). The
top-level `port <N>` form is still accepted.

**Commit gate.** `validateDNATPoolStrict` (`compiler_validate_strict.go`)
hard-rejects a DNAT pool whose configured port is 0/negative/>65535/non-numeric
(only when `PortRaw` is set — no port leaf is left untouched) or whose address
is empty or not a single host (a bare IP, /32, or /128 — `isHostMaskAddress`,
the same predicate static NAT uses). It runs after the §13 match-dest-port gate
and shares the `lenientDestNATAddresses` flag, so on the tolerant load /
peer-sync path (#1960) it downgrades to a warning rather than bricking a config
persisted before the gate existed.

**Dataplane fail-closed (lenient backstop).** The builder now resolves the pool
address through `dnatPoolHostIP` (bare IP / /32 / /128 → the bare host string;
non-host CIDR or non-IP token → not ok) and skips the whole rule when the
address is unusable or when a configured pool port is out of 1..65535. So a
leniently-loaded bad pool installs NO entry (matches nothing) rather than
wrapping the port, coercing the address to a network base, or emitting an entry
the Rust side drops. A pool with a valid host address and no port leaf still
emits the genuine preserve-destination-port entry, unchanged.

**Wire.** No new wire field. `PortRaw` is compiler-internal (never serialized);
the builder uses the existing `pool_address` / `pool_port` slots and simply
drops a rule that would have translated wrongly, so `protocol_wire_v1.json` is
unchanged.

## 15. `then destination-nat off` exemption (#3844)

Junos supports a DNAT **no-translate exemption**: a rule whose action is `then
destination-nat off` matches the traffic but applies NO translation, and because
DNAT rules are ORDERED, a matched `off` rule STOPS evaluation so a later rule
cannot re-translate the flow. SNAT already handled `source-nat off` (via
`NATThen.Off`); the DNAT path did not.

**The fail-open (fable-161 F-003).** The token was accepted at commit, but the
DNAT then-parser (`compileNATDestination`, `compiler_nat.go`) recognized ONLY
`pool`, so an `off` rule compiled to an EMPTY `Then` (`Type == 0`, `Off ==
false`, `PoolName == ""`). The snapshot builder
(`buildDestinationNATSnapshotsWithFeeds`) then skipped it (`rule.Then.PoolName ==
""` → `continue`). The "exempted" traffic was therefore NOT exempted — it fell
through and was DNAT'd by a later matching rule, reaching a destination the
operator explicitly exempted (fail-open).

**Parser.** The DNAT then-parser now recognizes `off` in both AST shapes
(flat-set leaf and hierarchical child), mirroring the SNAT `off` handling — it
sets `Then.Type = NATDestination`, `Then.Off = true`. The `set` schema
(`schema_security.go`) declares `off` under `then destination-nat` so CLI
completion / `?` help advertise it.

**Snapshot builder.** An `off` rule (`Then.Type == NATDestination && Then.Off`)
is no longer skipped for having no pool. It runs the SAME destination / source /
protocol / port match expansion as a translate rule (so the exemption is scoped
identically) but emits an entry with an empty `pool_address` and the additive,
skew-safe `off` wire field set. The pool lookup, pool-address/port validation,
and pool-port override are all skipped for an `off` rule (there is no pool).

**Dataplane (`nat/destination.rs`).** `DnatEntry` carries `off`.
`from_snapshots` skips the `pool_address` parse for an `off` entry (it has none)
and stores a placeholder value that is never read. The lookup helpers
(`match_entries`, `match_prefix_slots`) now return a `DnatOutcome` enum
(`Translate | Exempt`) instead of the raw pool value; a matched `off` entry
yields `Exempt`. Because `Exempt` is a non-`None` `.or_else` result, an
exemption at a more-specific proto/port/prefix tier HALTS the tier chain and is
never overridden by a broader translate tier — the Junos "matched rule wins,
stop" semantic. `lookup_with_counter_scoped` maps `Exempt` (and no-match) to no
DNAT decision. `off` is added to the `insert_entry` / `insert_prefix_slot` dedup
identity, so an exemption and a translate rule that share an otherwise-identical
match stay DISTINCT and the earlier-inserted (config-order-first) entry wins the
`.find()` (deduping them would drop the exemption — the fail-open again). An
`off` entry is excluded from `destination_ips_scoped`, so the exempted
destination is NOT registered as a firewall-local address (no proxy-ARP/ND for a
real routed host, only for a translated VIP).

**Shadowed-VIP withdrawal (#6025).** Excluding the `off` entry *itself* from
`destination_ips_scoped` is not sufficient. The common operator idiom is a
specific `/32 destination-nat off` inside a BROADER translate rule (a pool DNAT
over a subnet, one host exempted). The exempt `/32` correctly WINS the DNAT match
— an exact-host entry is probed before any prefix in `lookup_with_counter_scoped`
— so it is never translated. But the broader translate PREFIX registers its VIP
via the #3164 bounded host-by-host expansion, and that expansion re-registered
the exempt `/32` as a firewall-local address even though the `off` entry was
skipped. Result: the exempt host wins the match (no translation) yet its inbound
traffic was consumed via LocalDelivery instead of being routed to the real host —
a silent blackhole of exactly the host the operator meant to pass through.
`destination_ips_scoped` now withdraws a prefix-expanded (or prefix-base) address
when a superset exact-host `off` exemption shadows it: `off_scope_superset`
requires the exemption to catch every packet the translate slot would (protocol,
port, zone, interface, routing-instance are wildcard-or-equal; source and the
#3437/#3449 L4-application axes must be unconstrained). Because the exact-host
exemption is probed before the prefix, a superset match GUARANTEES the exemption
wins for that host, so withdrawing it can never blackhole genuinely-translated
traffic; a partially-scoped exemption (a narrower source/port/proto than the
translate) never suppresses, so a non-exempt host under the same translate prefix
stays firewall-local and its DNAT delivery is preserved. The withdrawal is
per-translate-slot, so a host exempt for one slot but translated by another slot
is still registered by the other slot.

**Wire.** One additive, skew-safe field: `DestinationNATRuleSnapshot.off`
(`json:"off,omitempty"` / `#[serde(default)]`). An older helper that ignores it
drops the pool-less `off` entry (reverting to the pre-#3844 fail-open, never a
crash); a newer helper honoring an older control plane that omits the field
defaults it `false` (a normal translate entry). `protocol_wire_v1.json`
regenerated (one `"off": false` line on the DNAT specimen).

## Known limitation: first-packet interface-address DNAT / static-NAT bypass (#5837)

**Symptom.** A destination-NAT or static-NAT rule whose PUBLIC (matched /
external) destination address is one of the firewall's own configured interface
addresses is INERT on the FIRST packet of a new flow. The client's initial
packet is delivered to the local host stack instead of being translated and
zone-policed. Reply packets and packets on an already-established session are
unaffected (the translation applies once a session exists) — only the very first
packet of each new flow is misrouted.

**Root cause.** On a non-GRE session miss the userspace AF_XDP shim
(`userspace-xdp/src/lib.rs` `try_xdp_userspace` / `is_local_destination`)
classifies a packet destined to a firewall-local interface address as
kernel-local and shunts it to the host BEFORE consulting destination-NAT /
static-NAT (`is_local_destination` runs ahead of `pre_routing_dnat`).
`is_local_destination` inspects the INGRESS destination — for a DNAT rule that is
the `match destination-address` (the public IP the client targets), NOT the
`then destination-nat pool` address (the internal translation TARGET, which the
ingress classifier never sees). So a legitimate Junos port-forward / static 1:1
mapping onto the WAN interface's own address never fires on the first packet.

**Track-1 mitigation (shipped): a commit-time WARNING.** The Go config compiler
now emits a WARN-only advisory (`validateNATInterfaceAddressCollisionWarnings`,
`pkg/config/compiler_validate_warn_nat_iface_addr.go`, wired into
`ValidateConfig`) for each destination-NAT / static-NAT rule whose matched /
external public address equals a configured interface address (static unit
addresses AND VRRP VIPs, both families). It names the rule-set/rule and the
colliding interface address. The advisory fires on BOTH the strict commit path
and the tolerant load / peer-sync path — the config is legal Junos and works for
reply / established traffic, so it never rejects or changes forwarding (a hard
reject would also brick a boot on a previously-committed config). This makes the
previously SILENT bypass LOUD so the operator can either move the service to a
non-interface public address or knowingly accept first-packet local delivery.
Scope: literal `match destination-address` values are checked; address-book-NAME
matches are out of scope (resolving them needs the address-book fold, and the
common case uses a literal address).

**Interface-mode-SNAT exclusion (rev6052): only fires when the address is
genuinely kernel-local.** An interface address is NOT always kernel-local. When
an interface-mode source-NAT rule translates traffic TO a zone, the dataplane
moves every address of that zone's interfaces OUT of the kernel-local set and
INTO `interface_nat` (`nat_translated_local_exclusions`,
`userspace-dp/src/afxdp/rst.rs`). `is_local_destination` then short-circuits to
FALSE for such an address (it checks `USERSPACE_INTERFACE_NAT` membership BEFORE
the `local_v4`/`local_v6` check), so the first SYN reaches the helper and inbound
DNAT / static-NAT DOES apply — the translation is NOT inert. Warning on it would
be a false-warn on the CANONICAL masquerade + WAN-port-forward config (interface
SNAT `trust`→`untrust` + a DNAT from `untrust` matching the untrust interface's
own WAN-IP). The advisory therefore excludes any matched address that
interface-mode source-NAT routes into `interface_nat`: it iterates
`cfg.Security.NAT.Source`, collects the to-zone of every rule that is
`interface_mode && !off && to_zone != ""` (mirroring the rst.rs predicate
exactly), and excludes the configured addresses of every interface in those
zones. The Go mirror excludes the SAFE SUPERSET (all configured unit addresses of
a to-zone interface, not just the single `pick_interface_v4/v6` result), so it
can never false-warn; it may only slightly under-warn on a genuinely-inert
SECONDARY (non-picked) address of a multi-address interface. VRRP VIPs are NOT
excluded — `pick_interface_v4/v6` reads configured interface addresses, never
VIPs, so a VIP stays kernel-local and a DNAT/static match on it is still inert
(still warns). The advisory now fires only when the address is genuinely
kernel-local, not when it is interface-NAT-routed.

**Track-2 (NOT PLANNED): the full dataplane fix.** A dedicated intent map probed
before the local classification (Option B) is a large, verifier-gated, HA-aware
project. It was tracked as #6051 and is **plan-killed** — the commit warning is
the terminal mitigation, not an interim one.

The three reasons, all still true at HEAD:

- **The verifier constraint is real and current.** `is_local_destination` lives
  in `userspace-xdp/src/lib.rs` — the retained AF_XDP shim, which is a real eBPF
  program under a real verifier. The eBPF *dataplane* retirement (#1373/#1476)
  deleted `bpf/xdp/` and `bpf/tc/` but did not retire this shim, so the 1M-insn
  cap and the tail-call ban still bind. The probe would have to live in the miss
  arm and every degraded / binding-missing / heartbeat-stale branch and behind an
  IPv6-AH guard, with no shimverify headroom metric to size it against.
- **Two correctness dimensions are unsolved, not merely unimplemented**:
  fail-closed behaviour on incomplete/failed intent-reconcile state, and
  HA-failover generation-safety of the intent map across a primary swap.
- **The affected population is small.** Per the interface-mode SNAT fold above,
  the canonical masquerade + WAN-port-forward config is not affected at all. The
  residual is a DNAT / static-NAT rule matching an interface address on an
  interface whose zone is not the to-zone of any interface-mode source-NAT rule —
  and it warns at commit with the workaround stated.

The converged design survives on branch `research/5837-xdp-dnat-before-local`
(`docs/research/5837-xdp-dnat-before-local/plan.md` §0b + §1-§13) if a measured
operator report on that residual ever revives it.
