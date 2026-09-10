# Deterministic NAT (CGNAT) Support

## Overview

Carrier-grade NAT with deterministic port block allocation. Each subscriber from
a configured host range gets a fixed, algorithmically-computed block of ports on
a public IP address. The mapping is purely mathematical -- no per-session state
is needed for reverse lookup, enabling ISP compliance logging without per-session
overhead.

**Commits:** `74e1d17` (IPv4 CGNAT, eBPF — historical), `439cd3f` (IPv6/NAPT64
extension, eBPF — historical), #4560 (commit-time advisory), #4559 (userspace
port of BOTH mode 1 and mode 2 — the current runtime path)

## Runtime status (userspace dataplane)

> The original block allocator (`74e1d17`, `439cd3f`) lived only in the eBPF
> plane, which was retired in #1373/#1476. After #1476 a deterministic pool
> committed clean but SILENTLY round-robined on the userspace dataplane (the
> only runtime). #4560 added a commit-time advisory; **#4559 ports BOTH the IPv4
> (mode 1) and the IPv6/NAPT64 (mode 2) block allocators to `userspace-dp`.**

| Path | Status |
|------|--------|
| **IPv4 subscriber (mode 1)** | **ENFORCED** on the userspace dataplane (#4559). The Go builder carries the block/host params; the Rust allocator maps each in-range subscriber IPv4 to a fixed external pool address + port block, reversible from `(external IP, port)` with no per-flow state. |
| **IPv6 subscriber / NAPT64 (mode 2)** | **ENFORCED** on the userspace dataplane (#4559) via the NAT64 forward path. When the source pool referenced by a `security nat nat64` rule-set carries `port deterministic` with a `/32` or `/64` IPv6 host, `buildNAT64Snapshots` carries the block/host params and `nat64.rs allocate_source` maps each IPv6 subscriber (the 32-bit word after the prefix) to a fixed external IPv4 + port block, reversible from `(external IPv4, port)` with no per-flow state. An IPv6-host deterministic pool NOT referenced by a NAT64 rule-set (a plain source-NAT rule cannot translate v6→v4), or with an unsupported subscriber-prefix length, still round-robins and keeps the commit-time advisory (`ValidateConfig`, #4559). **#6227 item 1:** `build_deterministic_v6` (`nat64.rs`) can ALSO fall back to round-robin for a rule that DID request deterministic mapping — a malformed host base, degenerate block math, or a `host_count` `u32` overflow (pool size × blocks-per-ip). That downgrade is no longer silent: it bumps `DETERMINISTIC_V6_DOWNGRADE_COUNT` (an `AtomicU64`, read via `#[cfg(test)]` today, future stats-plumbing candidate) and emits a one-line `eprintln!` naming the rule, so an operator relying on deterministic CGN mapping for compliance logging is not silently switched to round-robin. |

See "Userspace Dataplane Implementation (#4559)" below. The "BPF
Implementation" section is retained for historical reference only — that source
was deleted in #1476.

## Configuration

### IPv4 Subscribers (Deterministic Mode 1)

```
set security nat source pool CGNAT-POOL address 203.0.113.1/32 to 203.0.113.4/32
set security nat source pool CGNAT-POOL port deterministic block-size 2016
set security nat source pool CGNAT-POOL port deterministic host address 100.64.0.0/25
set security nat source pool CGNAT-POOL port range low 1024 high 65535
```

This allocates:
- 4 public IPs (203.0.113.1 through 203.0.113.4)
- Port range 1024-65535 = 64512 ports per IP
- Block size 2016 = 32 blocks per IP
- 4 IPs x 32 blocks = 128 subscriber slots
- 100.64.0.0/25 = 128 hosts (must fit within the 128 blocks -- validated at
  compile: `totalBlocks >= subscriberCount`, where `totalBlocks` counts EXPANDED
  pool hosts, so a CIDR member counts every host it enumerates -- #9498). A larger prefix such as
  `/22` (1024 hosts) is rejected `insufficient capacity (128 blocks) for
  1024 subscribers` -- widen the pool (more public IPs) or shrink the
  block-size to add blocks.

The four `set` lines above are entered in flat-set order; `block-size` and
`host address` are SEPARATE `set` lines under the same `port deterministic`
sub-stanza and GROUP onto one pool (#3864). The equivalent hierarchical
block form also compiles:

```
security {
    nat {
        source {
            pool CGNAT-POOL {
                address 203.0.113.1/32 to 203.0.113.4/32;
                port {
                    range low 1024 high 65535;
                    deterministic {
                        block-size 2016;
                        host address 100.64.0.0/25;
                    }
                }
            }
        }
    }
}
```

### IPv6 Subscribers / NAPT64 (Deterministic Mode 2)

```
set security nat source pool CGNAT64-POOL address 203.0.113.1/32 to 203.0.113.8/32
set security nat source pool CGNAT64-POOL port deterministic block-size 2016
set security nat source pool CGNAT64-POOL port deterministic host address 2001:db8::/32
```

IPv6 subscribers get deterministic IPv4 SNAT allocation based on their IPv6
source address prefix. The subscriber index is derived from the 32-bit word
after the configured prefix:
- `/32` prefix: word[1] (bytes 4-7 of IPv6 address)
- `/64` prefix: word[2] (bytes 8-11 of IPv6 address)

Only `/32` and `/64` prefix lengths are supported for IPv6 host addresses (any
other length is hard-rejected at commit: `IPv6 host prefix must be /32 or /64`).

**What a reverse lookup can actually resolve to (#9070).** The reverse direction
reconstructs the subscriber WORD, not the host, so its answer is the network
base of a *deterministic unit* — the configured prefix plus that 32-bit word:

| configured prefix | subscriber word | deterministic unit |
|---|---|---|
| `/32` | word[1] (bytes 4-7)  | **`/64`** |
| `/64` | word[2] (bytes 8-11) | **`/96`** |

The unit is therefore NEVER the configured prefix, and reporting the configured
value would be confidently wrong rather than merely ambiguous. `show` renders
this as `Internal prefix: <base>/<unit>` (not `Internal host:`, which reads as an
exact `/128`), and both APIs carry it: REST `internal_prefix_len`, gRPC
`internal_prefix_len`. It is 0 in IPv4 mode, where the recovered value IS an
exact host.

**The reverse index arithmetic cannot wrap (#9498).** A reverse lookup computes
the subscriber index as `pool_index x blocks_per_ip + block_index`. Go computed
that in 32 bits, so a pool larger than 66,576 addresses (at the widest 64,512
blocks per address) wrapped, and the wrapped index could land INSIDE the
subscriber range. The lookup then named the WRONG subscriber instead of failing
closed. The smallest commit-accepted config that reached it was a `/16` plus a
`/21` with `block-size 1` and a `/32` subscriber. The index is now computed in 64
bits, so any index past the subscriber range fails closed, exactly as the Rust
reverse path (`checked_mul` / `checked_add`) does.

The source must lie **inside the configured subscriber prefix**: the subscriber
index is derived from the 32-bit word alone, so a source in a DIFFERENT prefix
that happens to share that word would otherwise be mapped into the in-prefix
subscriber's fixed block, and the stateless reverse map (which reconstructs from
`host_base`) would attribute it to the WRONG subscriber. `deterministic_indices_v6`
therefore rejects any source whose prefix bytes before the subscriber word differ
from `host_base` (`/32` → `octets[0..4]`, `/64` → `octets[0..8]`); an
out-of-prefix source fails CLOSED rather than being translated (#4863).

**The pool must be referenced by a `security nat nat64` rule-set as its
`source-pool`** — mode-2 enforcement lives on the NAT64 forward path (the v6→v4
translation). A `/32` or `/64` deterministic pool NOT wired to a NAT64 rule-set
commits but round-robins (the plain source-NAT path has no v6→v4 mode); the
commit-time advisory surfaces that. Example wiring:

```
set security nat source pool CGNAT64-POOL address 198.51.100.1/32 to 198.51.100.8/32
set security nat source pool CGNAT64-POOL port deterministic block-size 2016
set security nat source pool CGNAT64-POOL port deterministic host address 2001:db8::/32
set security nat nat64 rule-set rs1 prefix 64:ff9b::/96
set security nat nat64 rule-set rs1 source-pool CGNAT64-POOL
```

Block boundaries for mode 2 are computed against the FIXED NAT64 translated-port
range (1024-65535, the per-prefix allocator range in `userspace-dp/src/nat64.rs`
`NAT64_PORT_LOW`/`NAT64_PORT_HIGH`), NOT the source pool's own `port` range
(which the NAT64 allocator ignores). The subscriber count is bounded by pool
capacity (`num_pool_ips * blocks_per_ip`): an IPv6 subscriber word extends far
beyond the pool, so a subscriber past that capacity fails CLOSED rather than
aliasing another subscriber's block. Go computes that product in 64 bits: a pool
whose capacity exceeds the 32-bit subscriber space is reported NOT deterministic,
matching the Rust `build_deterministic_v6` downgrade, rather than wrapping to a
small, wrong capacity (#9498).

### Pool Utilization Alarm (#2079)

```
set security nat source pool-utilization-alarm raise-threshold 80
set security nat source pool-utilization-alarm clear-threshold 70
```

This is a single GLOBAL raise/clear pair (matching Junos `set security nat
source pool-utilization-alarm` scope); the same thresholds apply to every
source pool. `clear-threshold` is OPTIONAL (#4077, Junos-faithful): a raise-only
config —

```
set security nat source pool-utilization-alarm raise-threshold 90
```

— commits, with `clear-threshold` defaulted at parse time to a 10-point
hysteresis margin below raise (`defaultPoolAlarmClearThreshold`, floored at 1),
so raise 90 → clear 80, raise 50 → clear 40, raise 5 → clear 1. The default
always lands inside `0 < clear < raise`, so the runtime monitor arms the alarm
(it treats `clear <= 0` as disabled).

When BOTH are set, validation requires `0 < clear-threshold < raise-threshold
<= 100` with the standard strict-vs-lenient split (`validatePoolUtilizationAlarm`,
`compiler_nat.go`): a bare `pool-utilization-alarm;` (raise=0/clear=0) and
inverted/equal thresholds — and an EXPLICIT `clear-threshold 0` — are hard
`commit`/`commit check` errors, but the tolerant load / HA peer-sync path
downgrades them to a warning so a node that committed a legacy config before
this gate existed still boots (the runtime monitor treats raise<=0 as disabled,
so a leniently-loaded bad config is inert).

Runtime behaviour (vSRX-faithful) is driven by a slow (10s) daemon-resident
monitor (`pkg/natpoolalarm`) over the helper's LAST-APPLIED NAT pool snapshot
(`dp.AppliedNATView()` — config + same-generation pool counters; no Rust /
wire change, no extra control-socket traffic — it reuses the cached 1 Hz
status poll). For each rule-referenced, non-deterministic source pool the
monitor computes port utilization
`UsedPorts * 100 / (AddressCount * (PortHigh - PortLow + 1))` and applies
hysteresis: it RAISES when utilization `>= raise-threshold` and CLEARS when it
drops `< clear-threshold` (strict). On each raise/clear transition (and only
on a transition — never per tick) it:

- updates `show security alarms` (Class NAT, Severity Minor), visible at both
  the gRPC and local-CLI render sites; and
- emits one structured `RT_NAT NAT_POOL_UTILIZATION_ALARM_RAISED` /
  `..._CLEARED` syslog line through the configured syslog streams / local
  writers.

An alarm is also cleared when its last referencing source-NAT rule is removed,
the pool is removed from config, the pool is converted to deterministic, or the
alarm feature is disabled. The monitor HOLDs (makes no decision, neither raise
nor clear) when the dataplane view is unavailable (helper down / no reconciled
apply yet — including just after a helper restart) or mid-apply (status
generation != applied generation), during a RETH-MAC bring-up `DeferWorkers`
window (the helper has accepted the new generation but not yet reconciled its
forwarding state, so the NAT counters are still the old generation — the applied
snapshot is recorded only after the post-`NotifyLinkCycle` rebind reconcile),
and for transiently uncomputable samples (`AddressCount==0` / `PortHigh<PortLow`
/ capacity 0). Deterministic pools are SKIPPED — `UsedPorts` is not the right
numerator for block-based allocation.

**Block-based utilization for deterministic pools.** There are two distinct
signals here; the config-derived one landed, the runtime one is deferred.

*Config-derived block provisioning (#4752 — DONE, Go-bounded).* The
`xpf_nat_deterministic_pool_blocks_total` /
`xpf_nat_deterministic_pool_blocks_allocated` gauges (see "Prometheus Metrics"
below) expose provisioned-subscriber-blocks over block capacity, computed
entirely from the committed config — the deterministic mapping is a stateless
reversible function, so no dataplane readout is needed. This is the
capacity-planning view the #2079 alarm could not provide (it keyed off pool-wide
`UsedPorts`). It answers "am I about to run out of blocks to assign new
subscribers?", NOT "is a subscriber's block full right now?".

*Runtime block occupancy (#4559 assessment — DEFERRED, not a bounded add).*
With the mode-1/mode-2 allocators now enforced (#4559), a deterministic pool's
runtime exhaustion mode is fundamentally PER-SUBSCRIBER, not pool-wide: each
subscriber owns a fixed port block and cannot borrow another's, so a subscriber
can exhaust its own block (new flows for THAT subscriber fail) while the pool's
total `UsedPorts / capacity` stays low. A pool-wide total-port alarm therefore
cannot capture the CGNAT failure it is meant to warn about, and neither can the
config-derived provisioning ratio above (which is static once the config is
committed).

The Junos-faithful runtime metric is block occupancy — distinct subscriber
blocks with
at least one live flow, over `AddressCount * blocks_per_ip` — but the allocator
does not track it: it holds a global per-address occupancy bitmap and a
`live_by_flow` map, neither of which is a distinct-occupied-blocks count.
Deriving it per poll would mean scanning every address bitmap by block range
(O(AddressCount * portRange) ≈ 16M bit tests for a 256-IP pool) or adding new
hot-path per-block active-flow counters — a design decision plus new allocator
state, not a mechanical add. And even block-occupancy does not surface the true
per-subscriber-block-full condition (that a specific subscriber's block is
saturated). This RUNTIME half is left as a scoped follow-up (the config-derived
provisioning gauges in #4752 do not cover it): pick the metric (occupied-block
ratio vs per-subscriber-block-full events), add the bounded counter to the
allocator, thread it through `SourceNATPoolStatus`, and teach `pkg/natpoolalarm`
to use it for deterministic pools instead of skipping them.

NOTE: the legacy eBPF `nat_port_counters` map (read by `metrics_nat.go` and
the CLI `show security nat source pool` "Utilization %") is never incremented
post eBPF-retirement and reports a random seed value in userspace mode — the
alarm deliberately uses the allocator snapshot (`SourceNATPoolStatus.UsedPorts`),
not that dead path. Fixing those two legacy surfaces is tracked separately.

## Algorithm

For a subscriber with source IP `src`:

```
sub_idx = ntohl(src) - ntohl(host_base)       # subscriber index in host range

ip_idx    = sub_idx / blocks_per_ip            # which public IP
block_idx = sub_idx % blocks_per_ip            # which port block on that IP

port_start = port_low + block_idx * block_size
port       = port_start + (counter++ % block_size)   # round-robin within block
```

The reverse mapping (given public IP + port, find subscriber) is equally simple:

```
ip_idx    = lookup(public_ip)                  # which pool IP index
block_idx = (port - port_low) / block_size     # which block
sub_idx   = ip_idx * blocks_per_ip + block_idx # subscriber index
subscriber = ntohl(host_base) + sub_idx        # subscriber IP
```

This allows ISP logging of just `(public_ip, port_range, subscriber)` tuples
at pool configuration time, instead of per-session SNAT logs.

`lookup(public_ip)` is an O(1) hash into a reverse index built ONCE from the
ordered pool (`build_pool_reverse_index`, #5660), not a per-lookup linear scan
of the pool (which could be up to `MAX_POOL_PREFIX_HOSTS` = 65536 addresses on
the reverse/session-miss cold path). The pool is an arbitrary, possibly
non-contiguous ordered list — `ip_idx` is a POSITION in that list, so a direct
`public_ip - pool_base` subtraction would be wrong; the index maps each pool
address to the same position the forward path selects with `pool_v4[ip_idx]`.

**Pool member grammar (#6812 F-C).** `expandPoolV4` rejects a member whose CIDR
mask is not CANONICAL — `netip.ParsePrefix` must accept it, not merely
`net.ParseCIDR`. The two disagree: `net.ParseCIDR` reads a leading-zero prefix
length, taking `10.0.0.0/016` as `/16`, while `netip.ParsePrefix` (the commit
gate's grammar) and `parse_canonical_prefix_len` (the dataplane's) both refuse
it. Without the check the deterministic surface was the most confident liar in
the system: the pool is stamped `invalid_pool` and translates NOTHING, while a
forward-mapping query answered with a 65,536-address pool built off a member no
other layer accepts — the invariant-8 forensic failure this section exists to
prevent. Narrowing only: such a pool TRANSLATES NOTHING either way — the
snapshot builder stamps it `invalid_pool` and it installs no allocator — so the
lookup now returns an error instead of a fiction. (Round 7 correction: this
sentence also said "already refused at commit". That holds only for a pool a
pool-mode rule REFERENCES —
`validateSourceNATPoolAddressGrammarStrict` walks rule references, not the pool
table, so an UNREFERENCED pool carrying `10.0.0.0/016` compiles strict-clean.
It is still unusable, which is what carries the conclusion.)
Bound by the REJECT half of
`TestDeterministicPoolExpansionMatchesSharedGrammarFixture_6812`, which reads
the same `snat_pool_grammar_v1.json` the Rust expander and the Go grammar
predicate read.

## Operator lookup surface (#5794)

The deterministic mapping is exposed for the CGN compliance / forensics
workflow through a single canonical domain query (`pkg/nat`,
`LookupForward` / `LookupReverse`) that the CLI, gRPC, and REST surfaces all
consume, so a CLI answer can never drift from an API answer. The math is the
Algorithm above, mirrored in Go and pinned to the Rust allocator by
cross-language golden vectors plus a Go-side parity test that cross-checks the
parameter derivation against the shipped wire-field builders
(`deterministicSourceNATFields` / `deterministicNAT64V6Fields`).

**Algorithmic mapping vs live session state.** This surface reports the
*algorithmic* subscriber↔translation attribution — the stateless, reversible
function of the applied pool configuration. It is NOT a live session lookup:
it does not consult the conntrack table and does not report whether a specific
port is currently in use. Use `show security nat source pool` and the session
commands for live occupancy; use this for "which subscriber owns
`(public IP, port)`" and "which block is subscriber X assigned", which hold
regardless of live traffic.

**Applied generation, not candidate config.** The query runs against the
LAST-APPLIED NAT generation (the configuration the dataplane is actually
enforcing), read from the userspace manager's cached `AppliedNATView` with no
control-socket I/O and no packet-path index. A candidate change that has been
committed but not yet applied does NOT move the answer until it lands; when the
dataplane has applied nothing yet, the query fails closed with
`no-applied-view`. The applied generation is echoed in every result.

### CLI (vSRX parity: `show security nat source deterministic-nat`)

```
# Forward — subscriber -> translated external IP + assigned port block
show security nat source deterministic-nat internal-host 100.64.0.5 [pool CGNAT-POOL]

# Reverse — translated (external IP, port) -> internal subscriber
show security nat source deterministic-nat nat-ip 203.0.113.1 nat-port 3900 [pool CGNAT-POOL]
```

The optional `pool` filter scopes the lookup to one source NAT pool. When it is
omitted and more than one deterministic pool contains the queried tuple, the
query is rejected as `ambiguous-pool` (it never returns a first-iteration
match); select a pool to disambiguate. Reordering a pool's addresses changes
`ip_idx` and therefore the attribution — the applied snapshot's pool order is
authoritative.

### gRPC / REST

- gRPC: `GetNATDeterministic(GetNATDeterministicRequest)` — `direction`
  FORWARD/REVERSE, optional `pool`, `internal_host` (forward) or
  `nat_ip` + `nat_port` (reverse). Failures return `found=false` with a stable
  `error_code` in the response body (not a gRPC status error).
- REST: `GET /api/v1/security/nat/deterministic?internal-host=<ip>[&pool=<name>]`
  (forward) and `?nat-ip=<ip>&nat-port=<n>[&pool=<name>]` (reverse), returning a
  `NATDeterministicInfo` JSON body.

**Stable machine-readable error codes** (identical across CLI/gRPC/REST):
`no-applied-view`, `unknown-pool`, `not-deterministic`, `malformed-input`,
`out-of-range` (subscriber outside the pool's servable range), `ambiguous-pool`,
and `not-found` (a reverse tuple that maps to no subscriber). A subscriber that
is inside the host CIDR but beyond the pool's servable capacity
(`ip_idx >= len(pool)`) returns `out-of-range`, matching the allocator's
fail-closed behavior.

## Userspace Dataplane Implementation (#4559)

Both the IPv4 (mode 1) and the IPv6/NAPT64 (mode 2) paths are implemented in the
Rust AF_XDP dataplane. The external-IP + port-block assignment is byte-for-byte
the same deterministic, reversible mapping the eBPF plane used (Algorithm
above); the userspace version additionally tracks live flows so a port is not
reused while a session is alive.

### Mode 1 (IPv4 subscriber, plain source NAT)

| Component | Change |
|-----------|--------|
| `pkg/dataplane/userspace/nat_source.go` | `deterministicSourceNATFields()` precomputes `mode`/`block_size`/`blocks_per_ip`/`host_base` (host-order u32)/`host_count` from the pool + the defaulted port range, and stamps them on `SourceNATRuleSnapshot`. IPv4 host → mode 1; an IPv6 host takes the NAT64 (mode 2) path below, not this one. |
| `pkg/dataplane/userspace/protocol.go` | `SourceNATRuleSnapshot` gains the five additive `deterministic_*` wire fields (omitempty, #1961 skew-safe). |
| `userspace-dp/src/protocol/nat.rs` | Rust mirror of the wire fields (`#[serde(default)]` — an old control plane omits them → round-robin). |
| `userspace-dp/src/nat/allocator.rs` | `DeterministicV4` params; `deterministic_indices_v4()` (subscriber IPv4 → `(ip_idx, block_idx)`); `allocate_deterministic_v4()` (claims the first free port in the subscriber's block against the live owner map, collision-free); `reverse_deterministic_v4()` (`(external IP, port)` → subscriber IPv4, no per-flow state — the external-IP→`ip_idx` step is an O(1) `PoolReverseIndex` hash built once by `build_pool_reverse_index()`, #5660, not a per-lookup pool scan). A deterministic allocation is NOT recycled on release (its block is re-scanned directly), so a deterministic-only pool never grows the recycle queue. **#5178:** the HA standby's synced-reservation path (`reserve_flow`, driven by `reserve_synced_source_nat_allocation` passing `rule.deterministic_v4.is_some()`) threads the SAME `deterministic` flag onto the reservation, so a synced deterministic reservation also releases via `free_no_recycle` — a standby running a deterministic pool never grows its recycle queue under synced-session churn. Before #5178 `reserve_flow` hardcoded `deterministic: false`, mis-tagging every synced reservation non-deterministic and leaking each released port into the recycle queue the deterministic path never drains (unbounded standby memory). |
| `userspace-dp/src/nat/source.rs` | Builds `SourceNatRule.deterministic_v4` from the snapshot (mode 1 only) and routes a deterministic-pool match through `allocate_deterministic_v4` instead of the round-robin allocator. An out-of-range subscriber fails CLOSED (`DeterministicSubscriberOutOfRange`) rather than silently round-robining. |

### Mode 2 (IPv6 subscriber / NAPT64, NAT64 forward path)

| Component | Change |
|-----------|--------|
| `pkg/dataplane/userspace/nat64.go` | `deterministicNAT64V6Fields()` computes `block_size`/`blocks_per_ip` (against the FIXED NAT64 range)/`host_prefix_len` (32 or 64)/`host_base_v6` from the referenced source pool, and `buildNAT64Snapshots` stamps them on `NAT64RuleSnapshot`. Only a `/32`-or-`/64` IPv6 host referenced by a NAT64 rule-set yields the params; anything else stays zero (round-robin + advisory). |
| `pkg/dataplane/userspace/protocol.go` | `NAT64RuleSnapshot` gains the four additive `deterministic_*` wire fields (omitempty, #1961 skew-safe). |
| `userspace-dp/src/protocol/nat.rs` | Rust mirror of the four NAT64 wire fields (`#[serde(default)]`). |
| `userspace-dp/src/nat/allocator.rs` | `DeterministicV6` params; `deterministic_indices_v6()` (IPv6 subscriber → `(ip_idx, block_idx)` from the 32-bit word after the prefix — offset 4 for `/32`, offset 8 for `/64`; #4863 rejects sources whose prefix bytes before the subscriber word differ from `host_base`, so an out-of-prefix source sharing the subscriber word fails CLOSED instead of stealing the in-prefix subscriber's block); `allocate_deterministic_v6()` (mirrors the v4 claim, collision-free, not recycled); `reverse_deterministic_v6()` (`(external IPv4, port)` → subscriber IPv6 prefix, no per-flow state — same O(1) `PoolReverseIndex` for the external-IP→`ip_idx` step, #5660). |
| `userspace-dp/src/nat64.rs` | `Nat64Prefix` gains `deterministic_v6: Option<DeterministicV6>`, built from the snapshot at `from_snapshots` time (`host_count` derived from the parsed pool size, pool-bounded). `allocate_source` routes through `allocate_deterministic_v6` when set. An out-of-range subscriber fails CLOSED. **#5178:** `reserve_synced_nat64_allocation` passes `prefix.deterministic_v6.is_some()` to `reserve_nat64_pool_port` → `reserve_flow`, so a synced NAPT64 reservation on the standby is tagged deterministic and released via `free_no_recycle`, mirroring the active node's `allocate_deterministic_v6` release (no recycle-queue growth). |
| `pkg/config/compiler_validate_warn.go` | The #4560 advisory is narrowed to residual UNENFORCEABLE deterministic pools only (an IPv6 host not referenced by a NAT64 rule-set, or an unsupported prefix length); an enforced mode-1 or mode-2 pool no longer warns (`deterministicIPv4Enforced` / `deterministicNAPT64Enforced`). |

**Difference from the retired eBPF version:** the eBPF allocator picked the
port within a block with a single per-pool `counter++ % block_size` and kept no
per-flow state. The userspace allocator instead claims the first *free* port in
the block (checked against the shared live-owner map) and records the flow, so
two concurrent sessions from one subscriber never collide on a translated tuple
and a flow re-allocates its own tuple on retransmit. The subscriber→block→IP
assignment (the part that must be deterministic and reversible for compliance
logging) is identical for both modes.

**Allocator lock discipline (#9130).** The block probe runs BEFORE the
allocator's `live` map mutex is taken, and every critical section around it is
O(1). Until #9130 both `allocate_deterministic_v4` and `allocate_deterministic_v6`
took `lock_live()` first and held it across the whole linear CAS scan of the
subscriber's block, so the hold time was O(occupied prefix of the block) — up to
a few thousand CAS attempts for a subscriber near its own block budget, with
every other flow through that pool serialized behind it. That is the shape #4676
had already removed from the sibling round-robin PAT path
(`allocate_translation_inner`: claim the port lock-free on the CAS occupancy
bitmap, take the mutex only for the reuse/cap/insert critical section); the
deterministic arms never received it. The order is now:

1. scan the subscriber's block on the lock-free occupancy bitmap;
2. **no free port** — take the mutex once, O(1), and check idempotent re-entry
   BEFORE reporting the block full. A live flow's own port is one of the
   occupied ones, so a full block is the normal state for a re-entering flow;
   reporting exhaustion here would turn a working flow's second packet into a
   drop;
3. **port claimed** — take the mutex once, O(1), for the re-entry check, the
   flow-table cap check, and the insert. Both refusals give the claimed port
   back with `free_no_recycle` (never `free_recycle`): a deterministic port is
   reusable via its occupancy bit alone, and the deterministic allocation path
   never drains the per-address recycle queue, so a recycled token would leak
   (the #4559/#5178 no-recycle contract).

The scope is bound by `userspace-dp/src/nat/tests_det_lock_scope_9130.rs`, which
holds `debug_live()` on one thread and asserts an allocating worker still claims
its port on the (lock-free) bitmap — a structural discriminator rather than a
timing assertion.

**Deferred (still tracked in #4559):**
- RUNTIME block-occupancy alarm for deterministic pools (the #2079 alarm still
  skips them — `UsedPorts` is not the right numerator for block allocation; see
  "Pool Utilization Alarm" above for the assessment). The config-derived
  block-PROVISIONING gauges (`blocks_total` / `blocks_allocated`) landed in
  #4752; the deferred half is the live-flow-per-block / per-subscriber-block-full
  runtime signal, which needs new allocator state.

## BPF Implementation

> Historical: this source was deleted in #1476 (eBPF dataplane retirement). It
> is retained here as the reference the userspace port (#4559) reproduces. The
> live implementation is "Userspace Dataplane Implementation (#4559)" above.

### C Struct Extension

`nat_pool_config` was extended from 8 bytes to 40 bytes:

| Field | Type | Mode | Description |
|-------|------|------|-------------|
| `num_ips` | u16 | all | Number of IPv4 IPs in pool |
| `pool_id` | u8 | all | Pool identifier |
| `port_low` | u16 | all | Port range start (default 1024) |
| `port_high` | u16 | all | Port range end (default 65535) |
| `addr_persistent` | u8 | 0 | Same src always maps to same pool IP |
| `deterministic` | u8 | 1,2 | 0=off, 1=IPv4 host, 2=IPv6 host |
| `block_size` | u16 | 1,2 | Ports per subscriber |
| `host_base` | be32 | 1 | IPv4 subscriber range base |
| `host_count` | u32 | 1,2 | Number of subscriber IPs/prefixes |
| `blocks_per_ip` | u16 | 1,2 | Precomputed port_range / block_size |
| `host_prefix_len` | u8 | 2 | IPv6 prefix length (32 or 64) |
| `host_base_v6` | be32[4] | 2 | IPv6 subscriber base address |

### BPF Functions

| Function | File | Purpose |
|----------|------|---------|
| `nat_pool_alloc_deterministic_v4` | xdp_policy.c | IPv4 deterministic allocation |
| `nat_pool_alloc_deterministic_v6` | xdp_policy.c | IPv6/NAT64 deterministic allocation |

Both are `__noinline` to stay within the BPF stack budget. Dispatch is via
`cfg->deterministic`: the policy program checks this flag before calling the
regular `nat_pool_alloc_v4()`.

### Map Changes

`MAX_NAT_POOL_IPS_PER_POOL` increased from 8 to 256 (CGNAT pools need 125+
public IPs). `MAX_NAT_POOL_IPS` correspondingly increased to 8192.

## Go Implementation

| Component | Change |
|-----------|--------|
| `pkg/config/types.go` | `DeterministicNATConfig` struct, `PoolUtilizationAlarmConfig` |
| `pkg/config/compiler_nat.go` | Parse deterministic port config (hierarchical + flat set, accumulated across both AST shapes, #3864), address ranges (`addr1/32 to addr2/32`), capacity validation |
| `pkg/config/schema_security.go` | Models `port deterministic { block-size; host address }` so the flat-set sub-stanza GROUPS + tab-completes (#3864) |
| `pkg/dataplane/compiler.go` | Compile deterministic fields to `NATPoolConfig`, mode 1 vs mode 2 dispatch |
| `pkg/dataplane/types.go` | `NATPoolConfig` extended with deterministic fields |
| `pkg/api/metrics.go` | `xpf_nat_pool_deterministic_info` Prometheus gauge |
| `pkg/cmdtree/tree.go` | `deterministic-nat nat-table` show command |

### Validation Rules

The compiler enforces these at commit time:

1. `block_size` must be > 0
2. `host_address` CIDR must be valid
3. IPv6 host prefix must be `/32` or `/64`
4. Total blocks (pool_ips * blocks_per_ip) must accommodate all subscribers
5. Deterministic NAT is mutually exclusive with `persistent-nat`
6. Deterministic NAT is mutually exclusive with `address-persistent`

### Address Range Expansion

The `expandAddressRange()` function handles `addr1/32 to addr2/32` syntax,
expanding into individual IP strings. Maximum 256 IPs per range.

## DPDK Parity

DPDK retired (#1525). The historical parity work mirrored deterministic
NAT struct and constant changes in `dpdk_worker/` (`shared_mem.h`
`nat_pool_config`, `tables.h` `MAX_NAT_POOL_IPS_PER_POOL=256`,
`policy.c` inline v4 SNAT, `nat64.c` inline v6 NAT64). The DPDK
backend is removed in #1527/#1528; no further DPDK parity work
applies.

## Prometheus Metrics

```
xpf_nat_pool_deterministic_info{pool="CGNAT-POOL", block_size="2016", host_count="1024"} 1
xpf_nat_deterministic_pool_blocks_total{pool="CGNAT-POOL"} 256
xpf_nat_deterministic_pool_blocks_allocated{pool="CGNAT-POOL"} 256
```

`xpf_nat_pool_deterministic_info` is a gauge exposing the deterministic
configuration for each pool.

`xpf_nat_deterministic_pool_blocks_total` and
`xpf_nat_deterministic_pool_blocks_allocated` (#4752) give the deterministic
pool's **block-provisioning** utilization — the signal the #2079 pool-utilization
alarm cannot provide because it keys off pool-wide `UsedPorts`, which is
meaningless when ports are pre-partitioned into fixed per-subscriber blocks:

- `blocks_total` = the pool's block capacity, `len(addresses) * floor(port-range
  / block-size)` (the same `totalBlocks` the compiler validates against the
  provisioned subscriber count).
- `blocks_allocated` = the port blocks statically allocated to the provisioned
  subscriber range (one block per subscriber). For an IPv4 subscriber CIDR this
  is the host-address count; for an IPv6 host the dataplane caps the subscriber
  count at capacity, so `blocks_allocated == blocks_total`.

An operator charts `blocks_allocated / blocks_total` and alarms as it approaches
1.0 — a **capacity-planning** signal ("am I about to run out of blocks to hand
new subscribers?"). Both values are derived entirely from the committed config
(the deterministic mapping is a stateless, reversible function — see
`allocate_deterministic_v4`), so no dataplane readout is required.

This is distinct from — and does **not** replace — the RUNTIME block-occupancy
alarm (distinct blocks with a live flow, and per-subscriber-block-full events),
which remains a deferred Rust follow-up because it needs new allocator state
(see "Block-based utilization for deterministic pools" above).

## CLI

```
show security nat source deterministic-nat nat-table
```

Displays the deterministic mapping table showing subscriber-to-public-IP/port-block
assignments.

## Limitations

- Maximum 256 public IPs per pool (`MAX_NAT_POOL_IPS_PER_POOL`)
- Maximum 32 pools total (`MAX_NAT_POOLS`)
- IPv6 subscriber index limited to 32-bit word extraction (prefix must be /32 or /64)
- No per-subscriber session counting (by design -- the whole point is to avoid per-session state)
