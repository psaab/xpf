# Embedded Router Advertisement (RA) Daemon

Research document analyzing the feasibility of replacing the external `radvd` dependency
with a native Go RA sender embedded directly in `xpfd`.

## 1. Current Architecture

### 1.1 External radvd Management (`pkg/radvd/`)

The `radvd.Manager` manages the external `radvd` binary through three operations:

| Method | Description |
|--------|-------------|
| `Apply()` | Writes `/etc/radvd.conf`, then `systemctl reload radvd` (fallback: SIGHUP via pidfile, fallback: `radvd -C`) |
| `Withdraw()` | Rewrites config with `AdvDefaultLifetime 0`, reloads, sleeps 500ms, then stops+removes config |
| `Clear()` | `systemctl stop radvd` (fallback: kill via pidfile), removes `/etc/radvd.conf` |

### 1.2 Config Pipeline

```
Junos AST
  → compileRouterAdvertisement() (pkg/config/compiler.go:2606)
    → []*RAInterfaceConfig (pkg/config/types.go:1223)
      → radvd.Manager.Apply() generates radvd.conf text
```

The `RAInterfaceConfig` struct captures all RA options xpf uses:

```go
type RAInterfaceConfig struct {
    Interface          string
    ManagedConfig      bool        // M flag
    OtherStateful      bool        // O flag
    Preference         string      // "high", "medium", "low"
    DefaultLifetime    int         // RA Router Lifetime, seconds; meaningful only when DefaultLifetimeSet
    DefaultLifetimeSet bool        // true when default-lifetime was explicitly configured (#4119)
    MaxAdvInterval     int         // seconds (0 = default 600)
    MinAdvInterval     int         // seconds (0 = default 200)
    Prefixes           []*RAPrefix
    DNSServers         []string    // RDNSS addresses (EVERY authored address,
                                   //   all five spellings — #6695)
    NAT64Prefix        string      // PREF64 prefix
    NAT64PrefixLife    int         // PREF64 lifetime seconds
    LinkMTU            int         // advertised MTU (0 = omit)
}

type RAPrefix struct {
    Prefix         string  // CIDR notation
    OnLink         bool
    Autonomous     bool
    ValidLifetime  int     // seconds (0 = default 2592000)
    PreferredLife  int     // seconds (0 = default 604800)
}
```

### 1.3 Integration Points in the Daemon

**Standalone mode** (`daemon.go:1165-1182`):
- `applyConfig()` calls `d.radvd.Apply(raConfigs)` or `d.radvd.Clear()`

**Cluster/HA mode** (`daemon.go:3133-3208`):
- `watchVRRPEvents()` monitors VRRP state transitions
- `applyRethServices()` → `d.radvd.Apply()` on MASTER transition
- `clearRethServices()` → `d.radvd.Withdraw()` on BACKUP transition (goodbye RA)
- RETH interface names resolved via `config.ResolveReth()` + `config.LinuxIfName()`

### 1.4 Pain Points with External radvd

1. **Process lifecycle bugs**: `systemctl reload` fails if radvd isn't running; `systemctl stop`
   races with SIGHUP; zombie processes after unclean daemon shutdown.

2. **Config file races**: Writing `/etc/radvd.conf` then reloading has a TOCTOU window. If xpfd
   crashes between write and reload, a stale config persists across restart.

3. **Goodbye RA fragility**: `Withdraw()` rewrites config → reloads → sleeps 500ms → kills. If
   radvd dies before the reload takes effect, the goodbye RA never sends. If the 500ms sleep is
   too short, radvd is killed before the RA packet hits the wire.

4. **HA failover latency**: On BACKUP transition, the goodbye RA sequence takes ~600ms minimum
   (config write + reload + 500ms sleep + stop). An embedded sender could fire the goodbye RA
   in <1ms.

5. **External dependency**: Requires `radvd` package installed. One more thing to manage in the
   VM image, one more potential security surface.

6. **No programmatic feedback**: Cannot know if the RA was actually transmitted. No error return
   from radvd after SIGHUP — just hope it worked.

## 2. Library Options

### 2.1 `mdlayher/ndp` (Recommended)

**Repository**: https://github.com/mdlayher/ndp
**License**: MIT
**Maturity**: Stable, used in production at DigitalOcean and MetalLB. Powers CoreRAD (a full RA daemon).

**API highlights relevant to RA**:

```go
// Open an ICMPv6 connection bound to an interface
conn, ip, err := ndp.Listen(ifi, ndp.LinkLocal)

// Join all-routers multicast (ff02::2) to receive Router Solicitations
conn.JoinGroup(netip.MustParseAddr("ff02::2"))

// Build and send a Router Advertisement
ra := &ndp.RouterAdvertisement{
    CurrentHopLimit:           64,
    ManagedConfiguration:      cfg.ManagedConfig,
    OtherConfiguration:        cfg.OtherStateful,
    RouterSelectionPreference: ndp.Medium,
    RouterLifetime:            1800 * time.Second,
    Options: []ndp.Option{
        &ndp.PrefixInformation{
            PrefixLength:                   64,
            OnLink:                         true,
            AutonomousAddressConfiguration: true,
            ValidLifetime:                  2592000 * time.Second,
            PreferredLifetime:              604800 * time.Second,
            Prefix:                         netip.MustParseAddr("2001:db8:1::"),
        },
        &ndp.RecursiveDNSServer{
            Lifetime: 1800 * time.Second,
            Servers:  []netip.Addr{netip.MustParseAddr("2001:4860:4860::8888")},
        },
        &ndp.PREF64{
            Lifetime: 600 * time.Second,
            Prefix:   netip.MustParsePrefix("64:ff9b::/96"),
        },
        ndp.NewMTU(1500),
    },
}
conn.WriteTo(ra, nil, netip.MustParseAddr("ff02::1"))
```

**Pros**:
- Complete RFC 4861 message types (RA, RS, NA, NS) and options (PrefixInformation, RDNSS, DNSSL, MTU, PREF64, RouteInformation, CaptivePortal)
- Handles ICMPv6 checksum computation internally
- `Conn.JoinGroup()` / `LeaveGroup()` for multicast management
- `SetICMPFilter()` for efficient kernel-side filtering
- `SetReadDeadline()` for non-blocking reads with periodic stopCh checks
- Already an indirect dependency (`mdlayher/packet` and `mdlayher/socket` in go.mod)
- Active maintenance, good test coverage, fuzzing support

**Cons**:
- Adds a direct dependency (~moderate size)
- Uses `netip.Addr`/`netip.Prefix` (not `net.IP`) — minor conversion needed from `RAInterfaceConfig` strings

### 2.2 `YutaroHayakawa/go-ra`

**Repository**: https://github.com/YutaroHayakawa/go-ra
**License**: Apache 2.0

Higher-level library built on top of `mdlayher/ndp`. Provides a complete RA daemon with YAML config.

**Pros**:
- Handles RA timer logic, RS response, periodic sending out-of-the-box
- Supports all the same options as ndp (RDNSS, PREF64, MTU, etc.)

**Cons**:
- Much heavier dependency — pulls in the full daemon framework
- Less control over integration with xpf's VRRP state machine
- YAML config model doesn't align with xpf's compiled RAInterfaceConfig
- Overkill — we only need the packet building from ndp plus our own timer logic

### 2.3 Raw implementation (no library)

Build RA packets from scratch using `golang.org/x/net/ipv6` + `AF_INET6` raw sockets.

**Pros**:
- Zero new dependencies
- Full control over every byte

**Cons**:
- Must implement ICMPv6 checksum with pseudo-header (already done in `cluster/garp.go`)
- Must implement all NDP option TLV encoding (PrefixInfo, RDNSS, PREF64, MTU, SLLA)
- Must handle multicast group join/leave
- Must handle hop limit = 255 enforcement
- More code to write and test (~300-400 lines just for packet building)
- Re-inventing what `mdlayher/ndp` already provides and tests

**Verdict**: `mdlayher/ndp` is the clear winner. It provides exactly the right abstraction level —
packet building, connection management, multicast — without imposing a daemon framework. The
existing codebase already depends on mdlayher's socket/packet libraries.

## 3. Proposed Implementation Design

### 3.1 Package Structure

```
pkg/ra/
├── ra.go           # Manager type, Apply/Withdraw/Clear methods
├── ra_test.go      # Unit tests (mock conn interface for testing without root)
├── sender.go       # Per-interface sender goroutine
└── sender_test.go  # Sender timer/packet tests
```

### 3.2 Core Types

```go
// Manager manages per-interface RA sender goroutines.
type Manager struct {
    mu       sync.Mutex
    senders  map[string]*sender  // keyed by interface name
}

// sender is a per-interface goroutine that sends periodic RAs
// and responds to Router Solicitations.
type sender struct {
    iface   string
    cfg     *config.RAInterfaceConfig
    conn    *ndp.Conn
    srcAddr netip.Addr
    stopCh  chan struct{}
    stopped chan struct{}
}
```

### 3.3 Manager API

```go
func New() *Manager

// Apply starts/updates RA senders for the given interface configs.
// Interfaces not in the list are stopped. Existing senders with
// unchanged config are left running (no RA gap).
func (m *Manager) Apply(configs []*config.RAInterfaceConfig) error

// Withdraw sends a goodbye RA (RouterLifetime=0) on all active
// interfaces, then stops all senders. Returns after the goodbye
// RAs have been transmitted (no sleep needed — direct socket write).
func (m *Manager) Withdraw() error

// Clear stops all senders without sending goodbye RAs.
func (m *Manager) Clear() error
```

The API surface is deliberately identical to the current `radvd.Manager`, making the
daemon integration a drop-in replacement.

### 3.4 Per-Interface Sender Goroutine

Each sender goroutine follows the VRRP instance pattern already established in `pkg/vrrp/instance.go`:

```
sender.run():
    1. Open ndp.Conn on interface (link-local address)
    2. Join ff02::2 (all-routers) for RS reception
    3. Set ICMPv6 filter to accept only RS (type 133)
    4. Start periodic RA timer (random between MinRtrAdvInterval..MaxRtrAdvInterval)
    5. Loop:
       select {
       case <-stopCh:
           return
       case <-advertTimer:
           send RA to ff02::1 (all-nodes multicast)
           reset timer with random jitter
       case rs from conn.ReadFrom():
           if RS from valid source:
               send unicast RA to solicitor (or multicast if MIN_DELAY_BETWEEN_RAS applies)
       }
```

### 3.5 RA Packet Construction

Map `RAInterfaceConfig` fields directly to `ndp.RouterAdvertisement`:

| RAInterfaceConfig field | ndp.RouterAdvertisement field |
|------------------------|-------------------------------|
| `ManagedConfig` | `ManagedConfiguration` |
| `OtherStateful` | `OtherConfiguration` |
| `Preference` | `RouterSelectionPreference` (map "high"→`ndp.High`, "low"→`ndp.Low`, default→`ndp.Medium`) |
| `DefaultLifetime` | `RouterLifetime` (time.Duration) — see the lifetime note below |
| `Prefixes[].Prefix` | Option: `ndp.PrefixInformation{Prefix, PrefixLength}` |
| `Prefixes[].OnLink` | `PrefixInformation.OnLink` |
| `Prefixes[].Autonomous` | `PrefixInformation.AutonomousAddressConfiguration` |
| `Prefixes[].ValidLifetime` | `PrefixInformation.ValidLifetime` |
| `Prefixes[].PreferredLife` | `PrefixInformation.PreferredLifetime` |
| `DNSServers` | Option: `ndp.RecursiveDNSServer{Servers, Lifetime}` |
| `NAT64Prefix` | Option: `ndp.PREF64{Prefix, Lifetime}` |
| `LinkMTU` | Option: `ndp.NewMTU(mtu)` |
| `ReachableTime` | `ReachableTime` (time.Duration, ms; RFC 4861 §4.2 — #4307) |
| `RetransTimer` | `RetransmitTimer` (time.Duration, ms; RFC 4861 §4.2 — #4307) |
| (interface MAC) | Option: `ndp.LinkLayerAddress{Direction: ndp.Source, Addr: mac}` |

Additionally, `CurrentHopLimit` should default to 64 (standard for Linux).

**Router Lifetime and `default-lifetime 0` (#4119).** `RouterLifetime` comes
from `DefaultLifetime`, but only when `DefaultLifetimeSet` is true. RFC 4861
§6.2.1 defines a Router Lifetime of 0 as "this router is NOT a default router":
a host removes it from its default-router list yet may still use the prefixes /
PREF64 it advertises. An operator therefore needs to advertise prefixes / NAT64
while declining default-router duty on a multi-router LAN. To support that:

- The schema floor is 0 (`ValidateInteger(0, 65535)`), so `set protocols
  router-advertisement interface <if> default-lifetime 0` commits.
- The compiler sets `DefaultLifetimeSet=true` for any explicit value; an
  absent leaf leaves it false.
- `buildRA` marshals `RouterLifetime = DefaultLifetime` when the flag is set
  (an explicit 0 stays 0) and defaults to 1800s only when it is unset. The old
  `if lifetime <= 0 { lifetime = 1800 }` coercion conflated an explicit 0 with
  "unset" and could never emit Router Lifetime 0.
- The Prefix Information options carry their own valid / preferred lifetimes
  (30d / 7d), so on-link prefixes and SLAAC keep working with a Router Lifetime
  of 0.
- The RDNSS and PREF64 option lifetimes default to the bounded router lifetime:
  RDNSS is capped at 65535 seconds and PREF64 at 65528 seconds. If the router
  lifetime is an explicit 0, both fall back to 1800s (PREF64 remains capped at
  65528s), so a 0 Router Lifetime withdraws only default-router duty, not the
  DNS server or NAT64 prefix.
- `configEqual` compares `DefaultLifetimeSet` so an unset → `default-lifetime 0`
  edit (both have `DefaultLifetime == 0` but a different wire value) restarts
  the sender.

### 3.6 Goodbye RA (Withdraw)

Sending a goodbye RA is trivially simple with direct socket access:

```go
func (s *sender) sendGoodbyeRA() error {
    ra := s.buildRA()
    ra.RouterLifetime = 0  // Tells hosts: remove me as default router
    return s.conn.WriteTo(ra, nil, netip.MustParseAddr("ff02::1"))
}
```

**Key improvement over current approach**: The goodbye RA is sent synchronously in a single
syscall. No config file rewrite, no process reload, no 500ms sleep. The packet is on the wire
in microseconds.

For extra reliability, send 2-3 goodbye RAs with 50ms gaps (a few lost packets on a busy
network shouldn't leave hosts stranded):

```go
func (m *Manager) Withdraw() error {
    m.mu.Lock()
    defer m.mu.Unlock()
    for _, s := range m.senders {
        for i := 0; i < 3; i++ {
            s.sendGoodbyeRA()
            if i < 2 {
                time.Sleep(50 * time.Millisecond)
            }
        }
        s.stop()
    }
    m.senders = make(map[string]*sender)
    return nil
}
```

Total withdraw latency: ~100ms (vs ~600ms+ with external radvd).

### 3.7 RFC 4861 Timer Requirements

The RFC specifies randomized RA intervals to prevent synchronization:

| Parameter | Default | Valid range (RFC 4861 §6.2.1) | xpf Config |
|-----------|---------|-------------------------------|-------------|
| `MaxRtrAdvInterval` | 600s | 4 .. 1800 s | `RAInterfaceConfig.MaxAdvInterval` |
| `MinRtrAdvInterval` | 0.33 * Max | 3 s .. 0.75 * Max (ceiling 1350 s) | `RAInterfaceConfig.MinAdvInterval` |
| `AdvDefaultLifetime` | 3 * Max (max 9000s) | 0 .. 9000 s | `RAInterfaceConfig.DefaultLifetime` |

Each periodic RA uses a random delay in `[MinRtrAdvInterval, MaxRtrAdvInterval]`.

**Interval validation (#4525).** `max-advertisement-interval` and
`min-advertisement-interval` are range-checked at commit against the
RFC 4861 §6.2.1 bounds above:

- `max-advertisement-interval` — `ValidateInteger(4, 1800)` (was
  `ValidateIntegerMin(1)`, which let `1`/`2` commit).
- `min-advertisement-interval` — `ValidateInteger(3, 1350)` per-leaf, plus a
  cross-field commit check that `min <= 0.75 * max`
  (`crossCheckRAIntervals`, `pkg/configstore/store.go`). Both siblings must
  be present for the ratio check to fire; a lone leaf is completed by the
  sender's own derivation.

These are strict on the operator commit / `commit check` / `xpfd
check-config` path and downgraded to a warning on the tolerant `Store.Load`
/ HA `SyncApply` ingress (the #1960 no-brick doctrine), so a legacy or
peer-synced config that predates the tightened range cannot blackout-boot the
node — the operator's next strict commit rejects it.

**Runtime floor (belt).** `randomAdvInterval` (`pkg/ra/sender.go`) floors the
drawn periodic delay at `minAdvInterval` (1 s). Before #4525, a legacy
`max-advertisement-interval 1` derived `minI = maxI/3 = 0`, so the draw could
be `0`; `advTimer.Reset(0)` fired immediately and spun `sendRA` in a tight
loop (RA/ND flood + CPU spin). The commit-time schema floor is the primary
guard; the runtime floor makes the hot-loop unreachable even for a config
that arrives through the tolerant load / peer-sync path.

For RS-triggered RAs, RFC 4861 §6.2.6 specifies:
- Delay response by random `[0, MAX_RA_DELAY_TIME]` (0.5s)
- Rate limit to no more than one RA per `MIN_DELAY_BETWEEN_RAS` (3s) per interface

Implementation: use a per-interface `lastRASent time.Time` field to enforce rate limiting.

### 3.8 Router Solicitation Handling

When a host boots or connects to the network, it sends an RS to ff02::2 (all-routers).
The RA sender must respond with a unicast RA to the solicitor's link-local address (or
multicast to ff02::1 if multiple RSes arrive within the rate-limit window).

```go
case msg := <-rsCh:
    rs, ok := msg.(*ndp.RouterSolicitation)
    if !ok {
        continue
    }
    // Rate limit: if less than MIN_DELAY_BETWEEN_RAS since last RA,
    // aggregate into next scheduled RA.
    if time.Since(s.lastRASent) < 3*time.Second {
        continue  // next periodic RA will serve as response
    }
    // Random delay [0, 500ms] per RFC 4861 §6.2.6
    time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond)
    s.sendRA(srcAddr)  // unicast to solicitor
```

## 4. Daemon Integration

### 4.1 Drop-in Replacement

The daemon currently holds:
```go
type Daemon struct {
    radvd *radvd.Manager
    // ...
}
```

Change to:
```go
type Daemon struct {
    ra *ra.Manager
    // ...
}
```

All three call sites map directly:

| Current | Replacement |
|---------|-------------|
| `d.radvd.Apply(raConfigs)` | `d.ra.Apply(raConfigs)` |
| `d.radvd.Withdraw()` | `d.ra.Withdraw()` |
| `d.radvd.Clear()` | `d.ra.Clear()` |

### 4.2 Standalone Mode (`applyConfig`)

```go
// daemon.go:1165-1182
if !isCluster {
    if d.ra != nil && len(raConfigs) > 0 {
        if err := d.ra.Apply(raConfigs); err != nil {
            slog.Warn("failed to apply RA config", "err", err)
        }
    } else if d.ra != nil {
        if err := d.ra.Clear(); err != nil {
            slog.Warn("failed to clear RA config", "err", err)
        }
    }
}
```

### 4.3 HA Mode (`watchVRRPEvents`)

```go
// applyRethServices — VRRP MASTER transition
if d.ra != nil {
    raConfigs := d.buildRAConfigs(cfg)
    if len(raConfigs) > 0 {
        if err := d.ra.Apply(raConfigs); err != nil {
            slog.Warn("vrrp: failed to apply RA on MASTER", "err", err)
        }
    }
}

// clearRethServices — VRRP BACKUP transition
if d.ra != nil {
    if err := d.ra.Withdraw(); err != nil {
        slog.Warn("vrrp: failed to withdraw RA on BACKUP", "err", err)
    }
}
```

### 4.4 DHCPv6 Prefix Delegation

The existing `buildRAConfigs()` function in `daemon.go:1297-1356` already merges
PD-derived prefixes into `RAInterfaceConfig` before passing to the RA manager. This
works identically with the embedded implementation — the Manager receives complete
configs and doesn't need to know where prefixes came from.

**Withdrawal is a distinct event from a change (#9239).** `buildRAConfigs()` only
runs on the full-apply path, and in STANDALONE mode that path is the *only* RA
applier — `reconcileClusterRAServices` is explicitly a no-op off-cluster, and the
30-second sender loop retries only DEAD senders, never a live one holding stale
desired state. So RA correctness after a PD change depends entirely on whether the
DHCP lease-change callback classified the event as needing a full apply.

That classifier reads the PD set *after* `commitLease` has already removed a
withdrawn prefix, which makes "the last prefix was just withdrawn" and "this box
never had one" the same empty set. `onDHCPAddressChange` therefore remembers
whether the previous pass saw a PD-for-RA (`Daemon.pdForRAPresent`) and forces the
apply on the falling edge as well as the rising one.

Without it, the sender keeps refreshing a prefix the upstream has withdrawn until
an unrelated apply or a restart, while downstream hosts keep autoconfiguring from
it — and the resulting drops appear off-box, far from the daemon that caused them.
`ra.Manager.Apply` with an empty set is already the graceful path (it removes the
sender and emits a router-lifetime-zero goodbye so the last PIO ages out); the
defect was only ever in reaching it.

### 4.5 RETH Interface Resolution

The `buildRAConfigs()` function already resolves RETH names to Linux interface names
(line 1351-1353). The embedded RA manager receives real Linux interface names, same
as external radvd.

### 4.6 Source Link-Layer Address

The SLLA (Source Link-Layer Address) option is important for RA: it tells hosts the
router's MAC address so they can populate their neighbor cache without an additional
NS/NA exchange. The ndp library's `LinkLayerAddress` option handles this:

```go
ifi, _ := net.InterfaceByName(cfg.Interface)
options = append(options, &ndp.LinkLayerAddress{
    Direction: ndp.Source,
    Addr:      ifi.HardwareAddr,
})
```

This is especially important for RETH interfaces with virtual MACs — the RA carries
the deterministic per-node/per-RETH `02:bf:72:CC:RR:(2*reth-index+node-id)` MAC,
ensuring hosts associate the correct MAC with the router's link-local address.

## 5. XDP Interaction

### 5.1 Will XDP Intercept Our RAs?

**Outbound RAs (TC egress)**: The RA sender uses an ICMPv6 socket in userspace. Packets
originate from the kernel network stack, so they go through the TC egress path. The TC
pipeline's `tc_conntrack` stage recognizes locally-originated packets
(`skb->ingress_ifindex == 0`) and passes them through. No issue.

**Inbound RSes (XDP ingress)**: Router Solicitations arrive from hosts on the LAN. The XDP
pipeline processes them through zone → conntrack → policy. For the RS to reach the
userspace RA sender, the firewall policy must allow ICMPv6 type 133 (RS) inbound on the
interface's zone. This is typically already allowed by the "host-inbound-traffic" system
services config (`protocols router-discovery`).

If XDP drops RSes before they reach userspace, the embedded RA sender won't receive them.
However, this is the same situation as external radvd — the RS must pass the firewall
regardless. Periodic unsolicited RAs still work even without RS reception.

### 5.2 Multicast Group Membership

The kernel automatically handles MLD (Multicast Listener Discovery) reports when the
ndp.Conn joins ff02::2. XDP should pass MLD packets (ICMPv6 type 130-132, 143) — verify
that the BPF policy doesn't drop these.

## 6. Complexity Estimate

### 6.1 Lines of Code

| Component | Estimated LOC |
|-----------|---------------|
| `ra.go` — Manager (Apply/Withdraw/Clear, sender lifecycle) | ~120 |
| `sender.go` — Per-interface goroutine (timers, RS handling, RA building) | ~200 |
| `ra_test.go` — Manager tests | ~100 |
| `sender_test.go` — Packet building + timer tests | ~150 |
| Daemon integration changes (3 call sites) | ~10 |
| Remove `pkg/radvd/` | -260 |
| **Net change** | ~+320 |

### 6.2 Effort

- **Implementation**: 1-2 days for a senior Go developer familiar with the codebase
- **Testing**: Half a day for unit tests + integration testing in the Incus VM
- **HA testing**: Half a day for VRRP failover + goodbye RA verification

### 6.3 Comparison with VRRP Implementation

The native VRRP implementation (`pkg/vrrp/`) is a very close analogue:
- Per-interface goroutine with state machine → per-interface goroutine with timer
- Raw socket for sending → ndp.Conn for sending
- AF_PACKET for receiving → ndp.Conn for receiving (RS)
- VRRPv3 packet building → RA packet building via ndp library
- GARP on state change → goodbye RA on state change

The RA sender is **simpler** than the VRRP implementation because:
- No state machine (just "running" or "stopped")
- No election logic
- ndp library handles packet encoding (VRRP uses hand-rolled codec)
- Simpler multicast (ff02::1 for send, ff02::2 for receive)

## 7. Risks and Mitigation

### 7.1 Risk: ICMPv6 Socket Requires Root/CAP_NET_RAW

**Severity**: Low
**Mitigation**: xpfd already runs as root (required for XDP attachment, netlink operations,
AF_PACKET sockets in VRRP). The ndp library uses `ipv6:ipv6-icmp` which requires `CAP_NET_RAW`,
already available.

### 7.2 Risk: ndp.Conn on Generic XDP Interfaces

**Severity**: Medium
**Mitigation**: The VRRP code already solved this problem. Generic XDP can interfere with
multicast socket delivery. However, RA outbound traffic (locally originated) goes through TC
egress, not XDP. Inbound RSes follow the same path as any other inbound packet. If RS delivery
is unreliable, periodic unsolicited RAs (the primary mechanism) still work. Test thoroughly
with generic XDP interfaces in the Incus VM.

### 7.3 Risk: VLAN Sub-Interface Multicast

**Severity**: Medium
**Mitigation**: The VRRP code discovered that raw IP sockets don't reliably receive multicast
on VLAN sub-interfaces with generic XDP (`d951626`). The ndp library uses an ICMPv6 socket
(not raw IP), which may have the same issue. If so, the same AF_PACKET fallback pattern from
`pkg/vrrp/manager.go` can be applied for RS reception. However, since RS reception is optional
(periodic RAs are the primary mechanism), this is lower risk than for VRRP where packet
reception is critical.

### 7.4 Risk: Regression in RA Behavior

**Severity**: Low
**Mitigation**: The config struct (`RAInterfaceConfig`) is the contract between the config
compiler and the RA manager. All fields map directly to ndp types. Write tests that verify
RA packet contents match expected values for each config field. Test DHCPv6 PD prefix injection
end-to-end.

### 7.5 Risk: Goodbye RA Race on VRRP Transition

**Severity**: Low (improvement over current)
**Mitigation**: With an embedded sender, `Withdraw()` writes directly to the socket — no
config file intermediary. The goodbye RA is on the wire before `Withdraw()` returns. This
is strictly better than the current approach.

### 7.6 Risk: ndp Library Bugs or Breaking Changes

**Severity**: Low
**Mitigation**: The ndp library is mature (used by CoreRAD in production, maintained by
Matt Layher who is active in the Go networking community). Pin the version in go.mod.
The API surface we need (Conn, RouterAdvertisement, options) is stable.

## 8. Migration Plan

### Phase 1: Implement `pkg/ra/`
- New package with Manager, sender, Apply/Withdraw/Clear
- Unit tests with mock ndp.Conn (or interface-based testing)
- Do NOT remove `pkg/radvd/` yet

### Phase 2: Wire into Daemon
- Replace `d.radvd` with `d.ra` in daemon.go
- Update all 3 call sites (applyConfig, applyRethServices, clearRethServices)
- Keep `pkg/radvd/` in the tree but unused (for rollback)

### Phase 3: Integration Testing
- Single-node: verify hosts receive RAs with correct prefixes, RDNSS, PREF64, MTU
- DHCPv6 PD: verify delegated prefixes appear in RAs after DHCP lease
- HA failover: verify goodbye RA on BACKUP, normal RA on MASTER
- Measure failover latency improvement

### Phase 4: Cleanup
- Remove `pkg/radvd/`
- Remove `radvd` from VM package dependencies
- Update CLAUDE.md and documentation

## 9. Summary

| Aspect | External radvd | Embedded RA (ndp) |
|--------|---------------|-------------------|
| Dependencies | radvd binary + systemd unit | `mdlayher/ndp` Go library |
| Goodbye RA latency | ~600ms (write+reload+sleep) | ~100ms (3 direct sends) |
| Error visibility | None (fire-and-forget SIGHUP) | Direct error return from WriteTo |
| Process management | start/stop/reload/pidfile | goroutine lifecycle |
| Config mechanism | Write file → SIGHUP | Direct struct → packet |
| HA race conditions | Config write ↔ reload ↔ kill | Atomic Withdraw() call |
| Code complexity | ~260 LOC (pkg/radvd/) | ~470 LOC (pkg/ra/) |
| Test coverage | Config generation only | Packet building + timer + integration |
| Existing pattern | Unique (external process) | Matches VRRP (per-interface goroutine) |

**Recommendation**: Proceed with implementation using `mdlayher/ndp`. The embedded approach
eliminates an external dependency, reduces HA failover latency, improves error handling, and
follows the established per-interface goroutine pattern from the VRRP implementation. The
implementation effort is modest (~1-2 days) and the risks are well-understood and mitigatable.
