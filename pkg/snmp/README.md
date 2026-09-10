# pkg/snmp

SNMPv1, SNMPv2c, and SNMPv3 agent. Responds to GET / GETNEXT (all three
versions) and GETBULK (v2c/v3 only — GETBULK is not an SNMPv1 PDU) on
ifTable, ifXTable, and a small set of system OIDs. Also sends link-up /
link-down traps. ASN.1 BER encoding is hand-coded, no external library.

## SNMPv1 polling (RFC 1157 / RFC 2089, #5049)

The request dispatch (`handlePacketFrom`) routes the message version field:
0 → `handleV1Packet`, 1 → `handleV2cPacket`, 3 → `handleV3Packet`. Before
#5049 only versions 1 and 3 had a case and version 0 fell through to the
"unsupported version" default — so the agent emitted v1 traps
(`buildLinkTrapV1`, `set snmp trap-group … version v1`) yet silently dropped
every v1 GET/GETNEXT/SET, and a legacy v1-only manager timed out and marked
the device down.

The v1 handlers share the v2c community frame, the `clients` source-IP
allowlist (#4289), the per-PDU interface snapshot (#4013), the bounded MIB
lookup (`getOIDValueSnap` / `findNextOIDSnap`), and the message-size ceiling
(`boundGetResponseVersion` → `tooBig` on overflow). Only the response rules
differ, per the SNMPv1 error model:

- **GET of a missing/unresolvable OID** → the whole PDU fails with
  `noSuchName` (error-status 2) and a **1-based error-index** naming the
  offending varbind; the request varbinds are **echoed unchanged** (NULL
  values). v1 has **no per-varbind exception values** — `noSuchObject`,
  `noSuchInstance`, and `endOfMibView` are v2-only and never appear in a v1
  response.
- **GETNEXT past the end of the MIB view** → `noSuchName` with the offending
  index (there is no `endOfMibView` in v1).
- **Counter64 (RFC 2089)** — Counter64 is not a v1 type. A **direct GET** of a
  Counter64-typed node (ifHCInOctets/…, ifXTable cols 6/7/10/11) returns
  `noSuchName`; a **GETNEXT walk steps OVER** every Counter64 node
  (`findNextV1OIDSnap`) so the walk advances to the next representable object.
  No Counter64 octet ever reaches the wire on a v1 response.

  **That skip is the ONE unbounded loop in the agent, and it is now
  self-bounding (#7433).** `findNextV1OIDSnap` advances by `cur = next` and
  repeats until the successor lookup returns nil, so it terminated only because
  `findNextOIDSnap` returns a successor that STRICTLY ADVANCES past the cursor.
  Nothing asserted that, and the property lives in a DIFFERENT function — so
  anyone optimising the successor lookup could not see what depended on it.

  The failure mode was the bad one: a HANG, not a wrong answer. It was found by
  mutation — changing the successor's search predicate from `> 0` to `>= 0`
  makes an OID its own successor and the walk spins forever. The cell did not
  fail, it hung, which produces no `--- FAIL` line and scores as a void or an
  escape rather than a defect.

  Two callers bounded it incidentally (GETNEXT does one lookup per request OID
  with no loop; GETBULK is bounded by max-repetitions plus the #6551 byte
  budget), so a spin was never wire-reachable. But those are properties of the
  CALLERS. The loop now carries its own bound — the MIB view length, which is
  the most steps a strictly-advancing walk can take — and exceeding it returns
  end-of-view with a warning. Fail-closed: a v1 walk ends early rather than
  spinning a CPU serving no one.

  Three things about the tests are worth knowing before editing them:

  - The load-bearing assertion is the PROPERTY (`TestSuccessorStrictlyAdvances`),
    not the consequence. Asserting "the walk terminates" requires running the
    walk, which is the thing that hangs.
  - Every cell that CALLS the loop goes through `withDeadline7433`. The first
    draft did not, and the matrix caught it: one cell reproduced the hang it was
    written to convert into a red.
  - `findNextV1OIDSnapWith` takes the successor as a parameter **so the bound
    can be exercised**, not for production flexibility — there is one production
    caller. With the real lookup the bound is unreachable (the successor is
    correct), so a mutation deleting it escaped every other cell until a test
    supplied a non-advancing successor. That fixture must return a **Counter64**
    OID: an ordinary value makes the loop return on its first iteration, and the
    non-advancing cursor never matters. The first version of it did exactly
    that and proved nothing.
- **SET** — the agent exposes no writable object, and v1 lacks the `noAccess`
  / `notWritable` statuses the v2c handler returns; per the RFC 2089 §2.1
  SNMPv2→SNMPv1 error mapping BOTH map to `noSuchName`. So a v1 SET (whether
  the community is read-only or read-write) returns `noSuchName` with
  error-index 1 and the request varbinds echoed.

`buildResponseVersion` (shared by v1 and v2c via `buildResponse`) writes the
message version field explicitly; the GetResponse PDU shape is otherwise
identical across the two versions. Coverage:
`agent_v1_polling_5049_test.go` (RED-on-revert: stashing the dispatch case +
handlers makes every "expect a response" assertion get nil).

## Community authorization (SET access control)

A v2c community carries an `authorization` level (`read-only` /
`read-write`, default `read-only`). `getCommunity` resolves the community
struct; SET requests (`pduSetRequest`, 0xa3) are gated on it:

- A community without `read-write` authorization is denied with `noAccess`
  (RFC 3416 error-status 6) before any write is attempted — this is the
  security boundary set by `set snmp community <name> authorization
  read-write`.
- A `read-write` community passes the gate, but the agent exposes only
  read-only MIB objects, so the write is refused per-varbind with
  `notWritable` (17). No served object is mutable, so a SET never succeeds;
  the read-only vs read-write distinction is enforced and observable in the
  response error-status.

SNMPv3 SET requests are uniformly refused with `notWritable` (the USM users
in this config carry no read-write authorization).

## SNMPv3 contexts (RFC 3412 §4.1, RFC 3413 §3)

The agent serves a single MIB view in the **default context** (empty
`contextName`). It does NOT model per-VRF / per-routing-instance context
views. The scopedPDU `contextEngineID` and `contextName` are decoded and the
`contextName` is honored when dispatching the request:

- **Default context** (empty `contextName`): served exactly as before —
  Get / GetNext / GetBulk return the real MIB objects. No behavior change.
- **Non-default context** (any non-empty `contextName`): there is no MIB view
  for that context, so per RFC 3413 the request yields no matching objects.
  Rather than leaking default-context data (an information-exposure /
  operator-confusion bug, #2611), the agent returns the **empty-view**
  exceptions: `noSuchInstance` for every Get varbind and `endOfMibView` for
  every GetNext / GetBulk varbind. SET is refused with `notWritable` as in any
  context. This is fail-closed: a manager addressing an unknown context never
  receives default-context values.
- The response **echoes the requested `contextName`** back in the scopedPDU
  (empty for the default context), so the manager sees the response is bound to
  the context it addressed. `contextEngineID` in the response is our own engine
  ID (we are the authoritative engine).

This is the empty-view route (RFC 3413), chosen over an `authorizationError` /
`snmpUnknownContexts` report because it is the standard, simplest result for a
single-context agent and needs no new error-counter MIB objects.

## SNMPv3 security levels (RFC 3414 §5)

RFC 3414 defines exactly three USM security levels, encoded in the two
low `msgFlags` bits:

- **noAuthNoPriv** — both flags clear (`0x00`): no HMAC, no encryption.
- **authNoPriv** — auth flag set (`0x01`): HMAC-verified, plaintext PDU.
- **authPriv** — both flags set (`0x03`): HMAC-verified and encrypted.

The fourth bit combination — privacy set, authentication clear
(`msgFlags = 0x02`, "noAuthPriv") — is **not a valid level**: an
encrypted message must be authenticated. `handleV3Packet` rejects it
**before** any authentication, decryption, or PDU execution. The agent
**drops** the message (returns nothing) rather than emitting a report,
because with no authentication it cannot produce an authenticated reply
at the requested security level and an unauthenticated report would
itself be unverifiable (#2681). Accepting noAuthPriv would let a sender
who can supply a decryptable PDU bypass HMAC and timeliness verification
entirely — its scopedPDU would be decrypted and executed with no auth.
The three valid levels are unaffected.

### Per-user minimum security level floor (RFC 3414 §3.1)

The `msgFlags` a request carries are the *sender's chosen* level, not a
policy the sender is free to lower. Each configured user has an implied
minimum level: a user with an auth key **must** authenticate, and a user
with a privacy key **must** use authPriv. After the user lookup,
`handleV3Packet` enforces this floor **before** decoding the scoped PDU:
a request that clears `msgFlagAuth` against a key-bearing user, or clears
`msgFlagPriv` against a privacy-configured user, is **dropped** (returns
nothing). Without this floor a request could set `msgFlags = 0`
(noAuthNoPriv) while naming an authPriv user; both gates below — HMAC
verification (gated on `msgFlagAuth`) and decryption (gated on
`msgFlagPriv`) — would be skipped and the scopedPDU answered in plaintext
without the configured password, an authentication + confidentiality
bypass (#4897). Usernames are not secret, so knowing the name would
otherwise suffice to read device identity and interface inventory and to
re-open the unauthenticated GETBULK CPU path. Requests **at or above**
the configured level are served exactly as before.

## SNMPv3 USM timeliness and replay protection (RFC 3414 §3.2)

Authenticating a request proves the sender holds the user's key; it does
**not** prove the message is fresh. Without a timeliness check an on-path
attacker can replay a captured authenticated PDU verbatim. The agent enforces
the RFC 3414 §3.2 timeliness window as the authoritative engine:

- After `verifyAuth` succeeds, `checkTimeliness(reqBoots, reqTime)` compares the
  request's `msgAuthoritativeEngineBoots`/`msgAuthoritativeEngineTime` against
  the agent's own `engineBoots`/`engineTime()`. A request is in the window only
  when our boots counter is below the RFC ceiling (`2147483647`), the request's
  boots equals ours, and the request's time is within ±150 seconds of ours.
- A request outside the window gets an **authenticated** Report PDU carrying
  `usmStatsNotInTimeWindows` (`1.3.6.1.6.3.15.1.1.2.0`) plus the agent's current
  boots/time, never a data response. A manager whose cached boots/time drifted
  (the legitimate case, e.g. after our restart bumped boots) reads the report
  and resynchronizes; a replay simply gets nothing useful.
- The engineID discovery handshake (empty `userName` →
  `usmStatsUnknownEngineIDs`, `1.3.6.1.6.3.15.1.1.4.0`) is unaffected: a manager
  still learns our engineID and current boots/time before its first
  authenticated request, so a freshly-discovered, timely request is accepted.

### Privacy (encryption) IV: RFC 3826 §3.1.2.1

For an `authPriv` request the scopedPDU is encrypted; the agent must rebuild the
exact IV the manager used. Per RFC 3826 §3.1.2.1 the AES-128-CFB IV is
`authoritativeEngineBoots(4) || authoritativeEngineTime(4) || privParams(8)`,
where boots/time are the values **carried in the message** — the boots/time the
sender learned about us via discovery, not our local clock at receive time.

- **Request decrypt** uses the RECEIVED `reqBoots`/`reqTime`
  (`msgAuthoritativeEngineBoots`/`...Time` from the request USM parameters),
  threaded `handleV3Packet → decryptPDU → decryptAES128`. `checkTimeliness`
  runs first and (for an authenticated request) bounds `reqBoots == engineBoots`
  and `reqTime` within ±150 s, but `reqTime` can still differ from the agent's
  *current* `engineTime()` by up to the window. Building the IV from the local
  clock instead (the #2640 bug) corrupted the CFB keystream and silently dropped
  every encrypted query made while the manager's cached time drifted from ours —
  the normal steady state under clock advance.
- **Response encrypt** uses the agent's *current* `engineBoots`/`engineTime()`
  (`encryptPDU → encryptAES128`), and the same values are written into the
  response's `msgAuthoritativeEngineBoots`/`...Time`. We are the authoritative
  engine for our own reply, so the IV and the header boots/time agree by
  construction and a manager decrypts the response using the boots/time it reads
  from our header. This path is unchanged by the #2640 fix.
- DES (`decryptDES`/`encryptDES`, RFC 3414 §8) derives its IV from `privParams`
  XOR the pre-IV salt alone, so boots/time do not enter the DES IV.

**Privacy salt is a monotonic counter, unique per engine boot (RFC 3826 §3.3,
RFC 3414 §8.1.1.1, #5032).** The privacy salt (`msgPrivacyParameters`) MUST be
UNIQUE per `(engineBoots, privKey)` so the derived cipher IV never repeats within
an engine boot — an AES-128-CFB IV repeat leaks the XOR of two plaintexts, and a
DES-CBC IV repeat (IV = key-derived pre-IV XOR salt) repeats first-block
structure. Drawing an *independent* random salt per message (the pre-#5032
behavior) gives only birthday-bound uniqueness. Instead `Agent.nextPrivSalt`
allocates the salt from a **monotonic 64-bit counter**: seeded ONCE from
`crypto/rand` (via the injectable `randRead` seam) at first use — an arbitrary
boot-time start per RFC 3826 §3.3 — and incremented atomically for each
encryption. `encryptPDU` calls `nextPrivSalt`, threads the returned salt into
`encryptDES`/`encryptAES128` as the IV/pre-IV input, and echoes it back as the
on-the-wire `privParams`. `engineBoots` (immutable per boot, monotonic across
restarts) scopes the counter to the boot: a restart re-randomizes the start and
advances the AES IV's boots field, so IVs stay unique across reboots too. The
counter increment is an atomic operation, so concurrent response and trap
encryption never draw the same salt.

**Fails closed on RNG error at seed time (RFC 3414 §8.2.1, #5453).** The counter
seed MUST come from good entropy so the starting point is unpredictable. If the
one-time seed draw fails (getrandom `EAGAIN` at early boot, a FIPS module error),
`nextPrivSalt` returns an error, `encryptPDU` propagates it, and
`buildV3Response` **fails closed** — it drops the response (returns `nil`, so no
datagram is written) rather than emit a PDU built from a zero/predictable salt.
An RNG failure therefore yields *no reply* to an `authPriv` request, never an
insecurely encrypted one. Because RFC 3826 consults the RNG only for the seed
(not per message), a later RNG outage does not block encryption once the counter
is seeded — fresh entropy per message is neither required nor drawn.

### engineBoots persistence

`engineBoots` is loaded, incremented, and persisted once at agent construction
so `(engineBoots, engineTime)` is monotonic across daemon restarts, as RFC 3414
requires of an authoritative engine:

- State file: `/var/lib/xpf/snmp-engineboots` (a single decimal integer). The
  path is injectable via `NewAgentWithBootsPath` — the test seam used to assert
  the load/increment/persist cycle without touching real state.
- First boot (file missing): `engineBoots` starts at `1` and the file is
  created. Each subsequent start reads the prior value, increments it, and
  persists the new value (1 → 2 → 3 …). `engineTime()` then counts from *this*
  boot (`startTime`), so the pair advances monotonically.
- A corrupt/unreadable counter, a value already at the RFC ceiling, an
  increment that would reach the ceiling, or a failed durable write all **fail
  closed** by pinning `engineBoots` to the ceiling (`engineBootsMax`) rather
  than restarting at `1` (#2649). RFC 3414 §2.2 requires `engineBoots` to be
  monotonic for the authoritative engine; resetting to a low value while the
  deterministic engineID is unchanged re-opens the replay window — a captured
  authenticated request from a prior low-boots epoch could become timely again.
  At the ceiling `checkTimeliness` rejects every authenticated request (§3.2
  step 7), so managers must re-discover and the engineID must be reconfigured
  to recover. The agent still starts and answers discovery/report (no SNMP
  DoS), but no replayed low-boots packet is serveable while the counter is
  corrupt, maxed, or unpersistable. First boot (missing file) still legitimately
  starts at `1` — that is a genuinely new epoch, not a reuse of a low value.
- The persist uses `fsatomic.WriteFileDurable` (fsync-on-write); the directory
  is created with `fsatomic.MkdirAllDurable`. This is slow-path (once per start),
  so per-write durability is affordable.

### Authoritative EngineID derivation (RFC 3411 §5)

`initEngine` derives the authoritative SNMPv3 `snmpEngineID` from the OS hostname
**and a per-device unique component** via `buildEngineID`. RFC 3411 constrains
`SnmpEngineID` to **5..32 octets** AND requires it to be **unique** per
authoritative engine (unique, not secret). Both properties matter:

- **Length (5..32 octets)** — an EngineID outside the range is rejected by
  compliant managers, breaking every v3 discovery, USM key localization, auth
  check, and response encoding that keys off the agent's identity (v2c is
  unaffected). This is the #4917/#5264 cap.
- **Uniqueness (per-device)** — USM localizes each user's auth/priv keys against
  the EngineID, so two engines with the **same** EngineID derive **byte-identical
  localized keys**. An authenticated SNMPv3 request captured from firewall A is
  then accepted by firewall B (same username/password): cross-device telemetry
  disclosure / auth bypass (**#5283**).

The historical construction derived the entire EngineID from a fixed prefix +
`os.Hostname()` only. It had no per-device component, so two same-hostname
**clones** (HA pair, factory default, lab image, config restore) derived
identical EngineIDs and identical USM keys — #4917/#5264 only capped the length,
they did not add uniqueness.

**Construction (always 32 octets):**

```
prefix(5) || 0x05 || sha256(deviceID || 0x00 || hostname)[:26]
```

- `prefix` is the 5-octet enterprise header (`0x80 0x00 0x01 0x86 0xa3`).
- `0x05` ("administratively assigned octets") honestly labels the binary SHA-256
  payload.
- The result is **exactly 32 octets for every input** (empty or multi-kilobyte
  hostname alike), so the #4917/#5264 length cap always holds.
- A `0x00` separator between `deviceID` and `hostname` prevents boundary-shift
  aliasing.

**Per-device component (`deviceComponent`)** combines two independent per-device
sources so a clone must defeat BOTH to collide:

1. **Persisted crypto/rand** — a 16-byte value generated ONCE and persisted at
   `/var/lib/xpf/snmp-engine-id` (hex text, `0600`), reused on every subsequent
   boot. This is the primary source: stable across reboots of the same device,
   unique per appliance. On read-corruption / RNG / persist failure it is
   regenerated or skipped (never an un-persisted value served as if stable).
2. **`/etc/machine-id`** — folded in as defense in depth. `virt-sysprep` resets
   machine-id per-appliance at image bake, so even a mistakenly-cloned
   persisted file still yields a distinct component (different machine-id →
   different EngineID).

If **every** source fails (no persistable random AND no machine-id — the
catastrophic path), the EngineID degrades to the pre-#5283 hostname-only
identity and `initEngine` logs a `slog.Warn` that it is not clone-unique.

**Clone/bake requirement:** the persisted `/var/lib/xpf/snmp-engine-id` file
MUST NOT be copied identically into cloned appliances or a golden image — that
would re-establish the collision. It is treated exactly like `/etc/machine-id`:
`scripts/image/bake.py` removes it (and `snmp-engineboots`) during
`virt-sysprep` so each appliance regenerates a fresh one on first boot. The
machine-id fold-in is the backstop if that removal is ever missed.

**Transition:** on an existing appliance upgrading, the EngineID changes ONCE
(hostname-derived → device-unique). Existing SNMPv3 managers re-discover the
EngineID on their next poll (a one-time, standard USM discovery — acceptable for
a security fix). `(engineBoots, engineTime)` monotonicity is unaffected: the
boots counter is keyed by its own persisted file, not by the EngineID bytes.

**Follow-up (out of scope here):** binding the USM replay window to the
destination IP is additional defense-in-depth; the unique EngineID alone closes
the cross-clone bypass because A's localized keys no longer equal B's.

RED-on-revert and length-cap coverage lives in `engineid_4917_test.go`; the
per-device uniqueness / reboot-stability / USM-key-divergence coverage lives in
`engineid_5283_test.go`.

## Live reconfigure (commit-time reconcile)

The full SNMP subsystem is reconciled on **every** commit, not just at boot
(#3967). The daemon's `reconcileSNMP` (`pkg/daemon/daemon_snmp_reconcile.go`),
called from `applyConfigLocked`, matches the running agent + link-state trap
monitor to the committed config:

- **disabled → enabled** — a commit that enables SNMP (an `snmp` stanza with a
  community or v3 user, `snmpd` not `disable`d) creates and starts the agent
  listener via `startSNMPLocked`, and the link-state trap monitor if trap
  groups are configured. No restart needed.
- **enabled → disabled** — a commit that removes SNMP (or `set system processes
  snmpd disable`) stops the listener and the monitor (`teardownSNMPLocked`
  cancels the lifetime context, joins the goroutines, and closes UDP/161).
- **enabled → enabled (changed)** — `UpdateConfig(cfg *config.SNMPConfig)` swaps
  the live authorization/identity config and rederives the USM v3 user table
  **in place**, so a commit that changes community authorization (`read-write`
  -> `read-only`, or a deleted community), the v3 user set, or a trap-group
  target reaches the running agent without dropping the UDP listener or
  interrupting in-flight polls. Trap targets are read live from `snapshotCfg`,
  so an added/changed target takes effect immediately; a newly-added trap group
  also starts the link-state monitor if it was not already running.
- **enabled → enabled (unchanged)** — a no-op, gated on an FNV fingerprint of
  the SNMP stanza (`snmpConfigHash`): an unchanged stanza never bounces the
  listener.

`snmpEnabled` is the single predicate both the boot start (`daemon_run.go`) and
`reconcileSNMP` use, so boot and day-2 can never disagree on what "SNMP is on"
means. The boot block performs the FIRST start (it runs even in config-only /
bootstrap mode, unlike the boot `applyConfig`) and sets `snmpBootReady`, which
hands day-2 lifecycle changes to `reconcileSNMP`; the `snmpBootReady` gate keeps
the boot apply and the boot block from double-starting the agent. The agent +
monitor goroutines bind to a lifetime context derived from `d.daemonCtx` and are
torn down explicitly at shutdown (`teardownSNMP`).

`Agent.Stop()` is self-contained and idempotent (#4916): the daemon-wide
context stays live across a day-2 SNMP disable, so Stop cannot rely on it. Stop
cancels a per-agent lifecycle context (unblocking the `<-ctx.Done()` watcher
goroutine `Start` spawns), signals the async trap worker to ABANDON its queued
backlog (so no trap is delivered to a removed/rotated receiver after the
authorizing config was revoked), closes the UDP socket, and waits for the
worker to exit. After Stop, `enqueueTrap` drops rather than starting a new
worker. Without this, each disable/re-enable cycle leaked a goroutine pair and
the trap worker could keep sending a stale backlog with the old community to
the old target.

The abandoned backlog is ACCOUNTED for, not silently discarded (C180-026): on
stop the worker (the sole queue reader) counts every dequeued-but-unsent job
plus every job still buffered in the queue into `trapsDropped` exactly once via
`countAbandonedTraps`, so the drop total covers shutdown-abandoned link-state
traps — not just queue-full and post-Stop-enqueue drops. Before this,
`trapsDropped` reported zero for a shutdown that discarded a queued backlog.
Fail-on-revert guard: `TestStop_CountsAbandonedTrapBacklog`.

This accounting is **exact** — `accepted == delivered + trapsDropped` with no
residual — because `enqueueTrap` publishes to the queue under the same `a.mu`
that `Stop` takes to set `stopped` / close `trapStop`. Enqueue and Stop are
therefore strictly serialized: a job admitted to the queue is buffered before
`close(trapStop)` is observable (so the shutdown drain counts it), and a job
that loses the race sees `stopped` and drops+counts. The send is non-blocking
(buffered channel + `default`) and the worker never takes `a.mu`, so publishing
under the lock cannot deadlock. Before the send was moved under the lock, an
enqueue that passed the stopped check could buffer into an orphaned queue after
the worker had already drained and exited — a job neither delivered nor
counted, breaking the invariant. Concurrent-accounting guard:
`TestStop_AccountingExactUnderConcurrentEnqueue`.

The reconcile runs **early** in `applyConfigLocked` — before the dataplane
apply, which can abort the reconcile pipeline early (it returns on
`ErrPolicySchedulerProtocolIncompatible`). `Store.Commit()` has already
promoted and persisted the compiled config by the time `applyConfigLocked`
runs, so the committed authorization is live regardless of whether the later
dataplane apply succeeds. Reconciling only at the tail would let an
early-aborting apply leave a committed-downgraded community still serving the
old (read-write) SET gate. The daemon-package test
`TestApplyConfigLockedReconcilesSNMPBeforeDataplaneAbort` pins this ordering
(it drives `applyConfigLocked` with a dataplane that returns the aborting
sentinel and asserts the live gate still reflects the downgrade).

Concurrency: `cfg` and the derived `v3Users` are guarded by `cfgMu`
(`sync.RWMutex`). The request-serving goroutine reads them through
`snapshotCfg` / `snapshotV3User` / `hasV3Users` under `RLock`; `UpdateConfig`
swaps both under `Lock`, so a request never observes a half-applied config
(new community map with stale v3 users, or vice versa). `engineID` /
`engineBoots` / `startTime` are the agent's stable identity and are never
swapped. A `nil` cfg (the whole `snmp` stanza removed) disables the agent's
authorization surface: every request is dropped because no community matches.

## Successor lookup: binary search over a per-PDU ordered MIB view (#6597)

`findNextOIDSnap` resolves each GETNEXT/GETBULK successor by **binary-searching**
`ifSnapshot.mibOIDs()` — the whole MIB view for that PDU (staticOIDs, then every
ifTable cell, then every ifXTable cell) built once on first use.

It used to LINEAR-SCAN that view for every varbind — `O(static + interfaces x
columns)` per lookup, multiplied by every varbind an operation emits. The agent
runs on a **single serial goroutine**, so that per-lookup cost is the floor on
requests/second for every operation at once, and it grows with interface count.
A max-size plain GETNEXT of 239 deep `ifXTable` OIDs measured **~33 ms** (~30
req/s for that shape) while fixing #6551.

Measured per-lookup cost, worst-case probe (`-benchtime=2000x`):

| interfaces | linear (before) | binary (after) |
|---|---|---|
| 1 | 2,010 ns | 77 ns |
| 8 | 12,897 ns | 148 ns |
| 64 | 103,060 ns | 201 ns |
| 256 | 677,284 ns | 158 ns |

The shape is the point, not the ratio: the old cost grows **linearly** with
interface count while the new cost stays flat. `BenchmarkFindNextOIDByInterfaceCount`
pins it so a regression to linear is visible.

**The equivalence obligation is bound by a differential test, not spot checks.**
`TestFindNextOIDMatchesLinearReference` keeps the pre-fix algorithm as a
reference oracle and asserts identical successors across an exhaustive probe set
(every MIB OID, each ±1 in its last sub-identifier, every bare column prefix,
and the boundaries above/below each table — 2,175 probes across five interface
counts). `TestFullWalkMatchesLinearReference` additionally walks the entire MIB
with both and asserts the emitted sequences are byte-identical.

**A correctness bug fell out of this, and it is more serious than the
performance one.** The linear scan's lexicographic correctness silently depended
on `ifDataFn` returning IfIndex-ascending data, and nothing enforces that — the
production provider (`buildSNMPIfData`, `pkg/daemon/daemon_snmp_reconcile.go`)
appends in netlink `LinkList` order with no sort. Given an out-of-order provider
the old scan still emitted **ascending** OIDs, because it returned the first
candidate sorting after the cursor — but it **skipped** every interface whose
index sorted below one already emitted in that column. Measured on a
4-interface out-of-order fixture: **40 of 87 MIB rows never appear in the walk**,
so a manager silently never sees those interfaces.

An ascending-only assertion passes on that broken behaviour; **completeness is
what discriminates**, which is why `TestUnsortedProviderWalksEveryRowInOrder`
asserts the full expected row set. `mibOIDs` sorts by IfIndex, so the walk is
now correct regardless of provider order.

`TestMIBOIDViewIsSorted` pins the precondition the binary search requires —
`sort.Search` on an unsorted slice returns silently wrong answers, so that guard
is load-bearing rather than stylistic.

## Configuration accepted but not implemented (#9414)

These commit clean and raise a commit-time advisory (`snmpInertKnobWarnings`,
`pkg/config`) because the agent does not implement them. They are listed here so
this module states the divergence, not only the compiler.

| statement | what the agent does instead |
|---|---|
| `v3 vacm` | applies no per-user or per-group MIB view |
| `v3 notify`, `notify-filter`, `target-address`, `target-parameters` | sends nothing from them; traps go only to `trap-group` targets (`traps.go`) |
| `v3 usm remote-engine` | creates no users for a remote engine; only `usm local-engine user` accounts exist |
| `engine-id` | ignores it; the engine ID is derived (see "Authoritative EngineID derivation") |
| `name` | ignores it; sysName is `os.Hostname()` |
| `arp`, `filter-duplicates`, `nonvolatile`, `proxy` | does not implement them |
| `view`, community `view`, `interface` / `filter-interfaces`, `routing-instance-access`, `health-monitor`, `rmon`, `trap-options source-address` | does not enforce them (#4306, #9416) |

## Entry points

- `Agent` — `agent.go`.
- `IfData` — `agent.go`. Per-interface metrics (name, MTU, speed,
  admin/oper status, octets, errors, drops).
- `V3UserDisplay` — `v3.go`.
- `NewAgent(cfg *config.SNMPConfig) *Agent` — `agent.go`.
- `Start(ctx context.Context) error` — `agent.go`. Blocks until ctx cancelled.
- `Stop()` — `agent.go`.
- `SetIfDataFn(fn)` — `agent.go`. Caller-supplied accessor for live
  interface data. The daemon wires `buildSNMPIfData`, which does a full
  netlink `LinkList` (RTM_GETLINK dump) per call — so the request path must
  invoke it at most once per PDU (see the per-PDU snapshot gotcha below).
  The callback contract is `func() []IfData` (no error channel), so
  `buildSNMPIfData` returns an empty slice when the netlink dump fails — but it
  LOGS the failure (`slog.Warn`, #5523 C179-123) so an empty ifTable caused by a
  transient netlink error is diagnosable and not mistaken for a genuine
  no-interface box; the next poll re-reads netlink and self-heals. The warning
  is rate-limited to at most once per minute (`warnThrottle`, #6396): the
  callback runs once per SNMP poll and a manager may poll several times a
  second, so a PERSISTENT failure would otherwise write one line per poll and
  drown the journal — the first failure logs immediately, subsequent ones in the
  window are counted and reported with the next emitted line, and a successful
  read logs a one-time recovery.

### IF-MIB class-counter semantics (#5050)

`ifInUcastPkts` / `ifHCInUcastPkts` and `ifOutUcastPkts` /
`ifHCOutUcastPkts` count only packets NOT addressed to a multicast or
broadcast address (RFC 2863); the unicast / multicast / broadcast columns
must not overlap. Linux `rtnl_link_stats` (netlink) reports total
`RxPackets` / `TxPackets` plus a single RX `Multicast` sub-count — no RX
broadcast count and no TX multicast/broadcast breakdown. The daemon's
`deriveIfCounters` (`pkg/daemon/daemon_snmp_reconcile.go`) therefore maps:

- `ifHCInUcastPkts = RxPackets - Multicast` (clamped at 0), so IN unicast +
  `ifInMulticastPkts` reconstructs `RxPackets` with no double-count.
- `ifHCOutUcastPkts = TxPackets` — an **upper-bound approximation**: the
  kernel exposes no TX class breakdown to subtract, and the TX non-unicast
  residual (negligible on a routed firewall) is not separable.
- `ifInMulticastPkts = Multicast`. The broadcast columns and the TX class
  columns stay 0 — the kernel does not expose them, and an honest zero beats
  folding those packets into the unicast counter.

Before #5050 the unicast counters were `RxPackets` / `TxPackets` verbatim,
which folded multicast/broadcast into unicast and made a manager
double-count when summing the class columns.
- `NotifyLinkUp` / `NotifyLinkDown` — `traps.go`.

## Callers

`pkg/daemon`, `pkg/cli`, `pkg/grpcapi`.

## Dependencies

`pkg/config`.

## ASN.1 specifics

The BER wire codec — every `berEncode*` / `berDecode*` helper, the OID
comparison helpers (`oidHasPrefix`, `oidEqual`, `oidCompare`), and
`decodePDUFields` — lives in `agent_ber.go` (#5661 code-motion split of
the over-threshold `agent.go`). They are pure, `Agent`-independent
package-level functions; `agent.go` retains the agent state machine,
packet handlers, and MIB view that call into them.

- Tag constants used: Counter32 (0x41), Gauge32 (0x42), TimeTicks (0x43),
  Counter64 (0x46).
- **Unsigned application integers prepend a leading `0x00` when the top content
  octet has its high bit set.** Counter32/Gauge32/Counter64 **and TimeTicks**
  are unsigned, but BER integer content is two's-complement; without the leading
  zero a value `>= 0x80…` decodes as negative. `berEncodeCounter32`,
  `berEncodeGauge32`, `berEncodeCounter64`, and `berEncodeTimeTicks` all strip
  leading zeros then prepend one `0x00` if `buf[0]&0x80 != 0`. TimeTicks lacked
  this (#4924): `sysUpTime` and v1/v2 link-trap timestamps at `>= 0x80000000`
  hundredths (~248.5 days uptime) encoded as non-canonical/negative BER.
- **OID sub-identifiers are bounded to RFC 2578 §7.1.3's `0..4294967295` at the
  DECODER (#9133).** They used to be modelled as a platform-width SIGNED `int`
  with no bound, and three symptoms followed from that one modelling choice: a
  crafted GET with a long continuation run made `berDecodeOID` return a NEGATIVE
  component with no error; `berEncodeSubID`'s `val < 0x80` fast path is true for
  every negative value, so re-encoding emitted a lone continuation octet — and
  since `echoVarbinds` puts the REQUEST OIDs into the response, the agent
  answered with BER its own decoder rejects; and `oidCompare`'s signed `<` sorted
  a huge sub-id BEFORE 1, so a GETNEXT from one restarted at the top of the
  subtree. `berDecodeOID` is the only entry point from the wire, so bounding it
  (a `uint64` accumulator checked BEFORE each shift) fixes all three, and
  `berEncodeSubID`'s parameter is now `uint32` so the bad case is
  unrepresentable rather than checked. `oidCompare` is deliberately unchanged —
  with the decoder bounded it only ever sees `0..4294967295`. Components are
  carried as `[]int`, so a compile-time constant guards that `int` is wider than
  32 bits; a 32-bit target fails to build rather than wrapping large sub-ids
  negative. The FOLDED first two arcs are deliberately NOT bounded: X.690
  §8.19.4 packs them into one octet and `berDecodeOID` reconstructs them as
  `data[0]/40` / `data[0]%40`, so a first octet above `0x77` yields a first arc
  above 2 — invalid ASN.1 that nonetheless round-trips byte for byte, and
  rejecting it would replace a faithful echo of the client's own OID with an
  empty one.
- **A varbind that cannot be decoded DISCARDS THE WHOLE PDU (#9333).** It used
  to be SKIPPED: `decodePDUFields` `continue`d past five malformed shapes and
  `break`ed out of a sixth, so the handler received a shorter OID list than the
  client sent and answered `noError` with it. Measured: a two-varbind v1 GET
  with one undecodable OID returned a response carrying ONE varbind,
  indistinguishable from a request that only ever asked for one. That violates
  RFC 1157 §4.1.2 — the GetResponse's variable-bindings must name the same
  variables the request did — and a manager pairing values to requests BY
  POSITION, which is the normal implementation, then reads the wrong value for
  every varbind after the dropped one. The `break` arm was the worst of the six:
  it dropped that varbind AND every one after it.

  Discarding is what RFC 1157 §4.1 and RFC 3416 §4.1 both prescribe for a
  message that cannot be parsed, and what this function ALREADY did for a
  malformed request-id, error-status, error-index or varbind-list header — the
  six varbind arms were the only inconsistent ones. Every caller turns an error
  from `decodePDUFields` into a dropped datagram.

  **A varbind carrying NO value TLV is NOT affected and is still accepted**
  (`SEQUENCE { OID }`, 5 bytes). It is well-formed, it reaches none of the six
  arms, and #6551's densest-packing bound depends on it —
  `TestWireVarbindByteFloors_6551` and the reference arm in
  `TestEveryMalformedVarbindShapeIsAnError9333` both pin it, because a gate that
  rejected it would be levelling down rather than fixing anything.
- Exception values: `noSuchObject` (0x80), `noSuchInstance` (0x81),
  `endOfMibView` (0x82) — emitted for missing OIDs in walks.
- GETNEXT walking order is driven by a static OID list; it must stay in
  ascending order.

## Gotchas

- Maximum response packet size is 4096 bytes. GETBULK may legitimately
  require multiple responses.
- **GETBULK response size is bounded (RFC 3416 §4.2.3).** The agent caps
  `maxRepetitions` at 100 (defense in depth) *and* bounds the fully-encoded
  response to an effective maximum size. For v3 that effective size is
  `min(request msgMaxSize, 4096)` with `msgMaxSize` clamped up to the RFC
  484-byte floor (a bogus/tiny advertised value cannot starve the response);
  v2c carries no per-request `msgMaxSize` on the wire, so the effective size is
  the local 4096-byte maximum. The response is trimmed to the largest leading
  prefix of varbinds whose encoded message (including the v3 USM/scopedPDU and
  any auth/priv overhead) fits. `trimToFit` finds that prefix by **binary
  search** — the encoded length is monotonic in the number of leading varbinds —
  so it costs O(log n) rebuilds, not the O(n) decrement-and-rebuild it replaced
  (#4918, which for v3 re-ran USM framing/HMAC/encryption on every dropped
  varbind). Trimming — not `tooBig` — is the normal outcome; the manager
  continues the walk with a follow-up GETBULK from the last returned OID.
  `tooBig` (with an empty varbind list) is returned only in the pathological
  case where not even a single varbind fits. See `effectiveMaxSize` /
  `trimToFit` in `agent.go`.
- **The GETBULK grid stops expanding AT the ceiling, it is not expanded and
  then trimmed (#6551).** `buildBulkVarbinds` takes the same `maxBytes` the
  caller will trim to and accumulates the exact encoded size of every varbind it
  emits (`bulkBudget` / `varbindEncodedLen`), stopping the moment the varbinds
  built already exceed it. Without that stop the whole
  `repeaters x max-repetitions` grid was materialized first, and
  `repeaterCount = len(oids) - nonRepeaters` is capped only by how many varbinds
  a manager can pack into one request datagram — nothing on the decode path
  bounds it. Every grid cell costs a `findNextOIDSnap` MIB walk plus a
  `getOIDValueSnap`. Measured with 50 interfaces: a 4094-byte v2c GETBULK with
  580 minimal repeater OIDs and `max-repetitions >= 100` built **58,000**
  varbinds to return **116**, ~0.67 s on the single serial SNMP goroutine
  against a ~2.5 us single-varbind poll — roughly 1.5 requests per second
  saturate SNMP permanently (a community-gated management-plane availability
  defect: a community with no `clients` list is allow-all, #4289). With the stop
  the same request builds 118 varbinds in ~48 us and answers in ~1.0 ms with a
  byte-identical response. The stop is output-neutral because the accumulated
  varbind bytes are a strict lower bound on the size of any message carrying
  them, so every dropped cell is one `trimToFit` would have discarded anyway;
  RFC 3416 §4.2.3 removes surplus bindings from the END of the ordered set
  ("Note that the number of variable bindings removed has no relationship to the
  values of N, M, or R"), which is exactly the prefix this preserves — the
  repetition-major order and per-column `endOfMibView` placement below are
  untouched. `varbindEncodedLen` MUST stay in step with the per-varbind encoding
  in `buildResponseVersion`: an overestimate would stop the grid short of
  varbinds that would have fit and silently shrink large responses.
  Fail-on-revert guards, one cost guard per CALL SITE — the two sites are
  separate surfaces and a single test cannot bind both (unbounding v3 alone once
  left every test green):
  `TestGetBulkBuildBounded_6551` (v2c construction),
  `TestGetBulkBuildBoundedV3_6551` (v3 construction),
  `TestGetBulkCostDoesNotScaleWithMaxRepetitions_6551` (v2c call site,
  `agent.go`), and
  `TestGetBulkCostDoesNotScaleWithMaxRepetitionsV3_6551` (v3 call site,
  `v3.go`). BOTH cost guards measure ALLOCATIONS rather than wall time, so
  machine load cannot move them — the v2c one measured wall time until #8211,
  and flaked under full-suite load in diffs that could not reach `pkg/snmp`.
  Equivalence-vs-unbounded and encoder-parity guards:
  `TestGetBulkBoundedMatchesUnbounded_6551`,
  `TestVarbindEncodedLenMatchesEncoder_6551`.
  **GET/GETNEXT have no equivalent amplification.** The argument is an
  OPERATION COUNT, not a byte count: RFC 3416 §4.2.1/§4.2.2 bind them to exactly
  one response varbind per request varbind, so the work is BOUNDED BY a constant
  number of snapshot operations per DECODED REQUEST OID and every varbind built
  is one the manager asked for. Precisely: GET performs `getOIDValueSnap` only;
  GETNEXT performs `findNextOIDSnap`, then `getOIDValueSnap` only when a
  successor exists. Neither is a pair-per-OID in general — the bound is what
  matters, and it is O(1) per request OID either way. There is no `max-repetitions`
  field and nothing else a request can set to make a single OID cost more than
  one operation — that is the whole difference from GETBULK, whose `R*M` grid is
  a request-controlled multiplier on top of the OID count. The only lever left
  is how many OIDs one datagram can carry, and that is a fixed ceiling: the read
  buffer is `maxPacketSize` (4096 bytes) and `decodePDUFields` does not require
  a request varbind to carry a value TLV at all, so the densest packing it
  accepts is a five-byte varbind (`30 03 06 01 2B`) — on the order of 800 OIDs
  per datagram, not the ~580 a well-formed seven-byte varbind allows.
  `TestWireVarbindByteFloors_6551` pins that five-byte minimum, and the
  companion fact on the response side: `berDecodeOID` rejects an empty body and
  yields at least two components, so a varbind built from a wire OID re-encodes
  to at least seven bytes and the six-byte `minVarbindEncodedBytes` floor used
  for the structural cap is conservative rather than reachable. A max-size
  GETNEXT (239 deep ifXTable OIDs) costs ~33 ms and returns all 239 varbinds in
  a full 4095-byte response; that cost is `findNextOIDSnap` being a linear MIB
  scan, not unbounded expansion, and is not addressed here.
- **GETBULK varbind order is repetition-major (RFC 3416 §4.2.3, #5065).** For
  `R` repeater columns and `M` repetitions the response interleaves by
  repetition — `rep0-col0, rep0-col1, …, rep1-col0, …` (varbind index
  `nonRepeaters + rep*R + col`), NOT column-major (`col0-rep0..col0-repM-1`).
  A table-oriented manager reconstructs rows by the known width `R`, so
  column-major mis-associates columns for `R >= 2`. Both the v2c handler
  (`handleGetBulk`) and the v3 dispatcher call the single shared
  `buildBulkVarbinds`, which keeps one GETNEXT cursor per repeater column and
  advances each across repetitions. A column that runs past the end of its MIB
  view emits `endOfMibView` (named with that column's terminal OID) in its own
  grid cell for that and every later repetition, so the `row*R+col` index stays
  aligned. Wire-order + early-exhaustion coverage:
  `ber_getbulk_conformance_test.go` (v2c + v3).
- **Plain GET/GETNEXT responses are size-bounded too (#4918).** A GET/GETNEXT
  carries a fixed 1:1 varbind-per-request-OID contract, so an oversized
  response cannot be trimmed like GETBULK (the manager cannot "continue" a
  GET). Per RFC 3416 §4.2.1/§4.2.2 an over-size GET/GETNEXT response is
  replaced with `tooBig` + an empty varbind list rather than emitting a
  datagram larger than the effective maximum. `boundGetResponse` (v2c, in
  `agent.go`) and the v3 GET/GETNEXT tail (`v3.go`) enforce this; before #4918
  only GETBULK was bounded (#2612), so a GET naming many OIDs — or one OID with
  a long configured string value — could reflect an oversized datagram.
- **The interface table is snapshotted ONCE per PDU (#4013).** `SetIfDataFn`
  (the daemon's `buildSNMPIfData`) performs a full netlink `LinkList`
  (RTM_GETLINK dump) on every call, so a request handler must NOT read it
  per-varbind. Each request builds one lazy `ifSnapshot` (`newIfSnapshot`) and
  threads it through `getOIDValueSnap` / `findNextOIDSnap` /
  `getIfTableValue` / `getIfXTableValue`, so a GETBULK/GETNEXT walk over N
  interfaces performs at most ONE dump for the whole PDU instead of two per
  returned varbind. Before this the ifTable GETBULK walk issued 2× a full
  RTM_GETLINK dump per varbind — an O(N)/O(N²) netlink storm that floods the
  kernel and contends with the interface reconcile and VRRP; an aggressive
  poller could amplify a single GETBULK into a netlink DoS. The snapshot is
  lazy: a PDU that never touches the ifTable/ifXTable (e.g. a system-group GET
  of `sysUpTime`) triggers no dump at all. The public one-shot forms
  (`getOIDValue` / `findNextOID`) build a fresh single-use snapshot and are for
  single-object callers/tests only — multi-varbind handlers use the `*Snap`
  forms with one shared snapshot. `ifSnapshot` is not safe for concurrent use;
  each request builds its own. Fail-on-revert guard:
  `TestV2cGetBulk_SingleLinkListPerPDU`.
- **Trap delivery is asynchronous and bounded (#2991).** Link-state traps
  are emitted from the daemon's netlink link-monitor goroutine.
  `sendLinkTraps` builds the packet on the caller's goroutine (cheap) and
  enqueues one job per target onto a bounded channel
  (`trapQueueDepth = 256`) drained by a single worker goroutine; the
  blocking `net.DialTimeout` (and DNS resolution for an FQDN target) runs
  on the worker, NOT on the link monitor. A dead or slow target therefore
  cannot stall link-state processing. The queue is started lazily (works
  for both `NewAgent` and bare-struct test agents). When the queue is full
  the trap is DROPPED and `trapsDropped` is incremented rather than
  blocking the caller — dropping is the correct backpressure when targets
  are not draining. The delivery is replaceable through the per-Agent
  `trapSender` field (the seam tests use to inject a slow/mock sender on
  their own Agent; #5023 moved it off a shared package var so the injection
  no longer races the running trap worker's read under `-race`). Before #2991
  delivery was synchronous and inline, so an unreachable trap target (or a
  hung DNS lookup for an FQDN target) blocked link-state processing for up
  to the 2s dial timeout × target count.
- **The v2c trap community is selected deterministically (#2989).**
  `selectTrapCommunity` picks the lexicographically-first configured
  community (falling back to `public` when none is configured). The old
  code ranged the `Communities` map and broke on the first entry, which —
  because Go map iteration is randomized — picked a different community per
  run when more than one was configured, so a collector accepting only one
  community saw flaky traps and a less-privileged community could leak
  through the wrong credential boundary. Trap groups are likewise iterated
  in sorted order so dispatch and log output are reproducible.
- **Trap-group `version` selects the emitted PDU shape (#3948).** Each trap
  group carries a `version` (`v1` | `v2` | `all`, schema enum in
  `pkg/config/schema_system.go`) compiled onto `config.SNMPTrapGroup.Version`.
  `sendLinkTraps` builds the trap **per group** and honors it via
  `buildLinkTrapsForVersion`: `v1` emits an SNMPv1 Trap-PDU
  (`buildLinkTrapV1` — message version field 0, PDU tag 0xa4, the trap type
  carried in the enterprise/generic-trap/specific-trap/time-stamp fields per
  RFC 1157, with ifIndex/ifDescr/ifOperStatus varbinds; enterprise =
  `snmpTraps` 1.3.6.1.6.3.1.1.5 and agent-addr 0.0.0.0 per the RFC 2576 §3.1
  SNMPv2→SNMPv1 mapping), `v2` (or an unspecified/empty version — the default)
  emits the SNMPv2c trap (`buildLinkTrap`, version 1, PDU tag 0xa7), and `all`
  emits BOTH. Before #3948 the version was parsed but had no typed field, so a
  `version v1` group silently emitted v2c traps that a v1-only receiver drops.
- Don't add a third BER library to this package. The hand-coded encoder
  is intentional; keeping the surface small avoids bringing in an SNMP
  framework with its own poll loop and threading model.
