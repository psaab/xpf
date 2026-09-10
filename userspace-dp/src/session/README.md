# userspace-dp/src/session/

Userspace session table and timer-wheel garbage collector. Each worker
owns its `SessionTable` by value (`afxdp/worker/loop_body/setup.rs`); all
mutation goes through `&mut self` on the worker thread — single-writer by
construction. (The `Arc<Mutex<FastMap<...>>>` maps in `session_glue` /
`tunnel.rs` are the separate synced-session side tables, not this
structure.)

## Files

- `mod.rs` — `SessionTable` coordinator: the slab + `FxHashMap`
  secondary indices (canonical / forward / reverse key), the delta
  queue, and the #1752/#1855 in-place-refresh contract
  (`update_session` / `refresh_for_ha_transition` + the secondary-index
  re-assert + the #964 eager-cleanup `remove_entry`/`index_*` helpers).
  Slab + integer-handle layout shipped in #964 Step 1; the impl is
  split across `lookup.rs` / `install.rs` / `expire.rs` (#2005,
  pure code-motion — all submodules attach `impl SessionTable` blocks).
- `lookup.rs` — forward/reverse tuple match read path: the `lookup`
  family (primary + NAT-translated-reverse alias), the NAT/wire reverse
  finders (`find_forward_nat_match` / `find_forward_wire_match`), the
  single-entry / owner-RG / iteration read accessors, and
  `take_synced_local`.
- `install.rs` — session-creation path: the #1861 capacity preflight
  (`can_admit` + counters), the new-flow installs
  (`install_with_protocol*` / `upsert_synced*`), and the delta-emit /
  `delete` / owner-RG demotion helpers. These build fresh records; the
  in-place-refresh path stays in `mod.rs`.
- `expire.rs` — timer-wheel sweeps + eviction: `expire_stale_entries`
  (the per-tick bucket drain / lazy-delete GC pass), the throttled
  `push_to_wheel` scheduler, `wheel_observe`, and the #2120 standby
  retention gate (`expire_stale_entries_ha` + `standby_gate_decision` +
  `rebucket_alive_entry`).
- `entry.rs` — the PUBLIC session data types: `SessionDecision`,
  `SessionMetadata`, `SessionLookup`, `ForwardSessionMatch`,
  `SessionOrigin`, `SessionDeltaKind`, `SessionDelta`, and
  `ExpiredSession`. The internal per-entry `SessionEntry` (and its #2120
  standby-gate fields `seen_rg_epoch` / `first_held_ns`, see "Standby
  retention" below) stays file-private in `mod.rs`, NOT here.
- `key.rs` — `SessionKey`, `forward_wire_key` (ingress 5-tuple),
  `reverse_canonical_key` (post-NAT lookup), and
  `reply_matches_forward_session` (the predicate used to detect "this
  inbound packet matches an existing outbound flow").
- `wheel.rs` — bucketed timer wheel (1 s per tick, 256 buckets). Each
  worker sweeps its own table once per second from its poll loop
  (`expire_stale_entries` in `afxdp/worker/loop_body/mod.rs`);
  lazy-delete on lookup picks up stragglers.
- `tests.rs` — co-located unit tests.

## Timeouts

| Class | Default | Operator leaf (#7342) |
|-------|---------|-----------------------|
| TCP established | 300 s | `security flow tcp-session established-timeout` |
| TCP opening (half-open) | 20 s | `... initial-timeout` |
| TCP CLOSING (FIN in one direction) | 30 s | `... closing-timeout` |
| TCP TIME_WAIT (FIN in both directions) | 30 s | `... time-wait-timeout` |
| TCP abort (RST) | 2 s | none — #3046, an xpf control |
| UDP   | 60 s | `security flow udp-session session-timeout` |
| ICMP  | 60 s | `security flow icmp-session session-timeout` |

### CLOSING vs TIME_WAIT (#7342)

Junos distinguishes CLOSING (after the first FIN) from TIME_WAIT (after the close
handshake completes). Before #7342 this dataplane had ONE post-FIN window, so
`closing-timeout` and `time-wait-timeout` had nothing to attach to independently
— mapping either onto that window was a guess and mapping both was impossible,
which is why #6539 could only record that neither was enforced.

The discriminator is a FIN per DIRECTION, on `SessionEntry`:

* `fin_own` — a FIN arrived in THIS entry's own direction, set on the read path.
* `fin_peer` — mirrored from the companion by
  `propagate_tcp_state_to_companion`, which already mirrors close state between
  the two halves (#4109 F17).

`SessionEntry::tcp_close_class` reads them: `reset` short-circuits to the abort
window, both bits are TIME_WAIT, otherwise CLOSING. `tcp_close_window_ns` is the
single formula that maps a class to a window — four sites used to carry their own
copy of "RST → 2s, else 30s", and adding a third arm to each is the drift the
one-formula rule exists to prevent.

The bits are gated on FIN specifically, not on `is_closing` (which is FIN **or**
RST): a RST is an abort with no close handshake to complete, and a reset session
never reaches TIME_WAIT.

**Why they could not be derived from existing state.**
`SessionEntry.observed_tcp_flags` looks like the answer and is not.
`account_packet` OR-folds BOTH directions' flags onto the FORWARD entry on
purpose (#2749, so NetFlow's `tcpControlBits` reports the whole flow), so
`observed_tcp_flags & TCP_FIN` is already true after ONE fin. A TIME_WAIT
detector built on it would put every half-closed session straight into TIME_WAIT
— and every single-FIN test would still pass.

**Close state does NOT cross the HA session-sync wire (#9412, OPEN).** All four
bits are node-local, so an imported session has `closing` / `reset` / `fin_own` /
`fin_peer` FALSE regardless of what the primary's session was doing, and
`install.rs` ages it on the ESTABLISHED window (300 s) instead of the close
windows above. A flow that closed within its close window of a failover and then
went SILENT therefore holds a table slot for up to 300 s on the new active.

Two things bound it, and they are why the severity is Low: the primary's own reap
emits a Close delta that removes the standby copy in steady state, and the first
post-promotion packet re-marks `closing` and recomputes the window through
`tcp_close_window_ns` on the `lookup.rs` read path. The residual is the
intersection — closed near a failover, then silent.

Two traps recorded because both look like the fix and are not:

- **Re-deriving from the synced `tcp_flags` is vacuous.** The production import
  constructor hardcodes `tcp_flags: 0`
  (`server/helpers/session_sync.rs`), so there is nothing to derive from. The
  #3152 comment block in `install.rs` used to describe those flags as
  "install-time flags", which reads as though real flags arrive and #3152 declines
  to trust them; that wording is corrected, and
  `tcp_flags_zero_on_sync_path_9412_tests.rs` pins the hard zero so it cannot
  drift back. That cell is deliberately TWO-SIDED: it FAILS when #9412 is fixed,
  so the fix cannot land while the code still claims close-state cannot cross.
- **Carrying close-state on the existing delta is not sufficient by itself.** The
  close transition happens on the `lookup.rs` read path, which pushes NO delta,
  and the incremental sweep re-sends only sessions whose `Created` is newer than
  the last tick (`pkg/cluster/sync_conn_sweep.go`) — so a mid-life state change is
  never re-sent. A working fix needs a state-update push as well as a wire field,
  and that push must not emit a spurious `RT_FLOW_SESSION_CREATE` (SessionDelta
  feeds the RT_FLOW exporter too) or overrun the #8593 loss-of-sync latch.

**Compatibility.** `tcp_closing_ns` and `tcp_time_wait_ns` both default to the
window every post-FIN close already used, `0` on the wire means unset, and the
three carriers are `omitempty` / `serde(default)`. An operator who sets neither
leaf, a Go binary that predates #7342, and a helper that predates it all reap
byte-identically to before the split; each of those three is pinned by its own
cell in `tcp_close_state_7342_tests.rs` and
`forwarding_build/tests.rs`.

**Precedence.** The per-zone `screen ... syn-flood timeout` override (#3527)
still beats the global `initial-timeout` for that zone's half-opens — a screen
control an operator set per zone must not be outranked by a global default.

**Per-application inactivity-timeout (#3227).** A custom application's
`inactivity-timeout` (`set applications application <a> inactivity-timeout
<secs>`) overrides the global per-protocol timeout for the ESTABLISHED /
idle window of any session admitted by a policy whose matched application
term carries it. It rides the wire on `PolicyApplicationSnapshot.
inactivity_timeout` (seconds, omitempty — 0/absent = use-global), is
surfaced by the matcher as `PolicyEvaluationResult.inactivity_timeout`,
and is stamped at install onto `SessionMetadata.inactivity_timeout_ns`
(seconds->ns, saturating). **Bound (#3714):** `app_inactivity_timeout_ns`
first clamps the seconds value to `APP_INACTIVITY_TIMEOUT_MAX_SECS`
(86400 s) — the runtime backstop mirroring the Go commit gate
`appTimeoutMax` (`pkg/config/compiler_applications.go`, which rejects
`inactivity-timeout > 86400` at commit). Because that conversion is the
single authority both the config-snapshot path and the HA session-sync
receive funnel through, a corrupt / mixed-version wire value (e.g.
`4294967295`) is clamped rather than stamping an effectively
never-expiring idle timeout that would diverge session GC from the
commit-time contract. `session_timeout_ns` then prefers that override
for the established TCP / UDP / ICMP idle window on install AND on every
real-traffic refresh (`lookup.rs` / `update_session`), so the conntrack
GC ages the flow out on the app's value. It deliberately does NOT extend
the short TCP closing/RST reap windows (a FIN/RST close still reaps on
`TCP_CLOSING_TIMEOUT_NS` / `TCP_RST_TIMEOUT_NS`), matching Junos, where
`inactivity-timeout` is the idle timeout of an established session.
**Precedence:** the first matching policy rule wins (policy order), and
within that rule the first matching application term supplies the timeout
— the exact destination-port term is consulted first, then range terms in
config order, then ICMP-type-constrained terms. An application with no
custom timeout (`None`) is byte-identical to pre-#3227 and ages on the
global per-protocol timeout. This restores the legacy-eBPF `appTimeout`
parity (the retired maps wired the same per-app value). **HA (#3301):**
like `policy_id` and `policy_counter_idx`, the override now rides the
cross-node session-sync wire — the helper emits it (in seconds) on the
SESSION_OPEN delta and on `SessionSyncRequest.inactivity_timeout`, and
`build_synced_session_entry` re-applies it via `app_inactivity_timeout_ns`.
A peer-promoted session therefore ages out on the app's idle window after
failover without waiting for a real-traffic refresh. An old peer omits the
field (`serde(default)` 0 → `None` → the global timeout), bit-identical to
pre-#3301 (rolling-upgrade safe).

**Not every `SyncImport` entry is a wire import (#6224).** The local-origin
GRE encapsulation path (`build_local_origin_tunnel_tx_request`, tunnel.rs)
seeds a session for the firewall's OWN kernel-routed traffic read off a TUN
device and tags it `SessionOrigin::SyncImport` purely to reach the uncapped
coordinator-authoritative install path — it is not a peer wire import and has
no `SessionSyncRequest`. That path runs no security policy / application match
(forwarding-only resolution; `policy_id: 0`), so there is no admitting
application to source a per-app `inactivity_timeout_ns` from: it correctly
stamps `None` (the global per-protocol timeout) rather than reading the wire
override, and its synthesized reverse companion inherits that `None`. This is
the correct value for self-originated traffic, not the #5153 forward-has-value
/ reverse-hardcoded-`None` inconsistency.

**TCP opening / half-open state (#3152).** A TCP session created by a
bare SYN (SYN set, ACK clear) starts in the OPENING (half-open) state
(`SessionEntry.established == false`) and is reaped on the short
`SessionTimeouts.tcp_opening_ns` window (20 s, the Junos
`tcp-initial-timeout` default) instead of the full 300 s established
timeout. It is promoted to ESTABLISHED only on a genuine reverse SYN-ACK
(**#4109**, tightened from "any ACK-bearing segment"): the server's
handshake response is a SYN-ACK on the REVERSE half of the flow, so ONLY a
SYN-ACK (`is_syn_ack`, not merely `has_ack`) on the reverse companion
(`metadata.is_reverse`) promotes, and it promotes BOTH the reverse entry
and its forward companion (see the companion propagation below). A
client-only forward ACK never promotes a half-open session — before #4109
any ACK did, so a bare SYN followed by a bare ACK pinned a 300 s
established entry with no peer ever replying, a 2-packet bypass of the
#3152 half-open reap (a real vSRX with the syn-check default does not mark
a session ESTABLISHED on a client ACK that precedes the server's SYN-ACK).

**The established idle window applies only once the handshake COMPLETES
(#6752),** which is a strictly later moment than the promotion above.
Promotion is on the SYN-ACK, so a SYN-ACK the client never ACKs used to put
BOTH halves on the 300 s window: the reverse half was re-stamped to 300 s
immediately, and the #4380 companion probe — protocol- and
handshake-agnostic — then re-stamped the forward half off it at the forward
half's 20 s deadline. #4109 had explicitly declined to extend the forward
half's expiry "so a handshake the client never completes still reaps on the
short opening window"; #4380 landed three days later and falsified that
without either change being wrong on its own. `SessionEntry.handshake_pending`
closes the gap: it is set on both halves by the SYN-ACK and cleared by the
handshake-completing forward segment. The idle-window selection then treats
`established && !handshake_pending` as the established class, which is what
closes the ~300 s hold — with it, both halves reap at ~20 s on their own.
`companion_keeps_alive` additionally refuses to extend a half whose companion
is still pending; that closes a smaller, separate leak, where a server
retransmitting its SYN-ACK slides the reverse half's window forward and the
handshake-agnostic probe re-stamps the forward half off it for as long as the
retransmissions continue. A completed handshake is unaffected — the forward segment that
completes it is guaranteed to reach the slow path, because `packet_eligible`
admits a TCP packet to the flow cache only when `is_ack_only` and
`should_cache` uses the same predicate, so neither the SYN nor the SYN-ACK
ever seeds an entry and the final ACK is a cache miss.
Requiring the SYN bit (not just `has_ack` on the reverse tuple) also closes
the residual where a server-spoofed bare reverse ACK could promote — in a
legitimate 3-way handshake (and simultaneous open) the server's only
pre-established reverse segment IS the SYN-ACK, and xpf is inline so it
always observes it (control segments bypass the flow cache and reach this
slow-path promotion site). The promotion is sticky (a later segment never demotes an
established session back to OPENING) and is applied on all three
timeout-selection sites (`install` / `upsert_synced`, `lookup`,
`update_session`). The state is initialised
ESTABLISHED for every non-TCP session and for any TCP session whose
creating packet is NOT a bare SYN (a mid-stream pickup such as a SYN-ACK
or data segment), so those paths are byte-identical to pre-#3152.

Without this, a bare SYN landed on the full established timeout, so a
low-rate bare-SYN flood (SYN with no follow-up ACK) could pin half-open
entries in the bounded `max_sessions` table for the full established
window and eventually deny new legitimate flows. The opt-in syn-flood
screen + SYN-cookie path already prevents half-open installs entirely
when configured on the ingress zone; this is the defense-in-depth /
Junos-parity backstop for zones without it. It is the SYN-flood/half-open
sibling of the #3046 RST-reap window and composes with the #3227 per-app
idle timeout (which is the established idle value and never shortens or
lengthens the opening window). The global `tcp_opening_ns` window is held
at the default on every construction path including `from_seconds`; the
per-zone override below (#3527) is the operator knob.

**Per-zone half-open override (#3527 — Junos `syn-flood timeout`).** The
Junos `tcp syn-flood timeout N` leaf does NOT belong to the screen-rate
substrate (#3315 D5); it bounds the half-completed-connection queue, which
maps to this OPENING window. The Go control plane carries it on the screen
snapshot (`ScreenProfileSnapshot.syn_flood_timeout`, seconds) and the
forwarding builder turns each screened zone's timeout into a per-ingress-
zone override (`ForwardingState.session_opening_overrides`, zone id → ns),
pushed onto the worker `SessionTable` via `set_opening_overrides` next to
`set_timeouts` (at startup AND on every runtime snapshot rotation — a full
replace, so removing the leaf reverts the zone to the global default).
`session_timeout_ns` takes an `opening_override_ns` consulted ONLY on the
OPENING branch (never the established / closing / RST windows): a bare-SYN
session in a zone with `syn-flood timeout N` reaps `N` seconds after
install instead of the global 20 s default, on all three timeout-selection
sites (install, lookup-refresh, update_session). The override resolves from
the entry's `ingress_zone`; an empty override map (no zone configures a
timeout) is byte-identical to pre-#3527.

**HA-sync interaction (#3152).** The `established` field is node-local
derived state and is NOT carried on the cross-node session-sync wire (no
wire-format change). Sync-delta emission/gating is unchanged, so HA
failover semantics are untouched — a half-open session is neither
specially suppressed from nor specially forced onto the peer. A
peer-synced session is imported as ESTABLISHED (`upsert_synced_with_
origin`), NOT re-derived as OPENING from the synced `tcp_flags`. Two
reasons: (1) the short opening window is a FORWARDING-NODE protection
against a locally-received bare-SYN flood, and the standby never receives
that flood directly (it receives synced sessions); (2) the synced
`tcp_flags` are the install-time flags (the opening SYN for a SYN-created
flow) and are not guaranteed to be re-published as the primary's
handshake completes, so deriving OPENING on import could misclassify a
LIVE established flow on the standby and reap its synced copy at the short
stale-synced ceiling (`STALE_SYNCED_CEILING_MULT × opening`), breaking
failover for any flow older than that ceiling. Importing as ESTABLISHED
preserves the exact pre-#3152 standby behaviour (full established timeout
+ #2120 standby retention). The half-open table-exhaustion mitigation
still holds end to end: the primary (the flood target) reaps its
half-opens at `tcp_opening_ns` and emits a Close delta
(`session/expire.rs`) that propagates to the standby, removing the synced
copy promptly without the standby needing its own OPENING window.

The #3527 per-zone opening override composes with this cleanly (the #3315
plan §11.1 open question). Like `established`, the override is node-local
derived state and does NOT cross the session-sync wire: it is re-derived
per node from each node's config snapshot (HA requires identical config,
so both build the same map). Because a peer-synced session is imported
ESTABLISHED, its OPENING branch is never taken, so the override is
irrelevant on the standby for synced sessions — `upsert_synced_with_origin`
passes `None` explicitly. The override only governs locally-received
bare-SYN floods on whichever node is forwarding.

**RST vs FIN close (#3046).** A graceful FIN close keeps the full 30 s
`TCP_CLOSING_TIMEOUT_NS` (TIME_WAIT-style window for half-closed /
delayed-ACK transitions). A connection torn down by RST is an abrupt
abort with no retransmit window, so it is reaped on the much shorter 2 s
`TCP_RST_TIMEOUT_NS` — this prevents a reset-flood (or any high-churn
reset workload) from saturating the session table with dead connections
and delays port reuse far less. The RST state is sticky (`SessionEntry.reset`):
once a session has carried a RST it stays on the short timeout even if a
later reordered non-RST segment arrives, so it can never be promoted back
to the 30 s FIN window.

**Sticky close state (#3489).** All three TCP state flags are sticky and
set with `|=` on both the read path (`lookup.rs`) and the refresh /
HA-promote path (`update_session` in `mod.rs`): `reset` (#3046),
`established` (#3152), and `closing` (#3489). `closing` was the last
non-sticky one — it used a plain `=` in `update_session`, so a later
non-closing segment (e.g. a reordered data-ACK, `flags=0x10`) refreshing
a FIN'd entry — including over the HA shared-promote path, where the
`closing` flag is synced to the peer — reset `closing` back to false. The
expires selection then took the established branch and moved the session
from the 30 s `TCP_CLOSING_TIMEOUT_NS` window back to the 300 s
established window, so a FIN'd connection lingered up to 10× too long
holding a bounded `max_sessions` slot. Making `closing` sticky restores
the read-path/refresh-path equivalence #3046 set out to guarantee. (The
close is an *idle* timeout — `expire.rs` reaps only after
`now - last_seen_ns > expires_after_ns`, and `last_seen_ns` is re-stamped
on every refresh — so a genuinely active half-closed flow keeps advancing
`last_seen_ns` and is never reaped early by the short window.)

**Forward↔reverse companion propagation (#4109).** A flow is TWO
independent `SessionEntry`s in the worker-owned table — the canonical
forward entry (`is_reverse == false`) and its reverse companion
(`is_reverse == true`, keyed on `reverse_session_key(forward.key, nat)` and
installed alongside the forward entry by `poll_descriptor`). The read path
resolves and mutates only the ONE entry a packet's wire tuple hits, so
per-direction TCP state had to be mirrored explicitly onto the sibling.
`SessionTable::propagate_tcp_state_to_companion` (called from `lookup.rs`
after the matched entry's borrow ends) recovers the companion key exactly
as `account_packet` hops reverse→forward — `reverse_session_key` on the
matched entry's OWN canonical key + nat, which is its own inverse — and
carries two things across:

- **Close (F17):** a FIN/RST advances only the entry it lands on into the
  short close window; the other half kept the 300 s established timeout, so
  a unidirectional RST left the dead flow's forward half lingering up to
  300 s (the #3046 2 s reset-reap was ~50 % effective under a reset
  workload; symmetric for a one-sided FIN vs #3489's 30 s). The companion
  now inherits `closing` (and `reset` if RST, sticky) and is pulled onto
  the same short window (2 s RST / 30 s FIN) and re-bucketed in the wheel,
  so both halves reap together — matching vSRX, where a RST invalidates the
  WHOLE session.
- **Promote (F16):** when a reverse SYN-ACK promotes the reverse companion,
  the forward companion is promoted too (flag only — its own
  handshake-completing forward ACK re-stamps the established idle window;
  we deliberately do not extend its expiry, so a handshake the client never
  completes still reaps on the opening window).

A missing companion (a `FabricRedirect` flow with no local reverse entry,
or a half already independently reaped) is a no-op — the same fail-open
posture as `account_packet`'s reverse hop. The propagation is gated behind
"a close or a reverse-promote happened", so a plain data-ACK refresh pays
no extra probe. On the HA-promote path (`update_session`), only the F16
`is_reverse` promotion gate is mirrored (a peer-synced session is imported
ESTABLISHED already, so the gate is a no-op there); cross-companion close
on a cluster is carried by the peer's Close-delta session-sync rather than
re-derived locally.

**Idle-companion retention (#4380).** The #4109 propagation above mirrors
TCP *close/promote* state, but nothing propagated plain *idle* activity, and
for UDP there is no propagation at all. Because forward and reverse are two
independent entries that age independently — the read path re-stamps
`last_seen_ns` only on the ONE entry a packet's wire tuple resolves
(`touch` / `touch_if_stale` / `lookup`), and `account_packet` folds both
directions' COUNTERS onto the forward entry WITHOUT touching either
`last_seen_ns` — a flow active on only one direction (a one-way UDP feed, or
a download whose forward ACKs have gone quiet) would reap its quiet half
mid-flow. That left a half-open session and, under NAT, let a later packet
re-create a session with a DIFFERENT translation while the surviving half
still mapped the old one. Junos measures a session's idle time from the last
activity in EITHER direction, so the quiet half must survive while the other
is active.

`SessionTable::companion_keeps_alive` (`expire.rs`, called from the Case-3
idle-crossed arm just before `remove_entry`, and ONLY on the owner-side
idle-expiry path — the `Age` HA decision or the `ha == None` standalone path,
gated by `companion_eligible`) enforces this off the hot path. The two
deliberate HA reaps do NOT consult it: `ReapStaleSynced` (the bounded
lost-primary-delete leak ceiling) and `AgedOwnerRgZeroActiveNode` (the known
active/active `owner_rg<=0` residual) both clear `companion_eligible` after
bumping their own counter, so the probe can neither override the leak ceiling
nor miscount them; and on a standby the `Hold` arm already retains BOTH halves
(it `continue`s before the probe is reached), making the probe redundant there.
When an entry crosses its idle timeout it probes its forward↔reverse companion
(recovered by `reverse_session_key` on the entry's OWN key + nat, its own
inverse, exactly as `account_packet` hops reverse↔forward). If the companion
is itself still within its idle window (the exact complement of the wheel's
strict-`>` expiry test), this half is re-stamped from the companion's REAL
`last_seen_ns` and `rebucket_alive_entry`'d instead of removed, and the
`kept_alive_by_companion` `WheelPopStats` counter is bumped. Bounded and
terminating: the re-stamp copies the companion's real timestamp (never
`now_ns`), so once BOTH halves stop receiving packets their timestamps freeze,
both cross the timeout, the probe fails, and the flow reaps within one timeout
window of its last activity in either direction — so the HA Close delta +
RT_FLOW harvest fire only when the WHOLE flow goes idle. A single-entry flow
(no companion — e.g. a `FabricRedirect` half with no local reverse, or a half
already independently reaped) is a no-op reap, the same fail-open posture as
`account_packet`'s reverse hop. The cost is one extra `key_to_handle` probe
per idle-crossed entry, in the GC pass only — the per-packet forwarding path is
unchanged (the alternative, refreshing the companion on every reverse packet,
would add a hot-path re-bucket).

**Reverse companion honors the app idle window (#5153).** Because the probe
compares the companion against `companion.expires_after_ns`, the reverse
companion built by `build_reverse_session_from_forward_match`
(`afxdp/shared_ops.rs`, the synthesized/failover and live reverse-install
path) inherits the forward session's per-application `inactivity_timeout_ns`
alongside the other metadata (log/policy/NAT64). Both halves of one flow share
the admitting application, so `session_timeout_ns` derives the SAME
`expires_after_ns` for either direction. Before #5153 the reverse companion
hardcoded `inactivity_timeout_ns: None`, so its window fell back to the global
per-protocol timeout; `companion_keeps_alive` then kept a short-timeout forward
half alive on the companion's longer global window — stale-state retention
beyond the app's configured idle timeout (residual of #3227/#3301/#4380). A
forward session with no per-app override still yields `None` on the reverse
companion (global timeout), bit-identical to the prior behavior.

**Seconds→nanoseconds bound (#2441).** Configured TCP/UDP/ICMP timeouts
arrive in the snapshot as `u64` seconds and are converted in
`SessionTimeouts::from_seconds`. The conversion uses `checked_mul` and
**saturates** at `MAX_SESSION_TIMEOUT_NS`
(`MAX_SESSION_TIMEOUT_SECS == i64::MAX / 1e9 == 9_223_372_036` s, the same
value as the Go `config.MaxDurationSeconds` commit gate) — it never wraps
and never panics. A snapshot-boundary helper must do neither, and
saturating fails toward a *longer*-lived session, the opposite of the
wrap bug it replaces (a huge configured timeout wrapping to a tiny one →
premature expiry). The bound is defense-in-depth: the Go commit gate
(`ValidateInteger(0, MaxDurationSeconds)` in `schema_security.go` +
`coerceWireSessionTimeout` build-time coercion) is the operator-facing
reject and is load-bearing for the normal in-band config path; this
saturation is the runtime backstop for an out-of-band snapshot or a
future caller that bypasses the Go gate.

## GC

`SESSION_GC_INTERVAL_NS = 1_000_000_000` (1 s). Single-threaded per-worker
sweep walks the wheel bucket for the current tick; stale entries get
lazy-deleted on the next lookup if they slip past the sweep (e.g.
because they were re-bucketed mid-sweep).

## Flow-cache keepalive (#2220)

The flow-cache fast path (`afxdp/poll_descriptor/flow_cache_hit.rs`) is
the ONLY code path that refreshes a forwarded flow's `last_seen_ns` — a
flow served entirely from the per-worker flow cache never re-runs the
slow path that would otherwise touch the session. `touch_if_stale` is
the keepalive it calls on every cache hit: it re-stamps the matched
session ONLY once that session has gone idle for at least
`expires_after_ns / SESSION_KEEPALIVE_DIVISOR` (a quarter of its OWN
timeout). An actively-forwarding cached flow is thus re-stamped whenever
its idle time crosses `expires_after_ns / N`, keeping its age ~`T/N` in
steady state regardless of co-resident flow rates, so it can never be
GC'd mid-flow (reaped only if a real inter-packet gap exceeds `T`). The
steady-state per-hit cost is one `key_to_handle` probe plus an integer
compare (the `last_seen_ns` write + throttled `push_to_wheel` run only
when actually stale); allocation-free.

This replaced the pre-#2220 binding-GLOBAL modulo-64 counter
(`flow_cache_session_touch`), which incremented across ALL flows on the
binding and touched only the flow whose hit happened to land on a global
multiple of 64. A low-rate flow co-resident with a saturating flow could
be served from the cache for a whole timeout window without its session
ever being touched, then be reaped while still forwarding (an HA Close
delta to the peer + BPF redirect-key deletion + a stale flow-cache
descriptor out-living its session). UDP (60 s) was the most exposed.

## Flow-cache invalidation on reap (#3776)

The #2220 keepalive only protects an ACTIVELY-forwarding flow — the cache
hit is what refreshes the session. It does nothing for a flow that idles
PAST its timeout: the GC wheel reaps the session and
`release_source_nat_allocation` returns its SNAT port to the pool, but
the flow-cache slot survives (config/fib generation, RG epoch, and RG
lease are all unchanged, and the slot is not LRU-evicted). If traffic
later resumes on the same 5-tuple it HITS the surviving
`RewriteDescriptor` and is forwarded WITHOUT a live session — a
stateful-firewall bypass (no policy re-evaluation, no session install, no
`show security flow session` row, not HA-synced) — and via a SNAT port
that may already have been re-handed to a different flow (NAT-port reuse /
reverse-path collision). This was the half of #2220 that was never
shipped.

`reap_expired_sessions` (`afxdp/worker/loop_body/mod.rs`) now closes it:
for every entry the GC sweep reaps it calls
`flow_cache.invalidate_slot(&key, binding.ifindex)` on every binding of
the owning worker, mirroring the RST-teardown eviction in
`afxdp/worker/lifecycle.rs`. The next packet on that tuple then MISSES the
cache and re-runs full session lookup/creation + policy (fail-closed: no
forwarding without a live session, no stale-SNAT reuse). Because the flow
cache is per-binding and worker-owned and the sweep runs on the owning
worker, this is a same-thread mutation — no cross-thread flush. Invalidating
on every binding is safe and precise: the session table is keyed by the
5-tuple ALONE, so at most one live session (hence at most one valid
descriptor) exists per key, and `invalidate_slot` drops only a slot whose
key AND ingress_ifindex both match — on a non-owning binding it either
no-ops or evicts a stale prior-flow slot with the same tuple, never
another live flow's entry. Forward and reverse are each their own
`ExpiredSession` with their own key, so both directions are covered. The
work is bounded by the ~1/s GC sweep, so it adds no per-packet cost and
does not regress the keepalive fast path. Config/RG-lifecycle removals
already invalidate via the generation/epoch stamp checks
(`flow_cache.rs` lookup); the reap path is the gap those checks do not
cover because a plain idle-timeout reap bumps neither.

## Flow-cache invalidation on control-plane delete (#6457)

The same stale-descriptor exposure existed on every control-plane session
delete. Three flows funnel through `WorkerCommand::DeleteSynced` —
the operator's `clear security flow session [all]` (Go
`ClearAllSessions` / singular `DeleteSession`), the cluster-stale sweep
(`BatchDeleteSessions`), and HA DeleteSynced propagation from the peer
(`delete_synced_session_gen` fan-out plus cross-worker
`replicate_session_delete`) — and none of them bumps config/fib
generation, RG epoch, or RG lease. `handle_delete_synced` dropped the
session (NAT/NAT64 release, session-map/conntrack delete) without
touching the flow cache, so a revoked-but-continuously-active 5-tuple
kept HITTING its cached `RewriteDescriptor` on the owning worker:
forwarded indefinitely with no session row, no policy re-evaluation, no
`show security flow session` visibility, and no HA sync — the operator's
explicit revocation primitive silently defeated on the fast path
(fail-open). Only continuously-active flows survived (an idle gap lets
the #3776 GC reap fire); a commit/RG change also flushed the stale slot
via the stamp checks.

`handle_delete_synced` now records every deleted key —
UNCONDITIONALLY, even when the worker's session table has no entry,
because a stale cached descriptor outlives the table entry it was seeded
from — into `WorkerCommandResults.deleted_synced_keys`
(`apply_worker_commands` has no `BindingWorker` access, the same
constraint that put the #941 vacate dispatch in the worker loop). The
worker loop drains the list through
`invalidate_flow_cache_slots_for_deleted_sessions`
(`afxdp/worker/loop_body/mod.rs`), which calls
`flow_cache.invalidate_slot(&key, binding.ifindex)` on every binding of
the worker — the same same-thread, key+ifindex-precise eviction as the
reap path, and `delete_synced_session_gen` fans out the forward AND
reverse keys so both directions are covered. The cost is one Vec push
per delete plus one `invalidate_slot` set-walk per binding per delete —
bounded by the control-plane delete rate, zero per-packet cost: the hit
path is untouched and ticks with no deletes skip the walk entirely.

Regression coverage: `afxdp/session_glue/tests.rs` pins the
unconditional key record (`delete_synced_records_key_*` — RED if the
push is removed) and `afxdp/worker/loop_body/mod.rs`'s
`flow_cache_invalidation_tests` pin the eviction
(`delete_synced_flow_cache_slot_is_invalidated`,
`delete_synced_snat_descriptor_is_not_reused`,
`delete_synced_invalidation_walks_every_binding` — RED if the
invalidate loop is removed).

## Static input-filter revalidation stamp (#7212)

Junos firewall filters are stateless and evaluated on every packet, so a filter
attached or tightened after a session exists applies to that flow immediately.
The dataplane's session-hit fast path re-evaluated an interface INPUT filter only
when its verdict genuinely varies per packet (#1430 DSCP / #2362 per-packet L4),
so a purely STATIC address/protocol/port `then discard` added later was never
rechecked and the flow forwarded until it idled out (#5858, closed against
#7212).

`SessionEntry.filter_revalidated_gen` closes it. It records the
`ValidationState::config_generation` this direction's input-filter verdict was
last computed under:

* `SessionTable::filter_revalidation_gen` is the generation a verdict is judged
  AGAINST. `poll_binding_process_descriptor` publishes it once per pass from the
  SAME `ValidationState` the pass classifies packets with, so the stamp a
  session carries and the generation it is later compared to can never come from
  different publishes.
* EVERY install stamps `UNVALIDATED`, not that generation — forward, reverse
  companion and peer-synced import alike (`session/install.rs`, both sites), and
  `mark_filter_revalidated` is the field's only other writer. (An earlier
  revision of this line said `install` stamps the live generation. It does not,
  and never did; corrected in #8356 while adding the policy sibling below.)
* `upsert_synced` stamps `0`, which is never a live generation. A peer-synced
  session therefore revalidates against THIS node's filter state on the first
  packet it forwards after a promotion — the failover fence, obtained from the
  import default rather than from cross-node plumbing.

The key the stamp is read and written through is the entry's CANONICAL key, and
the poll path does not hold one: `ResolvedFlowSessionDecision::key` is
`ResolvedSessionKey::QueryKey` on a local session-table hit — the tuple the
packet carried. For most established hits that IS the entry's key, including an
ordinary source-NAT reply: the pair install stores the reverse companion under
`reverse_session_key(forward, nat)`, which is already the wire reply tuple, so
the reply resolves through the PRIMARY index. But `lookup_with_origin` also
resolves through the reverse-translated ALIAS index, and an entry reached that
way is stored under a DIFFERENT key than the one that found it — a
primary-index-only probe reports it fresh forever, never revalidates it, never
re-stamps it, and a teardown handed the wire tuple deletes nothing.

`stale_filter_revalidation_key` resolves the wire tuple the same two ways
`lookup_with_origin` does — the primary key WITH its stale-handle guard (a
`key_to_handle` hit whose stored key does not match is a reused slab slot and
must not fall through to the alias index, where a live alias entry for the same
tuple would resolve a DIFFERENT session), then the reverse-translated index with
its own `is_reverse` + round-trip validation — and answers the staleness
question in the SAME probe, so the established-hit path pays one hash rather
than three. The verdict then carries the resolved key rather than a bool, so the
teardown acts on the session that was judged.

Those are the only two indexes an established HIT resolves through.
`forward_wire_index` and `nat_reverse_index` are also reachable from
`lookup_session_across_scopes`, but both surface as
`ResolvedSessionKey::Canonical`, so they primary-probe cleanly.

A `None` from that probe covers two answers. Either the entry is already judged
under this `(generation, ingress)` — the common one — or this worker's table
holds no entry for the tuple, because the hit was served from the SHARED map
without a local install (the #2120 transient synced-hit path) or because a
reverse-NAT repair's install was refused at `max_sessions`. In those there is
nothing local to stamp or tear down; the transient window is bounded by
`maybe_promote_synced_session` installing the entry `UNVALIDATED`, and both are
tracked in #8114.

On an established-session HIT, `evaluate_input_filter_on_session_hit`
(`afxdp/poll_descriptor/filter.rs`) does ONE `iface_filter_v{4,6}_fast` lookup
and branches: a per-packet-varying filter keeps its existing per-packet
re-evaluation; a static filter is re-derived only when the stamp is stale. The
re-derivation is side-effect free (`NonRoutingCountPolicy::Never` — no
`then count`, no `then log`, no policer meter), and only the ACCEPT exit
re-stamps. A DENY deliberately leaves the stamp stale: the caller revokes the
session, so normally there is no entry left to stamp, and if the teardown ever
failed to take, a stamped entry would say "already judged under the live
generation" and be FORWARDED for the rest of the generation under a filter that
denies it. Unstamped, the next packet re-derives the same DENY and drops — the
same failure, fail-closed instead of fail-open.

A session the filter still
PERMITS costs one term walk per config generation and is otherwise untouched —
critically including its NAT translation, since a purged-and-recreated permitted
SNAT flow reinstalls on a DIFFERENT translated port and breaks. Only on a DENY
does the ordinary counted evaluator run, so the one newly-denied packet is
counted, logged and rejected exactly once.

Why the stamp is per-ENTRY and not on `SessionMetadata`: it is node-local derived
state like `established` / `handshake_pending`, carried on no wire and not part
of session identity. Why there is no stored ingress ifindex: forward and reverse
are separate entries with separate stamps, and each revalidates against the
interface the packet in hand actually arrived on — an OBSERVATION, where the
forward half's `resolution.egress_ifindex` would be a PREDICTION of where the
reply lands that asymmetric routing can falsify (see "True ingress-interface
identity on the session (#4983)" above for why `ingress_ifindex` is `0` on the
reverse companion).

Revocation reuses `delete_terminal_filtered_session` (#5622): forward + reverse
deleted, source-NAT / NAT64 reservation released exactly once via the forward
entry, forward close delta emitted even when the reverse half hit the deny.
Both directions' keys go onto `WorkerScratch::scratch_filter_revoked_keys`, which
`worker/lifecycle.rs` drains under the `left`/`current`/`right` split borrow and
evicts from EVERY binding of this worker in the SAME tick — a session does not
carry the ingress ifindex the cache is keyed on, and the two directions of one
flow are routinely cached on different bindings. Sibling WORKERS evict on their
next tick through the `replicate_session_delete` -> `DeleteSynced` -> #6457 path
the teardown already queues; that is the same promptness the operator's own
`clear security flow session` has.

`config_generation` is a SUPERSET trigger — it advances on every commit, not
only on filter edits. (It does NOT advance on a `BumpFIBGeneration`: that path
assigns `validation.fib_generation` alone and republishes, reusing the same
forwarding `Arc` so the #1188 worker short-circuit still hits. An earlier
revision of this paragraph claimed it did, which over-stated the cost.) The
superset is deliberate: the
re-derivation can only DROP a session the current filter denies, so an extra
revalidation of a permitted flow is a no-op, and it is gated behind the single
fast-map lookup that only an interface with an input filter attached ever passes.
A generation bump already invalidates every flow-cache entry
(`FlowCacheStamp::config_generation`), so the packet that pays for the
revalidation is one already taking the session path.

Regression coverage: `session/filter_revalidation_7212_tests.rs` (stamp
lifecycle) and `afxdp/poll_descriptor/filter_revalidation_7212_tests.rs`
(verdict, side-effect freedom, the NAT-alias reverse half, the fragment purity
case, the DENY-exit fail-closed stamp, and the pinned permitted-SNAT case).

## Zone-policy revalidation stamp (#8356)

The stateless-filter argument above applies unchanged to ZONE POLICY, and until
#8356 the tree only made it for filters. A commit that narrowed an input FILTER
tore down the live flows it denied (#5858/#7212); a commit that narrowed ZONE
POLICY did not. #7323 closed on accepting that as a residual — a flow this
node's newer policy would deny, whose input filters permit it, surviving as a
session until it ends — with peer-synced imports the population where it bites
hardest, since they carry the PEER's verdict and the receiver never re-asked its
own.

`SessionEntry::policy_revalidated_gen` closes it, receiver-locally: no wire
field, no negotiation, no `ProtocolVersion` bump, so it also protects against an
OLD sender during a rolling upgrade. Cadence, side-effect freedom, the
PERMIT-only re-stamp and the `delete_terminal_filtered_session` revocation are
all exactly as described for the filter above. The peer-synced fence is the same
one and comes from the same place: `upsert_synced` stamps `0`, which is never
live, so an import re-derives against THIS node's policy on the first packet it
forwards after promotion.

**Scope is EVERY session, not only peer-synced imports.** The narrow scope would
need a peer-synced marker on the entry, which does not exist; the broad one
needs nothing new and removes the asymmetry rather than preserving it.

THREE things deliberately do NOT mirror #7212, and the first is the one that
would take a box down:

* **FORWARD ONLY** (`!metadata.is_reverse`). #7212's stamp is per-DIRECTION and
  correctly so — a filter is a per-interface object and each direction is judged
  against the interface its packet arrived on. Copying that here is
  catastrophic. The reverse companion is built with SWAPPED zones
  (`afxdp/shared_ops.rs`, `afxdp/poll_descriptor/mod.rs`), and this is a
  STATEFUL firewall: a reply is permitted because the session exists, not
  because a policy admits (to_zone -> from_zone). Re-derived per-direction it
  evaluates the reversed pair, matches nothing on any ordinary one-way policy
  set, hits the default deny and revokes — so every established session in the
  box would die on the first packet after ANY commit.
* **GENERATION-ONLY stamp**, where `FilterRevalidationStamp` is keyed
  `(generation, logical ingress ifindex)`. A policy verdict is a function of the
  (from_zone, to_zone) pair, and both come from the ENTRY —
  `metadata.ingress_zone` and `decision.resolution.egress_ifindex` — never from
  the interface a given packet arrived on. Keying by ifindex would only make the
  stamp go spuriously stale and re-walk terms that cannot change verdict.
* **Side-effect freedom is STRUCTURAL, not a flag.** The filter needs
  `NonRoutingCountPolicy::Never` because its evaluator counts internally.
  `evaluate_policy_result_with_icmp` takes `&PolicyState` and RETURNS a counter
  handle for the caller to bump; it cannot count, log or meter by itself.

Two populations are DECLINED rather than adjudicated, both because the
derivation cannot honestly produce a verdict for them:

* **ICMP.** A zone policy can match ICMP type/code through an application term,
  so an ICMP verdict is a property of the PACKET, not of the flow — and this
  derivation is frame-independent, so it has no type to offer. Evaluating with
  none would fail to match a type-specific term and manufacture a DENY. The
  #7323 residual stays open for ICMP alone.
* **An egress that resolves to no zone.** `egress_zone_id` is `unwrap_or(0)` and
  policy matches no rule against the 0 sentinel, so the flow would fall to the
  default policy. That is a lookup failure, not a verdict. Reachable rather than
  defensive: `ifindex_unambiguous_zone_id` is populated only for interfaces with
  a resolvable link-layer address, so a MAC-less egress (an IPsec `xfrmi` secure
  tunnel, #6722) resolves to 0 while being perfectly routable and correctly
  zoned.

**What this does NOT cover.** `to_id` comes from the egress interface resolved
at install/import time, read through the LIVE zone ledger. A commit that moves
an interface BETWEEN ZONES is caught; a commit that changes a ROUTE so the flow
would now leave a DIFFERENT interface is NOT. Catching that needs a fresh
routing evaluation on the established-hit path, which is exactly what #2620
forbids — that path is the sole counter for its packet precisely because it
never calls the routing evaluator. #8356 does not re-open #2620.

Operator-visible signal: `policy_revoked_sessions`, the sibling of
`filter_revoked_sessions`. A non-zero value right after a commit is the
expected, intended reading — it is what the operator's narrowed policy did.

Regression coverage: `session/policy_revalidation_8356_tests.rs` (stamp
lifecycle, generation-only keying, and the two stamps' mutual independence) and
`afxdp/tests_policy_revocation_8356.rs` (the verdict and the WIRING, driven
through the real poll body: revoke-on-narrowed-policy, the still-permitted
control, the reverse-companion trap against an ASYMMETRIC policy set, and the
unknown-zone decline).

## Per-session byte/packet accounting (#2501)

Each `SessionEntry` carries a `SessionCounters` (`fwd_packets`, `fwd_bytes`,
`rev_packets`, `rev_bytes`) — plain `u64`s, not atomics, because the
`SessionTable` is worker-owned and single-threaded (same precedent as
`create_drops`). Every forwarded packet is accounted via
`SessionTable::account_packet(key, len)` on the AF_XDP forwarding hot path:

- the flow-cache fast path (`poll_descriptor/flow_cache_hit.rs`) accounts
  every packet of an established flow;
- the slow-path forward-build chokepoint (`poll_descriptor/mod.rs`, the
  `ForwardCandidate | FabricRedirect` branch) accounts the packets that
  reach the full forward-build — the first packet(s) of a flow before its
  cache entry warms, and any non-cacheable flow (NAT64/NPTv6).

`account_packet` derives the direction from the resolved entry rather than
trusting the flow-cache `metadata.is_reverse` (which is always `false` —
every cache entry is built from a forward-build decision). Both directions
are folded onto the **single canonical forward entry**: a forward packet
keys directly to it (`fwd`); a reverse packet keys to the reverse entry,
whose `reverse_session_key(rev.key, nat)` recovers the forward tuple, and
the volume lands on the forward entry's `rev`. This keeps the
forward-only BPF-conntrack mirror and the forward-only SESSION_CLOSE
harvest complete without a cross-entry combine or any dependence on the
two entries' independent expiry ordering.

Cost: the dominant forward direction is one warm `key_to_handle` probe +
one `saturating_add`; the reverse direction pays one extra probe to hop
reverse→forward. No allocation, no atomic, no cross-core traffic.

Surfacing (no new wire field):

- `refresh_bpf_conntrack_last_seen` (afxdp/bpf_map, budgeted slice — see
  "Budgeted last_seen refresh" below) writes the counters into the BPF
  conntrack map value, so `show security flow session` reports live volume
  (Go reads `FwdBytes`/`FwdPackets`/… from that map today);
- the close `SessionDelta` snapshots the entry's counters at expiry, and
  `emit_session_close_rt_flow` writes them into the SESSION_CLOSE RT_FLOW
  frame's already-reserved `[56:64]`/`[64:72]` (forward) and
  `[112:120]`/`[120:128]` (reverse) wire slots — the slots the Go
  `logging.DecodeRawEventRecord` already parses (previously hard-zeroed),
  so NetFlow/IPFIX close records carry real volume.

## Budgeted last_seen refresh (#5287)

`refresh_bpf_conntrack_last_seen` mirrors each forward session's `last_seen`,
`policy_id` and byte/packet counters into the BPF conntrack map so the Go
`IterateSessions` surfaces (CLI, gRPC, Prometheus) read accurate idle time and
volume. It does one BPF `lookup + update` per forward entry.

The refresh used to walk the WHOLE table in one uninterrupted pass. Near the
`DEFAULT_MAX_SESSIONS` (131072) cap that is tens of thousands of synchronous
kernel crossings executed between two RX/TX polls — a deterministic
per-interval latency spike on the low-latency worker core, exactly under the
high-session load where service and heartbeat stability matter (issue #5287).

It is now an **incremental, budgeted slice** driven by
`SessionTable::iter_with_idle_budgeted`:

- **Persistent cursor.** The cursor is a stable `entries` slab index (slab
  handles do not renumber across insert/remove — a removed slot goes vacant and
  is reused). The worker loop keeps it in `ct_refresh_cursor` and passes it back
  each slice, so the walk resumes exactly where it stopped.
- **Hard per-slice budget.** Each slice examines at most `CT_REFRESH_SLICE_BUDGET`
  (2048) slab slots — bounding BOTH the index scan and the per-entry syscalls,
  regardless of the occupied/vacant/forward/reverse mix. No allocation; the
  per-tick added cost is one integer compare plus one `saturating_sub` in the
  common between-cycles idle case.
- **Window-paced cycles.** The worker drives one slice per `CT_SLICE_INTERVAL_NS`
  (100ms) while a cycle is in flight, and paces successive full-table CYCLES to
  `CT_REFRESH_WINDOW_NS` (10s). A small or idle table is walked in one short
  slice per 10s — the steady-state syscall rate is unchanged from the old 10s
  full-table cadence, so the common case is not regressed.
- **Live-extent bound (#6297).** A cycle ends at the slab's live-extent
  high-watermark (`SessionTable::slot_high_watermark` = `1 + the highest slot
  index ever handed out`), NOT `entries.capacity()`. The slab never shrinks, so
  after a session-count spike drains, `capacity()` stays at the doubled peak and
  a capacity-bound walk would re-scan tens of thousands of now-vacant slots
  every cycle. The watermark is bumped on every insert (`insert_record`) and is
  never shrunk on removal. INVARIANT: it is always `>= 1 + every currently-
  occupied slot index`, so bounding the walk to it can never skip a live
  session's `last_seen` refresh (which would look idle and expire early). A
  slightly-high watermark after a drain only costs a few skipped vacant visits;
  a stale-LOW one would be a premature-expiry correctness bug, so the watermark
  only ever grows.

**Freshness/latency tradeoff.** At the 131072 default cap and 100ms cadence a
full cycle spans ~64 slices (~6.4s ≤ the 10s freshness window), so the whole
table is still refreshed within the window. If `max_sessions` is raised far
above the default a cycle stretches past 10s (freshness degrades gracefully),
but the per-slice cost stays hard-bounded at `CT_REFRESH_SLICE_BUDGET` — no
single loop tick ever walks the whole table again. Because a session installed
into an already-passed slot mid-cycle isn't re-visited until the next cycle,
freshness is best-effort diagnostic (the entry already gets `last_seen` stamped
at install via `publish_bpf_conntrack_entry`; the Go GC has `SkipSweep` set, so
a stale `last_seen` never causes premature expiry).

## Standby retention (#2120)

The Rust wheel now owns HA standby session retention — the contract the
eBPF Go-GC `IsLocalPrimary` gate used to enforce before the eBPF dataplane
was retired (#1373/#1476). Without it, the STANDBY node silently expired
long-lived peer-synced sessions whose idle timeout elapsed with no local
refresh, and the newly-promoted primary then dropped their return traffic
as a brand-new connection (#131, reintroduced by the eBPF→userspace
migration).

`expire_stale_entries_ha(now_ns, Some(ctx))` makes a three-way decision
for each idle-crossed entry before removing it (the plain
`expire_stale_entries(now_ns)` / `ha = None` path is standalone behavior —
every idle entry ages, exactly as before):

- **SELF-HEAL** (edge) — peer-synced, this node now FORWARDS the entry's
  RG, but `seen_rg_epoch` predates the activation (`RefreshOwnerRGS` may
  not have landed). Re-stamp `last_seen_ns`, record the new epoch,
  re-bucket; fires once per activation, then the entry ages normally.
  `first_held_ns` is left UNTOUCHED so a flapping RG cannot reset the leak
  ceiling.
- **HOLD** — this node does NOT forward the entry (standby / demotion
  window) and it is peer-synced or this node forwards something
  (`peer_synced || node_active`, the "in a cluster" guard that excludes a
  standalone node). Held unless held past the stale-synced ceiling.
- **AGE** — normal removal: active-node-owned, standalone, fabric-ingress,
  or a held entry past the ceiling.

The HOLD keys on FORWARDING, not origin, so a still-`ForwardFlow`
demotion-window entry (the demote flip not yet applied) is held too.
`owner_rg_id <= 0` (fabric / unresolved-owner reverse) uses the
node-level `rg_epochs[0]` activation edge so the self-heal fires for
those entries.

`seen_rg_epoch` changes ONLY on install/refresh (→ 0) and SELF-HEAL
(→ current epoch). The HOLD branch does **not** stamp it. This is
load-bearing: the worker reads the HA map and `rg_epochs` as two separate
loads, so a HOLD can observe an OLD (inactive) map with a NEW (already
bumped) epoch. If HOLD stamped that new epoch, the next pass — which sees
the new ACTIVE map with the same epoch — would find
`current_epoch == seen_rg_epoch` and SKIP the self-heal, aging the synced
session. Leaving `seen_rg_epoch` at its install/refresh value guarantees
the first forwarding pass after any epoch-bumping activation fires the
self-heal; the self-heal arm then records the epoch, so it does not
re-fire perpetually.

The **stale-synced ceiling** is
`min(STALE_SYNCED_CEILING_MULT × expires_after_ns,
STALE_SYNCED_CEILING_ABS_NS)` (MULT = 3, ABS ≈ 7 days), measured from
`first_held_ns` (when the entry FIRST entered the held state). It bounds
the lost-primary-delete leak: a held entry whose Close delta AND journal
entry were both lost is reaped without a primary delete. RELATIVE so a
live long-`inactivity-timeout` session is never reaped on the standby
before failover; ABS-capped to bound the pathological `MaxDurationSeconds`
config; `first_held_ns`-based so self-heal re-stamps on a flapping RG
cannot reset the clock.

The command-landed `RefreshOwnerRGS` activation scan
(`afxdp/session_glue/commands/refresh_owner_rgs.rs::handle_refresh_owner_rgs`)
enforces the same invariant from the write side: `refresh_for_ha_transition`
(which clears `first_held_ns` / `seen_rg_epoch` and re-stamps `last_seen_ns`)
runs ONLY for a session whose refreshed disposition is forwarding
(`!= HAInactive`), mirroring the demote path. Activating one RG therefore never
resets the HOLD clock of an unrelated split-RG session that re-resolves to
`HAInactive` (#5152).

The HA-forwarding predicate (`HAGroupRuntime::is_forwarding_active`, which
includes the watchdog lease and so fails CLOSED — a node that lost cluster
state reads inactive → holds) lives on the `afxdp` side and is handed in
as `ExpireHaContext` closures (`forwards_rg`, `epoch_of`, `node_active`)
so the afxdp-private HA types never leak into `crate::session`. The
context is built in `afxdp/worker/loop_body/mod.rs` right before the
expire call.

The self-heal edge is made airtight by the **epoch-before-publish
ordering** in `afxdp/ha/state.rs::update_ha_state`: `rg_epochs` for every
activated/demoted RG (and the node-level `rg_epochs[0]` on any activation)
is bumped BEFORE `rg_runtime.store`, so a worker that observes the active
`rg_runtime` always observes the bumped epoch (never new-rg + old-epoch).

`WheelPopStats` exposes `held_standby`, `reaped_stale_synced`,
`healed_on_promote`, and `aged_owner_rg_zero_active_node` (the last makes
the known active/active `owner_rg_id == 0` under-retention residual
observable — a `==0` entry for a standby RG path on an otherwise-active
node ages and is re-derived on promotion via the reverse-synced prewarm).

## "Current sessions" gauge accounting (#2428)

The `session_creates` / `session_expires` BindingLiveState counters feed
the Go-side `show security flow statistics` "Current sessions" gauge,
which Go derives as `dataplane.CurrentSessions(session_creates,
session_expires)` — a **local-forwarding** gauge.

`SessionOrigin` has **8 variants**. `session_creates` is incremented ONLY
on the four local poll-descriptor install paths —
`SessionOrigin::{ForwardFlow, ReverseFlow, LocalMiss, MissingNeighborSeed}`.
The other four are **synced-derived and never create-counted**:

- `SyncImport` / `SharedMaterialize` / `WorkerLocalImport` — installed via
  the HA sync path (`upsert_synced_with_origin` /
  `WorkerCommand::UpsertLocal`);
- `SharedPromote` — a re-tag of an already-synced (uncounted) entry by
  `maybe_promote_synced_session` (`session_glue/promote.rs`), whose
  `promote_synced_with_origin` install does NOT touch `session_creates`.
  Note `is_peer_synced()` returns **false** for `SharedPromote`, so it must
  be excluded by name, not via `is_peer_synced()`. `shared_ops.rs` already
  groups `SharedPromote` with the peer-synced set for the wire-alias
  contract — this counter is consistent with that.

The expire pass therefore must count **only the four create-counted
locals** in `session_expires`, otherwise a node that reaps synced or
promoted sessions (the standby always; any node post-failover for
`SharedPromote`) drives `session_expires` past `session_creates`, wrapping
the unsigned Go subtraction to ~1.8e19. `worker_loop`'s
`count_local_session_expiries` does this with an **exhaustive `match` (no
wildcard)** over all 8 variants — so a future 9th variant forces a
compile-time decision instead of silently defaulting to "counted" — before
the `fetch_add`. The standby thus reports `Current sessions: 0`. The
Go-side `CurrentSessions` saturating floor (clamp at 0) is the
defense-in-depth backstop against any future imbalance.

### Metric-semantics note (#2428)

`session_expires` is the SAME counter the Go control plane reads as
`dataplane.GlobalCtrSessionsClosed` (mapped 1:1 from `cur.sessionExpires`
in `pkg/dataplane/userspace/manager_counters.go`). That global counter feeds the
exported `sessions_closed` surfaces — `pkg/api/stats.go`,
`pkg/api/metrics_counters.go` (`xpf_sessions_closed_total` Prometheus
metric), and `pkg/grpcapi/server_show_status.go`. So after this fix
`sessions_closed` (like `sessions_created`) means **LOCAL sessions
closed** — it excludes peer-synced / promoted reaps, matching
`sessions_created` which never counted those installs. This is a
deliberate semantics tightening, not a regression: the two counters are
now consistently local-only, so their difference (the "Current sessions"
gauge) is a coherent local-forwarding metric on every node.

## Corruption contract (#1855)

A `key_to_handle` mapping that points at a vacant or reused slab slot is
impossible-by-construction: installs pair the map insert with a freshly
allocated slab handle, and every removal funnels through `remove_entry`'s
#964 eager-cleanup (map remove first, all secondary indices value-guarded,
`no_index_points_at` debug scan before the slot is freed). The guard arms
in `update_session`, `refresh_for_ha_transition`, and `remove_entry`
therefore follow one contract:

- **debug builds**: `debug_assert!` fires — a loud logic-bug detector
  (the `*_asserts_in_debug` tests in `tests.rs` document each arm);
- **release builds**: tolerate and return `false`/`None` without touching
  the session occupying the reused slot (the
  `*_returns_false_no_panic` tests, compiled only under
  `cfg(not(debug_assertions))`, run via `cargo test --release`).

No counter/log on these arms: they are unreachable absent a logic bug,
and `update_session` is the per-packet refresh path (an unthrottled log
would flood under a real bug). Decision record:
`docs/research/1855-inplace-contract/plan.md`.

## Admission / transaction boundary (#1861)

`install_with_protocol_with_origin` refuses an install when
`len() >= max_sessions` (131,072 per worker table) — the ONLY install
failure mode. The new-flow path in `poll_descriptor` installs a
forward+reverse pair, and pre-#1861 the two halves were independent:
at cap, a refused forward still forwarded (and flow-cached) the trigger
packet on a rolled-back SNAT decision, and a refused reverse left a
one-sided forward session.

The transaction boundary is a preflight: `can_admit(needed)` checks
capacity for the whole install group BEFORE the first install. Because
the table is single-writer (`&mut`, worker thread; GC and worker
commands run between poll phases, never mid-descriptor), a passing
preflight makes the subsequent installs infallible — no reservation or
rollback machinery is needed. `can_admit` is deliberately conservative:
it charges a full slot per entry even when the key already exists,
matching the install's own cap check (which also refuses replacements
at cap), so the preflight can never pass where the install would fail.
On refusal the caller drops the trigger packet (Junos parity), rolls
back the SNAT allocation, and counts via `note_admission_refused`.

Counters (all plain worker-owned u64s like `create_drops`, exported
since #1861 via the worker-runtime status path as
`xpf_userspace[_worker]_session_*_total`):

- `create_drops` — at-cap refusals from the install itself (repair,
  seed, fabric-return, LocalMiss sites);
- `admission_refused` — preflight refusals (one per refused flow);
- `install_partial` — post-preflight residuals, expected 0 forever
  (the call sites pair the count with `debug_assert!` per the #1855
  contract above).

#### By-key lookup misses (#7919)

`record_by_key` / `record_by_key_mut` are the resolvers behind
`touch_if_stale` and `account_packet`, and both bail **silently** on a
miss. A flow whose key does not resolve is therefore neither accounted
nor keepalive-touched, and nothing says so — which is the measured shape
of #7919: `show security flow session` reporting `Pkts: 0, Bytes: 0` for
a live transit flow while a sibling flow on the same box accounts
perfectly, every frozen row carrying `idle ≈ age` because `last_seen`
never moved either.

Three `AtomicU64` counters (atomic, unlike their plain-`u64` siblings,
because `record_by_key` takes `&self`) split the miss by cause, exported
per worker as `session_lookup_miss_{no_handle,stale_handle,key_mismatch}`:

- `no_handle` — no handle in the key index. The session was never
  installed under this key, or was removed.
- `stale_handle` — a handle resolved but pointed past the slab: a handle
  outliving its record.
- `key_mismatch` — a handle resolved to a LIVE record whose stored key
  differs. The index and the record disagree, so the lookup finds a
  session and correctly refuses to account against it.

They are split, and exported **per worker**, because #7919 is
per-session rather than global — one of three concurrent flows accounted
correctly on the measured box, so any explanation predicting uniform
behaviour is already wrong, and a process-wide total cannot separate
"one worker misses everything" from "every worker misses occasionally".

The counters are instrumentation, not a fix: they exist to settle WHICH
of the three stories holds before anyone changes a disposition.

Decision record: `docs/research/1861-install-txn/plan.md`.

### UpsertLocal is in the uncapped sync family (#1870)

`upsert_synced_with_origin` has NO cap check (the #1861 plan's row
I11): HA sync, replica fan-out, and reactive shared-hit
materialization all install past `max_sessions` by design. Since
#1870 the local-tunnel prewarm (`WorkerCommand::UpsertLocal`,
`session_glue`) joins that family with `allow_replace_local=true` —
the entries are coordinator-authoritative `SyncImport` replicas of
state already published to the shared maps, and the capped install
previously refused the worker-table copy at cap while the reactive
materializer reinstalled the reverse entry uncapped on the next reply
packet anyway (futile cap; polluted `create_drops`; cap-1 partial
pairs). Consequently `create_drops` no longer counts `UpsertLocal`
installs — they cannot fail. The future cap arbitration for the sync
family (row I11) now covers `UpsertLocal` automatically. Decision
record: `docs/research/1870-local-tunnel-pair/plan.md`.

### Sync-family aggregate ceiling at the coordinator (#5674)

`upsert_synced_with_origin` stays uncapped (the infallibility contract
above), but the sync family is no longer *unbounded*: the row-I11 cap
arbitration is now enforced ONE level up, at the coordinator's peer-sync
entry point (`Coordinator::upsert_synced_session`,
`afxdp/ha/session_import.rs`). Before #5674 a peer-synced session was
published to the shared `synced` map and fanned out to EVERY worker
command queue+table with no cap, so a peer under session-table pressure
— or a malicious/compromised peer — could drive this node past its own
aggregate session ceiling and multiply that state across all workers (an
availability/DoS the per-worker `install_with_protocol_with_origin` cap
is meant to prevent). `upsert_synced_session` now bounds the shared
`synced` map (the single fan-out choke point) at this appliance's OWN
aggregate **ENTRY** ceiling — `2 * worker_count * DEFAULT_MAX_SESSIONS`
(`synced_import_cap()`) — and **drop-newest**-rejects a NEW over-ceiling
FORWARD key: it bumps `SessionManager::import_cap_drops`
(`Coordinator::synced_import_cap_drops_total()`, Prometheus
`xpf_userspace_synced_import_cap_drops_total`) and returns BEFORE the
publish + fan-out, so a rejected import is never enqueued to any worker
(the queue-multiplication is bounded too).

The 2× is load-bearing, and this is the crux of the cap's correctness.
Each admitted **forward** logical session publishes TWO keys into the
`synced` map — the forward key and a **synthesized reverse companion**
(`synthesized_synced_reverse_entry` returns `Some` for every non-reverse
import; `upsert_synced_session` publishes both via
`publish_shared_session`). So `K` admitted forwards occupy `2K` entries.
With the entry cap at `2N` (`N` = the appliance's logical ceiling), a new
forward is rejected exactly when `2K >= 2N ⇔ K >= N`: a full
symmetric-peer set (`N` logical sessions → `2N` entries) EXACTLY fits and
only a peer EXCEEDING its OWN logical ceiling is rejected. Sizing the cap
to the LOGICAL ceiling `N` while counting ENTRIES (the pre-#6172-review
bug) rejected ~half of a legitimate full-peer import above ~50% peer load
— a 2× shortfall THROUGHOUT normal operation, not the "±1 session-pair
overshoot on the last admit" the earlier framing claimed; on failover the
under-synced flows had no state and TCP broke (the session-miss guard
drops the non-SYN first packet).

The gate keys only on FORWARD new keys (`!entry.metadata.is_reverse`): a
synthesized reverse always rides with its forward (a rejected forward
returns BEFORE publishing its reverse, so no half-sync), and a lone
reverse import is never independently rejected at a boundary slot.

**The "+1 orphan" corner is closed (#8015).** Because the gate is
forward-only, a lone `is_reverse=1` import used to skip it and publish as
a bounded orphan with no matching forward whenever the map was AT the 2N
cap and its own forward was cap-rejected. #6413 assessed that as
self-inflicted, bounded by the local session rate and low-harm — which it
was, since the orphan's tuple and decision were the FORWARD's own, so it
admitted the reply direction of a flow this node had itself just
adjudicated, not any unsolicited inbound flow. What made it worth
removing rather than documenting is that it could OUTLIVE its forward:
`delete_synced_session_gen` derives the companion to remove from the
STORED forward, and after a refusal there is no stored forward, so a
later delete of that forward removed nothing and the reverse survived
until `reap_expired_sessions` idled it out.

#8015 removes it at both ends. The only sender was Go's
`mirrorSessionPairV4`/`V6` explicit companion pre-install (#310), which
is deleted — the mirror sends the forward alone and this function
synthesizes the companion, earlier and against live node-local state —
and `upsert_synced_session` now REFUSES an entry that arrives already
flagged `is_reverse`, returning
`SyncedImportOutcome::RejectedStandaloneReverse` (wire token
`synced-import-refused:standalone-reverse`) before any other decision. A
reverse entry is DERIVED state and can never be standalone authority.
The peer path never produced one in the first place: Go's
`SetClusterSyncedSessionV4`/`V6` early-return on
`!shouldMirrorUserspaceSession(val.IsReverse)` and write ONLY the BPF
mirror, so only FORWARD peer imports transit the helper. Pinned by
`upsert_synced_session_refuses_standalone_reverse_8015`
(`afxdp/ha_tests.rs`), whose control leg re-measures the
forward-only-leaves-two-entries fact the cap's 2x sizing depends on.

The refusal carries no counter of its own, deliberately: with the sender
deleted and the peer path excluded, no shipped daemon can produce the
condition, and a metric that can only read zero says nothing. The typed
outcome already reaches the caller through the control response.

A REPLACE of an existing
synced key is always allowed (it does not grow the map) so an in-flight
synced session keeps refreshing; an existing entry is never evicted to
make room. One documented residual: on an ASYMMETRIC pair (peer has MORE
workers than this node — unusual; xpf pairs are symmetric) the peer's
aggregate ceiling can exceed this node's `2N`, so a legitimate
over-ceiling import would be dropped. The uncapped
`upsert_synced_with_origin` and the local `UpsertLocal` / shared-hit
materialization paths are unchanged — they are locally bounded and do
not carry the peer-DoS vector. Pinned by
`upsert_synced_session_rejects_over_ceiling_import_and_does_not_fan_out`
(`afxdp/ha_tests.rs`), which asserts a full symmetric-peer logical set
all-admits with zero drops (the regression) and that the next
over-logical-ceiling forward is rejected + not fanned out.

### HA install-generation guard on SyncedSessionEntry (#2170)

`SyncedSessionEntry` (`afxdp/worker/mod.rs`) carries a `generation: u64`
mirrored from the Go cluster apply layer via `SessionSyncRequest.generation`.
Only peer `SyncImport` entries carry a meaningful (non-zero) generation;
local-origin entries (forward/reverse learn, tunnel decap, promote,
missing-neighbor seed) leave it 0. The synthesized reverse companion inherits
the forward entry's generation so a delete refusal is consistent across both
halves.

`upsert_synced_session` (`afxdp/ha/session_import.rs`) refuses a strictly-older-generation
install (both generations non-zero) so the helper's stored generation never
regresses (`SessionManager::install_stale_ignored`), mirroring the Go install
guard. `delete_synced_session_gen(key, delete_gen)` refuses a
strictly-older-generation delete (`SessionManager::delete_stale_ignored`); the
plain `delete_synced_session(key)`
wrapper passes `delete_gen = 0` so helper-local purges (tunnel-remap, GC) stay
unconditional. These helper-side guards are **belt-and-suspenders** — the
authoritative guard lives in the Go cluster apply layer (`deleteClusterSynced*`),
which short-circuits both the BPF map delete and the helper. The counters are
surfaced via `Coordinator::session_install_stale_ignored_total()` /
`session_delete_stale_ignored_total()`. See `docs/sync-protocol.md` and
`docs/research/2170-ha-deferred-delete/plan.md`.

All three sync-import refusal counters (`install_stale_ignored`,
`delete_stale_ignored`, `import_cap_drops`) are **per-`Coordinator` fields on
`SessionManager`**, not process-global statics. Production builds exactly one
`Coordinator`, so the **exported Prometheus value (`import_cap_drops`) is
unchanged; the other two have no surface outside this binary** — their
accessors are reachable only from `ha_tests.rs`. Only `import_cap_drops`
travels the wire, via `server/helpers/status.rs` →
`protocol::control::…synced_import_cap_drops_total` → the Go status struct →
`xpf_userspace_synced_import_cap_drops_total`. None of the three appears in
`proto/`; this crate has no gRPC dependency.

The distinction that matters is therefore purely a test one: the suite builds
one `Coordinator` per `#[test]` and runs them concurrently in a single
process. As globals, a test asserting on these counters was measuring every
*other* test's stale-install/stale-delete/over-ceiling refusals as well as its
own (#6819). Keep new refusal counters on `SessionManager` for the same reason
— a delta capture (`let before = ...; assert_eq!(..., before + 1)`) does
**not** make a process-global safe, because a concurrent test's increment lands
inside the capture window.

**That mechanism is measured, and the sanctioned gate cannot see it.** Reverting
`import_cap_drops` to a static reds 24 of 60 parallel runs and 0 of 12 runs
under `--test-threads=1`; reverting both stale counters reds 43 of 60 parallel
and 0 of 5 single-threaded.

The strongest evidence is independent of this change and predates it. While
gating an unrelated PR (#6843), a lane measured parallel
`cargo test -- afxdp::ha` over 40 iterations and found **34 of 40 runs failing
at that PR's HEAD — and 34 of 40 at a `origin/master` CONTROL** with the PR's
own files reverted and its tests confirmed absent. Identical rate with and
without the change under review, which is what identifies the flake as
pre-existing and environmental to these counters rather than caused by any one
PR. It root-caused the failures to exactly `SESSION_INSTALL_STALE_IGNORED` /
`SESSION_DELETE_STALE_IGNORED` being process-global and asserted with
`assert_eq!(total, before)`, so *any* concurrently-running test that refuses a
stale op reds them — and observed it as a whole family
(`stale_generation_install_refused_…`, `stale_generation_delete_refused_…`,
`over_ceiling_import_rejected_…`), not a single test. Those are the counters
this section is about.

`make test-rust` pins `-- --test-threads=1` (to dodge
an unrelated socket-test wedge in `__skb_wait_for_more_packets`, #6657), so a
regression of this property would ship **green** through the gate. Note the
coupling: the flag that hides this defect exists because of a *different* one.
Delta-capture assertions cannot close that hole — under serial execution a
process-global satisfies `before + 1` identically. The binding test is
`refusal_counters_are_per_coordinator_not_process_global`, which asserts one
`Coordinator`'s refusals are invisible to a second live instance and so reds at
any thread count. Any new refusal counter needs an equivalent, or it is
unguarded no matter how many delta assertions surround it.

### Per-policy log flags on the session-sync wire (#2785)

A locally-admitted session stamps the admitting policy's `then log
session-init`/`session-close` selection onto `SessionMetadata.log_session_init`
/`log_session_close` (the #2508 path). Before #2785 the HA sync-import path
hard-coded both flags `false`, so a session that failed over to the standby
emitted no per-policy RT_FLOW SESSION_CREATE/CLOSE syslog records on the new
active node.

#2785 carries the selection across the full sync path:

1. **Open frame** (`event_stream/codec.rs`): `FLAG_LOG_SESSION_INIT` (1<<3) /
   `FLAG_LOG_SESSION_CLOSE` (1<<4) on the existing flags byte, encoded from
   `metadata.log_session_init/close`.
2. **Go control plane**: decoded into `SessionDeltaInfo`, stamped onto
   `dataplane.SessionValue.LogFlags` (`LogFlagSessionInit`/`Close`, bits 0/1),
   which already rides the cluster wire (`pkg/cluster/sync_protocol.go`).
3. **Install**: `SessionSyncRequest.log_session_init/close` ->
   `build_synced_session_entry` -> the synced session's metadata.

`serde(default)`/`omitempty` make this rolling-upgrade safe: an old peer that
omits the fields decodes to `false` (no per-policy log) — bit-identical to
pre-#2785 behavior. The JSON RPC-fallback delta (`SessionDeltaInfo` in
`protocol/binding.rs`) carries the same fields at parity with the binary frame.

### Policy attribution is single-sourced across both session-delta legs (#6949)

A session delta leaves the helper on two wires, and both must describe the same
session identically:

* the BINARY `MSG_SESSION_OPEN` frame (`event_stream::codec::encode_session_open`)
  — the primary HA path; and
* the JSON RPC-fallback `SessionDeltaInfo` (`afxdp::session_delta_info`) — what
  `drain_session_deltas` puts on the control-plane RPC every 100 ms while the
  binary stream is down, every 5 s while it is up, and what every
  helper-requested FullResync exports through `ExportOwnerRGSessions`.

Until #6949 they had diverged on five fields. The binary frame carried
`policy_id` (#3056/#3301), `policy_counter_idx` (#3073), the per-application
inactivity timeout (#3227, ns→s), the `FLAG_NAT64` marker and the NAT64
`snat_v4` pool source (#4565). The JSON leg carried **none** of them, while the
Go consumer read all five unconditionally — so every session learned through
that leg imported policy 0, counter 0, the global idle timeout and no pool
source. It rendered `unattributed`, was skipped by the commit-time
deletion-clear and the #4234 policy-rematch (both exclude id 0), accrued no
per-rule hit count after a promotion, and — the one that is not a
mis-attribution — a NAT64 session could not rebuild its reverse v4→v6 BIB,
because `snat_v4` is chosen by `allocate_source` and is not derivable from the
synced forward v6 key. Worse, each reconciliation copy carries a fresh #2170
install generation, so a later JSON copy could OVERWRITE an earlier, correct,
event-derived copy on the peer.

It stayed invisible for four releases because a rendered `policy_id` of 0 shows
as `unattributed` (#6851) — identical to a session no policy admitted.

A divergence between the two producers is ALWAYS a bug (they describe one
session for one peer), so the derivation is **single-sourced** in
`session::SessionSyncAttribution::from_session` (`session/sync_attribution.rs`)
rather than written twice and held in agreement by a test. That helper also owns
the two non-trivial conversions — the saturating ns→s timeout and the
`(nat64, rewrite_src)` pool-source selection — which would otherwise have been a
second divergence waiting to happen. Both producers destructure it
EXHAUSTIVELY (no `..`), so a new field carried by only one leg does not compile;
`sync_attribution_exhaustive_destructure_6949` pins the absence of `..`, and
`session_delta_json_and_binary_agree_on_policy_attribution_6949` asserts the two
legs AGREE on one session rather than pinning either side to a literal.

`serde(default)` / `omitempty` keep it rolling-upgrade safe in both directions:
an old helper omits the keys and they decode to 0/""/false — precisely the
pre-#6949 behaviour of this leg — and an old daemon ignores keys it does not
know. Making that parity DURABLE across a mixed-version cluster (fail-closed
capability negotiation, and the canonical-schema equivalence test that would
have caught this whole class) is tracked separately as #7194.

### True ingress-interface identity on the session (#4983)

A session records the interface its FIRST packet arrived on. At install
`afxdp/poll_descriptor` stamps `SessionMetadata::ingress_ifindex` and
`ingress_vlan_id` from the frame's `UserspaceDpMeta` — the binding the packet
was actually received on plus its 802.1Q tag. For the sessions that ARE
mirrored to the kernel-visible conntrack map (see the next paragraph),
`afxdp/bpf_map/publish_conntrack` copies both into the conntrack value
(`session_value.ingress_ifindex` / `ingress_vlan_id`), where the Go control
plane reads them as `dataplane.SessionValue.IngressIfindex` /
`IngressVlanID`.

**Which sessions this is OPERATOR-VISIBLE for (#6965).** The stamp above is on
the helper's in-memory `SessionEntry`, and that is a different question from
what `show security flow session` can see. That command enumerates the BPF
conntrack map (`pkg/dataplane/maps_session.go`'s `Manager.IterateSessions`
over `m.maps["sessions"]`), and inside the HELPER **four** install sites write
it: `publish_bpf_conntrack_entry`'s callers in `afxdp/poll_descriptor` — the
TRANSIT forward install (#6965), the host-inbound `LocalMiss` install, the
`MissingNeighborSeed` install, and the reverse-companion repair on the
session-hit path (that fourth row is `is_reverse != 0`, which every
`show`/`clear` call site skips before filtering, so it never surfaces a flow on
its own).

**The transit site is #6965 and it is the one that matters for volume.** Until
it existed the mirror carried only the host-inbound and neighbor-seed
populations, so for the DOMINANT population — ordinary transit flows — `show
security flow session` showed nothing at all. Not a row with a zeroed identity:
no row. #6656 records the shape that produced, a node carrying 4.6M rx packets
while showing 33 sessions.

"Inside the helper" is load-bearing, because the map has a writer OUTSIDE it
(#6928 review). Every HA peer-synced row reaches the same `sessions` /
`sessions_v6` map from the GO side:
`Manager.SetClusterSyncedSessionV4`/`V6` (`pkg/dataplane/userspace/manager_sessions.go`)
call `bpfShim.SetSessionV4`/`V6`, which is `maps_session.go`'s
`m.maps["sessions"].Update`. That is the "for peer-synced sessions the Go side
installs directly" case named below; the four-site count is a claim about the
Rust helper's publication sites, never about the map's writers.

The transit forward install publishes the mirror row IN ADDITION to the shim's
steering table, not instead of it. The two are different maps and always were:
`publish_live_session_entry` writes `session_map_fd`, a 40-byte key with a
one-byte action value, and the mirror carries the 144-byte conntrack value.
`publish_shared_session` for the shared/HA maps is unchanged.

FORWARD ONLY, deliberately. The reverse companion installed in the same arm
gets no mirror row: every `show`/`clear` call site skips `IsReverse != 0`
before filtering, so a reverse row would cost a `bpf_map_update_elem` per
connection for something that can never surface a flow, and the forward row
already carries BOTH directions' counters (#2501). Pinned by
`transit_reverse_companion_gets_no_conntrack_row_6965`.

So the identity is stamped on every forward session installed from a RECEIVED
FRAME — the three frame-driven install sites, the only ones with an observed
binding to copy. (The two forward installs that carry `0`, host-outbound GRE
and the HA peer import, are not exceptions: neither has an observed local
ingress. Both are enumerated under "`0` means no ingress identity carried"
below.) Since #6965 the identity reaches the operator
surface for the TRANSIT population too, alongside the host-inbound and
missing-neighbor-seed ones and the peer-synced sessions the Go side installs
directly. Before it, transit sessions were absent from that map entirely — not
carrying a zeroed identity, but having no row at all — so `show`/`clear ...
interface <name>` could not select them either way. That gap dated to
`fab9230c5`, the commit that first added the conntrack mirror and wired only
three sites; #4983 neither introduced nor widened it.

What the mirror carries is the {PARENT ifindex, VLAN} PAIR, not a pre-resolved
logical unit — the Go side resolves the pair through the same map the egress
side uses. Both halves are pinned end to end:
`poll_descriptor_transit_install_stamps_ingress_binding_4983` on the in-memory
entry and `transit_forward_install_publishes_a_conntrack_row_6965` on the
mirrored row.

Before this the session carried only its ingress ZONE, so
`show security flow session interface <name>` and the matching `clear` had to
ask "is `<name>` bound to the session's ingress zone?". A session on interface
X therefore matched a filter for EVERY sibling interface Y of that zone.
(#4792 widened the CLI's zone map from one interface to all of them, which is
as precise as a zone-derived answer can be; this is the datum that makes it
exact.) `pkg/cli/session_filter.go`'s `resolveIngressIfaces` now resolves the
recorded pair through the very same `{parent ifindex, VLAN}` map the EGRESS
side already uses (`buildSessionEgressIfaces`), so one map defines one
interface identity for both directions and two units of a single trunk NIC —
`reth0.50` vs `reth0.80` — do not alias onto the parent. The `In: ... If:`
column of the detailed `show` output is resolved from the same identity
(`sessionIngressIf` in `pkg/cli/cli_show_flow.go`).

**What that buys, stated at the width it actually holds.** A previous revision
said the filter and the displayed name therefore "cannot disagree" for a
non-zero nameable identity. That is false, and no fallback is needed to break
it. `matchesV4`/`matchesV6` are a DISJUNCTION over two arms —
`!ifaceMatchesAny(inIfs) && !ifaceMatchesAny(outIfs)` in
`pkg/cli/session_filter.go` — while the `If:` column renders the INGRESS side
alone. A session that arrives on `A` and egresses on `B`, both stamped and both
nameable, is selected by `interface B` through the EGRESS arm and prints
`If: A`. Filter term and column differ with no zero identity and no fallback
anywhere in the derivation. That is the same account
`pkg/cli/cli_show_flow.go:307-315` derives at the print site, and this sentence
used to contradict it.

The property that DOES hold is narrower: when a row is selected BY ITS INGRESS
ARM and carries a non-zero nameable identity, the column names the interface
that was typed — because the arm and the column read the SAME stamped pair
through the SAME `{ifindex, VLAN}` map. Both halves are pinned by
`TestInterfaceFilterEgressArmMakesColumnNameAnotherInterface6928`
(`pkg/cli/cli_show_flow_ingress_if_4983_test.go`), whose two sub-tests assert
the egress-arm disagreement and the ingress-arm agreement against the real
`showFlowSession`.

For a ZERO or unresolvable identity the ingress arm and the column still degrade
differently, but no longer in a way that lets the column NAME an interface the
filter would not select. The FILTER falls back to every interface bound to the
zone (`resolveIngressIfaces`); the COLUMN falls back to that zone's interface
only when the zone binds exactly ONE, and otherwise prints the zone NAME
(`ingressIfaceDisplay`). So a zero-identity row in zone `[A, B]` is selected by
`interface A` and by `interface B`, and prints `If: <zone>` — not `If: A`.

**#6987 changed this.** Until then DISPLAY built its own
`map[uint16]string` holding each zone's FIRST interface, kept deliberately
separate from the filter's widened `map[uint16][]string`:

| side | map | built from | fallback yielded |
|---|---|---|---|
| FILTER (`session_filter.go`, `populateIfaceMaps`) | `map[uint16][]string` | `append(zoneIfaces[zid], zone.Interfaces...)` | EVERY bound interface |
| DISPLAY (`cli_show_flow.go`, retired) | `map[uint16]string` | `zone.Interfaces[0]` | the FIRST one, else the zone name |

A zero-identity row in zone `[A, B]` therefore printed `If: A` as though A were
the session's own interface. There is now ONE map (`populateIfaceMaps`) and one
rule; the column declines to pick a member where the row cannot support the
choice. The never-blank property is preserved — the column prints the zone name
instead — which is what keeps the peer-synced and reverse-direction populations
(§ "`0` means no ingress identity carried" below) visible in the output while
they remain selectable through the zone.

The column also declines when the identity RESOLVES but the row's own recorded
ingress zone does not bind the resulting interface. That is what a recycled
kernel ifindex looks like from the query side, and it is the one case where a
confident name is likeliest to be the wrong one — so it prints the zone even
where the zone binds exactly one interface.

Two consequences beyond the `[A, B]` example above. A zone binding NO interface
gives the filter an empty slice, so `ifaceMatchesAny` is false on the INGRESS
arm, while the column prints the zone name — which is not an interface name and
cannot be typed back into the filter.

That is a lost route in, not an unreachable row, and an earlier revision said
otherwise (#6928): "no interface filter selects that row at all" is refuted by
the code as written, with no edit required. `matchesV4`/`matchesV6` reject only
when BOTH arms miss, so a session whose ingress zone binds nothing is still
selected by the name of the interface it EGRESSES on whenever the FIB identity
is nameable — or, failing that, by any interface bound to its EGRESS zone.
`TestInterfaceFilterReachesRowViaEgressArm6928` constructs exactly that row
(ingress zone `quarantine`, which binds nothing, ingress identity 0, egress
`lo.80`) and shows `show security flow session interface lo.80` selecting it,
with a negative control that an interface neither arm can name selects nothing.
A row is invisible to every interface filter only when BOTH arms come up
empty — no nameable egress identity AND an egress zone that binds no
interface, on top of the ingress side already being empty. And the
`TestShowFlowSessionIngressIfColumnFallsBackWhenIdentityUnusable4983`
(`pkg/cli/cli_show_flow_ingress_if_4983_test.go`), which asserts exactly those
three arms; there is no corresponding test asserting the two sides agree,
because they do not.

**Which surfaces this applies to.** The consumer side landed in the IN-DAEMON
CLI first (`pkg/cli`) — the console session on `xpfd`. Two other surfaces read
the same session table and answered an `interface` filter from the ingress
ZONE, in the pre-#4792 FIRST-interface-only form, until #6960 ported the
identity to both:

- `pkg/grpcapi/server_sessions.go`, which is what the REMOTE `cli` binary uses
  for both `show security flow session interface <name>` and the matching
  `clear`, and what a console clear propagates to the HA peer over (#6975);
- `pkg/api/sessions.go`, the HTTP/REST session query.

Both now resolve the ingress interface through `resolveSessionIngressIfaces` —
the interface a CORROBORATED identity names, else EVERY interface bound to the
ingress zone. The zone reduction they used before (`zone.Interfaces[0]`) made
the ingress arm independent of the session, so `clear security flow session
interface <the zone's first interface>` DELETED every session in that zone.

"Corroborated" means the row's own recorded ingress ZONE binds the interface
the `{ifindex, VLAN}` table names. It has to be checked because that table is
rebuilt per query while the ifindex was recorded at install, so a RECYCLED
kernel ifindex can HIT and name an interface the session never arrived on. A
disagreement is a MISS: the filter feeds `clear`, and selecting on an
untrustworthy name would delete sessions that never touched the named
interface. The row stays reachable through its zone and its egress arm.

`pkg/cli` corroborates the same way since #6987, and the reported column on all
three surfaces now names the zone rather than one member standing in for its
siblings. What remains open on every surface is a recycle WITHIN one zone: the
recorded zone corroborates the new owner, so the name still passes. Separating
that from the truth needs an install-time generation carried on the session row
itself, which is a dataplane wire change (#7239). The EGRESS side is not
corroborated at all and carries the same recycle hazard (#7240).

The identity is stamped ONCE and never re-derived from the zone; re-deriving
is the approximation it exists to remove.

**Fabric ingress: the one path where the zone and the ifindex name DIFFERENT
interfaces.** A frame arriving over the fabric carries a zone-encoded override
(`poll_stages.rs`), which takes precedence over the ifindex->zone map in
`forwarding/mod.rs`, so `ingress_zone` is the ORIGINATING chassis's zone. The
identity stamp is unconditional and records the LOCAL fabric NIC the frame
physically arrived on. Neither is wrong — they answer different questions — but
an exact interface filter follows the ifindex, so the enumeration above is not
exhaustive without this case.

It is INERT in the shipped topology: the fabric member is declared only under
`fab0 { fabric-options { member-interfaces { ... } } }` with no unit
(`docs/ha-cluster-userspace.conf`), and `buildSessionEgressIfaces` keys on
`{parent ifindex, unit VLAN}` — a unit-less interface produces no entry, so the
lookup misses and the CLI falls back to the zone exactly as before. Give that
member a unit and the behaviour changes: on node B,
`show security flow session interface reth0.50` would stop matching a
cross-chassis flow it used to reach through the wan zone, and the matching
`clear` would leave it behind. No test or smoke covers this because the path is
unreachable from the shipped config, not merely uncovered.

**`0` means "no ingress identity carried" and is never a valid ifindex.** These
populations legitimately carry `0`, and the CLI falls back to the zone
approximation for all of them — never "matches nothing" (which would hide them
from `show`/`clear`), never "matches everything":

1. the REVERSE companion (`poll_descriptor` reverse install, `shared_ops`
   synthesized companion) — its own ingress has not been OBSERVED yet. The
   forward flow's egress IS resolved at install (`resolution.egress_ifindex`),
   so availability is not the reason: it is a PREDICTION of where the reply
   will arrive rather than an observation of where it did, and routing may be
   asymmetric, so there is nothing truthful to stamp. Note the CLI fallback is
   INERT for this one: every `show`/`clear` call site skips `IsReverse != 0`
   rows before reaching the filter, so a reverse entry is never
   interface-matched at all;
2. a PEER-SYNCED session (`server/helpers/session_sync.rs`) — an ifindex is
   NODE-LOCAL, so node 0's `ge-0-0-1` and node 1's `ge-7-0-1` are different
   numbers for the same logical RETH member. The identity is deliberately NOT
   carried across the cluster wire: shipping the peer's number would render a
   confidently WRONG interface name locally, strictly worse than approximating;
3. the HOST-OUTBOUND GRE encapsulation path (`afxdp/tunnel.rs`,
   `build_local_origin_tunnel_tx_request`) — firewall-self-originated traffic
   read off the TUN device. There is no ingress binding to record: its
   `UserspaceDpMeta` is synthesized from the raw packet, so `0` here is the
   correct answer, not a gap;
4. the flow-cache descriptor seed (`afxdp/flow_cache.rs`) — replay state for an
   already-installed session, never published as a session itself.

There is deliberately no "installed by a pre-#4983 helper" population. It looks
like one, but the ABI note below rules it out: `sessions` / `sessions_v6` are in
the pre-flight's ABI-checked set (`userspaceABICheckedPinnedMaps`, which unions
`userspaceShimSharedMapSpecs`), and `validateUserspaceShimLivePins` hard-refuses
a `ValueSize` mismatch against the live pin — so a new daemon never comes up
against an old helper's 136/184-byte map. Every recovery path leaves the old pin
GONE before the next load, so the map the new daemon reads is freshly created and
EMPTY.

Do NOT call that recovery "a reload" (this sentence did until #6928). A reload
never releases a pin at all — a bpffs pin outlives the process that made it. The
accurate, mode-dependent form is the one in `pkg/dataplane/types.go`: the
targeted recovery is to unlink the ONE named pin
(`docs/operations/userspace-shim-pin-recovery.md`); whether a plain restart is
enough DEPENDS on how xpfd last stopped, because a HITLESS shutdown
(`Manager.Close`) preserves the pins on purpose and hits the same refusal, while
a NON-hitless HA shutdown calls `Manager.Teardown` — which `os.RemoveAll`s the
pin path — so there a restart already suffices. The conclusion is unaffected in
every one of those modes: either the old pin is gone and the new map is empty, or
the pre-flight refuses and the new daemon does not read the map at all. There is
no path on which old-format rows reach a new reader. A row written in the old
format can therefore never be read by a new reader; the mixed state the
population would describe is unreachable rather than merely rare.

The MISSING-NEIGHBOR seed (`build_missing_neighbor_session_metadata`) is NOT in
that list: it is a forward session installed when a flow's first packet races
an unresolved ARP/NDP, it is published to the conntrack map, and the
pending-neighbor retry sweep never re-installs it — so it is stamped from the
frame's `meta` exactly like the two other forward install sites. Those two are
not both policy-admitted: the transit install is, but the LocalDelivery install
also runs for a `JunosHostLocalPolicy::NoMatch` host-bound flow, admitted by the
zone's host-inbound set with no junos-host policy matching at all (#6928 review).

That leaves exactly THREE production sites that stamp the pair — the TRANSIT
forward install and the HOST-INBOUND (`LocalMiss`) install, both in
`afxdp/poll_descriptor`, plus the missing-neighbor seed. Each has its own
fail-on-revert test in `afxdp/tests_session_ingress_identity.rs`, driven
through the real `poll_binding_process_descriptor` body on a binding whose
{ifindex, VLAN} is distinct from the other two fixtures', so reverting any ONE
site to `0` reddens exactly its own test. The reverse companion's deliberate
`0` is pinned by an over-reach test in the same module.

A NON-ZERO ifindex the running config cannot name (an interface deleted since
install, a tunnel/fabric ingress with no config unit) falls back the same way.

**ABI note.** The two fields are part of the shared C conntrack struct, not the
sync-only trailing fields: `session_value` grows 136 -> 144 and
`session_value_v6` 184 -> 192 (the u32 lands on the existing 8-byte boundary
and the u16 inside the tail pad it forces, so the pair costs 8 bytes, not 16).
`sessions`/`sessions_v6` are PINNED maps, so — exactly as for the #5460 flags
widen — a rolling deploy cannot cross this: the pre-flight
(`validateUserspaceShimLivePins`) refuses while the old daemon still forwards.
The TARGETED remediation is to unlink the ONE named pin
(`docs/operations/userspace-shim-pin-recovery.md`); `xpfd cleanup` also clears
it but is far broader (every pinned dataplane map plus the FRR managed routes).
Either way there is brief downtime and the next load recreates the map at the
new size.

**#9546 is the same crossing again.** `routing_domain` was appended after
`ingress_vlan_id` (so no offset above moved), growing `session_value` 144 -> 152
and `session_value_v6` 192 -> 200. The helper stamps it for FORWARD rows only
(`publish_conntrack::conntrack_row_routing_domain`); a reverse row states
`WIRE_ABSENT`, because its key is the deliberately domain-agnostic reverse-match
key (#7160) and encoding that 0 would falsely claim the default instance. Unlike
#4983 this also bumped the snapshot protocol to 12: the helper writes this struct
and has no value-size guard of its own, so a size-mismatched daemon/helper pair
would copy past the helper's buffer into the slot a new reader trusts.

Whether a plain RESTART is enough is MODE-DEPENDENT, exactly as the paragraph
above this one says — do not restate it here as "it is NOT a restart" (#6928).
That categorical form was as wrong as the "a reload" it replaced: a HITLESS
shutdown (`Manager.Close`) preserves the pins on purpose and hits the same
refusal, but a NON-hitless HA shutdown calls `Manager.Teardown` →
`dataplane.Cleanup()`, which unpins everything, so on that path a restart
already suffices.

Two facts underneath that sentence are pinned, and one thing is NOT (#6928).
`Cleanup()` has TWO production reference sites, not one, and
`pkg/dataplane/cleanup_reachability_6928_test.go` pins that set — resolving
each reference through the file's IMPORT bindings, so an aliased
`dp.Cleanup()` counts and an unrelated `Cleanup()` in some other package does
not. Since #6743 the Teardown site is a function VALUE
(`var teardownCleanupFn = Cleanup`) that `Manager.Teardown` invokes rather
than a direct call, so the walk records it as `(value)` and
`TestTeardownInvokesTheCleanupSeam_6928` binds the part a value reference
cannot prove — that Teardown still invokes it, with a polarity control that
`Manager.Close` does not. Which shutdown arm calls which lifecycle method is pinned behaviourally
by `TestShutdownModeChoosesCloseOrTeardown6928`
(`pkg/daemon/shutdown_dataplane_mode_6928_test.go`), which drives the real
`runShutdownSequence` against a substituted dataplane.

What is NOT pinned is this paragraph's WORDING, and an earlier revision claimed
otherwise — that the caller test stopped "the categorical wording coming back
green". It does not, and the check was run rather than reasoned about: replace
the remediation with a different false sentence ("A plain restart ALWAYS
releases this pin"), and the caller graph is unchanged, the two banned literals
in `stalepin_remediation_5363_test.go` are absent, and the whole
`./pkg/dataplane/...` suite stays green. A guard that forbids two strings
constrains VOCABULARY, not the claim — no test can decide whether an arbitrary
English sentence describes the pinned facts correctly. The two literals are
kept only to stop the two specific disproven phrasings returning verbatim, and
are labelled as that where they live. Correctness of this paragraph rests on
reading it against the two tests above.

Sizes are asserted in lockstep at `afxdp/bpf_map_tests.rs` and
`pkg/dataplane/bpf_session_value_test.go`.

### Admitting policy ID on the session (#3056)

A policy-admitted session stamps the admitting policy's ID onto
`SessionMetadata.policy_id` at install (`afxdp/poll_descriptor`, both the
forward entry and its reverse companion, from `policy_result.policy_id` — the
same ID namespace the deny/screen/filter frames carry in [44:48] and the Go
control plane assigns in `pkg/dataplane/userspace/policies.go`). Before #3056
the field did not exist: the live-session BPF-compat rows and the RT_FLOW
SESSION_CREATE/CLOSE records all published policy `0`, which the Go side renders
as the FIRST configured policy (policyID 0) — a wrong attribution that broke
incident response.

The ID is consumed at three surfaces:

1. **Live-session rows** (`afxdp/bpf_map/publish_conntrack`): the v4/v6
   BPF-compat conntrack value's `policy_id` slot, which the Go `show security
   flow session` / REST / gRPC surfaces read as `val.PolicyID`.
2. **RT_FLOW SESSION_CREATE** (`event_stream/codec.rs`
   `encode_session_create_rt_flow`): the [44:48] policy_id wire slot, which the
   Go decoder reads as `PolicyID` for every non-close frame.
3. **RT_FLOW SESSION_CLOSE** (`encode_session_close_rt_flow`): the *trailing*
   [136:140] slot — NOT [44:48], which #2853 repurposed on a close for the
   created-subsec-nanos. The RT_FLOW event payload grew 136 -> 144 bytes for
   this slot (`SECURITY_EVENT_PAYLOAD_SIZE`; mirrored by `pkg/dataplane.Event`
   and `pkg/logging` `rawEventWireSize` / `binary_test.go`); #2749 later grew it
   again 144 -> 152 for the class-of-service block (see below). The Go decoder
   reads [136:140] back as `PolicyID` ONLY on a SESSION_CLOSE and is
   length-guarded, so a short (legacy 136-byte) frame degrades to policy 0
   rather than misparsing.

`0` stays the legitimate value for a session with no admitting policy
(neighbor-seed, fabric-return, tunnel sync-import, flow-cache replay seed, and a
host-local session that matched NO `to-zone junos-host` policy). #3706 narrowed
the host-local case: a host-bound session admitted by an explicit
`to-zone junos-host then permit` policy now stamps that policy's real `policy_id`
(and its `then log` selection + hit-counter handle) at the session-MISS
local-delivery install, exactly like a transit permit — so only a genuinely
unattributed host-local session still carries `0`.

#### Re-resolution at the local publish surfaces (#3395)

`policy_id` is **positional**: the Go control plane computes it as
`PolicySetID * MaxRulesPerPolicy + RuleIndex`, span-accumulated in config order
(`walkPolicyRuleSlots`). It is pinned to the `show security policies` **Index**
column by the #3063 cross-reference contract, so it MUST stay positional — it
cannot be made content-stable without breaking #3063 and the `MaxRulesPerPolicy`
span model. But a positional id frozen onto a session at install goes **stale**
after a live mid-list policy insert/delete: every later rule renumbers, so the
frozen id resolves to a *different* policy's name. This is the display/forensic
sibling of the #3322 hit-counter mis-attribution, fixed by the same bound-handle
pattern — re-resolve at READ time instead of making the scalar content-stable.

The admitting rule's stable identity is recovered from the session's already-bound
hit-counter handle (`SessionMetadata::policy_counter`, #3322): `PolicyRuleCounter`
now stores its `rule_id` (set once in `PolicyCounterStore::rule_hit_counter`), so
no new per-session field is needed. `PolicyState::reresolve_session_policy_id`
maps that `rule_id` to its CURRENT positional id via an O(1) per-snapshot
`rule_id → policy_id` map and is called at the two LOCAL publish surfaces where
the value is otherwise frozen:

1. **Live-session rows** — `refresh_bpf_conntrack_last_seen` (budgeted slice —
   see "Budgeted last_seen refresh" below) re-stamps the BPF conntrack value's
   `policy_id` from the bound handle against the current `PolicyState`.
   (SESSION_CREATE is emitted at install, where the positional id is already
   correct — no re-resolution needed.)
2. **RT_FLOW SESSION_CLOSE** — `flush_session_deltas` re-resolves and passes the
   id to `emit_session_close_rt_flow` (the close path already holds
   `forwarding.policy`, so this needs no new plumbing). The frozen
   `delta.metadata.policy_id` is NOT used for the close frame's [136:140] slot.

**Deleted-rule fallback → unattributed sentinel.** If the admitting rule was
DELETED (its `rule_id` is absent from the current snapshot), re-resolution
returns `DEFAULT_POLICY_SENTINEL_ID` (rendered `default-policy` by the Go
log/display planes), NOT the frozen positional id. Resolving to the frozen id
would be unsafe: a later reorder can shift a *different* extant rule into that
freed index, so the session would log under the wrong policy name. An honest "no
longer attributable to an extant rule" beats a confidently-wrong name. An
**unbound** session (idx-0 non-policy: host-local / seed / fabric / tunnel; or a
peer-synced session carrying only the wire scalar) has no local stable identity
and keeps its frozen id — preserving the "no policy" rendering for id 0.

**Hot-path lookup does not clone the bound counter Arc (#5445).** The bound
`SessionMetadata::policy_counter` is an `Arc<PolicyRuleCounter>`; a plain
`#[derive(Clone)]` copy of `SessionMetadata` therefore does a `LOCK XADD`
refcount increment on the SHARED counter control block. The primary/alias
`SessionTable::lookup`(`_with_origin`) return runs on the packet-forwarding hot
path (every established-session lookup — every TCP control segment, every
flow-cache-miss packet), so cloning the metadata by value there reintroduced the
#919 hot-path-atomic problem: many workers bumping the same rule's refcount
contend one cacheline. The fix strips the `Arc` from the per-packet return —
`lookup_with_origin` builds its `SessionLookup.metadata` via
`SessionMetadata::clone_without_policy_counter` (all Copy fields, `policy_counter
= None`, zero atomics). The bound counter stays owned by the `SessionEntry`, and
the established-hit fast path re-sources it **by borrow** via
`SessionTable::bound_policy_counter_for` for the per-packet policy hit-count,
cloning the `Arc` at most once per flow to hand ownership to the flow-cache
entry (`poll_descriptor`). #3322 reorder-stable attribution is unchanged — the
same `Arc` instance is used, just borrowed instead of cloned per packet. The
once-per-flow `find_forward_*_match` finders (which feed reverse-companion
install, an owner handoff) keep carrying the `Arc` on `ForwardSessionMatch`.
Pinned by `lookup_does_not_clone_policy_counter_arc_5445` (an `Arc::strong_count`
stability guard: reverting to `entry.metadata.clone()` makes the count grow while
the lookup result is held → RED).

**Scope — re-resolution is LOCAL only; the HA peer is the deferred P2.**
`SessionMetadata` carries no serde, so `policy_id` and the bound `policy_counter`
handle ride the shared-session map and sibling-worker replicas automatically.
#3301 carries the (positional) `policy_id` scalar on the cross-node HA
`SessionDeltaInfo` / `SessionSyncRequest` wire, so a peer-PROMOTED session
resolves the admitting policy after failover. That was true of the BINARY
event-stream open frame only until #6949 — see "Policy attribution is
single-sourced across both session-delta legs (#6949)" below. But the **peer holds no local bound
handle** (the binding is local derived state, not serialized), so a reorder AFTER
a session was synced still shows a stale id ON THE PEER until the session ages
out. Fixing that needs a rule-id-on-wire identity change (three two-sided wire
growths + a version bump) — explicitly DEFERRED as #3395's P2 (the "future work"
#3322 named), disproportionate churn for a Medium forensic edge whose severe
sibling (#3322) is already fixed.

### Class-of-service + interface attribution on the close frame (#2749)

#2613 dropped five fields from the NetFlow v9 / IPFIX templates because the
close frame carried no real value for them: `srcTos`/`ipClassOfService` (IE 5),
`tcpFlags`/`tcpControlBits` (IE 6), `flowDirection` (IE 61),
`ingressInterface`/`InputSNMP` (IE 10) and `egressInterface`/`OutputSNMP`
(IE 14). #2615 restored IE 10 (the binding's ingress ifindex). #2749 restores
the class-of-service + egress fields with REAL values by **extending the
SESSION_CLOSE RT_FLOW frame from 144 to 152 bytes** — an ADDITIVE block at
`[144:152]`:

| Offset | Field | Source |
|--------|-------|--------|
| `[144]` | src ToS byte (DSCP<<2, ECN cleared) | `SessionEntry.observed_tos`, stamped from `meta.dscp` on each FORWARD packet (`account_packet`) |
| `[145]` | accumulated TCP control bits | `SessionEntry.observed_tcp_flags`, OR of `meta.tcp_flags` over BOTH directions |
| `[146]` | flow direction | reserved, 0 — **deferred** (no real per-flow inbound/outbound signal yet) |
| `[147]` | reserved | 0 |
| `[148:152]` | egress ifindex (LE u32) | `SessionDecision.resolution.egress_ifindex` (already on the session) |

The two observed bytes ride the close `SessionDelta` (`observed_tos` /
`observed_tcp_flags`), harvested off the expiring entry in `session/expire.rs`
exactly like the #2501 counters; the egress ifindex comes straight off the
session's forwarding resolution. `encode_session_close_rt_flow`
(`SECURITY_EVENT_PAYLOAD_SIZE`, 152 at #2749, later 160 at #4915) writes the
block; the Go
`pkg/logging/ringbuf.go` reader decodes it into
`EventRecord.TOS`/`TCPControlBits`/`EgressIfindex`, and
`pkg/flowexport` re-adds the template fields + encoder writes (NetFlow v9
srcTos/tcpFlags/OutputSNMP and IPFIX ipClassOfService/tcpControlBits/
egressInterface).

**Additive / rolling-safe (#1961 both-sides discipline).** The Go minimum-frame
acceptance stays at the legacy 144 bytes (`rawEventWireSize`); the `[144:152]`
slots are read ONLY when the frame carries them (`len >= rawEventExtSize`, 152)
AND only on a SESSION_CLOSE. So a NEW daemon still accepts an OLD helper's
144-byte frames (CoS block stays 0/"unknown"), and an OLD daemon ignores the
trailing 8 bytes of a new helper's frame. The `rawEvent` Go struct mirror is
intentionally NOT grown — the extended block is read directly from the slice —
so the `dataplane.Event` size contract (`binary_test.go`) is unchanged.

**Deferred — flowDirection (IE 61).** Re-adding it would require a real
inbound/outbound classification the close path does not carry; a constant
ingress=0 would re-introduce the exact synthetic-zero #2613 fixed. The
`export-extension flow-dir` knob stays accepted-but-not-applied
(`V9TemplateOptions`) until that signal exists.

### Stable session id on the create + close frames (#4915)

Before #4915 the RT_FLOW event stream carried NO dataplane session identity:
`pkg/logging` stamped `EventRecord.SessionID` with a per-EVENT monotonic ordinal
(`atomic.AddUint64(&sessionSeq, 1)`), so a session's SESSION_CREATE and
SESSION_CLOSE necessarily got DIFFERENT ids and could not be correlated, and a
reused 5-tuple could not be disambiguated. The legacy eBPF `session_id_gen`
per-CPU generator was retired with the dataplane (#1476), so no real id existed
to put on the wire.

#4915 makes `SessionTable` ASSIGN a stable id and threads it to the wire:

- **Generation** — `SessionTable::alloc_session_id` (called once per fresh
  install in `install_with_protocol_with_origin`, and once per peer-synced
  import in `upsert_synced_with_origin` **only when no wire id was carried** —
  see #5212 below) returns `(namespace << 48) | counter`, the per-worker counter
  starting at 1. The **namespace** is `node_bit << 15 | worker_id` (#6311), set
  at worker setup via `set_session_id_namespace(node_id, worker_id)`:

  - the **worker half** (15 bits) makes the id unique across the node's
    shared-nothing per-worker `SessionTable`s;
  - the **node half** (1 bit, from `ConfigSnapshot.node_id`) makes it unique
    across the CLUSTER, so a peer id ADOPTED verbatim on import (#5212) can
    never collide with an id this node mints. Both nodes otherwise run the same
    worker set (queue indices 0..N) with counters that both start at 1, so in
    active/active low-counter collisions were essentially guaranteed — and that
    also regressed pre-#5212 same-node uniqueness, where every import got a
    fresh local id. Node 0's layout is bit-for-bit the pre-#6311 one.

  The counter is monotonic, so a reused 5-tuple (same worker) gets a DISTINCT
  id. `0` is reserved as the wire "unknown" sentinel — a real id is never 0.

  Two invariants are ENFORCED with hard `assert!`s (not `debug_assert!`: the
  helper and `make test-rust` both build `--release`, where a debug assertion is
  stripped), at worker setup, where `docs/engineering-style.md` prefers
  crash-start over running with a wrong invariant:

  - **Namespace `0xFFFF` is reserved for the Go control plane (#6198)**:
    `nextUserspaceSyncedSessionID` (`pkg/daemon/daemon_ha_userspace_convert.go`)
    mints `0xFFFF << 48 | counter48` for the peer-synced sessions the daemon
    writes into the SAME BPF conntrack mirror field, so the two id spaces stay
    disjoint. Post-#6311 that value is node-bit-1 plus worker `0x7FFF`, so the
    assert guards the COMBINED namespace rather than the worker half alone.
  - **A worker id above `0x7FFF` is REFUSED, not masked** (#6311): masking would
    carry into the node bit and mint ids inside the PEER node's namespace — a
    silent cross-node collision, strictly worse than the counter aliasing the old
    16-bit mask prevented.

  Both unreachable today (`binding.worker_id` is bounded by
  `MAX_NAT_HOLDER_WORKERS` = 128 where it is minted), which is why they are
  pinned rather than merely documented:
  `session::tests::set_worker_id_rejects_the_control_plane_namespace_6198` and its
  negative control,
  `set_session_id_namespace_refuses_a_worker_id_that_would_reach_the_node_bit_6311`,
  `session_id_carries_the_node_discriminator_6311`, and
  `adopted_peer_id_cannot_collide_with_a_local_id_6311`.
- **Storage** — write-once on `SessionEntry.session_id`, never re-stamped, so a
  session's create and close read the same value.
- **Wire** — harvested onto the Open/Close `SessionDelta.session_id` and encoded
  at the additive `[152:160]` u64 (LE) slot by `encode_session_create_rt_flow` /
  `encode_session_close_rt_flow` (payload grew 152 -> 160,
  `SECURITY_EVENT_PAYLOAD_SIZE`). Both frames of a session carry the SAME id.
- **Decode** — `pkg/logging/ringbuf.go` reads `[152:160]` into
  `EventRecord.SessionID` ONLY on a SESSION_CREATE/CLOSE frame with `len >= 160`;
  otherwise SessionID falls back to the per-event ordinal (now also exposed as
  `EventRecord.EventSeq`). This keeps the change strictly additive: nothing
  observable moves until a new helper emits a 160-byte session frame.

**Additive / rolling-safe (#1961 both-sides discipline).** Same pattern as the
#2749 `[144:152]` block: the Go minimum-frame acceptance stays at
`rawEventWireSize` (144); `[152:160]` is read ONLY when the frame carries it
(`len >= rawEventSessionIDSize`, 160) AND only on a session frame. A new daemon
still accepts an old helper's 144/152-byte frames (id absent → ordinal
fallback), and an old daemon ignores the trailing 8 bytes.

**Scope — both documented follow-ups now RESOLVED.** (1) Cross-HA-node id
IDENTITY — **RESOLVED in #5212.** Before #5212 a peer-synced session was assigned
a FRESH node-local id on import, so a session that opened on the primary and
closed on the standby after a failover carried different ids on the two nodes.
#5212 carries the originating node's id on the HA session-sync wire as a
length-gated trailing field (both sides, mirroring the #4565/#5274 discipline):
`SessionDelta.session_id` → the MSG_SESSION_OPEN frame's trailing `session_id`
u64 (`encode_session_open`) — and, since #6312, the JSON RPC-fallback delta's
`rt_flow_session_id` key (`afxdp::session_delta_info`), so a session recovered
through the `drain_session_deltas` polling leg or the owner-RG resync export
carries the id at parity with the binary frame instead of importing 0 →
Go `SessionDeltaInfo.RTFlowSessionID` →
`SessionValue{,V6}.RTFlowSessionID` → the cluster sync wire (a length-gated
trailing u64 in `encodeSessionV{4,6}Payload`, after the #5274 `ConfigEpoch`) →
`SessionSyncRequest.session_id` → `build_synced_session_entry`. On import,
`upsert_synced_with_origin` ADOPTS the wire id (`SessionInstall::session_id`) when
it is non-zero, and only falls back to `alloc_session_id()` for a legacy peer
(wire id 0). The standby's SESSION_CLOSE RT_FLOW then carries the SAME id the
primary's SESSION_CREATE did. The id is a metadata-only correlation stamp (never
a lookup key), adopted verbatim for that cross-node correlation. It is NOT
globally unique — the `worker_id<<48 | counter` namespace has no node
discriminator and both nodes run the same worker set, so in active/active an
adopted id can collide with a local same-worker id (observability-only, bounded;
a node-discriminator bit is tracked as #6311). Pinned by
`session::tests::synced_import_adopts_peer_session_id_5212`,
`test_encode_session_open_carries_session_id_5212`, and the Go
`TestSessionWireRoundTripRTFlowSessionID5212{V4,V6}` /
`TestDecodeSessionEventRTFlowSessionID5212` /
`TestBuildSessionSyncRequestCarriesRTFlowSessionID5212` /
`TestUserspaceSessionFromDeltaCarriesRTFlowSessionID5212`. (2) RESOLVED in #5213:
`show security flow session` now shows the SAME id the RT_FLOW frames carry.
`publish_conntrack` (`build_conntrack_value_v4`/`_v6`) stamps the conntrack-map
`session_id` from `SessionTable::session_id_for(&forward_key)` at each
live-session-create publish site, and `cli_show_flow.go` renders `val.SessionID`
(via `flowSessionDisplayID`), keeping the `cli_show_flow.go` iteration-index
fallback ONLY when `val.SessionID == 0` (an absent/legacy id). Additive and
node-local-safe.

## Per-IP session-limit lifecycle (#2134; #3122 peer-synced fix; #2128 leak-fix preserved)

Junos `set security screen ids-option <name> limit-session
source-ip-based <n>` / `destination-ip-based <n>` caps the concurrent
sessions one source / destination IP may hold. The per-IP count is owned
by `SessionTable` (`session_limit_src_counts` / `session_limit_dst_counts`),
NOT by `ScreenState` — the count must track the real session lifecycle,
and `SessionTable` is the choke point every create/remove already passes
through.

**Counted-class predicate (#3122 — PRESENCE-based, origin-agnostic).** A
session counts iff it is forward-direction and real (not a transient
seed): `!is_reverse && !origin.is_transient_local_seed()`. As of #3122
this is **origin-agnostic** — a session counts whether it was
locally-admitted OR imported from the HA peer (`SyncImport` /
`SharedMaterialize` / `WorkerLocalImport`). Before #3122 the predicate
also excluded `!origin.is_peer_synced()`, which kept peer-synced sessions
invisible to the per-IP count; after a failover the standby-turned-active
held synced sessions it had never counted, so a client could open a full
fresh allotment ON TOP of its pre-existing (synced) sessions — a security
**limit bypass**. Counting on import closes that gap.

**Count vs. HA Open delta are now SEPARATE conditions (#3122).** The
fresh-install path increments the count for any counted-class session but
only emits an HA Open delta for the `!is_peer_synced()` subset — a
peer-synced session must NOT re-emit a delta (that would echo the peer's
own session back to it, a sync loop). Before #3122 the two shared one
condition; they diverged when the count became origin-agnostic.

**Maintenance sites (all OFF-gated by `session_limit_active`).** The
count is incremented at the two CREATE sinks and decremented at the sole
REMOVE sink. The two in-place HA origin flips (promote / demote) are
**count-neutral** — the session stays present in the table, only its
origin changes, so its slot stays charged exactly once across the whole
import → promote → … → demote → expire lifecycle:

| Transition | Site | Action |
|---|---|---|
| fresh install (local) | `install_with_protocol_with_origin` (next to the Open-delta push) | increment |
| peer-synced import (#3122) | `upsert_synced_with_origin` (after the insert) | increment |
| any removal (expire / clear / RST / fabric-cancel / take_synced_local) | `remove_entry` success path (the sole removal sink) | decrement |
| in-place HA promote synced→local | `update_session` promote branch (`mod.rs`) | **none** (already counted at import) |
| in-place HA demote local→synced | `demote_owner_rg` | **none** (session stays present) |

Removals are structurally exhaustive through `remove_entry`, so a future
delete site cannot forget the decrement; `remove_entry`'s decrement is now
origin-agnostic too, so a peer-synced removal (e.g. `take_synced_local`,
or a synced session expiring) balances its import increment. The
re-install promote path (`take_synced_local` + fresh install) decrements
on the remove and increments on the re-install → still nets to one. The
in-place promote (`update_session`) and demote (`demote_owner_rg`) do NOT
touch the count, so the same session is charged exactly once regardless of
how ownership moves — **no double-count at failover or failback**. Every
decrement uses `saturating_sub` and **evicts the map entry the moment its
count reaches 0** — so the maps are bounded by distinct IPs with ≥1 live
counted session (this is the #2128 fix: the read path never inserts a
phantom zero entry).

**Where the limit is CHECKED.** At the NEW-FLOW / session-MISS decision
in `afxdp/poll_descriptor` (`new_flow_session_limit_drop`), NOT in the
per-packet screen stage. The screen stage runs on every data packet of
every flow and before the session lookup; checking `count >= limit`
there would re-evaluate an established flow's own counted session and
self-drop it at the limit boundary. The new-flow check fires exactly once
per new flow, before its session exists, via a non-mutating
`session_limit_{src,dst}_count` query, and emits the
`session-limit-src` / `session-limit-dst` screen-drop event + counter.

**OFF-gate + clear-on-disable + back-count-on-enable (#4377).**
`set_session_limit_active(active)` is driven from the applied
screen-profile snapshot (startup + runtime-reload, next to `set_timeouts`
/ `ScreenState::update_profiles`). When no zone configures `limit-session`
the gate is OFF and every maintenance op short-circuits, so the ~99% of
deployments pay nothing. On an ON→OFF runtime transition the gate setter
**clears both count maps** — otherwise the decrement paths stop firing
and a later re-enable would resume from stale, over-counted values and
spuriously block an under-limit IP.

On an OFF→ON transition the gate setter **rebuilds both count maps from
the live slab** (#4377). This is NOT optional / benign: install and
`remove_entry` share the same presence predicate but keep no per-entry
record of whether the entry was actually charged — each is gated only on
`session_limit_active` at the moment of the op. A forward session
installed while the gate was OFF (or after a disable cleared the maps) is
uncounted, yet its teardown while ON still fires the sole-sink decrement.
That increment-less decrement drives `count[X]` BELOW the live
counted-session count; `saturating_sub` + evict-at-0 hide the underflow,
so `count[X]` can reach 0 while sessions are live and X is handed a fresh
full allotment — a **cap bypass** on the enable edge (or any
disable→enable toggle). The back-count walks `key_to_handle` (the
authoritative primary index, matching `iter_with_origin`) and increments
the per-IP maps for every counted-class entry
(`!is_reverse && !origin.is_transient_local_seed()`), using the SAME
origin-agnostic predicate as the install/decrement sinks so #3122
peer-SYNCED sessions are back-counted exactly as their later teardown
will decrement them. Now every decrement balances an increment and the
cap enforces on the true live count. O(N) once per rare enable, no
per-entry memory. Regression:
`session_limit_backcount_on_enable_covers_preexisting_sessions` and the
`session_limit_clear_on_disable` re-enable assertions.

**Per-worker scoping — the effective cap is `configured × num_workers`
(#2186).** Each worker owns its `SessionTable` by value, so the per-IP
count is maintained *independently per worker (per RX queue)*. With RSS
spreading the flows of a single source/destination across all N RX
queues, the limit is enforced N times in parallel, so the **effective
admitted cap ≈ `configured_limit × number_of_RX_queues/workers`**, not a
single global cap. The configured value is the per-worker ceiling.

Worked example (loss userspace cluster, 6 mlx5 RX queues → 6 workers):
`limit-session source-ip-based 2` admitted **12** sessions (2 × 6) from
one source before screen-drops engaged. Enforcement is correct and fires
on every worker; the cap is just per-worker-multiplied. This is a
pre-existing property of the per-worker dataplane (the same was true of
the eBPF per-CPU map), not introduced by #2134, and it is consistent
with Junos-approximate multi-queue semantics. Operators sizing a cap
should divide the desired global ceiling by the worker count, or treat
the configured value as an approximate per-source/destination bound that
scales with queue count.

Decision record: `docs/research/2128-2134-screen-session-limit/plan.md`.

## Scan/sweep detection on the new-flow path (#2210; per-zone + bounded #2209)

Port-scan and IP-sweep follow the SAME structural rule as the per-IP
session limit above: the scan/sweep MUTATION runs at the NEW-FLOW /
session-MISS decision in `afxdp/poll_descriptor`
(`ScreenState::scan_sweep_drop_on_new_flow`), NOT on the per-packet
pre-session screen stage.

- **#2210 (count-after-lookup).** The pre-#2210 code ran IP-sweep on the
  per-packet stage, which executes BEFORE the session lookup and on every
  protocol — so mid-stream established TCP ACKs/data and UDP all counted
  toward the sweep. A single legitimate high-fan-out client (one host with
  live connections to many backends) would trip IP-sweep without ever
  sending a probe, and the original #867 ACK-evasion contract ("an ACK
  that matches a live session is not a sweep probe") was lost. Moving the
  mutation to the session-MISS hook means an established flow's packets are
  session HITS and never reach it, so only a genuinely-new flow counts.
  Port-scan keeps its TCP-initial-SYN gate; IP-sweep counts the new flow
  on any protocol (a session-miss ACK to many destinations is the
  ACK-evasion sweep it is meant to catch).

- **#2209 (per-zone + bounded).** The trackers are keyed by
  `(zone_id, src_ip)` (was a single global per-`src_ip` instance), so a
  source scanning zone `wan` no longer bleeds its count into the `dmz`
  threshold evaluation. The backing maps are bounded on both
  attacker-driven axes: `MAX_SOURCES_PER_ZONE` distinct sources per zone
  and `MAX_UNIQUE_PER_SOURCE` unique entries per source. On a SOURCE-axis
  overflow the tracker SKIPS the new source (degrades to not-counting that
  source) and bumps a `skipped_pressure` counter — that can only make a
  drop verdict LESS likely, never grow without bound. The per-tick cleanup
  walks the source table (`HashMap::retain`, O(sources)) but removes at
  most `CLEANUP_BUDGET` entries per call, so the per-tick MUTATION cost is
  bounded; the real ceiling on the walk is the `MAX_SOURCES_PER_ZONE` cap
  on the table itself, with the budget spreading reclamation across ticks
  (`screen/scan.rs`). This mirrors the #2134/#2177 session-limit
  skip-on-full discipline.

- **#4114 (Junos µs-window semantics).** The port-scan / ip-sweep
  `threshold` is a Junos MICROSECOND detection WINDOW, and the detection
  COUNT is the fixed `SCAN_DETECT_COUNT` (10) in `screen/scan.rs`. The
  tracker resets its per-`(zone, src)` distinct-destination set each
  `window_micros` and fires once the set reaches 10. `MAX_UNIQUE_PER_SOURCE`
  (1024) is now purely a MEMORY bound — the fixed count sits well under it,
  so the verdict is never gated by the cap. This replaced the buggy
  pre-#4114 shape (a configurable COUNT over a hard-coded 10-second window
  plus a `MAX_UNIQUE_PER_SOURCE - 1` fail-closed clamp): a copied Junos
  `threshold 5000` was misread as a count and clamped to never-fire, while
  the default-armed sweep false-dropped normal browsing. The Go control
  plane (`pkg/config/compiler_security_screen.go`) defaults the window to
  5000 us (Junos default) and emits a commit-time ADVISORY
  (`validateScreenScanSweepWindows`) when a value falls outside the Junos
  [1000, 1000000] us range — the count->window migration net, never a hard
  reject (no-brick). `SCAN_DETECT_COUNT` mirrors the Go `scanSweepDetectCount`.

- **Perf (#2209).** The per-packet `check_packet_with_zone_id` no longer
  clones the whole `ScreenProfile` per screened packet — it borrows it and
  copies only the small scalar thresholds it needs. The scan/sweep stage
  reads the profile by zone name only on the cold session-miss path.

Per-worker scoping applies identically to scan/sweep (each worker owns its
`ScreenState`), so the effective unique-entry count is multiplied by the
worker count, exactly as documented for the session limit above.

**Source-table saturation — bounded stalest-eviction (#2234, was MINOR-2).**
The per-zone source table is still capped at `MAX_SOURCES_PER_ZONE = 4096`
(memory never grows without bound), but the cap is no longer a HARD cliff. The
pre-#2234 behaviour SKIPPED a brand-new source once the zone was full, so a
high-cardinality spoofed-source flood that filled the table could prevent a
*subsequently-arriving* genuine scanner from being tracked — and therefore
from being detected — until entries expired (which the attacker could defer
indefinitely by keeping its 4096 sources fresh). That was a detection-DoS: it
never fail-opened the *forwarding* path, but it suppressed scan/sweep
*detection*.

The new-source path now makes BOUNDED room instead of skipping. When a brand-
new `(zone, src_ip)` arrives at a full zone, the tracker samples at most
`EVICT_SCAN_LIMIT = 64` SAME-ZONE sources from a PER-ZONE source index
(`per_zone_srcs`, #4890), reclaims the first expired same-zone window it finds,
and if none is expired evicts the LEAST-SUSPICIOUS live same-zone entry within
that sample — the one with the FEWEST accumulated distinct destinations,
breaking ties on the stalest `window_start` (#4418). A brand-new decoy source
sits at count 1, while a slow scanner that has already probed several
destinations sits near the detection count, so a flood of fresh decoys evicts
one another (or the lowest-count live entry) and CANNOT displace a
near-threshold slow scanner. The pre-#4418 policy evicted the stalest
`window_start` regardless of count, which let an attacker keeping the table
full of fresher decoys evict a slow scanner whose window opened earlier (its
old-but-LIVE window made it "stalest") — reopening the slow-scan evasion on the
source-saturation axis.

Because the sample is drawn from the TARGET zone's OWN index, every one of the
`EVICT_SCAN_LIMIT` examined entries is a same-zone candidate and the budget is
never consumed by other zones. Since this path only runs when the target zone
alone holds `>= MAX_SOURCES_PER_ZONE` keys (>> `EVICT_SCAN_LIMIT`), a same-zone
victim is ALWAYS found and a fresh real scanner is ALWAYS admissible under
saturation — regardless of how the zones interleave in the global `per_src`
table. The pre-#4890 search instead sampled a fixed GLOBAL prefix of `per_src`
(`iter().take(EVICT_SCAN_LIMIT)`, budget counting EVERY iterated entry,
same-zone or not); in a many-zone / sparse-interleave table whose first
`EVICT_SCAN_LIMIT` global positions held no target-zone entry, eviction found
no victim, the fresh scanner was skipped, its distinct-destination count never
accrued, and port-scan / ip-sweep detection never fired for it even though its
packets were still forwarded (the #4890 fail-open of DETECTION; forwarding was
never fail-open). The per-new-flow worst case is O(`EVICT_SCAN_LIMIT`), NOT an
O(sources) min-scan over 4096 entries, which under a saturation flood would
itself be an O(n)-per-packet amplifier. The per-zone source count AND the
victim-search domain are both served by `per_zone_srcs` (its `.len()` is the
O(1) cap test), so the only walk is the bounded same-zone sample. The
skip-on-full fallback (`skipped_pressure`) remains only as a defensive guard —
still bounded, still never fail-open.

Each eviction bumps `evicted_pressure` (surfaced via
`ScreenState::scan_sweep_evicted_pressure`), and a rare LOGARITHMIC threshold
crossing (powers of two in the cumulative eviction count) emits a
`scan-table-pressure` screen event so the operator is told the detector is
saturated — at a handful of alarms under a sustained flood, never per-flow
(honouring the no-per-packet-logging rule). Defence-in-depth mitigations still
apply: anti-spoofing / uRPF upstream reduces the spoofed-source axis, and the
`skipped_pressure` / `evicted_pressure` signals surface the pressure.

**Window-aware cleanup floor — no time-cap evasion (#4379/#4418).** The
periodic budgeted cleanup (above) reaps an entry only once it has been idle
longer than the reap FLOOR. That floor is the LONGEST detection window
(`threshold`, microseconds) configured across the live screen profiles
(`scan_cleanup_floors` in `screen/mod.rs`), so an accumulating
distinct-destination set is never reclaimed before the operator's own
detection window could still fire on it. A pre-#4379 fixed 1s floor reaped the
set for any window > 1s → a slow scan spread across the window EVADED
detection (fail-open). The floor is clamped to `MAX_CLEANUP_WINDOW_MICROS` so a
floor beyond any configurable window cannot retain dead weight forever; #4418
raised that ceiling from a 5-minute cap to the u32 `threshold` type maximum
(~71.6 min), because the 5-minute cap re-reaped an accumulating set at 300s for
any configured window > 5 min — reopening the same evasion for that pathological
band. A >5min window is far outside the Junos `[1000, 1000000]` us range and
already draws a commit-time advisory (`validateScreenScanSweepWindows`), but the
dataplane must not silently reopen the evasion for a value the operator was
merely WARNED about, not rejected. Because a `threshold` is a `u32`, the u32-max
ceiling never clamps a configurable window, so the evasion is closed for EVERY
configurable window. This is a RECLAMATION-TIMING bound only: `MAX_SOURCES_PER_
ZONE` / `MAX_UNIQUE_PER_SOURCE` are enforced at INSERT time, so the table stays
bounded regardless of the window — a 71-min worst case is bounded by the SAME
4096-source / 1024-entry caps as a 5-second window; a longer floor only defers
reclamation of idle entries.

## Strict-syn-check drop on the new-flow path (#4400)

A TCP packet that MISSES the session table and carries a connection-CLOSING
control bit (FIN or RST) with **no SYN** can never legitimately OPEN a
connection. A real flow starts with a SYN; a bare RST/FIN for a flow this
node does not track is either a late segment for an already-GC'd session or
an attack. The pre-#4400 code let such a packet flow through the ordinary
session-miss install: policy evaluated, and
`install_with_protocol_with_origin` seeded a fresh entry that
`install.rs` immediately marked `closing`/`reset` from the packet's flags
(the lines that set `closing: matches!(protocol, PROTO_TCP) && is_closing(...)`
and `reset: ... && has_rst(...)`). The result was pure churn — an
immediately-closing session with no forwarding value — and a cheap way for a
RST/FIN flood to exhaust the per-worker table. Reported P6 (HIGH), confirmed
four times.

The fix is a **strict-syn-check-style guard** at the session-MISS choke point
in `afxdp/poll_descriptor` (`strict_syn_check_drops_new_flow`), applied right
after `finalize_new_flow_ha_resolution` and BEFORE both transit install sites
(the `ForwardCandidate` forward install and the `MissingNeighbor` seed
install). A bare RST/FIN (`is_closing(flags) && !has_syn(flags)`) on a
`ForwardCandidate` / `MissingNeighbor` miss is DROPPED — the frame is
recycled, no session is installed, and the aggregate `screen_drops`
flow-statistics counter is bumped (no per-reason ordinal — that array mirrors
the Junos SCREEN checks, and strict-syn-check is a flow `tcp-session` control;
it joins the syn-cookie / icmp-fragment aggregate-only class). No per-packet
event is emitted: a RST/FIN flood must never become a log storm.

Scope and deliberate exemptions:

- **Applied unconditionally (no config knob).** Junos exposes
  `security flow tcp-session strict-syn-check` as an opt-in that requires the
  first packet of EVERY TCP flow to be a SYN (dropping a non-SYN first packet
  outright). xpf keeps the looser Junos *default* (no-syn-check): a SYN-ACK /
  bare ACK / data first packet may still open an ESTABLISHED session (#3152),
  preserving asymmetric-routing mid-stream pickup. Only the pathological
  bare-RST/FIN-on-miss case is dropped, and it is dropped ALWAYS — a stray
  RST/FIN opening a closing session is never useful regardless of the
  operator's strict-syn-check setting, so this is the safe stateful-firewall
  default and needs no configuration surface.
- **SYN-bearing segments are untouched.** A bare SYN still installs; a SYN-ACK
  on miss still installs per existing policy (asymmetric routing); the
  malformed SYN-FIN stays owned by the `tcp-syn-fin` screen check (the guard's
  `!has_syn` clause excludes it).
- **LocalDelivery (host-inbound to the RE) is exempt.** The guard gates only
  the two TRANSIT dispositions. A peer RST tearing down a firewall-originated
  TCP session (BGP, IKE, management SSH) is host-inbound and MUST reach the
  local kernel stack, so it is never dropped here.
- **No fabric exemption needed.** Since #6478 removed the
  `cluster_peer_return_fast_path`, a fabric-ingress bare RST/FIN takes the
  normal miss block and IS dropped by this guard — a legitimate
  cross-chassis teardown arrives as a session HIT (the synced session is
  present), never as a session-less fabric packet, so no exemption is
  needed. Any bare RST/FIN reaching the guard is a genuine new-flow
  attempt and is dropped whether it ingressed locally or crossed the
  fabric.

## Why a slab + integer handles

Pre-#964 the table was `HashMap<Key, Arc<SessionEntry>>`. Reverse-NAT
and alias lookups now run 2.2–2.3× faster because integer handles are
cheap to compare and the slab layout fits more entries per cache line.
The owner-RG export path took a 2× regression on a rare HA codepath
that's known and accepted; see PR #1182 for the trade-off.
