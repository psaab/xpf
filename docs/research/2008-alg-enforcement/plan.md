# #2008 H3/H4 — `security alg dns/ftp disable` enforcement

**Status: PLAN-KILL (already shipped).**
**Revision:** r1
**Branch:** `research/2008-alg-enforcement`
**Scope:** Umbrella #2008 gaps H3 (`security alg dns disable`) and H4
(`security alg ftp disable`) — "ALG disable enforcement is inert".

---

## 0. TL;DR

The research request's premise is **stale**. The defect it describes — the Go
compiler writes `ALGFlags` bits but the Rust dataplane hardcodes `alg_type:0`
and never reads `alg_flags`, so `set security alg dns/ftp disable` is a silent
no-op — was **fixed and merged** in **PR #2015**
(`refactor/2008-alg-disable-enforce`), which the #2008 umbrella explicitly lists
under "Tier-1 + Tier-1.5 COMPLETE — 7/7 PRs merged". The fix is on `origin/master`
today (commits `067799bc2`, `8170f0d13`, `f6c932e72`; merge `1ea4057cd`).

There is **no remaining H3/H4 work to plan**. The one adjacent open item, **M6
(stateful ALG payload transforms / pinholes)**, is a *different and larger*
deferred gap, not H3/H4 disable enforcement, and is correctly tracked separately
in the umbrella as "large-needs-design / defer".

**Verdict: PLAN-KILL.** Do not engineer an H3/H4 slice — it is already done.

---

## 1. Problem statement (as filed) and what was actually true

The #2008 audit table (written against `b1ef3ed16`, pre-fix) sketched H3/H4 as:

> H3 `security alg dns disable`: parse/compile=full / implement=none
> (`ALGFlags` bit 0x01 written to `flow_config_map`, no reader; `alg_type`
> hardcoded 0 at `publish_conntrack.rs:105`). H4 mirrors for FTP (bit 0x02).

That was an accurate description of the **pre-#2015** state. PR #2015 closed
exactly this gap. The audit *body* was never edited after the fix landed (the
umbrella issue body is a frozen audit snapshot; progress is tracked in the
comment thread, which records #2015 as merged).

---

## 2. Current end-to-end state on `master` (source-verified)

The `alg disable` knob now flows config → compile → wire → Rust runtime →
conntrack session value, and the disable bits demonstrably change the stamped
`alg_type` from non-zero to `0` (none). Trace:

### 2.1 Go config → typed state
- `pkg/config` parses `security alg <proto> disable` into
  `config.ALGConfig{DNSDisable, FTPDisable, SIPDisable, TFTPDisable}` (full
  parse + compile — was never the gap).

### 2.2 Go → wire snapshot
- `pkg/dataplane/userspace/flow.go:104` `algDisableFlags(*config.ALGConfig)`
  packs the four knobs into a `uint8` (DNS=0x01, FTP=0x02, SIP=0x04, TFTP=0x08).
- `buildFlowSnapshot` (flow.go:96) sets
  `snap.ALGDisableFlags = algDisableFlags(&cfg.Security.ALG)`.
- `pkg/dataplane/userspace/protocol.go:134`
  `ALGDisableFlags uint8 \`json:"alg_disable_flags,omitempty"\`` carries it on
  the wire.
- Tests: `manager_test.go:4186 TestBuildFlowSnapshotPacksALGDisableFlags`
  (per-knob packing + JSON round-trip).

### 2.3 Wire → Rust ForwardingState
- `userspace-dp/src/protocol/snapshot.rs:176`
  `#[serde(rename = "alg_disable_flags", default)] pub alg_disable_flags: u8`
  (additive, defaults 0 for old Go binaries — back-compat safe).
- `userspace-dp/src/afxdp/forwarding_build/mod.rs:202`
  `state.alg_disable_flags = snapshot.flow.alg_disable_flags;`
- `userspace-dp/src/afxdp/types/forwarding.rs:56`
  `pub(in crate::afxdp) alg_disable_flags: u8`.
- Test: `forwarding_build/tests.rs:2460
  build_forwarding_state_carries_alg_disable_flags` (guards the carry from
  silently dropping).

### 2.4 Runtime session-create → conntrack stamp
- Live call site `userspace-dp/src/afxdp/poll_descriptor/mod.rs:387-396` (and
  the two sibling call sites at ~1130 and ~3112) pass
  `worker_ctx.forwarding.alg_disable_flags` into `publish_bpf_conntrack_entry`
  on **every** session create — not just in tests.
- `publish_conntrack.rs:63 alg_type_for_session(protocol, src_port, dst_port,
  disable)` derives the ALG type from the well-known service port (DNS UDP/53,
  FTP TCP/21, SIP UDP+TCP/5060) **unless** the matching disable bit is set, in
  which case it returns `ALG_TYPE_NONE` (0). Matches on either port slot so the
  reverse-keyed conntrack entry resolves to the same type.
- The result is written to `BpfSessionValue{V4,V6}.alg_type`
  (bpf_map/mod.rs:164/211), mirroring C `struct session_value.alg_type`
  (`bpf/headers/xpf_conntrack.h:55,116`).
- Tests: `publish_conntrack.rs:304 mod alg_type_tests` — forward + reverse-keyed
  DNS/FTP/SIP, disable-on / disable-off, full-mask, non-ALG ports. These tests
  **fail if `alg_type` regresses to hardcoded 0** (the assertion comments
  document the regression-trip).

### 2.5 Semantics match Junos
- Junos `alg <proto> disable` turns the ALG **off**; it does **not** drop
  traffic. The implementation does exactly that: a disabled-ALG session is
  forwarded normally and simply tagged `alg_type=none`. No drop, no special
  path. This is the correct and complete semantics **for a dataplane that has no
  ALG payload transforms** (see §3).

---

## 3. Why "disable enforcement" is complete even though `alg_type` has no reader

A natural hostile objection: *"`alg_type` is stamped into the session value but
no Rust code reads it back to do anything — so 'enforcement' is vacuous."*

That objection is **correct on the facts but wrong on the conclusion for H3/H4**:

- xpf's userspace dataplane has **no ALG payload-transform / pinhole / DNS-
  doctoring subsystem at all**. A repo-wide search for pinhole / doctoring /
  data-channel / expected-flow / payload-rewrite logic finds nothing (the only
  `ftp-data` hits are service-port *name→number* lookups in the policy/filter
  compilers, unrelated to an ALG helper). `docs/feature-gaps.md` independently
  confirms ALG runtime transforms are absent.
- Therefore there is **no ALG behavior to suppress**. "Enforcing disable" on a
  dataplane with no ALG helper means exactly one thing: do not *tag* the session
  as an active ALG. That is precisely what shipped.
- Building an actual ALG-helper and then gating it on the disable bit is the
  **M6** gap ("stateful ALG payload transforms"), which the umbrella explicitly
  scopes as a separate, large, deferred net-new subsystem ("File per-ALG issues
  led by TFTP + shared pinhole infra"). H3/H4 is *not* M6 and was never meant to
  build the helper — it was meant to stop the disable knob from being a silent
  no-op, which it now does (it changes observable session state: `alg_type`).

So the disable knob is **no longer inert**: with it set, `alg_type` is 0; without
it, `alg_type` is the per-port ALG code. The field is consumed for `show
security flow session` display parity and HA conntrack mirroring. There is
nothing further to enforce until M6 introduces a helper to disable.

---

## 4. Wire / snapshot impact

**None required.** The wire field already exists: `alg_disable_flags` (`u8`) is
in the Go `FlowSnapshot` (`protocol.go`) and the Rust `FlowSnapshot`
(`snapshot.rs`), additive with `default`/`omitempty` for forward/back-compat
across mixed Go/Rust binary versions. No new field, no `protocol_wire_v1.json`
regen needed for H3/H4 (that work was done in #2015).

---

## 5. HA impact

**Already handled.** `alg_type` lives in the kernel-visible conntrack
`session_value` that is HA-session-synced. The derivation matches on *either*
port slot so forward and reverse conntrack entries resolve to the same
`alg_type`, which is required for the mirrored reverse entry and for a peer that
takes over a synced session. The `disable` value is carried in
`ForwardingState` on both nodes (each compiles the same snapshot), so a
failed-over session is stamped consistently. Covered by the reverse-keyed tests
(§2.4).

---

## 6. Hot-path cost

**Negligible, already paid.** `alg_type_for_session` is a handful of integer
comparisons (`protocol` match + two `== port` checks + one bit test) executed
once per session create — not per packet. No allocation, no map lookup, no
branch on the per-packet fast path. Consistent with the project's hot-path
allocation rules in `docs/engineering-style.md`.

---

## 7. Path options

There is only one disposition because the work is already merged:

- **Path A (recommended): PLAN-KILL.** Close H3/H4 as done; point any residual
  interest at M6 for the actual ALG-helper feature. Zero code.
- **Path B (rejected): re-implement / "harden".** No defect exists to fix;
  re-touching `alg_type_for_session` would be churn against a tested, merged,
  reviewed (full quad on #2015) implementation.
- **Path C (out of scope, do NOT fold into H3/H4): build the ALG helper (M6).**
  Real L7 FTP-data pinholes, DNS doctoring, SIP/TFTP expected-flows. This is a
  net-new stateful subsystem with its own design, wire surface, HA, and hot-path
  cost. It must be its own `/research` under the M6 line, not smuggled into an
  H3/H4 "enforcement" PR. Explicitly deferred by the umbrella.

---

## 8. Test strategy

No new tests needed for H3/H4 — the merged change already ships:
- Go: `TestBuildFlowSnapshotPacksALGDisableFlags` (packing + round-trip).
- Rust: `mod alg_type_tests` (forward/reverse DNS/FTP/SIP, on/off, full-mask,
  non-ALG) + `build_forwarding_state_carries_alg_disable_flags` (carry guard).

If the umbrella ever wants belt-and-suspenders runtime proof, the existing
`security-matrix` smoke could add a check that a session to UDP/53 with `alg dns
disable` set shows `alg_type=none` in `show security flow session` — but that is
optional verification, not new enforcement, and is not required to close H3/H4.

---

## 9. Risk / blast radius

**Zero** — this plan ships no code. The existing implementation's blast radius
was already vetted at #2015 merge (full quad review per the umbrella comment:
"Every PR had a real review finding caught + fixed before merge (full quad on
the security ones)").

---

## 10. Recommendation

**PLAN-KILL.** H3/H4 (`security alg dns/ftp disable` enforcement) is implemented,
tested, reviewed, and merged on `master` via PR #2015. The research premise
("Rust hardcodes alg_type:0 and never reads alg_flags") describes the pre-fix
state captured in the frozen #2008 audit body; it does not reflect current
`master`. No engineer slice should be opened for H3/H4.

If the operator wants *actual ALG helper behavior* (pinholes / payload
doctoring), that is **M6** — a separate, deferred, design-first effort — and
should get its own `/research` under the M6 tracking line. Do not reopen H3/H4
to chase M6.

---

## 11. Reviewer ledger

- Claude SMR hostile self-review: `claude-smr-plan-r1.md` (this branch) —
  attempted to refute the kill (could the flag fail to reach runtime? is the
  "no reader" a real inertness? is M6 secretly H3/H4?) and could not. Verdict:
  PLAN-KILL upheld.
- Codex / AGY: not dispatched. A PLAN-KILL grounded in "the work is already
  merged on master, source-verified at three plumbing layers + the live runtime
  call site + the umbrella's own merged-PR ledger" is a factual determination,
  not an architectural judgment call where adversarial design review adds
  signal. (If the reader disagrees with the kill, the correct escalation is to
  point at a concrete line on `master` where the disable knob is still inert —
  none exists.)
