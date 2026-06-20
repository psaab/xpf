# Hostile plan reviewer A (independent Claude general-purpose) — r1 — #2078

VERDICT: NEEDS-REVISION (leans PLAN-KILL / Path C2; C2 is a clean exit the
plan honestly offers — if reviewers pick C2 the dataplane errors below are
moot).

1. [BLOCKER] The install call-site map in §2/§3 is materially wrong, and the
   "forward-create vs reverse" discriminator model is incomplete. Real
   production sites: `afxdp/shared_ops.rs:743`, `afxdp/forwarding/mod.rs:1112`,
   `afxdp/poll_descriptor/mod.rs:534,1373,1575,2777` (+ wrapper
   `session/install.rs:95`). Plan's four line numbers are all off by
   ~45-135 lines and omit two production sites. The real discriminator is
   `SessionOrigin` (`session/entry.rs:48-59`, 8 variants); the gate MUST be
   `origin == SessionOrigin::ForwardFlow`, not a binary forward/reverse split.
   Critically, `poll_descriptor/mod.rs:895` installs host-bound (firewall-
   local) sessions with `SessionOrigin::LocalMiss` — a non-SYN host-bound TCP
   packet (BGP keepalive/ACK to the box after a restart) would be a LocalMiss
   create; a "drop any non-reverse non-SYN create" gate breaks management/
   control-plane re-attach. Plan never mentions LocalMiss or MissingNeighborSeed.

2. [BLOCKER] `no-syn-check-in-tunnel` keys off the wrong signal.
   `metadata.fabric_ingress` / `ingress_is_fabric`
   (`afxdp/forwarding/mod.rs:293-297`) denotes the HA cross-chassis fabric
   link, NOT a Junos IPsec/GRE security tunnel. The real tunnel signal is the
   GRE-decap path (`stage_native_gre_decap`, `poll_descriptor/mod.rs:165`);
   there is no IPsec/GRE decap-ingress marker on `SessionMetadata`. Using
   `fabric_ingress` would relax syn-check for HA fabric traffic and never fire
   on tunnel traffic. §6 "SMALL" cost for this knob is unsupported. Either
   identify the real tunnel discriminator or scope this knob out.

3. [MAJOR] §4 wire-safety "parity guard" over-states what exists. #1977 guard
   (`flow_numwidth_agreement_test.go`) is a numeric range-agreement test;
   nothing about field-name/presence parity, and bools have no width. No
   Go↔Rust FlowSnapshot field-presence reflection guard exists to "extend."
   The genuine net is the §7 round-trip decode test. (Verified-favorable: no
   `deny_unknown_fields` in `userspace-dp/src/protocol/`, so the
   ignore-unknown-field forward-compat claim holds, and bool+omitempty+
   serde(default) is genuinely the #1961-safe subclass.)

4. [MAJOR] §5 understates rst-invalidate cost: removing a session inside
   `lookup` is not "one branch on an existing arm." The RST arm
   (`session/lookup.rs:70-94`) runs inside a scoped `&mut self.entries` borrow
   that must end before `self.wheel` is touched. Immediate teardown =
   `remove_entry`/secondary-index cleanup after the borrow ends + a close
   delta for HA sync — on the session-hit read path. Bounded but
   borrow-sensitive; re-cost honestly.

5. [MINOR] SYN-cookie interaction unanalyzed (favorable, so MINOR): under
   cookie mode a validated returning ACK is consumed without creating a
   session and the client's next real SYN traverses normal create
   (`afxdp/poll_stages.rs:329-396`) — so syn-check (requires SYN) is
   compatible. Plan should state this explicitly.

6. [MINOR] Line-number drift throughout §1/§2. `session/mod.rs` was split into
   `install.rs`/`lookup.rs`/`expire.rs` (#2005); `install_with_protocol_with_
   origin` is `session/install.rs:113`, `lookup_with_origin` is
   `session/lookup.rs:28`, `session_timeout_ns` is `mod.rs:901`,
   `TCP_FIN/TCP_RST` are `mod.rs:94-95`. Every §2/§3/§9 cite must be
   re-verified.

VERIFIED RIGHT: dead-map (`SetFlowConfig` literal `return nil` in userspace
path); FlowSnapshot gap both sides; no SYN gate at install; RST/FIN only set
closing + 30s; tcp_flags free on fast path; `state.x = snapshot.flow.x` seam
(`forwarding_build/mod.rs:173-181`); HA wire carries protocol+tcp_flags
(`worker/mod.rs:283-284`); Path A correctly rejected; plan honest that C2 is
a defensible PLAN-KILL.

Cost/benefit: concur with the plan's honest framing and lean harder toward
C2. Real harm is silent misleading; C2 removes it at zero risk. Path B, even
correct, touches session-create AND session-hit hot paths for two LOW
rarely-used knobs, and findings 1/2/4 show the surface is larger/subtler than
estimated. Recommend C2 unless an operator concretely needs enforcement; if B
is pursued, re-ground per findings 1-2 first.
