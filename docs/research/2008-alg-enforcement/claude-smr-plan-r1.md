# Claude SMR — HOSTILE plan-review r1 of #2008 H3/H4

**Mandate:** be hostile. Try to overturn the PLAN-KILL. A first-pass
agreeable verdict is a yellow flag, so I attack the kill from every angle a
skeptical reviewer would and only concede if the attacks fail against source.

**Going-in posture:** the request explicitly asserts the dataplane "hardcodes
alg_type:0 and never reads alg_flags." If that assertion is true on `master`,
this is PLAN-READY, not PLAN-KILL, and the plan doc is wrong. I default to
believing the request and force the doc to prove otherwise.

---

## Attack 1 — "The request says alg_type is hardcoded 0. Is it?"

Source on `master` (worktree off `origin/master`):
- `publish_conntrack.rs:108-109` and `:214-215`:
  `let alg_type = alg_type_for_session(key.protocol, key.src_port,
  key.dst_port, alg_disable_flags);` — **not** a literal 0.
- `alg_type_for_session` (`:63`) returns DNS/FTP/SIP codes or NONE based on the
  port and the `disable` bitfield.

The request's "hardcoded 0" describes the **pre-#2015** code. The audit body it
quotes is a frozen snapshot. **Attack fails** — the assertion is stale.

## Attack 2 — "Maybe the disable flag never reaches the runtime call site (tests only)."

This is the strongest possible attack: a fix that only wires the flag through
test helpers but not the production poll loop would be cosmetically 'done' but
actually inert.

Source:
- `poll_descriptor/mod.rs:387-396` — the **live session-create path** in the
  worker poll loop calls `publish_bpf_conntrack_entry(..., 
  worker_ctx.forwarding.alg_disable_flags, app_id)`. Two more identical live
  call sites at ~1130 and ~3112.
- `worker_ctx.forwarding.alg_disable_flags` is set by
  `forwarding_build/mod.rs:202` from `snapshot.flow.alg_disable_flags`, which
  deserializes the wire field from the Go snapshot.
- Go populates it in `flow.go:96` from real config (`cfg.Security.ALG`), not a
  test fixture.

Every hop is production code. **Attack fails.**

## Attack 3 — "alg_type has no reader, so disable enforces nothing — this is inert by another name. PLAN-READY to make it actually do something."

This is the subtle one and I pushed hardest here.

If there were an ALG helper that read `alg_type` to drive pinholes/doctoring,
then a complete H3/H4 would have to gate that helper. If the helper exists and
is NOT gated, the kill is wrong.

Source check for any ALG transform consumer:
- Repo-wide search for pinhole / doctor / data-channel / expected-flow /
  payload-rewrite / process_alg / run_alg in `*.rs`: **no matches** beyond
  `ftp-data` service-name→port lookups in `policy.rs` / `filter/compiler.rs`
  (these map the *string* "ftp-data" to "20" for policy matching — they are not
  an ALG helper).
- `docs/feature-gaps.md` independently lists ALG runtime transforms as absent.
- The umbrella comment thread explicitly: "M6 ... H3/H4 derive `alg_type` but
  **no consumer** reads it; no pinhole/expected-flow/payload-rewrite anywhere."

So there is **no helper to gate**. On a dataplane with zero ALG transforms,
"disable the ALG" can only mean "don't classify the session as an active ALG,"
which is exactly the shipped behavior (alg_type 0 vs non-0, an observable
session-state change, not a no-op).

Could a hostile reviewer still say "then H3/H4 isn't really done until the
helper exists"? No — because building the helper is **M6**, a separately scoped,
separately tracked, deferred gap. Conflating H3/H4 (stop the disable knob being
a silent no-op) with M6 (build stateful ALGs) would be scope-creep that the
umbrella explicitly forbids ("distinct from the simple H3/H4 disable"). The
audit author drew this line deliberately. **Attack fails** — it actually
targets M6, not H3/H4.

## Attack 4 — "Is #2015 really merged to master, or just an unmerged branch?"

- `git log` on the worktree (HEAD = origin/master, `cf9ccd3ac`) contains
  `1ea4057cd Merge pull request #2015 from psaab/refactor/2008-alg-disable-enforce`
  and the three feature commits `067799bc2`, `8170f0d13`, `f6c932e72` in the
  first-parent history.
- The umbrella comment "Tier-1 + Tier-1.5 COMPLETE — 7/7 PRs merged" lists
  "#2015 H3+H4 ALG dns/ftp disable enforcement."

**Attack fails** — merged and on the canonical branch.

## Attack 5 — "Back-compat / wire safety hole that makes it inert in mixed-version HA?"

- Rust `alg_disable_flags` is `#[serde(default)]`; Go field is `omitempty`.
- A new Go binary talking to an old Rust helper: the helper ignores the unknown
  field (serde default 0) → ALG tagged as before (no crash, graceful degrade).
- An old Go binary talking to a new Rust helper: field absent → defaults 0 → no
  disable applied (matches old behavior).
Neither is a *correctness regression in H3/H4*; both are the standard additive-
field contract. **Attack fails** (and anyway this would be a #2015 bug to file,
not new H3/H4 design work).

## Attack 6 — "Should we at least add a runtime smoke proving disable works?"

Optional, not load-bearing. The unit tests already trip if `alg_type` regresses
to 0. A `show security flow session` smoke would be nice-to-have verification,
not enforcement. It does not change the PLAN-KILL: there is no production gap to
close. I note it in plan §8 as optional and decline to make it a blocker.

---

## SMR verdict

**PLAN-KILL — upheld.** Every attack on the kill failed against `master`
source. H3/H4 disable enforcement is implemented (config→wire→runtime), tested
(Go packing/round-trip + Rust forward/reverse/on-off/full-mask + carry guard),
reviewed (full quad on #2015), and merged (`1ea4057cd`). The request's "inert /
hardcoded 0" premise is a stale audit snapshot. The only adjacent live work is
**M6** (stateful ALG transforms), which is a different, larger, deliberately
deferred gap and must not be folded into an H3/H4 slice.

No `/engineer` should run for H3/H4. If real ALG-helper behavior is wanted,
open a fresh `/research` against the M6 line.

**One concession to the request author:** the audit *body* should arguably be
annotated so future readers don't re-trip on the stale "hardcoded 0" sketch —
but the comment thread already records #2015 as the H3/H4 fix, so this is
documentation hygiene, not engineering, and is handled by this research comment.
