# Claude SMR hostile plan review — #1884 r3 (plan v3, 26e5bdfdf20b)

Verdict: **PLAN-READY**.

I attacked each v3 fold and the five §11 r3 questions. No fold re-opens
an r1/r2 closure; no new structural defect found. One transition
behavior is documented below as accepted (Q2) — it is today-parity and
self-healing, not a regression.

## Fold verification

- **oldOwned adoption authority (Codex r2 F1 / SMR2-1)**: the v3 A.1
  pseudo-code snapshots `oldOwned := t.ownedNames` before building
  `next`, and A.3 computes `adopting := !oldOwned[tc.Name]` once,
  consumed by BOTH reuse paths. The EEXIST-race-on-owned-name case now
  correctly suppresses the MTU write (§9 test 2 pins it). Closed.
- **Desired-MTU adoption (Codex r2 F2)**: strictly stronger than the v2
  bounce story — no dependence on compiler ordering OR zone membership.
  Consumer check: `TunnelConfig` is consumed by daemon_run/routing/cli/
  config compiler/dataplane compiler/userspace tunnels only — no
  cluster or grpcapi serialization (HA config sync is TEXT-based), no
  field iteration; `String()` redaction lists fields explicitly and an
  additive int cannot leak a secret. Closed.
- **appliedRI (Codex r2 F3)**: unbind is now provably scoped to
  manager-bound masters; the 0a-list bind survives (improvement over
  today's recreate destroying it every apply). Closed.
- **appliedAddrs AddrDel-failure retention (F4) / ownedNames
  LinkDel-failure retention (F5)**: both specified with retry-until-
  success-or-absence semantics and §9 tests 4/5 pin them. Closed.
- **SMR2-2**: stopKeepaliveLocked = cancel + drain + map delete, pinned
  by §9 test 4 (GetKeepaliveState returns nil). Closed.

## §11 round-3 answers

1. **MTU precedence/consumers**: `unit.MTU > 0 ? unit.MTU : ifc.MTU`
   matches the compiler's unit-overrides-interface rule
   (compiler_iface.go:545-553 "unit-level MTU overrides
   interface-level"). Consumers verified additive-safe (above). A
   precedence mismatch in a pathological config (unzoned unit-level
   tunnel with both MTUs set) could leave a once-written adoption MTU
   that differs from what the compiler would choose — but an unzoned
   tunnel passes no traffic, and the zoned case is corrected by the
   compiler in the same run. Acceptable.
2. **appliedRI vs 0a-replacement**: sequence stanza-RI=blue →
   (operator moves tunnel to RI red's interface LIST and deletes the
   stanza) → that apply: 0a binds red, A.5 sees appliedRI=blue ∧
   stanza empty ⇒ unbinds (clearing red for one cycle), clears the
   entry; NEXT apply: 0a rebinds red, appliedRI empty ⇒ never unbound
   again. Today's code destroys the red bind on EVERY apply (recreate
   after 0a); v3 mis-unbinds on exactly the transition apply and then
   converges. Bind-wins-last is acceptable; documenting this trace in
   the PR is sufficient.
3. **ownedNames growth bound**: retention happens only inside the
   `LinkByName == nil-err` branch on a failed LinkDel; a name whose
   link is gone out-of-band takes the not-found path and is dropped.
   Bounded by links that EXIST and refuse deletion — which is the set
   we must keep retrying anyway. No unbounded growth.
4. **Upgrade-boot adoption**: pre-fix anchors carry MTU 1500 (old code
   never set anchor MTU at create; any config MTU was applied by the
   compiler and equals tc.MTU). The single adoption write is therefore
   either a no-op (values equal) or the correct repair. No harm found.
5. **r1 closures**: keepalive skip-on-down (A.7), applied-set LL rule
   (A.4), NO_PI/persist checks (A.3), identity normalization (A.7),
   EEXIST kernel-fetched adoption (A.3) — all textually intact in v3;
   the folds touched A.1/A.3-MTU/A.5 only. Nothing re-opened.

## Residuals (accepted, §10)

Restart-window leaks (stale anchors, stale configured-LL, stale-RI on
adopted anchors), same-name external replacement between applies
(today-parity), WG configured-LL follow-up. None regress current
behavior.
