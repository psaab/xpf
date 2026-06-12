# Claude SMR hostile plan review — #1884 r5 (plan v5, ba91e16f4a27)

Verdict: **PLAN-NEEDS-REVISION** — one verified counterexample against
my own v5 fold (the r4-driven veto), plus ratification of everything
else. (My r4 PLAN-READY missed three edges the other reviewers caught;
this round I attacked my own fold first.)

## SMR5-1 (MUST FOLD) — veto-clears-claim leaks a permanent stale master on later list removal

Worked trace under v5 as written:
1. Commit 1: `tunnel routing-instance red` ⇒ manager binds,
   `appliedRI[gr-0-0-0] = "red"`.
2. Commit 2: stanza removed, `routing-instances red interface
   gr-0/0/0.0` added ⇒ 0a re-binds vrf-red; A.5 RIListMember veto
   fires ⇒ no unbind, **claim cleared** (v5 lapse case (d)).
3. Commit 3: the list membership is ALSO removed — config wants NO RI
   anywhere. Step 0a only ever binds (daemon_apply.go:218-237 has no
   unbind leg). A.5: `appliedRI` empty ⇒ no unbind. The tunnel stays
   enslaved to vrf-red FOREVER (route lookups in the wrong table)
   until a recreate-class event or manual `ip link set nomaster`.

Today's destructive Apply incidentally unbinds at commit 3 (recreate).
So v5 introduces a real regression in exactly the dimension this plan
exists to reconcile.

**Fix — claim TRANSFER instead of claim clear**: `appliedRI[name]`
tracks the config-DESIRED RI as applied each round:
`stanza RI if nonempty, else RIListMember, else delete-after-unbind`.
Concretely in A.5:
- stanza nonempty ⇒ bind (as now), `appliedRI[name] = stanza RI`;
- stanza empty ∧ RIListMember nonempty ⇒ no bind (0a did it), no
  unbind, `appliedRI[name] = RIListMember` (claim transferred, NOT
  cleared);
- stanza empty ∧ RIListMember empty ∧ appliedRI nonempty ⇒ unbind
  gated by the v5 identity check against `vrf-<appliedRI[name]>`;
  lapse/retention rules unchanged (clear on success / mismatch /
  not-found; retain on transient failure).
Commit 3 then unbinds correctly (claim = red, config wants none,
master == vrf-red). A list-ONLY tunnel (never stanza-bound) also gains
correct unbind-on-list-removal — strictly better reconciliation, still
guarded by the identity check so foreign/out-of-band masters are never
touched. No new state: same map, different update rule.

## Ratifications (attacked, held)

- **Q1 RIListMember population**: scanning `cfg.RoutingInstances`
  with 0a's exact normalization (LinuxIfName + `.0` strip, skip
  forwarding instance-type) is bidirectionally faithful BY
  CONSTRUCTION only if implemented as a shared helper or pinned by a
  test against the 0a loop's literal transform — recommend the §9
  matrix add a fixture with `gr-0/0/0.0`, `gr-0/0/0` (no unit), and a
  forwarding-type RI to pin equivalence. Multi-RI listings of the same
  tunnel: first-match is fine for the veto; under SMR5-1's transfer it
  picks the claim the same way 0a's last bind wins — document
  first-vs-last consistently (0a iterates and the LAST bind wins, so
  the scan should record the LAST match).
- **Reorder rejection**: sound — 0a binds arbitrary member interfaces;
  moving ApplyTunnels ahead of it to fix a tunnel-only edge inverts
  bind/unbind ordering for every other interface class.
- **vrf- prefix / transient retention / create-MTU**: correct folds;
  the create-MTU write also composes with adoption (created ⇒ not
  adopted ⇒ exactly one write path fires).
- **No earlier closure re-opened**: the r4 folds touch A.5's decision
  table, A.3's create path, and §9 only.

## Net

Fold SMR5-1 (one update-rule change + two test rows + the Q1 fixture
pin) ⇒ I am PLAN-READY on the result.
