# Generated policy agreement corpus (#10587)

This directory is the committed bridge between the Rust property harness and the
Go simulator. Rust is the only generator. The Go consumer compiles each
`config_set_lines` row and runs `policymatch.Match`; it never re-generates the
input or uses a second expectation-only matcher.

## Row schema

Each `rows/*.json` file is one pure policy-agreement row. The committed seed
contains exactly 48 rows: the #9167 corpus plus generated boundary shapes for
tiers, address families, exclusions, applications, ports, fragments, ICMP,
defaults, and ordering. `seed_manifest.json` is the pinned 48-ID contract.
Every gate requires all manifest IDs; committed-seed gates also require the
directory to contain exactly 48 rows. To grow the corpus, add the row file,
update `seed_manifest.json`, regenerate `seed_rows.json`, and rerun all three
Rust/Go seed gates before committing the complete set.

```json
{
  "schema_version": 1,
  "id": "stable-row-name",
  "config_set_lines": ["set ..."],
  "query": {
    "from_zone": "trust", "to_zone": "untrust",
    "src_ip": "10.0.1.5", "dst_ip": "10.0.2.5",
    "protocol": "tcp", "src_port": 1234, "dst_port": 80,
    "frag": false, "l4_present": true,
    "icmp_type": null, "icmp_code": null
  },
  "rust_verdict": {
    "action": "permit", "matched": true,
    "default_used": false, "policy_name": "p-allow", "policy_id": 42
  }
}
```

`go_verdict` is present in committed seed rows as a reviewed seed expectation;
rows emitted by a fresh property run MAY omit it. The consumer always computes
its own Go verdict and compares it with the Rust verdict. `policy_id` is
compared only for matched policies: the Go default result uses `0`, while Rust's
default result uses the reserved `u32::MAX` counter internally and serializes
`0` for an unmatched row. `junos-host` local-delivery fall-through has
`matched=false` and `default_used=false` on both sides.

The optional `snapshot` object in committed seed rows is the exact Go-built wire
snapshot consumed by Rust. `TestPolicyGeneratedSeedIsFresh10587` rebuilds it from
`config_set_lines` and rejects drift; it exists so the Rust oracle evaluates the
production snapshot, not a second hand-built matcher input.

## Unsupported tuple boundary

Cross-family IPv4-to-IPv6 forwarding is rejected by the Go forwarding contract
before policy matching. There is no corresponding Rust policy-evaluator
classification, so `boundaries/cross-family-v4-to-v6.json` pins this named
Go-only boundary separately. It is not counted as a differential row and is not
hidden behind a per-row bypass or an allowlist. The Go test compiles the same
configuration and asserts `UnsupportedTupleFamily` directly.

## Files and gates

* `rows/*.json` — pure policy-agreement seed rows.
* `boundaries/*.json` — named pre-policy forwarding contracts.
* `seed_manifest.json` — exact 48-ID seed contract used by every gate.
* `seed_rows.json` — canonical aggregate included by the Rust test binary. The
  Go freshness test requires it to match `rows/*.json` exactly, including
  snapshots.
* `known_divergences.json` — intentionally empty at land. A disagreement is a
  bug and MUST NOT be added here merely to make a soak green.
* `userspace-dp/proptest-regressions/policy_prop_tests/mod.txt` — committed
  proptest persistence file; minimized regressions are replayed before novel
  cases.

Rows are emitted by the opt-in Rust test hook:

```text
XPF_EMIT_POLICY_ROWS=/tmp/policy-generated \
  XPF_EMIT_POLICY_CASES=256 \
  cargo test --manifest-path userspace-dp/Cargo.toml --release \
  --bin xpf-userspace-dp policy_generated_seed_rows_are_fresh_and_emittable_10587
```

The hook writes the committed seed rows plus fresh `generated-NNN` rows. For
generated rows, the Rust strategy supplies concrete `set` lines and a temporary
evaluation snapshot so totality is checked immediately. The generated batch
uses fixed emitter seed `10587`, recorded in each generated row's
`emitter_seed`, so a second run into a fresh directory is byte-identical.
The cross-language pipeline then stamps the exact production snapshot and
recomputes the Rust verdict before comparing:

The aggregate is assembled from the sorted row files; it is not emitted by the
Rust hook. When adding or changing a committed seed, run this from the
repository root, then copy the resulting file into the corpus path:

```text
python3 - <<'PY'
import json
from pathlib import Path
rows = [json.loads(p.read_text()) for p in
        sorted(Path("testdata/policy_generated_corpus/rows").glob("*.json"))]
aggregate = {"_note": "Generated aggregate of rows/*.json; do not hand-edit.",
             "rows": rows, "schema_version": 1}
Path("/tmp/seed_rows.json").write_text(
    json.dumps(aggregate, indent=2, sort_keys=True) + "\n")
PY
cp /tmp/seed_rows.json testdata/policy_generated_corpus/seed_rows.json
```

The Go freshness gate canonicalizes snapshots before comparing the aggregate
and row files, so JSON formatting/key-order changes do not hide semantic drift.
```text
XPF_POLICY_ROWS_DIR=/tmp/policy-generated \
XPF_UPDATE_POLICY_ROWS=1 \
  go test ./pkg/dataplane/userspace -run PolicyGenerated -count=1
XPF_RESTAMP_POLICY_ROWS=/tmp/policy-generated \
  cargo test --manifest-path userspace-dp/Cargo.toml --release \
  --bin xpf-userspace-dp policy_generated_seed_rows_are_fresh_and_emittable_10587
XPF_POLICY_ROWS_DIR=/tmp/policy-generated \
  go test ./pkg/policymatch -run PolicyGenerated -count=1
```

`XPF_POLICY_ROWS_DIR` is independently compiled by Go; no Go verdict is used as
an oracle. A generated row must remain strictly committable: every `set` line
passes `config.CompileConfig`, and every query uses concrete, same-family
addresses.

The Rust harness uses `PROPTEST_CASES` as a soak override. Normal CI uses
bounded per-property defaults. P2/P4/P7 each accept only 2 of the 48 seed rows;
with proptest's default 65,536 local-reject budget, approximately 2,500 cases
is the practical ceiling for those filtered properties. `PROPTEST_CASES=1000`
is the supported soak used for this harness. A deep run records the effective
case count, row count, and disagreement count in the PR/issue report;
disagreements are filed as bugs, not allowlist entries.
