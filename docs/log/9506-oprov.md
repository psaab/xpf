# #9506 O-PROV provenance observer

## Implementation

The T12/G2 harness observer in `test/incus/t12-g2-9506.sh` now joins Rust provenance to the Go witness by `(run_id, generation, permit_epoch)`. It validates the four exact divert classes (inet forward/input and bridge forward/input), PF family coverage, queue and owner metadata, stN/ifindex metadata, and disposition buckets. Boolean family/hook metadata is rejected before integer dictionary lookup. Rust rows from older permit epochs are reported as `stale_samples` rather than being attributed to the current tuple. Malformed epochs and unknown classes are not silently accepted. Missing surfaces remain unavailable instead of becoming authoritative zeroes; an omitted `s5_reinject.provenance` array is an authoritative empty bounded witness.

Hermetic selftests cover the exact-class map, unknown class and operator poisoning, missing-vs-zero witnesses, mixed stale/current epochs, malformed rows, missing surfaces, and `accepted`/`would_reinject` aliases. Verification completed with:

```text
bash -n test/incus/t12-g2-9506.sh                 # passed
t12-g2-9506 selftest: 63 passed, 0 failed
```


Implementation commits:

- `13cf42d72` — exact provenance epoch join + parser/provenance validation gaps (bool guard + poison/alias cells)

## Attested replacement run

The first run archive, `/var/tmp/xpf-t12-g2-9506-1789873002`, is forensic only. It used the pre-fix observer and exited 2 at the restore-block syntax error before the global restore block. Its pre observer reported `packet_samples=26` and `prov_mismatch=26`; its post observer reported `packet_samples=30`, `prov_mismatch=26`, and `counter_mismatch=1`. It produced no `T12_G2_RESTORE` line, so restore was unverified. The run attributed stale rows to the current permit epoch and is not exactness evidence.

The authorized continuation first compared both nodes with the archived normalized baselines and found both configurations matching with no fixture residue. The canonical deploy then left both normalized configurations and residue probes clean. The worktree was clean at `13cf42d72` (the attested run executed its amended predecessor; the observer differs only by the bool guard and added poison/alias selftest cells, which the run's inputs never exercised — behaviorally equivalent on the attested evidence).

```text
local_just_built_sha = cf654836b131f1b6e7f27794a92bcc7058dc32afac32259791a02bae
fw0_exe_sha           = cf654836b131f1b6e7f27794a92bcc7058dc32afac32259791a02bae
fw1_exe_sha           = cf654836b131f1b6e7f27794a92bcc7058dc32afac32259791a02bae
exe_check              = MATCH
```

The replacement archive is `/var/tmp/xpf-t12-g2-9506-1789874972`. Its provenance observer reported, for both firewalls, one current packet row, zero stale rows, zero malformed rows, four static/provenance classes, `prov_mismatch=0`, and `pf_mismatch=0`. The live disposition witness reported `counter_mismatch=1`: the current Go tuple had `adjudicated=1`, `reinjected=0`, `written=0`, `uncertain=1`, `late=1`, and `timeouts=1`, while its bounded Rust row was classified as written/reinjected. The mismatch is retained in the evidence rather than suppressed. All 30 T12 cells were `VOID` for measurement-incomplete or harness-void reasons; no cell was marked pass or fail. The run exited with status 2 because all cells were void.

Restore and release completed cleanly:

```text
T12_G2_RESTORE fw0_config_cmp=1 fw1_config_cmp=1 fw0_residue_clear=1 fw1_residue_clear=1 residue_probe_error=0 archive=/var/tmp/xpf-t12-g2-9506-1789874972
```

The deployment lesson is that an executable hash must be compared as build-immediately-before-deploy versus both running `/proc/PID/exe` hashes. A historical binary hash is not stable because `buildTime` is embedded in `xpfd`.
