# P-MECH kernel-member boundary recipes F0–F9 + B8 probes (v11 retained)

Pinned recipe store for `kernel-allowlist-7.0.0-30.md` §5. Lane rule
allows only `docs/pr/9506-delta/*.md` writes, so the runnable scripts
live here as verbatim fenced blocks (extraction below) — each block is
the recipe, byte-identical to what P2 lands at the named site (adapted
from probe-shape to gate-shape). Per-boundary outputs were produced by
extracting + running THESE blocks (matrix at the end); content hashes
follow the matrix.

Member pins (identical in every script; `pins_consistency.sh` enforces):

- `UNAME = 7.0.0-30-generic`, `VER = 7.0.0-30.30`
- `TAG = Ubuntu-7.0.0-30.30`, `COMMIT = d974a4063f5c03c13b4f241a9ab511750e0b9f12`
- `BASE_SHA256 = 9dc7c5363c0146a08ba0c9aa834d82c2c6dfbb1c471ad9a2f0aba1189e21be05`
- Image SHA `6f01659e…8e5c2`, modules `d61aa07f…55292`,
  headers `f3be8e8d…f0e14`, buildinfo `24af1791…daa520` (full §1)

Extraction + run (from the worktree root; v11 executed exactly this):

```text
mkdir -p /tmp/f0f9 && awk '/^```(python|sh) [A-Za-z0-9_]+\.(py|sh)$/ {f=$2; cap=1; next} /^```$/ {cap=0; f=""; next} cap && f {print > ("/tmp/f0f9/" f)}' docs/pr/9506-delta/f0f9-recipes.md
chmod +x /tmp/f0f9/*.sh && cd /tmp/f0f9 && REPO=/var/tmp/worktrees/9506-research ./run_all.sh
```

Honesty ledger: scripts F0–F9 + pins + ENOTSOCK EXECUTED here
(build host, read-only). `rxbatched_drift.sh`, `kprobe_sync_proof.sh`,
`ptp_nodefer_cell.sh` are SPECIFIED text for P2 member-kernel
execution — retained, NOT executed (no member USP device/kernel here).

## F0 pin confirmation (bake `dpkg-query` rows vs §0 pins)

P2 site: bake manifest writer + pin checks (`bake.py` beside `:708-721`).

```python f0_pin_check.py
#!/usr/bin/env python3
"""F0: baked kernel rows must EQUAL the repo pins (confirmation, never blank enrollment)."""
import sys
UNAME = "7.0.0-30-generic"
VER = "7.0.0-30.30"
WANT = {
    "linux-image-7.0.0-30-generic": VER,
    "linux-modules-7.0.0-30-generic": VER,
    "linux-headers-7.0.0-30-generic": VER,
}
def check(rows):
    got = dict(r.split("=", 1) for r in rows if "=" in r)
    for pkg, ver in WANT.items():
        if got.get(pkg) != ver:
            return f"FAIL want {pkg}={ver} got {got.get(pkg)!r}"
    return "PASS"
CASES = {
    "member": (["linux-image-7.0.0-30-generic=7.0.0-30.30", "linux-modules-7.0.0-30-generic=7.0.0-30.30", "linux-headers-7.0.0-30-generic=7.0.0-30.30"], "PASS"),
    "revision-skew": (["linux-image-7.0.0-30-generic=7.0.0-30.31", "linux-modules-7.0.0-30-generic=7.0.0-30.30", "linux-headers-7.0.0-30-generic=7.0.0-30.30"], "FAIL"),
    "coherent-B": (["linux-image-7.0.0-31-generic=7.0.0-31.31", "linux-modules-7.0.0-31-generic=7.0.0-31.31", "linux-headers-7.0.0-31-generic=7.0.0-31.31"], "FAIL"),
    "missing-row": (["linux-image-7.0.0-30-generic=7.0.0-30.30", "linux-headers-7.0.0-30-generic=7.0.0-30.30"], "FAIL"),
}
rc = 0
for name, (rows, want) in CASES.items():
    got = check(rows)
    ok = got.startswith(want)
    rc |= not ok
    print(f"F0 {name}: {got} [{'OK' if ok else 'SURPRISE'}]")
sys.exit(rc)
```

## F1 bake member check (single kernel + rows)

P2 site: virt-customize run-commands beside `bake.py:645-646/670-671/676`.

```python f1_bake_check.py
#!/usr/bin/env python3
"""F1: exactly one kernel == member uname AND dpkg rows == pins."""
import sys
UNAME = "7.0.0-30-generic"
VER = "7.0.0-30.30"
def check(modules, rows):
    if modules != [UNAME]:
        return f"FATAL modules={modules}"
    got = dict(r.split("=", 1) for r in rows if "=" in r)
    for pkg in ("linux-image-7.0.0-30-generic", "linux-modules-7.0.0-30-generic", "linux-headers-7.0.0-30-generic"):
        if got.get(pkg) != VER:
            return f"FATAL {pkg}={got.get(pkg)!r}"
    return "PASS"
M = ["linux-image-7.0.0-30-generic=7.0.0-30.30", "linux-modules-7.0.0-30-generic=7.0.0-30.30", "linux-headers-7.0.0-30-generic=7.0.0-30.30"]
CASES = {
    "member": ((["7.0.0-30-generic"], M), "PASS"),
    "coherent-B": ((["7.0.0-31-generic"], [r.replace("7.0.0-30-generic=7.0.0-30.30", "7.0.0-31-generic=7.0.0-31.31") for r in M]), "FATAL"),
    "two-kernels": ((["7.0.0-22-generic", "7.0.0-30-generic"], M), "FATAL"),
    "revision-skew": ((["7.0.0-30-generic"], [M[0].replace("7.0.0-30.30", "7.0.0-30.31"), M[1], M[2]]), "FATAL"),
}
rc = 0
for name, ((mods, rows), want) in CASES.items():
    got = check(mods, rows)
    ok = got.startswith(want)
    rc |= not ok
    print(f"F1 {name}: {got} [{'OK' if ok else 'SURPRISE'}]")
sys.exit(rc)
```

## F2/F3 sign membership (`assert_bake_set`)

P2 site: `scripts/dist/sign.py` (extends `:438-442`). Imports the CURRENT
parser from `$REPO/scripts/dist` (default: relative `scripts/dist`).

```python f2f3_sign_check.py
#!/usr/bin/env python3
"""F2/F3: current nonempty rule (gap demo) vs specified membership rule."""
import os, sys
sys.path.insert(0, os.path.join(os.environ.get("REPO", "."), "scripts", "dist"))
import sign  # noqa: E402  (current parser only; verdict logic below is the recipe)
UNAME = "7.0.0-30-generic"
VER = "7.0.0-30.30"
def current(fields):
    return "SIGN" if fields.get("guest_kernel") else "SignError"
def specified(fields):
    if fields.get("guest_kernel") != UNAME:
        return "SignError(member-mismatch)"
    if fields.get("kernel-source-revision") != VER:
        return "SignError(revision-mismatch)"
    if not fields.get("kernel-allowlist"):
        return "SignError(no-allowlist-key)"
    return "SIGN"
def sidecar(gkern, rev="7.0.0-30.30", allow="7.0.0-30-generic"):
    lines = ["validated: true", "base_image_pinned: true", f"guest_kernel: {gkern}"]
    if rev is not None:
        lines.append(f"kernel-source-revision: {rev}")
    if allow is not None:
        lines.append(f"kernel-allowlist: {allow}")
    return "\n".join(lines) + "\n"
CASES = {
    "member": (sidecar("7.0.0-30-generic"), "SIGN", "SIGN"),
    "coherent-B": (sidecar("7.0.0-31-generic", "7.0.0-31.31", "7.0.0-31-generic"), "SIGN", "SignError"),
    "22-sidecar": (sidecar("7.0.0-22-generic", "7.0.0-22.22", "7.0.0-22-generic"), "SIGN", "SignError"),
    "revision-skew": (sidecar("7.0.0-30-generic", "7.0.0-30.31"), "SIGN", "SignError"),
    "missing-keys": (sidecar("7.0.0-30-generic", None, None), "SIGN", "SignError"),
}
rc = 0
for name, (text, want_cur, want_spec) in CASES.items():
    fields = sign.parse_sidecar_fields(text)
    c, s = current(fields), specified(fields)
    ok = c.startswith(want_cur) and s.startswith(want_spec)
    rc |= not ok
    print(f"F2F3 {name}: current={c} specified={s} [{'OK' if ok else 'SURPRISE'}]")
sys.exit(rc)
```

## F4 publish membership (`gate_provenance`)

P2 site: `scripts/dist/publish.py` (extends the `:711-756` kernel leg).

```python f4_publish_check.py
#!/usr/bin/env python3
"""F4: current agreement-only (gap demo) vs specified pin-equality."""
import sys
UNAME = "7.0.0-30-generic"
VER = "7.0.0-30.30"
def current(gkern, inv_kern):
    if not gkern:
        return "die(no guest_kernel)"
    if inv_kern != gkern:
        return "die(disagree)"
    return "PUBLISH"
def specified(gkern, inv_kern, rows):
    if gkern != UNAME or inv_kern != UNAME:
        return "die(member-mismatch)"
    got = dict(r.split("=", 1) for r in rows if "=" in r)
    for pkg in ("linux-image-7.0.0-30-generic", "linux-modules-7.0.0-30-generic"):
        if got.get(pkg) != VER:
            return "die(pin-mismatch)"
    return "PUBLISH"
M = ["linux-image-7.0.0-30-generic=7.0.0-30.30", "linux-modules-7.0.0-30-generic=7.0.0-30.30"]
B = ["linux-image-7.0.0-31-generic=7.0.0-31.31", "linux-modules-7.0.0-31-generic=7.0.0-31.31"]
CASES = {
    "member-agree": (("7.0.0-30-generic", "7.0.0-30-generic", M), "PUBLISH", "PUBLISH"),
    "coherent-B-agree": (("7.0.0-31-generic", "7.0.0-31-generic", B), "PUBLISH", "die"),
    "skew": (("7.0.0-30-generic", "7.0.0-31-generic", M), "die", "die"),
    "lacks-member-package": (("7.0.0-30-generic", "7.0.0-30-generic", M[:1]), "PUBLISH", "die"),
}
rc = 0
for name, ((g, i, r), want_cur, want_spec) in CASES.items():
    c, s = current(g, i), specified(g, i, r)
    ok = c.startswith(want_cur) and s.startswith(want_spec)
    rc |= not ok
    print(f"F4 {name}: current={c} specified={s} [{'OK' if ok else 'SURPRISE'}]")
sys.exit(rc)
```

## F5 validate/boot (scenario A floor + rows + Kconfig)

P2 site: `scripts/image/validate.py:1185-1230` + live snippet `:1212`.

```python f5_validate_check.py
#!/usr/bin/env python3
"""F5: current floor (gap demo) vs specified exact+rows+Kconfig."""
import re, sys
UNAME = "7.0.0-30-generic"
VER = "7.0.0-30.30"
def current_floor(kver):
    parts = tuple(map(int, kver.split("-")[0].split(".")))
    if parts < (6, 18):
        return "fail(floor)"
    if "-generic" not in kver:
        return "fail(flavor)"
    return "PASS"
def kconfig_ok(config):
    if re.search(r"^[ \t]*CONFIG_4KSTACKS=(m|y)$", config, re.M):
        return False
    for sym in ("CONFIG_BRIDGE", "CONFIG_NF_TABLES_BRIDGE"):
        if not re.search(rf"^[ \t]*{sym}=(m|y)$", config, re.M):
            return False
    return True
def specified(kver, rows, config):
    if kver != UNAME:
        return "fail(member-mismatch)"
    got = dict(r.split("=", 1) for r in rows if "=" in r)
    if got.get("linux-image-7.0.0-30-generic") != VER:
        return "fail(pin-mismatch)"
    if not kconfig_ok(config):
        return "fail(kconfig)"
    return "PASS"
MEMBER_CFG = "CONFIG_VERSION_SIGNATURE=\"Ubuntu 7.0.0-30.30-generic 7.0.12\"\nCONFIG_BRIDGE=m\nCONFIG_NF_TABLES_BRIDGE=m\nCONFIG_TUN=y\n"
M = ["linux-image-7.0.0-30-generic=7.0.0-30.30"]
CASES = {
    "member": (("7.0.0-30-generic", M, MEMBER_CFG), "PASS", "PASS"),
    "coherent-B": (("7.0.0-31-generic", ["linux-image-7.0.0-31-generic=7.0.0-31.31"], MEMBER_CFG), "PASS", "fail"),
    "22-held": (("7.0.0-22-generic", ["linux-image-7.0.0-22-generic=7.0.0-22.22"], MEMBER_CFG), "PASS", "fail"),
    "4kstacks-set": (("7.0.0-30-generic", M, MEMBER_CFG + "CONFIG_4KSTACKS=y\n"), "PASS", "fail"),
}
rc = 0
for name, ((k, r, c), want_cur, want_spec) in CASES.items():
    cf, sp = current_floor(k), specified(k, r, c)
    ok = cf.startswith(want_cur) and sp.startswith(want_spec)
    rc |= not ok
    print(f"F5 {name}: current={cf} specified={sp} [{'OK' if ok else 'SURPRISE'}]")
sys.exit(rc)
```

## F5b/F5c boot/rollback admission (supervisor gate)

P2 site: supervisor OPEN gate (same gate as the mode predicate).

```python f5b_admission.py
#!/usr/bin/env python3
"""F5b/F5c: full-tuple match before OPEN; booted non-member runs, never opens."""
import sys
UNAME = "7.0.0-30-generic"
VER = "7.0.0-30.30"
def admit(booted_u, booted_v, manif_u, manif_v):
    if (booted_u, booted_v, manif_u, manif_v) == (UNAME, VER, UNAME, VER):
        return "OPEN"
    return "SHUT(deny-only+alarm)"
CASES = {
    "member/member": (("7.0.0-30-generic", "7.0.0-30.30") * 2, "OPEN"),
    "F5b-booted-22": (("7.0.0-22-generic", "7.0.0-22.22", "7.0.0-30-generic", "7.0.0-30.30"), "SHUT"),
    "F5c-rollback-22": (("7.0.0-22-generic", "7.0.0-22.22", "7.0.0-22-generic", "7.0.0-22.22"), "SHUT"),
    "revision-skew": (("7.0.0-30-generic", "7.0.0-30.31", "7.0.0-30-generic", "7.0.0-30.30"), "SHUT"),
}
rc = 0
for name, (tup, want) in CASES.items():
    got = admit(*tup)
    ok = got.startswith(want)
    rc |= not ok
    print(f"F5bc {name}: {got} [{'OK' if ok else 'SURPRISE'}]")
sys.exit(rc)
```

## F6/F7 LANE-1 Arm + Gate 2

P2 sites: Arm after `ValidateKernelSegment` (`version.go:124`); Gate 2
(`kernel_run.go:551-558`); promote outer gate. Truth table of the
SPECIFIED predicate (Go LANDED test at P2); current behavior cited
from code reads (gap noted, not executed — no Go harness in lane).

```python f6f7_lane1.py
#!/usr/bin/env python3
"""F6/F7: Arm refuses non-member candidates; Gate 2 requires running in tuple."""
import sys
UNAME = "7.0.0-30-generic"
VER = "7.0.0-30.30"
def arm(candidate_u, candidate_v):
    return "ACCEPT" if (candidate_u, candidate_v) == (UNAME, VER) else "REFUSE"
def gate2(running_u, running_v, candidate_u, candidate_v):
    if (running_u, running_v) != (candidate_u, candidate_v):
        return "REVERT(running!=candidate)"
    if (running_u, running_v) != (UNAME, VER):
        return "REVERT(non-member)"
    return "PROMOTE-PATH"
CASES = {
    "member/member": (("7.0.0-30-generic", "7.0.0-30.30") * 2, "ACCEPT", "PROMOTE-PATH"),
    "F6-candidate-31": (("7.0.0-31-generic", "7.0.0-31.31", "7.0.0-30-generic", "7.0.0-30.30"), "REFUSE", "REVERT"),
    "F7-running-31": (("7.0.0-31-generic", "7.0.0-31.31") * 2, "REFUSE", "REVERT"),
    "running-22-candidate-30": (("7.0.0-30-generic", "7.0.0-30.30", "7.0.0-22-generic", "7.0.0-22.22"), "ACCEPT", "REVERT"),
}
rc = 0
for name, ((cu, cv, ru, rv), want_arm, want_g2) in CASES.items():
    a, g = arm(cu, cv), gate2(ru, rv, cu, cv)
    ok = a.startswith(want_arm) and g.startswith(want_g2)
    rc |= not ok
    print(f"F6F7 {name}: arm={a} gate2={g} [{'OK' if ok else 'SURPRISE'}]")
sys.exit(rc)
```

## F8 Kconfig third predicate (offline + live snippet shapes)

P2 sites: `bridge_floor_10171.py` `_CONFIG_ASSERT` + `bake.py:676` /
`validate.py:1212` call sites. Member excerpt retained verbatim below
(lines from `/usr/lib/linux/7.0.0-30-generic/config`,
full-file SHA256 `b07d3cb0…5233bf6`, re-fetchable per record §7).

```sh f8_kconfig.sh
#!/bin/sh
# F8: CONFIG_4KSTACKS absent-or-n + BRIDGE + NF_TABLES_BRIDGE, both shapes.
set -eu
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/root/boot" "$tmp/live/boot"
cat > "$tmp/root/boot/config-7.0.0-30-generic" <<'EOF'
CONFIG_VERSION_SIGNATURE="Ubuntu 7.0.0-30.30-generic 7.0.12"
CONFIG_BRIDGE=m
CONFIG_NF_TABLES_BRIDGE=m
CONFIG_TUN=y
EOF
cp "$tmp/root/boot/config-7.0.0-30-generic" "$tmp/live/boot/config-7.0.0-30-generic"
printf 'CONFIG_4KSTACKS=y\n' >> "$tmp/live/boot/config-7.0.0-30-generic"
grade=0
check() { # $1 = label, $2 = config path, $3 = want (PASS|FATAL)
  config=$2
  got=PASS
  if [ ! -r "$config" ]; then got=FATAL
  elif grep -Eq '^[[:space:]]*CONFIG_4KSTACKS=(m|y)$' "$config"; then got=FATAL
  elif ! grep -Eq '^[[:space:]]*CONFIG_BRIDGE=(m|y)$' "$config"; then got=FATAL
  elif ! grep -Eq '^[[:space:]]*CONFIG_NF_TABLES_BRIDGE=(m|y)$' "$config"; then got=FATAL
  fi
  if [ "$got" = "$3" ]; then echo "F8 $1: $got [OK]"; else echo "F8 $1: $got want $3 [SURPRISE]"; grade=1; fi
}
check "offline-member" "$tmp/root/boot/config-7.0.0-30-generic" PASS
check "live-4kstacks-set" "$tmp/live/boot/config-7.0.0-30-generic" FATAL
check "missing-file" "$tmp/root/boot/config-absent" FATAL
exit $grade
```

## F9 review linkage (record quotes pins verbatim)

P2 site: reviewed-commit discipline + `pins_consistency.sh` in CI.

```sh f9_linkage.sh
#!/bin/sh
# F9: this record quotes the member strings verbatim; a non-member record is VOID.
set -eu
record="${RECORD:-docs/pr/9506-delta/kernel-allowlist-7.0.0-30.md}"
[ -f "$record" ] || { echo "F9 record-missing: $record [SURPRISE]"; exit 1; }
grade=0
for s in 7.0.0-30-generic 7.0.0-30.30 Ubuntu-7.0.0-30.30 d974a4063; do
  if grep -qF "$s" "$record"; then echo "F9 quotes-$s: PRESENT [OK]";
  else echo "F9 quotes-$s: ABSENT [SURPRISE]"; grade=1; fi
done
tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
sed 's/7\.0\.0-30/7.0.0-31/g' "$record" > "$tmp"
if grep -q '7.0.0-30-generic' "$tmp"; then echo "F9 negative-control: BROKEN [SURPRISE]"; grade=1;
else echo "F9 negative-control: -31-substituted copy lacks member strings → VOID [OK]"; fi
exit $grade
```

## pins consistency (all recipes pin identical values)

```sh pins_consistency.sh
#!/bin/sh
# Every recipe pins the same uname/version/tag; drift fails loudly.
set -eu
d="${1:-.}"
grade=0
for f in f0_pin_check.py f1_bake_check.py f2f3_sign_check.py f4_publish_check.py f5_validate_check.py f5b_admission.py f6f7_lane1.py; do
  for pin in 7.0.0-30-generic 7.0.0-30.30; do
    grep -qF "$pin" "$d/$f" || { echo "pins $f lacks $pin [SURPRISE]"; grade=1; }
  done
done
[ "$grade" = 0 ] && echo "pins: unanimous across 7 recipes [OK]"
exit $grade
```

## ENOTSOCK probe (B8 — sendmsg unreachable on USP char fd)

Retains fd/device identity + raw output. Positive control on the
member kernel/USP device is P2 (same script, `$TUNDEV`).

```python enotsock_probe.py
#!/usr/bin/env python3
"""B8: sendmsg on the TUN char fd must fail ENOTSOCK (errno 88), never hold."""
import os, platform, socket, stat, sys
dev = os.environ.get("TUNDEV", "/dev/net/tun")
st = os.stat(dev)
print(f"device: {dev} mode={oct(stat.S_IMODE(st.st_mode))} rdev={os.major(st.st_rdev)}:{os.minor(st.st_rdev)}")
print(f"host: {platform.uname().release} {platform.uname().version[:64]}")
fd = os.open(dev, os.O_RDWR)
print(f"fd: char fd opened O_RDWR (fd={fd})")
try:
    s = socket.fromfd(fd, socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendmsg([b"x" * 100])
        print("sendmsg: SUCCEEDED [SURPRISE — hazard reachable]")
        rc = 1
    finally:
        s.detach()
except OSError as e:
    ok = e.errno == 88
    print(f"socket-op: errno={e.errno} ({e.strerror}) [{'OK' if ok else 'SURPRISE'}]")
    rc = 0 if ok else 1
finally:
    os.close(fd)
sys.exit(rc)
```

## rx_batched drift fixture (SPECIFIED for P2 — NOT executed here)

Requires a member USP device + ethtool; retained as specified text.

```sh rxbatched_drift.sh
#!/bin/sh
# B8 drift: ethtool-set rx_max_coalesced_frames=64 while OPEN → P-MECH must
# revoke+fence+freeze (drift path). P2 executes on the member appliance.
set -eu
dev="${USPDEV:-xpf-usp0}"
ethtool -C "$dev" rx-frames 64
val=$(ethtool -c "$dev" | awk '/rx-frames:/{print $2; exit}')
[ "$val" = "64" ] || { echo "drift: set did not stick (got $val)"; exit 2; }
echo "drift: rx-frames=64 armed on $dev; P2 asserts supervisor revoke+fence+freeze within one audit tick"
```

## kprobe sync-proof (SPECIFIED for P2 — NOT executed here)

Member kernel + root + BPF required. v4+v6 windows inside
`tun_chr_write_iter`; ANY missing path/observation/readback keeps
permits CLOSED (P2-entry evidence contract).

```sh kprobe_sync_proof.sh
#!/bin/sh
# B8 timing bar (bpftrace sketch; P2 lands + executes on the member kernel):
# tracepoint/sched/sched_process_exit excluded; probes:
#   kprobe:tun_chr_write_iter { @w_enter[tid] = nsecs; }
#   kretprobe:tun_chr_write_iter { @w_exit[tid] = nsecs; }
#   kprobe:ip_forward { @f4[tid] = nsecs; } kretprobe:ip_forward { @f4x[tid] = nsecs; }
#   kprobe:ip6_forward { @f6[tid] = nsecs; } kretprobe:ip6_forward { @f6x[tid] = nsecs; }
# Assert per xpf-shape write, BOTH families: w_enter < f_entry < f_exit < w_exit.
# Missing probe, missing observation, or window violation → permits stay CLOSED.
set -eu
echo "kprobe contract retained; P2 executes on member kernel (not run here)"
exit 3
```

## PTP no-defer cell (SPECIFIED for P2 — NOT executed here)

```sh ptp_nodefer_cell.sh
#!/bin/sh
# B7-ts adversarial: PTP-class frame through USP must route inline (no
# skb_defer_rx_timestamp stall/drop — phydev NULL). P2 executes on member:
# inject PTP UDP/319+320 inner frames both families, assert forward disposition
# within the write window (kprobe above) + no phydev symlink present.
set -eu
echo "ptp cell retained; P2 executes on member kernel (not run here)"
exit 3
```

## Runner (executes the HERE set; P2-only listed, never faked)

```sh run_all.sh
#!/bin/sh
set -u
cd "$(dirname "$0")"
grade=0
for t in f0_pin_check.py f1_bake_check.py f2f3_sign_check.py f4_publish_check.py f5_validate_check.py f5b_admission.py f6f7_lane1.py; do
  python3 "$t" || grade=1
done
REPO="${REPO:-.}" sh f8_kconfig.sh || grade=1
RECORD="${RECORD:-$REPO/docs/pr/9506-delta/kernel-allowlist-7.0.0-30.md}" sh f9_linkage.sh || grade=1
sh pins_consistency.sh . || grade=1
python3 enotsock_probe.py || grade=1
echo "--- P2-only (retained, not executed here) ---"
echo "rxbatched_drift.sh kprobe_sync_proof.sh ptp_nodefer_cell.sh: SPECIFIED (exit 3 = not-run-here)"
[ "$grade" = 0 ] && echo "MATRIX: ALL-HERE-OK" || echo "MATRIX: SURPRISES-PRESENT"
exit $grade
```

## Per-boundary output matrix (v11 — extracted + executed)

Executed 2026-09-27 on the build host (`7.0.13+deb14-amd64`, read-only)
via the extraction command at the top (`REPO=/var/tmp/worktrees/9506-research`).
Exit 0. (Host is NOT the member — member-kernel positive controls are P2.)

```text
F0 member: PASS [OK]
F0 revision-skew: FAIL want linux-image-7.0.0-30-generic=7.0.0-30.30 got '7.0.0-30.31' [OK]
F0 coherent-B: FAIL want linux-image-7.0.0-30-generic=7.0.0-30.30 got None [OK]
F0 missing-row: FAIL want linux-modules-7.0.0-30-generic=7.0.0-30.30 got None [OK]
F1 member: PASS [OK]
F1 coherent-B: FATAL modules=['7.0.0-31-generic'] [OK]
F1 two-kernels: FATAL modules=['7.0.0-22-generic', '7.0.0-30-generic'] [OK]
F1 revision-skew: FATAL linux-image-7.0.0-30-generic='7.0.0-30.31' [OK]
F2F3 member: current=SIGN specified=SIGN [OK]
F2F3 coherent-B: current=SIGN specified=SignError(member-mismatch) [OK]
F2F3 22-sidecar: current=SIGN specified=SignError(member-mismatch) [OK]
F2F3 revision-skew: current=SIGN specified=SignError(revision-mismatch) [OK]
F2F3 missing-keys: current=SIGN specified=SignError(revision-mismatch) [OK]
F4 member-agree: current=PUBLISH specified=PUBLISH [OK]
F4 coherent-B-agree: current=PUBLISH specified=die(member-mismatch) [OK]
F4 skew: current=die(disagree) specified=die(member-mismatch) [OK]
F4 lacks-member-package: current=PUBLISH specified=die(pin-mismatch) [OK]
F5 member: current=PASS specified=PASS [OK]
F5 coherent-B: current=PASS specified=fail(member-mismatch) [OK]
F5 22-held: current=PASS specified=fail(member-mismatch) [OK]
F5 4kstacks-set: current=PASS specified=fail(kconfig) [OK]
F5bc member/member: OPEN [OK]
F5bc F5b-booted-22: SHUT(deny-only+alarm) [OK]
F5bc F5c-rollback-22: SHUT(deny-only+alarm) [OK]
F5bc revision-skew: SHUT(deny-only+alarm) [OK]
F6F7 member/member: arm=ACCEPT gate2=PROMOTE-PATH [OK]
F6F7 F6-candidate-31: arm=REFUSE gate2=REVERT(running!=candidate) [OK]
F6F7 F7-running-31: arm=REFUSE gate2=REVERT(non-member) [OK]
F6F7 running-22-candidate-30: arm=ACCEPT gate2=REVERT(running!=candidate) [OK]
F8 offline-member: PASS [OK]
F8 live-4kstacks-set: FATAL [OK]
F8 missing-file: FATAL [OK]
F9 quotes-7.0.0-30-generic: PRESENT [OK]
F9 quotes-7.0.0-30.30: PRESENT [OK]
F9 quotes-Ubuntu-7.0.0-30.30: PRESENT [OK]
F9 quotes-d974a4063: PRESENT [OK]
F9 negative-control: -31-substituted copy lacks member strings → VOID [OK]
pins: unanimous across 7 recipes [OK]
device: /dev/net/tun mode=0o666 rdev=10:200
host: 7.0.13+deb14-amd64 #1 SMP PREEMPT_DYNAMIC Debian 7.0.13-1 (2026-06-19)
fd: char fd opened O_RDWR (fd=3)
socket-op: errno=88 (Socket operation on non-socket) [OK]
--- P2-only (retained, not executed here) ---
rxbatched_drift.sh kprobe_sync_proof.sh ptp_nodefer_cell.sh: SPECIFIED (exit 3 = not-run-here)
MATRIX: ALL-HERE-OK
```

Content hashes (sha256sum of the extracted files, same run):

```text
01f149e441909173fcdb160d4f181ffeff27a4b9ba464099886937028f17a71f enotsock_probe.py
41036eb2997c32c0febf4fd31f4081d9ad1a2ff1481a9a4fec88ccc909464b55 f0_pin_check.py
75a3964b7ab9e9eb4a579985c83049a1d0bcc5460030a24769fdbbf9fe76d2b2 f1_bake_check.py
02df89eef0f201d4563c53e76e82ca0e652f2fc462b53e81b8a1cfafc4bbc32e f2f3_sign_check.py
0017ae1ec3aef725966046b098477e38b2b5f1b75f69e129e5ed00e380e00cd2 f4_publish_check.py
596ddbf18e77b75e9d0a663c4d5850c0b2faeb77a0e5c95816d35a26ec7440f1 f5_validate_check.py
b5f6d33593047d32baa32901bea676ed01d74c3e987b0682aa2848a53b1a8523 f5b_admission.py
e5a784b7ffd79fbda8d89a48b6a5855c5b6b9706338150c2870d6d04fff431ad f6f7_lane1.py
c42c9cf92a6776aedc3069bddf417538f81c333721ddcd9072b8de337baf3193 f8_kconfig.sh
d585c50db9ed489f7367ab254429305912d46dd10bdc7982c63f8dbabb766d93 f9_linkage.sh
12f74807917db7470a06e8d0fae168a3ea002e13e2868d4bc7e86c39dd607dc5 kprobe_sync_proof.sh
57cb7c425b7a587b3b6b1101bab5d73badce63bc98f3aad52c8e8f25c08dab8e pins_consistency.sh
464042e3e840746390f993b5d82bdd2a57b3d18e5693ee91db3106fb3f60f6c8 ptp_nodefer_cell.sh
0614a1f2920ac3eb1aae67f2c85bbd98d43bdf459131365741b2a50899b75cb5 run_all.sh
e454636fc804e043b6f95843b39c19d8f37e3ecf7553bc725271c3af3690f3f6 rxbatched_drift.sh
```
