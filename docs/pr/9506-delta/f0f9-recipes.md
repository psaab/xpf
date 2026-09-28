# P-MECH kernel-member boundary recipes F0–F9 + B8 probes (v14 contract)

Pinned recipe store for `kernel-allowlist-7.0.0-30.md` §5. Lane rule
allows only `docs/pr/9506-delta/*.md` writes, so runnable truth-table
fixtures live here as fenced blocks. These blocks specify the complete
behavioral matrix; they are NOT claimed to be byte-identical to eventual
Go/bake/kernel-site implementation. Any adaptation at a LANDED boundary
must preserve and execute the same full matrix, with the adapted test
assertions reviewed against these fixtures. Per-boundary outputs recorded
below come from extracting and running the scripts named in the ledger.

v14 contract: EVERY boundary's LANDED test consumes and compares EACH
observable tuple field (member A + coherent `-31` B + coherent same-Uname
B + INDEPENDENT per-field mismatches), across every supplied kernel row;
it covers missing/malformed config and the exact boundary-pinned tuple.
The repo-level LANDED `pins_consistency` agreement test (distinct from
the recipe-only helper at the bottom of this file) MUST compare
`bake.py` `PINNED_BASE_*`, Go pin constants, and the recipe pin tuple.
A subset matrix, stale artifact, or pin disagreement is not a PASS.
Fields genuinely unobservable at a boundary are named in that recipe's
docstring with the already-enforced dependency that covers them (record
§5 observability table is normative).

Member pins are identical in every recipe script; the bottom
`pins_consistency.sh` checks only that per-script pin map.

- `UNAME = 7.0.0-30-generic`, `VER = 7.0.0-30.30`
- `TAG = Ubuntu-7.0.0-30.30`, `COMMIT = d974a4063f5c03c13b4f241a9ab511750e0b9f12`
- `BASE_SHA256 = 9dc7c5363c0146a08ba0c9aa834d82c2c6dfbb1c471ad9a2f0aba1189e21be05`
- `KSRC` (canonical `kernel-source-revision` serialization — sorted
  comma-joined `pkg=ver`, record §2 normative):
  `linux-headers-7.0.0-30-generic=7.0.0-30.30,linux-image-7.0.0-30-generic=7.0.0-30.30,linux-modules-7.0.0-30-generic=7.0.0-30.30`
- Image SHA `6f01659e…8e5c2`, modules `d61aa07f…55292`,
  headers `f3be8e8d…f0e14`, buildinfo `24af1791…daa520` (full §1)

Extraction + run (from the worktree root; v12 executed exactly this):

```text
mkdir -p /tmp/f0f9 && awk '/^```(python|sh) [A-Za-z0-9_]+\.(py|sh)$/ {f=$2; cap=1; next} /^```$/ {cap=0; f=""; next} cap && f {print > ("/tmp/f0f9/" f)}' docs/pr/9506-delta/f0f9-recipes.md
chmod +x /tmp/f0f9/*.sh && cd /tmp/f0f9 && REPO=/var/tmp/worktrees/9506-research USE_SUDO=1 ./run_all.sh
```

Honesty ledger: scripts F0–F9 + pins + ENOTSOCK EXECUTED here
(build host, read-only; ENOTSOCK bind leg under `sudo -n`, device
removed on close). `rxbatched_drift.sh`, `kprobe_sync_proof.sh`,
`ptp_nodefer_cell.sh` are SPECIFIED text for P2 member-kernel
execution — retained, NOT executed (no member USP device/kernel here).

## F0 pin confirmation (bake `dpkg-query` rows vs §0 pins)

P2 site: bake manifest writer + pin checks (`bake.py` beside `:708-721`).
Observes: installed package rows. Unobservable here: uname (F1, same
bake), Kconfig (F8-offline, same bake), base digest (sidecar leg,
sign/publish chain).

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
M = ["linux-image-7.0.0-30-generic=7.0.0-30.30", "linux-modules-7.0.0-30-generic=7.0.0-30.30", "linux-headers-7.0.0-30-generic=7.0.0-30.30"]
def skew(i, v="7.0.0-30.31"):
    r = list(M); r[i] = r[i].rsplit("=", 1)[0] + "=" + v; return r
SAMEU = ["linux-image-7.0.0-30-generic=7.0.0-30.31", "linux-modules-7.0.0-30-generic=7.0.0-30.31", "linux-headers-7.0.0-30-generic=7.0.0-30.31"]
COHB = ["linux-image-7.0.0-31-generic=7.0.0-31.31", "linux-modules-7.0.0-31-generic=7.0.0-31.31", "linux-headers-7.0.0-31-generic=7.0.0-31.31"]
CASES = {
    "member-A": (M, "PASS"),
    "coherent-B-31": (COHB, "FAIL"),
    "coherent-same-uname-B": (SAMEU, "FAIL"),
    "image-only-skew": (skew(0), "FAIL"),
    "modules-only-skew": (skew(1), "FAIL"),
    "headers-only-skew": (skew(2), "FAIL"),
    "missing-row": ([M[0], M[2]], "FAIL"),
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
Observes: `/lib/modules` dir set + dpkg rows. Unobservable here:
Kconfig (F8-offline), base digest (sidecar leg).

```python f1_bake_check.py
#!/usr/bin/env python3
"""F1: exactly one kernel == member uname AND all three dpkg rows == pins."""
import sys
UNAME = "7.0.0-30-generic"
VER = "7.0.0-30.30"
PKGS = ("linux-image-7.0.0-30-generic", "linux-modules-7.0.0-30-generic", "linux-headers-7.0.0-30-generic")
def check(modules, rows):
    if modules != [UNAME]:
        return f"FATAL modules={modules}"
    got = dict(r.split("=", 1) for r in rows if "=" in r)
    for pkg in PKGS:
        if got.get(pkg) != VER:
            return f"FATAL {pkg}={got.get(pkg)!r}"
    return "PASS"
M = [f"{p}={VER}" for p in PKGS]
def skew(i, v="7.0.0-30.31"):
    r = list(M); r[i] = r[i].rsplit("=", 1)[0] + "=" + v; return r
CASES = {
    "member-A": ((["7.0.0-30-generic"], M), "PASS"),
    "coherent-B-31": ((["7.0.0-31-generic"], [f"{p.replace('7.0.0-30', '7.0.0-31')}=7.0.0-31.31" for p in PKGS]), "FATAL"),
    "coherent-same-uname-B": ((["7.0.0-30-generic"], [r.rsplit('=', 1)[0] + "=7.0.0-30.31" for r in M]), "FATAL"),
    "two-kernels": ((["7.0.0-22-generic", "7.0.0-30-generic"], M), "FATAL"),
    "image-only-skew": ((["7.0.0-30-generic"], skew(0)), "FATAL"),
    "modules-only-skew": ((["7.0.0-30-generic"], skew(1)), "FATAL"),
    "headers-only-skew": ((["7.0.0-30-generic"], skew(2)), "FATAL"),
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
Observes: full sidecar (guest_kernel, kernel-allowlist,
kernel-source-revision, validated, base_image_pinned,
base_image_sha256) + file set. Unobservable here: Kconfig (F8),
.pkgs rows (publish F4 dependency — sign checks the sidecar record,
publish checks the inventory record; both vs PIN).

```python f2f3_sign_check.py
#!/usr/bin/env python3
"""F2/F3: current nonempty rule (gap demo) vs specified full-field membership."""
import os, sys
sys.path.insert(0, os.path.join(os.environ.get("REPO", "."), "scripts", "dist"))
import sign  # noqa: E402  (current parser only; verdict logic below is the recipe)
UNAME = "7.0.0-30-generic"
VER = "7.0.0-30.30"
BASE_SHA256 = "9dc7c5363c0146a08ba0c9aa834d82c2c6dfbb1c471ad9a2f0aba1189e21be05"
WANT_ROWS = {
    "linux-image-7.0.0-30-generic": VER,
    "linux-modules-7.0.0-30-generic": VER,
    "linux-headers-7.0.0-30-generic": VER,
}
def parse_ksrc(value):
    """Canonical KSRC grammar: sorted comma-joined pkg=ver. Unparseable -> None."""
    try:
        rows = dict(part.split("=", 1) for part in value.split(",") if part)
    except ValueError:
        return None
    if set(rows) != set(WANT_ROWS):
        return None
    return rows
def current(fields):
    return "SIGN" if fields.get("guest_kernel") else "SignError"
def specified(fields):
    if fields.get("guest_kernel") != UNAME:
        return "SignError(member-mismatch)"
    if fields.get("kernel-allowlist") != UNAME:
        return "SignError(allowlist-mismatch)"
    rows = parse_ksrc(fields.get("kernel-source-revision", ""))
    if rows is None:
        return "SignError(revision-unparseable)"
    for pkg, ver in WANT_ROWS.items():
        if rows.get(pkg) != ver:
            return f"SignError(revision-mismatch:{pkg})"
    if fields.get("validated") != "true":
        return "SignError(unvalidated)"
    if fields.get("base_image_pinned") != "true":
        return "SignError(unpinned-base)"
    if fields.get("base_image_sha256") != BASE_SHA256:
        return "SignError(base-digest-mismatch)"
    return "SIGN"
def ksrc(image="7.0.0-30.30", modules="7.0.0-30.30", headers="7.0.0-30.30", abi="7.0.0-30"):
    return ",".join(sorted([
        f"linux-headers-{abi}-generic={headers}",
        f"linux-image-{abi}-generic={image}",
        f"linux-modules-{abi}-generic={modules}",
    ]))
def sidecar(gkern, rev="PIN", allow="7.0.0-30-generic", base="PIN", valid="true", pinned="true"):
    if rev == "PIN":
        rev = ksrc()
    lines = [f"validated: {valid}", f"base_image_pinned: {pinned}",
             f"base_image_sha256: {BASE_SHA256 if base == 'PIN' else base}",
             f"guest_kernel: {gkern}"]
    if rev is not None:
        lines.append(f"kernel-source-revision: {rev}")
    if allow is not None:
        lines.append(f"kernel-allowlist: {allow}")
    return "\n".join(lines) + "\n"
CASES = {
    "member-A": (sidecar("7.0.0-30-generic"), "SIGN", "SIGN"),
    "coherent-B-31": (sidecar("7.0.0-31-generic", ksrc("7.0.0-31.31", "7.0.0-31.31", "7.0.0-31.31", "7.0.0-31"), "7.0.0-31-generic"), "SIGN", "SignError"),
    "coherent-same-uname-B": (sidecar("7.0.0-30-generic", ksrc("7.0.0-30.31", "7.0.0-30.31", "7.0.0-30.31")), "SIGN", "SignError"),
    "image-only-skew": (sidecar("7.0.0-30-generic", ksrc("7.0.0-30.31")), "SIGN", "SignError"),
    "modules-only-skew": (sidecar("7.0.0-30-generic", ksrc(modules="7.0.0-30.31")), "SIGN", "SignError"),
    "headers-only-skew": (sidecar("7.0.0-30-generic", ksrc(headers="7.0.0-30.31")), "SIGN", "SignError"),
    "wrong-nonempty-allowlist": (sidecar("7.0.0-30-generic", allow="7.0.0-31-generic"), "SIGN", "SignError"),
    "base-digest-skew": (sidecar("7.0.0-30-generic", base="0" * 64), "SIGN", "SignError"),
    "malformed-revision": (sidecar("7.0.0-30-generic", rev="linux-image-7.0.0-30-generic"), "SIGN", "SignError"),
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
Observes: verified sidecar fields (guest_kernel, kernel-source-revision
string, kernel-allowlist, validated, base pins — `publish.py:663-667`)
+ verified `.pkgs` (inv_kern + full rows incl `xpf=<ver>` —
`:728-734`). Manifest KSRC and inventory rows are consumed as TWO
INDEPENDENT collections, each parsed and compared vs PIN (v13
Fix-1a). Unobservable here: Kconfig (F5/F8 live dependency),
running state (F5b/boot dependency).

```python f4_publish_check.py
#!/usr/bin/env python3
"""F4: current agreement-only (gap demo) vs specified both-records-vs-PIN.

Consumes the manifest kernel-source-revision (canonical §2 serialization,
parsed per-package) AND the inventory rows INDEPENDENTLY — a manifest-only
skew with inventory-A unchanged must die (v13 Fix-1a)."""
import sys
UNAME = "7.0.0-30-generic"
VER = "7.0.0-30.30"
BASE_SHA256 = "9dc7c5363c0146a08ba0c9aa834d82c2c6dfbb1c471ad9a2f0aba1189e21be05"
PKGS = ("linux-image-7.0.0-30-generic", "linux-modules-7.0.0-30-generic", "linux-headers-7.0.0-30-generic")
def parse_ksrc(value):
    """Canonical kernel-source-revision grammar: sorted comma-joined pkg=ver, exact set."""
    try:
        rows = dict(part.split("=", 1) for part in value.split(",") if part)
    except ValueError:
        return None
    if set(rows) != set(PKGS):
        return None
    return rows
def ksrc(image="7.0.0-30.30", modules="7.0.0-30.30", headers="7.0.0-30.30", abi="7.0.0-30"):
    return ",".join(sorted([
        f"linux-headers-{abi}-generic={headers}",
        f"linux-image-{abi}-generic={image}",
        f"linux-modules-{abi}-generic={modules}",
    ]))
def current(gkern, inv_kern):
    if not gkern:
        return "die(no guest_kernel)"
    if inv_kern != gkern:
        return "die(disagree)"
    return "PUBLISH"
def specified(gkern, manif_ksrc, inv_kern, inv_rows, allow, base, ver):
    if gkern != UNAME or inv_kern != UNAME:
        return "die(member-mismatch)"
    if allow != UNAME:
        return "die(allowlist-mismatch)"
    if base != BASE_SHA256:
        return "die(base-digest-mismatch)"
    mrows = parse_ksrc(manif_ksrc)
    if mrows is None:
        return "die(manifest-revision-unparseable)"
    for p in PKGS:
        if mrows.get(p) != VER:
            return f"die(manifest-skew:{p})"
    got = dict(r.split("=", 1) for r in inv_rows if "=" in r)
    for p in PKGS:
        if got.get(p) != VER:
            return f"die(pin-mismatch:{p})"
    if [e.partition("=")[2] for e in inv_rows if e.partition("=")[0] == "xpf"] != [ver]:
        return "die(xpf-identity-mismatch)"
    if gkern != inv_kern:
        return "die(tamper-disagree)"
    return "PUBLISH"
M = [f"{p}={VER}" for p in PKGS] + ["xpf=0.0.test"]
def skewm(rows, i, v="7.0.0-30.31"):
    r = list(rows); r[i] = r[i].rsplit("=", 1)[0] + "=" + v; return r
B = [f"{p.replace('7.0.0-30', '7.0.0-31')}=7.0.0-31.31" for p in PKGS] + ["xpf=0.0.test"]
SAMEU = [f"{p}=7.0.0-30.31" for p in PKGS] + ["xpf=0.0.test"]
KSRC_B = ksrc("7.0.0-31.31", "7.0.0-31.31", "7.0.0-31.31", "7.0.0-31")
KSRC_SAMEU = ksrc("7.0.0-30.31", "7.0.0-30.31", "7.0.0-30.31")
CASES = {
    "member-A": (("7.0.0-30-generic", ksrc(), "7.0.0-30-generic", M, "7.0.0-30-generic", BASE_SHA256), "PUBLISH", "PUBLISH"),
    "coherent-B-31": (("7.0.0-31-generic", KSRC_B, "7.0.0-31-generic", B, "7.0.0-31-generic", BASE_SHA256), "PUBLISH", "die"),
    "coherent-same-uname-B": (("7.0.0-30-generic", KSRC_SAMEU, "7.0.0-30-generic", SAMEU, "7.0.0-30-generic", BASE_SHA256), "PUBLISH", "die"),
    "inv-image-only-skew": (("7.0.0-30-generic", ksrc(), "7.0.0-30-generic", skewm(M, 0), "7.0.0-30-generic", BASE_SHA256), "PUBLISH", "die"),
    "inv-modules-only-skew": (("7.0.0-30-generic", ksrc(), "7.0.0-30-generic", skewm(M, 1), "7.0.0-30-generic", BASE_SHA256), "PUBLISH", "die"),
    "inv-headers-only-skew": (("7.0.0-30-generic", ksrc(), "7.0.0-30-generic", skewm(M, 2), "7.0.0-30-generic", BASE_SHA256), "PUBLISH", "die"),
    "manifest-image-only-skew": (("7.0.0-30-generic", ksrc("7.0.0-30.31"), "7.0.0-30-generic", M, "7.0.0-30-generic", BASE_SHA256), "PUBLISH", "die"),
    "manifest-modules-only-skew": (("7.0.0-30-generic", ksrc(modules="7.0.0-30.31"), "7.0.0-30-generic", M, "7.0.0-30-generic", BASE_SHA256), "PUBLISH", "die"),
    "manifest-headers-only-skew": (("7.0.0-30-generic", ksrc(headers="7.0.0-30.31"), "7.0.0-30-generic", M, "7.0.0-30-generic", BASE_SHA256), "PUBLISH", "die"),
    "manifest-unparseable": (("7.0.0-30-generic", "linux-image-7.0.0-30-generic", "7.0.0-30-generic", M, "7.0.0-30-generic", BASE_SHA256), "PUBLISH", "die"),
    "manifest-inv-rows-disagree": (("7.0.0-30-generic", ksrc(), "7.0.0-30-generic", SAMEU, "7.0.0-30-generic", BASE_SHA256), "PUBLISH", "die"),
    "allowlist-skew": (("7.0.0-30-generic", ksrc(), "7.0.0-30-generic", M, "7.0.0-31-generic", BASE_SHA256), "PUBLISH", "die"),
    "manifest-inventory-uname-disagree": (("7.0.0-30-generic", ksrc(), "7.0.0-31-generic", M, "7.0.0-30-generic", BASE_SHA256), "die", "die"),
}
rc = 0
for name, ((g, k, i, r, a, b), want_cur, want_spec) in CASES.items():
    c, s = current(g, i), specified(g, k, i, r, a, b, "0.0.test")
    ok = c.startswith(want_cur) and s.startswith(want_spec)
    rc |= not ok
    print(f"F4 {name}: current={c} specified={s} [{'OK' if ok else 'SURPRISE'}]")
sys.exit(rc)
```

## F5 validate/boot (scenario A floor + rows + Kconfig)

P2 site: `scripts/image/validate.py:1185-1230` + live snippet `:1212`.
Observes: guest `uname -r`, guest dpkg rows, guest `/boot/config`,
single `/lib/modules` dir. Retained existing checks (dependency, not
replaced): mlx5 driver dir, `-generic` flavor, hold assert.

```python f5_validate_check.py
#!/usr/bin/env python3
"""F5: current floor (gap demo) vs specified exact+rows+Kconfig+single-dir."""
import re, sys
UNAME = "7.0.0-30-generic"
VER = "7.0.0-30.30"
PKGS = ("linux-image-7.0.0-30-generic", "linux-modules-7.0.0-30-generic", "linux-headers-7.0.0-30-generic")
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
def specified(kver, rows, config, modules):
    if kver != UNAME:
        return "fail(member-mismatch)"
    if modules != [UNAME]:
        return "fail(multi-kernel)"
    got = dict(r.split("=", 1) for r in rows if "=" in r)
    for p in PKGS:
        if got.get(p) != VER:
            return f"fail(pin-mismatch:{p})"
    if not kconfig_ok(config):
        return "fail(kconfig)"
    return "PASS"
MEMBER_CFG = "CONFIG_VERSION_SIGNATURE=\"Ubuntu 7.0.0-30.30-generic 7.0.12\"\nCONFIG_BRIDGE=m\nCONFIG_NF_TABLES_BRIDGE=m\nCONFIG_TUN=y\n"
M = [f"{p}={VER}" for p in PKGS]
def skew(i, v="7.0.0-30.31"):
    r = list(M); r[i] = r[i].rsplit("=", 1)[0] + "=" + v; return r
SAMEU = [f"{p}=7.0.0-30.31" for p in PKGS]
CASES = {
    "member-A": (("7.0.0-30-generic", M, MEMBER_CFG, ["7.0.0-30-generic"]), "PASS", "PASS"),
    "coherent-B-31": (("7.0.0-31-generic", [f"{p.replace('7.0.0-30', '7.0.0-31')}=7.0.0-31.31" for p in PKGS], MEMBER_CFG, ["7.0.0-31-generic"]), "PASS", "fail"),
    "coherent-same-uname-B": (("7.0.0-30-generic", SAMEU, MEMBER_CFG, ["7.0.0-30-generic"]), "PASS", "fail"),
    "image-only-skew": (("7.0.0-30-generic", skew(0), MEMBER_CFG, ["7.0.0-30-generic"]), "PASS", "fail"),
    "modules-only-skew": (("7.0.0-30-generic", skew(1), MEMBER_CFG, ["7.0.0-30-generic"]), "PASS", "fail"),
    "headers-only-skew": (("7.0.0-30-generic", skew(2), MEMBER_CFG, ["7.0.0-30-generic"]), "PASS", "fail"),
    "missing-modules-headers": (("7.0.0-30-generic", [M[0]], MEMBER_CFG, ["7.0.0-30-generic"]), "PASS", "fail"),
    "4kstacks-set": (("7.0.0-30-generic", M, MEMBER_CFG + "CONFIG_4KSTACKS=y\n", ["7.0.0-30-generic"]), "PASS", "fail"),
    "two-kernels": (("7.0.0-30-generic", M, MEMBER_CFG, ["7.0.0-22-generic", "7.0.0-30-generic"]), "PASS", "fail"),
}
rc = 0
for name, ((k, r, c, m), want_cur, want_spec) in CASES.items():
    cf, sp = current_floor(k), specified(k, r, c, m)
    ok = cf.startswith(want_cur) and sp.startswith(want_spec)
    rc |= not ok
    print(f"F5 {name}: current={cf} specified={sp} [{'OK' if ok else 'SURPRISE'}]")
sys.exit(rc)
```

## F5b/F5c boot/rollback admission (supervisor OPEN gate)

P2 site: supervisor OPEN gate (same gate as the mode predicate).
Observes: booted uname + booted dpkg rows + live Kconfig + manifest
sidecar tuple (guest_kernel, kernel-source-revision rows,
kernel-allowlist). Unobservable here: base digest (bake-time;
dependency: sign F2/F3 + publish F4 chain verified the booted
image before it exists).

```python f5b_admission.py
#!/usr/bin/env python3
"""F5b/F5c: booted-tuple AND manifest-tuple, every field vs pins, before OPEN."""
import sys
UNAME = "7.0.0-30-generic"
VER = "7.0.0-30.30"
PKGS = ("linux-image-7.0.0-30-generic", "linux-modules-7.0.0-30-generic", "linux-headers-7.0.0-30-generic")
def rows_ok(rows):
    got = dict(r.split("=", 1) for r in rows if "=" in r)
    return all(got.get(p) == VER for p in PKGS)
def admit(booted_u, booted_rows, booted_kcfg_ok, manif_u, manif_rows, manif_allow):
    if booted_u != UNAME:
        return "SHUT(booted-uname)"
    if not rows_ok(booted_rows):
        return "SHUT(booted-rows)"
    if not booted_kcfg_ok:
        return "SHUT(booted-kconfig)"
    if manif_u != UNAME:
        return "SHUT(manifest-uname)"
    if not rows_ok(manif_rows):
        return "SHUT(manifest-rows)"
    if manif_allow != UNAME:
        return "SHUT(manifest-allowlist)"
    return "OPEN"
M = [f"{p}={VER}" for p in PKGS]
def skew(rows, i, v="7.0.0-30.31"):
    r = list(rows); r[i] = r[i].rsplit("=", 1)[0] + "=" + v; return r
CASES = {
    "member-A": (("7.0.0-30-generic", M, True, "7.0.0-30-generic", M, "7.0.0-30-generic"), "OPEN"),
    "coherent-B-31": (("7.0.0-31-generic", [f"{p.replace('7.0.0-30', '7.0.0-31')}=7.0.0-31.31" for p in PKGS], True, "7.0.0-31-generic", [f"{p.replace('7.0.0-30', '7.0.0-31')}=7.0.0-31.31" for p in PKGS], "7.0.0-31-generic"), "SHUT"),
    "coherent-same-uname-B": (("7.0.0-30-generic", [f"{p}=7.0.0-30.31" for p in PKGS], True, "7.0.0-30-generic", [f"{p}=7.0.0-30.31" for p in PKGS], "7.0.0-30-generic"), "SHUT"),
    "F5b-booted-22": (("7.0.0-22-generic", [f"{p.replace('7.0.0-30', '7.0.0-22')}=7.0.0-22.22" for p in PKGS], True, "7.0.0-30-generic", M, "7.0.0-30-generic"), "SHUT"),
    "F5c-rollback-22": (("7.0.0-22-generic", [f"{p.replace('7.0.0-30', '7.0.0-22')}=7.0.0-22.22" for p in PKGS], True, "7.0.0-22-generic", [f"{p.replace('7.0.0-30', '7.0.0-22')}=7.0.0-22.22" for p in PKGS], "7.0.0-22-generic"), "SHUT"),
    "booted-modules-only-skew": (("7.0.0-30-generic", skew(M, 1), True, "7.0.0-30-generic", M, "7.0.0-30-generic"), "SHUT"),
    "booted-kconfig-bad": (("7.0.0-30-generic", M, False, "7.0.0-30-generic", M, "7.0.0-30-generic"), "SHUT"),
    "manifest-headers-only-skew": (("7.0.0-30-generic", M, True, "7.0.0-30-generic", skew(M, 2), "7.0.0-30-generic"), "SHUT"),
    "manifest-allowlist-skew": (("7.0.0-30-generic", M, True, "7.0.0-30-generic", M, "7.0.0-31-generic"), "SHUT"),
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

P2 sites: Arm after `ValidateKernelSegment` (`version.go:124` —
charset/path only, not membership); Gate 2 (`kernel_run.go:551-558`);
promote outer gate. Arm observes the candidate (`uname -r` + dpkg rows
from the candidate inventory + journal fields); Kconfig of the
NON-BOOTED candidate is unobservable at Arm. Exact version/package rows
and bake F8 pin the approved member config, but SAME-VERSION/DIFFERENT-
BINARY runtime content integrity is explicitly OUT OF MODEL (see
`kernel-allowlist-7.0.0-30.md` §6); no same-bits claim is made.
Gate 2 runs AFTER boot and observes running `uname -r`, running dpkg rows,
RUNNING Kconfig (`/boot/config-$(uname -r)`, `_CONFIG_ASSERT` shape), and
journal candidate; its predicate requires `running==candidate` on full
rows, reviewed-member membership, and the running Kconfig.
The required `verifyAndPromote` call path covers normal Gate-2 entry
(`kernel_run.go:551-558`) and BootCurrent-unreadable recovery
(`kernel_run.go:524-531`).
A LANDED wiring test injects unreadable `BootCurrent` with
`running==candidate` and invalid live Kconfig (e.g. `CONFIG_4KSTACKS=y`);
the shared gate must REVERT and never promote. Also test bad running
package rows. The recipe below proves only the predicate, not that call
path. Base digest is unobservable at both (publish-chain dependency).
Current code is cited from the gap review; the Go LANDED predicate and
wiring tests remain P2 entry gates.

```python f6f7_lane1.py
#!/usr/bin/env python3
"""F6/F7: candidate full-tuple at Arm; running full-tuple + running Kconfig at Gate 2."""
import re, sys
UNAME = "7.0.0-30-generic"
VER = "7.0.0-30.30"
PKGS = ("linux-image-7.0.0-30-generic", "linux-modules-7.0.0-30-generic", "linux-headers-7.0.0-30-generic")
def rows_ok(rows):
    got = dict(r.split("=", 1) for r in rows if "=" in r)
    return all(got.get(p) == VER for p in PKGS)
def kconfig_ok(config):
    if re.search(r"^[ \t]*CONFIG_4KSTACKS=(m|y)$", config, re.M):
        return False
    for sym in ("CONFIG_BRIDGE", "CONFIG_NF_TABLES_BRIDGE"):
        if not re.search(rf"^[ \t]*{sym}=(m|y)$", config, re.M):
            return False
    return True
def arm(cand_u, cand_rows):
    if cand_u != UNAME:
        return "REFUSE(candidate-uname)"
    if not rows_ok(cand_rows):
        return "REFUSE(candidate-rows)"
    return "ACCEPT"
def gate2(run_u, run_rows, run_kconfig, cand_u, cand_rows):
    if run_u != cand_u or dict(r.split("=", 1) for r in run_rows) != dict(r.split("=", 1) for r in cand_rows):
        return "REVERT(running!=candidate)"
    if run_u != UNAME or not rows_ok(run_rows):
        return "REVERT(non-member)"
    if not kconfig_ok(run_kconfig):
        return "REVERT(kconfig)"
    return "PROMOTE-PATH"
M = [f"{p}={VER}" for p in PKGS]
MEMBER_CFG = "CONFIG_VERSION_SIGNATURE=\"Ubuntu 7.0.0-30.30-generic 7.0.12\"\nCONFIG_BRIDGE=m\nCONFIG_NF_TABLES_BRIDGE=m\nCONFIG_TUN=y\n"
BAD_CFG = MEMBER_CFG + "CONFIG_4KSTACKS=y\n"
def rows31():
    return [f"{p.replace('7.0.0-30', '7.0.0-31')}=7.0.0-31.31" for p in PKGS]
def rows22():
    return [f"{p.replace('7.0.0-30', '7.0.0-22')}=7.0.0-22.22" for p in PKGS]
def skew(rows, i, v="7.0.0-30.31"):
    r = list(rows); r[i] = r[i].rsplit("=", 1)[0] + "=" + v; return r
SAMEU = [f"{p}=7.0.0-30.31" for p in PKGS]
CASES = {
    "member-A": (("7.0.0-30-generic", M, MEMBER_CFG, "7.0.0-30-generic", M), "ACCEPT", "PROMOTE-PATH"),
    "coherent-B-31": (("7.0.0-31-generic", rows31(), MEMBER_CFG, "7.0.0-31-generic", rows31()), "REFUSE", "REVERT"),
    "coherent-same-uname-B": (("7.0.0-30-generic", SAMEU, MEMBER_CFG, "7.0.0-30-generic", SAMEU), "REFUSE", "REVERT"),
    "F6-candidate-31-running-30": (("7.0.0-31-generic", rows31(), MEMBER_CFG, "7.0.0-30-generic", M), "REFUSE", "REVERT"),
    "F7-running-31": (("7.0.0-31-generic", rows31(), MEMBER_CFG, "7.0.0-31-generic", rows31()), "REFUSE", "REVERT"),
    "candidate-modules-only-skew": (("7.0.0-30-generic", skew(M, 1), MEMBER_CFG, "7.0.0-30-generic", M), "REFUSE", "REVERT"),
    "running-headers-only-skew": (("7.0.0-30-generic", M, MEMBER_CFG, "7.0.0-30-generic", skew(M, 2)), "ACCEPT", "REVERT"),
    "running-kconfig-bad": (("7.0.0-30-generic", M, BAD_CFG, "7.0.0-30-generic", M), "ACCEPT", "REVERT"),
    "running-22-candidate-30": (("7.0.0-30-generic", M, MEMBER_CFG, "7.0.0-22-generic", rows22()), "ACCEPT", "REVERT"),
}
rc = 0
for name, ((cu, cr, rk, ru, rr), want_arm, want_g2) in CASES.items():
    a, g = arm(cu, cr), gate2(ru, rr, rk, cu, cr)
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
grep -v '^CONFIG_BRIDGE=' "$tmp/root/boot/config-7.0.0-30-generic" > "$tmp/root/boot/config-nobridge"
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
check "bridge-absent" "$tmp/root/boot/config-nobridge" FATAL
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

## Recipe-script pin-map consistency (recipe fixture only)

This extracted helper verifies only that the F0–F9 scripts share their
own pinned values; it does not compare repository `bake.py` or Go
constants. The separate repo-level LANDED agreement test above owns that
cross-source assertion.

```sh pins_consistency.sh
#!/bin/sh
# Each gate recipe pins every value its predicate compares; drift fails loudly.
set -eu
d="${1:-.}"
grade=0
need() { # $1 = file, $2.. = pins that must appear verbatim
  f=$1; shift
  for pin in "$@"; do
    grep -qF "$pin" "$d/$f" || { echo "pins $f lacks $pin [SURPRISE]"; grade=1; }
  done
}
U=7.0.0-30-generic; V=7.0.0-30.30
BASE=9dc7c5363c0146a08ba0c9aa834d82c2c6dfbb1c471ad9a2f0aba1189e21be05
need f0_pin_check.py "$U" "$V"
need f1_bake_check.py "$U" "$V"
need f2f3_sign_check.py "$U" "$V" "$BASE" kernel-source-revision kernel-allowlist
need f4_publish_check.py "$U" "$V" "$BASE" kernel-source-revision
need f5_validate_check.py "$U" "$V" CONFIG_4KSTACKS
need f5b_admission.py "$U" "$V"
need f6f7_lane1.py "$U" "$V" CONFIG_4KSTACKS
need f8_kconfig.sh CONFIG_4KSTACKS CONFIG_BRIDGE 7.0.0-30.30
need f9_linkage.sh 7.0.0-30-generic 7.0.0-30.30 Ubuntu-7.0.0-30.30 d974a4063
need enotsock_probe.py TUNSETIFF ENOTSOCK INCOMPLETE
[ "$grade" = 0 ] && echo "pins: per-script pin map holds [OK]"
exit $grade
```

## ENOTSOCK probe (B8 — corrected positive-control procedure)

Stages (each attributed; shared-handler acceptance FORBIDDEN):
SETUP binds a temp TUN via TUNSETIFF `IFF_TUN|IFF_NO_PI` (mirrors
`slowpath.rs:2234-2242`; needs CAP_NET_ADMIN — `USE_SUDO=1` re-execs
under `sudo -n`; EPERM without it reports BIND-SKIPPED explicitly,
never OK-by-absence). SEND issues the RAW `sendmsg(2)` syscall via
ctypes on the bound fd (no `socket.fromfd` wrapper in this path).
WRAPPER drives `socket.fromfd` as the EXPECTED-WRAPPER-FAILURE
control. NULLCTL repeats both calls on `/dev/null` (known
non-socket signature). PAIRECTL proves the harness observes success
(socketpair `sendmsg` bytes). P2 re-runs on the member kernel/USP
device; the recipe asserts the same contract there.

```python enotsock_probe.py
#!/usr/bin/env python3
"""B8 corrected: TUNSETIFF-bound fd + raw-sendmsg errno attribution + controls."""
import ctypes
import fcntl
import glob
import os
import platform
import socket
import stat
import struct
import sys
TUNSETIFF = 0x400454ca
IFF_TUN, IFF_NO_PI = 0x0001, 0x1000
ENOTSOCK = 88
if os.environ.get("USE_SUDO") == "1" and os.geteuid() != 0:
    os.execvp("sudo", ["sudo", "-n", sys.executable] + sys.argv)
class IOV(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]
class Msghdr(ctypes.Structure):
    _fields_ = [("name", ctypes.c_void_p), ("namelen", ctypes.c_uint32),
                ("pad0", ctypes.c_uint32), ("iov", ctypes.POINTER(IOV)),
                ("iovlen", ctypes.c_size_t), ("control", ctypes.c_void_p),
                ("controllen", ctypes.c_size_t), ("flags", ctypes.c_int)]
libc = ctypes.CDLL("libc.so.6", use_errno=True)
def raw_sendmsg(fd, payload=b"x" * 100):
    """Issue sendmsg(2) directly. Returns (ret, errno-or-None). No wrapper."""
    buf = ctypes.create_string_buffer(payload)
    iov = IOV(ctypes.cast(buf, ctypes.c_void_p), len(payload))
    msg = Msghdr(None, 0, 0, ctypes.pointer(iov), 1, None, 0, 0)
    ctypes.set_errno(0)
    ret = libc.sendmsg(fd, ctypes.byref(msg), 0)
    return (ret, ctypes.get_errno() if ret < 0 else None)
def check(label, cond, detail):
    print(f"{label}: {detail} [{'OK' if cond else 'SURPRISE'}]")
    return 0 if cond else 1
rc = 0
dev = os.environ.get("TUNDEV", "/dev/net/tun")
st = os.stat(dev)
print(f"device: {dev} mode={oct(stat.S_IMODE(st.st_mode))} rdev={os.major(st.st_rdev)}:{os.minor(st.st_rdev)}")
print(f"host: {platform.uname().release} euid={os.geteuid()}")
fd = os.open(dev, os.O_RDWR | os.O_CLOEXEC)
print(f"fd: char fd opened O_RDWR|O_CLOEXEC (fd={fd})")
bound_name = None
bound_ok = False
try:
    name = ("v13en%d" % (os.getpid() % 100000)).encode()[:15]
    flags = IFF_TUN | IFF_NO_PI
    ifr = struct.pack("16sH22s", name, flags, b"\x00" * 22)
    try:
        fcntl.ioctl(fd, TUNSETIFF, ifr)
        bound_name = name.decode()
        node = f"/sys/class/net/{bound_name}"
        bound_ok = os.path.isdir(node)
        rc |= check("SETUP-bind", bound_ok, f"TUNSETIFF {bound_name} flags=0x{flags:04x} sysfs={bound_ok}")
    except OSError as e:
        print(f"SETUP-bind: SKIPPED errno={e.errno} ({e.strerror}) — P2-only leg (needs CAP_NET_ADMIN)")
    ret, err = raw_sendmsg(fd)
    rc |= check("SEND-raw-sendmsg", ret < 0 and err == ENOTSOCK,
                f"syscall ret={ret} errno={err} ({os.strerror(err) if err else 'n/a'}) on {'bound' if bound_name else 'unbound'} fd")
    # NOTE: no socket.fromfd on the TUN fd: fromfd dup()s internally and
    # leaks the dup when the constructor raises, which would pin the device
    # and break CLEANUP. Wrapper behavior is fd-type-generic: proven below
    # on /dev/null, where a leaked dup is harmless.
    nfd = os.open("/dev/null", os.O_RDWR)
    try:
        nret, nerr = raw_sendmsg(nfd)
        rc |= check("NULLCTL-send", nret < 0 and nerr == ENOTSOCK, f"errno={nerr}")
        try:
            s = socket.fromfd(os.dup(nfd), socket.AF_INET, socket.SOCK_DGRAM)
            s.close()
            rc |= check("WRAPPER-fromfd", False, "SUCCEEDED (unexpected)")
        except OSError as e:
            rc |= check("WRAPPER-fromfd", e.errno == ENOTSOCK,
                        f"constructor errno={e.errno} (expected wrapper failure, distinct from SEND)")
    finally:
        os.close(nfd)
    a, b = socket.socketpair()
    try:
        n = a.sendmsg([b"x" * 10])
        rc |= check("PAIRECTL-success", n == 10, f"socketpair sendmsg sent {n} bytes")
    finally:
        a.close()
        b.close()
finally:
    os.close(fd)
if bound_name:
    gone = not glob.glob(f"/sys/class/net/{bound_name}")
    rc |= check("CLEANUP-device-removed", gone, f"{bound_name} removed={gone}")
if rc:
    print("ENOTSOCK-STATUS: FAILED")
    sys.exit(1)
if not bound_ok:
    print("ENOTSOCK-STATUS: INCOMPLETE (bound-fd leg missing — not P2 evidence)")
    sys.exit(4)
print("ENOTSOCK-STATUS: COMPLETE (bound member-USP-shape fd + controls + cleanup)")
sys.exit(0)
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
python3 enotsock_probe.py; eno=$?
echo "--- P2-only (retained, not executed here) ---"
echo "rxbatched_drift.sh kprobe_sync_proof.sh ptp_nodefer_cell.sh: SPECIFIED (exit 3 = not-run-here)"
if [ "$grade" != 0 ] || { [ "$eno" != 0 ] && [ "$eno" != 4 ]; }; then
  echo "MATRIX: SURPRISES-PRESENT"; exit 1
elif [ "$eno" = 4 ]; then
  echo "MATRIX: INCOMPLETE (bound-fd leg missing — not P2 evidence)"; exit 4
else
  echo "MATRIX: ALL-HERE-OK"; exit 0
fi
```

## Per-boundary output matrix (v13 — extracted + executed)

Executed 2026-09-27 on the build host (`7.0.13+deb14-amd64`, read-only;
ENOTSOCK bind leg under `sudo -n`, device removed on close) via the extraction
command at the top (`REPO=/var/tmp/worktrees/9506-research USE_SUDO=1`).
Exit 0. (Host is NOT the member — member-kernel positive controls are P2.)
No-sudo variant: exit 4 with `MATRIX: INCOMPLETE (bound-fd leg missing —
not P2 evidence)` and zero surprises (bound leg SKIPPED explicitly).

```text
F0 member-A: PASS [OK]
F0 coherent-B-31: FAIL want linux-image-7.0.0-30-generic=7.0.0-30.30 got None [OK]
F0 coherent-same-uname-B: FAIL want linux-image-7.0.0-30-generic=7.0.0-30.30 got '7.0.0-30.31' [OK]
F0 image-only-skew: FAIL want linux-image-7.0.0-30-generic=7.0.0-30.30 got '7.0.0-30.31' [OK]
F0 modules-only-skew: FAIL want linux-modules-7.0.0-30-generic=7.0.0-30.30 got '7.0.0-30.31' [OK]
F0 headers-only-skew: FAIL want linux-headers-7.0.0-30-generic=7.0.0-30.30 got '7.0.0-30.31' [OK]
F0 missing-row: FAIL want linux-modules-7.0.0-30-generic=7.0.0-30.30 got None [OK]
F1 member-A: PASS [OK]
F1 coherent-B-31: FATAL modules=['7.0.0-31-generic'] [OK]
F1 coherent-same-uname-B: FATAL linux-image-7.0.0-30-generic='7.0.0-30.31' [OK]
F1 two-kernels: FATAL modules=['7.0.0-22-generic', '7.0.0-30-generic'] [OK]
F1 image-only-skew: FATAL linux-image-7.0.0-30-generic='7.0.0-30.31' [OK]
F1 modules-only-skew: FATAL linux-modules-7.0.0-30-generic='7.0.0-30.31' [OK]
F1 headers-only-skew: FATAL linux-headers-7.0.0-30-generic='7.0.0-30.31' [OK]
F2F3 member-A: current=SIGN specified=SIGN [OK]
F2F3 coherent-B-31: current=SIGN specified=SignError(member-mismatch) [OK]
F2F3 coherent-same-uname-B: current=SIGN specified=SignError(revision-mismatch:linux-image-7.0.0-30-generic) [OK]
F2F3 image-only-skew: current=SIGN specified=SignError(revision-mismatch:linux-image-7.0.0-30-generic) [OK]
F2F3 modules-only-skew: current=SIGN specified=SignError(revision-mismatch:linux-modules-7.0.0-30-generic) [OK]
F2F3 headers-only-skew: current=SIGN specified=SignError(revision-mismatch:linux-headers-7.0.0-30-generic) [OK]
F2F3 wrong-nonempty-allowlist: current=SIGN specified=SignError(allowlist-mismatch) [OK]
F2F3 base-digest-skew: current=SIGN specified=SignError(base-digest-mismatch) [OK]
F2F3 malformed-revision: current=SIGN specified=SignError(revision-unparseable) [OK]
F2F3 missing-keys: current=SIGN specified=SignError(allowlist-mismatch) [OK]
F4 member-A: current=PUBLISH specified=PUBLISH [OK]
F4 coherent-B-31: current=PUBLISH specified=die(member-mismatch) [OK]
F4 coherent-same-uname-B: current=PUBLISH specified=die(manifest-skew:linux-image-7.0.0-30-generic) [OK]
F4 inv-image-only-skew: current=PUBLISH specified=die(pin-mismatch:linux-image-7.0.0-30-generic) [OK]
F4 inv-modules-only-skew: current=PUBLISH specified=die(pin-mismatch:linux-modules-7.0.0-30-generic) [OK]
F4 inv-headers-only-skew: current=PUBLISH specified=die(pin-mismatch:linux-headers-7.0.0-30-generic) [OK]
F4 manifest-image-only-skew: current=PUBLISH specified=die(manifest-skew:linux-image-7.0.0-30-generic) [OK]
F4 manifest-modules-only-skew: current=PUBLISH specified=die(manifest-skew:linux-modules-7.0.0-30-generic) [OK]
F4 manifest-headers-only-skew: current=PUBLISH specified=die(manifest-skew:linux-headers-7.0.0-30-generic) [OK]
F4 manifest-unparseable: current=PUBLISH specified=die(manifest-revision-unparseable) [OK]
F4 manifest-inv-rows-disagree: current=PUBLISH specified=die(pin-mismatch:linux-image-7.0.0-30-generic) [OK]
F4 allowlist-skew: current=PUBLISH specified=die(allowlist-mismatch) [OK]
F4 manifest-inventory-uname-disagree: current=die(disagree) specified=die(member-mismatch) [OK]
F5 member-A: current=PASS specified=PASS [OK]
F5 coherent-B-31: current=PASS specified=fail(member-mismatch) [OK]
F5 coherent-same-uname-B: current=PASS specified=fail(pin-mismatch:linux-image-7.0.0-30-generic) [OK]
F5 image-only-skew: current=PASS specified=fail(pin-mismatch:linux-image-7.0.0-30-generic) [OK]
F5 modules-only-skew: current=PASS specified=fail(pin-mismatch:linux-modules-7.0.0-30-generic) [OK]
F5 headers-only-skew: current=PASS specified=fail(pin-mismatch:linux-headers-7.0.0-30-generic) [OK]
F5 missing-modules-headers: current=PASS specified=fail(pin-mismatch:linux-modules-7.0.0-30-generic) [OK]
F5 4kstacks-set: current=PASS specified=fail(kconfig) [OK]
F5 two-kernels: current=PASS specified=fail(multi-kernel) [OK]
F5bc member-A: OPEN [OK]
F5bc coherent-B-31: SHUT(booted-uname) [OK]
F5bc coherent-same-uname-B: SHUT(booted-rows) [OK]
F5bc F5b-booted-22: SHUT(booted-uname) [OK]
F5bc F5c-rollback-22: SHUT(booted-uname) [OK]
F5bc booted-modules-only-skew: SHUT(booted-rows) [OK]
F5bc booted-kconfig-bad: SHUT(booted-kconfig) [OK]
F5bc manifest-headers-only-skew: SHUT(manifest-rows) [OK]
F5bc manifest-allowlist-skew: SHUT(manifest-allowlist) [OK]
F6F7 member-A: arm=ACCEPT gate2=PROMOTE-PATH [OK]
F6F7 coherent-B-31: arm=REFUSE(candidate-uname) gate2=REVERT(non-member) [OK]
F6F7 coherent-same-uname-B: arm=REFUSE(candidate-rows) gate2=REVERT(non-member) [OK]
F6F7 F6-candidate-31-running-30: arm=REFUSE(candidate-uname) gate2=REVERT(running!=candidate) [OK]
F6F7 F7-running-31: arm=REFUSE(candidate-uname) gate2=REVERT(non-member) [OK]
F6F7 candidate-modules-only-skew: arm=REFUSE(candidate-rows) gate2=REVERT(running!=candidate) [OK]
F6F7 running-headers-only-skew: arm=ACCEPT gate2=REVERT(running!=candidate) [OK]
F6F7 running-kconfig-bad: arm=ACCEPT gate2=REVERT(kconfig) [OK]
F6F7 running-22-candidate-30: arm=ACCEPT gate2=REVERT(running!=candidate) [OK]
F8 offline-member: PASS [OK]
F8 live-4kstacks-set: FATAL [OK]
F8 bridge-absent: FATAL [OK]
F8 missing-file: FATAL [OK]
F9 quotes-7.0.0-30-generic: PRESENT [OK]
F9 quotes-7.0.0-30.30: PRESENT [OK]
F9 quotes-Ubuntu-7.0.0-30.30: PRESENT [OK]
F9 quotes-d974a4063: PRESENT [OK]
F9 negative-control: -31-substituted copy lacks member strings → VOID [OK]
pins: per-script pin map holds [OK]
device: /dev/net/tun mode=0o666 rdev=10:200
host: 7.0.13+deb14-amd64 euid=0
fd: char fd opened O_RDWR|O_CLOEXEC (fd=3)
SETUP-bind: TUNSETIFF v13en85618 flags=0x1001 sysfs=True [OK]
SEND-raw-sendmsg: syscall ret=-1 errno=88 (Socket operation on non-socket) on bound fd [OK]
NULLCTL-send: errno=88 [OK]
WRAPPER-fromfd: constructor errno=88 (expected wrapper failure, distinct from SEND) [OK]
PAIRECTL-success: socketpair sendmsg sent 10 bytes [OK]
CLEANUP-device-removed: v13en85618 removed=True [OK]
ENOTSOCK-STATUS: COMPLETE (bound member-USP-shape fd + controls + cleanup)
--- P2-only (retained, not executed here) ---
rxbatched_drift.sh kprobe_sync_proof.sh ptp_nodefer_cell.sh: SPECIFIED (exit 3 = not-run-here)
MATRIX: ALL-HERE-OK
```

No-sudo variant tail (same run without `USE_SUDO`, exit 4):

```text
SETUP-bind: SKIPPED errno=1 (Operation not permitted) — P2-only leg (needs CAP_NET_ADMIN)
ENOTSOCK-STATUS: INCOMPLETE (bound-fd leg missing — not P2 evidence)
MATRIX: INCOMPLETE (bound-fd leg missing — not P2 evidence)
```

Content hashes (sha256sum of the extracted files, sudo run):

```text
10a118af1e6e49204fc2373712d3027229be6c6c78cf17565be492bce1181cc1 enotsock_probe.py
5ec3d635fe13caced31486a33916f036c36d02a5a1f5a801a161c5b1d3249784 f0_pin_check.py
959e423192dbbd0e52115be452e5f68440327d86d4f02ceb0a2e4e334b765cee f1_bake_check.py
6c8574ed24bf7cbcd21e45e4a76d0d00fa069de46cb027a72e64afc0d3ee287e f2f3_sign_check.py
00b4c8c1cf72800db65c743b68293094b3a1741de3b5b97b22a55b0d2dd72142 f4_publish_check.py
d47615f9bfdf64ec58520af8f3c7273783e3ad37c0fa3190c30820939f958461 f5_validate_check.py
77b5c4daa0b834599f28ea21a2a3288dd6ba40dd3d1180be2d992d935a9c7cbc f5b_admission.py
a198e9d33dcb7cecc9d0c0d771aee2dec1d798d9bed9f9650a587b7ef2eebd9c f6f7_lane1.py
f67b3bd34dbc25e559b2c0d444b1be128f54aef2879c2eed9531ea5c6f849a02 f8_kconfig.sh
d585c50db9ed489f7367ab254429305912d46dd10bdc7982c63f8dbabb766d93 f9_linkage.sh
12f74807917db7470a06e8d0fae168a3ea002e13e2868d4bc7e86c39dd607dc5 kprobe_sync_proof.sh
26131b929c97b7fba9b895356ee12e6a28c760df1d83ba641ab3fed70bef1ca9 pins_consistency.sh
464042e3e840746390f993b5d82bdd2a57b3d18e5693ee91db3106fb3f60f6c8 ptp_nodefer_cell.sh
17110272fdb27256859b36435163861516be5d9bed780623a36d831b4511d641 run_all.sh
e454636fc804e043b6f95843b39c19d8f37e3ecf7553bc725271c3af3690f3f6 rxbatched_drift.sh
```
