// #9726: the pure half of build.rs's linked-library checks. build.rs includes
// this file with `#[path]`, and src/main.rs includes it again under cfg(test),
// so the decisions that stop a helper build are unit-tested on both sides of
// their boundaries instead of only by a host that happens to be out of range.
// Everything here is a function of its arguments: no std::process, no std::env.

/// The libxdp range the ring-layout asserts (#4976) and the helper were
/// validated on. A build host with a libxdp outside it fails the build, naming
/// the version it found, instead of shipping a helper nothing tested.
pub(crate) const LIBXDP_MIN: (u64, u64, u64) = (1, 6, 3);
pub(crate) const LIBXDP_MAX_EXCLUSIVE: (u64, u64, u64) = (1, 7, 0);

/// The libbpf major.minor the vendored copy was validated on. Cargo.toml's
/// `libbpf-sys = "~1.6"` asks for it; check_libbpf_family is what enforces it.
pub(crate) const LIBBPF_FAMILY: (u64, u64) = (1, 6);

/// #9931: lower bounds for the three host-supplied transitive static libs
/// (`-lelf -lz -lzstd`, via libelf/libbpf). Unlike libxdp's tight range there
/// is no upper bound: these are ordinary distro libraries with stable ABIs
/// the helper never calls directly, and an upper bound would brick routine
/// `apt upgrade`s (libelf 0.196 was already a candidate when this shipped).
/// A host below the validated floor fails the build instead of shipping a
/// helper nothing tested. `debian/control` declares the same floors.
pub(crate) const LIBELF_MIN: (u64, u64, u64) = (0, 195, 0);
/// zlib 1.3.0, not 1.3.2: the 1.3.x line is ABI-stable bugfixes, and Debian's
/// `1.3.dfsg+really1.3.2` mangling sorts AFTER a plain `1.3.2`, so a patch
/// bound would admit 1.3.1-dfsg while looking precise. Minor precision avoids
/// the trap; 1.2.x stays rejected as unvalidated.
pub(crate) const ZLIB_MIN: (u64, u64, u64) = (1, 3, 0);
pub(crate) const ZSTD_MIN: (u64, u64, u64) = (1, 5, 7);

/// #9931: admits a libelf version only at or above `LIBELF_MIN`. A version
/// without a patch reads as `.0`.
pub(crate) fn check_libelf_version(elf: &str) -> Result<(), String> {
    let v = parse_version(elf)
        .ok_or_else(|| format!("#9931: unparsable libelf version {elf:?}"))?;
    if v < LIBELF_MIN {
        return Err(format!(
            "#9931: libelf {elf} is below the validated minimum 0.195; \
             re-validate the helper against it before lowering LIBELF_MIN"
        ));
    }
    Ok(())
}

/// #9931: admits a zlib version only at or above `ZLIB_MIN`.
pub(crate) fn check_zlib_version(z: &str) -> Result<(), String> {
    let v = parse_version(z)
        .ok_or_else(|| format!("#9931: unparsable zlib version {z:?}"))?;
    if v < ZLIB_MIN {
        return Err(format!(
            "#9931: zlib {z} is below the validated minimum 1.3; \
             re-validate the helper against it before lowering ZLIB_MIN"
        ));
    }
    Ok(())
}

/// #9931: admits a zstd version only at or above `ZSTD_MIN`.
pub(crate) fn check_zstd_version(zstd: &str) -> Result<(), String> {
    let v = parse_version(zstd)
        .ok_or_else(|| format!("#9931: unparsable zstd version {zstd:?}"))?;
    if v < ZSTD_MIN {
        return Err(format!(
            "#9931: zstd {zstd} is below the validated minimum 1.5.7; \
             re-validate the helper against it before lowering ZSTD_MIN"
        ));
    }
    Ok(())
}

/// #9931: `elfutils/version.h` carries no dotted version, only
/// `#define _ELFUTILS_VERSION 195` for 0.195 (major * 1000 + minor, per its
/// `_ELFUTILS_PREREQ` macro). Decode it to the pkg-config spelling so the
/// header fallback records the same string pkg-config would.
pub(crate) fn elfutils_version_string(raw: u64) -> String {
    format!("{}.{}", raw / 1000, raw % 1000)
}

/// #9931: compose the pkg-config spelling from three numeric header defines:
/// zlib's `ZLIB_VER_MAJOR/MINOR/REVISION`, zstd's
/// `ZSTD_VERSION_MAJOR/MINOR/RELEASE`.
pub(crate) fn dotted_version(major: u64, minor: u64, patch: u64) -> String {
    format!("{major}.{minor}.{patch}")
}

pub(crate) fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut parts = v.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = match parts.next() {
        Some(p) => p.parse().ok()?,
        None => 0,
    };
    Some((major, minor, patch))
}

/// Admits a libxdp version only inside `LIBXDP_MIN..LIBXDP_MAX_EXCLUSIVE`. A
/// version without a patch reads as `.0`.
pub(crate) fn check_libxdp_version(libxdp: &str) -> Result<(), String> {
    let xdp = parse_version(libxdp)
        .ok_or_else(|| format!("#9726: unparsable libxdp version {libxdp:?}"))?;
    if xdp < LIBXDP_MIN || xdp >= LIBXDP_MAX_EXCLUSIVE {
        return Err(format!(
            "#9726: libxdp {libxdp} is outside the validated range >= 1.6.3, < 1.7; \
             re-validate the ring layout (#4976) and the xsk flags before widening it"
        ));
    }
    Ok(())
}

/// Checks the vendored libbpf against the validated family and against the
/// libbpf-sys version Cargo.lock pins, and returns the libbpf version to record.
/// libbpf-sys versions itself `<crate>+v<libbpf>` (`1.6.3+v1.6.3`), so the libbpf
/// version is the part after `+v` when present, and the crate version otherwise.
pub(crate) fn check_libbpf_family(
    header_major: u64,
    header_minor: u64,
    locked_version: &str,
) -> Result<String, String> {
    if (header_major, header_minor) != LIBBPF_FAMILY {
        return Err(format!(
            "#9726: the vendored libbpf headers are {header_major}.{header_minor}, outside the \
             validated family {}.{}; re-validate the helper against it before widening it",
            LIBBPF_FAMILY.0, LIBBPF_FAMILY.1
        ));
    }
    let libbpf = locked_version
        .split_once("+v")
        .map_or(locked_version, |(_, libbpf)| libbpf);
    let locked = parse_version(libbpf).ok_or_else(|| {
        format!("#9726: unparsable libbpf version in the locked libbpf-sys {locked_version:?}")
    })?;
    if (locked.0, locked.1) != (header_major, header_minor) {
        return Err(format!(
            "#9726: Cargo.lock pins libbpf-sys {locked_version}, but its vendored libbpf \
             headers are {header_major}.{header_minor}"
        ));
    }
    Ok(libbpf.to_string())
}

/// The numeric value of `#define <name> <value>` in a C header, if present.
pub(crate) fn header_define(text: &str, name: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next() == Some("#define") && fields.next() == Some(name) {
            fields.next()?.parse().ok()
        } else {
            None
        }
    })
}

/// The version of the `[[package]]` named `package` in a Cargo.lock's text.
/// A name that appears only in another package's `dependencies` is not a match.
pub(crate) fn locked_package_version(lock_text: &str, package: &str) -> Option<String> {
    let mut in_package = false;
    let mut name = None;
    let mut version = None;
    // A trailing sentinel header closes the last table.
    for line in lock_text.lines().map(str::trim).chain(["[end]"]) {
        if line.starts_with('[') {
            if in_package && name == Some(package) {
                return version.map(str::to_string);
            }
            in_package = line == "[[package]]";
            name = None;
            version = None;
        } else if in_package {
            if let Some(value) = toml_string_value(line, "name") {
                name = Some(value);
            } else if let Some(value) = toml_string_value(line, "version") {
                version = Some(value);
            }
        }
    }
    None
}

// `key = "value"` -> `value`.
fn toml_string_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.strip_prefix(key)?
        .trim_start()
        .strip_prefix('=')?
        .trim()
        .strip_prefix('"')?
        .strip_suffix('"')
}
