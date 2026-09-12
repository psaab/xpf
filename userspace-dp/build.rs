use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// #9726: the pure version checks. src/main.rs includes the same file under
// cfg(test), so the crate's test suite unit-tests what this script decides.
#[path = "build_support/libversions.rs"]
mod libversions;

// #9726: the snapshots this build links, each under a name no other directory on
// any search path supplies. See snapshot_libxdp_archive.
const LINKED_LIBXDP_LINK_NAME: &str = "xpfxdp";
const LINKED_LIBXDP_ARCHIVE: &str = "libxpfxdp.a";
const LINKED_LIBBPF_LINK_NAME: &str = "xpfbpf";
const LINKED_LIBBPF_ARCHIVE: &str = "libxpfbpf.a";

fn main() {
    // #9726: bound libxdp first, before this script compiles against it or copies
    // its archive. A libxdp outside the range can fail the C compile, or ship
    // no libxdp.a, and either failure would hide the version that caused it.
    let libxdp_version = pkg_config_version("libxdp")
        .unwrap_or_else(|e| panic!("#9726: cannot read the libxdp version: {e}"));
    libversions::check_libxdp_version(&libxdp_version).unwrap_or_else(|e| panic!("{e}"));

    // #9726: Cargo re-runs this script when a tracked file's mtime changes, which
    // misses a library replaced by one carrying an older mtime. The Makefile's
    // helper recipes pass XPF_LINKED_LIBS_STAMP, a content hash of libxdp.a,
    // libxdp.pc and libbpf.pc, so those builds also re-run on a content change. A
    // raw `cargo build` outside the Makefile relies on mtimes alone.
    println!("cargo:rerun-if-env-changed=XPF_LINKED_LIBS_STAMP");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG");

    // #9726: compile against, link, and record the same libxdp: the one
    // pkg-config describes.
    let libxdp_include = pkg_config_variable("libxdp", "includedir")
        .unwrap_or_else(|e| panic!("#9726: cannot read libxdp's includedir: {e}"));
    let libxdp_libdir = pkg_config_variable("libxdp", "libdir")
        .unwrap_or_else(|e| panic!("#9726: cannot read libxdp's libdir: {e}"));
    let snapshot_dir = prepare_snapshot_dir();
    let libxdp_version = snapshot_libxdp_archive(&snapshot_dir, &libxdp_libdir, &libxdp_version);
    snapshot_libbpf_archive(&snapshot_dir);

    // Compile the C bridge that wraps libxdp's inline xsk helpers.
    cc::Build::new()
        .file("csrc/xsk_bridge.c")
        .include(&libxdp_include)
        .warnings(true)
        .flag("-Wno-unused-parameter")
        .opt_level(2)
        .compile("xsk_bridge");

    // Statically link libxdp and its transitive dependencies so the
    // binary is self-contained (no libxdp.so.1 needed on target VMs).
    //
    // #9726: libxdp is linked as `static=xpfxdp` and libbpf as `static=xpfbpf`, so
    // the linker looks for the file names libxpfxdp.a and libxpfbpf.a and finds
    // them ONLY in this build's snapshot directory. No system, SDK or dependency
    // directory holds either, so no `-L` from anywhere — RUSTFLAGS,
    // `cargo rustc -- -L...`, a rustc wrapper, a dependency build script — can
    // supply one, and a snapshot that is missing fails the link instead of falling
    // through to another archive.
    //
    // The emission ORDER below is load-bearing: libxdp's undefined libbpf symbols
    // are resolved by the libbpf that FOLLOWS it, so the snapshot must come before
    // the bare `bpf` below.
    println!("cargo:rustc-link-search=native={}", snapshot_dir.display());
    println!("cargo:rustc-link-lib=static={LINKED_LIBXDP_LINK_NAME}");
    println!("cargo:rustc-link-lib=static={LINKED_LIBBPF_LINK_NAME}");
    // #9726: this bare `bpf` is what libbpf-sys itself emits, and it resolves along
    // the whole search path — including any system directory a `-L` puts ahead of
    // this crate's, where a HOST libbpf.a (1.7.0 on the development host) would
    // satisfy it while the build records the vendored 1.6.3. It is kept because
    // libbpf-sys emits it in any case, but it can no longer decide anything: by the
    // time the linker reaches it, the snapshot above has already resolved libbpf's
    // symbols, and a -Wl,-Map link trace taken with -Lnative=/usr/lib/x86_64-linux-gnu
    // shows it extracting no members at all.
    println!("cargo:rustc-link-lib=static=bpf");
    println!("cargo:rustc-link-lib=static=elf");
    println!("cargo:rustc-link-lib=static=z");
    println!("cargo:rustc-link-lib=static=zstd");
    println!("cargo:rerun-if-changed=csrc/xsk_bridge.c");
    // #4976: an in-place libxdp header upgrade that reorders/resizes the ring
    // structs must re-run the C `_Static_assert`s in xsk_bridge.c. Cargo would
    // otherwise reuse the cached bridge object (the .c file is unchanged) and
    // silently skip the ABI check on an incremental build — exactly the drift
    // this gate exists to catch. Track the installed header so a package
    // upgrade forces a recompile (#9726: the one in libxdp's pkg-config
    // includedir, which the bridge compiles against).
    println!("cargo:rerun-if-changed={libxdp_include}/xdp/xsk.h");

    record_library_versions(&libxdp_libdir, &libxdp_version);
}

// #9726: the directory both snapshots live in, emptied of everything else.
//
// It is on the link's search path, and an OUT_DIR outlives a build, so anything
// left here from an earlier revision of this script — a snapshot named libxdp.a,
// before the unique names — would stay for an `-lxdp` to find. The directory is
// this build unit's own (Cargo scopes OUT_DIR per package, per profile, per
// target, and serializes work in a target directory), and only immediate entries
// are removed: a directory here is not recursed into but fails the build, and a
// symlink is unlinked rather than followed.
fn prepare_snapshot_dir() -> PathBuf {
    let out_dir = env::var_os("OUT_DIR")
        .unwrap_or_else(|| panic!("#9726: Cargo set no OUT_DIR for this build script"));
    let dir = PathBuf::from(&out_dir).join("xpf-linked-libxdp");
    fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("#9726: create {}: {e}", dir.display()));
    let keep = [LINKED_LIBXDP_ARCHIVE, LINKED_LIBBPF_ARCHIVE];
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            if keep.iter().any(|name| entry.file_name() == *name) {
                continue;
            }
            let stale = entry.path();
            fs::remove_file(&stale)
                .unwrap_or_else(|e| panic!("#9726: remove stale {}: {e}", stale.display()));
        }
    }
    dir
}

// #9726: THE SIBLING. libbpf is linked the same way and for the same reason.
//
// libbpf-sys builds a vendored libbpf (the one Cargo.lock pins, whose headers
// record_library_versions reads and reports) into its own OUT_DIR and emits a bare
// `-lbpf` plus a `-L` for that directory. Resolving a bare `-lbpf` is a search-order
// argument, and this host ships a static libbpf 1.7.0 in /usr/lib/x86_64-linux-gnu:
// any `-L` naming a directory with a libbpf.a that lands ahead of the build-script
// paths — `cargo rustc -- -Lnative=/usr/lib/x86_64-linux-gnu` does exactly that —
// makes the link take the host's 1.7.0 while XPF_LINKED_LIBBPF_VERSION reports the
// vendored 1.6.3. That is the acceptance criterion of #9726 failing for the other
// library, so libbpf gets the unique name too.
//
// The version/copy window that snapshot_libxdp_archive closes does not arise here:
// both the archive and the libbpf_version.h that names its version are outputs of
// the libbpf-sys build script in this same cargo invocation, in a target directory
// Cargo locks, not files a host package manager can replace mid-build.
fn snapshot_libbpf_archive(dir: &Path) {
    let include = env::var_os("DEP_BPF_INCLUDE")
        .unwrap_or_else(|| panic!("#9726: libbpf-sys did not export DEP_BPF_INCLUDE"));
    let vendored = Path::new(&include)
        .parent()
        .unwrap_or_else(|| panic!("#9726: DEP_BPF_INCLUDE {include:?} has no parent directory"))
        .join("libbpf.a");
    let snapshot = dir.join(LINKED_LIBBPF_ARCHIVE);
    fs::copy(&vendored, &snapshot).unwrap_or_else(|e| {
        panic!(
            "#9726: copy the libbpf libbpf-sys vendored, {}, to {}: {e}",
            vendored.display(),
            snapshot.display()
        )
    });
    // A libbpf-sys rebuild rewrites this archive; re-copy when it does. Its
    // libbpf_version.h and Cargo.lock are tracked in record_library_versions.
    println!("cargo:rerun-if-changed={}", vendored.display());
}

// #9726: LINK THE ARCHIVE THIS BUILD READ, under a name nothing else supplies,
// rather than predicting which libxdp.a the link will take.
//
// The prediction was made at the wrong time. This script reads pkg-config's
// version and archive; the LINK runs later, and in between the file can change:
// Cargo decides whether to re-run a build script by MTIME, so a libxdp replaced by
// one carrying an older mtime is linked against a cached script output that
// recorded the previous version, and a package upgrade can land while cargo is
// running. No amount of inspecting search paths closes that window.
//
// Copying does. The linker opens a private file this build owns, in a directory
// that holds nothing else. If this script does not re-run, the previous snapshot
// is reused — so the binary, its recorded version and the archive it links stay
// one consistent set, which is exactly what #9726 asks for. The host's newer
// library is simply not adopted until the script re-runs.
//
// The UNIQUE NAME is what leaves the snapshot as the only candidate any ORDINARY
// build offers — no system, SDK, dependency or repo path supplies that file name.
// It is not a claim of total possession: a planted libxpfxdp.a on an earlier `-L`,
// a linker script or an explicit archive argument naming it, a custom linker or
// rustc wrapper, or replacing the snapshot after this script runs would all still
// substitute an archive. Each has to be constructed on purpose, and anyone who can
// do that can edit this build script; none of them is machinery worth adding.
// Copying to
// libxdp.a and linking `-lxdp` selected the snapshot only by search ORDER, which
// is an argument about rustc's `-L` ordering and about every `-L` any other
// mechanism might add — and it failed OPEN: a snapshot deleted from OUT_DIR
// without Cargo re-running this script let `-lxdp` fall through to a system or
// SDK directory, and the binary reported the cached version of an archive it no
// longer linked. `libxpfxdp.a` exists in no distribution, no SDK and no
// dependency's OUT_DIR, so an added `-L` cannot supply one and a missing snapshot
// fails the link — "unable to find library -lxpfxdp" — instead of linking
// something else.
//
// It also removes a class of question this file kept re-litigating: which program
// rustc invokes as the linker, whether `CC` or `RUSTC_LINKER` names it, what its
// `-print-search-dirs` says, and whether `-B`/`gcc-ld`/`LIBRARY_PATH` reach it.
// The link no longer has to FIND libxdp, so none of it decides anything.
//
// Returns the version that describes the snapshot's bytes. `version_before` is the
// one main already range-checked; reading the version AFTER the copy and then
// re-reading the source is what ties the recorded version to the copied bytes. A
// separate read-then-copy could record 1.6.3 and copy a 1.7.0 installed in between,
// which would pass the range gate while linking an archive outside it. Equality is
// observational: it cannot exclude a change and a change back inside the window.
// Making the pair atomic would need a package-manager lock, a filesystem snapshot,
// or version metadata inside the archive itself.
fn snapshot_libxdp_archive(dir: &Path, libdir: &str, version_before: &str) -> String {
    let described = Path::new(libdir).join("libxdp.a");
    let snapshot = dir.join(LINKED_LIBXDP_ARCHIVE);

    // Write the snapshot from bytes held here, so the linked archive IS this
    // content by construction rather than by a second read of a file that can
    // change.
    let bytes = fs::read(&described).unwrap_or_else(|e| {
        panic!(
            "#9726: read the libxdp pkg-config describes, {}: {e}",
            described.display()
        )
    });
    fs::write(&snapshot, &bytes)
        .unwrap_or_else(|e| panic!("#9726: write {}: {e}", snapshot.display()));

    // The version that will be RECORDED is read after the copy, and the source is
    // then read again: if it still holds the bytes that were copied, the version
    // read between the two reads describes them.
    let version = pkg_config_version("libxdp")
        .unwrap_or_else(|e| panic!("#9726: cannot read the libxdp version: {e}"));
    libversions::check_libxdp_version(&version).unwrap_or_else(|e| panic!("{e}"));
    let after = fs::read(&described).unwrap_or_else(|e| {
        panic!(
            "#9726: re-read the libxdp pkg-config describes, {}: {e}",
            described.display()
        )
    });
    if after != bytes {
        panic!(
            "#9726: {} changed while this build was recording its version ({} bytes, then {}), \
             so the recorded version need not describe the archive that was copied; \
             finish the libxdp install and build again",
            described.display(),
            bytes.len(),
            after.len()
        );
    }
    if version != version_before {
        panic!(
            "#9726: libxdp's pkg-config version changed from {version_before} to {version} \
             while this build snapshotted {}; finish the libxdp install and build again",
            described.display()
        );
    }

    // Re-copy when the installed archive changes in place, so an upgrade is
    // adopted on the next build rather than pinned forever. This is an mtime
    // check; XPF_LINKED_LIBS_STAMP (main) covers a content change under an
    // unchanged mtime for the Makefile's recipes.
    println!("cargo:rerun-if-changed={}", described.display());
    version
}

// #9726: nothing used to record which libraries went into a helper binary. The
// build now exports them for ProcessStatus and the startup log:
//   - XPF_LINKED_LIBXDP_VERSION: the build host's libxdp — the pkg-config version
//     snapshot_libxdp_archive read against the bytes it copied into OUT_DIR, which
//     are the bytes this build links as libxpfxdp.a;
//   - XPF_LINKED_LIBBPF_VERSION: the vendored libbpf's full version, from the
//     libbpf-sys that Cargo.lock pins, checked against its libbpf_version.h;
//   - XPF_BUILD_HOST_LIBBPF_VERSION: the build host's libbpf (pkg-config). It is
//     not linked, and it does not identify the libbpf headers the prebuilt
//     libxdp.a was compiled with.
fn record_library_versions(libxdp_libdir: &str, libxdp: &str) {
    // Re-record, and so relink, when an installed library changes in place. xsk.h
    // is tracked in main, but an upgrade can leave the header alone. These are
    // mtime checks; XPF_LINKED_LIBS_STAMP (main) covers a content change under
    // the Makefile. A path that does not exist is not tracked, because Cargo would
    // then rerun the build script on every build.
    let mut tracked = vec![format!("{libxdp_libdir}/libxdp.a")];
    for lib in ["libxdp", "libbpf"] {
        if let Ok(dir) = pkg_config_variable(lib, "pcfiledir") {
            tracked.push(format!("{dir}/{lib}.pc"));
        }
    }
    for path in tracked {
        if Path::new(&path).is_file() {
            println!("cargo:rerun-if-changed={path}");
        }
    }

    println!("cargo:rustc-env=XPF_LINKED_LIBXDP_VERSION={libxdp}");

    let include = env::var("DEP_BPF_INCLUDE")
        .unwrap_or_else(|_| panic!("#9726: libbpf-sys did not export DEP_BPF_INCLUDE"));
    let header = PathBuf::from(include).join("bpf").join("libbpf_version.h");
    println!("cargo:rerun-if-changed={}", header.display());
    let text = fs::read_to_string(&header)
        .unwrap_or_else(|e| panic!("#9726: read {}: {e}", header.display()));
    let define = |name: &str| {
        libversions::header_define(&text, name)
            .unwrap_or_else(|| panic!("#9726: {name} not found in {}", header.display()))
    };
    let (major, minor) = (
        define("LIBBPF_MAJOR_VERSION"),
        define("LIBBPF_MINOR_VERSION"),
    );

    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|_| panic!("#9726: Cargo did not set CARGO_MANIFEST_DIR"));
    let lock_path = Path::new(&manifest_dir).join("Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock_path.display());
    let lock = fs::read_to_string(&lock_path)
        .unwrap_or_else(|e| panic!("#9726: read {}: {e}", lock_path.display()));
    let locked = libversions::locked_package_version(&lock, "libbpf-sys")
        .unwrap_or_else(|| panic!("#9726: {} locks no libbpf-sys", lock_path.display()));
    let libbpf =
        libversions::check_libbpf_family(major, minor, &locked).unwrap_or_else(|e| panic!("{e}"));
    println!("cargo:rustc-env=XPF_LINKED_LIBBPF_VERSION={libbpf}");

    let host = pkg_config_version("libbpf").unwrap_or_else(|_| "unknown".to_string());
    if libversions::parse_version(&host).map(|v| (v.0, v.1)) != Some((major, minor)) {
        println!(
            "cargo:warning=#9726: the build host's libbpf (pkg-config) is {host}, \
             but the helper links vendored libbpf {libbpf}"
        );
    }
    println!("cargo:rustc-env=XPF_BUILD_HOST_LIBBPF_VERSION={host}");
}

fn pkg_config_version(lib: &str) -> Result<String, String> {
    pkg_config(&["--modversion", lib])
}

fn pkg_config_variable(lib: &str, variable: &str) -> Result<String, String> {
    let arg = format!("--variable={variable}");
    pkg_config(&[arg.as_str(), lib]).and_then(|v| {
        if v.is_empty() {
            Err(format!("{lib} defines no {variable}"))
        } else {
            Ok(v)
        }
    })
}

// Runs pkg-config, or the command PKG_CONFIG names, as the pkg-config crate does.
fn pkg_config(args: &[&str]) -> Result<String, String> {
    let cmd = env::var("PKG_CONFIG").unwrap_or_else(|_| "pkg-config".to_string());
    let out = Command::new(&cmd)
        .args(args)
        .output()
        .map_err(|e| format!("run {cmd}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{cmd} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
