use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// #9726: the pure version checks. src/main.rs includes the same file under
// cfg(test), so the crate's test suite unit-tests what this script decides.
#[path = "build_support/libversions.rs"]
mod libversions;

// #9726/#9931: snapshots this build links, each under a name no other
// directory on any search path supplies. See snapshot_libxdp_archive and
// snapshot_host_archive.
const LINKED_LIBXDP_LINK_NAME: &str = "xpfxdp";
const LINKED_LIBXDP_ARCHIVE: &str = "libxpfxdp.a";
const LINKED_LIBBPF_LINK_NAME: &str = "xpfbpf";
const LINKED_LIBBPF_ARCHIVE: &str = "libxpfbpf.a";
const LINKED_LIBELF_LINK_NAME: &str = "xpfelf";
const LINKED_LIBELF_ARCHIVE: &str = "libxpfelf.a";
const LINKED_ZLIB_LINK_NAME: &str = "xpfz";
const LINKED_ZLIB_ARCHIVE: &str = "libxpfz.a";
const LINKED_ZSTD_LINK_NAME: &str = "xpfzstd";
const LINKED_ZSTD_ARCHIVE: &str = "libxpfzstd.a";

#[derive(Clone, Copy)]
struct HostLibrarySpec {
    label: &'static str,
    pkg_config: &'static str,
    source_archive_name: &'static str,
    snapshot_archive_name: &'static str,
    link_name: &'static str,
}

const HOST_LIBRARY_SPECS: [HostLibrarySpec; 3] = [
    HostLibrarySpec {
        label: "libelf",
        pkg_config: "libelf",
        source_archive_name: "libelf.a",
        snapshot_archive_name: LINKED_LIBELF_ARCHIVE,
        link_name: LINKED_LIBELF_LINK_NAME,
    },
    HostLibrarySpec {
        label: "zlib",
        pkg_config: "zlib",
        source_archive_name: "libz.a",
        snapshot_archive_name: LINKED_ZLIB_ARCHIVE,
        link_name: LINKED_ZLIB_LINK_NAME,
    },
    HostLibrarySpec {
        label: "zstd",
        pkg_config: "libzstd",
        source_archive_name: "libzstd.a",
        snapshot_archive_name: LINKED_ZSTD_ARCHIVE,
        link_name: LINKED_ZSTD_LINK_NAME,
    },
];

struct HostLibrary {
    spec: HostLibrarySpec,
    version: String,
    archive: PathBuf,
    header: Option<PathBuf>,
    pcfile: Option<PathBuf>,
    pkg_configured: bool,
    search_dirs: Vec<PathBuf>,
}

fn main() {
    // #9931: discover and range-check the three host-supplied static
    // libraries before the C bridge compile. A missing archive or a stale
    // `-dev` install must name the library and the package it needs.
    let linker_dirs = linker_search_dirs();
    let include_dirs = include_search_dirs();
    let host_libraries = HOST_LIBRARY_SPECS
        .iter()
        .map(|spec| discover_host_library(spec, &linker_dirs, &include_dirs))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|e| panic!("{e}"));
    for library in &host_libraries {
        guard_host_library(library).unwrap_or_else(|e| panic!("{e}"));
    }

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
    for library in &host_libraries {
        snapshot_host_archive(&snapshot_dir, library);
    }

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
    // #9726/#9931: every archive this build records is linked under a unique
    // name from this build's snapshot directory. No system, SDK, dependency or
    // RUSTFLAGS `-L` directory can supply one of these names, so a missing
    // snapshot fails the link instead of falling through to another archive.
    //
    // The emission ORDER below is load-bearing: each archive's undefined
    // symbols are resolved by the dependency that FOLLOWS it. The trailing
    // bare `bpf`, `elf` and `z` names are emitted by libbpf-sys; by the time
    // they are reached the uniquely named snapshots have already resolved
    // every member they can satisfy, so those flags extract no host members.
    println!("cargo:rustc-link-search=native={}", snapshot_dir.display());
    println!("cargo:rustc-link-lib=static={LINKED_LIBXDP_LINK_NAME}");
    println!("cargo:rustc-link-lib=static={LINKED_LIBBPF_LINK_NAME}");
    for library in &host_libraries {
        println!("cargo:rustc-link-lib=static={}", library.spec.link_name);
    }
    println!("cargo:rustc-link-lib=static=bpf");
    println!("cargo:rerun-if-changed=csrc/xsk_bridge.c");
    // #4976: an in-place libxdp header upgrade that reorders/resizes the ring
    // structs must re-run the C `_Static_assert`s in xsk_bridge.c. Cargo would
    // otherwise reuse the cached bridge object (the .c file is unchanged) and
    // silently skip the ABI check on an incremental build — exactly the drift
    // this gate exists to catch. Track the installed header so a package
    // upgrade forces a recompile (#9726: the one in libxdp's pkg-config
    // includedir, which the bridge compiles against).
    println!("cargo:rerun-if-changed={libxdp_include}/xdp/xsk.h");

    record_library_versions(&libxdp_libdir, &libxdp_version, &host_libraries);
}


fn env_path_list(name: &str) -> Vec<PathBuf> {
    env::var_os(name)
        .map(|value| {
            value
                .to_string_lossy()
                .split(':')
                .filter(|entry| !entry.is_empty())
                .map(PathBuf::from)
                .collect()
        })
        .unwrap_or_default()
}

fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

fn parse_library_search_dirs(flags: &str) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mut after_l = false;
    for token in flags.split(|ch: char| ch.is_whitespace() || ch == '\u{1f}') {
        if token.is_empty() {
            continue;
        }
        if after_l {
            push_unique_path(&mut dirs, PathBuf::from(token));
            after_l = false;
            continue;
        }
        if token == "-L" || token == "-Lnative" {
            after_l = true;
        } else if let Some(path) = token.strip_prefix("-Lnative=") {
            push_unique_path(&mut dirs, PathBuf::from(path));
        } else if let Some(path) = token.strip_prefix("-L") {
            if !path.is_empty() {
                push_unique_path(&mut dirs, PathBuf::from(path));
            }
        }
    }
    dirs
}

fn target_rustflags_name(suffix: &str) -> Option<String> {
    let target = env::var("TARGET").ok()?;
    Some(format!(
        "CARGO_TARGET_{}_{}",
        target.replace('-', "_").to_ascii_uppercase(),
        suffix
    ))
}

fn linker_search_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    // `LD_LIBRARY_PATH` only affects runtime shared-library lookup; it cannot
    // shadow a static archive selected by the linker's `-L`/`LIBRARY_PATH`.
    for path in env_path_list("LIBRARY_PATH") {
        push_unique_path(&mut dirs, path);
    }
    println!("cargo:rerun-if-env-changed=LIBRARY_PATH");
    for name in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"] {
        if let Ok(flags) = env::var(name) {
            for path in parse_library_search_dirs(&flags) {
                push_unique_path(&mut dirs, path);
            }
        }
        println!("cargo:rerun-if-env-changed={name}");
    }
    if let Some(name) = target_rustflags_name("RUSTFLAGS") {
        if let Ok(flags) = env::var(&name) {
            for path in parse_library_search_dirs(&flags) {
                push_unique_path(&mut dirs, path);
            }
        }
        println!("cargo:rerun-if-env-changed={name}");
    }
    let target = env::var("TARGET").unwrap_or_default();
    for name in [
        "LIBBPF_SYS_LIBRARY_PATH".to_string(),
        format!("LIBBPF_SYS_LIBRARY_PATH_{target}"),
        format!(
            "LIBBPF_SYS_LIBRARY_PATH_{}",
            target.replace('-', "_")
        ),
    ] {
        for path in env_path_list(&name) {
            push_unique_path(&mut dirs, path);
        }
        println!("cargo:rerun-if-env-changed={name}");
    }
    dirs
}

fn include_search_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for name in ["C_INCLUDE_PATH", "CPATH", "CPLUS_INCLUDE_PATH"] {
        for path in env_path_list(name) {
            push_unique_path(&mut dirs, path);
        }
        println!("cargo:rerun-if-env-changed={name}");
    }
    for path in [PathBuf::from("/usr/local/include"), PathBuf::from("/usr/include")] {
        push_unique_path(&mut dirs, path);
    }
    dirs
}

fn default_library_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(target_arch) = env::var("CARGO_CFG_TARGET_ARCH") {
        push_unique_path(
            &mut dirs,
            PathBuf::from(format!("/usr/lib/{target_arch}-linux-gnu")),
        );
    }
    for path in [
        PathBuf::from("/usr/local/lib"),
        PathBuf::from("/usr/lib64"),
        PathBuf::from("/usr/lib"),
    ] {
        push_unique_path(&mut dirs, path);
    }
    dirs
}

fn parse_header_version(spec: HostLibrarySpec, text: &str) -> Option<String> {
    match spec.label {
        "libelf" => libversions::header_define(text, "_ELFUTILS_VERSION")
            .map(libversions::elfutils_version_string),
        "zlib" => Some(libversions::dotted_version(
            libversions::header_define(text, "ZLIB_VER_MAJOR")?,
            libversions::header_define(text, "ZLIB_VER_MINOR")?,
            libversions::header_define(text, "ZLIB_VER_REVISION")?,
        )),
        "zstd" => Some(libversions::dotted_version(
            libversions::header_define(text, "ZSTD_VERSION_MAJOR")?,
            libversions::header_define(text, "ZSTD_VERSION_MINOR")?,
            libversions::header_define(text, "ZSTD_VERSION_RELEASE")?,
        )),
        _ => None,
    }
}

fn header_version(
    spec: HostLibrarySpec,
    include_dirs: &[PathBuf],
) -> Option<(String, PathBuf)> {
    for include in include_dirs {
        let relative = match spec.label {
            "libelf" => "elfutils/version.h",
            "zlib" => "zlib.h",
            "zstd" => "zstd.h",
            _ => return None,
        };
        let path = include.join(relative);
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        if let Some(version) = parse_header_version(spec, &text) {
            return Some((version, path));
        }
    }
    None
}

fn find_archive(spec: HostLibrarySpec, dirs: &[PathBuf]) -> Option<PathBuf> {
    for dir in dirs {
        let archive = dir.join(spec.source_archive_name);
        if archive.is_file() {
            return Some(archive);
        }
    }
    None
}

fn installation_prefix(path: &Path, is_library_dir: bool) -> Option<PathBuf> {
    let canonical = fs::canonicalize(path).ok()?;
    let mut prefix = PathBuf::new();
    let mut last_marker_prefix = None;
    for component in canonical.components() {
        let name = component.as_os_str().to_string_lossy();
        let marker = if is_library_dir {
            matches!(name.as_ref(), "lib" | "lib32" | "lib64")
        } else {
            name == "include"
        };
        if marker {
            // A custom install prefix may itself contain a marker directory
            // (for example, /var/lib/xpf); use the innermost layout marker.
            last_marker_prefix = Some(prefix.clone());
        }
        prefix.push(component.as_os_str());
    }
    last_marker_prefix
}

fn require_same_static_install(
    spec: HostLibrarySpec,
    header: &Path,
    archive: &Path,
) -> Result<(), String> {
    let header_prefix = installation_prefix(header, false);
    let archive_dir = archive.parent().unwrap_or_else(|| Path::new(""));
    let archive_prefix = installation_prefix(archive_dir, true);
    if header_prefix.is_some() && header_prefix == archive_prefix {
        return Ok(());
    }
    Err(format!(
        "#9931: static-only {} header {} (prefix {:?}) and archive {} (prefix {:?}) \
         come from different installation prefixes; provide matching C_INCLUDE_PATH and \
         LIBRARY_PATH entries for {}",
        spec.label,
        header.display(),
        header_prefix,
        archive.display(),
        archive_prefix,
        spec.pkg_config,
    ))
}

fn discover_host_library(
    spec: &HostLibrarySpec,
    linker_dirs: &[PathBuf],
    include_dirs: &[PathBuf],
) -> Result<HostLibrary, String> {
    let explicit_dirs = linker_dirs.to_vec();
    let pkg_error = match pkg_config_version(spec.pkg_config) {
        Ok(version) => {
            let mut pkg_dirs = Vec::new();
            if let Ok(libdir) = pkg_config_variable(spec.pkg_config, "libdir") {
                push_unique_path(&mut pkg_dirs, PathBuf::from(libdir));
            }
            let flags = pkg_config(&["--libs", "--static", spec.pkg_config]).map_err(|e| {
                format!(
                    "#9931: cannot read static link flags for {}: {e}; install {}",
                    spec.label, spec.pkg_config
                )
            })?;
            for path in parse_library_search_dirs(&flags) {
                push_unique_path(&mut pkg_dirs, path);
            }
            let archive = find_archive(*spec, &pkg_dirs).ok_or_else(|| {
                format!(
                    "#9931: {} has no readable {}; install the static development archive \
                     from {}",
                    spec.label, spec.source_archive_name, spec.pkg_config
                )
            })?;
            check_host_version(*spec, &version)?;
            let mut package_include_dirs = Vec::new();
            if let Ok(includedir) = pkg_config_variable(spec.pkg_config, "includedir") {
                push_unique_path(&mut package_include_dirs, PathBuf::from(includedir));
            }
            for path in include_dirs.iter().cloned() {
                push_unique_path(&mut package_include_dirs, path);
            }
            let header = header_version(*spec, &package_include_dirs);
            if let Some((header_version, _)) = &header {
                if libversions::parse_version(header_version)
                    != libversions::parse_version(&version)
                {
                    return Err(format!(
                        "#9931: {} pkg-config reports {}, but its version header reports {}; \
                         install matching {} headers and archive",
                        spec.label, version, header_version, spec.pkg_config
                    ));
                }
            }
            let header = header.map(|(_, path)| path);
            let pcfile = pkg_config_variable(spec.pkg_config, "pcfiledir")
                .ok()
                .map(|dir| PathBuf::from(dir).join(format!("{}.pc", spec.pkg_config)));
            let mut search_dirs = explicit_dirs;
            for path in pkg_dirs {
                push_unique_path(&mut search_dirs, path);
            }
            for path in default_library_dirs() {
                push_unique_path(&mut search_dirs, path);
            }
            return Ok(HostLibrary {
                spec: *spec,
                pkg_configured: true,
                version,
                archive,
                header,
                pcfile,
                search_dirs,
            });
        }
        Err(error) => error,
    };

    // #9931: static-only installs need not ship a .pc file. The installed
    // public headers are the fallback source of a version, and LIBRARY_PATH /
    // the normal multiarch directories locate the matching archive.
    let mut search_dirs = explicit_dirs;
    for path in default_library_dirs() {
        push_unique_path(&mut search_dirs, path);
    }
    let (version, header) = header_version(*spec, &include_dirs).ok_or_else(|| {
        format!(
            "#9931: cannot discover {}: pkg-config failed ({pkg_error}) and no usable \
             version header was found; install {} (including its static archive)",
            spec.label, spec.pkg_config
        )
    })?;
    check_host_version(*spec, &version)?;
    let archive = find_archive(*spec, &search_dirs).ok_or_else(|| {
        format!(
            "#9931: discovered {} {} from {}, but found no readable {} in {:?}; \
             install the static development archive from {}",
            spec.label,
            version,
            header.display(),
            spec.source_archive_name,
            search_dirs,
            spec.pkg_config
        )
    })?;
    require_same_static_install(*spec, &header, &archive)?;
    Ok(HostLibrary {
        spec: *spec,
        version,
        pkg_configured: false,
        archive,
        header: Some(header),
        pcfile: None,
        search_dirs,
    })
}

fn check_host_version(spec: HostLibrarySpec, version: &str) -> Result<(), String> {
    match spec.label {
        "libelf" => libversions::check_libelf_version(version),
        "zlib" => libversions::check_zlib_version(version),
        "zstd" => libversions::check_zstd_version(version),
        _ => Err(format!("#9931: unknown host library {}", spec.label)),
    }
}

fn canonical(path: &Path) -> Result<PathBuf, String> {
    fs::canonicalize(path)
        .map_err(|e| format!("#9931: canonicalize {}: {e}", path.display()))
}

fn guard_host_library(library: &HostLibrary) -> Result<(), String> {
    let selected = canonical(&library.archive)?;
    let mut searched = Vec::new();
    for dir in &library.search_dirs {
        let candidate = dir.join(library.spec.source_archive_name);
        if !candidate.is_file() {
            continue;
        }
        let candidate = canonical(&candidate)?;
        searched.push(candidate.display().to_string());
        if candidate == selected {
            return Ok(());
        }
        return Err(format!(
            "#9931: unexpected {} archive {} appears before the selected {} in the \
             linker search set; recorded {} from {}; remove the shadow or use the \
             intended package path. Searched {:?}",
            library.spec.label,
            candidate.display(),
            selected.display(),
            library.version,
            library.archive.display(),
            library.search_dirs
        ));
    }
    Err(format!(
        "#9931: selected {} archive {} is outside the searched linker set; recorded {}. \
         Searched {:?} (observed {:?})",
        library.spec.label,
        selected.display(),
        library.version,
        library.search_dirs,
        searched
    ))
}


// #9726/#9931: the directory all snapshots live in, emptied of everything
// else. It is on the link's search path, and an OUT_DIR outlives a build, so
// anything left here from an earlier revision of this script cannot become a
// candidate under a bare library name. The directory is this build unit's own
// (Cargo scopes OUT_DIR per package, per profile, per target, and serializes
// work in a target directory), and only immediate entries are removed: a
// directory here is not recursed into but fails the build, and a symlink is
// unlinked rather than followed.
fn prepare_snapshot_dir() -> PathBuf {
    let out_dir = env::var_os("OUT_DIR")
        .unwrap_or_else(|| panic!("#9726: Cargo set no OUT_DIR for this build script"));
    let dir = PathBuf::from(&out_dir).join("xpf-linked-libxdp");
    fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("#9726: create {}: {e}", dir.display()));
    let keep = [
        LINKED_LIBXDP_ARCHIVE,
        LINKED_LIBBPF_ARCHIVE,
        LINKED_LIBELF_ARCHIVE,
        LINKED_ZLIB_ARCHIVE,
        LINKED_ZSTD_ARCHIVE,
    ];
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
fn verify_host_version_source(library: &HostLibrary) {
    // #9931: the version source is read after the snapshot is written. This
    // closes the window in which a package upgrade could leave old metadata
    // beside new archive bytes.
    let version_after = if library.pkg_configured {
        pkg_config_version(library.spec.pkg_config).unwrap_or_else(|e| {
            panic!(
                "#9931: {}'s pkg-config version became unreadable while snapshotting: {e}",
                library.spec.label
            )
        })
    } else {
        let header = library.header.as_ref().unwrap_or_else(|| {
            panic!(
                "#9931: {} has no version header to re-read after snapshotting",
                library.spec.label
            )
        });
        let text = fs::read_to_string(header).unwrap_or_else(|e| {
            panic!(
                "#9931: re-read the {} version header {} after snapshotting: {e}",
                library.spec.label,
                header.display()
            )
        });
        parse_header_version(library.spec, &text).unwrap_or_else(|| {
            panic!(
                "#9931: {} version header {} became unparseable while snapshotting",
                library.spec.label,
                header.display()
            )
        })
    };
    check_host_version(library.spec, &version_after).unwrap_or_else(|e| panic!("{e}"));
    if version_after != library.version {
        panic!(
            "#9931: {} version changed from {} to {} while snapshotting {}; \
             finish the install and build again",
            library.spec.label,
            library.version,
            version_after,
            library.archive.display()
        );
    }
    if library.pkg_configured {
        if let Some(header) = &library.header {
            let text = fs::read_to_string(header).unwrap_or_else(|e| {
                panic!(
                    "#9931: re-read the {} version header {} after snapshotting: {e}",
                    library.spec.label,
                    header.display()
                )
            });
            let header_after = parse_header_version(library.spec, &text).unwrap_or_else(|| {
                panic!(
                    "#9931: {} version header {} became unparseable while snapshotting",
                    library.spec.label,
                    header.display()
                )
            });
            if libversions::parse_version(&header_after)
                != libversions::parse_version(&version_after)
            {
                panic!(
                    "#9931: {} pkg-config reports {} after snapshotting, but its version \
                     header reports {}; finish the install and build again",
                    library.spec.label, version_after, header_after
                );
            }
        }
    }
}

fn snapshot_host_archive(dir: &Path, library: &HostLibrary) {
    let snapshot = dir.join(library.spec.snapshot_archive_name);
    // #9931: hold the bytes that will be linked while copying, then re-read
    // both the version source and archive. An upgrade racing this build must
    // fail rather than leave recorded metadata beside different archive bytes.
    let bytes = fs::read(&library.archive).unwrap_or_else(|e| {
        panic!(
            "#9931: read the {} archive {}, to snapshot it: {e}",
            library.spec.label,
            library.archive.display()
        )
    });
    fs::write(&snapshot, &bytes).unwrap_or_else(|e| {
        panic!(
            "#9931: write the {} snapshot {}: {e}",
            library.spec.label,
            snapshot.display()
        )
    });
    verify_host_version_source(library);
    let after = fs::read(&library.archive).unwrap_or_else(|e| {
        panic!(
            "#9931: re-read the {} archive {} after snapshotting: {e}",
            library.spec.label,
            library.archive.display()
        )
    });
    if after != bytes {
        panic!(
            "#9931: {} changed while this build was snapshotting {}; finish the \
             install and build again",
            library.spec.label,
            library.archive.display()
        );
    }
    println!("cargo:rerun-if-changed={}", library.archive.display());
    if let Some(header) = &library.header {
        println!("cargo:rerun-if-changed={}", header.display());
    }
    if let Some(pcfile) = &library.pcfile {
        println!("cargo:rerun-if-changed={}", pcfile.display());
    }
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

// #9726/#9931: nothing used to record which libraries went into a helper
// binary. The build now exports them for ProcessStatus and the startup log:
//   - XPF_LINKED_LIBXDP_VERSION: the build host's libxdp — the pkg-config version
//     snapshot_libxdp_archive read against the bytes it copied into OUT_DIR, which
//     are the bytes this build links as libxpfxdp.a;
//   - XPF_LINKED_LIBBPF_VERSION: the vendored libbpf's full version, from the
//     libbpf-sys that Cargo.lock pins, checked against its libbpf_version.h;
//   - XPF_BUILD_HOST_LIBBPF_VERSION: the build host's libbpf (pkg-config). It is
//     not linked, and it does not identify the libbpf headers the prebuilt
//     libxdp.a was compiled with;
//   - XPF_LINKED_LIBELF_VERSION, XPF_LINKED_ZLIB_VERSION and
//     XPF_LINKED_ZSTD_VERSION: the versions of the static archives copied into
//     this build's private snapshot directory.
fn record_library_versions(
    libxdp_libdir: &str,
    libxdp: &str,
    host_libraries: &[HostLibrary],
) {
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
    for library in host_libraries {
        let variable = match library.spec.label {
            "libelf" => "XPF_LINKED_LIBELF_VERSION",
            "zlib" => "XPF_LINKED_ZLIB_VERSION",
            "zstd" => "XPF_LINKED_ZSTD_VERSION",
            _ => panic!("#9931: unknown host library {}", library.spec.label),
        };
        println!("cargo:rustc-env={variable}={}", library.version);
    }

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
