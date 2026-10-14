//! Installer/container unpacking — works from macOS/Linux, no Windows needed.
//!
//! Windows malware samples may ship as MSI, and installers may nest CAB/NSIS/Inno. This
//! peels them so the PE binaries inside can be reverse-engineered statically from a Mac.
//! Strategy per format, first available tool wins:
//!   MSI  -> msiextract | 7z | binwalk-carve
//!   CAB  -> cabextract | 7z
//!   EXE installer (NSIS/Inno/SFX) -> 7z
//! After extraction, recursively unpack nested installers and return the Mach-O/PE files.

use std::path::{Path, PathBuf};
use std::process::Command;

fn have(bin: &str) -> bool {
    Command::new("sh").arg("-c").arg(format!("command -v {bin}")).output().map(|o| o.status.success()).unwrap_or(false)
}

/// First available 7-Zip binary name (macOS `sevenzip` ships `7zz`; Linux `7z`/`7za`).
fn sevenzip() -> Option<&'static str> {
    ["7z", "7zz", "7za"].into_iter().find(|b| have(b))
}

/// Sniff container type from magic + extension.
pub fn kind_of(path: &Path) -> &'static str {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    let magic = std::fs::File::open(path).ok().and_then(|mut f| {
        use std::io::Read;
        let mut b = [0u8; 8];
        f.read_exact(&mut b).ok().map(|_| b)
    });
    match ext.as_str() {
        "msi" => return "msi",
        "cab" => return "cab",
        "msix" | "appx" | "zip" | "nupkg" => return "zip",
        _ => {}
    }
    match magic {
        // MSI/compound-file: D0 CF 11 E0 A1 B1 1A E1
        Some([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) => "msi",
        // MSCF cabinet
        Some([0x4D, 0x53, 0x43, 0x46, ..]) => "cab",
        // PK zip (msix/appx/jar/nsis-zip)
        Some([0x50, 0x4B, 0x03, 0x04, ..]) => "zip",
        // MZ — could be an NSIS/Inno/SFX installer exe
        Some([0x4D, 0x5A, ..]) => "exe",
        _ => "unknown",
    }
}

/// Is this file a Mach-O or PE binary worth analyzing?
fn is_binary(path: &Path) -> bool {
    use std::io::Read;
    let mut b = [0u8; 4];
    std::fs::File::open(path).ok().and_then(|mut f| f.read_exact(&mut b).ok()).is_some()
        && matches!(
            b,
            [0xCF, 0xFA, 0xED, 0xFE] | [0xCE, 0xFA, 0xED, 0xFE] | [0xCA, 0xFE, 0xBA, 0xBE] // mach-o/fat
                | [0x4D, 0x5A, _, _] // PE (MZ)
        )
}

fn run(cmd: &str) -> bool {
    Command::new("sh").arg("-c").arg(cmd).output().map(|o| o.status.success()).unwrap_or(false)
}

/// Extract one container into `out_dir`. Returns true if a tool ran successfully.
fn extract_one(path: &Path, out_dir: &Path) -> Result<bool, String> {
    std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    let p = path.to_string_lossy();
    let o = out_dir.to_string_lossy();
    let ok = match kind_of(path) {
        "msi" => {
            if have("msiextract") {
                run(&format!("cd {o:?} && msiextract {p:?} >/dev/null 2>&1"))
            } else if let Some(z) = sevenzip() {
                run(&format!("{z} x -y -o{o:?} {p:?} >/dev/null 2>&1"))
            } else if have("binwalk") {
                // last resort: carve embedded CABs/streams
                run(&format!("binwalk -e -C {o:?} {p:?} >/dev/null 2>&1"))
            } else {
                return Err("no MSI extractor (install msitools or sevenzip)".into());
            }
        }
        "cab" => {
            if have("cabextract") {
                run(&format!("cabextract -d {o:?} {p:?} >/dev/null 2>&1"))
            } else if let Some(z) = sevenzip() {
                run(&format!("{z} x -y -o{o:?} {p:?} >/dev/null 2>&1"))
            } else {
                return Err("no CAB extractor (install cabextract or sevenzip)".into());
            }
        }
        "zip" | "exe" => {
            if let Some(z) = sevenzip() {
                run(&format!("{z} x -y -o{o:?} {p:?} >/dev/null 2>&1"))
            } else if kind_of(path) == "zip" {
                run(&format!("cd {o:?} && unzip -o {p:?} >/dev/null 2>&1"))
            } else {
                return Err("no installer extractor (install sevenzip)".into());
            }
        }
        _ => return Ok(false),
    };
    Ok(ok)
}

/// Recursively extract an installer and collect the PE/Mach-O binaries inside.
/// `out_root` gets a subtree; returns (all extracted binary paths, log lines).
pub fn extract_recursive(input: &Path, out_root: &Path) -> (Vec<String>, Vec<String>) {
    let mut binaries = Vec::new();
    let mut log = Vec::new();
    let mut queue: Vec<PathBuf> = vec![input.to_path_buf()];
    let mut depth = 0;

    while let Some(container) = queue.pop() {
        if depth > 6 {
            log.push("max nesting depth reached".into());
            break;
        }
        let k = kind_of(&container);
        if k == "unknown" {
            continue;
        }
        let stem = container.file_stem().and_then(|s| s.to_str()).unwrap_or("x");
        let out = out_root.join(format!("{stem}_{depth}"));
        match extract_one(&container, &out) {
            Ok(true) => log.push(format!("extracted {k}: {} -> {}", container.display(), out.display())),
            Ok(false) => continue,
            Err(e) => {
                log.push(format!("extract {} failed: {e}", container.display()));
                continue;
            }
        }
        depth += 1;
        // walk the output: collect binaries, enqueue nested installers.
        walk(&out, &mut |p| {
            if is_binary(p) {
                binaries.push(p.to_string_lossy().into_owned());
            } else if matches!(kind_of(p), "msi" | "cab" | "zip") {
                queue.push(p.to_path_buf());
            }
        });
    }

    binaries.sort();
    binaries.dedup();
    (binaries, log)
}

fn walk(dir: &Path, f: &mut dyn FnMut(&Path)) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, f);
        } else {
            f(&p);
        }
    }
}

/// Public entry: unpack an installer next to it under <parent>/<name>.extracted/ and
/// return the binaries found. Used by `malvex extract` and by the run pipeline when the
/// target is an installer rather than a raw binary.
pub fn unpack(input: &Path) -> anyhow::Result<(Vec<String>, Vec<String>)> {
    let parent = input.parent().unwrap_or(Path::new("."));
    let name = input.file_name().and_then(|s| s.to_str()).unwrap_or("installer");
    let out_root = parent.join(format!("{name}.extracted"));
    std::fs::create_dir_all(&out_root)?;
    Ok(extract_recursive(input, &out_root))
}
