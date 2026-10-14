//! PoC compile-validation. Tries to compile/syntax-check each generated PoC so a finding's
//! proof is shown to be at least well-formed. Cross-compiles Windows PoCs with mingw-w64 and
//! Mac PoCs with clang. A compile failure due to a missing SDK/header is reported as
//! `skipped (limitation)`, never a hard error — the PoC still ships for the analyst.

use std::path::Path;
use std::process::Command;

fn have(bin: &str) -> bool {
    Command::new("sh").arg("-c").arg(format!("command -v {bin}")).output().map(|o| o.status.success()).unwrap_or(false)
}

/// Windows vs Mac intent from the source (Win32 API / headers => windows). `pub(crate)` so
/// pocrun.rs's execute_poc can reuse the same heuristic when deciding whether a compiled C/
/// Objective-C PoC can actually be linked+run here (mac target, mac host) or only cross-
/// compiled (Windows target, no Windows runtime on the analyst's Mac to execute it on).
pub(crate) fn is_windows_src(path: &Path, text: &str) -> bool {
    let name = path.to_string_lossy().to_lowercase();
    let win_markers = ["windows.h", "createremotethread", "loadlibrary", "virtualalloc",
        "createnamedpipe", "winverifytrust", "#pragma comment", "__declspec", "GetProcAddress"];
    win_markers.iter().any(|m| text.to_lowercase().contains(&m.to_lowercase()))
        || name.contains("dll") || name.contains("windows")
}

#[derive(Debug)]
pub struct PocResult {
    pub file: String,
    pub lang: String,
    pub status: String, // compiled | syntax-ok | failed | skipped
    pub detail: String,
}

fn compile_c(path: &Path, text: &str, out_dir: &Path) -> PocResult {
    let stem = path.file_stem().unwrap_or_default().to_string_lossy().into_owned();
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("c");
    let windows = is_windows_src(path, text);
    let (cc, target, obj) = if windows {
        // object-only compile (-c): PoCs reference Win32 libs we won't link on macOS.
        let cc = if have("x86_64-w64-mingw32-gcc") { "x86_64-w64-mingw32-gcc" } else { "i686-w64-mingw32-gcc" };
        (cc, "windows", out_dir.join(format!("{stem}.obj")))
    } else {
        ("clang", "macos", out_dir.join(format!("{stem}.o")))
    };
    if !have(cc) {
        return PocResult { file: path.display().to_string(), lang: ext.into(), status: "skipped".into(),
            detail: format!("no compiler {cc} ({target})") };
    }
    let lang_flag = if ext == "m" { "-x objective-c" } else { "-x c" };
    let cmd = format!("{cc} {lang_flag} -c {:?} -o {:?} 2>&1", path, obj);
    let out = Command::new("sh").arg("-c").arg(&cmd).output();
    match out {
        Ok(o) if o.status.success() => PocResult { file: path.display().to_string(), lang: ext.into(),
            status: "compiled".into(), detail: format!("{cc} -c ok ({target})") },
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr).to_string() + &String::from_utf8_lossy(&o.stdout);
            let first = err.lines().find(|l| l.contains("error")).unwrap_or("").trim().to_string();
            // Missing SDK header => limitation, not a real failure.
            let limitation = err.contains("file not found") || err.contains("No such file");
            PocResult { file: path.display().to_string(), lang: ext.into(),
                status: if limitation { "skipped".into() } else { "failed".into() },
                detail: if first.is_empty() { "compile error".into() } else { first.chars().take(90).collect() } }
        }
        Err(e) => PocResult { file: path.display().to_string(), lang: ext.into(), status: "skipped".into(), detail: e.to_string() },
    }
}

fn check(path: &Path) -> Option<PocResult> {
    let ext = path.extension().and_then(|e| e.to_str())?.to_lowercase();
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let r = match ext.as_str() {
        "c" | "m" => {
            let td = std::env::temp_dir().join("malvex-pocval");
            std::fs::create_dir_all(&td).ok();
            compile_c(path, &text, &td)
        }
        "py" => {
            let ok = Command::new("python3").args(["-m", "py_compile"]).arg(path).output()
                .map(|o| o.status.success()).unwrap_or(false);
            PocResult { file: path.display().to_string(), lang: "py".into(),
                status: if ok { "syntax-ok".into() } else { "failed".into() }, detail: "py_compile".into() }
        }
        "js" => {
            let ok = have("node") && Command::new("node").arg("--check").arg(path).output()
                .map(|o| o.status.success()).unwrap_or(false);
            PocResult { file: path.display().to_string(), lang: "js".into(),
                status: if ok { "syntax-ok".into() } else if have("node") { "failed".into() } else { "skipped".into() },
                detail: "node --check".into() }
        }
        "sh" => {
            let ok = Command::new("sh").arg("-n").arg(path).output().map(|o| o.status.success()).unwrap_or(false);
            PocResult { file: path.display().to_string(), lang: "sh".into(),
                status: if ok { "syntax-ok".into() } else { "failed".into() }, detail: "sh -n".into() }
        }
        _ => return None,
    };
    Some(r)
}

/// Validate every PoC in <session>/poc/. Writes poc/compile-report.md, returns the results.
pub fn validate(session_dir: &Path) -> anyhow::Result<Vec<PocResult>> {
    let poc_dir = session_dir.join("poc");
    if !poc_dir.is_dir() {
        anyhow::bail!("no poc/ dir in {}", session_dir.display());
    }
    let mut results = Vec::new();
    for e in std::fs::read_dir(&poc_dir)?.flatten() {
        let p = e.path();
        if p.is_file() && p.file_name().map(|n| n != "compile-report.md").unwrap_or(true) {
            if let Some(r) = check(&p) {
                results.push(r);
            }
        }
    }
    results.sort_by(|a, b| a.file.cmp(&b.file));

    let mut md = String::from("# PoC compile-validation\n\n");
    let n = |s: &str| results.iter().filter(|r| r.status == s).count();
    md.push_str(&format!("compiled: {} · syntax-ok: {} · failed: {} · skipped(limitation): {}\n\n",
        n("compiled"), n("syntax-ok"), n("failed"), n("skipped")));
    md.push_str("| PoC | lang | status | detail |\n|---|---|---|---|\n");
    for r in &results {
        let name = Path::new(&r.file).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        md.push_str(&format!("| {} | {} | {} | {} |\n", name, r.lang, r.status, r.detail.replace('|', "\\|")));
    }
    std::fs::write(poc_dir.join("compile-report.md"), &md)?;
    Ok(results)
}
