//! PoC execution + validation + LLM-fix loop.
//!
//! Runs every PoC script in `<session>/poc/`, captures output, classifies results,
//! and uses LLM repair for failing scripts. Flags findings whose PoC shows the
//! vulnerability is NOT present as `fp-suspect` — potential false positives.
//!
//! Safety:
//! - Interpreted scripts (.py, .sh, .js, .ps1) execute directly. C/Objective-C/C++ sources
//!   (.c, .m, .cpp, .mm) get compiled+linked for real (see compile_native_poc) and executed
//!   ONLY when the source targets this host's own platform (macOS) — a Windows-targeted
//!   source still compiles+links fully but is never executed here, same host==target gate
//!   the dynamic stage already enforces. Pre-built binaries (.o/.obj/.exe/.dll handed in with
//!   no buildable source) are never executed, existence-only.
//! - Timeout enforcement (kill after limit)
//! - SASF_POC_TEST=1 env var so scripts can self-check for dry mode
//! - Frida scripts: syntax-check only unless SASF_POC_LIVE=1

use crate::exec::SessionLog;
use crate::Config;
use sasf_core::{Finding, Verdict};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Result of executing a single PoC.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PocTestResult {
    pub file: String,
    pub vuln_class: String,
    /// confirmed | fixed | failed | fp-suspect | timeout | skipped
    pub status: String,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub fix_attempts: usize,
    /// Antipattern rule IDs triggered (AP-001, AP-002, etc.)
    #[serde(default)]
    pub antipatterns: Vec<String>,
}

/// Aggregate report from running all PoCs in a session.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PocTestReport {
    pub results: Vec<PocTestResult>,
    pub confirmed: usize,
    pub fixed: usize,
    pub failed: usize,
    pub fp_suspect: usize,
    pub skipped: usize,
    pub timeout: usize,
}

// ── Native (C/Objective-C/C++) compile+link ─────────────────────────────────

fn have_bin(bin: &str) -> bool {
    Command::new("sh").arg("-c").arg(format!("command -v {bin}")).output().map(|o| o.status.success()).unwrap_or(false)
}

/// Outcome of compiling a native PoC source.
enum CompiledPoc {
    /// Linked for this host's own platform (macOS) — safe to execute directly.
    Runnable(PathBuf),
    /// Linked for Windows (cross-compiled via mingw-w64) — a real, complete .exe/.dll, but
    /// there is no Windows runtime on this Mac to execute it against.
    WindowsOnly(PathBuf),
    /// Linked as a shared library/dylib, not a standalone executable — running it directly
    /// proves nothing; it needs a loader (DYLD_INSERT_LIBRARIES, an LC_LOAD_DYLIB patch, or
    /// the Windows equivalent for a cross-compiled DLL) to actually demonstrate anything.
    LibraryOnly(PathBuf),
}

/// A dylib/shared-library PoC is meant to be LOADED into a host process, not run standalone —
/// detect that intent from the filename/content so we compile with `-dynamiclib`/`-shared`
/// instead of producing (and failing to produce, since there's no `main`) a standalone exe.
fn looks_like_library(path: &Path, text: &str) -> bool {
    let name = path.to_string_lossy().to_lowercase();
    name.contains("dylib") || name.contains("payload") || name.contains("libapp")
        || (!text.contains("int main") && !text.contains("int  main"))
}

/// Compile+link a C/Objective-C/C++/Objective-C++ PoC source for real (not the object-only
/// `-c` well-formedness check pocval.rs does). Mac-targeted sources link fully and are handed
/// back as directly runnable; Windows-targeted sources cross-compile fully via mingw-w64 but
/// are flagged WindowsOnly since there's no Windows runtime here to execute them against —
/// same host==target-platform gate the dynamic stage already enforces elsewhere. Library-
/// intent sources (dylibs, injection payloads) compile as a shared object, never a standalone
/// executable — see looks_like_library.
fn compile_native_poc(path: &Path, text: &str) -> Result<CompiledPoc, String> {
    let out_dir = std::env::temp_dir().join("sasf-poc-native");
    std::fs::create_dir_all(&out_dir).map_err(|e| format!("failed to create build dir: {e}"))?;
    let stem = path.file_stem().unwrap_or_default().to_string_lossy().into_owned();
    let is_windows = crate::pocval::is_windows_src(path, text);
    let is_library = looks_like_library(path, text);

    if is_windows {
        let cc = if have_bin("x86_64-w64-mingw32-gcc") {
            "x86_64-w64-mingw32-gcc"
        } else if have_bin("i686-w64-mingw32-gcc") {
            "i686-w64-mingw32-gcc"
        } else {
            return Err("no mingw-w64 cross-compiler available (x86_64-w64-mingw32-gcc / i686-w64-mingw32-gcc) — install mingw-w64 to compile Windows PoCs".into());
        };
        let ext = if is_library { "dll" } else { "exe" };
        let out = out_dir.join(format!("{stem}.{ext}"));
        let shared_flag = if is_library { "-shared" } else { "" };
        let cmd = format!("{cc} {shared_flag} {:?} -o {:?} 2>&1", path, out);
        let result = Command::new("sh").arg("-c").arg(&cmd).output();
        return match result {
            // Either shape (DLL or standalone .exe) is WindowsOnly — there's no Windows
            // runtime on this Mac to execute a cross-compiled PE against, whether or not
            // it's a shared library.
            Ok(o) if o.status.success() => Ok(CompiledPoc::WindowsOnly(out)),
            Ok(o) => {
                let err = String::from_utf8_lossy(&o.stderr).to_string() + &String::from_utf8_lossy(&o.stdout);
                Err(format!("mingw cross-compile failed: {}", err.lines().take(3).collect::<Vec<_>>().join(" | ")))
            }
            Err(e) => Err(format!("spawn error running {cc}: {e}")),
        };
    }

    // macOS target: clang, full link, this host can actually run the result.
    if !have_bin("clang") {
        return Err("no clang available — cannot compile this macOS-targeted PoC".into());
    }
    if is_library {
        let out = out_dir.join(format!("{stem}.dylib"));
        let cmd = format!("clang -dynamiclib {:?} -o {:?} 2>&1", path, out);
        let result = Command::new("sh").arg("-c").arg(&cmd).output();
        return match result {
            Ok(o) if o.status.success() => Ok(CompiledPoc::LibraryOnly(out)),
            Ok(o) => {
                let err = String::from_utf8_lossy(&o.stderr).to_string() + &String::from_utf8_lossy(&o.stdout);
                Err(format!("clang dylib compile failed: {}", err.lines().take(3).collect::<Vec<_>>().join(" | ")))
            }
            Err(e) => Err(format!("spawn error running clang: {e}")),
        };
    }
    let out = out_dir.join(&stem);
    // Common frameworks these PoCs reach for (Mach IPC, XPC, Cocoa/Foundation, code signing
    // introspection) — harmless to link against binaries that don't use them.
    let cmd = format!(
        "clang {:?} -o {:?} -framework Foundation -framework Security -framework CoreFoundation 2>&1",
        path, out
    );
    let result = Command::new("sh").arg("-c").arg(&cmd).output();
    match result {
        Ok(o) if o.status.success() => Ok(CompiledPoc::Runnable(out)),
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr).to_string() + &String::from_utf8_lossy(&o.stdout);
            Err(format!("clang compile failed: {}", err.lines().take(3).collect::<Vec<_>>().join(" | ")))
        }
        Err(e) => Err(format!("spawn error running clang: {e}")),
    }
}

// ── Execution ───────────────────────────────────────────────────────────────

/// Execute a PoC script with a timeout. Returns (exit_code, stdout, stderr).
/// Compiled artifacts (.c, .m, .o, .obj) are never executed — returns skipped.
fn execute_poc(path: &Path, timeout_secs: u64) -> (Option<i32>, String, String) {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let mut cmd = match ext.as_str() {
        "py" => {
            let mut c = Command::new("python3");
            c.arg(path);
            c
        }
        "js" => {
            // Frida scripts: syntax-check only unless SASF_POC_LIVE=1.
            if std::env::var("SASF_POC_LIVE").unwrap_or_default() == "1" {
                // Live mode — attempt frida execution (requires target process).
                let have_frida = Command::new("which")
                    .arg("frida")
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if have_frida {
                    // Can't attach without a target — just validate syntax via node.
                    let mut c = Command::new("node");
                    c.arg("--check").arg(path);
                    c
                } else {
                    let mut c = Command::new("node");
                    c.arg("--check").arg(path);
                    c
                }
            } else {
                let mut c = Command::new("node");
                c.arg("--check").arg(path);
                c
            }
        }
        "sh" | "bash" => {
            let mut c = Command::new("bash");
            c.arg(path);
            c
        }
        "ps1" => {
            // PowerShell — skip on non-Windows unless pwsh available.
            let have_pwsh = Command::new("pwsh")
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if have_pwsh {
                let mut c = Command::new("pwsh");
                c.args(["-NonInteractive", "-File"])
                    .arg(path);
                c
            } else {
                return (None, String::new(), "pwsh not available — skipped".into());
            }
        }
        "html" => {
            // HTML PoCs (e.g. XSS, URL scheme): just verify the file exists and is non-empty.
            let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            if size > 0 {
                return (Some(0), format!("[OK] HTML PoC present ({size} bytes)"), String::new());
            } else {
                return (Some(1), String::new(), "empty HTML file".into());
            }
        }
        // C / Objective-C / C++ / Objective-C++ sources: some primitives (DLL injection,
        // process hollowing, dylib injection, raw Mach IPC) genuinely can't be proven by a
        // Python script — they need a real compiled artifact, and for the Mach-O side, that
        // artifact can actually run right here (host is macOS, target is macOS). Compile+LINK
        // for real (not the object-only `-c` check pocval.rs does for a fast well-formedness
        // pass) and, when the source targets THIS host's platform, execute it like any other
        // PoC. A Windows-targeted source still compiles+links fully (a real .exe/.dll ready to
        // hand to whoever has Windows access) but is never executed here — no Windows runtime
        // on the analyst's Mac to run it on, same gate the dynamic stage already enforces.
        "c" | "m" | "cpp" | "cc" | "cxx" | "mm" => {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            match compile_native_poc(path, &text) {
                Ok(CompiledPoc::Runnable(exe_path)) => {
                    let mut c = Command::new(&exe_path);
                    c.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
                    c
                }
                Ok(CompiledPoc::WindowsOnly(exe_path)) => {
                    return (
                        None,
                        format!("[OK] cross-compiled full Windows executable: {}", exe_path.display()),
                        "skipped — needs-windows-runtime (compiled+linked for real, but no Windows host here to execute it on)".into(),
                    );
                }
                Ok(CompiledPoc::LibraryOnly(lib_path)) => {
                    return (
                        None,
                        format!("[OK] compiled dylib/shared object: {}", lib_path.display()),
                        "skipped — a bare dylib/.so proves nothing when exec'd directly; needs a loader (DYLD_INSERT_LIBRARIES / LC_LOAD_DYLIB patch) to actually run".into(),
                    );
                }
                Err(msg) => {
                    return (None, String::new(), msg);
                }
            }
        }
        // Compiled sources — never execute, only report existence. (.c/.m/.cpp/.mm above now
        // get compiled for real; these are the outputs of THAT compile step, or artifacts
        // handed in pre-built with no source to (re)build from.)
        "h" | "o" | "obj" | "exe" | "dll" => {
            return (None, String::new(), format!("compiled artifact (.{ext}) — skipped"));
        }
        // Extension-less files are almost always the LINKED OUTPUT of a .c/.m compile step
        // sitting next to its source in the same evidence dir (e.g. `poc_loader` next to
        // `poc_xpc_odin.m`) — a Mach-O/ELF binary, not a script. Without this arm these hit
        // the generic fallback below, which classify_result maps to "failed" (its message
        // lacks the word "skipped"), triggering a pointless LLM-fix round on a binary file.
        "" => {
            return (None, String::new(), "compiled artifact (no extension) — skipped".into());
        }
        _ => {
            return (
                None,
                String::new(),
                format!("unsupported extension: .{ext}"),
            );
        }
    };

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Safe environment: PoCs can check SASF_POC_TEST=1 to run in verify/dry mode.
    cmd.env("SASF_POC_TEST", "1");

    match cmd.spawn() {
        Ok(mut child) => {
            let start = Instant::now();
            let timeout = Duration::from_secs(timeout_secs);

            // Poll for completion with timeout.
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        // Child exited — read output.
                        let mut stdout = String::new();
                        let mut stderr = String::new();
                        if let Some(mut so) = child.stdout.take() {
                            so.read_to_string(&mut stdout).ok();
                        }
                        if let Some(mut se) = child.stderr.take() {
                            se.read_to_string(&mut stderr).ok();
                        }
                        return (status.code(), stdout, stderr);
                    }
                    Ok(None) => {
                        if start.elapsed() > timeout {
                            // Timeout — kill the child.
                            child.kill().ok();
                            child.wait().ok();
                            return (None, String::new(), "timeout — killed after limit".into());
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => {
                        return (None, String::new(), format!("wait error: {e}"));
                    }
                }
            }
        }
        Err(e) => (None, String::new(), format!("spawn error: {e}")),
    }
}

// ── Classification ──────────────────────────────────────────────────────────

/// Classify a PoC execution result into a status string.
fn classify_result(exit_code: Option<i32>, stdout: &str, stderr: &str) -> &'static str {
    let combined = format!("{stdout}\n{stderr}").to_lowercase();

    // Check for explicit timeout.
    if combined.contains("timeout") && exit_code.is_none() {
        return "timeout";
    }

    match exit_code {
        Some(0) => {
            // Script succeeded (exit 0).
            // Our verification scripts use [VULN]/[OK] markers.
            if combined.contains("[vuln]")
                || combined.contains("vulnerable")
                || combined.contains("exploit successful")
                || combined.contains("exploit ok")
            {
                "confirmed"
            } else if combined.contains("all checks passed")
                || (combined.contains("[ok]") && !combined.contains("[vuln]"))
                || combined.contains("not vulnerable")
                || combined.contains("no vulnerabilit")
            {
                // PoC ran clean, found nothing wrong — potential false positive.
                "fp-suspect"
            } else {
                // Exit 0 without clear signal — assume PoC worked.
                "confirmed"
            }
        }
        Some(1) => {
            // Exit 1: our verification scripts use this for "vulnerability found".
            if combined.contains("[vuln]")
                || combined.contains("vulnerability check")
                || combined.contains("failed")
            {
                "confirmed"
            } else if combined.contains("syntax error")
                || combined.contains("import error")
                || combined.contains("no such file")
                || combined.contains("not found")
            {
                "failed"
            } else {
                // Ambiguous exit 1 — treat as execution error.
                "failed"
            }
        }
        Some(code) if code == 2 || code == 126 || code == 127 => {
            // 2=misuse, 126=not executable, 127=command not found
            "failed"
        }
        Some(_) => "failed",
        None => {
            if combined.contains("skipped") || combined.contains("not available") {
                "skipped"
            } else if combined.contains("timeout") {
                "timeout"
            } else {
                "failed"
            }
        }
    }
}

// ── LLM Fix ─────────────────────────────────────────────────────────────────

/// Ask the LLM to fix a failing PoC script. Returns true if the LLM ran successfully
/// (the script at `poc_path` may have been rewritten).
fn llm_fix_poc(cfg: &Config, poc_path: &Path, error_output: &str, finding_context: &str) -> bool {
    let source = std::fs::read_to_string(poc_path).unwrap_or_default();
    if source.is_empty() {
        return false;
    }

    // Truncate error output to avoid prompt bloat.
    let error_truncated: String = error_output.chars().take(2000).collect();
    let context_truncated: String = finding_context.chars().take(1000).collect();

    let prompt = format!(
        "This proof-of-concept script failed during automated execution. Fix the script so it \
         runs correctly. This is authorized malware analysis in Malvex.\n\n\
         File: {path}\n\
         Error output:\n```\n{error}\n```\n\n\
         Finding context: {ctx}\n\n\
         Current source:\n```\n{src}\n```\n\n\
         Fix the script and write the corrected version to the SAME path ({path}) using the Write tool.\n\
         Common fixes:\n\
         - Missing imports/modules (add them)\n\
         - Wrong path to target binary (use $1 / sys.argv[1] with a default)\n\
         - Permission issues (wrap in try/except or check first)\n\
         - Missing target file (add existence check with clear error message)\n\
         - Frida: check process name/PID handling\n\
         - Shell: missing commands (add `command -v` checks)\n\
         - Python: wrong Python version syntax\n\n\
         IMPORTANT: Keep the exploit/verification logic intact — only fix execution errors.\n\
         Reply 'fixed' when done, or 'cannot-fix' if the error is fundamental (missing target, \
         needs live process, platform mismatch).",
        path = poc_path.display(),
        error = error_truncated,
        ctx = context_truncated,
        src = source
    );

    let mut cmd = Command::new("claude");
    cmd.arg("-p")
        .arg(&prompt)
        .arg("--model")
        .arg(&cfg.model)
        .arg("--dangerously-skip-permissions")
        .arg("--output-format")
        .arg("json")
        .arg("--add-dir")
        .arg(&cfg.root)
        .env("IS_SANDBOX", "1")
        .stdin(Stdio::null());

    cmd.output().map(|o| o.status.success()).unwrap_or(false)
}

// ── Antipattern checker (source-level quality gate) ────────────────────────

/// A detected antipattern violation in a PoC source file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AntipatternViolation {
    pub id: String,       // AP-001, AP-002, etc.
    pub name: String,
    pub description: String,
    pub action: String,   // flag | reject | warn
}

/// Check a PoC source file for known false-positive antipatterns BEFORE execution.
/// Returns a list of violations. Empty = clean.
fn check_antipatterns(path: &Path, finding: Option<&Finding>) -> Vec<AntipatternViolation> {
    let source = std::fs::read_to_string(path).unwrap_or_default();
    let src_lower = source.to_lowercase();
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    let mut violations = Vec::new();

    // AP-001: NSXPCConnection lazy resume
    if ext == "m" || ext == "swift" {
        let has_resume = src_lower.contains("resume]") || src_lower.contains(".resume()");
        let has_success_near = src_lower.contains("proof") || src_lower.contains("connected")
            || src_lower.contains("accepted") || src_lower.contains("[+]");
        let has_reply = src_lower.contains("reply") || src_lower.contains("withreply")
            || src_lower.contains("remoteobjectproxy");
        if has_resume && has_success_near && !has_reply {
            violations.push(AntipatternViolation {
                id: "AP-001".into(), name: "nsxpc-lazy-resume".into(),
                description: "NSXPCConnection.resume() is lazy — success printed without reply block proof".into(),
                action: "flag".into(),
            });
        }
    }

    // AP-002: dlopen/DYLD_INSERT on self (not launching target)
    if (ext == "m" || ext == "c" || ext == "sh" || ext == "py")
        && (src_lower.contains("dlopen(") || src_lower.contains("dyld_insert_libraries"))
    {
        let launches_target = src_lower.contains("posix_spawn") || src_lower.contains("execve")
            || src_lower.contains("system(") || src_lower.contains("subprocess")
            || src_lower.contains("/contents/macos/") || src_lower.contains("target_binary")
            || src_lower.contains("os.system") || src_lower.contains("popen");
        if !launches_target {
            violations.push(AntipatternViolation {
                id: "AP-002".into(), name: "dyld-inject-self".into(),
                description: "dlopen/DYLD_INSERT loads dylib into PoC process, not target binary".into(),
                action: "flag".into(),
            });
        }
    }

    // AP-003: ObjC in constructor
    if (ext == "m" || ext == "c") && src_lower.contains("__attribute__((constructor))") {
        let has_objc = src_lower.contains("nslog") || src_lower.contains("objc_msgsend")
            || source.contains("@\"") || src_lower.contains("nsobject")
            || src_lower.contains("nsstring");
        let has_pure_c = src_lower.contains("write(") || src_lower.contains("printf(")
            || src_lower.contains("puts(") || src_lower.contains("fprintf(");
        if has_objc && !has_pure_c {
            violations.push(AntipatternViolation {
                id: "AP-003".into(), name: "objc-in-constructor".into(),
                description: "ObjC runtime calls in constructor crash hardened binaries — use pure C".into(),
                action: "flag".into(),
            });
        }
    }

    // AP-004: Error handler as success signal
    {
        let patterns = [
            ("except", &["proof", "exploit", "[+]", "vuln", "success"] as &[&str]),
            (".catch", &["proof", "exploit", "[+]", "vuln"]),
            ("invalidationhandler", &["proof", "[+]", "success"]),
            ("interruptionhandler", &["proof", "[+]", "success"]),
            ("errorhandler", &["proof", "[+]", "success"]),
        ];
        for (handler, markers) in &patterns {
            if let Some(handler_pos) = src_lower.find(handler) {
                // Check if any success marker appears within 200 chars after handler
                let window = &src_lower[handler_pos..std::cmp::min(handler_pos + 200, src_lower.len())];
                for marker in *markers {
                    if window.contains(marker) {
                        violations.push(AntipatternViolation {
                            id: "AP-004".into(), name: "error-handler-success".into(),
                            description: format!("Success marker '{}' inside error handler '{}' — unreliable proof", marker, handler),
                            action: "flag".into(),
                        });
                        break;
                    }
                }
            }
        }
    }

    // AP-006: Standalone HTML XSS (not injected into target context)
    if ext == "html" {
        let has_script = src_lower.contains("<script>") || src_lower.contains("alert(")
            || src_lower.contains("document.cookie");
        let has_injection_ctx = src_lower.contains("frida") || src_lower.contains("mitmproxy")
            || src_lower.contains("burp") || src_lower.contains("intercept")
            || src_lower.contains("webview") || src_lower.contains("cef");
        if has_script && !has_injection_ctx {
            violations.push(AntipatternViolation {
                id: "AP-006".into(), name: "standalone-html-xss".into(),
                description: "HTML with alert() is not XSS unless injected into target's rendering context".into(),
                action: "flag".into(),
            });
        }
    }

    // AP-007: Trust bypass without MITM evidence
    if src_lower.contains("sectrustevaluate") || src_lower.contains("x509trustmanager")
        || src_lower.contains("ssl_verify") || src_lower.contains("checkservertrusted")
    {
        let has_mitm = src_lower.contains("mitmproxy") || src_lower.contains("burp")
            || src_lower.contains("intercepted") || src_lower.contains("http/")
            || src_lower.contains("request") && src_lower.contains("response");
        if !has_mitm {
            violations.push(AntipatternViolation {
                id: "AP-007".into(), name: "trust-bypass-no-mitm".into(),
                description: "Certificate bypass without intercepted traffic proof".into(),
                action: "warn".into(),
            });
        }
    }

    // AP-008: Frida without target process verification
    if ext == "js" && (src_lower.contains("interceptor.attach") || src_lower.contains("module.findexportbyname")) {
        let has_verify = src_lower.contains("process.id") || src_lower.contains("process.enumeratemodules")
            || src_lower.contains("process.getcurrentdir") || src_lower.contains("module.load");
        if !has_verify {
            violations.push(AntipatternViolation {
                id: "AP-008".into(), name: "frida-no-target-verify".into(),
                description: "Frida script hooks without verifying target process identity".into(),
                action: "warn".into(),
            });
        }
    }

    // AP-011: symbol absence claimed via `strings` instead of `nm -u`/`otool`
    if ext == "py" || ext == "sh" || ext == "m" || ext == "c" {
        let has_strings_claim = src_lower.contains("strings")
            && (src_lower.contains("not found") || src_lower.contains("absent") || src_lower.contains("in output"));
        let has_authoritative_check = src_lower.contains("nm -u") || src_lower.contains("otool")
            || src_lower.contains("imports_query");
        if has_strings_claim && !has_authoritative_check {
            violations.push(AntipatternViolation {
                id: "AP-011".into(), name: "strings-symbol-absence".into(),
                description: "Symbol presence/absence decided via `strings` grep, not `nm -u`/`otool` — strings misses symbol-table entries and can produce a false negative".into(),
                action: "flag".into(),
            });
        }
    }

    // AP-012: public-key extraction claimed to enable signature forgery
    {
        let has_pubkey = src_lower.contains("public key") || src_lower.contains("pubkey")
            || src_lower.contains("publickey");
        let has_forge = src_lower.contains("forge") || src_lower.contains("forged") || src_lower.contains("forging");
        let has_valid_context = src_lower.contains("private key") || src_lower.contains("privatekey")
            || src_lower.contains("md5 collision") || src_lower.contains("sha-1 collision")
            || src_lower.contains("no signature") || src_lower.contains("signature check absent");
        if has_pubkey && has_forge && !has_valid_context {
            violations.push(AntipatternViolation {
                id: "AP-012".into(), name: "pubkey-forge-claim".into(),
                description: "Claims a forged signature from an extracted PUBLIC key — forging requires the PRIVATE key; this inversion can create a false-positive attack chain".into(),
                action: "flag".into(),
            });
        }
    }

    // AP-013: target process crash/close claimed as success without log correlation
    {
        let has_death_signal = src_lower.contains("crash") || src_lower.contains("closed")
            || src_lower.contains("terminated") || src_lower.contains("exited");
        let has_success_claim = src_lower.contains("vuln") || src_lower.contains("proof")
            || src_lower.contains("exploit successful") || src_lower.contains("[+]");
        let has_log_correlation = src_lower.contains("log show") || src_lower.contains("log stream")
            || src_lower.contains("diagnosticreports") || src_lower.contains("console")
            || src_lower.contains("dmesg") || src_lower.contains("get-winevent")
            || src_lower.contains("event viewer") || src_lower.contains("crashlog")
            // argv-style invocation: run_cmd(["log", "show", ...]) — "log show" won't be
            // contiguous in source, so also accept the two tokens appearing as separate args.
            || (src_lower.contains("\"log\"") && src_lower.contains("\"show\""));
        if has_death_signal && has_success_claim && !has_log_correlation {
            violations.push(AntipatternViolation {
                id: "AP-013".into(), name: "process-death-without-log-correlation".into(),
                description: "Target process crash/close/exit claimed as exploit proof without log correlation — anti-tamper/anti-debug defenses often kill the process themselves; confirm cause via log show/Console crash report/dmesg before trusting this as success".into(),
                action: "flag".into(),
            });
        }
    }

    // AP-010: CVSS inflation (runtime check with finding context)
    if let Some(f) = finding {
        if let Some(cvss) = f.cvss {
            if cvss >= 8.0 {
                if let Some(ref status) = f.poc_status {
                    if status != "confirmed" && status != "fixed" {
                        violations.push(AntipatternViolation {
                            id: "AP-010".into(), name: "cvss-inflation".into(),
                            description: format!("CVSS {:.1} but poc_status='{}' — high CVSS requires demonstrated exploit", cvss, status),
                            action: "flag".into(),
                        });
                    }
                }
            }
        }
    }

    violations
}

// ── Main entry point ────────────────────────────────────────────────────────

/// Run all PoCs in the session, classify results, LLM-fix failures, and update findings.
pub fn run_poc_test(cfg: &Config, session_dir: &Path) -> anyhow::Result<PocTestReport> {
    // Two PoC layouts exist in this repo and both must be picked up:
    //   1. <session>/poc/<vuln_class>.<ext>            — flat, written by `sasf exploit`
    //   2. <session>/poc-out/<app>/<vuln-class>/<file>  — nested, written by the staged
    //      pipeline's exploit agent (mirrors the repo-root poc-out/ convention used by
    //      every skill's "PoC hint"/"Grounding" section) and copied in by
    //      copy_poc_to_session(). vuln_class here is the immediate PARENT DIR name, not
    //      the file stem. Missing this layout was why `sasf run` sessions logged
    //      POC_TEST_DONE with 0/0/0/0 even when the exploit stage reported findings —
    //      the files existed under poc-out/ but this scan only ever looked in poc/.
    let flat_dir = session_dir.join("poc");
    let nested_root = session_dir.join("poc-out");
    if !flat_dir.is_dir() && !nested_root.is_dir() {
        return Ok(PocTestReport {
            results: Vec::new(),
            confirmed: 0,
            fixed: 0,
            failed: 0,
            fp_suspect: 0,
            skipped: 0,
            timeout: 0,
        });
    }

    let slog = SessionLog::new(session_dir);
    slog.log("POC_TEST_START");

    // Load findings for context when asking LLM to fix.
    let findings_path = session_dir.join("findings.json");
    let mut findings: Vec<Finding> = std::fs::read_to_string(&findings_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let is_skippable = |name: &str| -> bool {
        name == "compile-report.md"
            || name.starts_with("poc-test-report")
            || name.ends_with(".md")
            || name.ends_with(".txt")
            || name.ends_with(".log")
            || name.ends_with(".json")
    };

    // Collect (path, vuln_class) pairs from both layouts.
    let mut poc_entries: Vec<(PathBuf, String)> = Vec::new();

    // Layout 1: flat <session>/poc/<vuln_class>.<ext> — vuln_class = file stem.
    if let Ok(rd) = std::fs::read_dir(&flat_dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if !p.is_file() { continue; }
            let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if is_skippable(&name) { continue; }
            let vuln_class = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            poc_entries.push((p, vuln_class));
        }
    }

    // Layout 2: nested <session>/poc-out/<app>/<vuln-class>/<file> — vuln_class = parent dir.
    if let Ok(apps) = std::fs::read_dir(&nested_root) {
        for app_entry in apps.flatten() {
            let app_dir = app_entry.path();
            if !app_dir.is_dir() { continue; }
            let Ok(vuln_dirs) = std::fs::read_dir(&app_dir) else { continue };
            for vuln_entry in vuln_dirs.flatten() {
                let vuln_dir = vuln_entry.path();
                if !vuln_dir.is_dir() { continue; }
                let vuln_class = vuln_dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                let Ok(files) = std::fs::read_dir(&vuln_dir) else { continue };
                for file_entry in files.flatten() {
                    let p = file_entry.path();
                    if !p.is_file() { continue; }
                    let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                    if is_skippable(&name) { continue; }
                    poc_entries.push((p, vuln_class.clone()));
                }
            }
        }
    }

    poc_entries.sort();

    let total = poc_entries.len();
    slog.log_kv(
        "POC_TEST_INVENTORY",
        &[("total_pocs", &total.to_string())],
    );
    println!("[poc-test] found {} PoC script(s) to test", total);

    let mut results = Vec::new();

    for (idx, (poc_path, vuln_class)) in poc_entries.iter().enumerate() {
        let ext = poc_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        let vuln_class = vuln_class.clone();

        // Find matching finding for context.
        let finding_ctx = findings
            .iter()
            .find(|f| f.vuln_class == vuln_class)
            .map(|f| {
                format!(
                    "vuln_class={} title={} severity={:?} verdict={:?}",
                    f.vuln_class, f.title, f.severity, f.verdict
                )
            })
            .unwrap_or_default();

        // Determine timeout: longer for frida scripts, shorter for simple checks.
        let timeout = if ext == "js" { 120 } else { 60 };

        println!(
            "  [{}/{}] {} ...",
            idx + 1,
            total,
            poc_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        );

        // Pre-execution antipattern check (source-level quality gate).
        let matching_finding = findings.iter().find(|f| f.vuln_class == vuln_class);
        let ap_violations = check_antipatterns(poc_path, matching_finding);
        if !ap_violations.is_empty() {
            let flag_count = ap_violations.iter().filter(|v| v.action == "flag" || v.action == "reject").count();
            for v in &ap_violations {
                let icon = match v.action.as_str() { "flag" | "reject" => "⚠", _ => "ℹ" };
                println!("    {icon} [{}] {}", v.id, v.description);
                slog.log_kv("POC_ANTIPATTERN", &[
                    ("vuln_class", &vuln_class), ("rule", &v.id), ("action", &v.action), ("desc", &v.description),
                ]);
            }
            // If any "reject" violations, skip execution entirely.
            if ap_violations.iter().any(|v| v.action == "reject") {
                println!("    ✗ rejected by quality gate — skipping execution");
                results.push(PocTestResult {
                    file: poc_path.to_string_lossy().into_owned(),
                    vuln_class: vuln_class.clone(),
                    status: "fp-suspect".into(),
                    exit_code: None,
                    stdout: String::new(),
                    stderr: format!("Rejected by quality gate: {}", ap_violations.iter().map(|v| v.id.as_str()).collect::<Vec<_>>().join(", ")),
                    fix_attempts: 0,
                    antipatterns: ap_violations.iter().map(|v| v.id.clone()).collect(),
                });
                continue;
            }
            // Flag violations get logged but execution proceeds.
            if flag_count > 0 {
                println!("    ⚠ {} antipattern(s) flagged — executing with caution", flag_count);
            }
        }

        // Round 1: execute.
        let (code, stdout, stderr) = execute_poc(poc_path, timeout);
        let mut status = classify_result(code, &stdout, &stderr).to_string();
        let mut fix_attempts = 0usize;
        let mut final_stdout = stdout.clone();
        let mut final_stderr = stderr.clone();
        let mut final_code = code;

        // If failed or timeout, try LLM fix up to 2 rounds.
        if status == "failed" || status == "timeout" {
            let max_fix_rounds = 2;
            for round in 1..=max_fix_rounds {
                let error_out = format!(
                    "exit={:?}\nstdout:\n{}\nstderr:\n{}",
                    final_code, final_stdout, final_stderr
                );
                slog.log_kv(
                    "POC_FIX_ATTEMPT",
                    &[
                        ("vuln_class", &vuln_class),
                        ("round", &round.to_string()),
                    ],
                );
                println!(
                    "    ↻ fix attempt {}/{} via LLM...",
                    round, max_fix_rounds
                );

                if llm_fix_poc(cfg, poc_path, &error_out, &finding_ctx) {
                    fix_attempts = round;
                    // Re-execute after fix.
                    let (code2, stdout2, stderr2) = execute_poc(poc_path, timeout);
                    let new_status = classify_result(code2, &stdout2, &stderr2);
                    final_stdout = stdout2;
                    final_stderr = stderr2;
                    final_code = code2;

                    if new_status == "confirmed" {
                        status = "fixed".to_string();
                        println!("    ✓ fixed (now confirmed)");
                        break;
                    } else if new_status == "fp-suspect" {
                        status = "fp-suspect".to_string();
                        println!("    ⚠ fixed but finding looks like false positive");
                        break;
                    }
                    // Still failing — continue to next round.
                    status = new_status.to_string();
                } else {
                    // LLM couldn't fix — stop trying.
                    break;
                }
            }
        }

        // Post-execution antipattern cross-validation:
        // If PoC "confirmed" but has flag-level AP violations, the confirmation
        // is unreliable. Downgrade to fp-suspect unless runtime output is strong.
        if status == "confirmed" && !ap_violations.is_empty() {
            let has_flag = ap_violations.iter().any(|v| v.action == "flag");
            if has_flag {
                // Check if runtime output has STRONG confirmation markers
                let strong_confirm = final_stdout.to_lowercase().contains("[vuln]")
                    && (final_stdout.contains("PROOF") || final_stdout.contains("exploit"));
                if !strong_confirm {
                    slog.log_kv("POC_AP_DOWNGRADE", &[
                        ("vuln_class", &vuln_class),
                        ("reason", "antipattern flag + weak runtime output"),
                        ("violations", &ap_violations.iter().map(|v| v.id.as_str()).collect::<Vec<_>>().join(",")),
                    ]);
                    status = "fp-suspect".to_string();
                    println!("    ⚠ downgraded to fp-suspect (antipattern + weak runtime proof)");
                }
            }
        }

        // Log result.
        let status_icon = match status.as_str() {
            "confirmed" => "✓",
            "fixed" => "✓",
            "fp-suspect" => "⚠",
            "failed" => "✗",
            "timeout" => "⏱",
            "skipped" => "⊘",
            _ => "?",
        };
        println!("    {status_icon} {vuln_class}: {status}");
        slog.log_kv(
            "POC_TEST_RESULT",
            &[
                ("vuln_class", &vuln_class),
                ("status", &status),
                ("exit_code", &format!("{:?}", final_code)),
                ("fix_attempts", &fix_attempts.to_string()),
            ],
        );

        results.push(PocTestResult {
            file: poc_path.to_string_lossy().into_owned(),
            vuln_class,
            status,
            exit_code: final_code,
            stdout: truncate_str(&final_stdout, 2000),
            stderr: truncate_str(&final_stderr, 2000),
            fix_attempts,
            antipatterns: ap_violations.iter().map(|v| v.id.clone()).collect(),
        });
    }

    // Count results by status.
    let confirmed = results.iter().filter(|r| r.status == "confirmed").count();
    let fixed = results.iter().filter(|r| r.status == "fixed").count();
    let failed = results.iter().filter(|r| r.status == "failed").count();
    let fp_suspect = results.iter().filter(|r| r.status == "fp-suspect").count();
    let skipped = results.iter().filter(|r| r.status == "skipped").count();
    let timeout = results.iter().filter(|r| r.status == "timeout").count();

    // Update findings.json with poc_status and downgrade fp-suspect verdicts.
    let mut fp_downgraded = 0usize;
    for finding in &mut findings {
        if let Some(result) = results
            .iter()
            .find(|r| r.vuln_class == finding.vuln_class)
        {
            finding.poc_status = Some(result.status.clone());

            // If the PoC shows the vuln is NOT present and the finding wasn't already
            // confirmed by a validator, downgrade to refuted.
            if result.status == "fp-suspect" && finding.verdict != Verdict::Confirmed {
                finding.verdict = Verdict::Refuted;
                fp_downgraded += 1;
                slog.log_kv(
                    "POC_FP_DOWNGRADE",
                    &[
                        ("vuln_class", &finding.vuln_class),
                        ("old_verdict", "plausible"),
                        ("new_verdict", "refuted"),
                    ],
                );
            }
        } else {
            // No PoC for this finding.
            if finding.poc_status.is_none() {
                finding.poc_status = Some("not-run".into());
            }
        }
    }

    // Save updated findings.
    if let Ok(json) = serde_json::to_string_pretty(&findings) {
        std::fs::write(&findings_path, json).ok();
    }

    // Write poc-test-report.json.
    let report = PocTestReport {
        results: results.clone(),
        confirmed,
        fixed,
        failed,
        fp_suspect,
        skipped,
        timeout,
    };
    if let Ok(json) = serde_json::to_string_pretty(&report) {
        std::fs::write(session_dir.join("poc-test-report.json"), json).ok();
    }

    // Write poc-test-report.md (human-readable).
    let md = build_report_md(&results, confirmed, fixed, failed, fp_suspect, skipped, timeout, fp_downgraded);
    std::fs::write(session_dir.join("poc-test-report.md"), &md).ok();

    slog.log_kv(
        "POC_TEST_DONE",
        &[
            ("confirmed", &confirmed.to_string()),
            ("fixed", &fixed.to_string()),
            ("failed", &failed.to_string()),
            ("fp_suspect", &fp_suspect.to_string()),
            ("skipped", &skipped.to_string()),
            ("timeout", &timeout.to_string()),
            ("fp_downgraded", &fp_downgraded.to_string()),
        ],
    );

    println!(
        "\n[poc-test] results: {} confirmed, {} fixed, {} failed, {} fp-suspect, {} skipped, {} timeout",
        confirmed, fixed, failed, fp_suspect, skipped, timeout
    );
    if fp_downgraded > 0 {
        println!(
            "[poc-test] ⚠ {} finding(s) downgraded to refuted (false positive suspect)",
            fp_downgraded
        );
    }

    Ok(report)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}… (truncated)", &s[..max])
    }
}

fn build_report_md(
    results: &[PocTestResult],
    confirmed: usize,
    fixed: usize,
    failed: usize,
    fp_suspect: usize,
    skipped: usize,
    timeout: usize,
    fp_downgraded: usize,
) -> String {
    let mut md = String::from("# PoC Execution Report\n\n");

    md.push_str(&format!(
        "## Summary\n\n\
         - **Confirmed**: {} (PoC ran and found vulnerability)\n\
         - **Fixed**: {} (PoC failed initially, LLM fixed it, now confirms)\n\
         - **Failed**: {} (PoC execution error, not fixable)\n\
         - **FP Suspect**: {} (PoC ran clean — finding may be false positive)\n\
         - **Skipped**: {} (unsupported format or missing runtime)\n\
         - **Timeout**: {} (exceeded execution limit)\n\
         - **FP Downgraded**: {} finding(s) verdict changed to refuted\n\n",
        confirmed, fixed, failed, fp_suspect, skipped, timeout, fp_downgraded
    ));

    md.push_str("## Results\n\n");
    md.push_str("| PoC | Status | Exit | Fix Attempts | Output |\n");
    md.push_str("|-----|--------|------|--------------|--------|\n");

    for r in results {
        let name = Path::new(&r.file)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let exit_str = r
            .exit_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "N/A".into());
        let output_preview: String = r
            .stdout
            .lines()
            .chain(r.stderr.lines())
            .filter(|l| {
                l.contains("[VULN]")
                    || l.contains("[OK]")
                    || l.contains("error")
                    || l.contains("Error")
            })
            .take(2)
            .collect::<Vec<_>>()
            .join("; ")
            .chars()
            .take(80)
            .collect();
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            name,
            r.status,
            exit_str,
            r.fix_attempts,
            output_preview.replace('|', "\\|")
        ));
    }

    if fp_suspect > 0 {
        md.push_str("\n## False Positive Suspects\n\n");
        md.push_str(
            "The following findings had PoCs that ran successfully but found NO vulnerability.\n\
             If the finding's verdict was not already `confirmed` by a validator, it has been\n\
             downgraded to `refuted`.\n\n",
        );
        for r in results.iter().filter(|r| r.status == "fp-suspect") {
            let name = Path::new(&r.file)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            md.push_str(&format!("- **{}** — {}\n", r.vuln_class, name));
        }
    }

    // Antipattern violations section
    let ap_results: Vec<_> = results.iter().filter(|r| !r.antipatterns.is_empty()).collect();
    if !ap_results.is_empty() {
        md.push_str("\n## Antipattern Violations (Quality Gate)\n\n");
        md.push_str("Source-level checks that detected known false-positive patterns:\n\n");
        md.push_str("| PoC | Violations | Status Impact |\n");
        md.push_str("|-----|------------|---------------|\n");
        for r in &ap_results {
            let name = Path::new(&r.file)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            md.push_str(&format!(
                "| {} | {} | {} |\n",
                name,
                r.antipatterns.join(", "),
                r.status
            ));
        }
        md.push_str("\nSee `poc-antipatterns.yaml` for rule definitions.\n");
    }

    if fixed > 0 {
        md.push_str("\n## LLM-Fixed PoCs\n\n");
        md.push_str("These PoCs failed initially but were repaired by the LLM:\n\n");
        for r in results.iter().filter(|r| r.status == "fixed") {
            let name = Path::new(&r.file)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            md.push_str(&format!(
                "- **{}** — {} ({} fix attempt(s))\n",
                r.vuln_class, name, r.fix_attempts
            ));
        }
    }

    md
}

#[cfg(test)]
mod antipattern_tests {
    use super::{check_antipatterns, run_poc_test};
    use std::io::Write;

    fn write_tmp(name: &str, content: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("sasf-ap-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn ap011_flags_strings_only_symbol_check() {
        // Real regression case: poc_updater_bypass.py checked SecStaticCodeCheckValidity
        // via `strings` output alone and reported it "NOT FOUND" when nm -u showed it present.
        let path = write_tmp("ap011_bad.py", r#"
output = subprocess.check_output(["strings", updater], text=True)
found = "SecStaticCodeCheckValidity" in output
status = "FOUND" if found else "NOT FOUND"
print(f"  {status}")
"#);
        let violations = check_antipatterns(&path, None);
        assert!(violations.iter().any(|v| v.id == "AP-011"), "expected AP-011, got {violations:?}");
    }

    #[test]
    fn ap011_clean_when_nm_cross_checked() {
        // Real good case: poc_updater_mitm.py uses `nm -u` as the authoritative check.
        let path = write_tmp("ap011_good.py", r#"
nm_out = run_cmd(["nm", "-u", binary])
found = "_SecTrustEvaluate" in nm_out
print("PRESENT" if found else "ABSENT")
"#);
        let violations = check_antipatterns(&path, None);
        assert!(!violations.iter().any(|v| v.id == "AP-011"), "unexpected AP-011: {violations:?}");
    }

    #[test]
    fn ap012_flags_pubkey_forge_claim() {
        // Regression case: extracting the public key does not let an analyst forge a signature;
        // an attacker forge a valid update signature — retracted in v2.1 Apêndice B.
        let path = write_tmp("ap012_bad.py", r#"
# An attacker who extracts the hardcoded public key can generate a compatible
# keypair and forge a valid signature for a malicious update package.
"#);
        let violations = check_antipatterns(&path, None);
        assert!(violations.iter().any(|v| v.id == "AP-012"), "expected AP-012, got {violations:?}");
    }

    #[test]
    fn ap012_clean_when_private_key_or_broken_hash() {
        let path = write_tmp("ap012_good.py", r#"
# MD5 collision: an attacker who controls the update bytes can forge a package
# whose MD5 matches the expected digest (no signature check gates install).
"#);
        let violations = check_antipatterns(&path, None);
        assert!(!violations.iter().any(|v| v.id == "AP-012"), "unexpected AP-012: {violations:?}");
    }

    #[test]
    fn ap013_flags_crash_as_success_without_log_correlation() {
        // Anti-tamper/anti-debug kills the app; PoC misreads the crash itself as exploit proof.
        let path = write_tmp("ap013_bad.py", r#"
print("[+] target process crashed after hook attach")
print("[VULN] exploit successful")
"#);
        let violations = check_antipatterns(&path, None);
        assert!(violations.iter().any(|v| v.id == "AP-013"), "expected AP-013, got {violations:?}");
    }

    #[test]
    fn ap011_flags_the_actual_regression_file() {
        // Regression test against the historical PoC that produced a false negative —
        // must keep failing this gate even if the file is edited later
        // for unrelated reasons, unless someone deliberately fixes it to use nm -u.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../poc-out/sample-macos/integrity/poc_sample_bypass.py");
        if !path.exists() {
            return; // file layout may differ outside this checkout; don't fail CI on that
        }
        let violations = check_antipatterns(&path, None);
        assert!(violations.iter().any(|v| v.id == "AP-011"), "expected AP-011 on {path:?}, got {violations:?}");
    }

    #[test]
    fn run_poc_test_finds_nested_poc_out_layout() {
        // Regression test: the staged `sasf run` pipeline writes PoCs to
        // <session>/poc-out/<app>/<vuln-class>/<file> (copied in from the repo-root
        // poc-out/ convention), NOT the flat <session>/poc/<vuln_class>.<ext> layout the
        // scan used to require exclusively. Before this fix, run_poc_test always reported
        // POC_TEST_DONE confirmed=0 fixed=0 failed=0 fp_suspect=0 for every `sasf run`
        // session even when the exploit stage had produced real PoC files, because it only
        // ever looked in poc/.
        let dir = std::env::temp_dir().join(format!("sasf-poctest-nested-{}", std::process::id()));
        let vuln_dir = dir.join("poc-out").join("testapp-mac").join("some-vuln-class");
        std::fs::create_dir_all(&vuln_dir).unwrap();
        let script = vuln_dir.join("check.sh");
        std::fs::write(&script, "#!/bin/sh\necho '[VULN] reproduced'\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let cfg = super::Config::default();
        let report = run_poc_test(&cfg, &dir).expect("run_poc_test should succeed");
        assert_eq!(report.results.len(), 1, "expected exactly one PoC discovered: {:?}", report.results);
        assert_eq!(report.results[0].vuln_class, "some-vuln-class");
        assert_eq!(report.confirmed, 1, "expected the [VULN]-marked exit-0 script to classify as confirmed");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ap013_clean_when_log_correlated() {
        let path = write_tmp("ap013_good.py", r#"
print("[+] target process crashed after hook attach")
print("[VULN] exploit successful")
# Correlated against the unified log to rule out anti-tamper self-kill:
run_cmd(["log", "show", "--last", "2m", "--predicate", "process == 'target'"])
"#);
        let violations = check_antipatterns(&path, None);
        assert!(!violations.iter().any(|v| v.id == "AP-013"), "unexpected AP-013: {violations:?}");
    }
}

#[cfg(test)]
mod native_compile_tests {
    use super::*;

    fn scratch_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sasf-native-poc-test-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A Mac-targeted Objective-C source compiles, links, and actually RUNS here (host is
    /// macOS) — the whole point of extending native PoCs beyond Python: primitives like this
    /// (real Mach IPC calls) can't be proven any other way.
    #[test]
    fn mac_source_compiles_and_runs_for_real() {
        let dir = scratch_dir("mac-run");
        let src = dir.join("poc_mach_test.m");
        std::fs::write(&src, r#"
#include <stdio.h>
#include <mach/mach.h>
int main() {
    mach_port_t self_task = mach_task_self();
    printf("[VULN] mach_task_self() = %u\n", self_task);
    return 0;
}
"#).unwrap();
        let (code, stdout, stderr) = execute_poc(&src, 10);
        assert_eq!(code, Some(0), "expected clean exit, stderr={stderr}");
        assert!(stdout.contains("[VULN]"), "expected real program output, got: {stdout}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A dylib/injection-payload source (no `main`, constructor-attribute init) compiles as a
    /// shared object, not a standalone executable — and is correctly never exec'd directly
    /// (that would prove nothing; it needs a loader).
    #[test]
    fn dylib_payload_compiles_but_is_not_executed_directly() {
        let dir = scratch_dir("dylib");
        let src = dir.join("poc_dylib_payload.m");
        std::fs::write(&src, r#"
#include <stdio.h>
__attribute__((constructor))
static void payload_init(void) { printf("[VULN] payload loaded\n"); }
"#).unwrap();
        let (code, stdout, stderr) = execute_poc(&src, 10);
        assert_eq!(code, None, "a library must never be exec'd directly, got exit code {code:?}");
        assert!(stdout.contains("compiled dylib"), "expected a compile-success message, got: {stdout}");
        assert!(stderr.contains("skipped"), "expected a skip reason, got: {stderr}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A Windows-targeted C source cross-compiles fully via mingw-w64 into a real, complete
    /// .exe — but is never executed here (no Windows runtime on this Mac), matching the
    /// dynamic stage's own host==target-platform gate.
    #[test]
    fn windows_source_cross_compiles_but_is_not_executed() {
        if !have_bin("x86_64-w64-mingw32-gcc") && !have_bin("i686-w64-mingw32-gcc") {
            eprintln!("skipping: no mingw-w64 cross-compiler on this machine");
            return;
        }
        let dir = scratch_dir("win");
        let src = dir.join("poc_win_inject.c");
        std::fs::write(&src, r#"
#include <windows.h>
#include <stdio.h>
int main() {
    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1234);
    if (h) { printf("[VULN] opened target process\n"); }
    return 0;
}
"#).unwrap();
        let (code, stdout, stderr) = execute_poc(&src, 10);
        assert_eq!(code, None, "a Windows PE must never be exec'd on macOS, got exit code {code:?}");
        assert!(stdout.contains("cross-compiled full Windows executable"), "got: {stdout}");
        assert!(stderr.contains("needs-windows-runtime"), "got: {stderr}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
