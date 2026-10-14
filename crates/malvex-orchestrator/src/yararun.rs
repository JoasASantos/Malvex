//! YARA detection-rule generation + validation, one rule per exploited finding — runs right
//! after poc-test. A rule that hasn't actually been compiled and run against the real target
//! is just a string someone wrote; this module treats "well validated" the same way pocrun.rs
//! treats a PoC: never trust the LLM's own claim, always execute it for real.
//!
//! Two phases, mirroring exploit/poc-test's own split:
//!   1. generate — `agents/yara-gen.md` writes one `.yar` file per finding with a real PoC to
//!      `<session>/yara/<vuln_class>.yar`, grounded in that finding's actual evidence.
//!   2. validate — deterministic, no LLM by default: compile each rule with the real `yara`
//!      binary, require it to MATCH the actual target (positive test) and NOT match a small
//!      corpus of unrelated clean binaries (negative/false-positive test). A rule that fails
//!      either check goes through up to 2 rounds of LLM repair, then is reported as-is.
//!
//! Layout on disk:
//!   <session>/yara/<vuln_class>.yar
//!   <session>/yara/<vuln_class>.validation.json
//!   <session>/yara-report.md
//!   <session>/yara-report.json

use crate::Config;
use malvex_core::{Finding, Target};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleResult {
    pub vuln_class: String,
    pub file: String,
    /// valid | too-broad | no-match | syntax-error | tool-missing
    pub status: String,
    pub matched_target: bool,
    /// Clean-corpus files this rule incorrectly matched, if any.
    pub false_positive_hits: Vec<String>,
    pub fix_attempts: usize,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct YaraReport {
    pub results: Vec<YaraRuleResult>,
    pub valid: usize,
    pub too_broad: usize,
    pub no_match: usize,
    pub syntax_error: usize,
    pub tool_missing: usize,
}

fn have_yara() -> bool {
    Command::new("which").arg("yara").output().map(|o| o.status.success()).unwrap_or(false)
}

/// Small built-in corpus of common, definitely-unrelated host binaries to negative-test a
/// rule against — catches a rule so generic it would false-positive on nearly anything (the
/// same "unproven confirmation" trap pocrun.rs's antipattern gate exists to catch for PoCs).
fn clean_corpus() -> Vec<PathBuf> {
    [
        "/bin/ls", "/bin/cat", "/bin/echo", "/bin/sh", "/bin/pwd",
        "/usr/bin/curl", "/usr/bin/env", "/usr/bin/true", "/usr/bin/false",
    ]
    .iter()
    .map(PathBuf::from)
    .filter(|p| p.is_file())
    .collect()
}

/// All binaries this session's target actually resolves to — the main path plus every bundle
/// binary (Mac .app bundles carry XPC services/Updater/CEF helpers, and a finding can be
/// scoped to any one of them, not just the main executable).
fn target_candidates(target: &Target) -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from(&target.path)];
    for b in &target.bundle_binaries {
        v.push(PathBuf::from(b));
    }
    v.retain(|p| p.is_file());
    v
}

/// Compile+run one YARA rule file against one file. `yara` exits 0 on a successful scan
/// (match or no match), non-zero only on a real error (bad syntax, missing file, etc.) — so
/// the exit code alone tells us error-vs-not, and stdout emptiness tells us match-vs-not.
fn yara_matches(rule_path: &Path, file: &Path) -> Result<bool, String> {
    let out = Command::new("yara")
        .arg(rule_path)
        .arg(file)
        .output()
        .map_err(|e| format!("failed to spawn yara: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(if stderr.trim().is_empty() {
            format!("yara exited with status {:?}", out.status.code())
        } else {
            stderr.trim().to_string()
        });
    }
    Ok(!out.stdout.trim_ascii().is_empty())
}

/// Validate one rule against the target candidates + clean corpus. Does NOT run the LLM-fix
/// loop — that's the caller's job, so this stays a pure, cheap, re-runnable check.
fn validate_one_rule(rule_path: &Path, targets: &[PathBuf], clean: &[PathBuf]) -> YaraRuleResult {
    let vuln_class = rule_path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let file = rule_path.to_string_lossy().into_owned();

    let mut matched_on: Vec<String> = Vec::new();
    for t in targets {
        match yara_matches(rule_path, t) {
            Err(e) => {
                return YaraRuleResult {
                    vuln_class, file, status: "syntax-error".into(), matched_target: false,
                    false_positive_hits: vec![], fix_attempts: 0, detail: e,
                };
            }
            Ok(true) => matched_on.push(t.display().to_string()),
            Ok(false) => {}
        }
    }

    if matched_on.is_empty() {
        return YaraRuleResult {
            vuln_class, file, status: "no-match".into(), matched_target: false,
            false_positive_hits: vec![], fix_attempts: 0,
            detail: "rule compiled but did not match the target binary (or any bundle binary)".into(),
        };
    }

    let mut fp_hits = Vec::new();
    for c in clean {
        match yara_matches(rule_path, c) {
            Ok(true) => fp_hits.push(c.display().to_string()),
            Ok(false) => {}
            Err(_) => {} // a clean-corpus scan error isn't this rule's fault; ignore
        }
    }

    if fp_hits.is_empty() {
        YaraRuleResult {
            vuln_class, file, status: "valid".into(), matched_target: true,
            false_positive_hits: fp_hits, fix_attempts: 0,
            detail: format!("matched {} — no false positives on {} clean reference binary(ies)", matched_on.join(", "), clean.len()),
        }
    } else {
        YaraRuleResult {
            vuln_class, file, status: "too-broad".into(), matched_target: true,
            false_positive_hits: fp_hits.clone(), fix_attempts: 0,
            detail: format!(
                "matched the target ({}) but ALSO matched {} unrelated clean binary(ies) — rule is too generic",
                matched_on.join(", "), fp_hits.len()
            ),
        }
    }
}

/// Ask the LLM to repair one rule given its real validation failure. Returns true if the LLM
/// ran (the file may have been rewritten) — mirrors pocrun.rs's `llm_fix_poc`.
fn llm_fix_yara_rule(cfg: &Config, rule_path: &Path, result: &YaraRuleResult, finding_ctx: &str) -> bool {
    let src = std::fs::read_to_string(rule_path).unwrap_or_default();
    let issue = match result.status.as_str() {
        "syntax-error" => format!("Compile error from the real `yara` binary: {}", result.detail),
        "no-match" => "The rule compiles but does NOT match the target binary (or any bundle binary). \
             Inspect the actual finding evidence again (strings/otool/nm/hex as fits) and rewrite the \
             rule around a byte/string pattern that is REALLY present in the binary — do not guess."
            .to_string(),
        "too-broad" => format!(
            "The rule matches the target but ALSO matches these unrelated clean binaries: {} — it is \
             too generic (likely keyed on a common string/byte sequence every binary shares). Rewrite \
             it to key on the SPECIFIC vulnerable pattern (exact bytes at the finding's locus, a \
             distinctive string combination, or a `condition:` that ANDs several pieces so the \
             combination is actually rare).",
            result.false_positive_hits.join(", ")
        ),
        _ => return false,
    };
    let prompt = format!(
        "This YARA detection rule (generated for a SafeApp finding, NOT a malware signature) failed \
         real validation. {issue}\n\nFinding context: {finding_ctx}\n\nCurrent rule ({}):\n{src}\n\n\
         Rewrite the COMPLETE corrected rule to the SAME path using the Write tool — one valid YARA \
         rule, specific to the vulnerable pattern. This is authorized defensive tooling. Reply only \
         'fixed' or 'cannot'.",
        rule_path.display()
    );
    let mut cmd = Command::new("claude");
    cmd.arg("-p").arg(prompt)
        .arg("--model").arg(&cfg.model)
        .arg("--dangerously-skip-permissions")
        .arg("--add-dir").arg(&cfg.root)
        .arg("--output-format").arg("json")
        .env("IS_SANDBOX", "1")
        .stdin(std::process::Stdio::null());
    cmd.output().map(|o| o.status.success()).unwrap_or(false)
}

fn render_report_md(report: &YaraReport) -> String {
    let mut md = String::new();
    md.push_str("# YARA Detection Rules — Validation Report\n\n");
    md.push_str(&format!(
        "**{} rule(s): {} valid, {} too-broad, {} no-match, {} syntax-error, {} tool-missing.**\n\n",
        report.results.len(), report.valid, report.too_broad, report.no_match, report.syntax_error, report.tool_missing
    ));
    md.push_str("| Rule | Status | Matched target | False positives | Fix attempts |\n");
    md.push_str("|------|--------|-----------------|------------------|--------------|\n");
    for r in &report.results {
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            r.vuln_class, r.status, r.matched_target,
            if r.false_positive_hits.is_empty() { "-".to_string() } else { r.false_positive_hits.len().to_string() },
            r.fix_attempts
        ));
    }
    if report.tool_missing > 0 {
        md.push_str("\n`yara` is not installed on this host — rules were generated but never actually \
                     validated. Install it (`malvex doctor --install`, or `brew install yara` on macOS) \
                     and re-run `malvex yara-test <session>` before trusting any of them.\n");
    }
    md.push_str("\nRules marked anything other than `valid` should not be relied on without further \
                 work — a `no-match`/`too-broad`/`syntax-error` rule is reported for visibility, not \
                 as a usable detection.\n");
    md
}

/// Generate rules via the `yara-gen` agent for every finding with a real PoC, then validate
/// every rule that landed on disk. The one entry point `exec.rs` calls after poc-test.
pub fn run_yara_stage(cfg: &Config, session_dir: &Path) -> anyhow::Result<YaraReport> {
    let findings_json = session_dir.join("findings.json");
    if !findings_json.is_file() {
        anyhow::bail!("no findings.json in {}", session_dir.display());
    }
    let yara_dir = session_dir.join("yara");
    std::fs::create_dir_all(&yara_dir)?;

    let findings: Vec<Finding> = std::fs::read_to_string(&findings_json)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let eligible: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.poc.is_some() && matches!(f.verdict, malvex_core::Verdict::Confirmed | malvex_core::Verdict::Plausible))
        .collect();

    if eligible.is_empty() {
        println!("[yara-gen] no findings with a PoC + confirmed/plausible verdict — nothing to generate");
        return Ok(YaraReport::default());
    }

    let agent_file = cfg.root.join("agents").join("yara-gen.md");
    let prompt = format!(
        "Read the findings at {} (JSON array of malvex-core::Finding). For each finding with `poc` set \
         and verdict confirmed/plausible, write one YARA rule to {}/<vuln_class>.yar per your system \
         prompt's rules. Return the JSON summary described there.",
        findings_json.display(), yara_dir.display()
    );
    println!("[yara-gen] generating detection rules for {} exploited finding(s)...", eligible.len());
    let mut cmd = Command::new("claude");
    cmd.arg("-p").arg(&prompt)
        .arg("--model").arg(&cfg.model)
        .arg("--fallback-model").arg(cfg.fallbacks.join(","))
        .arg("--dangerously-skip-permissions")
        .arg("--append-system-prompt-file").arg(&agent_file)
        .arg("--add-dir").arg(&cfg.root)
        .arg("--output-format").arg(&cfg.output_format)
        .env("IS_SANDBOX", "1")
        .stdin(std::process::Stdio::null());
    let out = cmd.output()?;
    std::fs::write(session_dir.join("yara-gen.out.json"), String::from_utf8_lossy(&out.stdout).as_bytes()).ok();

    validate_yara_rules(cfg, session_dir)
}

/// Validate whatever `.yar` files already exist under `<session>/yara/` — separated from
/// `run_yara_stage` so a session can be re-validated (`malvex yara-test <session>`) without
/// burning another generation call, e.g. after `yara` gets installed.
pub fn validate_yara_rules(cfg: &Config, session_dir: &Path) -> anyhow::Result<YaraReport> {
    let yara_dir = session_dir.join("yara");
    let mut rule_files: Vec<PathBuf> = std::fs::read_dir(&yara_dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("yar"))
                .collect()
        })
        .unwrap_or_default();
    rule_files.sort();

    if rule_files.is_empty() {
        return Ok(YaraReport::default());
    }

    if !have_yara() {
        let results: Vec<YaraRuleResult> = rule_files
            .iter()
            .map(|p| YaraRuleResult {
                vuln_class: p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default(),
                file: p.to_string_lossy().into_owned(),
                status: "tool-missing".into(),
                matched_target: false,
                false_positive_hits: vec![],
                fix_attempts: 0,
                detail: "`yara` binary not found on PATH — install via `malvex doctor --install` or `brew install yara`".into(),
            })
            .collect();
        let report = YaraReport { tool_missing: results.len(), results, ..Default::default() };
        std::fs::write(session_dir.join("yara-report.md"), render_report_md(&report)).ok();
        std::fs::write(session_dir.join("yara-report.json"), serde_json::to_string_pretty(&report).unwrap_or_default()).ok();
        println!("[yara-test] `yara` not installed — {} rule(s) generated but unvalidated", report.tool_missing);
        return Ok(report);
    }

    let target: Target = serde_json::from_str(&std::fs::read_to_string(session_dir.join("target.json"))?)?;
    let targets = target_candidates(&target);
    if targets.is_empty() {
        anyhow::bail!("target.json resolved to no existing binary — nothing to validate rules against");
    }
    let clean = clean_corpus();

    let findings: Vec<Finding> = std::fs::read_to_string(session_dir.join("findings.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let mut results = Vec::new();
    for rule_path in &rule_files {
        let vuln_class = rule_path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let finding_ctx = findings
            .iter()
            .find(|f| f.vuln_class == vuln_class)
            .map(|f| format!("vuln_class={} title={} severity={:?}", f.vuln_class, f.title, f.severity))
            .unwrap_or_default();

        let mut result = validate_one_rule(rule_path, &targets, &clean);
        let mut fix_attempts = 0usize;
        if matches!(result.status.as_str(), "syntax-error" | "no-match" | "too-broad") {
            for round in 1..=2 {
                println!("    ↻ [{vuln_class}] {} — fix attempt {round}/2 via LLM...", result.status);
                if !llm_fix_yara_rule(cfg, rule_path, &result, &finding_ctx) {
                    break;
                }
                fix_attempts = round;
                result = validate_one_rule(rule_path, &targets, &clean);
                if result.status == "valid" {
                    break;
                }
            }
        }
        result.fix_attempts = fix_attempts;
        println!("    {} [{vuln_class}] {}", if result.status == "valid" { "✓" } else { "⚠" }, result.status);
        std::fs::write(
            yara_dir.join(format!("{vuln_class}.validation.json")),
            serde_json::to_string_pretty(&result).unwrap_or_default(),
        )
        .ok();
        results.push(result);
    }

    let report = YaraReport {
        valid: results.iter().filter(|r| r.status == "valid").count(),
        too_broad: results.iter().filter(|r| r.status == "too-broad").count(),
        no_match: results.iter().filter(|r| r.status == "no-match").count(),
        syntax_error: results.iter().filter(|r| r.status == "syntax-error").count(),
        tool_missing: results.iter().filter(|r| r.status == "tool-missing").count(),
        results,
    };
    std::fs::write(session_dir.join("yara-report.md"), render_report_md(&report)).ok();
    std::fs::write(session_dir.join("yara-report.json"), serde_json::to_string_pretty(&report).unwrap_or_default()).ok();
    println!(
        "[yara-test] {} valid, {} too-broad, {} no-match, {} syntax-error",
        report.valid, report.too_broad, report.no_match, report.syntax_error
    );
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(dir: &Path, name: &str, content: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    fn skip_if_no_yara() -> bool {
        if !have_yara() {
            eprintln!("skipping — `yara` not installed on this test host");
            true
        } else {
            false
        }
    }

    #[test]
    fn valid_rule_matches_target_and_not_clean_corpus() {
        if skip_if_no_yara() { return; }
        let dir = std::env::temp_dir().join(format!("malvex-yara-valid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Target: a file with a genuinely distinctive marker string.
        let target = write_tmp(&dir, "target.bin", "some prefix bytes VERY_DISTINCTIVE_MALVEX_TEST_MARKER_9f8e trailing bytes");
        let rule = write_tmp(&dir, "test_vuln.yar", "rule test_vuln_pattern { strings: $a = \"VERY_DISTINCTIVE_MALVEX_TEST_MARKER_9f8e\" condition: $a }");
        let clean = write_tmp(&dir, "clean.bin", "totally unrelated content, nothing like the marker at all");
        let result = validate_one_rule(&rule, &[target], &[clean]);
        assert_eq!(result.status, "valid", "{result:?}");
        assert!(result.matched_target);
        assert!(result.false_positive_hits.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn too_broad_rule_flags_false_positive_on_clean_corpus() {
        if skip_if_no_yara() { return; }
        let dir = std::env::temp_dir().join(format!("malvex-yara-broad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = write_tmp(&dir, "target.bin", "contains COMMON_WORD somewhere");
        let rule = write_tmp(&dir, "test_vuln.yar", "rule test_vuln_pattern { strings: $a = \"COMMON_WORD\" condition: $a }");
        let clean = write_tmp(&dir, "clean.bin", "also contains COMMON_WORD, unrelated file");
        let result = validate_one_rule(&rule, &[target], &[clean]);
        assert_eq!(result.status, "too-broad", "{result:?}");
        assert!(!result.false_positive_hits.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_match_rule_flagged_when_pattern_absent() {
        if skip_if_no_yara() { return; }
        let dir = std::env::temp_dir().join(format!("malvex-yara-nomatch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = write_tmp(&dir, "target.bin", "nothing interesting here");
        let rule = write_tmp(&dir, "test_vuln.yar", "rule test_vuln_pattern { strings: $a = \"NEVER_PRESENT_STRING_xyz\" condition: $a }");
        let result = validate_one_rule(&rule, &[target], &[]);
        assert_eq!(result.status, "no-match", "{result:?}");
        assert!(!result.matched_target);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn syntax_error_rule_flagged_not_panicked() {
        if skip_if_no_yara() { return; }
        let dir = std::env::temp_dir().join(format!("malvex-yara-syntax-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = write_tmp(&dir, "target.bin", "irrelevant");
        let rule = write_tmp(&dir, "test_vuln.yar", "this is not valid yara syntax at all {{{");
        let result = validate_one_rule(&rule, &[target], &[]);
        assert_eq!(result.status, "syntax-error", "{result:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn target_candidates_includes_bundle_binaries_and_drops_missing() {
        let dir = std::env::temp_dir().join(format!("malvex-yara-targets-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let main = write_tmp(&dir, "main.bin", "x");
        let helper = write_tmp(&dir, "helper.bin", "y");
        let target = Target {
            path: main.to_string_lossy().into_owned(),
            format: "mach-o".into(),
            arch: "arm64".into(),
            shielding: vec![],
            app: "test".into(),
            sha256: None,
            md5: None,
            bundle_binaries: vec![helper.to_string_lossy().into_owned(), "/nonexistent/path".into()],
            bundle_hashes: std::collections::HashMap::new(),
        };
        let cands = target_candidates(&target);
        assert_eq!(cands.len(), 2, "{cands:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn render_report_md_summarizes_all_statuses() {
        let report = YaraReport {
            results: vec![
                YaraRuleResult { vuln_class: "a".into(), file: "a.yar".into(), status: "valid".into(), matched_target: true, false_positive_hits: vec![], fix_attempts: 0, detail: "ok".into() },
                YaraRuleResult { vuln_class: "b".into(), file: "b.yar".into(), status: "too-broad".into(), matched_target: true, false_positive_hits: vec!["/bin/ls".into()], fix_attempts: 1, detail: "broad".into() },
            ],
            valid: 1, too_broad: 1, no_match: 0, syntax_error: 0, tool_missing: 0,
        };
        let md = render_report_md(&report);
        assert!(md.contains("1 valid"));
        assert!(md.contains("1 too-broad"));
        assert!(md.contains("| a | valid"));
        assert!(md.contains("| b | too-broad"));
    }
}
