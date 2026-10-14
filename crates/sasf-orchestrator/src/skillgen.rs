//! Self-learning skill generation: identifies novel findings, scores confidence via
//! reward metrics, and generates candidate SKILL.md files for validated patterns.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A candidate skill derived from novel findings in a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillCandidate {
    /// Skill ID (kebab-case, e.g. "inj-thread-pool-hijack").
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// CWE identifier (e.g. "CWE-114").
    pub cwe: String,
    /// Target platform: windows | macos | linux | any.
    pub platform: String,
    /// Agent that should own this vector.
    pub agent: String,
    /// The generated SKILL.md content.
    pub skill_content: String,
    /// Reward metrics used to score confidence.
    pub metrics: RewardMetrics,
    /// Overall confidence score [0.0, 1.0].
    pub confidence: f64,
    /// Source session ID where the finding originated.
    pub source_session: String,
    /// Source finding title for traceability.
    pub source_finding: String,
}

/// Reward metrics that prevent learning from false positives.
/// Each metric is a boolean signal; confidence = weighted sum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardMetrics {
    /// Finding has concrete evidence (not just metadata/strings).
    pub evidence_count: usize,
    /// At least one evidence has a real IDA/Ghidra address locus.
    pub has_ida_locus: bool,
    /// A PoC script exists for this finding.
    pub has_poc: bool,
    /// Finding is part of an attack chain (chain field populated).
    pub in_chain: bool,
    /// Validator confirmed the finding (verdict == confirmed).
    pub confirmed_verdict: bool,
    /// Finding was cross-validated by multiple agents or sessions.
    pub cross_validated: bool,
    /// Finding has decompiled code excerpt in evidence.
    pub has_code_excerpt: bool,
    /// Finding severity is high or critical (stronger signal).
    pub high_severity: bool,
}

impl RewardMetrics {
    /// Compute weighted confidence score [0.0, 1.0].
    /// Weights reflect how much each signal reduces false-positive risk.
    pub fn confidence(&self) -> f64 {
        let mut score = 0.0;
        let mut max = 0.0;

        // Evidence count: 0=0, 1=0.05, 2+=0.10
        let w_evidence = 0.10;
        max += w_evidence;
        score += if self.evidence_count >= 2 { w_evidence }
                 else if self.evidence_count == 1 { w_evidence * 0.5 }
                 else { 0.0 };

        // IDA locus: strong signal of real RE work
        let w_locus = 0.20;
        max += w_locus;
        if self.has_ida_locus { score += w_locus; }

        // PoC: proves exploitability
        let w_poc = 0.15;
        max += w_poc;
        if self.has_poc { score += w_poc; }

        // Chain: contextualizes the vuln in a real attack
        let w_chain = 0.10;
        max += w_chain;
        if self.in_chain { score += w_chain; }

        // Confirmed verdict: validator says it's real
        let w_confirmed = 0.25;
        max += w_confirmed;
        if self.confirmed_verdict { score += w_confirmed; }

        // Cross-validated: multiple sources agree
        let w_cross = 0.10;
        max += w_cross;
        if self.cross_validated { score += w_cross; }

        // Code excerpt: real decompiled code, not guesswork
        let w_code = 0.05;
        max += w_code;
        if self.has_code_excerpt { score += w_code; }

        // High severity: not definitive but indicates importance
        let w_severity = 0.05;
        max += w_severity;
        if self.high_severity { score += w_severity; }

        if max > 0.0 { score / max } else { 0.0 }
    }
}

/// Minimum confidence threshold to auto-generate a skill.
/// Below this, the candidate is logged but not written.
pub const MIN_CONFIDENCE: f64 = 0.60;

/// Minimum confidence to auto-register in taxonomy (higher bar).
pub const MIN_TAXONOMY_CONFIDENCE: f64 = 0.75;

/// Check if a finding represents a novel pattern not already covered by existing skills.
pub fn is_novel(finding: &sasf_core::Finding, skills_dir: &Path) -> bool {
    let skill_path = skills_dir.join(&finding.vuln_class).join("SKILL.md");
    !skill_path.is_file()
}

/// Scan a session's findings for novel patterns and build SkillCandidate entries.
pub fn scan_session(
    session_dir: &Path,
    skills_dir: &Path,
) -> anyhow::Result<Vec<SkillCandidate>> {
    let findings_path = session_dir.join("findings.json");
    if !findings_path.is_file() {
        return Ok(Vec::new());
    }
    let findings: Vec<sasf_core::Finding> =
        serde_json::from_str(&std::fs::read_to_string(&findings_path)?)?;

    let session_id = session_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Check which findings have PoCs.
    let poc_dir = session_dir.join("poc");
    let poc_out = session_dir.parent().and_then(|p| p.parent()).map(|r| r.join("poc-out"));

    let mut candidates = Vec::new();

    for finding in &findings {
        if !is_novel(finding, skills_dir) {
            continue;
        }
        // Skip parser artifacts and unknowns.
        if finding.vuln_class == "unknown" || finding.title.is_empty() {
            continue;
        }
        // Skip refuted findings — never learn from them.
        if finding.verdict == sasf_core::Verdict::Refuted {
            continue;
        }

        let metrics = compute_metrics(finding, &poc_dir, &poc_out);
        let confidence = metrics.confidence();

        let platform = guess_platform(&finding.vuln_class);
        let agent = guess_agent(&finding.vuln_class, &platform);
        let cwe = finding.cwe.clone().unwrap_or_else(|| "TBD".into());

        let skill_content = generate_skill_md(finding, &cwe, &platform, &agent, &session_id);

        candidates.push(SkillCandidate {
            id: finding.vuln_class.clone(),
            title: finding.title.clone(),
            cwe,
            platform,
            agent,
            skill_content,
            metrics,
            confidence,
            source_session: session_id.clone(),
            source_finding: finding.title.clone(),
        });
    }

    // Deduplicate by vuln_class (keep highest confidence).
    candidates.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
    let mut seen = std::collections::HashSet::new();
    candidates.retain(|c| seen.insert(c.id.clone()));

    Ok(candidates)
}

/// Compute reward metrics for a single finding.
fn compute_metrics(
    finding: &sasf_core::Finding,
    poc_dir: &Path,
    poc_out: &Option<PathBuf>,
) -> RewardMetrics {
    let evidence_count = finding.evidence.len();

    let has_ida_locus = finding.evidence.iter().any(|e| {
        e.locus.as_ref().map(|l| {
            // Real locus: contains hex address (0x...) or function name with offset
            l.contains("0x") || l.contains("sub_") || l.contains("+0x")
        }).unwrap_or(false)
    });

    let has_poc = {
        let poc_subdir = poc_dir.join(&finding.vuln_class);
        let poc_out_subdir = poc_out.as_ref().map(|p| p.join(&finding.vuln_class));
        let dir_has_files = |d: &Path| -> bool {
            d.is_dir() && std::fs::read_dir(d).map(|rd| rd.count() > 0).unwrap_or(false)
        };
        dir_has_files(&poc_subdir) || poc_out_subdir.map(|d| dir_has_files(&d)).unwrap_or(false)
    };

    let in_chain = !finding.chain.is_empty();

    let confirmed_verdict = finding.verdict == sasf_core::Verdict::Confirmed;

    let has_code_excerpt = finding.evidence.iter().any(|e| {
        let d = &e.detail;
        // Heuristic: real code has function calls, addresses, or assembly
        d.len() > 100 && (d.contains("(") || d.contains("0x") || d.contains("mov ") || d.contains("call "))
    });

    let high_severity = matches!(finding.severity, sasf_core::Severity::Critical | sasf_core::Severity::High);

    RewardMetrics {
        evidence_count,
        has_ida_locus,
        has_poc,
        in_chain,
        confirmed_verdict,
        cross_validated: false, // requires multi-session comparison — set externally
        has_code_excerpt,
        high_severity,
    }
}

/// Guess platform from vuln_class naming conventions.
fn guess_platform(vuln_class: &str) -> String {
    let vc = vuln_class.to_lowercase();
    if vc.starts_with("inj-") || vc.contains("dll") || vc.contains("pe-") || vc.contains("pipe")
        || vc.contains("registry") || vc.contains("com-hijack") || vc.contains("service-")
        || vc.contains("ntdll") || vc.contains("crt-") || vc.contains("ldr-")
    {
        "windows".into()
    } else if vc.contains("dylib") || vc.contains("xpc") || vc.contains("macho")
        || vc.contains("entitlement") || vc.contains("sandbox-escape") || vc.contains("restrict")
    {
        "macos".into()
    } else {
        "any".into()
    }
}

/// Guess owning agent from vuln_class and platform.
fn guess_agent(vuln_class: &str, platform: &str) -> String {
    let vc = vuln_class.to_lowercase();
    if vc.starts_with("inj-") || vc.contains("hook") || vc.contains("patch") {
        format!("static-{}", if platform == "macos" { "mac" } else { "windows" })
    } else if vc.contains("dynamic") || vc.contains("frida") || vc.contains("runtime") {
        format!("dynamic-{}", if platform == "macos" { "mac" } else { "windows" })
    } else {
        format!("static-{}", if platform == "macos" { "mac" } else { "windows" })
    }
}

/// Generate SKILL.md content from a finding.
fn generate_skill_md(
    finding: &sasf_core::Finding,
    cwe: &str,
    platform: &str,
    agent: &str,
    session_id: &str,
) -> String {
    let severity = format!("{:?}", finding.severity);
    let evidence_summary: Vec<String> = finding.evidence.iter().take(3).map(|e| {
        let kind = format!("{:?}", e.kind);
        let locus = e.locus.as_deref().unwrap_or("N/A");
        format!("- kind={}, locus={}", kind, locus)
    }).collect();

    let chain_info = if finding.chain.is_empty() { "standalone".to_string() } else { finding.chain.join(" | ") };

    format!(
r#"# Skill: {id}

Vector: `{id}` | {cwe} | {platform} | agent: {agent} |
prior_ref: session-{session_id} ({severity})

Authorized malware-analysis skill for Malvex.
Auto-generated by skill-learner from session {session_id}.

{title}

## Precondition
{platform_note} IDA Pro or equivalent disassembler available.

## Procedure
1. Identify imports/exports related to the vulnerability pattern.
2. Locate the vulnerable function via xrefs and decompilation.
3. Verify the vulnerability condition through code analysis.
4. Trace data flow to confirm exploitability.
5. Document the exploitation path and preconditions.

## Proof
{proof}

## Evidence out
{evidence}
`severity: {severity_lower}`, `cwe: {cwe}`.

## Chain context
{chain_info}

## Mitigations
- Apply vendor-recommended security controls.
- Enable runtime protection mechanisms.
- Monitor for exploitation attempts.

## PoC hint
Reproduce the vulnerability condition and capture evidence showing
the vulnerable code path is reachable.

## Confidence
Auto-generated skill. Review and refine procedure before production use.
Evidence from source session:
{evidence_lines}
"#,
        id = finding.vuln_class,
        cwe = cwe,
        platform = platform,
        agent = agent,
        session_id = session_id,
        severity = severity,
        title = finding.title,
        platform_note = match platform {
            "windows" => "Windows PE binary.",
            "macos" => "macOS Mach-O binary or .app bundle.",
            _ => "Target binary on supported platform.",
        },
        proof = {
            let default_proof = "Decompiled code showing the vulnerability pattern.";
            finding.evidence.first()
                .map(|e| {
                    let d = &e.detail;
                    if d.is_empty() { default_proof }
                    else if d.len() > 200 { &d[..200] }
                    else { d.as_str() }
                })
                .unwrap_or(default_proof)
        },
        evidence = evidence_summary.join("\n"),
        severity_lower = format!("{:?}", finding.severity).to_lowercase(),
        chain_info = chain_info,
        evidence_lines = evidence_summary.join("\n"),
    )
}

/// Write validated skill candidates to disk (skills/<id>/SKILL.md).
/// Returns the number of skills written.
pub fn write_skills(candidates: &[SkillCandidate], skills_dir: &Path) -> usize {
    let mut written = 0;
    for c in candidates {
        if c.confidence < MIN_CONFIDENCE {
            continue;
        }
        let skill_dir = skills_dir.join(&c.id);
        if skill_dir.join("SKILL.md").is_file() {
            continue; // Don't overwrite manually-authored skills.
        }
        if std::fs::create_dir_all(&skill_dir).is_err() {
            continue;
        }
        if std::fs::write(skill_dir.join("SKILL.md"), &c.skill_content).is_ok() {
            written += 1;
        }
    }
    written
}

/// Summary report of the skill learning pass.
#[derive(Debug, Serialize)]
pub struct LearnReport {
    pub session_id: String,
    pub total_findings: usize,
    pub novel_findings: usize,
    pub candidates: Vec<SkillCandidate>,
    pub skills_written: usize,
    pub below_threshold: usize,
}

/// Full learning pipeline: scan session, score, write qualifying skills, return report.
pub fn learn(session_dir: &Path, skills_dir: &Path) -> anyhow::Result<LearnReport> {
    let session_id = session_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let findings_path = session_dir.join("findings.json");
    let total_findings = if findings_path.is_file() {
        let f: Vec<serde_json::Value> = serde_json::from_str(&std::fs::read_to_string(&findings_path)?)?;
        f.len()
    } else {
        0
    };

    let candidates = scan_session(session_dir, skills_dir)?;
    let novel_findings = candidates.len();
    let below_threshold = candidates.iter().filter(|c| c.confidence < MIN_CONFIDENCE).count();
    let skills_written = write_skills(&candidates, skills_dir);

    // Write learn report JSON to session dir.
    let report = LearnReport {
        session_id,
        total_findings,
        novel_findings,
        candidates: candidates.clone(),
        skills_written,
        below_threshold,
    };
    let report_json = serde_json::to_string_pretty(&report)?;
    std::fs::write(session_dir.join("learn-report.json"), &report_json).ok();

    Ok(report)
}
