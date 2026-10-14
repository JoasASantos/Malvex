//! Scan an arbitrary events/telemetry JSON file against every YARA rule this framework has
//! ever generated (across all sessions, `sessions/*/yara/*.yar`) plus every known IOC from
//! `threat-intel/known-iocs.json`, and report which events look suspicious and why.
//!
//! Not tied to a single session or target binary — this is the cross-cutting "did anything we
//! already know how to detect show up in this log dump" check: upload a JSON export of events
//! (process starts, file writes, network calls, registry changes — whatever shape a real
//! telemetry/EDR export has) and get back which individual events matched a validated
//! detection rule or a real-world IOC, and which rule/IOC it was.
//!
//! Only rules whose sibling `.validation.json` says `status: "valid"` are used — the same
//! "never trust an unproven rule" principle `yararun.rs` enforces when it generates them.

use crate::{threatintel, Config};
use serde_json::Value;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMatch {
    pub event_index: usize,
    /// First ~200 chars of the event's JSON, so the report is legible without cross-
    /// referencing back into the original (possibly huge) events file.
    pub event_summary: String,
    /// "yara:<session_id>:<rule_name>" or "ioc:<kind>:<family>"
    pub matched_by: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventScanReport {
    pub total_events: usize,
    pub rules_used: usize,
    pub iocs_used: usize,
    pub matches: Vec<EventMatch>,
}

fn have_yara() -> bool {
    Command::new("which").arg("yara").output().map(|o| o.status.success()).unwrap_or(false)
}

/// Flatten the input JSON into individual events. Accepts a bare array, an object with an
/// "events"/"logs"/"data"/"items" array field (real telemetry exports vary in shape), or a
/// single bare event object.
fn extract_events(raw: &str) -> anyhow::Result<Vec<Value>> {
    let v: Value = serde_json::from_str(raw)?;
    match v {
        Value::Array(items) => Ok(items),
        Value::Object(map) => {
            for key in ["events", "logs", "data", "items"] {
                if let Some(Value::Array(items)) = map.get(key) {
                    return Ok(items.clone());
                }
            }
            Ok(vec![Value::Object(map)])
        }
        other => Ok(vec![other]),
    }
}

fn event_summary(v: &Value) -> String {
    let s = serde_json::to_string(v).unwrap_or_default();
    if s.chars().count() > 200 {
        format!("{}…", s.chars().take(200).collect::<String>())
    } else {
        s
    }
}

/// Every YARA rule across every session that actually passed real validation (status ==
/// "valid" in its sibling `.validation.json`) — an unproven or too-broad rule doesn't get to
/// flag live events as suspicious. Namespaced by session id (`s<id>:<rule_name>`) so two
/// sessions' rule identifiers never collide in one combined `yara` invocation.
fn collect_valid_rules(root: &Path) -> Vec<(String, PathBuf)> {
    let mut rules = Vec::new();
    let sessions_dir = root.join("sessions");
    let Ok(rd) = std::fs::read_dir(&sessions_dir) else { return rules };
    for session in rd.flatten() {
        let session_path = session.path();
        if !session_path.is_dir() {
            continue;
        }
        let session_id = session_path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let yara_dir = session_path.join("yara");
        let Ok(files) = std::fs::read_dir(&yara_dir) else { continue };
        for f in files.flatten() {
            let p = f.path();
            if p.extension().and_then(|e| e.to_str()) != Some("yar") {
                continue;
            }
            let val_path = p.with_extension("validation.json");
            let is_valid = std::fs::read_to_string(&val_path)
                .ok()
                .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                .and_then(|v| v.get("status").and_then(|s| s.as_str()).map(|s| s == "valid"))
                .unwrap_or(false);
            if is_valid {
                rules.push((format!("s{session_id}"), p));
            }
        }
    }
    rules
}

/// Run every collected rule (namespaced) against one target file in a single `yara`
/// invocation; returns the `namespace:rule_name` of every rule that matched. `None` on a
/// spawn/compile failure (degrades that one event's YARA check rather than losing the whole
/// scan — every rule here already passed individual validation, so a batch failure would be
/// unusual, but never let it take down IOC matching too).
fn run_yara_multi(rule_files: &[(String, PathBuf)], target: &Path) -> Option<Vec<String>> {
    let mut cmd = Command::new("yara");
    cmd.arg("-e"); // print namespace:identifier
    for (ns, path) in rule_files {
        cmd.arg(format!("{ns}:{}", path.display()));
    }
    cmd.arg(target);
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .map(|s| s.to_string())
            .collect(),
    )
}

/// Scan every event in `events_path` against all valid YARA rules + all known IOCs. Each
/// event is written to its own temp file (yara scans files, not in-memory JSON) and cleaned
/// up afterward regardless of outcome.
pub fn scan_events(cfg: &Config, events_path: &Path) -> anyhow::Result<EventScanReport> {
    let raw = std::fs::read_to_string(events_path)?;
    let events = extract_events(&raw)?;

    let rule_files = if have_yara() { collect_valid_rules(&cfg.root) } else { Vec::new() };
    // Every known IOC from both the weekly threat-intel sweep AND every on-demand
    // `intel-lookups/` query — an analyst who looked up one specific family gets that
    // coverage in Event Scan immediately, not just families the weekly cycle happened to hit.
    let mut known_iocs = threatintel::known_iocs(cfg);
    known_iocs.extend(crate::lookup::known_iocs(cfg));

    let tmp_dir = std::env::temp_dir().join(format!("sasf-event-scan-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir)?;

    let mut matches = Vec::new();
    for (i, ev) in events.iter().enumerate() {
        let text = serde_json::to_string(ev).unwrap_or_default();

        if !rule_files.is_empty() {
            let event_file = tmp_dir.join(format!("event-{i}.json"));
            if std::fs::write(&event_file, &text).is_ok() {
                if let Some(hits) = run_yara_multi(&rule_files, &event_file) {
                    for h in hits {
                        matches.push(EventMatch {
                            event_index: i,
                            event_summary: event_summary(ev),
                            matched_by: format!("yara:{h}"),
                            detail: format!("matched YARA detection rule {h} (generated from a prior session's exploited finding)"),
                        });
                    }
                }
            }
        }

        let text_lower = text.to_lowercase();
        for ioc in &known_iocs {
            let v = ioc.value.to_lowercase();
            // Skip anything too short to be a meaningful signal (avoids e.g. a 2-char IOC
            // value matching half the events by accident).
            if v.len() < 4 {
                continue;
            }
            if text_lower.contains(&v) {
                matches.push(EventMatch {
                    event_index: i,
                    event_summary: event_summary(ev),
                    matched_by: format!("ioc:{}:{}", ioc.kind, ioc.family),
                    detail: format!("contains known IOC ({}) from threat-intel family '{}': {}", ioc.kind, ioc.family, ioc.value),
                });
            }
        }
    }
    std::fs::remove_dir_all(&tmp_dir).ok();

    Ok(EventScanReport {
        total_events: events.len(),
        rules_used: rule_files.len(),
        iocs_used: known_iocs.len(),
        matches,
    })
}

fn now_epoch() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Run a scan and persist it under `<root>/event-scans/<epoch>/` (events.json + report.md +
/// report.json), same `sessions/<epoch>/`-style convention as everywhere else in this repo —
/// for sasf-web's "Event Scan" tab, which needs a history to list, not just a one-off result.
pub fn scan_and_save(cfg: &Config, events_path: &Path) -> anyhow::Result<(String, EventScanReport)> {
    let report = scan_events(cfg, events_path)?;
    let run_id = now_epoch().to_string();
    let es_root = cfg.root.join("event-scans");
    let dir = es_root.join(&run_id);
    std::fs::create_dir_all(&dir)?;
    std::fs::copy(events_path, dir.join("events.json")).ok();
    std::fs::write(dir.join("report.md"), render_report_md(&report)).ok();
    std::fs::write(dir.join("report.json"), serde_json::to_string_pretty(&report).unwrap_or_default()).ok();

    let idx_path = es_root.join("index.json");
    let mut ids: Vec<String> = std::fs::read_to_string(&idx_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    ids.retain(|i| i != &run_id);
    ids.insert(0, run_id.clone());
    std::fs::write(&idx_path, serde_json::to_string_pretty(&ids).unwrap_or_default()).ok();

    Ok((run_id, report))
}

/// List past scan ids, newest first.
pub fn list_scans(cfg: &Config) -> Vec<String> {
    std::fs::read_to_string(cfg.root.join("event-scans").join("index.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Read back a previously saved scan's report (no re-scan — just the persisted JSON).
pub fn load_scan(cfg: &Config, run_id: &str) -> Option<EventScanReport> {
    let s = std::fs::read_to_string(cfg.root.join("event-scans").join(run_id).join("report.json")).ok()?;
    serde_json::from_str(&s).ok()
}

// ── LLM analysis (optional second pass) ───────────────────────────────────────
// The deterministic pass above is pattern matching, not judgment — it can only flag what a
// validated YARA rule or a known IOC value already names verbatim. This pass hands the actual
// events (not just the hit list) to the `event-scan-analyst` agent, which can catch a
// multi-event attack chain, LOLBin-style tradecraft with zero literal IOC, or call out a
// rule/IOC hit that's probably a false positive in context — none of which string/pattern
// matching can do. Deliberately separate from `scan_events`: the base scan stays instant and
// free (no LLM call), this is an explicit opt-in per scan, same "cheap deterministic first,
// LLM only when asked" split as the rest of this repo.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventFinding {
    pub event_index: usize,
    /// "matched" (already in the deterministic hit list) or "llm_only" (zero rule/IOC hit —
    /// the analyst found it purely from reading the event content).
    pub source: String,
    /// "true_positive" | "suspicious" | "benign" | "false_positive" (false_positive only valid
    /// for source == "matched").
    pub verdict: String,
    #[serde(default)]
    pub mitre_techniques: Vec<String>,
    pub rationale: String,
    #[serde(default)]
    pub recommended_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositive {
    pub event_index: usize,
    pub matched_by: String,
    pub false_positive_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventScanAnalysis {
    #[serde(default)]
    pub overall_verdict: String,
    #[serde(default)]
    pub executive_summary: String,
    #[serde(default)]
    pub event_findings: Vec<EventFinding>,
    #[serde(default)]
    pub chain_analysis: String,
    #[serde(default)]
    pub false_positives: Vec<FalsePositive>,
    #[serde(default)]
    pub recommended_detections: String,
}

/// Cap on how many raw events get embedded in the LLM prompt — every matched event goes in in
/// full, then the remaining budget is filled with a sample of unmatched ones (in file order),
/// each truncated to keep one enormous event from starving the sample. Bounds prompt size (and
/// therefore cost/latency) against an events.json with tens of thousands of entries without
/// silently dropping the events the deterministic pass already cares about.
const MAX_PROMPT_EVENTS: usize = 300;
const MAX_EVENT_CHARS_IN_PROMPT: usize = 800;

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max).collect::<String>())
    }
}

/// Build the events context block for the prompt: every matched event first (so the analyst
/// always sees what the deterministic pass already flagged, in full), then unmatched events in
/// file order until `MAX_PROMPT_EVENTS` is reached.
fn build_events_context(events: &[Value], report: &EventScanReport) -> String {
    let matched: std::collections::HashSet<usize> = report.matches.iter().map(|m| m.event_index).collect();
    let mut sorted_matched: Vec<usize> = matched.iter().copied().collect();
    sorted_matched.sort_unstable();
    let mut lines = Vec::new();
    let mut count = 0usize;

    for &i in &sorted_matched {
        if count >= MAX_PROMPT_EVENTS {
            break;
        }
        if let Some(ev) = events.get(i) {
            let text = serde_json::to_string(ev).unwrap_or_default();
            lines.push(format!("[{i}] (matched by deterministic scan) {}", truncate_chars(&text, MAX_EVENT_CHARS_IN_PROMPT)));
            count += 1;
        }
    }
    for (i, ev) in events.iter().enumerate() {
        if count >= MAX_PROMPT_EVENTS {
            break;
        }
        if matched.contains(&i) {
            continue;
        }
        let text = serde_json::to_string(ev).unwrap_or_default();
        lines.push(format!("[{i}] {}", truncate_chars(&text, MAX_EVENT_CHARS_IN_PROMPT)));
        count += 1;
    }
    if events.len() > count {
        lines.push(format!("... ({} more event(s) omitted from this prompt for size)", events.len() - count));
    }
    lines.join("\n")
}

fn render_analysis_md(report: &EventScanReport, analysis: &EventScanAnalysis) -> String {
    let mut md = String::new();
    md.push_str("# Event Scan — Análise LLM\n\n");
    md.push_str(&format!("**Veredito geral:** {}\n\n", analysis.overall_verdict));
    md.push_str(&analysis.executive_summary);
    md.push_str("\n\n");

    if !analysis.chain_analysis.trim().is_empty() {
        md.push_str("## Cadeia de ataque\n\n");
        md.push_str(&analysis.chain_analysis);
        md.push_str("\n\n");
    }

    md.push_str("## Achados por evento\n\n");
    if analysis.event_findings.is_empty() {
        md.push_str("Nenhum achado além dos hits determinísticos.\n\n");
    } else {
        md.push_str("| Evento # | Origem | Veredito | MITRE | Justificativa | Ação recomendada |\n|---|---|---|---|---|---|\n");
        for f in &analysis.event_findings {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                f.event_index, f.source, f.verdict, f.mitre_techniques.join(", "),
                f.rationale.replace('|', "/"), f.recommended_action.replace('|', "/"),
            ));
        }
        md.push('\n');
    }

    if !analysis.false_positives.is_empty() {
        md.push_str("## Prováveis falsos positivos (hits determinísticos)\n\n");
        md.push_str("| Evento # | Matched by | Motivo |\n|---|---|---|\n");
        for fp in &analysis.false_positives {
            md.push_str(&format!(
                "| {} | {} | {} |\n",
                fp.event_index, fp.matched_by, fp.false_positive_reason.replace('|', "/")
            ));
        }
        md.push('\n');
    }

    if !analysis.recommended_detections.trim().is_empty() {
        md.push_str("## Detecções recomendadas\n\n");
        md.push_str(&analysis.recommended_detections);
        md.push('\n');
    }

    let _ = report; // kept in signature for symmetry with render_report_md / future use
    md
}

/// Run the LLM analysis pass over an already-saved scan and persist `analysis.md` +
/// `analysis.json` alongside it. Spawns `claude` exactly like `threatintel::run_threat_intel`
/// (same flags, same `--append-system-prompt-file` convention) — this is the only part of
/// event-scan that makes an LLM call, and it is always explicit opt-in per scan.
pub fn analyze_scan_with_llm(cfg: &Config, run_id: &str) -> anyhow::Result<EventScanAnalysis> {
    let es_root = cfg.root.join("event-scans");
    let dir = es_root.join(run_id);
    let report = load_scan(cfg, run_id).ok_or_else(|| anyhow::anyhow!("scan {run_id} not found"))?;
    let raw = std::fs::read_to_string(dir.join("events.json"))?;
    let events = extract_events(&raw)?;

    let agent_file = cfg.root.join("agents").join("event-scan-analyst.md");
    let events_context = build_events_context(&events, &report);
    let hits_context = if report.matches.is_empty() {
        "(nenhum hit determinístico — a checagem de YARA/IOC não encontrou nada; procure só pelo conteúdo dos eventos abaixo)".to_string()
    } else {
        report
            .matches
            .iter()
            .map(|m| format!("event #{}: matched_by={} — {}", m.event_index, m.matched_by, m.detail))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let prompt = format!(
        "Deterministic scan summary: {} total events, {} validated YARA rule(s), {} known IOC(s), {} hit(s).\n\n\
         Deterministic hits:\n{hits_context}\n\n\
         Events ({} shown of {} total):\n{events_context}\n\n\
         Output ONLY the JSON object described in your system prompt's 'Output' section. No prose outside the JSON.",
        report.total_events, report.rules_used, report.iocs_used, report.matches.len(),
        events.len().min(MAX_PROMPT_EVENTS), events.len(),
    );

    let forced_hermes_cmd = if cfg.force_hermes { crate::build_hermes_command(cfg, &agent_file, &prompt) } else { None };
    let primary_engine = if forced_hermes_cmd.is_some() { "hermes" } else { "claude" };
    println!("[event-scan] {run_id}: running LLM analysis over {} event(s) (engine={primary_engine})...", events.len());
    let mut cmd = forced_hermes_cmd.unwrap_or_else(|| {
        let mut c = Command::new("claude");
        c.arg("-p").arg(&prompt)
            .arg("--model").arg(&cfg.model)
            .arg("--dangerously-skip-permissions")
            .arg("--append-system-prompt-file").arg(&agent_file)
            .arg("--add-dir").arg(&cfg.root)
            .arg("--output-format").arg(&cfg.output_format)
            .env("IS_SANDBOX", "1")
            .stdin(std::process::Stdio::null());
        c
    });

    let out = cmd.output()?;
    let mut stdout = String::from_utf8_lossy(&out.stdout).into_owned();

    // Same account-exhaustion fallback as exec.rs::run_one — skipped when hermes was already
    // primary. This call has no `--fallback-model` either, so a flat session/usage-limit 429
    // would otherwise fail the whole analysis pass outright.
    if primary_engine != "hermes" && crate::is_account_exhausted(&stdout) {
        if let Some(mut hermes_cmd) = crate::build_hermes_command(cfg, &agent_file, &prompt) {
            println!("[event-scan] {run_id}: claude account exhausted — retrying via hermes fallback...");
            if let Ok(hout) = hermes_cmd.output() {
                stdout = String::from_utf8_lossy(&hout.stdout).into_owned();
            }
        }
    }
    std::fs::write(dir.join("analysis.raw.out.json"), &stdout).ok();

    let analysis: EventScanAnalysis = crate::parse::extract_json_object(&stdout).unwrap_or_default();
    std::fs::write(dir.join("analysis.md"), render_analysis_md(&report, &analysis)).ok();
    std::fs::write(dir.join("analysis.json"), serde_json::to_string_pretty(&analysis).unwrap_or_default()).ok();

    println!(
        "[event-scan] {run_id}: analysis done — verdict={}, {} finding(s), {} probable false positive(s)",
        analysis.overall_verdict, analysis.event_findings.len(), analysis.false_positives.len()
    );

    Ok(analysis)
}

/// Read back a previously saved LLM analysis, if one was ever run for this scan.
pub fn load_analysis(cfg: &Config, run_id: &str) -> Option<EventScanAnalysis> {
    let s = std::fs::read_to_string(cfg.root.join("event-scans").join(run_id).join("analysis.json")).ok()?;
    serde_json::from_str(&s).ok()
}

pub fn render_report_md(report: &EventScanReport) -> String {
    let mut md = String::new();
    md.push_str("# Event Scan Report\n\n");
    md.push_str(&format!(
        "**{} events scanned against {} validated YARA rule(s) and {} known IOC(s) — {} suspicious hit(s) on {} distinct event(s).**\n\n",
        report.total_events,
        report.rules_used,
        report.iocs_used,
        report.matches.len(),
        report.matches.iter().map(|m| m.event_index).collect::<std::collections::HashSet<_>>().len(),
    ));
    if report.matches.is_empty() {
        md.push_str("No suspicious events found.\n");
        return md;
    }
    md.push_str("| Event # | Matched by | Detail | Event summary |\n|---|---|---|---|\n");
    for m in &report.matches {
        md.push_str(&format!(
            "| {} | {} | {} | `{}` |\n",
            m.event_index, m.matched_by, m.detail.replace('|', "/"), m.event_summary.replace('|', "/")
        ));
    }
    md
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_events_handles_bare_array() {
        let events = extract_events(r#"[{"a":1},{"a":2}]"#).unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn extract_events_handles_wrapped_object() {
        let events = extract_events(r#"{"events":[{"a":1}],"meta":"x"}"#).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn extract_events_handles_single_bare_object() {
        let events = extract_events(r#"{"a":1}"#).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn event_summary_truncates_long_json() {
        let v: Value = serde_json::from_str(&format!(r#"{{"x":"{}"}}"#, "a".repeat(500))).unwrap();
        let s = event_summary(&v);
        assert!(s.ends_with('…'));
        assert!(s.chars().count() <= 201);
    }

    #[test]
    fn render_report_md_reports_zero_matches_cleanly() {
        let report = EventScanReport { total_events: 5, rules_used: 2, iocs_used: 3, matches: vec![] };
        let md = render_report_md(&report);
        assert!(md.contains("No suspicious events found."));
    }

    #[test]
    fn scan_events_end_to_end_flags_yara_and_ioc_hits() {
        if !have_yara() {
            eprintln!("skipping — `yara` not installed on this test host");
            return;
        }
        let root = std::env::temp_dir().join(format!("sasf-eventscan-e2e-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(&root).unwrap();

        // Fake session with one VALID rule (per its .validation.json) and one rule that
        // failed validation, which must NOT be used to flag anything.
        let yara_dir = root.join("sessions").join("999").join("yara");
        std::fs::create_dir_all(&yara_dir).unwrap();
        std::fs::write(
            yara_dir.join("evil_pattern.yar"),
            "rule evil_pattern { strings: $a = \"EVIL_MARKER_9f8e\" condition: $a }",
        )
        .unwrap();
        std::fs::write(
            yara_dir.join("evil_pattern.validation.json"),
            r#"{"vuln_class":"evil-pattern","file":"x","status":"valid","matched_target":true,"false_positive_hits":[],"fix_attempts":0,"detail":"ok"}"#,
        )
        .unwrap();
        std::fs::write(
            yara_dir.join("broken_pattern.yar"),
            "rule broken_pattern { strings: $a = \"NEVER_SEEN\" condition: $a }",
        )
        .unwrap();
        std::fs::write(
            yara_dir.join("broken_pattern.validation.json"),
            r#"{"vuln_class":"broken-pattern","file":"x","status":"no-match","matched_target":false,"false_positive_hits":[],"fix_attempts":2,"detail":"never matched"}"#,
        )
        .unwrap();

        // Fake known-iocs.json with one IOC that should hit a different event.
        let ti_dir = root.join("threat-intel");
        std::fs::create_dir_all(&ti_dir).unwrap();
        std::fs::write(
            ti_dir.join("known-iocs.json"),
            r#"[{"kind":"domain","value":"evil-c2.example","family":"Grandoreiro","notes":"test"}]"#,
        )
        .unwrap();

        let events_path = root.join("events.json");
        std::fs::write(
            &events_path,
            r#"[
                {"proc": "clean.exe", "msg": "nothing interesting"},
                {"proc": "dropper.exe", "msg": "beacon with EVIL_MARKER_9f8e payload"},
                {"domain": "evil-c2.example", "action": "dns-query"}
            ]"#,
        )
        .unwrap();

        let cfg = Config { root: root.clone(), ..Default::default() };
        let report = scan_events(&cfg, &events_path).expect("scan should succeed");

        assert_eq!(report.total_events, 3);
        assert_eq!(report.rules_used, 1, "only the valid rule should be collected: {report:?}");
        assert_eq!(report.iocs_used, 1);
        assert!(
            report.matches.iter().any(|m| m.event_index == 1 && m.matched_by.starts_with("yara:")),
            "expected a yara match on event 1: {:?}", report.matches
        );
        assert!(
            report.matches.iter().any(|m| m.event_index == 2 && m.matched_by.starts_with("ioc:")),
            "expected an ioc match on event 2: {:?}", report.matches
        );
        assert!(
            !report.matches.iter().any(|m| m.event_index == 0),
            "clean event should not have matched anything: {:?}", report.matches
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn render_report_md_lists_matches() {
        let report = EventScanReport {
            total_events: 3,
            rules_used: 1,
            iocs_used: 1,
            matches: vec![EventMatch {
                event_index: 1,
                event_summary: r#"{"proc":"evil.exe"}"#.into(),
                matched_by: "ioc:sha256:Grandoreiro".into(),
                detail: "contains known IOC".into(),
            }],
        };
        let md = render_report_md(&report);
        assert!(md.contains("ioc:sha256:Grandoreiro"));
        assert!(md.contains("evil.exe"));
    }
}
