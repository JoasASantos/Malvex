//! On-demand single-malware/threat-actor intel lookup. Unlike `threatintel` (a recurring,
//! broad landscape sweep), this handles one analyst-supplied query — an APT name, a malware
//! family, a campaign — and researches that ONE thing as deeply as public sources allow: what
//! it is, its IOCs, and its TTPs structured by MITRE ATT&CK tactic. Not tied to a target
//! binary/session, same as `threatintel`.
//!
//! Layout on disk (same `<slug>-<epoch>/` convention as `sessions/<epoch>/` elsewhere, with a
//! human-readable slug prefix since a lookup is identified by name, not by target):
//!   intel-lookups/<slug>-<epoch>/report.md
//!   intel-lookups/<slug>-<epoch>/result.json
//!   intel-lookups/<slug>-<epoch>/raw.out.json   (raw agent stdout, for debugging/reparse)
//!   intel-lookups/index.json                    (list of lookup ids, newest first)

use crate::Config;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LookupIoc {
    /// sha256 | md5 | domain | ip | url | mutex | regkey | filepath | android-package
    pub kind: String,
    pub value: String,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MitreEntry {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub tactic: String,
}

/// TTPs bucketed by MITRE ATT&CK tactic (not a flat list) — an empty Vec on a tactic is honest
/// signal ("sources didn't document this phase"), not a gap the agent was told to pad.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Ttps {
    #[serde(default)]
    pub initial_access: Vec<String>,
    #[serde(default)]
    pub execution: Vec<String>,
    #[serde(default)]
    pub persistence: Vec<String>,
    #[serde(default)]
    pub privilege_escalation: Vec<String>,
    #[serde(default)]
    pub defense_evasion: Vec<String>,
    #[serde(default)]
    pub credential_access: Vec<String>,
    #[serde(default)]
    pub discovery: Vec<String>,
    #[serde(default)]
    pub lateral_movement: Vec<String>,
    #[serde(default)]
    pub collection: Vec<String>,
    #[serde(default)]
    pub command_and_control: Vec<String>,
    #[serde(default)]
    pub exfiltration: Vec<String>,
    #[serde(default)]
    pub impact: Vec<String>,
}

impl Ttps {
    /// (label, entries) pairs in kill-chain order, for rendering — skips the per-field
    /// boilerplate in both `render_report_md` and the web detail page.
    pub fn tactics(&self) -> [(&'static str, &Vec<String>); 12] {
        [
            ("Initial Access", &self.initial_access),
            ("Execution", &self.execution),
            ("Persistence", &self.persistence),
            ("Privilege Escalation", &self.privilege_escalation),
            ("Defense Evasion", &self.defense_evasion),
            ("Credential Access", &self.credential_access),
            ("Discovery", &self.discovery),
            ("Lateral Movement", &self.lateral_movement),
            ("Collection", &self.collection),
            ("Command and Control", &self.command_and_control),
            ("Exfiltration", &self.exfiltration),
            ("Impact", &self.impact),
        ]
    }
}

/// Raw shape the agent is asked to emit — see `agents/malware-lookup.md`'s "Output" section.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AgentOutput {
    #[serde(default)]
    found: bool,
    #[serde(default)]
    name: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    malware_type: String,
    #[serde(default)]
    platform: String,
    #[serde(default)]
    threat_actor: String,
    #[serde(default)]
    first_seen: String,
    #[serde(default)]
    last_seen: String,
    #[serde(default)]
    targets: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    modus_operandi: String,
    #[serde(default)]
    ttps: Ttps,
    #[serde(default)]
    mitre_techniques: Vec<MitreEntry>,
    #[serde(default)]
    iocs: Vec<LookupIoc>,
    #[serde(default)]
    detection_notes: String,
    #[serde(default)]
    confidence: String,
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default)]
    not_found_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MalwareLookup {
    pub id: String,
    pub query: String,
    pub generated_at_epoch: u64,
    pub found: bool,
    pub name: String,
    pub aliases: Vec<String>,
    pub malware_type: String,
    pub platform: String,
    pub threat_actor: String,
    pub first_seen: String,
    pub last_seen: String,
    pub targets: String,
    pub summary: String,
    pub modus_operandi: String,
    pub ttps: Ttps,
    pub mitre_techniques: Vec<MitreEntry>,
    pub iocs: Vec<LookupIoc>,
    pub detection_notes: String,
    pub confidence: String,
    pub sources: Vec<String>,
    pub not_found_note: String,
    /// Set ONLY when the LLM call itself failed technically (network error, HTTP 4xx/5xx,
    /// timeout — anything whose output isn't parseable JSON at all) — never when the agent
    /// genuinely researched the query and concluded nothing credible exists (that's `found:
    /// false` + `not_found_note`, a real research outcome). Distinguishing the two matters:
    /// a technical failure disguised as "not found" reads as a completed, honest miss when no
    /// research happened at all — exactly the kind of false signal this agent's anti-
    /// hallucination design exists to prevent, just one layer down (the code, not the model).
    #[serde(default)]
    pub technical_error: String,
    #[serde(skip)]
    pub dir: PathBuf,
}

fn now_epoch() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Filesystem/URL-safe slug from the free-text query, for a human-readable dir prefix
/// ("Breeze Comet" -> "breeze-comet"). Falls back to "query" if the whole thing strips away
/// (e.g. a query that's pure punctuation/emoji) so the id never collapses to a bare epoch.
fn slugify(query: &str) -> String {
    let mut slug = String::new();
    let mut last_was_dash = true; // suppress a leading dash
    for ch in query.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash {
            slug.push('-');
            last_was_dash = true;
        }
    }
    let slug = slug.trim_end_matches('-');
    let slug: String = slug.chars().take(48).collect();
    if slug.is_empty() { "query".to_string() } else { slug }
}

fn append_index(root: &Path, id: &str) {
    let idx_path = root.join("index.json");
    let mut ids: Vec<String> = std::fs::read_to_string(&idx_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    ids.retain(|i| i != id);
    ids.insert(0, id.to_string());
    std::fs::write(&idx_path, serde_json::to_string_pretty(&ids).unwrap_or_default()).ok();
}

/// List lookup ids, newest first (reads index.json; falls back to a directory scan if missing).
pub fn list_lookups(cfg: &Config) -> Vec<String> {
    let root = cfg.root.join("intel-lookups");
    if let Ok(s) = std::fs::read_to_string(root.join("index.json")) {
        if let Ok(ids) = serde_json::from_str::<Vec<String>>(&s) {
            return ids;
        }
    }
    let mut ids: Vec<String> = std::fs::read_dir(&root)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.path().is_dir())
                .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    ids.sort_by(|a, b| b.cmp(a));
    ids
}

/// Read back a previously generated lookup (no re-run — just the persisted JSON).
pub fn load_lookup(cfg: &Config, id: &str) -> Option<MalwareLookup> {
    let dir = cfg.root.join("intel-lookups").join(id);
    let s = std::fs::read_to_string(dir.join("result.json")).ok()?;
    let mut r: MalwareLookup = serde_json::from_str(&s).ok()?;
    r.dir = dir;
    Some(r)
}

/// Every IOC across every past lookup — same cross-cutting role as
/// `threatintel::known_iocs`, so Event Scan benefits from on-demand lookups too, not just the
/// weekly sweep. Returned as `threatintel::Ioc` (kind/value/family/notes) so `eventscan.rs` can
/// merge both sources without a second matching code path.
pub fn known_iocs(cfg: &Config) -> Vec<crate::threatintel::Ioc> {
    list_lookups(cfg)
        .iter()
        .filter_map(|id| load_lookup(cfg, id))
        .flat_map(|l| {
            let family = l.name.clone();
            l.iocs.into_iter().map(move |i| crate::threatintel::Ioc {
                kind: i.kind,
                value: i.value,
                family: family.clone(),
                notes: i.notes,
            })
        })
        .collect()
}

fn render_report_md(l: &MalwareLookup) -> String {
    let mut md = String::new();
    md.push_str(&format!("# Intel Lookup — {}\n\n", l.name));
    md.push_str(&format!("Consulta `{}` (rodada `{}`)\n\n", l.query, l.id));

    if !l.technical_error.is_empty() {
        md.push_str("**⚠ ERRO TÉCNICO — nenhuma pesquisa foi realizada.**\n\n");
        md.push_str(&l.technical_error);
        md.push_str("\n\nIsso NÃO é uma conclusão de \"não encontrado\" — a chamada ao LLM falhou antes de pesquisar. Tente de novo (outro modelo/engine se persistir).\n\n");
        return md;
    }

    if !l.found {
        md.push_str("**Não encontrado.**\n\n");
        if !l.not_found_note.trim().is_empty() {
            md.push_str(l.not_found_note.trim());
            md.push_str("\n\n");
        }
        return md;
    }

    if !l.aliases.is_empty() {
        md.push_str(&format!("- **Aliases:** {}\n", l.aliases.join(", ")));
    }
    if !l.malware_type.is_empty() {
        md.push_str(&format!("- **Tipo:** {}\n", l.malware_type));
    }
    if !l.platform.is_empty() {
        md.push_str(&format!("- **Plataforma:** {}\n", l.platform));
    }
    if !l.threat_actor.is_empty() {
        md.push_str(&format!("- **Ator/Grupo:** {}\n", l.threat_actor));
    }
    if !l.first_seen.is_empty() || !l.last_seen.is_empty() {
        md.push_str(&format!(
            "- **Visto entre:** {} — {}\n",
            if l.first_seen.is_empty() { "?" } else { &l.first_seen },
            if l.last_seen.is_empty() { "?" } else { &l.last_seen }
        ));
    }
    if !l.confidence.is_empty() {
        md.push_str(&format!("- **Confiança:** {}\n", l.confidence));
    }
    md.push('\n');

    if !l.targets.trim().is_empty() {
        md.push_str("## Alvos\n\n");
        md.push_str(l.targets.trim());
        md.push_str("\n\n");
    }
    if !l.summary.trim().is_empty() {
        md.push_str("## Resumo\n\n");
        md.push_str(l.summary.trim());
        md.push_str("\n\n");
    }
    if !l.modus_operandi.trim().is_empty() {
        md.push_str("## Modus operandi\n\n");
        md.push_str(l.modus_operandi.trim());
        md.push_str("\n\n");
    }

    md.push_str("## TTPs (MITRE ATT&CK)\n\n");
    let mut any_ttp = false;
    for (label, entries) in l.ttps.tactics() {
        if entries.is_empty() {
            continue;
        }
        any_ttp = true;
        md.push_str(&format!("**{label}**\n"));
        for e in entries {
            md.push_str(&format!("- {e}\n"));
        }
        md.push('\n');
    }
    if !any_ttp {
        md.push_str("Nenhuma TTP documentada pelas fontes encontradas.\n\n");
    }

    if !l.mitre_techniques.is_empty() {
        md.push_str("## Técnicas MITRE ATT&CK\n\n");
        md.push_str("| ID | Nome | Tática |\n|---|---|---|\n");
        for t in &l.mitre_techniques {
            md.push_str(&format!("| {} | {} | {} |\n", t.id, t.name, t.tactic));
        }
        md.push('\n');
    }

    md.push_str(&format!("## IOCs ({})\n\n", l.iocs.len()));
    if l.iocs.is_empty() {
        md.push_str("Nenhum IOC concreto encontrado.\n\n");
    } else {
        md.push_str("| Tipo | Valor | Notas |\n|---|---|---|\n");
        for i in &l.iocs {
            md.push_str(&format!("| {} | `{}` | {} |\n", i.kind, i.value, i.notes.replace('|', "/")));
        }
        md.push('\n');
    }

    if !l.detection_notes.trim().is_empty() {
        md.push_str("## Notas de detecção\n\n");
        md.push_str(l.detection_notes.trim());
        md.push_str("\n\n");
    }

    if !l.sources.is_empty() {
        md.push_str("## Fontes\n\n");
        for s in &l.sources {
            md.push_str(&format!("- {s}\n"));
        }
    }
    md
}

/// Run one on-demand lookup for `query` and persist it under `intel-lookups/<slug>-<epoch>/`.
pub fn lookup_malware(cfg: &Config, query: &str) -> anyhow::Result<MalwareLookup> {
    let root = cfg.root.join("intel-lookups");
    std::fs::create_dir_all(&root)?;
    let epoch = now_epoch();
    let id = format!("{}-{epoch}", slugify(query));
    let dir = root.join(&id);
    std::fs::create_dir_all(&dir)?;

    let agent_file = cfg.root.join("agents").join("malware-lookup.md");
    let prompt = format!(
        "Research this malware/threat-actor/campaign name as deeply as public sources allow: \
         \"{query}\"\n\n\
         Output ONLY the JSON object described in your system prompt's 'Output' section. No \
         prose outside the JSON."
    );

    let forced_hermes_cmd = if cfg.force_hermes { crate::build_hermes_command(cfg, &agent_file, &prompt) } else { None };
    let primary_engine = if forced_hermes_cmd.is_some() { "hermes" } else { "claude" };
    println!("[intel] lookup {id}: researching \"{query}\" (engine={primary_engine})...");
    let mut cmd = forced_hermes_cmd.unwrap_or_else(|| {
        let mut c = std::process::Command::new("claude");
        c.arg("-p").arg(&prompt)
            .arg("--model").arg(&cfg.model)
            .arg("--fallback-model").arg(cfg.fallbacks.join(","))
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

    // Same account-exhaustion fallback as exec.rs::run_one / threatintel::run_threat_intel —
    // skipped when hermes was already primary.
    if primary_engine != "hermes" && crate::is_account_exhausted(&stdout) {
        if let Some(mut hermes_cmd) = crate::build_hermes_command(cfg, &agent_file, &prompt) {
            println!("[intel] lookup {id}: claude account exhausted — retrying via hermes fallback...");
            if let Ok(hout) = hermes_cmd.output() {
                stdout = String::from_utf8_lossy(&hout.stdout).into_owned();
            }
        }
    }
    std::fs::write(dir.join("raw.out.json"), &stdout).ok();

    let parsed_opt: Option<AgentOutput> = crate::parse::extract_json_object(&stdout);
    // No parseable JSON at all means the LLM call itself failed (network error, HTTP
    // 4xx/5xx, timeout, empty output) — NOT a genuine "nothing found" research conclusion.
    // Surface that distinction explicitly (`technical_error`) instead of silently defaulting
    // into a normal-looking found:false result, which would misrepresent a failed call as a
    // completed, honest miss.
    let technical_error = if parsed_opt.is_none() {
        let tail: String = stdout.chars().take(400).collect();
        format!("Chamada ao LLM falhou tecnicamente (engine={}) — nenhuma pesquisa real ocorreu. \
                 Saída bruta: {}", if cfg.force_hermes { "hermes" } else { "claude" }, tail.trim())
    } else {
        String::new()
    };
    let parsed = parsed_opt.unwrap_or_default();
    let result = MalwareLookup {
        id: id.clone(),
        query: query.to_string(),
        generated_at_epoch: epoch,
        found: parsed.found,
        name: if parsed.name.is_empty() { query.to_string() } else { parsed.name },
        aliases: parsed.aliases,
        malware_type: parsed.malware_type,
        platform: parsed.platform,
        threat_actor: parsed.threat_actor,
        first_seen: parsed.first_seen,
        last_seen: parsed.last_seen,
        targets: parsed.targets,
        summary: parsed.summary,
        modus_operandi: parsed.modus_operandi,
        ttps: parsed.ttps,
        mitre_techniques: parsed.mitre_techniques,
        iocs: parsed.iocs,
        detection_notes: parsed.detection_notes,
        confidence: parsed.confidence,
        sources: parsed.sources,
        not_found_note: parsed.not_found_note,
        technical_error,
        dir: dir.clone(),
    };

    std::fs::write(dir.join("report.md"), render_report_md(&result)).ok();
    std::fs::write(dir.join("result.json"), serde_json::to_string_pretty(&result).unwrap_or_default()).ok();
    append_index(&root, &id);

    if !result.technical_error.is_empty() {
        println!("[intel] lookup {id}: TECHNICAL ERROR — {}", result.technical_error);
    } else {
        println!(
            "[intel] lookup {id}: found={}, {} ioc(s), {} mitre technique(s)",
            result.found, result.iocs.len(), result.mitre_techniques.len()
        );
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugify_handles_spaces_and_case() {
        assert_eq!(slugify("Breeze Comet"), "breeze-comet");
    }

    #[test]
    fn slugify_strips_punctuation() {
        assert_eq!(slugify("  Grandoreiro (Delf)!! "), "grandoreiro-delf");
    }

    #[test]
    fn slugify_never_empty() {
        assert_eq!(slugify("???"), "query");
    }

    #[test]
    fn render_report_md_not_found_is_honest() {
        let l = MalwareLookup {
            id: "x-1".into(), query: "Nonexistent123".into(), generated_at_epoch: 1,
            found: false, name: "Nonexistent123".into(), not_found_note: "sem fontes confiáveis".into(),
            ..Default::default()
        };
        let md = render_report_md(&l);
        assert!(md.contains("Não encontrado"));
        assert!(md.contains("sem fontes confiáveis"));
    }

    #[test]
    fn render_report_md_distinguishes_technical_error_from_not_found() {
        let l = MalwareLookup {
            id: "x-2".into(), query: "BANANA RAT".into(), generated_at_epoch: 1,
            found: false, name: "BANANA RAT".into(),
            technical_error: "Chamada ao LLM falhou tecnicamente (engine=hermes) — nenhuma pesquisa real ocorreu. Saída bruta: API call failed after 3 retries: HTTP 404".into(),
            ..Default::default()
        };
        let md = render_report_md(&l);
        assert!(md.contains("ERRO TÉCNICO"));
        assert!(md.contains("HTTP 404"));
        assert!(!md.contains("**Não encontrado.**"), "a technical failure must never render as a normal not-found miss: {md}");
    }

    #[test]
    fn render_report_md_lists_ttps_by_tactic() {
        let mut l = MalwareLookup { found: true, name: "TestFam".into(), ..Default::default() };
        l.ttps.defense_evasion.push("DLL side-loading".into());
        let md = render_report_md(&l);
        assert!(md.contains("Defense Evasion"));
        assert!(md.contains("DLL side-loading"));
        assert!(!md.contains("**Execution**"));
    }
}
