//! Recurring threat-intelligence stage. Unlike every other module in this crate, this one is
//! NOT tied to a target binary/session — it researches the current malware landscape for any
//! configured threat families/campaigns, extracts IOCs, and proposes detection rules. Meant to
//! run periodically via `malvex threat-intel run` or the "Threat Intel" tab in malvex-web.
//!
//! Layout on disk (mirrors the `sessions/<epoch>/` convention used everywhere else in this
//! repo — no chrono dependency, just a unix-epoch-seconds run id):
//!   threat-intel/<epoch>/report.md
//!   threat-intel/<epoch>/iocs.json
//!   threat-intel/<epoch>/detection-rules.md
//!   threat-intel/<epoch>/raw.out.json      (raw agent stdout, for debugging/reparse)
//!   threat-intel/known-iocs.json           (rolling dedup set across all runs)
//!   threat-intel/index.json                (list of run ids, newest first, for the web tab)

use crate::Config;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Ioc {
    /// sha256 | md5 | domain | ip | url | mutex | regkey | filepath | android-package
    pub kind: String,
    pub value: String,
    pub family: String,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MalwareFamily {
    pub name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub banks_targeted: Vec<String>,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub techniques: Vec<String>,
    /// MITRE ATT&CK technique IDs (e.g. "T1574.002") — only what the agent could justify
    /// from a source, never a rote checklist.
    #[serde(default)]
    pub mitre_techniques: Vec<String>,
    /// "alta" | "media" | "baixa" — agent's own confidence, not auto-derived.
    #[serde(default)]
    pub confidence: String,
    /// YYYY-MM-DD if the source gave a date; empty if unknown (never guessed).
    #[serde(default)]
    pub first_seen: String,
    #[serde(default)]
    pub last_seen: String,
    /// ASN/hosting/C2 pattern/country notes, in Portuguese — empty if the source had none.
    #[serde(default)]
    pub infra_notes: String,
    #[serde(default)]
    pub detection_notes: String,
    #[serde(default)]
    pub suggested_vectors: Vec<String>,
}

/// Raw shape the agent is asked to emit — see agents/threat-intel.md's "Output" section.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AgentOutput {
    #[serde(default)]
    families: Vec<MalwareFamily>,
    #[serde(default)]
    iocs: Vec<Ioc>,
    #[serde(default)]
    executive_summary: String,
    #[serde(default)]
    detection_rules_md: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatIntelReport {
    pub run_id: String,
    pub generated_at_epoch: u64,
    pub families: Vec<MalwareFamily>,
    pub iocs: Vec<Ioc>,
    pub new_ioc_count: usize,
    pub report_md: String,
    pub detection_rules_md: String,
    pub dir: PathBuf,
}

fn now_epoch() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn ioc_key(i: &Ioc) -> String {
    format!("{}:{}", i.kind.to_lowercase(), i.value.to_lowercase())
}

/// Load the rolling dedup set of every IOC ever reported by a prior run.
fn load_known_iocs(ti_root: &Path) -> Vec<Ioc> {
    std::fs::read_to_string(ti_root.join("known-iocs.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Public accessor for other modules (e.g. `eventscan`) that want to check arbitrary data
/// against every IOC this framework has ever collected, without reaching into the private
/// `known-iocs.json` layout directly.
pub fn known_iocs(cfg: &Config) -> Vec<Ioc> {
    load_known_iocs(&cfg.root.join("threat-intel"))
}

fn save_known_iocs(ti_root: &Path, iocs: &[Ioc]) {
    std::fs::write(
        ti_root.join("known-iocs.json"),
        serde_json::to_string_pretty(iocs).unwrap_or_default(),
    )
    .ok();
}

/// Append this run's id to `threat-intel/index.json` (newest first), for the web tab to list
/// without scanning the whole directory tree every request.
fn append_index(ti_root: &Path, run_id: &str) {
    let idx_path = ti_root.join("index.json");
    let mut ids: Vec<String> = std::fs::read_to_string(&idx_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    ids.retain(|i| i != run_id);
    ids.insert(0, run_id.to_string());
    std::fs::write(&idx_path, serde_json::to_string_pretty(&ids).unwrap_or_default()).ok();
}

/// List run ids, newest first (reads index.json; falls back to a directory scan if the index
/// is missing — e.g. the very first run, or a directory populated before this feature existed).
pub fn list_runs(cfg: &Config) -> Vec<String> {
    let ti_root = cfg.root.join("threat-intel");
    if let Ok(s) = std::fs::read_to_string(ti_root.join("index.json")) {
        if let Ok(ids) = serde_json::from_str::<Vec<String>>(&s) {
            return ids;
        }
    }
    let mut ids: Vec<String> = std::fs::read_dir(&ti_root)
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

/// Read back a previously generated report's summary (for the web tab's list page — cheap,
/// no LLM call, just reads the small JSON files already on disk).
pub fn load_run(cfg: &Config, run_id: &str) -> Option<ThreatIntelReport> {
    let dir = cfg.root.join("threat-intel").join(run_id);
    let report_md = std::fs::read_to_string(dir.join("report.md")).ok()?;
    let detection_rules_md = std::fs::read_to_string(dir.join("detection-rules.md")).unwrap_or_default();
    let iocs: Vec<Ioc> = std::fs::read_to_string(dir.join("iocs.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let families: Vec<MalwareFamily> = std::fs::read_to_string(dir.join("families.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let new_ioc_count = std::fs::read_to_string(dir.join("meta.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<RunMeta>(&s).ok())
        .map(|m| m.new_ioc_count)
        .unwrap_or(0);
    Some(ThreatIntelReport {
        run_id: run_id.to_string(),
        generated_at_epoch: run_id.parse().unwrap_or(0),
        families,
        iocs,
        new_ioc_count,
        report_md,
        detection_rules_md,
        dir,
    })
}

/// Small persisted sidecar so `load_run()` doesn't need to recompute `new_ioc_count` (that
/// number only makes sense at generation time, diffed against `known-iocs.json` as it stood
/// right before this run).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RunMeta {
    new_ioc_count: usize,
}

/// Minimal, dependency-free unix-epoch-seconds → "YYYY-MM-DD HH:MM UTC" formatter. No chrono
/// anywhere in this workspace — same shell-out-first, no-crate-bloat convention as the rest of
/// this repo. Days→civil-date via Howard Hinnant's well-known `civil_from_days` algorithm.
pub fn epoch_to_iso(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (hh, mm) = (rem / 3600, (rem % 3600) / 60);
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02} UTC")
}

fn render_report_md(
    run_id: &str,
    generated_at_epoch: u64,
    families: &[MalwareFamily],
    iocs: &[Ioc],
    new_ioc_count: usize,
    executive_summary: &str,
) -> String {
    let mut md = String::new();
    md.push_str("# Inteligência de Ameaças SafeApp — Malware Bancário Brasileiro\n\n");
    md.push_str(&format!("Rodada `{run_id}` (epoch unix {generated_at_epoch})\n\n"));
    md.push_str(&format!(
        "**{} famílias monitoradas, {} IOCs no total, {} novos desde a última rodada.**\n\n",
        families.len(),
        iocs.len(),
        new_ioc_count
    ));
    if !executive_summary.trim().is_empty() {
        md.push_str("## Resumo executivo\n\n");
        md.push_str(executive_summary.trim());
        md.push_str("\n\n");
    }
    md.push_str("## Famílias\n\n");
    for f in families {
        md.push_str(&format!("### {}\n\n", f.name));
        if !f.aliases.is_empty() {
            md.push_str(&format!("- **Aliases:** {}\n", f.aliases.join(", ")));
        }
        md.push_str(&format!("- **Plataforma:** {}\n", if f.platform.is_empty() { "desconhecida" } else { &f.platform }));
        if !f.banks_targeted.is_empty() {
            md.push_str(&format!("- **Bancos afetados:** {}\n", f.banks_targeted.join(", ")));
        }
        if !f.techniques.is_empty() {
            md.push_str(&format!("- **Técnicas:** {}\n", f.techniques.join("; ")));
        }
        if !f.mitre_techniques.is_empty() {
            md.push_str(&format!("- **MITRE ATT&CK:** {}\n", f.mitre_techniques.join(", ")));
        }
        if !f.confidence.is_empty() {
            md.push_str(&format!("- **Confiança:** {}\n", f.confidence));
        }
        if !f.first_seen.is_empty() || !f.last_seen.is_empty() {
            md.push_str(&format!(
                "- **Visto entre:** {} — {}\n",
                if f.first_seen.is_empty() { "?" } else { &f.first_seen },
                if f.last_seen.is_empty() { "?" } else { &f.last_seen }
            ));
        }
        let family_iocs: Vec<&Ioc> = iocs.iter().filter(|i| i.family == f.name).collect();
        md.push_str(&format!("- **IOCs nesta rodada:** {}\n", family_iocs.len()));
        if !f.summary.is_empty() {
            md.push_str(&format!("\n{}\n", f.summary));
        }
        if !f.infra_notes.is_empty() {
            md.push_str(&format!("\n**Infraestrutura:** {}\n", f.infra_notes));
        }
        if !f.detection_notes.is_empty() {
            md.push_str(&format!("\n**Notas de detecção SafeApp:** {}\n", f.detection_notes));
        }
        if !f.suggested_vectors.is_empty() {
            md.push_str(&format!(
                "\n**Cobertura sugerida em `vulns/taxonomy.yaml` (NÃO aplicada automaticamente — revisar antes de mesclar):** {}\n",
                f.suggested_vectors.join(", ")
            ));
        }
        md.push('\n');
    }
    md.push_str("## Apêndice de IOCs\n\n");
    md.push_str("| tipo | valor | família | notas |\n|---|---|---|---|\n");
    for i in iocs {
        md.push_str(&format!(
            "| {} | `{}` | {} | {} |\n",
            i.kind, i.value, i.family, i.notes.replace('|', "/")
        ));
    }
    md.push_str("\nVeja `detection-rules.md` para as regras YARA-sketch de cada família. As regras são ");
    md.push_str("esboços NÃO TESTADOS — validar antes de aplicar contra tráfego/binários reais.\n");
    md
}

/// Run one threat-intel cycle: spawn the `threat-intel` agent, parse its JSON output, dedup
/// against `known-iocs.json`, and write everything under `threat-intel/<epoch>/`.
pub fn run_threat_intel(cfg: &Config) -> anyhow::Result<ThreatIntelReport> {
    let ti_root = cfg.root.join("threat-intel");
    std::fs::create_dir_all(&ti_root)?;

    // Checado ANTES de criar o diretório da rodada: sem essa guarda, um `claude` ausente do
    // PATH (caso clássico sob launchd) deixava para trás um diretório vazio por execução, que
    // é o que fazia a aba Threat Intel parecer "configurada mas vazia".
    if !cfg.force_hermes && !crate::claude_on_path() {
        anyhow::bail!("{}", crate::claude_missing_error());
    }

    let run_id = now_epoch().to_string();
    let dir = ti_root.join(&run_id);
    std::fs::create_dir_all(&dir)?;

    let agent_file = cfg.root.join("agents").join("threat-intel.md");
    let prior_families: Vec<String> = list_runs(cfg)
        .into_iter()
        .filter(|id| id != &run_id)
        .take(1)
        .filter_map(|id| load_run(cfg, &id))
        .flat_map(|r| r.families.into_iter().map(|f| f.name))
        .collect();

    let prompt = format!(
        "Research the current Brazilian banking-malware threat landscape (this week's cycle). \
         Prior run already covered these families — still re-check them for updates, but \
         prioritize what's NEW: {}\n\n\
         Output ONLY the JSON object described in your system prompt's 'Output' section. No \
         prose outside the JSON.",
        if prior_families.is_empty() { "(no prior run — first cycle)".to_string() } else { prior_families.join(", ") }
    );

    // Explicit engine choice (Config::force_hermes) runs hermes as PRIMARY, skipping `claude`
    // entirely — same as exec.rs::run_one.
    let forced_hermes_cmd = if cfg.force_hermes { crate::build_hermes_command(cfg, &agent_file, &prompt) } else { None };
    let primary_engine = if forced_hermes_cmd.is_some() { "hermes" } else { "claude" };
    println!("[threat-intel] run {run_id}: researching Brazilian banking malware landscape (engine={primary_engine})...");

    let mut cmd = forced_hermes_cmd.unwrap_or_else(|| {
        let mut c = std::process::Command::new("claude");
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
    // primary. `--fallback-model` doesn't apply here at all (no such flag is even passed to
    // claude), so a flat session/usage-limit 429 would otherwise kill the whole weekly cycle.
    if primary_engine != "hermes" && crate::is_account_exhausted(&stdout) {
        if let Some(mut hermes_cmd) = crate::build_hermes_command(cfg, &agent_file, &prompt) {
            println!("[threat-intel] run {run_id}: claude account exhausted — retrying via hermes fallback...");
            if let Ok(hout) = hermes_cmd.output() {
                stdout = String::from_utf8_lossy(&hout.stdout).into_owned();
            }
        }
    }
    std::fs::write(dir.join("raw.out.json"), &stdout).ok();

    let parsed_opt: Option<AgentOutput> = crate::parse::extract_json_object(&stdout);
    // Saída não-parseável = a chamada falhou tecnicamente (rate limit, erro de rede, CLI que
    // não rodou), não "nada encontrado esta semana". Falha explícita, com a saída bruta
    // preservada para diagnóstico — mesmo princípio do `technical_error` do Intel Lookup. Sem
    // isso, a rodada seguia adiante e gravava um relatório vazio que parecia legítimo.
    let Some(parsed) = parsed_opt else {
        let tail: String = stdout.chars().take(400).collect();
        anyhow::bail!(
            "a chamada ao agente threat-intel não retornou JSON utilizável — nenhuma pesquisa \
             foi concluída (saída bruta preservada em {}).\nInício da saída: {}",
            dir.join("raw.out.json").display(),
            if tail.trim().is_empty() { "(vazia)" } else { tail.trim() }
        );
    };

    let known = load_known_iocs(&ti_root);
    let known_keys: HashSet<String> = known.iter().map(ioc_key).collect();
    let new_ioc_count = parsed.iocs.iter().filter(|i| !known_keys.contains(&ioc_key(i))).count();

    // Merge into the rolling known-IOC set (dedup by kind+value, keep first-seen notes).
    let mut merged = known;
    let mut merged_keys: HashSet<String> = merged.iter().map(ioc_key).collect();
    for i in &parsed.iocs {
        let k = ioc_key(i);
        if !merged_keys.contains(&k) {
            merged_keys.insert(k);
            merged.push(i.clone());
        }
    }
    save_known_iocs(&ti_root, &merged);

    let generated_at_epoch = now_epoch();
    let report_md = render_report_md(
        &run_id,
        generated_at_epoch,
        &parsed.families,
        &parsed.iocs,
        new_ioc_count,
        &parsed.executive_summary,
    );

    std::fs::write(dir.join("report.md"), &report_md).ok();
    std::fs::write(dir.join("detection-rules.md"), &parsed.detection_rules_md).ok();
    std::fs::write(dir.join("iocs.json"), serde_json::to_string_pretty(&parsed.iocs).unwrap_or_default()).ok();
    std::fs::write(dir.join("families.json"), serde_json::to_string_pretty(&parsed.families).unwrap_or_default()).ok();
    std::fs::write(dir.join("meta.json"), serde_json::to_string_pretty(&RunMeta { new_ioc_count }).unwrap_or_default()).ok();
    append_index(&ti_root, &run_id);

    println!(
        "[threat-intel] run {run_id}: {} families, {} IOCs ({} new)",
        parsed.families.len(),
        parsed.iocs.len(),
        new_ioc_count
    );

    Ok(ThreatIntelReport {
        run_id,
        generated_at_epoch,
        families: parsed.families,
        iocs: parsed.iocs,
        new_ioc_count,
        report_md,
        detection_rules_md: parsed.detection_rules_md,
        dir,
    })
}

/// launchd plist body for weekly execution (macOS — this repo's only real deployment target,
/// same shell-out-first convention as the `.dmg`/hdiutil resolution code in malvex-cli). Runs
/// every Monday 06:00 local time; launchd's own catch-up-on-wake handles a sleeping machine.
fn launchd_plist(malvex_bin: &Path, root: &Path, label: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin}</string>
        <string>threat-intel</string>
        <string>run</string>
        <string>--root</string>
        <string>{root}</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Weekday</key><integer>1</integer>
        <key>Hour</key><integer>6</integer>
        <key>Minute</key><integer>0</integer>
    </dict>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key><string>{path}</string>
    </dict>
    <key>StandardOutPath</key><string>{root}/threat-intel/launchd.out.log</string>
    <key>StandardErrorPath</key><string>{root}/threat-intel/launchd.err.log</string>
    <key>RunAtLoad</key><false/>
</dict>
</plist>
"#,
        label = label,
        bin = malvex_bin.display(),
        root = root.display(),
        path = launchd_path(),
    )
}

/// PATH to bake into the launchd plist.
///
/// launchd does NOT inherit the user's shell PATH — it hands the job a bare
/// `/usr/bin:/bin:/usr/sbin:/sbin`. The `claude` CLI installs to `~/.local/bin`, which is not
/// in that list, so without this the weekly job fails at `Command::new("claude")` with a bare
/// `No such file or directory (os error 2)` after already creating the run directory — which
/// is exactly what made scheduled Threat Intel runs show up empty in the web tab.
///
/// Snapshots the PATH in effect when `schedule_weekly` runs (which is the analyst's real shell
/// PATH, so it already contains wherever they actually installed things) and unions it with
/// `$HOME/.local/bin` plus the usual Homebrew prefixes, since those are where `claude`,
/// `uv`/`pipx`-installed MCP servers, and the RE tooling land.
fn launchd_path() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/var/root".into());
    let mut parts: Vec<String> = Vec::new();
    let mut push = |p: String| {
        if !p.is_empty() && !parts.contains(&p) {
            parts.push(p);
        }
    };
    push(format!("{home}/.local/bin"));
    push("/opt/homebrew/bin".into());
    push("/usr/local/bin".into());
    if let Ok(current) = std::env::var("PATH") {
        for p in current.split(':') {
            push(p.to_string());
        }
    }
    push("/usr/bin".into());
    push("/bin".into());
    push("/usr/sbin".into());
    push("/sbin".into());
    // XML text node — a literal '&' or '<' in a path would break the plist.
    parts.join(":").replace('&', "&amp;").replace('<', "&lt;")
}

pub const LAUNCHD_LABEL: &str = "io.unico.malvex.threatintel";

fn plist_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME not set"))?;
    Ok(PathBuf::from(home).join("Library/LaunchAgents").join(format!("{LAUNCHD_LABEL}.plist")))
}

/// Install (or refresh) the weekly launchd job. `malvex_bin` should be an absolute path to the
/// running `malvex` binary (e.g. from `std::env::current_exe()`), since launchd jobs run
/// outside any shell PATH.
pub fn schedule_weekly(malvex_bin: &Path, root: &Path) -> anyhow::Result<PathBuf> {
    let path = plist_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, launchd_plist(malvex_bin, root, LAUNCHD_LABEL))?;
    // unload first in case a stale copy is already loaded, then load the fresh one — launchd
    // errors loudly on a double-load of the same label.
    let _ = std::process::Command::new("launchctl").arg("unload").arg(&path).output();
    let status = std::process::Command::new("launchctl").arg("load").arg(&path).status()?;
    if !status.success() {
        anyhow::bail!("launchctl load failed (exit {:?}) for {}", status.code(), path.display());
    }
    Ok(path)
}

pub fn unschedule_weekly() -> anyhow::Result<()> {
    let path = plist_path()?;
    if path.is_file() {
        let _ = std::process::Command::new("launchctl").arg("unload").arg(&path).output();
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

/// Whether the weekly job is currently installed (plist present — doesn't verify launchd's
/// live state, just the on-disk artifact `schedule_weekly`/`unschedule_weekly` manage).
pub fn is_scheduled() -> bool {
    plist_path().map(|p| p.is_file()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioc_key_is_case_insensitive_dedup_key() {
        let a = Ioc { kind: "SHA256".into(), value: "ABC123".into(), family: "x".into(), notes: String::new() };
        let b = Ioc { kind: "sha256".into(), value: "abc123".into(), family: "y".into(), notes: "different family, same IOC".into() };
        assert_eq!(ioc_key(&a), ioc_key(&b));
    }

    #[test]
    fn render_report_md_counts_new_iocs_and_lists_families() {
        let families = vec![MalwareFamily {
            name: "Grandoreiro".into(),
            aliases: vec!["Delf".into()],
            platform: "windows".into(),
            banks_targeted: vec!["Itau".into(), "Bradesco".into()],
            summary: "Trojan bancário.".into(),
            techniques: vec!["DLL side-loading".into()],
            mitre_techniques: vec!["T1574.002".into()],
            confidence: "alta".into(),
            first_seen: "2026-08-15".into(),
            last_seen: "2026-08-25".into(),
            infra_notes: "C2 via DGA, hospedagem rotativa.".into(),
            detection_notes: "Varredura estática por strings do loader conhecido.".into(),
            suggested_vectors: vec!["dll-sideload-detect".into()],
        }];
        let iocs = vec![Ioc { kind: "sha256".into(), value: "deadbeef".into(), family: "Grandoreiro".into(), notes: "dropper".into() }];
        let md = render_report_md("123456", 123456, &families, &iocs, 1, "Resumo em português.");
        assert!(md.contains("Grandoreiro"));
        assert!(md.contains("1 novos desde a última rodada"));
        assert!(md.contains("deadbeef"));
        assert!(md.contains("Resumo em português."));
        assert!(md.contains("T1574.002"));
        assert!(md.contains("alta"));
        assert!(md.contains("2026-08-15"));
    }

    #[test]
    fn known_iocs_roundtrip() {
        let dir = std::env::temp_dir().join(format!("malvex-ti-known-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let iocs = vec![Ioc { kind: "domain".into(), value: "evil.example".into(), family: "x".into(), notes: String::new() }];
        save_known_iocs(&dir, &iocs);
        let loaded = load_known_iocs(&dir);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].value, "evil.example");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn epoch_to_iso_matches_known_timestamp() {
        // 2024-01-01 00:00:00 UTC == epoch 1704067200 (verified against `date -u -r`).
        assert_eq!(epoch_to_iso(1704067200), "2024-01-01 00:00 UTC");
        // 2026-08-28 11:45:00 UTC == epoch 1787917500 (verified against `date -u -r`).
        assert_eq!(epoch_to_iso(1787917500), "2026-08-28 11:45 UTC");
    }

    #[test]
    fn launchd_plist_embeds_bin_and_root_paths() {
        let plist = launchd_plist(Path::new("/usr/local/bin/malvex"), Path::new("/opt/SafeAppReverseHarness"), LAUNCHD_LABEL);
        assert!(plist.contains("/usr/local/bin/malvex"));
        assert!(plist.contains("/opt/SafeAppReverseHarness"));
        assert!(plist.contains("<key>Weekday</key><integer>1</integer>"));
    }

    #[test]
    fn launchd_plist_carries_a_path_including_local_bin() {
        // Sem isso a job semanal roda com o PATH mínimo do launchd
        // (/usr/bin:/bin:/usr/sbin:/sbin), não acha o `claude` em ~/.local/bin, e morre com um
        // ENOENT que parece "arquivo não encontrado" — a causa real das rodadas vazias.
        let plist = launchd_plist(Path::new("/usr/local/bin/malvex"), Path::new("/opt/x"), LAUNCHD_LABEL);
        assert!(plist.contains("<key>EnvironmentVariables</key>"), "plist precisa declarar o ambiente: {plist}");
        assert!(plist.contains("<key>PATH</key>"));
        assert!(plist.contains(".local/bin"), "PATH precisa incluir ~/.local/bin (onde o claude instala)");
    }

    #[test]
    fn launchd_path_is_deduped_and_has_system_fallbacks() {
        let p = launchd_path();
        let parts: Vec<&str> = p.split(':').collect();
        let mut sorted = parts.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), parts.len(), "PATH não pode ter entrada repetida: {p}");
        for required in ["/usr/bin", "/bin"] {
            assert!(parts.contains(&required), "faltou fallback de sistema {required} em {p}");
        }
    }
}
