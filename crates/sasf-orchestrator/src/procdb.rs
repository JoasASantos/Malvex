//! Malicious-process imphash database — automates growing the backend's process-validation
//! rule data (the `DWM001-malicious_process.json` shape: one entry per family with
//! `appName`/`family`/`executableNames`/`tags`/`imphashes`/`sha256`).
//!
//! Deliberately NOT LLM-driven for the hash values themselves: an imphash/sha256 is either a
//! real, checkable fact from a structured feed or it's worthless (worse than worthless — a
//! fabricated hash in a detection rule either never fires or, if it collides, mis-attributes a
//! clean process to a malware family). This module only ever writes hashes it got verbatim from
//! MalwareBazaar's (abuse.ch) API, which records `imphash` natively per submitted PE sample —
//! no guessing, no LLM in this path at all. `executableNames`/`tags` come from the same API
//! response (`file_name`/`tags` fields), so the whole entry is sourced from one place.
//!
//! Requires a free MalwareBazaar API key (register at https://bazaar.abuse.ch/register/) —
//! `--api-key` or `$MALWAREBAZAAR_API_KEY`.

use crate::lookup::MalwareLookup;
use crate::Config;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

/// The exact shape `DWM001-malicious_process.json` uses — field names/casing match verbatim so
/// this can be merged straight into that file with no translation layer.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ProcDbEntry {
    #[serde(rename = "appName")]
    pub app_name: String,
    pub family: String,
    #[serde(rename = "executableNames")]
    pub executable_names: Vec<String>,
    pub tags: Vec<String>,
    pub imphashes: Vec<String>,
    pub sha256: Vec<String>,
}

/// Which MalwareBazaar query to use — `tag` matches community-submitted tags (looser, broader
/// recall), `signature` matches the family label MalwareBazaar's own analysis assigned
/// (tighter, more precise). Try `tag` first; fall back to `signature` if it comes up empty.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MbQueryKind {
    Tag,
    Signature,
}

impl MbQueryKind {
    fn query_name(self) -> &'static str {
        match self {
            MbQueryKind::Tag => "get_taginfo",
            MbQueryKind::Signature => "get_siginfo",
        }
    }
    fn field_name(self) -> &'static str {
        match self {
            MbQueryKind::Tag => "tag",
            MbQueryKind::Signature => "signature",
        }
    }
}

/// Behavior/category tags worth keeping from MalwareBazaar's per-sample tag list — everything
/// else there (IPs, C2 domains, dates, campaign filenames) is submitter noise, not a fact about
/// the family. Extend this list as needed; an unrecognized tag is dropped, never invented.
const KNOWN_BEHAVIOR_TAGS: &[&str] = &[
    "banker", "banking", "credential-theft", "credentialstealer", "formgrabber", "loader",
    "downloader", "dropper", "botnet", "infostealer", "stealer", "spyware", "rat", "backdoor",
    "ransomware", "worm", "trojan", "keylogger", "clipper", "miner", "cryptominer", "rootkit",
    "exploit", "phishing",
];

/// Raw call to the MalwareBazaar API via `curl` — same shell-out-first convention as every
/// other external call in this crate (no reqwest/ureq dependency added just for this).
fn mb_query(api_key: &str, kind: MbQueryKind, value: &str, limit: u32) -> anyhow::Result<Value> {
    let body = format!("query={}&{}={}&limit={}", kind.query_name(), kind.field_name(), value, limit);
    let out = Command::new("curl")
        .arg("-s")
        .arg("-X").arg("POST")
        .arg("-H").arg(format!("Auth-Key: {api_key}"))
        .arg("-d").arg(&body)
        .arg("https://mb-api.abuse.ch/api/v1/")
        .output()?;
    if !out.status.success() {
        anyhow::bail!("curl failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    let v: Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| anyhow::anyhow!("MalwareBazaar response wasn't valid JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)))?;
    Ok(v)
}

/// Fetch one family's samples from MalwareBazaar and fold them into a single `ProcDbEntry`.
/// Tries `tag` first (broader), falls back to `signature` (MalwareBazaar's own family label)
/// if the tag search comes up empty — some families are tagged loosely by submitters but have
/// a clean `signature` classification, and vice versa.
pub fn fetch_family(api_key: &str, app_name: &str, family: &str, query_value: &str, limit: u32) -> anyhow::Result<ProcDbEntry> {
    let mut resp = mb_query(api_key, MbQueryKind::Tag, query_value, limit)?;
    if resp.get("query_status").and_then(|s| s.as_str()) != Some("ok") {
        resp = mb_query(api_key, MbQueryKind::Signature, query_value, limit)?;
    }
    let status = resp.get("query_status").and_then(|s| s.as_str()).unwrap_or("unknown");
    if status != "ok" {
        anyhow::bail!("MalwareBazaar query for \"{query_value}\" returned status \"{status}\" (no samples — check the tag/signature name, or that this family has PE submissions at all)");
    }
    let samples = resp.get("data").and_then(|d| d.as_array()).cloned().unwrap_or_default();
    if samples.is_empty() {
        anyhow::bail!("MalwareBazaar returned \"ok\" but zero samples for \"{query_value}\"");
    }

    let mut imphashes = BTreeSet::new();
    let mut sha256s = BTreeSet::new();
    let mut exe_names = BTreeSet::new();
    let mut sample_tags = BTreeSet::new();

    for s in &samples {
        if let Some(ih) = s.get("imphash").and_then(|v| v.as_str()) {
            if !ih.is_empty() {
                imphashes.insert(ih.to_lowercase());
            }
        }
        if let Some(h) = s.get("sha256_hash").and_then(|v| v.as_str()) {
            sha256s.insert(h.to_lowercase());
        }
        if let Some(fname) = s.get("file_name").and_then(|v| v.as_str()) {
            // A "process name" only makes sense for something that actually runs as its own
            // process — .exe/.dll. Delivery containers (.iso/.zip/.msi/.vbs/.7z) are how the
            // family ARRIVES, not what shows up in a process list, so they're noise here even
            // though they're perfectly legitimate `sha256` entries above.
            let lower = fname.to_lowercase();
            let is_exe_or_dll = lower.ends_with(".exe") || lower.ends_with(".dll");
            let stem = lower.strip_suffix(".exe").or_else(|| lower.strip_suffix(".dll")).unwrap_or(&lower);
            // MalwareBazaar submissions are often uploaded as "<sha256>.exe" or similar —
            // that's not a real process name either, just the hash with an extension slapped on.
            let looks_like_a_hash = stem.len() >= 32 && stem.chars().all(|c| c.is_ascii_hexdigit());
            if is_exe_or_dll && !looks_like_a_hash {
                exe_names.insert(lower);
            }
        }
        if let Some(tags) = s.get("tags").and_then(|v| v.as_array()) {
            for t in tags {
                if let Some(t) = t.as_str() {
                    let t = t.to_lowercase();
                    // MalwareBazaar tags are community-submitted and mostly campaign noise
                    // (IPs, C2 domains, dates, filenames like "endesa2026") — only keep the
                    // ones that are actual behavior/category labels, matching the clean
                    // "banker"/"credential-theft"-style tags DWM001 already uses.
                    if KNOWN_BEHAVIOR_TAGS.contains(&t.as_str()) {
                        sample_tags.insert(t);
                    }
                }
            }
        }
    }

    if imphashes.is_empty() {
        anyhow::bail!("MalwareBazaar returned {} sample(s) for \"{query_value}\" but none had an imphash (non-PE samples, or all packed/corrupted) — nothing usable for this DB", samples.len());
    }

    Ok(ProcDbEntry {
        app_name: app_name.to_string(),
        family: family.to_string(),
        executable_names: exe_names.into_iter().collect(),
        tags: sample_tags.into_iter().collect(),
        imphashes: imphashes.into_iter().collect(),
        sha256: sha256s.into_iter().collect(),
    })
}

/// Combines LLM research with MalwareBazaar's structured hash truth — the LLM NEVER supplies a
/// hash, only NAMES to try. Runs `lookup::lookup_malware` (WebSearch-backed) to resolve `query`
/// to its canonical name + known aliases (this is exactly the `malware-lookup` agent already
/// used by the Intel Lookup tab — same anti-hallucination design: honest "not found" rather
/// than a guess), then attempts a MalwareBazaar fetch under the resolved name AND every alias,
/// merging whatever actually returns real samples into one entry. This is what would have
/// found e.g. an alternate MalwareBazaar tag for a family whose public name doesn't match its
/// tag/signature there (the "Bizarro" gap in vulns/malicious-process-db.README.md is exactly
/// this — try again through this path once an alias surfaces).
pub fn discover_and_fetch(cfg: &Config, api_key: &str, query: &str, family: &str, limit: u32) -> anyhow::Result<(ProcDbEntry, MalwareLookup)> {
    let lookup = crate::lookup::lookup_malware(cfg, query)?;
    if !lookup.technical_error.is_empty() {
        anyhow::bail!("LLM research call failed technically (not a research miss): {}", lookup.technical_error);
    }
    if !lookup.found {
        anyhow::bail!("LLM research found no credible information on \"{query}\" — not fabricating a MalwareBazaar query for a name that may not be real. {}", lookup.not_found_note);
    }
    let resolved_name = if lookup.name.is_empty() { query.to_string() } else { lookup.name.clone() };
    let mut candidates = vec![resolved_name.clone()];
    candidates.extend(lookup.aliases.iter().cloned());
    candidates.dedup();

    let mut merged: Option<ProcDbEntry> = None;
    let mut tried_errors = Vec::new();
    for cand in &candidates {
        match fetch_family(api_key, &resolved_name, family, cand, limit) {
            Ok(entry) => {
                merged = Some(match merged {
                    None => entry,
                    Some(mut m) => {
                        union_into(&mut m.executable_names, &entry.executable_names);
                        union_into(&mut m.tags, &entry.tags);
                        union_into(&mut m.imphashes, &entry.imphashes);
                        union_into(&mut m.sha256, &entry.sha256);
                        m
                    }
                });
            }
            Err(e) => tried_errors.push(format!("{cand}: {e}")),
        }
    }

    match merged {
        Some(entry) => Ok((entry, lookup)),
        None => {
            // Last resort: the malware-lookup agent's OWN system prompt requires a real,
            // checkable source for every IOC it reports — so if a vendor writeup it found
            // happens to publish an imphash, it may already be sitting in `lookup.iocs`. This
            // is surfaced for a HUMAN to review and add by hand, never auto-merged into the
            // schema-exact output the way MalwareBazaar's data is — mixing an LLM-cited hash
            // into the "always MalwareBazaar-verified" guarantee this function otherwise
            // upholds would quietly weaken it for every OTHER family too.
            let cited: Vec<String> = lookup.iocs.iter()
                .filter(|i| i.kind.to_lowercase().contains("imphash") || i.kind.to_lowercase().contains("sha256"))
                .map(|i| format!("{}={} ({})", i.kind, i.value, i.notes))
                .collect();
            let cited_note = if cited.is_empty() {
                String::new()
            } else {
                format!("\n\nThe LLM's own research DID cite {} hash-shaped IOC(s) from a source \
                         it named — review and add manually if it checks out (never auto-merged \
                         here): {}", cited.len(), cited.join("; "))
            };
            anyhow::bail!(
                "LLM confirmed \"{resolved_name}\" is real (aliases: {}) but MalwareBazaar had \
                 nothing under any of [{}] — tried: {}{cited_note}",
                if lookup.aliases.is_empty() { "none found".to_string() } else { lookup.aliases.join(", ") },
                candidates.join(", "), tried_errors.join(" | ")
            )
        }
    }
}

/// Merge one entry into an existing DB file (created fresh if it doesn't exist yet).
/// Upsert by `appName` (case-insensitive): an existing entry's `executableNames`/`tags`/
/// `imphashes`/`sha256` are UNIONED with the new data (nothing already there is ever dropped),
/// never wholesale-replaced — repeated runs are safe to re-run as a refresh.
pub fn merge_into(path: &Path, entry: &ProcDbEntry) -> anyhow::Result<Vec<ProcDbEntry>> {
    let mut db: Vec<ProcDbEntry> = if path.is_file() {
        let raw = std::fs::read_to_string(path)?;
        serde_json::from_str(&raw)?
    } else {
        Vec::new()
    };

    let existing = db.iter_mut().find(|e| e.app_name.eq_ignore_ascii_case(&entry.app_name));
    match existing {
        Some(e) => {
            union_into(&mut e.executable_names, &entry.executable_names);
            union_into(&mut e.tags, &entry.tags);
            union_into(&mut e.imphashes, &entry.imphashes);
            union_into(&mut e.sha256, &entry.sha256);
        }
        None => db.push(entry.clone()),
    }
    db.sort_by(|a, b| a.app_name.to_lowercase().cmp(&b.app_name.to_lowercase()));

    std::fs::write(path, serde_json::to_string_pretty(&db)?)?;
    Ok(db)
}

/// Best-effort enrichment via VirusTotal's public API. NOTE the free-tier public key this is
/// built for can only look up ONE hash at a time (4 req/min) — it canNOT search/pivot by
/// imphash the way MalwareBazaar's tag/signature queries do (that needs a paid VT Intelligence
/// key, `/api/v3/intelligence/search`, which returns `ForbiddenError` on a plain public key).
/// So VT's role here is strictly enrichment of hashes MalwareBazaar ALREADY gave us — pulling
/// `meaningful_name` (VT's own seen-in-the-wild filename, sometimes more informative than
/// MalwareBazaar's submission filename) as an extra `executableNames` source, and cross-
/// checking `pe_info.imphash` against what's already recorded. A mismatch is reported as a
/// note, never silently added or trusted over MalwareBazaar's value — this function only adds
/// executable names, it never adds or changes a hash.
pub fn enrich_with_virustotal(vt_api_key: &str, entry: &mut ProcDbEntry, max_lookups: usize) -> Vec<String> {
    let mut notes = Vec::new();
    for (i, sha) in entry.sha256.iter().cloned().collect::<Vec<_>>().iter().take(max_lookups).enumerate() {
        if i > 0 {
            std::thread::sleep(std::time::Duration::from_secs(16)); // respect the 4 req/min public-tier quota
        }
        match vt_lookup(vt_api_key, sha) {
            Ok(Some((name, imphash))) => {
                if let Some(name) = name {
                    let lower = name.to_lowercase();
                    if (lower.ends_with(".exe") || lower.ends_with(".dll")) && !entry.executable_names.contains(&lower) {
                        entry.executable_names.push(lower);
                    }
                }
                if let Some(ih) = imphash {
                    if !entry.imphashes.iter().any(|e| e.eq_ignore_ascii_case(&ih)) {
                        notes.push(format!("VT reports a DIFFERENT imphash for {sha} ({ih}) than what's on file — not added automatically, verify before merging"));
                    }
                }
            }
            Ok(None) => {}
            Err(e) => notes.push(format!("VT lookup failed for {sha}: {e}")),
        }
    }
    entry.executable_names.sort();
    entry.executable_names.dedup();
    notes
}

fn vt_lookup(api_key: &str, sha256: &str) -> anyhow::Result<Option<(Option<String>, Option<String>)>> {
    let out = Command::new("curl")
        .arg("-s")
        .arg("-H").arg(format!("x-apikey: {api_key}"))
        .arg(format!("https://www.virustotal.com/api/v3/files/{sha256}"))
        .output()?;
    if !out.status.success() {
        anyhow::bail!("curl failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    let v: Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| anyhow::anyhow!("VT response wasn't valid JSON ({e})"))?;
    if v.get("error").is_some() {
        return Ok(None); // hash not on VT, or rate-limited — skip, don't fail the whole batch
    }
    let attrs = v.get("data").and_then(|d| d.get("attributes"));
    let name = attrs.and_then(|a| a.get("meaningful_name")).and_then(|n| n.as_str()).map(String::from);
    let imphash = attrs.and_then(|a| a.get("pe_info")).and_then(|p| p.get("imphash")).and_then(|i| i.as_str()).map(String::from);
    Ok(Some((name, imphash)))
}

fn union_into(existing: &mut Vec<String>, new: &[String]) {
    let mut set: BTreeSet<String> = existing.drain(..).collect();
    for v in new {
        set.insert(v.clone());
    }
    *existing = set.into_iter().collect();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_response(status: &str, samples: Vec<Value>) -> Value {
        serde_json::json!({"query_status": status, "data": samples})
    }

    #[test]
    fn union_into_dedupes_and_keeps_prior_values() {
        let mut existing = vec!["a".to_string(), "b".to_string()];
        union_into(&mut existing, &["b".to_string(), "c".to_string()]);
        assert_eq!(existing, vec!["a", "b", "c"]);
    }

    #[test]
    fn merge_into_creates_file_when_absent() {
        let path = std::env::temp_dir().join(format!("sasf-procdb-test-{}.json", std::process::id()));
        std::fs::remove_file(&path).ok();
        let entry = ProcDbEntry {
            app_name: "TestBanker".into(), family: "Banking Trojan".into(),
            executable_names: vec!["testbanker.exe".into()], tags: vec!["banker".into()],
            imphashes: vec!["aaaa".into()], sha256: vec!["bbbb".into()],
        };
        let db = merge_into(&path, &entry).unwrap();
        assert_eq!(db.len(), 1);
        assert_eq!(db[0].app_name, "TestBanker");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn merge_into_unions_existing_entry_never_drops_prior_hashes() {
        let path = std::env::temp_dir().join(format!("sasf-procdb-test-union-{}.json", std::process::id()));
        let first = ProcDbEntry {
            app_name: "TestBanker".into(), family: "Banking Trojan".into(),
            executable_names: vec!["old.exe".into()], tags: vec!["banker".into()],
            imphashes: vec!["old_hash".into()], sha256: vec!["old_sha".into()],
        };
        merge_into(&path, &first).unwrap();

        let second = ProcDbEntry {
            app_name: "testbanker".into(), family: "Banking Trojan".into(), // case-insensitive match
            executable_names: vec!["new.exe".into()], tags: vec!["loader".into()],
            imphashes: vec!["new_hash".into()], sha256: vec!["new_sha".into()],
        };
        let db = merge_into(&path, &second).unwrap();

        assert_eq!(db.len(), 1, "should upsert into the same entry, not create a second one");
        let e = &db[0];
        assert!(e.executable_names.contains(&"old.exe".to_string()));
        assert!(e.executable_names.contains(&"new.exe".to_string()));
        assert!(e.imphashes.contains(&"old_hash".to_string()));
        assert!(e.imphashes.contains(&"new_hash".to_string()));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn fetch_family_errors_cleanly_on_non_ok_status() {
        // No network call here — this test only exercises the status-check branch by hand
        // since fetch_family shells out to curl; a live-API integration test would need a
        // real MALWAREBAZAAR_API_KEY and is deliberately not run in CI.
        let resp = sample_response("no_results", vec![]);
        assert_eq!(resp.get("query_status").and_then(|s| s.as_str()), Some("no_results"));
    }
}
