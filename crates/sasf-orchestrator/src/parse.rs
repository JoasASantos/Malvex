//! Lenient extraction of `sasf-core::Finding` objects from an agent's free-form output.
//!
//! Agents are asked to emit a JSON array of Findings, but LLM output varies (prose around
//! it, ```json fences, missing fields). We extract the first balanced `[...]`, parse it as
//! generic JSON, then map each object into a Finding with defaults — never panicking on a
//! shape mismatch.

use sasf_core::{Evidence, Finding, Severity, Verdict};
use serde_json::Value;

/// Pull the agent's final text out of a `claude --output-format json` wrapper.
/// If `stdout` is that wrapper object, return its `.result` string; else return stdout as-is.
pub fn unwrap_claude_json(stdout: &str) -> String {
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(stdout.trim()) {
        if let Some(Value::String(s)) = map.get("result") {
            return s.clone();
        }
    }
    stdout.to_string()
}

/// Extract the first balanced JSON array substring, honoring strings/escapes.
fn first_json_array(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    let start = text.find('[')?;
    let mut depth = 0i32;
    let mut in_str = false;
    let mut esc = false;
    for i in start..bytes.len() {
        let c = bytes[i];
        if in_str {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
            continue;
        }
        match c {
            b'"' => in_str = true,
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[start..=i]);
                }
            }
            _ => {}
        }
    }
    None
}

fn severity_of(v: Option<&Value>) -> Severity {
    match v.and_then(|x| x.as_str()).unwrap_or("").to_lowercase().as_str() {
        "critical" | "crit" => Severity::Critical,
        "high" => Severity::High,
        "medium" | "med" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn verdict_of(v: Option<&Value>) -> Verdict {
    match v.and_then(|x| x.as_str()).unwrap_or("").to_lowercase().as_str() {
        "confirmed" => Verdict::Confirmed,
        "refuted" => Verdict::Refuted,
        "plausible" => Verdict::Plausible,
        _ => Verdict::Pending,
    }
}

fn str_of(o: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(Value::String(s)) = o.get(*k) {
            if !s.is_empty() {
                return Some(s.clone());
            }
        }
    }
    None
}

/// Pull a locus out of a free-form evidence string: a `0x…`/`sub_…` address if present,
/// else a leading symbol/selector name (e.g. "checkCertificate:fromChain:",
/// "new_connection_handler") so name-only IDA evidence still carries a locus.
fn sniff_locus(s: &str) -> Option<String> {
    // 1. explicit address token.
    for tok in s.split(|c: char| c.is_whitespace() || c == '@' || c == '(' || c == ')' || c == ',') {
        if tok.starts_with("0x") && tok.len() > 3 && tok[2..].chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(tok.to_string());
        }
        if tok.starts_with("sub_") && tok.len() > 4 {
            return Some(tok.to_string());
        }
    }
    // 2. leading symbol / Obj-C selector before a ' - ' / ': ' description separator.
    let head = s.split(" - ").next().unwrap_or(s);
    let head = head.strip_prefix("IDA:").unwrap_or(head).trim();
    // an identifier possibly with Obj-C selector colons: -[Class sel:arg:] or foo:bar:
    let sym: String = head
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '[' | ']' | '-' | ' '))
        .collect();
    let sym = sym.trim().trim_end_matches(|c: char| c == ':' && !head.contains("::")).trim().to_string();
    // Accept only if it looks like a symbol (has a letter, no sentence-y length, not all words).
    if sym.len() >= 4 && sym.len() <= 60 && sym.chars().any(|c| c.is_ascii_alphabetic()) && sym.split(' ').count() <= 4 {
        return Some(sym.trim_end_matches(':').to_string());
    }
    None
}

fn evidence_of(v: Option<&Value>) -> Vec<Evidence> {
    let Some(Value::Array(arr)) = v else { return Vec::new() };
    arr.iter()
        .filter_map(|e| match e {
            // Agents often emit evidence as an array of plain strings.
            Value::String(s) => Some(Evidence {
                kind: "note".into(),
                locus: sniff_locus(s),
                detail: s.clone(),
                artifact: None,
            }),
            Value::Object(o) => Some(Evidence {
                kind: str_of(o, &["kind", "type"]).unwrap_or_else(|| "note".into()),
                locus: str_of(o, &["locus", "addr", "address", "ea", "offset", "location"])
                    .or_else(|| str_of(o, &["detail", "description", "text"]).as_deref().and_then(sniff_locus)),
                detail: str_of(o, &["detail", "description", "text"]).unwrap_or_default(),
                artifact: str_of(o, &["artifact", "path", "file"]),
            }),
            _ => None,
        })
        .collect()
}

fn strvec_of(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// Map a single JSON object into a Finding with defaults.
fn finding_from(o: &serde_json::Map<String, Value>, target: &str, i: usize) -> Finding {
    let vuln_class = str_of(o, &["vuln_class", "vulnClass", "vector", "id"]).unwrap_or_else(|| "unknown".into());
    Finding {
        id: str_of(o, &["id"]).unwrap_or_else(|| format!("{vuln_class}-{i}")),
        vuln_class: vuln_class.clone(),
        title: str_of(o, &["title", "name"]).unwrap_or_else(|| vuln_class.clone()),
        severity: {
            let sev = o.get("severity").or_else(|| o.get("sev"));
            if sev.is_some() {
                severity_of(sev)
            } else {
                // Derive from CVSS base score when the agent only gave a number.
                match o.get("cvss").and_then(|x| x.as_f64()) {
                    Some(s) if s >= 9.0 => Severity::Critical,
                    Some(s) if s >= 7.0 => Severity::High,
                    Some(s) if s >= 4.0 => Severity::Medium,
                    Some(s) if s > 0.0 => Severity::Low,
                    _ => Severity::Info,
                }
            }
        },
        cvss: o.get("cvss").and_then(|x| x.as_f64()).map(|f| f as f32),
        cwe: str_of(o, &["cwe"]),
        verdict: verdict_of(o.get("verdict")),
        target: str_of(o, &["target"]).unwrap_or_else(|| target.to_string()),
        summary: str_of(o, &["summary", "description", "detail"]).unwrap_or_default(),
        evidence: {
            let mut ev = evidence_of(o.get("evidence"));
            // Synthesize evidence when the agent put the locus in the title and/or named the
            // binary in a `binary`/`file`/`module` field (common LLM shape with no evidence array).
            if ev.is_empty() {
                let title = str_of(o, &["title", "name"]).unwrap_or_default();
                let bin = str_of(o, &["binary", "file", "module"]);
                let locus = sniff_locus(&title).or_else(|| bin.clone());
                if locus.is_some() || !title.is_empty() {
                    ev.push(Evidence {
                        kind: "note".into(),
                        locus,
                        detail: match &bin { Some(b) => format!("{title} [{b}]"), None => title },
                        artifact: None,
                    });
                }
            }
            ev
        },
        poc: str_of(o, &["poc", "exploit"]),
        mitigations: strvec_of(o.get("mitigations")),
        prior_ref: str_of(o, &["prior_ref", "priorRef"]),
        chain: strvec_of(o.get("chain").or_else(|| o.get("chains")).or_else(|| o.get("attack_chain"))),
        poc_status: str_of(o, &["poc_status", "pocStatus"]),
    }
}

/// Extract the first balanced JSON object substring, honoring strings/escapes.
fn first_json_object(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    let start = text.find('{')?;
    let mut depth = 0i32;
    let mut in_str = false;
    let mut esc = false;
    for i in start..bytes.len() {
        let c = bytes[i];
        if in_str {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
            continue;
        }
        match c {
            b'"' => in_str = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[start..=i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Generic version of `extract_findings` for agents whose output contract is a single JSON
/// object rather than an array (e.g. threat-intel's `{families, iocs, ...}`). Unwraps the
/// `claude --output-format json` envelope, finds the first balanced `{...}`, and deserializes
/// it as `T`. Returns `None` on any parse failure.
pub fn extract_json_object<T: serde::de::DeserializeOwned>(stdout: &str) -> Option<T> {
    let text = unwrap_claude_json(stdout);
    let obj_str = first_json_object(&text)?;
    serde_json::from_str(obj_str).ok()
}

/// Extract Findings from an agent's raw stdout (claude json wrapper or plain text).
pub fn extract_findings(stdout: &str, target: &str) -> Vec<Finding> {
    let text = unwrap_claude_json(stdout);
    let Some(arr_str) = first_json_array(&text) else { return Vec::new() };
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(arr_str) else { return Vec::new() };
    items
        .iter()
        .enumerate()
        .filter_map(|(i, v)| v.as_object().map(|o| finding_from(o, target, i)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_from_fenced_prose() {
        let raw = r#"Here are findings:
```json
[{"vuln_class":"named-pipe-null-dacl","title":"NULL DACL","severity":"critical","verdict":"plausible","evidence":[{"kind":"decompile","locus":"0x1400238EA","detail":"SetSecurityDescriptorDacl(sd,1,0,0)"}],"prior_ref":"c6-01"}]
```
done"#;
        let f = extract_findings(raw, "sample.exe");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[0].evidence[0].locus.as_deref(), Some("0x1400238EA"));
        assert_eq!(f[0].prior_ref.as_deref(), Some("c6-01"));
    }

    #[test]
    fn unwraps_claude_result() {
        let raw = r#"{"type":"result","is_error":false,"result":"[{\"vuln_class\":\"x\",\"severity\":\"high\"}]"}"#;
        let f = extract_findings(raw, "t");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn empty_on_garbage() {
        assert!(extract_findings("no json here", "t").is_empty());
    }
}
