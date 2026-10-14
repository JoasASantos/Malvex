use crate::{ToolOutput, ToolRunner, elapsed_ms, has_cmd, run_cmd_status};
use std::path::Path;
use std::time::Instant;

pub struct Strings;

fn categorize(s: &str) -> Option<&'static str> {
    let lower = s.to_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") { return Some("url"); }
    if lower.starts_with("ftp://") { return Some("url"); }
    if s.contains("HKEY_") || s.contains("HKLM\\") || s.contains("HKCU\\") { return Some("registry"); }
    if (s.contains('.') && s.len() > 4 && s.len() < 60)
        && (lower.ends_with(".exe") || lower.ends_with(".dll") || lower.ends_with(".sys")
            || lower.ends_with(".bat") || lower.ends_with(".ps1") || lower.ends_with(".vbs"))
    { return Some("filename"); }
    if s.starts_with('/') && s.len() > 3 && s.contains('/') { return Some("path"); }
    if s.starts_with("C:\\") || s.starts_with("c:\\") { return Some("path"); }
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) { return Some("ipv4"); }
    if (lower.contains("aes") || lower.contains("rsa") || lower.contains("rc4")
        || lower.contains("blowfish") || lower.contains("chacha") || lower.contains("salsa"))
        && s.len() < 40
    { return Some("crypto"); }
    if lower.contains("password") || lower.contains("passwd") || lower.contains("secret")
        || lower.contains("token") || lower.contains("api_key") || lower.contains("apikey")
    { return Some("credential_hint"); }
    None
}

impl ToolRunner for Strings {
    fn name(&self) -> &str { "strings" }

    fn is_available(&self) -> bool {
        has_cmd("strings")
    }

    fn run(&self, target: &Path, options: &serde_json::Value) -> ToolOutput {
        if !self.is_available() {
            return ToolOutput::unavailable(self.name());
        }
        let start = Instant::now();
        let target_str = target.to_string_lossy();
        let min_len = options.get("min_length").and_then(|v| v.as_u64()).unwrap_or(6);

        let (ok, stdout, stderr) = run_cmd_status("strings", &["-n", &min_len.to_string(), &target_str]);
        if !ok {
            return ToolOutput::fail(self.name(), vec![stderr], elapsed_ms(start));
        }

        let all: Vec<&str> = stdout.lines().collect();
        let mut categorized = std::collections::HashMap::<&str, Vec<String>>::new();
        for s in &all {
            if let Some(cat) = categorize(s) {
                categorized.entry(cat).or_default().push(s.to_string());
            }
        }

        let has_floss = has_cmd("floss");
        let mut decoded_strings = Vec::new();
        if has_floss {
            let (fok, fout, _) = run_cmd_status("floss", &["-q", &target_str]);
            if fok {
                for line in fout.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && trimmed.len() >= min_len as usize {
                        decoded_strings.push(trimmed.to_string());
                    }
                }
            }
        }

        ToolOutput::ok(self.name(), serde_json::json!({
            "total_strings": all.len(),
            "categorized": categorized,
            "floss_available": has_floss,
            "floss_decoded": decoded_strings.len(),
            "decoded_strings": decoded_strings.iter().take(500).collect::<Vec<_>>(),
            "sample": all.iter().take(200).collect::<Vec<_>>(),
        }), elapsed_ms(start))
    }
}
