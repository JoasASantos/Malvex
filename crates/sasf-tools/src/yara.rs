use crate::{ToolOutput, ToolRunner, elapsed_ms, has_cmd, run_cmd_status};
use std::path::Path;
use std::time::Instant;

pub struct Yara;

impl ToolRunner for Yara {
    fn name(&self) -> &str { "yara" }

    fn is_available(&self) -> bool {
        has_cmd("yara")
    }

    fn run(&self, target: &Path, options: &serde_json::Value) -> ToolOutput {
        if !self.is_available() {
            return ToolOutput::unavailable(self.name());
        }
        let start = Instant::now();
        let target_str = target.to_string_lossy();

        let rules = options.get("rules").and_then(|v| v.as_str()).unwrap_or("");
        if rules.is_empty() {
            return ToolOutput::fail(self.name(), vec!["no rules path specified in options.rules".into()], elapsed_ms(start));
        }

        let recursive = options.get("recursive").and_then(|v| v.as_bool()).unwrap_or(false);
        let mut args = vec!["-s", "-m"];
        if recursive {
            args.push("-r");
        }
        args.push(rules);
        args.push(&target_str);

        let (ok, stdout, stderr) = run_cmd_status("yara", &args);

        let mut matches = Vec::new();
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() { continue; }
            let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
            if parts.len() >= 2 {
                matches.push(serde_json::json!({
                    "rule": parts[0],
                    "target": parts[1],
                }));
            } else if !trimmed.starts_with("0x") {
                matches.push(serde_json::json!({ "rule": trimmed, "target": &*target_str }));
            }
        }

        if ok || !matches.is_empty() {
            ToolOutput::ok(self.name(), serde_json::json!({
                "matches": matches,
                "match_count": matches.len(),
                "rules_file": rules,
            }), elapsed_ms(start))
        } else {
            let mut errors = vec!["yara scan failed".into()];
            if !stderr.trim().is_empty() {
                errors.push(stderr.lines().last().unwrap_or("").to_string());
            }
            ToolOutput::fail(self.name(), errors, elapsed_ms(start))
        }
    }
}
