use crate::{ToolOutput, ToolRunner, elapsed_ms, has_cmd, run_cmd_status};
use std::path::Path;
use std::time::Instant;

pub struct Binwalk;

impl ToolRunner for Binwalk {
    fn name(&self) -> &str { "binwalk" }

    fn is_available(&self) -> bool {
        has_cmd("binwalk")
    }

    fn run(&self, target: &Path, options: &serde_json::Value) -> ToolOutput {
        if !self.is_available() {
            return ToolOutput::unavailable(self.name());
        }
        let start = Instant::now();
        let target_str = target.to_string_lossy();
        let extract = options.get("extract").and_then(|v| v.as_bool()).unwrap_or(false);

        let mut args = vec![];
        if extract {
            args.push("-e");
            args.push("--run-as=root");
        }
        args.push(&target_str);

        let (ok, stdout, stderr) = run_cmd_status("binwalk", &args);

        let mut entries = Vec::new();
        for line in stdout.lines().skip(3) {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('-') { continue; }
            let parts: Vec<&str> = trimmed.splitn(3, char::is_whitespace).collect();
            if parts.len() >= 3 {
                entries.push(serde_json::json!({
                    "offset": parts[0],
                    "type": parts[1],
                    "description": parts[2..].join(" ").trim().to_string(),
                }));
            }
        }

        if ok {
            ToolOutput::ok(self.name(), serde_json::json!({
                "entries": entries,
                "entry_count": entries.len(),
                "extracted": extract,
            }), elapsed_ms(start))
        } else {
            let mut errors = vec!["binwalk failed".into()];
            if !stderr.trim().is_empty() {
                errors.push(stderr.lines().last().unwrap_or("").to_string());
            }
            ToolOutput::fail(self.name(), errors, elapsed_ms(start))
        }
    }
}
