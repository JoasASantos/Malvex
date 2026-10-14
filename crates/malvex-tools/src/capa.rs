use crate::{ToolOutput, ToolRunner, elapsed_ms, has_cmd, run_cmd_status};
use std::path::Path;
use std::time::Instant;

pub struct Capa;

impl ToolRunner for Capa {
    fn name(&self) -> &str { "capa" }

    fn is_available(&self) -> bool {
        has_cmd("capa")
    }

    fn run(&self, target: &Path, options: &serde_json::Value) -> ToolOutput {
        if !self.is_available() {
            return ToolOutput::unavailable(self.name());
        }
        let start = Instant::now();
        let target_str = target.to_string_lossy();

        let mut args = vec!["--format", "json"];
        let rules_dir: String;
        if let Some(rules) = options.get("rules").and_then(|v| v.as_str()) {
            rules_dir = rules.to_string();
            args.extend_from_slice(&["-r", &rules_dir]);
        }
        args.push(&target_str);

        let (ok, stdout, stderr) = run_cmd_status("capa", &args);

        if ok {
            match serde_json::from_str::<serde_json::Value>(&stdout) {
                Ok(parsed) => ToolOutput::ok(self.name(), parsed, elapsed_ms(start)),
                Err(_) => ToolOutput::ok(self.name(), serde_json::json!({
                    "raw_output": stdout.lines().take(500).collect::<Vec<_>>(),
                }), elapsed_ms(start)),
            }
        } else {
            let mut errors = vec!["capa analysis failed".into()];
            if !stderr.trim().is_empty() {
                errors.push(stderr.lines().last().unwrap_or("").to_string());
            }
            ToolOutput::fail(self.name(), errors, elapsed_ms(start))
        }
    }
}
