use crate::{ToolOutput, ToolRunner, elapsed_ms, has_cmd, run_cmd_status};
use std::path::Path;
use std::time::Instant;

pub struct Volatility;

impl ToolRunner for Volatility {
    fn name(&self) -> &str { "volatility" }

    fn is_available(&self) -> bool {
        has_cmd("vol") || has_cmd("vol3") || has_cmd("volatility3")
    }

    fn run(&self, target: &Path, options: &serde_json::Value) -> ToolOutput {
        if !self.is_available() {
            return ToolOutput::unavailable(self.name());
        }
        let start = Instant::now();
        let target_str = target.to_string_lossy();
        let exe = if has_cmd("vol3") { "vol3" } else if has_cmd("vol") { "vol" } else { "volatility3" };

        let plugin = options.get("plugin").and_then(|v| v.as_str()).unwrap_or("windows.pslist.PsList");

        let (ok, stdout, stderr) = run_cmd_status(exe, &["-f", &target_str, "-r", "json", plugin]);

        if ok {
            match serde_json::from_str::<serde_json::Value>(&stdout) {
                Ok(parsed) => ToolOutput::ok(self.name(), parsed, elapsed_ms(start)),
                Err(_) => ToolOutput::ok(self.name(), serde_json::json!({
                    "plugin": plugin,
                    "output_lines": stdout.lines().count(),
                    "raw": stdout.lines().take(200).collect::<Vec<_>>(),
                }), elapsed_ms(start)),
            }
        } else {
            let mut errors = vec![format!("{exe} {plugin} failed")];
            if !stderr.trim().is_empty() {
                errors.push(stderr.lines().last().unwrap_or("").to_string());
            }
            ToolOutput::fail(self.name(), errors, elapsed_ms(start))
        }
    }
}
