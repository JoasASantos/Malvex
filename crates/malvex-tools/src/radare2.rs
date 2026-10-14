use crate::{ToolOutput, ToolRunner, elapsed_ms, has_cmd, run_cmd_status};
use std::path::Path;
use std::time::Instant;

pub struct Radare2;

impl ToolRunner for Radare2 {
    fn name(&self) -> &str { "radare2" }

    fn is_available(&self) -> bool {
        has_cmd("r2") || has_cmd("radare2")
    }

    fn run(&self, target: &Path, options: &serde_json::Value) -> ToolOutput {
        if !self.is_available() {
            return ToolOutput::unavailable(self.name());
        }
        let start = Instant::now();
        let target_str = target.to_string_lossy();
        let exe = if has_cmd("r2") { "r2" } else { "radare2" };

        let custom_cmds = options.get("commands").and_then(|v| v.as_str()).unwrap_or("");
        let cmds = if custom_cmds.is_empty() {
            "aaa; aflj; izj; iij; iej; iSj"
        } else {
            custom_cmds
        };

        let (ok, stdout, stderr) = run_cmd_status(exe, &["-q", "-c", cmds, &target_str]);

        if !ok && stdout.trim().is_empty() {
            let mut errors = vec![format!("{exe} failed")];
            if !stderr.trim().is_empty() {
                errors.push(stderr.lines().last().unwrap_or("").to_string());
            }
            return ToolOutput::fail(self.name(), errors, elapsed_ms(start));
        }

        let mut sections = Vec::new();
        for block in stdout.split('\n') {
            let trimmed = block.trim();
            if trimmed.starts_with('[') {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                    sections.push(val);
                }
            }
        }

        ToolOutput::ok(self.name(), serde_json::json!({
            "json_sections": sections.len(),
            "data": sections,
            "raw_lines": stdout.lines().count(),
        }), elapsed_ms(start))
    }
}
