use crate::{ToolOutput, ToolRunner, elapsed_ms, has_cmd, run_cmd_status};
use std::path::Path;
use std::time::Instant;

pub struct Frida;

impl ToolRunner for Frida {
    fn name(&self) -> &str { "frida" }

    fn is_available(&self) -> bool {
        has_cmd("frida") || has_cmd("frida-trace")
    }

    fn run(&self, target: &Path, options: &serde_json::Value) -> ToolOutput {
        if !self.is_available() {
            return ToolOutput::unavailable(self.name());
        }
        let start = Instant::now();
        let target_str = target.to_string_lossy();

        let mode = options.get("mode").and_then(|v| v.as_str()).unwrap_or("trace");

        match mode {
            "trace" => {
                let functions = options.get("functions").and_then(|v| v.as_str()).unwrap_or("*!open*");
                let (ok, stdout, stderr) = run_cmd_status("frida-trace", &[
                    "-f", &target_str, "-i", functions,
                ]);
                if ok {
                    ToolOutput::ok(self.name(), serde_json::json!({
                        "mode": "trace",
                        "functions_traced": functions,
                        "output_lines": stdout.lines().count(),
                        "events": stdout.lines().take(500).collect::<Vec<_>>(),
                    }), elapsed_ms(start))
                } else {
                    ToolOutput::fail(self.name(), vec![
                        "frida-trace failed".into(),
                        stderr.lines().last().unwrap_or("").to_string(),
                    ], elapsed_ms(start))
                }
            }
            "script" => {
                let script = options.get("script").and_then(|v| v.as_str()).unwrap_or("");
                if script.is_empty() {
                    return ToolOutput::fail(self.name(), vec!["script mode requires options.script".into()], elapsed_ms(start));
                }
                let (ok, stdout, stderr) = run_cmd_status("frida", &[
                    "-f", &target_str, "-l", script, "--no-pause",
                ]);
                if ok {
                    ToolOutput::ok(self.name(), serde_json::json!({
                        "mode": "script",
                        "script": script,
                        "output": stdout.lines().take(500).collect::<Vec<_>>(),
                    }), elapsed_ms(start))
                } else {
                    ToolOutput::fail(self.name(), vec![
                        "frida script failed".into(),
                        stderr.lines().last().unwrap_or("").to_string(),
                    ], elapsed_ms(start))
                }
            }
            _ => {
                ToolOutput::fail(self.name(), vec![format!("unknown mode: {mode}, use 'trace' or 'script'")], elapsed_ms(start))
            }
        }
    }
}
