use crate::{ToolOutput, ToolRunner, elapsed_ms, has_cmd, run_cmd_status};
use std::path::Path;
use std::time::Instant;

pub struct Ida;

impl ToolRunner for Ida {
    fn name(&self) -> &str { "ida" }

    fn is_available(&self) -> bool {
        has_cmd("idat64") || has_cmd("idat")
    }

    fn run(&self, target: &Path, options: &serde_json::Value) -> ToolOutput {
        if !self.is_available() {
            return ToolOutput::unavailable(self.name());
        }
        let start = Instant::now();
        let target_str = target.to_string_lossy();

        let exe = if has_cmd("idat64") { "idat64" } else { "idat" };
        let script = options.get("script").and_then(|v| v.as_str()).unwrap_or("");

        let mut args: Vec<&str> = vec!["-A", "-B"];
        if !script.is_empty() {
            args.push("-S");
            args.push(script);
        }
        args.push(&target_str);

        let (ok, stdout, stderr) = run_cmd_status(exe, &args);

        if ok {
            ToolOutput::ok(self.name(), serde_json::json!({
                "executable": exe,
                "output_lines": stdout.lines().count(),
                "idb_generated": true,
                "analysis": "batch mode complete",
            }), elapsed_ms(start))
        } else {
            let mut errors = vec![format!("{exe} batch analysis failed")];
            if !stderr.trim().is_empty() {
                errors.push(stderr.lines().last().unwrap_or("").to_string());
            }
            ToolOutput::fail(self.name(), errors, elapsed_ms(start))
        }
    }
}
