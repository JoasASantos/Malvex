use crate::{ToolOutput, ToolRunner, elapsed_ms, has_cmd, run_cmd_status};
use std::path::Path;
use std::time::Instant;

pub struct Tshark;

impl ToolRunner for Tshark {
    fn name(&self) -> &str { "tshark" }

    fn is_available(&self) -> bool {
        has_cmd("tshark")
    }

    fn run(&self, target: &Path, options: &serde_json::Value) -> ToolOutput {
        if !self.is_available() {
            return ToolOutput::unavailable(self.name());
        }
        let start = Instant::now();
        let target_str = target.to_string_lossy();

        let filter = options.get("filter").and_then(|v| v.as_str()).unwrap_or("");
        let max_packets = options.get("max_packets").and_then(|v| v.as_u64()).unwrap_or(1000);

        let max_str = max_packets.to_string();
        let mut args = vec!["-r", &target_str, "-T", "json", "-c", &max_str];
        let filter_owned = filter.to_string();
        if !filter.is_empty() {
            args.extend_from_slice(&["-Y", &filter_owned]);
        }

        let (ok, stdout, stderr) = run_cmd_status("tshark", &args);

        if ok {
            match serde_json::from_str::<serde_json::Value>(&stdout) {
                Ok(parsed) => ToolOutput::ok(self.name(), serde_json::json!({
                    "packets": parsed,
                    "filter": filter,
                }), elapsed_ms(start)),
                Err(_) => ToolOutput::ok(self.name(), serde_json::json!({
                    "output_lines": stdout.lines().count(),
                    "raw": stdout.lines().take(200).collect::<Vec<_>>(),
                }), elapsed_ms(start)),
            }
        } else {
            let mut errors = vec!["tshark failed".into()];
            if !stderr.trim().is_empty() {
                errors.push(stderr.lines().last().unwrap_or("").to_string());
            }
            ToolOutput::fail(self.name(), errors, elapsed_ms(start))
        }
    }
}
