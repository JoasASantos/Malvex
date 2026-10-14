use crate::{ToolOutput, ToolRunner, elapsed_ms, has_cmd, run_cmd_status};
use std::path::Path;
use std::time::Instant;

pub struct ExifTool;

impl ToolRunner for ExifTool {
    fn name(&self) -> &str { "exiftool" }

    fn is_available(&self) -> bool {
        has_cmd("exiftool")
    }

    fn run(&self, target: &Path, _options: &serde_json::Value) -> ToolOutput {
        if !self.is_available() {
            return ToolOutput::unavailable(self.name());
        }
        let start = Instant::now();
        let target_str = target.to_string_lossy();
        let (ok, stdout, stderr) = run_cmd_status("exiftool", &["-json", &target_str]);

        if ok {
            match serde_json::from_str::<serde_json::Value>(&stdout) {
                Ok(parsed) => ToolOutput::ok(self.name(), parsed, elapsed_ms(start)),
                Err(_) => ToolOutput::ok(self.name(), serde_json::json!({
                    "raw_output": stdout.lines().take(300).collect::<Vec<_>>(),
                }), elapsed_ms(start)),
            }
        } else {
            ToolOutput::fail(self.name(), vec![stderr.lines().last().unwrap_or("exiftool failed").to_string()], elapsed_ms(start))
        }
    }
}
