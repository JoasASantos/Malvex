use crate::{ToolOutput, ToolRunner, elapsed_ms, has_cmd, run_cmd_status};
use std::path::Path;
use std::time::Instant;

pub struct PdfParser;

impl ToolRunner for PdfParser {
    fn name(&self) -> &str { "pdf-parser" }

    fn is_available(&self) -> bool {
        has_cmd("pdf-parser") || has_cmd("pdf-parser.py")
    }

    fn run(&self, target: &Path, _options: &serde_json::Value) -> ToolOutput {
        if !self.is_available() {
            return ToolOutput::unavailable(self.name());
        }
        let start = Instant::now();
        let target_str = target.to_string_lossy();
        let cmd = if has_cmd("pdf-parser") { "pdf-parser" } else { "pdf-parser.py" };
        let (ok, stdout, stderr) = run_cmd_status(cmd, &["-a", &target_str]);

        if ok {
            ToolOutput::ok(self.name(), serde_json::json!({
                "raw_output": stdout.lines().take(500).collect::<Vec<_>>(),
            }), elapsed_ms(start))
        } else {
            ToolOutput::fail(self.name(), vec![stderr.lines().last().unwrap_or("pdf-parser failed").to_string()], elapsed_ms(start))
        }
    }
}

pub struct PdfId;

impl ToolRunner for PdfId {
    fn name(&self) -> &str { "pdfid" }

    fn is_available(&self) -> bool {
        has_cmd("pdfid") || has_cmd("pdfid.py")
    }

    fn run(&self, target: &Path, _options: &serde_json::Value) -> ToolOutput {
        if !self.is_available() {
            return ToolOutput::unavailable(self.name());
        }
        let start = Instant::now();
        let target_str = target.to_string_lossy();
        let cmd = if has_cmd("pdfid") { "pdfid" } else { "pdfid.py" };
        let (ok, stdout, stderr) = run_cmd_status(cmd, &[&target_str]);

        if ok {
            ToolOutput::ok(self.name(), serde_json::json!({
                "raw_output": stdout.lines().take(200).collect::<Vec<_>>(),
            }), elapsed_ms(start))
        } else {
            ToolOutput::fail(self.name(), vec![stderr.lines().last().unwrap_or("pdfid failed").to_string()], elapsed_ms(start))
        }
    }
}
