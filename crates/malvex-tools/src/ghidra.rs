use crate::{ToolOutput, ToolRunner, elapsed_ms, has_cmd, run_cmd_status};
use std::path::Path;
use std::time::Instant;

pub struct Ghidra;

impl ToolRunner for Ghidra {
    fn name(&self) -> &str { "ghidra" }

    fn is_available(&self) -> bool {
        has_cmd("analyzeHeadless") || has_cmd("ghidraRun") || has_cmd("ghidra")
    }

    fn run(&self, target: &Path, options: &serde_json::Value) -> ToolOutput {
        if !self.is_available() {
            return ToolOutput::unavailable(self.name());
        }
        let start = Instant::now();
        let target_str = target.to_string_lossy();

        let tmp_project = format!("/tmp/malvex_ghidra_{}", std::process::id());
        let _ = std::fs::create_dir_all(&tmp_project);

        let script = options.get("script").and_then(|v| v.as_str()).unwrap_or("");
        let mut args = vec![
            tmp_project.as_str(), "MalvexAnalysis",
            "-import", &target_str,
            "-overwrite",
            "-analysisTimeoutPerFile", "300",
        ];
        if !script.is_empty() {
            args.extend_from_slice(&["-postScript", script]);
        }

        let (ok, stdout, stderr) = run_cmd_status("analyzeHeadless", &args);
        let _ = std::fs::remove_dir_all(&tmp_project);

        let mut functions = Vec::new();
        let mut imports = Vec::new();
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.contains("Function:") || trimmed.contains("found function") {
                functions.push(trimmed.to_string());
            }
            if trimmed.contains("Import:") || trimmed.contains("imported") {
                imports.push(trimmed.to_string());
            }
        }

        if ok {
            ToolOutput::ok(self.name(), serde_json::json!({
                "functions_found": functions.len(),
                "imports_found": imports.len(),
                "functions": functions.iter().take(100).collect::<Vec<_>>(),
                "imports": imports.iter().take(200).collect::<Vec<_>>(),
                "raw_lines": stdout.lines().count(),
            }), elapsed_ms(start))
        } else {
            let mut errors = vec![format!("analyzeHeadless exited with error")];
            if !stderr.trim().is_empty() {
                errors.push(stderr.lines().last().unwrap_or("").to_string());
            }
            ToolOutput::fail(self.name(), errors, elapsed_ms(start))
        }
    }
}
