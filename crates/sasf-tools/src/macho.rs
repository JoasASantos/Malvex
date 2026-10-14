use crate::{ToolOutput, ToolRunner, elapsed_ms, has_cmd, run_cmd_status};
use std::path::Path;
use std::time::Instant;

pub struct MachO;

impl ToolRunner for MachO {
    fn name(&self) -> &str { "macho" }

    fn is_available(&self) -> bool {
        has_cmd("otool") || has_cmd("jtool2")
    }

    fn run(&self, target: &Path, _options: &serde_json::Value) -> ToolOutput {
        if !self.is_available() {
            return ToolOutput::unavailable(self.name());
        }
        let start = Instant::now();
        let target_str = target.to_string_lossy();

        if has_cmd("otool") {
            let (h_ok, h_out, _) = run_cmd_status("otool", &["-h", &target_str]);
            let (_l_ok, l_out, _) = run_cmd_status("otool", &["-l", &target_str]);
            let (_, libs_out, _) = run_cmd_status("otool", &["-L", &target_str]);

            if !h_ok {
                return ToolOutput::fail(self.name(), vec!["otool -h failed (not a Mach-O?)".into()], elapsed_ms(start));
            }

            let libraries: Vec<String> = libs_out.lines()
                .filter(|l| l.contains("(compatibility"))
                .map(|l| l.trim().split(" (").next().unwrap_or("").trim().to_string())
                .collect();

            let mut segments = Vec::new();
            let mut current_segment = String::new();
            for line in l_out.lines() {
                if line.contains("cmd LC_SEGMENT") {
                    if !current_segment.is_empty() {
                        segments.push(current_segment.clone());
                    }
                    current_segment = String::new();
                }
                if !current_segment.is_empty() || line.contains("cmd LC_SEGMENT") {
                    current_segment.push_str(line.trim());
                    current_segment.push('\n');
                }
            }
            if !current_segment.is_empty() {
                segments.push(current_segment);
            }

            ToolOutput::ok(self.name(), serde_json::json!({
                "tool": "otool",
                "header": h_out.lines().take(5).collect::<Vec<_>>(),
                "segments_count": segments.len(),
                "libraries": libraries,
                "libraries_count": libraries.len(),
                "load_commands_lines": l_out.lines().count(),
            }), elapsed_ms(start))
        } else {
            let (ok, stdout, stderr) = run_cmd_status("jtool2", &["-h", &target_str]);
            if ok {
                ToolOutput::ok(self.name(), serde_json::json!({
                    "tool": "jtool2",
                    "output": stdout.lines().take(100).collect::<Vec<_>>(),
                }), elapsed_ms(start))
            } else {
                ToolOutput::fail(self.name(), vec!["jtool2 failed".into(), stderr], elapsed_ms(start))
            }
        }
    }
}
