use crate::{ToolOutput, ToolRunner, elapsed_ms, has_cmd, run_cmd_status};
use std::path::Path;
use std::time::Instant;

pub struct Sandbox;

impl ToolRunner for Sandbox {
    fn name(&self) -> &str { "sandbox" }

    fn is_available(&self) -> bool {
        has_cmd("cuckoo") || has_cmd("cape-submit") || has_cmd("docker")
    }

    fn run(&self, target: &Path, options: &serde_json::Value) -> ToolOutput {
        if !self.is_available() {
            return ToolOutput::unavailable(self.name());
        }
        let start = Instant::now();
        let target_str = target.to_string_lossy();
        let backend = options.get("backend").and_then(|v| v.as_str()).unwrap_or("auto");

        let chosen = match backend {
            "cuckoo" if has_cmd("cuckoo") => "cuckoo",
            "cape" if has_cmd("cape-submit") => "cape",
            "docker" if has_cmd("docker") => "docker",
            "auto" => {
                if has_cmd("cuckoo") { "cuckoo" }
                else if has_cmd("cape-submit") { "cape" }
                else if has_cmd("docker") { "docker" }
                else { return ToolOutput::unavailable(self.name()); }
            }
            _ => return ToolOutput::fail(self.name(), vec![format!("unknown backend: {backend}")], elapsed_ms(start)),
        };

        match chosen {
            "cuckoo" => {
                let (ok, stdout, stderr) = run_cmd_status("cuckoo", &["submit", &target_str]);
                if ok {
                    ToolOutput::ok(self.name(), serde_json::json!({
                        "backend": "cuckoo",
                        "submitted": true,
                        "output": stdout.trim(),
                    }), elapsed_ms(start))
                } else {
                    ToolOutput::fail(self.name(), vec!["cuckoo submit failed".into(), stderr], elapsed_ms(start))
                }
            }
            "cape" => {
                let (ok, stdout, stderr) = run_cmd_status("cape-submit", &[&target_str]);
                if ok {
                    ToolOutput::ok(self.name(), serde_json::json!({
                        "backend": "cape",
                        "submitted": true,
                        "output": stdout.trim(),
                    }), elapsed_ms(start))
                } else {
                    ToolOutput::fail(self.name(), vec!["cape submit failed".into(), stderr], elapsed_ms(start))
                }
            }
            "docker" => {
                let image = options.get("image").and_then(|v| v.as_str()).unwrap_or("remnux/remnux-distro");
                let (ok, stdout, stderr) = run_cmd_status("docker", &[
                    "run", "--rm", "--network=none",
                    "-v", &format!("{}:/sample:ro", target_str),
                    image, "timeout", "120", "file", "/sample",
                ]);
                if ok {
                    ToolOutput::ok(self.name(), serde_json::json!({
                        "backend": "docker",
                        "image": image,
                        "output": stdout.trim(),
                    }), elapsed_ms(start))
                } else {
                    ToolOutput::fail(self.name(), vec!["docker sandbox failed".into(), stderr], elapsed_ms(start))
                }
            }
            _ => unreachable!(),
        }
    }
}
