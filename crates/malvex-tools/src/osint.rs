use crate::{ToolOutput, ToolRunner, elapsed_ms, has_cmd, run_cmd_status};
use std::path::Path;
use std::time::Instant;

pub struct Osint;

impl ToolRunner for Osint {
    fn name(&self) -> &str { "osint" }

    fn is_available(&self) -> bool {
        has_cmd("vt") || has_cmd("malwarebazaar-cli") || has_cmd("sha256sum") || has_cmd("shasum")
    }

    fn run(&self, target: &Path, options: &serde_json::Value) -> ToolOutput {
        if !self.is_available() {
            return ToolOutput::unavailable(self.name());
        }
        let start = Instant::now();
        let target_str = target.to_string_lossy().to_string();

        let sha256 = {
            let (ok, out, _) = if has_cmd("sha256sum") {
                run_cmd_status("sha256sum", &[&target_str])
            } else {
                run_cmd_status("shasum", &["-a", "256", &target_str])
            };
            if ok {
                out.trim().split_whitespace().next().unwrap_or("").to_string()
            } else {
                String::new()
            }
        };

        if sha256.is_empty() {
            return ToolOutput::fail(self.name(), vec!["could not compute sha256".into()], elapsed_ms(start));
        }

        let mut results = serde_json::Map::new();
        results.insert("sha256".into(), serde_json::Value::String(sha256.clone()));

        if has_cmd("vt") {
            let skip_vt = options.get("skip_vt").and_then(|v| v.as_bool()).unwrap_or(false);
            if !skip_vt {
                let (ok, stdout, _) = run_cmd_status("vt", &["file", &sha256, "--format", "json"]);
                if ok {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&stdout) {
                        results.insert("virustotal".into(), parsed);
                    } else {
                        results.insert("virustotal_raw".into(), serde_json::Value::String(
                            stdout.lines().take(50).collect::<Vec<_>>().join("\n")
                        ));
                    }
                }
            }
        }

        if has_cmd("malwarebazaar-cli") {
            let (ok, stdout, _) = run_cmd_status("malwarebazaar-cli", &["query", "sha256", &sha256]);
            if ok {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    results.insert("malwarebazaar".into(), parsed);
                } else {
                    results.insert("malwarebazaar_raw".into(), serde_json::Value::String(
                        stdout.lines().take(50).collect::<Vec<_>>().join("\n")
                    ));
                }
            }
        }

        ToolOutput::ok(self.name(), serde_json::Value::Object(results), elapsed_ms(start))
    }
}
