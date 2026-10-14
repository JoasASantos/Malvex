use crate::{ToolOutput, ToolRunner, elapsed_ms, has_cmd, run_cmd_status};
use std::path::Path;
use std::time::Instant;

pub struct Hashing;

fn hash_via(cmd: &str, args: &[&str]) -> Option<String> {
    let (ok, stdout, _) = run_cmd_status(cmd, args);
    if ok {
        let hash = stdout.trim().split_whitespace().next().unwrap_or("").to_lowercase();
        if hash.len() >= 16 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(hash);
        }
    }
    None
}

impl ToolRunner for Hashing {
    fn name(&self) -> &str { "hashing" }

    fn is_available(&self) -> bool {
        has_cmd("sha256sum") || has_cmd("shasum")
    }

    fn run(&self, target: &Path, _options: &serde_json::Value) -> ToolOutput {
        if !self.is_available() {
            return ToolOutput::unavailable(self.name());
        }
        let start = Instant::now();
        let target_str = target.to_string_lossy().to_string();

        let sha256 = hash_via("sha256sum", &[&target_str])
            .or_else(|| hash_via("shasum", &["-a", "256", &target_str]));
        let sha1 = hash_via("sha1sum", &[&target_str])
            .or_else(|| hash_via("shasum", &["-a", "1", &target_str]));
        let md5 = hash_via("md5sum", &[&target_str])
            .or_else(|| hash_via("md5", &["-q", &target_str]));

        let ssdeep = if has_cmd("ssdeep") {
            let (ok, out, _) = run_cmd_status("ssdeep", &["-b", &target_str]);
            if ok { out.lines().nth(1).map(|l| l.split(',').next().unwrap_or("").to_string()) } else { None }
        } else { None };

        let tlsh = if has_cmd("tlsh") {
            let (ok, out, _) = run_cmd_status("tlsh", &["-f", &target_str]);
            if ok { out.lines().next().map(|l| l.split_whitespace().next().unwrap_or("").to_string()) } else { None }
        } else { None };

        let imphash = if has_cmd("python3") {
            let script = format!(
                "import pefile,sys; pe=pefile.PE(sys.argv[1]); print(pe.get_imphash())"
            );
            let (ok, out, _) = run_cmd_status("python3", &["-c", &script, &target_str]);
            if ok && !out.trim().is_empty() && out.trim() != "None" { Some(out.trim().to_string()) } else { None }
        } else { None };

        ToolOutput::ok(self.name(), serde_json::json!({
            "sha256": sha256,
            "sha1": sha1,
            "md5": md5,
            "ssdeep": ssdeep,
            "tlsh": tlsh,
            "imphash": imphash,
        }), elapsed_ms(start))
    }
}
