pub mod binwalk;
pub mod capa;
pub mod elf;
pub mod exiftool;
pub mod frida;
pub mod ghidra;
pub mod hashing;
pub mod ida;
pub mod macho;
pub mod oletools;
pub mod osint;
pub mod pdf;
pub mod pe;
pub mod radare2;
pub mod sandbox;
pub mod strings;
pub mod tshark;
pub mod volatility;
pub mod yara;

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOutput {
    pub tool: String,
    pub success: bool,
    pub data: serde_json::Value,
    pub errors: Vec<String>,
    pub duration_ms: u64,
}

impl ToolOutput {
    pub fn ok(tool: &str, data: serde_json::Value, duration_ms: u64) -> Self {
        Self { tool: tool.into(), success: true, data, errors: Vec::new(), duration_ms }
    }

    pub fn fail(tool: &str, errors: Vec<String>, duration_ms: u64) -> Self {
        Self { tool: tool.into(), success: false, data: serde_json::Value::Null, errors, duration_ms }
    }

    pub fn unavailable(tool: &str) -> Self {
        Self { tool: tool.into(), success: false, data: serde_json::Value::Null, errors: vec!["tool not found in PATH".into()], duration_ms: 0 }
    }
}

pub trait ToolRunner: Send + Sync {
    fn name(&self) -> &str;
    fn is_available(&self) -> bool;
    fn run(&self, target: &Path, options: &serde_json::Value) -> ToolOutput;
}

fn has_cmd(name: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {name}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn run_cmd(prog: &str, args: &[&str], timeout_secs: u64) -> Result<(String, String), String> {
    let child = Command::new(prog)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {prog}: {e}"))?;

    let output = if timeout_secs > 0 {
        let start = Instant::now();
        let out = child.wait_with_output().map_err(|e| format!("wait {prog}: {e}"))?;
        if start.elapsed().as_secs() > timeout_secs {
            return Err(format!("{prog} timed out after {timeout_secs}s"));
        }
        out
    } else {
        child.wait_with_output().map_err(|e| format!("wait {prog}: {e}"))?
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    Ok((stdout, stderr))
}

fn run_cmd_status(prog: &str, args: &[&str]) -> (bool, String, String) {
    match Command::new(prog)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
    {
        Ok(out) => (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        ),
        Err(e) => (false, String::new(), format!("exec error: {e}")),
    }
}

fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

pub fn all_runners() -> Vec<Box<dyn ToolRunner>> {
    vec![
        Box::new(ghidra::Ghidra),
        Box::new(ida::Ida),
        Box::new(radare2::Radare2),
        Box::new(yara::Yara),
        Box::new(strings::Strings),
        Box::new(capa::Capa),
        Box::new(volatility::Volatility),
        Box::new(frida::Frida),
        Box::new(binwalk::Binwalk),
        Box::new(tshark::Tshark),
        Box::new(pe::Pe),
        Box::new(elf::Elf),
        Box::new(macho::MachO),
        Box::new(hashing::Hashing),
        Box::new(sandbox::Sandbox),
        Box::new(osint::Osint),
        Box::new(pdf::PdfParser),
        Box::new(pdf::PdfId),
        Box::new(oletools::Olevba),
        Box::new(oletools::Oleid),
        Box::new(oletools::Rtfobj),
        Box::new(exiftool::ExifTool),
    ]
}

pub fn find_runner(name: &str) -> Option<Box<dyn ToolRunner>> {
    all_runners().into_iter().find(|r| r.name() == name)
}

pub fn available_runners() -> Vec<Box<dyn ToolRunner>> {
    all_runners().into_iter().filter(|r| r.is_available()).collect()
}
