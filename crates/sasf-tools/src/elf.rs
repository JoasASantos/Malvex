use crate::{ToolOutput, ToolRunner, elapsed_ms, has_cmd, run_cmd_status};
use std::path::Path;
use std::time::Instant;

pub struct Elf;

impl ToolRunner for Elf {
    fn name(&self) -> &str { "elf" }

    fn is_available(&self) -> bool {
        has_cmd("readelf")
    }

    fn run(&self, target: &Path, _options: &serde_json::Value) -> ToolOutput {
        if !self.is_available() {
            return ToolOutput::unavailable(self.name());
        }
        let start = Instant::now();
        let target_str = target.to_string_lossy();

        let (h_ok, h_out, _) = run_cmd_status("readelf", &["-h", &target_str]);
        let (_s_ok, s_out, _) = run_cmd_status("readelf", &["-S", &target_str]);
        let (_d_ok, d_out, _) = run_cmd_status("readelf", &["--dyn-syms", &target_str]);

        if !h_ok {
            return ToolOutput::fail(self.name(), vec!["readelf -h failed (not an ELF?)".into()], elapsed_ms(start));
        }

        let mut header = std::collections::HashMap::new();
        for line in h_out.lines() {
            if let Some((key, val)) = line.split_once(':') {
                header.insert(key.trim().to_string(), val.trim().to_string());
            }
        }

        let sections: Vec<&str> = s_out.lines()
            .filter(|l| l.contains('[') && !l.contains("Key to Flags"))
            .collect();

        let dynamic_symbols: Vec<&str> = d_out.lines()
            .filter(|l| !l.trim().is_empty() && !l.contains("Symbol table") && !l.contains("Num:"))
            .collect();

        ToolOutput::ok(self.name(), serde_json::json!({
            "header": header,
            "sections_count": sections.len(),
            "sections_raw": sections.iter().take(50).collect::<Vec<_>>(),
            "dynamic_symbols_count": dynamic_symbols.len(),
            "dynamic_symbols": dynamic_symbols.iter().take(200).collect::<Vec<_>>(),
        }), elapsed_ms(start))
    }
}
