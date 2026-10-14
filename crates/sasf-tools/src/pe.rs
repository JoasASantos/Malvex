use crate::{ToolOutput, ToolRunner, elapsed_ms, has_cmd, run_cmd_status};
use std::path::Path;
use std::time::Instant;

pub struct Pe;

impl ToolRunner for Pe {
    fn name(&self) -> &str { "pe" }

    fn is_available(&self) -> bool {
        has_cmd("python3")
    }

    fn run(&self, target: &Path, _options: &serde_json::Value) -> ToolOutput {
        if !self.is_available() {
            return ToolOutput::unavailable(self.name());
        }
        let start = Instant::now();
        let target_str = target.to_string_lossy();

        let script = format!(r#"
import json, sys
try:
    import pefile
    pe = pefile.PE(sys.argv[1])
    info = {{
        "machine": hex(pe.FILE_HEADER.Machine),
        "num_sections": pe.FILE_HEADER.NumberOfSections,
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
        "sections": [{{
            "name": s.Name.decode("utf-8","replace").strip("\x00"),
            "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "entropy": round(s.get_entropy(), 3),
            "characteristics": hex(s.Characteristics),
        }} for s in pe.sections],
        "imports": [{{
            "dll": e.dll.decode("utf-8","replace") if e.dll else "?",
            "functions": [i.name.decode("utf-8","replace") if i.name else str(i.ordinal) for i in e.imports]
        }} for e in (pe.DIRECTORY_ENTRY_IMPORT if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") else [])],
        "exports": [e.name.decode("utf-8","replace") if e.name else str(e.ordinal) for e in (pe.DIRECTORY_ENTRY_EXPORT.symbols if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else [])],
    }}
    print(json.dumps(info))
except ImportError:
    print(json.dumps({{"error": "pefile not installed"}}))
except Exception as e:
    print(json.dumps({{"error": str(e)}}))
"#);

        let (ok, stdout, stderr) = run_cmd_status("python3", &["-c", &script, &target_str]);

        if ok {
            match serde_json::from_str::<serde_json::Value>(stdout.trim()) {
                Ok(parsed) => {
                    if parsed.get("error").is_some() {
                        ToolOutput::fail(self.name(), vec![parsed["error"].as_str().unwrap_or("").to_string()], elapsed_ms(start))
                    } else {
                        ToolOutput::ok(self.name(), parsed, elapsed_ms(start))
                    }
                }
                Err(_) => ToolOutput::fail(self.name(), vec!["failed to parse pefile output".into()], elapsed_ms(start)),
            }
        } else {
            ToolOutput::fail(self.name(), vec!["python3 pefile script failed".into(), stderr], elapsed_ms(start))
        }
    }
}
