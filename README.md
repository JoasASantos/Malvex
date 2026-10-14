# Malvex

**Reverse engineer malware with agents, from packed droppers down to memory-resident payloads.**

Malvex is a local-first orchestration harness that connects AI agents to 126 reverse-engineering and malware-analysis tools through MCP (Model Context Protocol). Point it at a binary, a memory dump, a document, or a packet capture. Malvex triages the sample, fans out parallel agents over IDA, Ghidra, radare2, Frida, volatility3, YARA, and dozens of other backends, and returns evidence-grounded findings — IOCs, MITRE ATT&CK mappings, detection rules, and attack-chain graphs — without uploading anything.

Analysis runs locally. Results include the evidence and limitations behind each conclusion.

> **Important rule:** LLM output is not evidence.
> The model may propose hypotheses, likely function names, algorithm matches, or ATT&CK mappings.
> Malvex treats those as analyst leads until they are tied to static or runtime evidence.

## What it analyzes

| Target | What Malvex recovers | Backends |
|---|---|---|
| **Native binaries** (PE, ELF, Mach-O, FAT) | Pseudocode, call graphs, xrefs, imports, strings, resources, compiler/packer ID | IDA, Ghidra, radare2, rizin, Binary Ninja, Cutter, otool, readelf, objdump, nm, lief |
| **Packed / obfuscated** | OEP recovery, unpacked payload, decoded strings, API hash resolution, de-virtualized control flow | UPX, DIE, PEiD, capa, FLOSS, unicorn, angr, VMProtect/Themida stub analysis |
| **Memory dumps** | Injected regions, hollowed processes, decrypted config, loaded modules, handle tables, process trees | volatility3, rekall, custom RWX scanners |
| **Documents** (Office, PDF, RTF, HTA) | Macros, embedded objects, exploit payloads, PowerShell stages, VBA deobfuscation | oletools (olevba/oleid), pdf-parser, peepdf, rtfobj |
| **Network captures** (pcap, HAR) | DNS, HTTP(S), TLS fingerprints, C2 beaconing, DGA, exfiltration patterns | tshark, tcpdump, mitmproxy, zeek, suricata |
| **Android / Mobile** (APK, DEX) | Manifest, decompiled methods, class references, permissions, native libs | apktool, jadx, androguard, adb |
| **Firmware** | Binary extraction, region analysis, embedded filesystem carving | binwalk, unblob, foremost, bulk\_extractor |
| **Shellcode** | Disassembly, emulation, payload staging, C2 config extraction | capstone, unicorn, speakeasy, keystone |
| **.NET assemblies** | IL disassembly, metadata, obfuscation layer identification | de4dot, dnSpy, ILSpy, monodis |
| **Scripts** (PowerShell, VBS, JS, Python) | Deobfuscation chains, encoded payloads, dropped artifacts | AST analysis, string decoding, regex extraction |

## Quick start

```bash
./setup.sh                           # install Rust + tools + MCP servers + Claude Code
malvex doctor                        # what analysis tools + MCP servers are available
malvex doctor --install              # install missing open-source tools
malvex mcp-setup --install           # wire RE MCP servers into Claude Code
malvex run /path/to/sample --dry-run # print the plan + agent commands (0 tokens)
malvex run /path/to/sample           # full pipeline
```

## Commands

| Command | Purpose |
|---|---|
| `malvex setup [--commercial]` | One-shot: install tools + MCP servers |
| `malvex doctor [--json] [--install]` | Detect tools + MCP servers; install missing open-source ones |
| `malvex mcp-setup [--install] [--commercial]` | Install + register RE MCP servers with your AI agent |
| `malvex run <target> [--dry-run] [--stages] [--resume] [--model] [--runtime]` | Full analysis pipeline |
| `malvex extract <installer>` | Unpack MSI/CAB/NSIS → PE binaries |
| `malvex graph <session>` | Build attack-chain graph (mermaid + JSON) |
| `malvex sessions` | List completed runs |
| `malvex reparse <session>` | Re-derive findings from raw output (no LLM) |
| `malvex coverage` | Taxonomy coverage: skills + agents present |
| `malvex repl <session>` | Interactive analyst Q&A against session findings |
| `malvex serve --mcp` | MCP server mode (JSON-RPC 2.0 over stdio, 8 tools) |
| `malvex preflight` | Pre-flight checks (10 checks: auth, tools, dirs, permissions) |

## Supported AI agents

Malvex drives analysis through your preferred AI agent. Choose your runtime:

| Runtime | Agent | How it works |
|---|---|---|
| `claude` (default) | Claude Code | `claude -p` with `--dangerously-skip-permissions`, parallel markdown agents |
| `codex` | Codex CLI | `codex exec --skip-git-repo-check --ephemeral` |
| `custom` | Any | Set `MALVEX_CUSTOM_CMD` — OpenRouter, LiteLLM, or your own wrapper |
| `hermes` | Hermes CLI | deepseek/qwen/kimi/glm/grok via `hermes-cli`, with `--hermes-provider` and `--hermes-model` |
| `ollama` | Ollama | Local LLM for offline/air-gapped labs, uses `MALVEX_OLLAMA_MODEL` env var |

```bash
# Claude Code (default)
malvex run sample.exe

# Codex CLI
malvex run sample.exe --runtime codex

# Custom provider (OpenRouter, LiteLLM, etc.)
MALVEX_CUSTOM_CMD="./my-llm-wrapper.sh" malvex run sample.exe --runtime custom

# Hermes (deepseek, qwen, kimi, glm, grok)
malvex run sample.exe --runtime hermes --hermes-provider deepseek --hermes-model deepseek-chat

# Ollama (local, offline / air-gapped)
MALVEX_OLLAMA_MODEL=llama3.1 malvex run sample.exe --runtime ollama
```

Runtime profiles are documented in [`config/runtime-profiles.yaml`](config/runtime-profiles.yaml).

## Analysis pipeline

```
 sample path
       │
       ▼
 ┌───────────┐   ┌──────────────────────────┐   ┌──────────────────────┐
 │  TRIAGE    │──▶│  STATIC                  │──▶│  DYNAMIC             │
 │ hashes,    │   │  static-core ∥            │   │  dynamic-analysis ∥   │
 │ type,      │   │  decompilation ∥          │   │  memory-analysis ∥    │
 │ packer,    │   │  deobfuscation ∥          │   │                      │
 │ entropy,   │   │                           │   │  (host must match    │
 │ strings,   │   │                           │   │   target platform    │
 │ IOC surface│   │                           │   │   for runtime proof) │
 └───────────┘   └──────────────────────────┘   └──────────┬───────────┘
                                                            ▼
                  ┌──────────────────────────┐   ┌──────────────────────┐
                  │  NETWORK                 │   │  INTELLIGENCE        │
                  │  network-analysis ∥       │   │  detection-eng ∥      │
                  │  tshark / tcpdump /      │──▶│  threat-intel ∥       │
                  │  mitmproxy / zeek        │   │                      │
                  └──────────────────────────┘   └──────────┬───────────┘
                                                            ▼
                  ┌──────────────────────────┐
                  │  VALIDATE                │
                  │  rejects unsupported     │
                  │  conclusions; forces     │
                  │  evidence/confidence     │
                  └──────────────────────────┘
                             │
                             ▼
                    session artifacts
```

Six pipeline stages, each spawning one or more agents in parallel. Agents share state through MCP (muster blackboard + claude-mem). Findings flow through a validator gate — no finding reaches `confirmed` without independent reproduction.

## Tooling matrix

### Disassemblers & decompilers

| Tool | License | Mac | Windows | Linux | Access |
|---|---|---|---|---|---|
| IDA Pro | commercial | ✓ | ✓ | ✓ | MCP `ida-pro-mcp` / `re-mcp` |
| Ghidra | open | brew | choco | apt | MCP `ghidra-mcp` / headless `analyzeHeadless` |
| radare2 | open | brew | choco | apt | MCP `radare2-mcp` / CLI `r2` |
| rizin | open | brew | choco | apt | CLI `rizin` |
| Cutter | open | brew | choco | flatpak | MCP `cutter-mcp` |
| Binary Ninja | commercial | ✓ | ✓ | ✓ | MCP `binaryninja-mcp` |

### Binary surface & metadata

| Tool | License | Mac | Windows | Linux | Purpose |
|---|---|---|---|---|---|
| otool | open | xcode | — | — | Mach-O load commands, dylibs, entitlements |
| codesign | open | xcode | — | — | Signature + hardened runtime checks |
| class-dump | open | ✓ | — | — | Objective-C runtime metadata extraction |
| readelf | open | brew | — | apt | ELF headers, sections, symbols, relocations |
| objdump | open | brew | — | apt | Section dumps, disassembly, imports |
| nm | open | brew | — | apt | Symbols and export surface |
| strings | open | brew | — | apt | Fast ASCII/Unicode extraction |
| exiftool | open | brew | choco | apt | Metadata from installers, documents, scripts |
| lief | open | pip | pip | pip | PE/Mach-O/ELF parse + patch (Python) |
| osslsigncode | open | brew | — | apt | Authenticode parsing for PE samples |
| checksec | open | brew | — | apt | Mitigation triage: RELRO, Canary, NX, PIE |

### Malware-specific analysis

| Tool | License | Mac | Windows | Linux | Purpose |
|---|---|---|---|---|---|
| capa | open | pip | pip | pip | FLARE capability inference from static rules |
| FLOSS | open | pip | pip | pip | Stack, decoded, and obfuscated string recovery |
| YARA | open | brew | choco | apt | Signature matching + detection rule validation |
| ssdeep | open | brew | — | apt | Fuzzy hashing for clustering and lineage |
| hashdeep | open | brew | — | apt | Recursive hashing for evidence inventories |
| oletools | open | pip | pip | pip | Office/OLE macro and embedded object triage |
| volatility3 | open | pip | pip | pip | Memory forensics: injections, modules, handles |
| DIE | open | — | choco | apt | Detect It Easy — packer/compiler identification |
| PEiD/peframe | open | pip | choco | pip | Packer signature detection |

### Unpacking & carving

| Tool | License | Mac | Windows | Linux | Purpose |
|---|---|---|---|---|---|
| UPX | open | brew | choco | apt | Unpack UPX-compressed binaries |
| binwalk | open | brew | pip | apt | Firmware + embedded blob carving |
| foremost | open | — | — | apt | File carving from memory dumps |
| bulk\_extractor | open | brew | — | apt | Bulk artifact extraction |
| msitools | open | brew | choco | apt | MSI table + file extraction |
| p7zip | open | brew | choco | apt | MSI/CAB/NSIS/InnoSetup unpacking |
| cabextract | open | brew | choco | apt | CAB decompression |
| innoextract | open | brew | — | apt | Inno Setup extraction |

### Emulation & symbolic execution

| Tool | License | Mac | Windows | Linux | Purpose |
|---|---|---|---|---|---|
| capstone | open | pip | pip | pip | Multi-arch disassembly engine |
| keystone | open | pip | pip | pip | Assembler engine for patch generation |
| unicorn | open | pip | pip | pip | CPU emulator — runs packer stubs in isolation |
| angr | open | pip | pip | pip | Symbolic execution + constraint solving |
| ropper | open | pip | pip | pip | ROP/JOP gadget search |

### Dynamic instrumentation & debuggers

| Tool | License | Mac | Windows | Linux | Access |
|---|---|---|---|---|---|
| Frida | open | pip | pip | pip | MCP `frida-mcp` / CLI `frida-trace` |
| lldb | open | xcode | — | apt | macOS native debugging |
| gdb | open | brew | choco | apt | Linux/cross debugging |
| x64dbg | open | — | choco | — | Windows user-mode debugging |
| WinDbg | commercial | — | winget | — | Kernel + user debugging |
| strace | open | — | — | apt | Linux syscall tracing |
| ltrace | open | — | — | apt | Linux library-call tracing |

### Network analysis

| Tool | License | Mac | Windows | Linux | Purpose |
|---|---|---|---|---|---|
| mitmproxy | open | brew | pip | apt | TLS intercept for C2 and update-channel analysis |
| tshark | open | brew | choco | apt | CLI packet analysis: DNS, HTTP(S), JA3 |
| tcpdump | open | brew | — | apt | Raw packet capture for sandbox evidence |

### MCP orchestration

| Tool | Kind | Purpose |
|---|---|---|
| claude-mem | MCP plugin | Persistent cross-run memory of findings + context |
| muster | MCP server | Blackboard + budget shared across parallel agents |

## MCP servers

Malvex can auto-install and wire these MCP servers into your AI agent via `malvex mcp-setup --install`:

| MCP server | Backend | License |
|---|---|---|
| `ida-pro-mcp` ([mrexodia](https://github.com/mrexodia/ida-pro-mcp)) | IDA Pro | commercial |
| `ghidra-mcp` ([bethington](https://github.com/bethington/ghidra-mcp)) | Ghidra | open |
| `radare2-mcp` ([radareorg](https://github.com/radareorg/radare2-mcp)) | radare2 | open |
| `frida-mcp` ([dnakov](https://github.com/dnakov/frida-mcp)) | Frida | open |
| `x64dbg-mcp` ([wasdubya](https://github.com/wasdubya/x64dbgmcp)) | x64dbg | open |
| `re-mcp` ([jtsylve](https://github.com/jtsylve/re-mcp)) | IDA headless | open |
| `binaryninja-mcp` ([fosdickio](https://github.com/fosdickio/binary_ninja_mcp)) | Binary Ninja | commercial |
| `cutter-mcp` ([ap425q](https://github.com/ap425q/CutterMCP)) | Cutter/rizin | open |
| `yaraflux-mcp` ([ThreatFlux](https://github.com/ThreatFlux/YaraFlux)) | YARA | open |
| `rea` ([morluto](https://github.com/morluto/rea)) | Ghidra/IDA/r2/Frida/.NET/Android | open |

Verify with `claude mcp list` after setup. Commercial backends (IDA, Binary Ninja) are detected and reported, never auto-installed.

## REA integration

Malvex automatically installs and integrates [REA](https://github.com/morluto/rea)
for base reverse engineering capabilities. REA provides:

- **Binary analysis**: Ghidra, IDA Pro, radare2, Binary Ninja — disassembly, decompilation, function listing, xrefs
- **Dynamic analysis**: Frida hooking, runtime instrumentation
- **.NET**: Assembly decompilation and analysis
- **Android**: APK analysis via JADX/apktool
- **Browser/Electron**: Web app and Electron inspection

Malvex adds malware-specific layers on top of REA:

- **Detection engineering**: YARA/Sigma rule generation and validation
- **Memory forensics**: Volatility3 injection detection, RWX scanning, config extraction
- **Sandbox integration**: CAPE/Cuckoo automated detonation and behavioral analysis
- **Threat intelligence**: MISP, VirusTotal, MalwareBazaar, OSINT lookups
- **Evidence-driven pipeline**: 15 specialized agents with hypothesis-evidence-verification model
- **200+ malware analysis tools**: from triage to advanced forensics

```bash
malvex setup                    # installs everything including REA
npx rea-agents setup            # or manually configure REA for Claude Code
```

When REA is available, Malvex agents automatically prefer REA's unified MCP interface
for disassembly, decompilation, and cross-reference analysis — falling back to direct
tool invocation only when REA is not installed.

## MCP server mode

`malvex serve` exposes 30 analysis tools over MCP (JSON-RPC 2.0, stdio transport). Any AI agent — Claude Code, Cursor, Windsurf, Cline, Codex — can connect and use them directly.

```bash
# Register with Claude Code
claude mcp add malvex -- malvex serve

# Or run standalone
malvex serve --transport stdio
```

### Available MCP tools

| Category | Tool | What it does |
|---|---|---|
| **Pipeline** | `malvex_analyze` | Full analysis pipeline on a target |
| | `malvex_triage` | Quick triage: hashes, format, packer, entropy |
| | `malvex_doctor` | Environment check: tools, MCPs available |
| | `malvex_sessions` | List completed analysis sessions |
| | `malvex_findings` | Retrieve findings from a session |
| | `malvex_coverage` | Taxonomy coverage report |
| | `malvex_extract` | Unpack MSI/CAB/NSIS installers |
| | `malvex_reparse` | Re-derive findings (no LLM) |
| **Discovery** | `malvex_tools_available` | List installed tools with versions |
| **Triage** | `malvex_hash` | All hashes: MD5, SHA1, SHA256, ssdeep, imphash, TLSH |
| | `malvex_strings` | Categorized strings: URLs, IPs, paths, registry, crypto |
| | `malvex_file_type` | File type, magic, entropy, sections, packer |
| | `malvex_capa` | Capability detection with ATT&CK mapping |
| **RE** | `malvex_disasm` | Disassemble function (r2 > Ghidra > IDA) |
| | `malvex_decompile` | Decompile to pseudocode (IDA > Ghidra > r2) |
| | `malvex_functions` | List functions with sizes |
| | `malvex_imports` | Imports grouped by library |
| | `malvex_exports` | Exported symbols |
| | `malvex_xrefs` | Cross-references to/from address |
| | `malvex_sections` | Section details with entropy |
| **Detection** | `malvex_yara_scan` | YARA rule scanning (file or inline) |
| | `malvex_sigma_check` | Sigma rule validation |
| | `malvex_ioc_extract` | Extract IOCs from file or text |
| **Dynamic** | `malvex_frida_hook` | Frida instrumentation hooks |
| | `malvex_sandbox_submit` | Submit to CAPE/Cuckoo sandbox |
| **OSINT** | `malvex_vt_lookup` | VirusTotal hash/URL/domain lookup |
| | `malvex_malware_bazaar` | MalwareBazaar sample lookup |
| **Memory** | `malvex_vol_pslist` | Volatility3 process listing |
| | `malvex_vol_malfind` | Volatility3 injection detection |
| | `malvex_vol_dlllist` | Volatility3 DLL listing |
| **Network** | `malvex_pcap_analyze` | PCAP analysis: protocols, DNS, HTTP, TLS |

Each tool automatically selects the best available backend (e.g. `malvex_disasm` tries radare2, then Ghidra, then IDA) and returns structured output. Tools that require external backends report exactly what to install if missing.

## Agents

Malvex drives 15 orchestrated agent roles, each with a specific mission and owned vectors:

| Agent | Role |
|---|---|
| `triage` | Hashes, real type, architecture, packer, entropy, strings, initial IOCs |
| `static-core` | Headers, resources, manifests, embedded config, compiler/runtime fingerprinting |
| `decompilation` | Function recovery, call graph, CFG, xrefs, renaming, behavior reconstruction |
| `deobfuscation` | Packers, OEP recovery, string/API decryption, anti-analysis, staged loaders |
| `dynamic-analysis` | Process tree, persistence, discovery, C2, exfiltration, privilege behavior |
| `memory-analysis` | Injections, RWX regions, manual mapping, reflective loading, decrypted config |
| `detection-engineering` | YARA, Sigma, EDR logic, network + memory detection ideas |
| `threat-intel` | Family hypotheses, overlap, variant comparison, lineage |
| `validator` | Rejects unsupported conclusions; forces evidence + confidence normalization |
| `network-analysis` | Packet capture, C2 beaconing, DGA, TLS fingerprints, protocol dissection |
| `firmware-analysis` | Binary extraction, region analysis, embedded filesystem carving, firmware RE |
| `mobile-analysis` | APK/DEX decompilation, manifest analysis, native lib extraction, permission audit |
| `sandbox-analysis` | Automated detonation, behavioral trace collection, sandbox evasion detection |

One agent invokes many skills. See [agents/](agents/) for the full system prompts.

## Skills

61 active malware-analysis skills aligned to the MITRE ATT&CK matrix. Each skill is a concrete procedure: which tool to run, what to grep, what pattern proves the vector, and what evidence to return.

See [SKILLS.md](SKILLS.md) for the full skill index and usage guide.

Highlights: `triage-initial`, `static-analysis`, `disassembly-decompilation`, `packing-obfuscation`, `debugging`, `dynamic-analysis`, `process-memory-analysis`, `network-analysis`, `persistence-analysis`, `credential-data-access`, `defense-evasion`, `command-and-control`, `exfiltration-analysis`, `anti-analysis`, `malware-configuration`, `capability-mapping`, `ioc-extraction`, `detection-engineering`, `threat-intelligence`, `malware-lineage`, `ai-assisted-re`.

## Deliverables

Every session produces in `sessions/<id>/`:

```
target.json              identified target (hashes, format, shielding)
findings.json            evidence-backed findings (source of truth)
summary.md               severity tally + finding list
attack-graph.md          chained exploitation paths (mermaid)
attack-graph.json        machine-readable attack graph
session.log              structured log of every event
<stage>-<agent>.out.json raw agent output per stage
```

Optional (when evidence supports):
- `iocs.json` — hashes, domains, IPs, URLs, registry keys, mutexes, services, certificates
- `detections/yara/` — generated + validated YARA rules
- `detections/sigma/` — Sigma detection rules
- `memory/` — memory dump artifacts
- `pcap/` — captured network traffic

## Evidence model

Every conclusion must point to one or more of:

- File offsets, RVA / VA, section names + entropy
- Import/export symbols, strings, decoded strings
- Disassembly or pseudocode loci, xrefs, graph relationships
- Debugger traces, memory artifacts
- Files, registry keys, services, tasks, pipes, mutexes
- DNS / HTTP / TLS observations
- Generated detections (YARA/Sigma with validation results)

The workflow: **hypothesis → evidence → verification → confidence**.

Similarity is not attribution. ATT&CK mappings, family matches, and lineage are derived outputs — they never substitute for primary evidence.

## Layout

```
crates/
  sasf-core           shared types (Target, Finding, Severity, Tool)
  sasf-doctor         tool detection + install + MCP registry
  sasf-orchestrator   pipeline orchestration, execution, parsing, PoC validation
  sasf-cli            `malvex` binary
  sasf-web            web UI (axum upload + session review)
agents/               15 agent system prompts (markdown)
skills/               61 SKILL.md procedures aligned to the malware analysis matrix
vulns/
  taxonomy.yaml       analysis vectors owned by the active agents
  attack-chains.yaml  curated exploitation chains
config/
  headless-tooling.yaml    tool preferences per platform
  runtime-profiles.yaml    agent runtime configurations
tools/
  yara_mcp.py         YARA MCP compatibility shim
plugins/
  ida/                IDA Pro analysis plugins
setup.sh / .ps1 / .bat    environment bootstrap scripts
```

## Setup

### macOS / Linux

```bash
./setup.sh
```

Idempotent. Installs (in order): Rust toolchain, open-source RE tools (radare2, Ghidra, YARA, binwalk, mitmproxy, lief, capstone, frida-tools, capa, FLOSS, volatility3, oletools, unicorn, angr), Claude Code CLI, uv/pipx helpers. Then builds `malvex`, runs `malvex setup`, and starts `malvex-web`.

### Windows

```bat
setup.bat
```

Launches `setup.ps1` (elevated). Installs via winget/choco/pip: radare2, rizin, x64dbg, WinDbg, Ghidra, Frida, YARA, lief, 7zip, Claude Code. Builds `malvex.exe`.

### Kali Linux

`malvex setup` and `malvex doctor --install` auto-detect Kali via `/etc/os-release` and install a broad apt-based malware-analysis bundle (38 packages) in addition to per-tool installs.

### Notes

- On macOS, several packages depend on Homebrew and should be run as a non-root user.
- Commercial tools (IDA, Binary Ninja, WinDbg) are detected and reported, never auto-installed.
- Headless tool preferences are in [`config/headless-tooling.yaml`](config/headless-tooling.yaml).
- MCP bridges may show as configured before they show as healthy. Backends need their local tool active.

## Cross-platform analysis

Static reverse engineering is host-independent — IDA (via idalib MCP), Ghidra, radare2, and lief all parse Windows PE from macOS. The full static pipeline runs on a Mac against `.exe`/`.dll`/`.msi` targets. `malvex extract` unpacks MSI/CAB on macOS.

**Dynamic** instrumentation runs natively when the host OS matches the target platform. Cross-host, agents emit a concrete `needs-<platform>-runtime` plan with exact steps, hooks, breakpoints, and expected artifacts — never fabricated evidence.

## Building

```bash
cargo build --release
cargo test --release -p sasf-orchestrator
./target/release/malvex doctor
```

## Disclaimer

Malvex provides tools for lawful malware analysis, reverse-engineering research, and detection engineering. You are responsible for obtaining any required authorization and complying with applicable laws. Analysis runs locally on your machine.

## License

MIT
