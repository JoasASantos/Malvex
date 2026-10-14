# Malvex — Tutorial

Full command reference and workflows for `malvex`. Every command, every flag, real examples.

> Evidence-driven malware analysis and reverse-engineering harness for Windows, Linux, and
> macOS. Runs on the analyst machine and drives AI agents over IDA/Ghidra/radare2/Frida per
> a malware-analysis taxonomy. Local-only: samples never leave your host.

---

## 0. Install

```bash
# macOS / Linux
./setup.sh
# Windows (elevated)
setup.bat            # launches setup.ps1
```

`setup.sh` / `setup.ps1` are idempotent and do, in order:
1. Package manager check (brew / choco|winget / apt)
2. Rust toolchain (rustup if missing)
3. Open-source RE tools: radare2, rizin, Ghidra, YARA, binwalk, mitmproxy,
   MSI unpackers (msitools, sevenzip, cabextract), unpackers (UPX, DIE),
   Python libs (lief, capstone, frida-tools, yara-python, oletools, volatility3,
   angr, unicorn, floss, capa)
4. Claude Code CLI (installs if absent), then uv/pipx helpers
5. Audit configured MCP servers
6. Build `malvex`, run `malvex doctor`, then `malvex mcp-setup --install`

After setup, sign in once: run `claude` interactively.

---

## 0b. `malvex setup` — one-shot automated install

Installs everything in one command: missing analysis tools + MCP servers.

```bash
malvex setup                            # tools + MCP servers (open-source only)
malvex setup --commercial               # also wire commercial MCP servers (IDA, Binary Ninja)
malvex setup --no-mcp                   # tools only, skip MCP servers
malvex setup --no-tools                 # MCP servers only, skip tools
malvex setup --mcp-home ~/my-mcp-dir    # custom directory for git-cloned MCP servers
```

Runs in 3 phases:
1. **Tools** — installs missing open-source RE tools. Same as `malvex doctor --install`.
2. **MCP servers** — clones/installs + `claude mcp add` for 18 RE MCP servers. Same as `malvex mcp-setup --install`.
3. **Status** — prints final environment status (what's present, what's still missing).

Idempotent — safe to run multiple times. On Kali Linux, auto-detects the distro and
installs a broad apt-based malware-analysis bundle in addition to per-tool installs.

---

## 1. `malvex doctor` — environment check

```bash
malvex doctor                 # table: which tools + MCP servers are present
malvex doctor --json          # machine-readable output
malvex doctor --install       # install missing OPEN-SOURCE tools
```

Detects 216 tools across categories: disassemblers (IDA, Ghidra, radare2, rizin, Cutter,
Binary Ninja, JD-GUI, CFR, Procyon), parsers (lief, capstone, readelf, objdump, otool, nm,
strings, exiftool, capa, floss, YARA, elfparser, macholib), carvers (binwalk, 7zip, msitools,
cabextract, UPX, foremost, bulk_extractor, scalpel, photorec, firmware-mod-kit), dynamic
instruments (Frida, strace, ltrace, regshot, apimonitor, process-hacker), debuggers (gdb, lldb,
x64dbg, WinDbg), network forensics (mitmproxy, tshark, tcpdump, RITA, NetworkMiner, maltrail,
passivedns, dnschef), memory forensics (volatility3, findaes, voldiff), threat platforms (MISP,
OpenCTI, SpiderFoot, TheHive, Cortex), classification (ClamAV, LOKI, fenrir, pestudio, peframe),
YARA ecosystem (yarGen, yarAnalyzer, yextend, yara-forge), Sigma ecosystem (pySigma + backends),
deobfuscation (balbuzard, PowerDecode, de4js, jsbeautifier), symbolic execution (Manticore,
Triton, Miasm, BAP, PANDA, QIRA), sandbox CLIs (DRAKVUF, detux, malware-jail), document
analysis (box-js, ViperMonkey, officeparser, hachoir), enrichment (iocextract, ThreatFox,
URLhaus, Munin, cymru-whois), mobile (MobSF, DroidLysis, Quark), visualization (Gephi,
Cytoscape, graph-tool), and helpers (checksec, ssdeep, hashdeep, radamsa, stegdetect, REMnux).
Commercial tools (IDA, Binary Ninja, WinDbg, pestudio) are detected and reported, never
auto-installed.

---

## 2. `malvex mcp-setup` — wire RE MCP servers into Claude Code

```bash
malvex mcp-setup                          # plan only (prints what would be installed)
malvex mcp-setup --install                # install + register open-source servers
malvex mcp-setup --install --commercial   # also wire IDA / Binary Ninja MCPs
malvex mcp-setup --install --home ~/.malvex/mcp  # where git-cloned servers live
malvex mcp-setup --install --force        # re-register even if already configured
```

Wires these MCP servers (idempotent — skips already-configured):

| MCP name | Backend | License |
|---|---|---|
| ida-pro-mcp | IDA Pro | Commercial |
| ghidra-mcp | Ghidra | Open |
| radare2-mcp | radare2 | Open |
| frida-mcp | Frida | Open |
| x64dbg-mcp | x64dbg (Windows) | Open |
| re-mcp | IDA headless | Open |
| binaryninja-mcp | Binary Ninja | Commercial |
| cutter-mcp | Cutter/rizin | Open |
| yaraflux-mcp | YARA | Open |

Verify with `claude mcp list`.

---

## 3. `malvex run` — the full analysis pipeline

Accepts **anything**: a raw binary, a macOS `.app` bundle, a Windows installer
(`.msi`/`.cab`), or a directory. Locates the main binary automatically.

```bash
malvex run <target>                       # full pipeline (Opus 4.6, confirm-risky)
malvex run <target> --dry-run             # print the plan + commands only (0 tokens)
malvex run <target> --stages triage,static     # run a subset of stages
malvex run <target> --model claude-opus-4-6    # override the model
malvex run <target> --runtime codex            # use Codex CLI instead of Claude
malvex run <target> --root .                   # repo root holding agents/ skills/ vulns/
malvex run <target> --resume sessions/<id>     # continue a session, skip completed agents
malvex run <target> -j 3                       # shard static agents into 3 parallel workers
malvex run <target> --prompt "focus on C2"     # inject analyst guidance into every agent
malvex run <target> --prompt-file notes.txt    # same, from a file
malvex run <target> --fallback-models claude-opus-4-7,claude-opus-4-8
malvex run <target> --approval-mode auto       # auto | confirm-risky | human
```

**Pipeline stages** (each stage fans out its agents in parallel when `-j` > 1):

```
triage → static (static-core ∥ decompilation ∥ deobfuscation)
       → dynamic (dynamic-analysis ∥ memory-analysis)
       → network (network-analysis)
       → intelligence (detection-engineering ∥ threat-intel)
       → validate
```

- **triage** — hashes, real type, architecture, packer, entropy, sections, imports, strings, initial IOCs.
- **static** — headers, resources, manifests, compiler fingerprinting, function recovery, CFG,
  xrefs, behavior reconstruction, OEP recovery, string/API decryption.
- **dynamic** — debugging plan, process tree, persistence, C2, exfiltration, injections, RWX
  regions, decrypted strings, config in memory. Runtime evidence only when host matches target
  platform; otherwise emits a concrete runtime plan.
- **network** — packet capture, C2 beaconing, DGA detection, TLS fingerprints, protocol
  dissection via tshark/tcpdump/mitmproxy/zeek.
- **intelligence** — YARA/Sigma rules, EDR logic, family hypotheses, overlap, lineage.
- **validate** — rejects unsupported conclusions and forces evidence/confidence normalization.

---

## 4. `malvex extract` — unpack a Windows installer from macOS

```bash
malvex extract itauApp-1.1.0.msi          # MSI → CABs → PE binaries, recursively
```

Uses msiextract / 7z / binwalk (MSI) + cabextract / 7z (CAB). Prints every binary found,
ready to `malvex run`. `malvex run <installer>` does this automatically.

---

## 5. `malvex graph` — attack-chain graph

```bash
malvex graph sessions/<id>
```

Builds `attack-graph.md` (mermaid `flowchart`) + `attack-graph.json` from the findings'
chain fields, seeded with the curated `vulns/attack-chains.yaml` library.

---

## 6. `malvex sessions` — list runs

```bash
malvex sessions
```

Shows: session id, target, finding count, graph presence, log presence. Then inspect any
session with `malvex reparse` or `malvex repl`.

---

## 7. `malvex reparse` — re-derive findings (no LLM)

```bash
malvex reparse sessions/<id>
```

Re-parses the raw agent output into `findings.json` with the current parser — use after a
parser improvement to recover evidence from an old run, no token spend.

---

## 8. `malvex repl` — interactive session query

```bash
malvex repl sessions/<id>
malvex repl sessions/<id> --model claude-opus-4-6
malvex repl sessions/<id> --runtime codex
```

Opens an interactive prompt scoped to a completed session. The agent sees all prior findings
as context. Ask follow-up questions, request deeper analysis of specific functions, or
query for ATT&CK mappings.

---

## 9. `malvex coverage` — taxonomy coverage

```bash
malvex coverage
```

Shows how many vectors in `vulns/taxonomy.yaml` have a corresponding `SKILL.md` and whether
all agents exist. Use this after adding new skills to verify wiring.

---

## 10. Provider selection

Malvex supports five runtime backends. The provider is replaceable; the session model and
evidence model are not.

```bash
# 1. Claude Code (default)
malvex run sample.exe --runtime claude --model claude-opus-4-6

# 2. Codex CLI (non-interactive)
malvex run sample.exe --runtime codex

# 3. Custom wrapper (any provider — OpenRouter, LiteLLM, internal gateway)
MALVEX_CUSTOM_CMD="./my-wrapper.sh" malvex run sample.exe --runtime custom

# 4. Hermes (deepseek, qwen, kimi, glm, grok via hermes-cli)
malvex run sample.exe --runtime hermes --hermes-provider deepseek --hermes-model deepseek-chat

# 5. Ollama (local LLM, offline / air-gapped labs)
MALVEX_OLLAMA_MODEL=llama3.1 malvex run sample.exe --runtime ollama
```

**Custom runtime**: set `MALVEX_CUSTOM_CMD` in the environment. Malvex exposes
`MALVEX_PROMPT`, `MALVEX_MODEL`, `MALVEX_FALLBACKS`, `MALVEX_AGENT`, and `MALVEX_ROOT`
to the wrapper script. Use this for OpenAI-compatible gateways, OpenRouter, internal
brokers, or any custom provider router.

**Hermes runtime**: routes through `hermes-cli` to deepseek, qwen, kimi, glm, or grok.
Use `--hermes-provider` and `--hermes-model` to select the backend. Falls back on rate
limit automatically.

**Ollama runtime**: uses a locally running Ollama instance for fully offline or air-gapped
analysis. Set `MALVEX_OLLAMA_MODEL` to the model tag (e.g. `llama3.1`, `codellama`).

**Environment variables**:

| Variable | Purpose |
|---|---|
| `MALVEX_RUNTIME` | Default runtime backend (`claude`, `codex`, `custom`, `hermes`, `ollama`) |
| `MALVEX_APPROVAL_MODE` | Default approval policy (`auto`, `confirm-risky`, `human`) |
| `MALVEX_CUSTOM_CMD` | Command for the custom runtime |
| `MALVEX_MODEL_HINT` | Model hint passed to Codex |
| `MALVEX_OLLAMA_MODEL` | Model tag for Ollama runtime (e.g. `llama3.1`) |

---

## 10b. `malvex serve --mcp` — MCP server mode

Exposes Malvex as an MCP server over JSON-RPC 2.0 on stdio, so any MCP-capable AI agent
can drive Malvex analysis directly.

```bash
malvex serve --mcp                    # start MCP server on stdio
malvex serve --mcp --port 9100        # alternative: HTTP transport on port 9100
```

The server exposes 8 tools:

| MCP tool | Purpose |
|---|---|
| `malvex_analyze` | Run the full analysis pipeline on a target |
| `malvex_triage` | Quick triage: hashes, type, packer, entropy, strings |
| `malvex_doctor` | Environment check: which tools + MCP servers are present |
| `malvex_sessions` | List completed analysis sessions |
| `malvex_findings` | Retrieve findings from a session |
| `malvex_coverage` | Taxonomy coverage: skills + agents present |
| `malvex_extract` | Unpack MSI/CAB/NSIS/installer to raw binaries |
| `malvex_reparse` | Re-derive findings from raw output (no LLM) |

Wire into Claude Code:

```bash
claude mcp add malvex -- malvex serve --mcp
```

---

## 10c. `malvex preflight` — pre-flight checks

Validates the environment before a run. Reports 10 checks at three severity levels:
**Blocker** (analysis cannot proceed), **Degraded** (some stages will be limited), and
**Ok** (ready).

```bash
malvex preflight                      # run all 10 checks
malvex preflight --json               # machine-readable output
```

**Checks performed:**

| # | Check | Blocker if missing |
|---|---|---|
| 1 | Claude auth + quota | yes |
| 2 | Rust toolchain | yes |
| 3 | Disassembler (IDA / Ghidra / radare2) | yes |
| 4 | C compiler (cc / gcc / clang) | degraded |
| 5 | Python 3 | degraded |
| 6 | agents/ directory | yes |
| 7 | skills/ directory | yes |
| 8 | vulns/taxonomy.yaml | yes |
| 9 | Write permission on sessions/ | yes |
| 10 | Root / elevated privilege | degraded |

Run `malvex preflight` before `malvex run` to catch blockers early.

---

## 11. Evidence management

A session lives in `sessions/<timestamp>/`:

```
target.json              the identified target (hashes, format, shielding)
<stage>-<agent>.out.json raw agent output per stage (for reparse without LLM)
findings.json            parsed Finding array (source of truth)
summary.md               severity tally + finding list
attack-graph.md / .json  chained exploitation paths (mermaid)
session.log              structured log with timestamps
```

Inspect findings directly:

```bash
cat sessions/<id>/findings.json | jq '.[].title'
cat sessions/<id>/summary.md
```

---

## 12. End-to-end example

```bash
# 1. environment
./setup.sh
malvex mcp-setup --install --commercial

# 2. triage a sample
malvex run ~/samples/emotet.dll --stages triage --dry-run  # plan only
malvex run ~/samples/emotet.dll --stages triage            # real triage

# 3. full analysis with parallel static agents
malvex run ~/samples/emotet.dll -j 3

# 4. from the session it created
malvex sessions
S=sessions/<id-from-above>

# 5. inspect results
cat $S/findings.json | jq 'length'       # how many findings
cat $S/summary.md                         # human-readable summary
malvex graph $S                           # attack chains → $S/attack-graph.md

# 6. interactive follow-up
malvex repl $S
malvex> What encryption does the C2 protocol use?
malvex> /exit

# 7. reparse after parser improvements (no token spend)
malvex reparse $S
```

---

## 13. Model & flags reference

- Default model: `claude-opus-4-6`, fallback chain: `claude-opus-4-7`, `claude-opus-4-8`.
- Every agent runs with `--dangerously-skip-permissions` and `IS_SANDBOX=1`.
- Override the model per command with `--model`.
- `--root` points at the repo holding `agents/`, `skills/`, `vulns/` (default `.`).
- `--approval-mode`: `auto` (no confirmation), `confirm-risky` (default — confirms dangerous ops), `human` (confirms everything).
- `--parallel` / `-j`: shard static agents into N workers (max 5). Each shard gets a subset of taxonomy vectors.
- `--resume`: resume a prior session by path. Completed agents are skipped; failed ones re-run.

---

## Host-specific notes

- **Kali Linux**: `malvex setup` auto-installs 38+ distro packages (RE, tracing, network, helpers).
- **macOS**: Homebrew-backed tools should be installed as a non-root user. The setup script handles this.
- **Windows**: `setup.ps1` uses choco/winget. Cross-compilation from macOS works for static analysis.
- **MCP bridges**: may show as configured before they show as healthy. Tools such as Ghidra, Cutter, x64dbg, or Frida need their local backend active.
- **Headless preference**: for batch and agentic usage, prefer the headless paths listed in `config/headless-tooling.yaml`. Use GUI tooling only when the evidence requires manual inspection.

---

## Evidence standard

If a result cannot answer "what evidence proves it?", it is incomplete.

LLM output is not evidence. The model may propose hypotheses, likely function names,
algorithm matches, or ATT&CK mappings. Malvex treats those as analyst leads until they are
tied to static or runtime evidence.
