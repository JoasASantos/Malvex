# Malvex RE Tool Plugins

Reverse engineering tool plugins that complement Malvex agents.
These are invoked automatically by agents when the corresponding tool is available,
or can be run manually for standalone analysis.

## IDA Pro Plugins (Python)

| Plugin | Purpose |
|--------|---------|
| `malvex_auto_rename.py` | Renames sub_* functions based on shielding SDK patterns, string refs, and import calls |
| `malvex_vuln_scanner.py` | Scans for hardcoded secrets, insecure APIs, RWX sections, weak crypto, missing canaries |
| `malvex_string_xref_map.py` | Builds JSON map of interesting strings with all function cross-references |
| `malvex_protection_map.py` | Maps anti-debug, anti-tamper, integrity check, and obfuscation routines |

**Usage (batch):** `idat64 -A -S"plugins/ida/<script>.py" target.idb`

## Ghidra Scripts (Java)

| Script | Purpose |
|--------|---------|
| `MalvexControlFlowDeobfuscator.java` | Detects opaque predicates, dispatcher-based CFF, bogus blocks |
| `MalvexCryptoLocator.java` | Locates crypto constants (AES S-box, DES IP, RC4, ChaCha20) and API imports |

**Usage:** Run via Script Manager or `analyzeHeadless . proj -import bin -postScript <script>.java`

## Frida Scripts (JavaScript)

| Script | Purpose |
|--------|---------|
| `malvex_anti_debug_bypass.js` | Universal anti-debug bypass (Windows/macOS/Linux + Frida detection) |
| `malvex_tls_intercept.js` | SSL/TLS pinning bypass + plaintext traffic logging |
| `malvex_api_tracer.js` | Security API call tracer (file, process, registry, network, IPC) |
| `malvex_memory_scanner.js` | Runtime memory scanner for credentials, keys, PII |

**Usage:** `frida -l plugins/frida/<script>.js -f <target>`

## radare2 Scripts

| Script | Purpose |
|--------|---------|
| `malvex_quick_audit.r2` | Fast security audit: protections, imports, strings, dangerous xrefs |

**Usage:** `r2 -i plugins/radare2/malvex_quick_audit.r2 -q <binary>`
