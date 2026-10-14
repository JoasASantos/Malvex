---
name: import-export-surface
description: Use when Malvex needs to map the complete import/export API surface of a binary to identify capabilities, suspicious API usage patterns and dynamic resolution techniques.
---

# Skill: import-export-surface

Vector: `import-export-surface` | agent: static-core | platforms: windows, linux, macos
ATT&CK: T1106 (Native API), T1129 (Shared Modules)

## Objective

Map the complete import/export API surface to identify malware capabilities, suspicious API
combinations, dynamic resolution techniques (GetProcAddress, dlsym), and API hashing.

## Checklist

- Static import table (IAT/PLT/dyld stubs)
- Delayed imports and forwarded exports
- Dynamic resolution via GetProcAddress/dlsym/LdrGetProcedureAddress
- API hashing (hash-to-API resolution)
- Suspicious API combinations (injection, credential access, persistence)

## Procedure

1. **Static imports**: enumerate all imported DLLs/SOs/dylibs and their functions. Flag
   suspicious imports: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread (injection);
   CryptEncrypt, BCryptEncrypt (crypto); InternetOpen, URLDownloadToFile (network);
   RegSetValueEx, CreateService (persistence).
2. **Delayed imports**: enumerate delay-load entries — malware uses these to avoid static
   detection of suspicious APIs.
3. **Exports**: analyze exported functions — RAT DLLs export ServiceMain, DllInstall,
   or numbered ordinals hiding functionality.
4. **Dynamic resolution**: find GetProcAddress/dlsym call sites, trace the function name
   argument to recover dynamically resolved APIs.
5. **API hashing**: identify hash computation routines (ROR13, CRC32, djb2, custom) and
   resolve hashes to API names using known hash databases.
6. **Capability mapping**: group resolved APIs into capability categories — process
   injection, file operations, registry, network, crypto, anti-debug, persistence.

## Proof

Complete API inventory with capability groupings, dynamic resolution chains traced to
concrete API names, and API hash algorithms identified with resolution tables.

## Evidence out

- locus: import table entries, GetProcAddress call sites, hash computation routines
- detail: API name, DLL, resolution method, capability category
- confidence: high for static imports; medium for dynamic resolution; varies for hash resolution
- follow-up: `process-injection` for injection APIs, `persistence-analysis` for persistence APIs

## Guardrail

LLM output is a lead, not proof. Dynamic API resolution requires tracing, not guessing.
