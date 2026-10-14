---
name: library-dependency-map
description: Use when Malvex needs to map statically linked libraries, their versions and known vulnerabilities within a malware sample.
---

# Skill: library-dependency-map

Vector: `library-dependency-map` | agent: static-core | platforms: windows, linux, macos
ATT&CK: T1195.002 (Compromise Software Supply Chain)

## Objective

Identify statically linked and dynamically loaded libraries, their versions, and known
vulnerabilities. In malware analysis, this reveals the toolchain, capabilities (crypto,
networking, compression), and potential supply chain indicators.

## Checklist

- Dynamically linked libraries (DLL/SO/dylib dependencies)
- Statically linked library signatures (FLIRT, function patterns)
- Version strings and build metadata
- Known CVEs for identified library versions
- Compiler/linker identification (MSVC, GCC, Clang, MinGW, Borland)

## Procedure

1. **Dynamic dependencies**: enumerate import DLLs (PE), NEEDED entries (ELF), LC_LOAD_DYLIB
   (Mach-O). Note unusual or custom library names.
2. **Static library detection**: apply FLIRT signatures, function pattern matching, or string
   scanning for library identifiers — OpenSSL version strings, Crypto++ namespace markers,
   zlib version, curl version, Boost signatures.
3. **Compiler identification**: Rich header analysis (PE), .comment section (ELF), LC_VERSION
   (Mach-O). Identify MSVC version, GCC/MinGW version, cross-compilation indicators.
4. **Version extraction**: scan strings for version patterns, build timestamps, PDB paths.
5. **CVE mapping**: check identified library+version against known vulnerability databases.
6. Emit dependency map: library name, version, linkage type, known issues.

## Proof

Library identified by converging evidence (FLIRT match + version string + characteristic
functions), with compiler/linker toolchain confirmed.

## Evidence out

- locus: library identification points (strings, function signatures, headers)
- detail: library name, version, linkage type, compiler, known CVEs
- confidence: high on FLIRT + version convergence; medium on heuristic identification
- follow-up: `algorithm-identification` for crypto library primitives

## Guardrail

LLM output is a lead, not proof. FLIRT matches need version string confirmation.
