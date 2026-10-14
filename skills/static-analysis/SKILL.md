---
name: static-analysis
description: Use when Malvex needs static malware analysis of headers, sections, imports, resources, compiler/runtime fingerprints, or embedded configuration.
---

# Skill: static-analysis

Vector: static-analysis | agent: static-core | platforms: windows, linux, macos

## Objective

Map the structural metadata that constrains interpretation of the sample.

## Checklist

- PE/ELF/Mach-O headers
- entry point
- section permissions
- import/export table
- resources, TLS callbacks, relocations
- debug info, exception handlers, manifest
- embedded files and embedded config
- libraries, runtime, compiler and framework fingerprints
- crypto, compression, encoding, obfuscated strings, sensitive APIs

## Procedure

1. Parse native headers with format-aware tooling.
2. Enumerate imported and exported symbols.
3. Recover manifests, resources, notes, load commands, or sections that affect behavior.
4. Fingerprint compiler, runtime, framework, and likely libraries.
5. Record anything that explains later code patterns.

## Proof

A static claim should point to a header field, section, symbol, resource, or embedded object.
