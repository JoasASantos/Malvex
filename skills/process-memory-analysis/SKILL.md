---
name: process-memory-analysis
description: Use when Malvex needs process and memory analysis for injection, RWX regions, private executable memory, threads, or resident configuration.
---

# Skill: process-memory-analysis

Vector: process-memory-analysis | agent: memory-analysis | platforms: windows, linux, macos

## Objective

Recover volatile indicators of injection, in-memory config, and post-decryption behavior.

## Checklist

- injection indicators
- suspicious memory regions
- RWX and private executable regions
- unbacked executable memory
- loaded modules and thread start addresses
- config and decrypted strings in memory
- credential or token handling
- shellcode, reflective loading, hollowing, DLL injection, manual mapping

## Procedure

1. Enumerate memory regions and thread starts.
2. Recover decoded strings or config from memory.
3. Tie suspicious regions back to loader or injector code.
4. Record region permissions, addresses, sizes, and dump paths.

## Proof

Memory claims require a PID, address range, permissions, module state, or dump artifact.
