---
name: packing-obfuscation
description: Use when Malvex needs to detect or reverse packers, stubs, encrypted strings, API hashing, or staged payload loading.
---

# Skill: packing-obfuscation

Vector: packing-obfuscation | agent: deobfuscation | platforms: windows, linux, macos

## Objective

Determine how the sample hides its real payload or logic and recover the hidden code where possible.

## Checklist

- packer detection
- stub identification
- OEP recovery
- runtime unpacking and memory dumping
- import reconstruction
- string encryption and decryption routines
- API hashing
- control-flow flattening, opaque predicates, junk instructions, dead code, indirect jumps
- dynamic imports, encoded config, embedded payloads, multi-stage loaders

## Procedure

1. Confirm whether the entrypoint is a stub.
2. Identify unpacking, decryption, or stage-transition routines.
3. Recover decrypted code, strings, imports, or config.
4. Separate loader logic from payload logic.

## Proof

Claims about packing or API hashing must point to the stub, dispatcher, hash loop, resolver, or dumped payload artifact.
