---
name: embedded-blob-carve
description: Use when Malvex needs to locate and extract embedded payloads, encrypted blobs, configuration data and secondary-stage binaries hidden within a malware sample.
---

# Skill: embedded-blob-carve

Vector: `embedded-blob-carve` | agent: static-core | platforms: windows, linux, macos
ATT&CK: T1027.009 (Embedded Payloads), T1140 (Deobfuscate/Decode Files)

## Objective

Locate and extract embedded payloads, encrypted configuration blobs, secondary-stage
binaries, shellcode and resource-hidden data from within malware samples.

## Checklist

- High-entropy data regions distinct from normal sections
- Magic byte signatures for embedded PE/ELF/MachO/ZIP/CAB within the binary
- Resource section payloads (RT_RCDATA, custom resource types)
- Overlay/appended data beyond section boundaries
- XOR/RC4 encrypted blobs referenced by decryption routines

## Procedure

1. **Entropy map**: generate byte-level or block-level entropy graph. High-entropy islands
   within low-entropy sections indicate embedded encrypted/compressed data.
2. **Magic scan**: search for PE (`MZ`/`PE\0\0`), ELF (`\x7fELF`), ZIP (`PK`), GZIP
   (`\x1f\x8b`), CAB (`MSCF`), and other container signatures at non-standard offsets.
3. **Resource carving**: enumerate PE resources (RT_RCDATA, RT_BITMAP, custom IDs). Malware
   frequently hides payloads in oversized or mistyped resource entries.
4. **Overlay extraction**: identify data appended after the last section. Compute its entropy
   and attempt format identification.
5. **Decryptor tracing**: for encrypted blobs, trace xrefs to the blob address — identify
   the decryption routine, extract key/IV, and attempt offline decryption.
6. **Recursive analysis**: carved payloads feed back into triage for independent analysis.

## Proof

Extracted blob with identified format (PE header, shellcode, config structure) or successful
decryption yielding interpretable data, with exact offset and size documented.

## Evidence out

- locus: blob offset, size, containing section/resource
- detail: format, entropy, decryption method if applicable, SHA-256 of carved blob
- confidence: high when format confirmed; medium when entropy suggests but format unknown
- follow-up: `dropper-loader` for multi-stage chains, `config-extraction` for config blobs

## Guardrail

LLM output is a lead, not proof. Carve and hash every extracted blob independently.
