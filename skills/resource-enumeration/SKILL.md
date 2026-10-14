---
name: resource-enumeration
description: Use when Malvex needs to enumerate and analyze embedded resources in PE/ELF/Mach-O binaries for hidden payloads, configuration and icons.
---

# Skill: resource-enumeration

Vector: `resource-enumeration` | agent: static-core | platforms: windows, linux, macos
ATT&CK: T1027.009 (Embedded Payloads), T1036.005 (Match Legitimate Name/Location)

## Objective

Enumerate and analyze all embedded resources — PE resource directory, ELF notes, Mach-O
segments — to find hidden payloads, configuration data, icons used for social engineering,
and version information revealing build metadata.

## Checklist

- PE resource directory (RT_RCDATA, RT_DIALOG, RT_MANIFEST, RT_VERSION, RT_ICON)
- Oversized or mistyped resource entries
- High-entropy resources (encrypted payloads)
- Icon analysis (mimicking legitimate software)
- Manifest analysis (requested execution level, DPI awareness)
- Version information (company, product, internal name)

## Procedure

1. **Resource enumeration**: list all resources by type, name/ID, language, size.
2. **Anomaly detection**: flag oversized resources (>100KB RT_RCDATA), mistyped entries
   (bitmap resource with PE magic), unusual language IDs.
3. **Payload scanning**: check high-entropy resources for embedded PE/shellcode/config.
4. **Icon analysis**: extract icons — social engineering via mimicking Word, PDF, folder
   icons is a common malware technique.
5. **Manifest parsing**: extract requested execution level (requireAdministrator),
   compatibility settings, DPI awareness, SxS assembly dependencies.
6. **Version info**: extract company name, product name, internal name, original filename,
   file version — these may reveal builder tools or campaign metadata.

## Proof

Complete resource inventory with anomalies flagged. Extracted payloads from suspicious
resources with format identification and SHA-256 hashes.

## Evidence out

- locus: resource type, ID, language, offset, size
- detail: content classification, entropy, anomalies, extracted payload hashes
- confidence: high — resource enumeration is deterministic
- follow-up: `embedded-blob-carve` for payload extraction

## Guardrail

LLM output is a lead, not proof. Resource content must be extracted and verified, not described.
