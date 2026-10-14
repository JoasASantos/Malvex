---
name: config-extraction
description: Use when Malvex needs to extract and parse malware configuration data including C2 addresses, encryption keys, campaign IDs, bot settings and operational parameters.
---

# Skill: config-extraction

Vector: `config-extraction` | agent: static-core, deobfuscation | platforms: windows, linux, macos
ATT&CK: T1132 (Data Encoding), T1573 (Encrypted Channel)

## Objective

Extract and parse malware configuration — C2 addresses, encryption keys, campaign/bot IDs,
mutex names, sleep intervals, targeted applications, and operational parameters. Config is
the highest-value static artifact for threat intelligence.

## Checklist

- Config location (resource, data section, overlay, registry, file)
- Config encryption/encoding (XOR, RC4, AES, base64, custom)
- Config structure (binary struct, JSON, INI, custom format)
- C2 endpoints (domains, IPs, ports, paths, protocols)
- Encryption keys (RSA public, AES key, session key derivation)
- Campaign metadata (campaign ID, bot ID, version, build date)
- Operational parameters (sleep interval, jitter, mutex, user-agent)

## Procedure

1. **Config location**: identify where config is stored — PE resource, data section blob,
   file overlay, hardcoded strings, external config file path.
2. **Decryption**: trace config access routines to identify decryption — common patterns
   include XOR with hardcoded key, RC4, AES-CBC, or multi-layer encoding.
3. **Structure parsing**: once decrypted, parse the config format — binary structs with
   fixed offsets, delimited text, JSON, or tagged fields.
4. **Field extraction**: extract all fields — C2 URLs, fallback addresses, encryption keys,
   campaign ID, mutex name, sleep/jitter values, targeted app lists.
5. **Cross-reference**: correlate extracted config with code behavior — verify C2 addresses
   are actually used, confirm encryption keys match usage in crypto routines.
6. **Family matching**: compare config structure and field types against known malware family
   config formats (Emotet, TrickBot, Cobalt Strike, AgentTesla, etc.).

## Proof

Complete config extracted with decryption method documented, all fields parsed and
classified, and config structure matched to known family format if applicable.

## Evidence out

- locus: config blob address, decryption routine, parsed field addresses
- detail: all extracted fields with values, decryption method, family match
- confidence: high when decryption confirmed and fields validated
- follow-up: `malware-configuration` for operational analysis, `ioc-extraction` for C2 IOCs

## Guardrail

LLM output is a lead, not proof. Every config field must be extracted from the binary.
