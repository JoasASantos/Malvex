---
name: dropper-loader
description: Use when Malvex needs to analyze multi-stage delivery mechanisms including droppers, downloaders, loaders, and staged payload deployment chains.
---

# Skill: dropper-loader

Vector: `dropper-loader` | agent: static-core, dynamic-analysis | platforms: windows, linux, macos
ATT&CK: T1105 (Ingress Tool Transfer), T1129 (Shared Modules), T1620 (Reflective Code Loading)

## Objective

Analyze multi-stage malware delivery — droppers (embedded payload extraction), downloaders
(remote payload fetch), loaders (in-memory execution), and the complete staging chain from
initial access to final payload.

## Checklist

- Embedded payload location and extraction method
- Download URLs and fallback mechanisms
- Payload decryption/decompression
- In-memory loading technique (reflective, manual map, .NET Assembly.Load)
- Anti-sandbox checks before payload delivery
- Stage communication (how stages pass control/data)
- Persistence between stages

## Procedure

1. **Stage mapping**: identify the complete delivery chain — how many stages, what each
   stage does, how control passes between stages.
2. **Dropper analysis**: for embedded payloads, identify storage location (resource,
   overlay, data section), extraction method, decryption/decompression.
3. **Downloader analysis**: identify download URLs, HTTP methods, User-Agent strings,
   authentication tokens, fallback URLs, retry logic.
4. **Loader analysis**: identify how the final payload executes in memory — process
   hollowing, reflective loading, manual PE mapping, .NET Assembly.Load.
5. **Guard checks**: identify anti-sandbox/anti-analysis checks performed before payload
   delivery — VM detection, debugger checks, domain-joined check, user activity.
6. **Payload extraction**: extract each stage's payload with hash, for independent analysis.

## Proof

Complete delivery chain documented with each stage extracted, decrypted, and hashed.
Transition between stages documented with specific mechanisms.

## Evidence out

- locus: each stage's location, extraction routine, delivery mechanism
- detail: stage count, payload types, encryption, URLs, guard checks
- confidence: high when all stages extracted
- follow-up: start full pipeline on each extracted payload

## Guardrail

LLM output is a lead, not proof. Every stage must be independently extracted and verified.
