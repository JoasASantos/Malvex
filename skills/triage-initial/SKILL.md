---
name: triage-initial
description: Use when Malvex needs initial malware triage: hashes, real type, architecture, timestamps, signing, entropy, strings, and broad IOC surface.
---

# Skill: triage-initial

Vector: triage-initial | agent: triage | platforms: windows, linux, macos

## Objective

Produce the initial dossier: hashes, real type, architecture, format, signing state, timestamps, packer hints, entropy, suspicious sections, overlay, imports/exports, strings, and broad IOC surface.

## Checklist

- SHA256 / SHA1 / MD5
- real file type and format
- architecture and size
- signature / certificate / compile timestamp
- packer or protector indicators
- entropy, abnormal sections, overlay
- imports, exports, ASCII/Unicode strings
- URLs, domains, IPs, user-agents, paths, mutexes, registry keys, emails, wallets, services, PDB paths

## Procedure

1. Hash the artifact and every extracted inner binary.
2. Use format-aware parsers, not only magic bytes.
3. Record section layout, entropy, overlay, timestamps, and signature state.
4. Extract strings and normalize obvious IOCs.
5. Mark whether the sample appears packed, scripted, staged, or multi-binary.

## Proof

The dossier is complete when it can tell a downstream analyst what the sample is, what platform it targets, and what immediate leads deserve deeper analysis.

## Guardrail

Do not claim malware family or behavior from strings alone.
