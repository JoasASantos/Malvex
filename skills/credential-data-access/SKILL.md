---
name: credential-data-access
description: Use when Malvex needs to determine which credential or data stores a sample targets and how it accesses them.
---

# Skill: credential-data-access

Vector: credential-data-access | agent: decompilation | platforms: windows, linux, macos

## Objective

Explain what categories of secrets or user data the malware targets.

## Checklist

- browser data, passwords, cookies, tokens, extensions
- wallets, SSH material, FTP config
- email, messaging, cloud and developer credentials
- env vars, config files, databases
- clipboard, screenshots, keylogging

## Procedure

1. Identify target stores, file paths, registry keys, SQLite schemas, APIs, or browser-specific code.
2. Rename the functions that collect or stage this data.
3. Tie those functions to downstream exfiltration or staging logic.

## Proof

Claims require the target artifact category and the proving code path or runtime access trace.
