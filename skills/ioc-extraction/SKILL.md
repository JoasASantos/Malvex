---
name: ioc-extraction
description: Use when Malvex needs to extract and normalize actionable IOCs and configuration markers from static or runtime evidence.
---

# Skill: ioc-extraction

Vector: ioc-extraction | agent: triage | platforms: windows, linux, macos

## Objective

Extract durable indicators and separate them from noisy artifacts.

## Checklist

- hashes
- domains, IPs, URLs
- file names and paths
- registry paths
- mutexes, services, tasks, certificates
- user-agents, named pipes
- C2 patterns and config markers

## Procedure

1. Extract raw indicators from strings, config, and runtime traces.
2. Deduplicate and normalize them.
3. Tag each IOC with source and confidence.

## Proof

An IOC entry should always say where it came from.
