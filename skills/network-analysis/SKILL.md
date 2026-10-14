---
name: network-analysis
description: Use when Malvex needs analysis of DNS, IPs, URLs, HTTP(S), TLS, beaconing, C2, or exfiltration behavior.
---

# Skill: network-analysis

Vector: network-analysis | agent: memory-analysis | platforms: windows, linux, macos

## Objective

Extract network behavior from static and runtime evidence.

## Checklist

- DNS, domains, IPs, ports, protocols
- HTTP/HTTPS requests
- TLS characteristics
- user-agents, headers, URI patterns, POST structures
- beacon intervals, C2 patterns, downloads, uploads, proxy usage
- tunneling, hardcoded infrastructure, DGA indicators

## Procedure

1. Extract infrastructure from strings, config, and decompiled code.
2. Correlate that with live traffic if available.
3. Separate staging, beaconing, command exchange, and exfiltration traffic.

## Proof

Network claims should cite hardcoded config, packet artifacts, logs, or protocol handlers.
