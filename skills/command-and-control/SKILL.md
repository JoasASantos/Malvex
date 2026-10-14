---
name: command-and-control
description: Use when Malvex needs to recover C2 configuration, protocols, tasking, fallback infrastructure, or communications security details.
---

# Skill: command-and-control

Vector: command-and-control | agent: dynamic-analysis | platforms: windows, linux, macos

## Objective

Recover how the sample receives commands and maintains operator control.

## Checklist

- C2 config, protocol, beaconing
- encryption and authentication
- command, tasking, and response formats
- fallback infrastructure, rotation, DGA, proxy support, Tor, dead drops, cloud abuse

## Procedure

1. Locate C2 bootstrap and session-establishment code.
2. Recover protocol structure from code, strings, or traffic.
3. Map message fields to capabilities when possible.

## Proof

C2 claims should cite config blobs, protocol handlers, or observed exchanges.
