---
name: privilege-escalation
description: Use when Malvex needs to analyze token, service, driver, impersonation, or elevated-child-process behavior.
---

# Skill: privilege-escalation

Vector: privilege-escalation | agent: dynamic-analysis | platforms: windows, linux, macos

## Objective

Determine whether the sample attempts to gain higher privileges.

## Checklist

- token manipulation
- UAC behavior
- service or permission abuse
- vulnerable drivers
- exploit components
- credential reuse, impersonation, elevated children

## Procedure

1. Identify privilege-sensitive APIs or helpers.
2. Determine whether elevation is attempted, required, or optional.
3. Record any exploit or driver component separately from the main payload.

## Proof

Privilege-escalation claims require the relevant API, component, or observed elevated child process.
