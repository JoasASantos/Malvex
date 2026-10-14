---
name: persistence-analysis
description: Use when Malvex needs to determine persistence mechanisms across Windows, Linux, or macOS.
---

# Skill: persistence-analysis

Vector: persistence-analysis | agent: dynamic-analysis | platforms: windows, linux, macos

## Objective

Identify how the sample survives reboot or user logout.

## Checklist

- Run keys, startup folders, tasks, services, WMI, COM hijack
- browser extension abuse
- login scripts, shell config
- systemd, cron
- LaunchAgents / LaunchDaemons
- abuse of legitimate apps

## Procedure

1. Inspect static strings, manifests, scripts, and service/task creation code.
2. Confirm persistence actions dynamically when possible.
3. Distinguish one-shot execution helpers from true persistence.

## Proof

Persistence findings require the actual mechanism, path/key/name, and where the sample creates or references it.
