---
name: discovery-analysis
description: Use when Malvex needs to map host, user, privilege, software, process, locale, network, or virtualization discovery behavior.
---

# Skill: discovery-analysis

Vector: discovery-analysis | agent: dynamic-analysis | platforms: windows, linux, macos

## Objective

Determine what environment knowledge the sample attempts to collect.

## Checklist

- OS, username, hostname, domain, privileges
- installed software and security products
- processes, services, interfaces, drives, files
- browser profiles, cloud apps
- virtualization artifacts
- locale, keyboard layout, geolocation signals

## Procedure

1. Map discovery APIs and strings statically.
2. Confirm the executed discovery path dynamically where possible.
3. Group the results by victim-impact category.

## Guardrail

The goal is to understand targeting and impact, not to collect real victim data.
