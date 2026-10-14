---
name: exfiltration-analysis
description: Use when Malvex needs to trace staging, compression, encryption, transport, destination, or cleanup of outbound data theft.
---

# Skill: exfiltration-analysis

Vector: exfiltration-analysis | agent: dynamic-analysis | platforms: windows, linux, macos

## Objective

Show what the sample prepares to send out and how it sends it.

## Checklist

- staging directory
- archive creation, compression, encryption, chunking
- POST/API/custom protocol exfil
- cloud-service abuse
- destination and cleanup

## Procedure

1. Track collection-to-staging-to-transmit flow.
2. Identify serialization, compression, archive, or encryption helpers.
3. Correlate those with network destinations or dead-drop logic.

## Proof

Exfiltration claims require staging code, archive buffers, request builders, or runtime traffic.
