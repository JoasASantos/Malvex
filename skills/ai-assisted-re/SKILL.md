---
name: ai-assisted-re
description: Use when Malvex needs AI assistance for function classification, renaming, decoder recognition, ATT&CK leads, or variant comparison that still requires evidence.
---

# Skill: ai-assisted-re

Vector: ai-assisted-re | agent: decompilation | platforms: windows, linux, macos

## Objective

Use the model to accelerate reverse engineering without letting it outrun the evidence.

## Checklist

- function classification
- function renaming
- pseudocode explanation
- algorithm or crypto identification
- string-decoder recognition
- config discovery
- call-graph interpretation
- ATT&CK mapping, IOC context, detection suggestions, variant comparison

## Procedure

1. Ask the model focused questions over real artifacts.
2. Force answers to cite functions, xrefs, APIs, strings, dumps, or packets.
3. Mark every unsupported claim as a hypothesis.

## Proof

The model helped only if the resulting claim became better evidenced, not just longer.
