---
name: sigma-rule-generation
description: Use when Malvex needs to generate Sigma rules for behavioral detection of malware based on process, network, file and registry events.
---

# Skill: sigma-rule-generation

Vector: `sigma-rule-generation` | agent: detection-engineering | platforms: windows, linux, macos
ATT&CK: Detection Engineering

## Objective

Generate Sigma rules for behavioral detection based on identified malware behaviors —
process creation chains, file operations, registry modifications, network connections,
and service/task creation patterns.

## Checklist

- Process creation events (parent-child relationships, command lines)
- File creation/modification events (paths, names, content indicators)
- Registry modification events (persistence keys, configuration storage)
- Network connection events (C2 communication patterns, DGA domains)
- Service/scheduled task creation
- Named pipe creation and access patterns
- WMI event subscription creation

## Procedure

1. **Behavior mapping**: from dynamic analysis findings, identify observable events that
   can be captured by endpoint logging (Sysmon, Windows Event Log, auditd).
2. **Event selection**: choose the appropriate Sigma log source — process_creation,
   file_event, registry_event, network_connection, dns_query, pipe_created.
3. **Detection logic**: construct selection criteria — specific command line patterns,
   file paths, registry keys, network destinations. Use Sigma modifiers (contains,
   endswith, startswith, re) appropriately.
4. **Filter construction**: add filter conditions to exclude known false positives —
   legitimate software that exhibits similar behavior.
5. **Metadata**: include title, description, status, level (critical/high/medium/low),
   ATT&CK tags, references, and author.
6. **Validation**: convert with `sigma-cli` to target SIEM format (Splunk, Elastic,
   Microsoft Sentinel) to verify syntax and logic.

## Proof

Sigma rule with valid YAML syntax, appropriate log source, specific detection logic,
and false positive filters. Each detection condition maps to an observed behavior.

## Evidence out

- locus: Sigma rule YAML source
- detail: targeted behavior, log source, detection conditions, ATT&CK mapping
- confidence: high when behavior confirmed in dynamic analysis
- follow-up: `detection-engineering` for broader detection strategy

## Guardrail

LLM output is a lead, not proof. Rules must capture observed behavior, not hypothetical.
