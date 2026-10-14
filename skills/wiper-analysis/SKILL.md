---
name: wiper-analysis
description: Use when Malvex needs to analyze destructive wiper malware including disk wiping patterns, MFT destruction, backup deletion and propagation mechanisms.
---

# Skill: wiper-analysis

Vector: `wiper-analysis` | agent: static-core, dynamic-analysis | platforms: windows, linux
ATT&CK: T1561 (Disk Wipe), T1485 (Data Destruction), T1490 (Inhibit System Recovery)

## Objective

Analyze destructive wiper malware — disk overwrite patterns, MFT/filesystem destruction,
backup/shadow copy deletion, boot sector wiping, and propagation for maximum impact.

## Checklist

- Disk access method (direct \\.\PhysicalDrive, DeviceIoControl, raw /dev/sdX)
- Overwrite pattern (zeros, random, incremental, specific byte patterns)
- MFT targeting (direct MFT overwrite vs file-by-file deletion)
- Boot sector destruction (MBR overwrite, partition table zeroing)
- Shadow copy / backup deletion (vssadmin, wmic, bcdedit)
- File targeting (all files, specific extensions, specific directories)
- Propagation before destruction (network spread for coordinated wipe)
- Timing/trigger mechanisms (scheduled destruction, kill switch)

## Procedure

1. **Destruction method**: identify how the wiper accesses storage — raw disk
   (CreateFile on PhysicalDrive), filesystem API (DeleteFile, MoveFileEx), or
   driver-based (DeviceIoControl).
2. **Overwrite analysis**: determine the overwrite pattern and number of passes. Check
   for secure delete (DoD 5220.22-M pattern) vs simple zeroing.
3. **Target scope**: identify what is destroyed — MBR, partition table, MFT, specific file
   types, all user files, entire disk. Check for exclusion logic (skip system files
   needed for propagation).
4. **Recovery inhibition**: identify backup destruction — vssadmin delete shadows,
   bcdedit /set recoveryenabled no, wbadmin delete catalog.
5. **Propagation**: check if the wiper spreads before destroying — SMB propagation, AD
   exploitation, scheduled task deployment for coordinated detonation.
6. **Kill switch / timer**: identify detonation triggers — hardcoded date/time, external
   command, absence of check-in (dead man's switch).

## Proof

Destruction mechanism documented with disk access method, overwrite pattern, target scope,
and propagation method. Recovery assessment based on destruction completeness.

## Evidence out

- locus: disk access routine, overwrite loop, propagation code
- detail: destruction method, overwrite pattern, target scope, propagation
- confidence: high when destruction chain fully traced
- follow-up: `lateral-movement` for propagation, `persistence-analysis` for pre-wipe setup

## Guardrail

LLM output is a lead, not proof. Destruction mechanisms must be confirmed in code.
